"""Lane scheduler — pool of N concurrent execution lanes.

A lane wraps a single (idea, victim, harness) triple. The scheduler:

- maintains a fixed pool of N lanes (config.lanes.pool_size)
- accepts ideas from the orchestrator via `submit(idea)`
- dispatches each idea to an available lane in priority order
- enforces per-lane timeouts and max-turn caps
- collects `LaneResult` objects via a callback to the orchestrator
- gracefully tears down victims even on exceptions

Note: the actual attack logic lives in `red_team/execution_agent.py` (Person 2).
We invoke their entrypoint via the `executor` callable passed at construction
time. This keeps the scheduler agnostic of the agent runtime.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from queue import Empty, PriorityQueue

from infra.monitoring_harness import HarnessConfig, MonitoringHarness
from interfaces.config_schema import LaneConfig, NemoClawConfig
from interfaces.provisioning import VictimConfig, VictimInstance, VictimProvisioner
from interfaces.types import IdeaObject, LaneResult

LOG = logging.getLogger("monkeyclaw.lanes")

# Type of Person 2's lane executor. Signature is fully under their control but
# we standardize the entrypoint here.
LaneExecutor = Callable[
    [IdeaObject, VictimInstance, MonitoringHarness, LaneConfig],
    None,
]


@dataclass
class _Job:
    """Priority queue item — highest priority popped first."""
    neg_priority: float  # priority queue is a min-heap → negate
    seq: int  # tiebreaker for FIFO order at equal priority
    idea: "IdeaObject"

    def __lt__(self, other: "_Job") -> bool:
        return (self.neg_priority, self.seq) < (other.neg_priority, other.seq)


class LaneScheduler:
    """Thread-pool-backed lane scheduler. NOT process-isolated by itself —
    the isolation boundary is the NemoClaw sandbox per victim."""

    def __init__(
        self,
        lane_cfg: LaneConfig,
        nemoclaw_cfg: NemoClawConfig,
        provisioner: VictimProvisioner,
        executor: LaneExecutor,
        on_result: Callable[[LaneResult], None],
        on_error: Callable[[Exception, IdeaObject], None] | None = None,
    ) -> None:
        self.lane_cfg = lane_cfg
        self.nemoclaw_cfg = nemoclaw_cfg
        self.provisioner = provisioner
        self.executor = executor
        self.on_result = on_result
        self.on_error = on_error or (lambda e, idea: LOG.exception(
            "lane error for idea %s: %s", idea.idea_id, e))
        self._queue: PriorityQueue[_Job] = PriorityQueue()
        self._pool = ThreadPoolExecutor(max_workers=lane_cfg.pool_size,
                                         thread_name_prefix="mc-lane")
        self._seq_lock = threading.Lock()
        self._seq = 0
        self._inflight: dict[str, Future] = {}
        self._stop = threading.Event()
        self._dispatcher: threading.Thread | None = None

    # ------------------------------------------------------------------
    def submit(self, idea: IdeaObject) -> None:
        with self._seq_lock:
            self._seq += 1
            seq = self._seq
        self._queue.put(_Job(neg_priority=-idea.priority_score, seq=seq, idea=idea))

    def queue_depth(self) -> int:
        return self._queue.qsize()

    def start(self) -> None:
        if self._dispatcher is not None:
            return
        self._dispatcher = threading.Thread(target=self._dispatch_loop,
                                             name="mc-lane-dispatch", daemon=True)
        self._dispatcher.start()

    def shutdown(self, timeout: float = 30.0) -> None:
        self._stop.set()
        if self._dispatcher is not None:
            self._dispatcher.join(timeout=timeout)
        self._pool.shutdown(wait=True, cancel_futures=True)

    def drain(self, timeout: float | None = None) -> None:
        """Block until the queue is empty AND all inflight lanes complete."""
        deadline = time.time() + timeout if timeout is not None else None
        while not self._stop.is_set():
            if self._queue.empty() and not self._inflight:
                return
            if deadline is not None and time.time() > deadline:
                LOG.warning("drain timed out; %d queued, %d inflight",
                             self._queue.qsize(), len(self._inflight))
                return
            time.sleep(0.1)

    # ------------------------------------------------------------------
    def _dispatch_loop(self) -> None:
        while not self._stop.is_set():
            try:
                job = self._queue.get(timeout=0.5)
            except Empty:
                continue
            # Submit to the thread pool; pool size caps concurrent lanes
            fut = self._pool.submit(self._run_lane, job.idea)
            self._inflight[job.idea.idea_id] = fut
            fut.add_done_callback(lambda f, iid=job.idea.idea_id: self._inflight.pop(iid, None))

    # ------------------------------------------------------------------
    def _run_lane(self, idea: IdeaObject) -> None:
        lane_id = f"LANE-{uuid.uuid4().hex[:10]}"
        LOG.info("lane %s starting idea %s zone=%s priority=%.3f",
                  lane_id, idea.idea_id, idea.zone_id, idea.priority_score)
        instance: VictimInstance | None = None
        try:
            instance = self.provisioner.provision_victim(VictimConfig(
                nemoclaw_version=self.nemoclaw_cfg.version,
                policy_path=self.nemoclaw_cfg.default_policy_path,
                agent_type="coding_assistant",
                agent_config_path=self.nemoclaw_cfg.default_agent_config_path,
                enable_monitoring=True,
            ))
            harness = MonitoringHarness(
                cfg=HarnessConfig(
                    watched_paths=self.nemoclaw_cfg.monitored_paths,
                    allowed_paths=self.nemoclaw_cfg.allowed_paths,
                    sandbox_pid=instance.pid,
                    psutil_interval=self.lane_cfg.psutil_interval_seconds,
                ),
                lane_id=lane_id,
                idea_id=idea.idea_id,
                zone_id=idea.zone_id,
            )
            with harness:
                t = threading.Thread(
                    target=self._executor_wrapper,
                    args=(idea, instance, harness),
                    name=f"{lane_id}-exec",
                )
                t.start()
                t.join(timeout=self.lane_cfg.lane_timeout_seconds)
                if t.is_alive():
                    LOG.warning("lane %s timeout — abandoning thread", lane_id)
                    harness.set_termination("timeout")
            result = harness.result()
            self.on_result(result)
        except Exception as e:  # noqa: BLE001
            self.on_error(e, idea)
        finally:
            if instance is not None:
                try:
                    self.provisioner.teardown_victim(instance.instance_id)
                except Exception as e:  # noqa: BLE001
                    LOG.warning("teardown failed for %s: %s", instance.instance_id, e)

    def _executor_wrapper(self, idea: IdeaObject, instance: VictimInstance,
                          harness: MonitoringHarness) -> None:
        try:
            self.executor(idea, instance, harness, self.lane_cfg)
        except Exception as e:  # noqa: BLE001
            LOG.exception("executor crashed for lane %s: %s", harness.lane_id, e)
            harness.set_termination("error")
