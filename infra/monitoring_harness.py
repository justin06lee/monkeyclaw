"""Monitoring harness — captures observable side-effects during a lane run.

This module wraps an execution lane in five concurrent collectors:
- Filesystem snapshot + diff (before/after content hashes, mtime checks)
- Network event log (callback API used by the network proxy / pcap shim)
- Process event log (psutil sampling + optional seccomp log tail)
- Persistent-memory diff (caller hands us before/after dicts)
- Inference routing log (a callback the NemoClaw client invokes for every
  inference request — we don't intercept the wire ourselves)

Design note: NemoClaw runs each agent inside an OpenShell sandbox with seccomp.
Capturing real syscalls in production requires hooking the sandbox itself,
which is out of scope for this Python wrapper. We expose a structured event
sink (`record_*`) that the lane scheduler is responsible for wiring into the
sandbox's actual monitoring channels (auditd, seccomp logs, eBPF tracer, etc.).
For the local mock victim, the harness can use psutil polling + filesystem
diffs, which is sufficient for development against planted vulnerabilities.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shlex
import subprocess
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from infra.guardrails import PolicyEnforcer
    from infra.telemetry import TelemetryEmitter

from interfaces.types import (
    FsDiff,
    InferenceEvent,
    LaneResult,
    MemoryDiff,
    Message,
    NetworkEvent,
    ProcessEvent,
)

LOG = logging.getLogger("monkeyclaw.harness")

# Container/namespace/pod names that get interpolated into a docker/kubectl
# argv must be restricted to a safe character set.
_K8S_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _now() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Filesystem snapshot
# ---------------------------------------------------------------------------


@dataclass
class FsSnapshot:
    files: dict[str, tuple[int, float, str]] = field(default_factory=dict)
    # path -> (size, mtime, sha256_first_16k)


def _hash_head(p: Path, n: int = 16 * 1024) -> str:
    try:
        with p.open("rb") as f:
            return hashlib.sha256(f.read(n)).hexdigest()
    except OSError:
        return ""


def snapshot_paths(roots: Iterable[str | Path]) -> FsSnapshot:
    """Snapshot the union of `roots` recursively. Roots can be files or dirs."""
    snap = FsSnapshot()
    for root in roots:
        root = Path(root).expanduser()
        if not root.exists():
            continue
        if root.is_file():
            try:
                st = root.stat()
                snap.files[str(root)] = (st.st_size, st.st_mtime, _hash_head(root))
            except OSError:
                pass
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            # avoid descending into very large or noisy dirs
            dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__"}]
            for fn in filenames:
                p = Path(dirpath) / fn
                try:
                    st = p.stat()
                except OSError:
                    continue
                snap.files[str(p)] = (st.st_size, st.st_mtime, _hash_head(p))
    return snap


def snapshot_sandbox_paths(
    container: str,
    namespace: str,
    pod: str,
    roots: Iterable[str | Path],
    *,
    timeout_s: int = 120,
) -> FsSnapshot:
    """Snapshot paths *inside* a NemoClaw sandbox pod.

    The sandbox runs as a k3s pod inside the gateway container, so we reach
    its filesystem via `docker exec <container> kubectl exec <pod> -- find`.
    One `find` call returns size + mtime + path for every file; the fs-diff
    compares those tuples (no content hash — an mtime/size change is enough
    to flag a created/modified/deleted file).
    """
    snap = FsSnapshot()
    root_list = [str(r) for r in roots]
    if not root_list:
        return snap
    # These three values are interpolated into a docker/kubectl argv —
    # restrict them to a safe character set so they cannot inject flags or
    # extra arguments.
    for label, value in (("container", container), ("namespace", namespace),
                         ("pod", pod)):
        if not _K8S_NAME_RE.match(value):
            LOG.error("sandbox fs snapshot: refusing unsafe %s name %r",
                      label, value)
            return snap
    quoted = " ".join(shlex.quote(r) for r in root_list)
    # 2>/dev/null: some roots may not exist in a given image — tolerate that.
    # `stat` is portable across GNU/BusyBox; `find -printf` is GNU-only and
    # silently yields nothing on Alpine/BusyBox sandbox images, which would
    # let in-sandbox filesystem escapes go undetected.
    find_cmd = (f"find {quoted} -type f -exec stat -c '%s\\t%Y\\t%n' {{}} + "
                f"2>/dev/null")
    cmd = [
        "docker", "exec", container,
        "kubectl", "exec", "-n", namespace, "-c", "agent", pod,
        "--", "sh", "-c", find_cmd,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except (subprocess.TimeoutExpired, OSError) as e:
        LOG.warning("sandbox fs snapshot failed (%s/%s): %s", container, pod, e)
        return snap
    if not proc.stdout:
        # Empty output with a non-zero exit is a hard failure (image missing
        # `stat`, pod gone, etc.) — log loudly so escapes are not missed.
        if proc.returncode != 0:
            LOG.error("sandbox fs snapshot returned %d with NO output "
                      "(filesystem escapes may be undetected): %s",
                      proc.returncode, proc.stderr.strip()[:200])
        return snap
    for line in proc.stdout.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        size_s, mtime_s, path = parts
        try:
            snap.files[path] = (int(size_s), float(mtime_s), "")
        except ValueError:
            continue
    return snap


def diff_snapshots(before: FsSnapshot, after: FsSnapshot,
                    allowed_paths: list[str]) -> FsDiff:
    allowed = [str(Path(p).expanduser().resolve()) for p in allowed_paths]

    def _outside(path: str) -> bool:
        try:
            rp = str(Path(path).resolve())
        except OSError:
            rp = path
        if not allowed:
            return False
        # A bare `startswith` would treat /tmp/openshell-evil as inside the
        # allowed /tmp/openshell — require an exact match or a true subpath.
        return not any(
            rp == a or rp.startswith(a + os.sep) for a in allowed)

    created, modified, deleted, accessed = [], [], [], []
    outside: list[str] = []

    before_paths = set(before.files)
    after_paths = set(after.files)
    for p in after_paths - before_paths:
        created.append(p)
        if _outside(p):
            outside.append(p)
    for p in before_paths - after_paths:
        deleted.append(p)
        if _outside(p):
            outside.append(p)
    for p in after_paths & before_paths:
        if before.files[p] != after.files[p]:
            modified.append(p)
            if _outside(p):
                outside.append(p)
    # `accessed` would require atime tracking which most filesystems disable.
    # Leave empty; the seccomp log inside the sandbox is the authoritative source.
    return FsDiff(
        files_created=created,
        files_modified=modified,
        files_deleted=deleted,
        files_accessed=accessed,
        files_outside_allowed_paths=outside,
    )


# ---------------------------------------------------------------------------
# Process sampler — best-effort psutil polling
# ---------------------------------------------------------------------------


@dataclass
class _ProcSampler:
    target_pid: int | None
    allowed_pids: set[int]
    events: list[ProcessEvent] = field(default_factory=list)
    interval: float = 0.5
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _loop(self) -> None:
        try:
            import psutil
        except ImportError:
            return
        seen: set[int] = set(self.allowed_pids)
        while not self._stop.is_set():
            try:
                if self.target_pid is None:
                    iter_procs = psutil.process_iter(["pid", "name", "ppid"])
                else:
                    try:
                        root = psutil.Process(self.target_pid)
                    except psutil.NoSuchProcess:
                        return
                    iter_procs = [root, *root.children(recursive=True)]
                for proc in iter_procs:
                    try:
                        info = proc.as_dict(attrs=["pid", "name", "ppid"])
                    except Exception:
                        continue
                    pid = info["pid"]
                    if pid in seen:
                        continue
                    seen.add(pid)
                    self.events.append(ProcessEvent(
                        timestamp=_now(),
                        process_name=info.get("name") or "?",
                        pid=pid,
                        syscall=None,
                        syscall_args=None,
                        blocked=False,
                        inside_sandbox=pid in self.allowed_pids,
                    ))
            except Exception as e:  # noqa: BLE001
                LOG.debug("proc sampler tick failed: %s", e)
            self._stop.wait(self.interval)


# ---------------------------------------------------------------------------
# Memory diff
# ---------------------------------------------------------------------------


def diff_memory(before: dict, after: dict) -> MemoryDiff:
    added = [k for k in after if k not in before]
    deleted = [k for k in before if k not in after]
    modified = [k for k in before if k in after and before[k] != after[k]]
    return MemoryDiff(
        keys_added=added,
        keys_modified=modified,
        keys_deleted=deleted,
        values_changed={k: {"old": before[k], "new": after[k]} for k in modified},
    )


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@dataclass
class HarnessConfig:
    watched_paths: list[str]
    allowed_paths: list[str]
    sandbox_pid: int | None = None
    seccomp_allowed_pids: set[int] = field(default_factory=set)
    psutil_interval: float = 0.5
    # When `sandbox_container` is set, the filesystem snapshot is taken
    # inside the NemoClaw sandbox pod (docker exec -> kubectl exec) rather
    # than against host paths. `sandbox_pod` defaults to the sandbox name.
    sandbox_container: str | None = None
    sandbox_namespace: str = "openshell"
    sandbox_pod: str | None = None


class MonitoringHarness:
    """Per-lane monitoring. Use as a context manager; produces a LaneResult."""

    def __init__(self, cfg: HarnessConfig, lane_id: str, idea_id: str,
                 zone_id: str, telemetry: TelemetryEmitter | None = None,
                 enforcer: PolicyEnforcer | None = None) -> None:
        self.cfg = cfg
        self.lane_id = lane_id
        self.idea_id = idea_id
        self.zone_id = zone_id
        # Optional TelemetryEmitter. When set, network/file events are
        # mirrored as A5 telemetry. Unset -> behavior is identical to before.
        self._telemetry = telemetry
        # Optional PolicyEnforcer (A8). When set, host-path reads and network
        # destinations are checked against policy. Unset -> behavior is
        # identical to before.
        self._enforcer = enforcer
        # An orphaned (timed-out) executor thread may still call record_*
        # while the scheduler thread builds the LaneResult — guard every
        # mutable collector and the final snapshot with this lock.
        self._record_lock = threading.Lock()
        self._terminated = False
        self.network_log: list[NetworkEvent] = []
        self.inference_log: list[InferenceEvent] = []
        self.transcript: list[Message] = []
        # Process events recorded externally (e.g. by the lane scheduler from
        # in-sandbox monitoring). Kept separate from the psutil sampler's own
        # events so they are never dropped when host sampling is disabled.
        self._external_process_events: list[ProcessEvent] = []
        self.attacker_tokens = 0
        self.victim_tokens = 0
        self.attacker_self_assessment = ""
        self._fs_before: FsSnapshot | None = None
        self._fs_after: FsSnapshot | None = None
        self._mem_before: dict | None = None
        self._mem_after: dict | None = None
        # Host psutil sampling is meaningless for a real sandbox lane: the
        # victim runs as a k3s pod, so its processes are never host
        # processes — sampling would record host PIDs and (with no sandbox
        # PID set) mark them all "outside the sandbox", a pure false
        # positive. Skip it; `process_log` is left empty. Real in-pod
        # process capture (kubectl exec ps) can be added later.
        self._monitor_processes = cfg.sandbox_container is None
        self._sampler = _ProcSampler(
            target_pid=cfg.sandbox_pid,
            allowed_pids=set(cfg.seccomp_allowed_pids),
            interval=cfg.psutil_interval,
        )
        self._started_at: float = 0
        self._start_iso: str = ""
        self._termination = "idea_completed"
        self._turns = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def __enter__(self) -> MonitoringHarness:
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self, initial_memory: dict | None = None) -> None:
        self._fs_before = self._snapshot()
        self._mem_before = dict(initial_memory or {})
        if self._monitor_processes:
            self._sampler.start()
        self._started_at = time.time()
        self._start_iso = _now()

    def stop(self, final_memory: dict | None = None) -> None:
        self._fs_after = self._snapshot()
        self._mem_after = dict(final_memory or {})
        if self._monitor_processes:
            self._sampler.stop()

    def _snapshot(self) -> FsSnapshot:
        """Snapshot the watched paths — inside the sandbox pod if this lane
        targets a real NemoClaw victim, otherwise against host paths."""
        if self.cfg.sandbox_container:
            return snapshot_sandbox_paths(
                self.cfg.sandbox_container,
                self.cfg.sandbox_namespace,
                self.cfg.sandbox_pod or "monkey-victim",
                self.cfg.watched_paths,
            )
        return snapshot_paths(self.cfg.watched_paths)

    # ------------------------------------------------------------------
    # Event recording — callbacks for the execution lane
    # ------------------------------------------------------------------
    def record_message(self, msg: Message) -> None:
        with self._record_lock:
            if self._terminated:
                return
            self.transcript.append(msg)
            self._turns += 1
        if self._telemetry is not None:
            self._telemetry.agent_event(
                agent_id=self.lane_id,
                agent_kind="lane",
                event_type=f"{msg.role}.message",
                role=msg.role,
                lane_id=self.lane_id,
                idea_id=self.idea_id,
                text=msg.content,
                metadata={
                    "tool_calls": msg.tool_calls or [],
                    "tool_results": msg.tool_results or [],
                },
            )

    def guard_path_read(self, path: str):
        """Consult the PolicyEnforcer for a host-path read; emit telemetry.

        Returns the PolicyDecision, or None when no enforcer is attached.
        """
        if self._enforcer is None:
            return None
        decision = self._enforcer.check_path_read(path)
        if self._telemetry is not None:
            self._telemetry.tool_decision(
                "harness", target=path, decision=decision.decision,
                reason_code=decision.reason_code)
        return decision

    def guard_network(self, destination: str, phase: str = "default"):
        """Consult the PolicyEnforcer for a network destination; emit telemetry.

        Returns the PolicyDecision, or None when no enforcer is attached.
        """
        if self._enforcer is None:
            return None
        decision = self._enforcer.check_network(destination, phase)
        if self._telemetry is not None:
            self._telemetry.network_request(
                "harness", destination=destination,
                decision=decision.decision, reason_code=decision.reason_code)
        return decision

    def record_network(self, event: NetworkEvent) -> None:
        with self._record_lock:
            if self._terminated:
                return
            self.network_log.append(event)
        if self._enforcer is not None:
            decision = self.guard_network(event.destination_domain,
                                          phase="default")
            if decision is not None and decision.decision == "deny":
                # Only escalate toward blocked — never un-block an event the
                # network proxy already flagged.
                event.blocked = True
        elif self._telemetry is not None:
            self._telemetry.network_request(
                "harness",
                destination=event.destination_domain,
                decision="deny" if event.blocked else "allow")
        if self._telemetry is not None:
            self._telemetry.agent_event(
                agent_id=self.lane_id,
                agent_kind="lane",
                event_type="tool.event",
                role="victim",
                lane_id=self.lane_id,
                idea_id=self.idea_id,
                tool_name="network",
                status="blocked" if event.blocked else "allow",
                text=event.destination_domain,
                metadata={
                    "method": event.method,
                    "port": event.destination_port,
                    "response_code": event.response_code,
                    "payload_size_bytes": event.payload_size_bytes,
                },
            )

    def record_inference(self, event: InferenceEvent) -> None:
        with self._record_lock:
            if self._terminated:
                return
            self.inference_log.append(event)
        if self._telemetry is not None:
            self._telemetry.agent_event(
                agent_id=self.lane_id,
                agent_kind="lane",
                event_type="tool.event",
                role="victim",
                lane_id=self.lane_id,
                idea_id=self.idea_id,
                tool_name="inference",
                status=event.routed_to,
                text=event.content_preview,
                metadata={
                    "pii_detected": event.pii_detected,
                    "pii_types": event.pii_types or [],
                },
            )

    def record_process(self, event: ProcessEvent) -> None:
        # Externally-recorded process events must always be reported, even
        # when host psutil sampling is disabled — keep them in a dedicated
        # list that result() always includes.
        with self._record_lock:
            if self._terminated:
                return
            self._external_process_events.append(event)
        if self._telemetry is not None:
            self._telemetry.agent_event(
                agent_id=self.lane_id,
                agent_kind="lane",
                event_type="tool.event",
                role="victim",
                lane_id=self.lane_id,
                idea_id=self.idea_id,
                tool_name="process",
                status="blocked" if event.blocked else "allow",
                text=event.process_name,
                metadata={
                    "pid": event.pid,
                    "syscall": event.syscall,
                    "syscall_args": event.syscall_args or [],
                    "inside_sandbox": event.inside_sandbox,
                },
            )

    def set_self_assessment(self, text: str) -> None:
        self.attacker_self_assessment = text

    def set_termination(self, reason: str) -> None:
        self._termination = reason

    def add_tokens(self, attacker: int = 0, victim: int = 0) -> None:
        self.attacker_tokens += attacker
        self.victim_tokens += victim

    # ------------------------------------------------------------------
    # Build the final LaneResult
    # ------------------------------------------------------------------
    def result(self) -> LaneResult:
        if self._fs_before is None or self._fs_after is None:
            raise RuntimeError("MonitoringHarness.stop() must be called before result()")
        fs_diff = diff_snapshots(self._fs_before, self._fs_after, self.cfg.allowed_paths)
        if self._telemetry is not None:
            for path in fs_diff.files_outside_allowed_paths:
                self._telemetry.file_write(
                    "harness", path=path, decision="deny",
                    reason_code="outside_allowed_path")
        mem_diff = diff_memory(self._mem_before or {}, self._mem_after or {})
        end_iso = _now()
        wall_ms = int((time.time() - self._started_at) * 1000)
        # Snapshot all collector lists under the lock and stop accepting new
        # record_* calls — an orphaned executor thread must not mutate these
        # lists while we copy them.
        with self._record_lock:
            self._terminated = True
            transcript = list(self.transcript)
            network_log = list(self.network_log)
            inference_log = list(self.inference_log)
            external_proc = list(self._external_process_events)
            turns = self._turns
        # Always include externally-recorded process events; add psutil
        # sampler events only when host process sampling was enabled.
        process_log = external_proc + (
            list(self._sampler.events) if self._monitor_processes else [])
        return LaneResult(
            lane_id=self.lane_id,
            idea_id=self.idea_id,
            zone_targeted=self.zone_id,
            start_time=self._start_iso,
            end_time=end_iso,
            wall_time_ms=wall_ms,
            turns_used=turns,
            tokens_used_attacker=self.attacker_tokens,
            tokens_used_victim=self.victim_tokens,
            termination_reason=self._termination,
            transcript=transcript,
            fs_diff=fs_diff,
            network_log=network_log,
            process_log=process_log,
            memory_diff=mem_diff,
            inference_routing_log=inference_log,
            attacker_self_assessment=self.attacker_self_assessment,
        )


# ---------------------------------------------------------------------------
# Helper for execution agents — return a closure-bound sink
# ---------------------------------------------------------------------------


def make_inference_router_hook(harness: MonitoringHarness) -> Callable[[dict], None]:
    """Returns a callable suitable for passing into a NemoClaw client as the
    `on_route` callback. Each call records an InferenceEvent."""

    def _hook(payload: dict) -> None:
        harness.record_inference(InferenceEvent(
            timestamp=_now(),
            routed_to=payload.get("routed_to", "cloud"),
            content_preview=str(payload.get("content", ""))[:200],
            pii_detected=bool(payload.get("pii_detected")),
            pii_types=payload.get("pii_types"),
        ))

    return _hook
