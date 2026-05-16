"""Main cycle loop — orchestrator.

Drives the red/blue cadence and ties all infrastructure together.

This file is the keystone runtime. It plugs in the agents that Persons 2 and 3
write via small adapter interfaces:

- `RedTeamPipeline` — implemented by Person 2. Produces ideas, executes, judges.
- `BluePipeline`    — implemented by Person 3. Reproduces, patches, verifies.

Both are duck-typed Protocols (`RedTeamPipeline`, `BluePipeline` below). On Day
8, Persons 2 and 3 hand us their real implementations and we wire them via the
two CLI flags `--red` and `--blue`. Until then, the orchestrator runs with the
no-op stubs in this module so the end-to-end loop can be exercised.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
from dataclasses import dataclass
from typing import Protocol

from infra.bootstrap import Runtime, boot
from infra.lane_scheduler import LaneScheduler
from infra.monitoring_harness import MonitoringHarness
from infra.sandbox_runs_store import SandboxRunsStore
from infra.sandbox_telemetry import SandboxTelemetryCapturer
from infra.telemetry import TelemetryEmitter
from interfaces.config_schema import LaneConfig
from interfaces.provisioning import VictimInstance
from interfaces.types import (
    CycleSummaryInput,
    IdeaObject,
    LaneResult,
)

LOG = logging.getLogger("monkeyclaw.orchestrator")


# ---------------------------------------------------------------------------
# Protocols for cross-team plug-ins
# ---------------------------------------------------------------------------


class RedTeamPipeline(Protocol):
    """Person 2's pipeline. Lives in red_team/ — orchestrator imports lazily."""

    def generate_ideas(self, cycle_id: int, n_lanes: int) -> list[IdeaObject]: ...
    def execute_lane(self, idea: IdeaObject, victim: VictimInstance,
                      harness: MonitoringHarness, lane_cfg: LaneConfig) -> None: ...
    def judge(self, lane_result: LaneResult) -> None: ...


class BluePipeline(Protocol):
    """Person 3's pipeline. Lives in blue_team/ — orchestrator imports lazily."""

    def process_repro_queue(self) -> int: ...    # returns # processed
    def process_blue_queue(self) -> int: ...     # returns # patches generated
    def run_regression(self) -> None: ...


# ---------------------------------------------------------------------------
# Built-in no-op stubs so the orchestrator runs before P2/P3 land
# ---------------------------------------------------------------------------


@dataclass
class StubRedTeam:
    """Generates trivial ideas + does nothing in the lane. Used pre-integration."""

    def generate_ideas(self, cycle_id: int, n_lanes: int) -> list[IdeaObject]:
        return [
            IdeaObject(
                idea_id=f"STUB-IDEA-{cycle_id}-{i}",
                cycle_id=cycle_id,
                zone_id="PROMPT-INJ",
                source_mode="creative",
                title=f"Stub idea {i}",
                approach="No-op placeholder until Person 2 lands.",
                success_criteria="never satisfied",
                estimated_turns=1,
                novelty_notes="-",
                priority_score=1.0 - 0.01 * i,
            )
            for i in range(n_lanes)
        ]

    def execute_lane(self, idea: IdeaObject, victim: VictimInstance,
                      harness: MonitoringHarness, lane_cfg: LaneConfig) -> None:
        # Pretend to do something useful — record one message so the harness
        # has data to return.
        from datetime import UTC, datetime

        from interfaces.types import Message
        harness.record_message(Message(
            role="attacker",
            content=f"[stub] would attack {idea.zone_id} with: {idea.approach}",
            timestamp=datetime.now(UTC).isoformat(),
        ))
        harness.set_self_assessment("stub: no real attack performed")
        harness.set_termination("idea_completed")

    def judge(self, lane_result: LaneResult) -> None:
        LOG.info("stub judge: lane=%s zone=%s — no verdict (stub)",
                  lane_result.lane_id, lane_result.zone_targeted)


@dataclass
class StubBlue:
    def process_repro_queue(self) -> int:
        return 0
    def process_blue_queue(self) -> int:
        return 0
    def run_regression(self) -> None:
        LOG.info("stub regression: no tests to run")


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class Orchestrator:
    def __init__(self, rt: Runtime,
                 red: RedTeamPipeline,
                 blue: BluePipeline) -> None:
        self.rt = rt
        self.red = red
        self.blue = blue
        self._stop = threading.Event()
        self._results_lock = threading.Lock()
        self._results: list[LaneResult] = []
        # Connect A5 telemetry: per-lane session events come from the
        # scheduler when it has the MCP handle; agent.mcp.invoked events come
        # from MCPServer once a telemetry emitter is attached.
        if hasattr(rt.mcp, "attach_telemetry"):
            rt.mcp.attach_telemetry(
                TelemetryEmitter(rt.mcp, session_id="orchestrator"))
        self.scheduler = LaneScheduler(
            lane_cfg=rt.cfg.lanes,
            nemoclaw_cfg=rt.cfg.nemoclaw,
            provisioner=rt.provisioner,
            executor=red.execute_lane,
            on_result=self._on_result,
            mcp=rt.mcp,
            sandbox_runs=SandboxRunsStore(rt.db),
            telemetry_capturer=SandboxTelemetryCapturer(
                rt.cfg.nemoclaw.cli_binary),
        )

    # ------------------------------------------------------------------
    def run(self) -> None:
        self.scheduler.start()
        self._install_signal_handlers()
        cycle_id = self._next_cycle_id()
        try:
            while not self._stop.is_set():
                self._run_cycle(cycle_id)
                cycle_id += 1
        finally:
            LOG.info("shutting down orchestrator")
            self.scheduler.shutdown(timeout=self.rt.cfg.orchestrator.graceful_shutdown_timeout_s)
            self.rt.shutdown()

    def _run_cycle(self, cycle_id: int) -> None:
        LOG.info("--- cycle %d ---", cycle_id)
        start = time.time()
        n = self.rt.cfg.lanes.pool_size
        results: list[LaneResult] = []
        ideas: list[IdeaObject] = []
        try:
            # Recover crashed-worker repro claims before this cycle's work.
            try:
                requeued = self.rt.mcp.sweep_stale_claims(
                    self.rt.cfg.orchestrator.stale_claim_timeout_s)
                if requeued:
                    LOG.warning("requeued %d stale repro claim(s)", requeued)
            except Exception as e:  # noqa: BLE001
                LOG.exception("stale-claim sweep failed in cycle %d: %s",
                              cycle_id, e)
            ideas = self.red.generate_ideas(cycle_id, n)
            for idea in ideas:
                self.scheduler.submit(idea)
            # Drain in-flight lanes before we leave the lane phase — no lane
            # may still be touching the sandbox when bookkeeping runs.
            self.scheduler.drain(
                timeout=self.rt.cfg.lanes.lane_timeout_seconds + 60)
            with self._results_lock:
                results = list(self._results)
                self._results.clear()
            for r in results:
                # One lane's judge failure must not abort the cycle — isolate
                # each, log it, and continue. Person 2's judge writes findings
                # via MCP; for the stub path, no findings are produced.
                try:
                    self.red.judge(r)
                except Exception as e:  # noqa: BLE001
                    LOG.exception("judge failed for lane %s (zone %s): %s",
                                  r.lane_id, r.zone_targeted, e)
            # Repro batch (blue side runs continuously, we nudge it per cycle).
            try:
                self.blue.process_repro_queue()
                self.blue.process_blue_queue()
            except Exception as e:  # noqa: BLE001
                LOG.exception("blue queue processing failed in cycle %d: %s",
                              cycle_id, e)
        except Exception as e:  # noqa: BLE001
            # A failure in the lane phase itself must not skip end-of-cycle
            # bookkeeping — fall through to the always-run block below.
            LOG.exception("cycle %d lane phase failed: %s", cycle_id, e)
        finally:
            self._finalize_cycle(cycle_id, ideas, results, start)

    def _finalize_cycle(self, cycle_id: int, ideas: list[IdeaObject],
                        results: list[LaneResult], start: float) -> None:
        """End-of-cycle bookkeeping that ALWAYS runs, even if lanes failed:
        write the cycle summary, decay unvisited-zone coverage, and run
        regression if configured."""
        confirmed = 0
        suspicious = 0
        zones = sorted({r.zone_targeted for r in results})
        # Person 2's judge writes findings to the DB during the judge loop
        # above — read back the real verdict counts for this cycle.
        try:
            cyc = self.rt.db.fetchall(
                "SELECT verdict FROM findings WHERE cycle_id = ?", (cycle_id,)
            )
            confirmed = sum(1 for f in cyc if f["verdict"] == "confirmed")
            suspicious = sum(1 for f in cyc if f["verdict"] == "suspicious")
        except Exception as e:  # noqa: BLE001
            LOG.warning("could not read cycle findings: %s", e)
        # `ideas` is only the lanes that were dispatched (top-N after dedup).
        # The red pipeline records the real pre-dedup ideation volume in
        # `_last_cycle_metrics` — use it so the summary reflects actual work.
        red_metrics = getattr(self.red, "_last_cycle_metrics", {}) or {}
        generated = red_metrics.get("ideas_generated", len(ideas))
        deduped = red_metrics.get("ideas_deduplicated", 0)
        executed = len(results)
        # ALWAYS write the cycle summary, even if the lane phase failed.
        # Append a per-role model-cost breakdown from the model_runs accounting.
        summary_text = (f"Cycle {cycle_id}: {generated} ideas generated, "
                        f"{executed} executed, "
                        f"{confirmed} confirmed, {suspicious} suspicious.")
        try:
            rollup = self.rt.mcp.get_model_cost_rollup()
            if rollup:
                cost_lines = "; ".join(
                    f"{r['role']}: {r['cost_usd']:.4f} USD / {r['runs']} runs"
                    for r in rollup
                )
                summary_text += f"\nModel cost by role — {cost_lines}"
        except Exception as e:  # noqa: BLE001 - reporting is best-effort
            LOG.warning("model cost rollup unavailable for cycle %d: %s", cycle_id, e)
        try:
            self.rt.mcp.log_cycle_summary(CycleSummaryInput(
                cycle_id=cycle_id,
                summary=summary_text,
                zones_targeted=zones,
                ideas_generated=generated,
                ideas_deduplicated=deduped,
                ideas_executed=executed,
                vulns_confirmed=confirmed,
                vulns_suspicious=suspicious,
                total_tokens_used=sum(
                    r.tokens_used_attacker + r.tokens_used_victim
                    for r in results),
                wall_time_seconds=time.time() - start,
            ))
        except Exception as e:  # noqa: BLE001
            LOG.exception("failed to write cycle %d summary: %s", cycle_id, e)
        # Telegram live-feed: one summary message per completed cycle. Routing
        # already alerts on each confirmed vuln individually; this is the
        # per-cycle digest. Delivered when a Telegram token is configured.
        try:
            self.rt.mcp.send_alert(
                f"Cycle {cycle_id} complete — {generated} ideas generated, "
                f"{executed} executed, {confirmed} confirmed, "
                f"{suspicious} suspicious. Zones: {', '.join(zones) or '-'}",
                severity="high" if confirmed else "info",
            )
        except Exception as e:  # noqa: BLE001
            LOG.warning("cycle-summary alert failed: %s", e)
        # ALWAYS apply coverage decay for unvisited zones.
        try:
            all_zones = {
                z.zone_id for z in self.rt.mcp.get_coverage_gaps(top_n=999)}
            for zid in all_zones - set(zones):
                self.rt.mcp.update_zone_coverage(zid, -0.01)
        except Exception as e:  # noqa: BLE001
            LOG.exception("unvisited-zone decay failed in cycle %d: %s",
                          cycle_id, e)
        # ALWAYS run regression at end of cycle if configured.
        if self.rt.cfg.orchestrator.regression_before_batch:
            try:
                self.blue.run_regression()
            except Exception as e:  # noqa: BLE001
                LOG.exception("regression failed in cycle %d: %s", cycle_id, e)

    # ------------------------------------------------------------------
    def _on_result(self, result: LaneResult) -> None:
        with self._results_lock:
            self._results.append(result)
        LOG.info("lane result: %s zone=%s turns=%d wall_ms=%d",
                  result.lane_id, result.zone_targeted, result.turns_used, result.wall_time_ms)

    def _next_cycle_id(self) -> int:
        row = self.rt.db.fetchone("SELECT MAX(cycle_id) AS m FROM cycle_log")
        return ((row["m"] or 0) + 1) if row else 1

    def _install_signal_handlers(self) -> None:
        def _handle(signum, _frame):  # noqa: ANN001
            LOG.warning("received signal %d — stopping after current cycle", signum)
            self._stop.set()
        try:
            signal.signal(signal.SIGINT, _handle)
            signal.signal(signal.SIGTERM, _handle)
        except ValueError:
            # Not in main thread (e.g. when run from tests) — caller must stop us.
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_pipeline(dotted: str | None, fallback, rt: Runtime | None = None):
    """Instantiate a pipeline class loaded from a dotted path.

    Tries calling `cls(rt)` first so pipelines that want a Runtime get one
    for free; falls back to `cls()` for the stub path and for legacy
    pipelines that bootstrap themselves.
    """
    if dotted is None:
        return fallback
    import importlib
    import inspect
    mod_name, _, attr = dotted.rpartition(":")
    if not mod_name:
        raise SystemExit(f"--red/--blue must be 'module.path:Class', got {dotted!r}")
    mod = importlib.import_module(mod_name)
    cls = getattr(mod, attr)
    if rt is not None:
        try:
            sig = inspect.signature(cls)
            if len(sig.parameters) >= 1:
                return cls(rt)
        except (TypeError, ValueError):
            pass
    return cls()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MonkeyClaw orchestrator")
    parser.add_argument("--config", default=None)
    parser.add_argument("--use-mock-provisioner", action="store_true",
                        help="Skip the nemoclaw CLI; use the in-memory provisioner.")
    parser.add_argument("--red", default=None,
                        help="Dotted path to Person 2's pipeline, e.g. red_team.pipeline:Pipeline")
    parser.add_argument("--blue", default=None,
                        help="Dotted path to Person 3's pipeline, e.g. blue_team.pipeline:Pipeline")
    parser.add_argument("--max-cycles", type=int, default=0,
                        help="If >0, exit after this many cycles. 0 = run forever.")
    parser.add_argument("--dev", action="store_true",
                        help="Dev mode: use the host machine's `claude` CLI "
                             "as the LLM (no Anthropic API key required). "
                             "Equivalent to MC_LLM_BACKEND=claude_cli.")
    args = parser.parse_args(argv)

    if args.dev:
        import os as _os  # noqa: PLC0415
        _os.environ.setdefault("MC_LLM_BACKEND", "claude_cli")

    rt = boot(args.config, use_mock_provisioner=args.use_mock_provisioner)
    red = _load_pipeline(args.red, StubRedTeam(), rt=rt)
    blue = _load_pipeline(args.blue, StubBlue(), rt=rt)

    orch = Orchestrator(rt, red, blue)
    if args.max_cycles > 0:
        # Wrap _run_cycle to stop after N
        original = orch._run_cycle
        count = {"n": 0}
        def limited(cycle_id: int) -> None:
            original(cycle_id)
            count["n"] += 1
            if count["n"] >= args.max_cycles:
                orch._stop.set()
        orch._run_cycle = limited  # type: ignore[method-assign]
    try:
        orch.run()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
