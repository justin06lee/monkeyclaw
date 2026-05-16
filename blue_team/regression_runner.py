"""Regression runner — Deliverable 9.

Executes the full active regression suite. Two trigger points:

- **Post-patch** — called by the patch verifier as Gate 3 in
  `blue_team.patch_verifier.PatchVerifier`. (That path runs tests
  in-process via `execute_test_script`.)
- **Pre-red-team-batch / standalone** — called by the orchestrator before
  each new red team batch. Produces a `RegressionRunResult` with coverage
  delta that informs ideation.

Per-test tracking we maintain in-memory:
- `last_run_at`, `last_run_result`, `consecutive_passes`. The MCP schema
  exposes these fields but the current mock MCP doesn't allow in-place
  test updates — we surface the deltas via the result object so the
  caller (pipeline glue) can decide how to persist.

Coverage delta: for every passing test we issue
`update_zone_coverage(zone_id, +0.02)` (small bump — the test was already
known to pass) so an idle suite doesn't decay. For NEWLY-FAILING tests we
issue a negative delta on their zone to reflect lost confidence.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.provisioning import VictimProvisioner
from interfaces.types import (
    PolicyConfig,
    RegressionRunResult,
    RegressionTest,
)

from blue_team._common import default_policy, now_iso
from blue_team.replay_minimizer import (
    JudgeFn,
    ReplayFn,
    default_judge,
    make_mock_replay_fn,
)
from blue_team.test_generator import execute_test_script

LOG = logging.getLogger("monkeyclaw.blue.regression")


# ---------------------------------------------------------------------------
# Tracking state — process-local, mirrors what would persist in the DB
# ---------------------------------------------------------------------------


@dataclass
class _TestRunRecord:
    last_run_at: str = ""
    last_run_result: str = ""  # "pass" | "fail" | "error"
    consecutive_passes: int = 0
    # Flakiness tracking: every time a result differs from the previous
    # one, that is a transition. A test with >= `flaky_min_transitions`
    # transitions has oscillated and cannot be trusted.
    transitions: int = 0

    def is_flaky(self, min_transitions: int) -> bool:
        return self.transitions >= min_transitions


@dataclass
class RegressionRunnerConfig:
    coverage_bump_passing: float = 0.02
    coverage_penalty_regressed: float = -0.10
    # A test that flips pass<->fail at least this many times is flaky.
    # 2 transitions == pass->fail->pass (or the inverse): a true
    # oscillation, not a one-way regression.
    flaky_min_transitions: int = 2


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class RegressionRunner:
    def __init__(
        self,
        mcp: MonkeyClawMCP,
        provisioner: VictimProvisioner,
        *,
        cfg: RegressionRunnerConfig | None = None,
        policy: PolicyConfig | None = None,
        replay_fn: ReplayFn | None = None,
        judge_fn: JudgeFn | None = None,
    ) -> None:
        self.mcp = mcp
        self.provisioner = provisioner
        self.cfg = cfg or RegressionRunnerConfig()
        self.policy = policy or default_policy()
        self.replay_fn = replay_fn or make_mock_replay_fn()
        self.judge_fn = judge_fn or default_judge
        # test_id → record
        self._records: dict[str, _TestRunRecord] = {}
        self._previous_test_ids: set[str] = set()

    # ------------------------------------------------------------------
    def run(self) -> RegressionRunResult:
        suite = list(self.mcp.get_regression_suite())
        started = time.time()
        previous_ids = set(self._previous_test_ids)
        current_ids = {t.test_id for t in suite}
        new_since_last = len(current_ids - previous_ids)

        passing = 0
        failing = 0
        newly_failing: list[str] = []
        zones_seen: dict[str, list[bool]] = {}  # zone → list of pass bools

        for test in suite:
            outcome = self._run_one(test)
            zones_seen.setdefault(test.zone_id, []).append(outcome)
            rec = self._records.setdefault(test.test_id, _TestRunRecord())
            previous_result = rec.last_run_result
            previous_pass = previous_result == "pass"
            new_result = "pass" if outcome else "fail"
            # A transition is any change of result from the prior run.
            if previous_result and previous_result != new_result:
                rec.transitions += 1
            rec.last_run_at = now_iso()
            rec.last_run_result = new_result
            try:
                self.mcp.record_regression_run(test.test_id, new_result)
            except Exception as e:  # noqa: BLE001
                LOG.warning("record_regression_run(%s) failed: %s",
                            test.test_id, e)
            if outcome:
                rec.consecutive_passes += 1
                passing += 1
            else:
                # Newly failing: previously passing OR previously unrecorded
                if previous_pass or not previous_result:
                    newly_failing.append(test.test_id)
                rec.consecutive_passes = 0
                failing += 1

        # Compute coverage delta and apply to MCP.
        newly_failing_set = set(newly_failing)
        regressed_zones = {
            t.zone_id for t in suite if t.test_id in newly_failing_set
        }
        coverage_delta: dict[str, float] = {}
        for zone, results in zones_seen.items():
            if all(results):
                delta = self.cfg.coverage_bump_passing
            elif any(not r for r in results) and zone in regressed_zones:
                delta = self.cfg.coverage_penalty_regressed
            else:
                # Mixed results, no new regression — neutral.
                delta = 0.0
            if delta != 0.0:
                try:
                    self.mcp.update_zone_coverage(zone, delta)
                except Exception as e:  # noqa: BLE001
                    LOG.warning("update_zone_coverage(%s, %s) failed: %s",
                                 zone, delta, e)
            coverage_delta[zone] = delta

        # Update the previous-id set for next run.
        self._previous_test_ids = current_ids

        # Flaky tests: still in the suite and oscillating across runs.
        flaky_tests = sorted(
            tid for tid in current_ids
            if self._records[tid].is_flaky(self.cfg.flaky_min_transitions)
        )

        for tid in flaky_tests:
            try:
                self.mcp.record_regression_run(tid, "fail", flaky=True)
            except Exception as e:  # noqa: BLE001
                LOG.warning("quarantine(%s) failed: %s", tid, e)
        # A newly-failing permanent regression test means a fixed vuln is
        # live again — reopen the finding(s) behind it.
        suite_by_id = {t.test_id: t for t in suite}
        for tid in newly_failing:
            test = suite_by_id.get(tid)
            if test is None:
                continue
            for fid in self._finding_ids_for_vuln(test.vuln_id):
                try:
                    self.mcp.reopen_finding(
                        fid, f"regression {tid} ({test.vuln_id}) failed")
                except Exception as e:  # noqa: BLE001
                    LOG.warning("reopen_finding(%s) failed: %s", fid, e)

        result = RegressionRunResult(
            total_tests=len(suite),
            tests_passing=passing,
            tests_failing=failing,
            newly_failing=newly_failing,
            coverage_delta=coverage_delta,
            new_tests_since_last_run=new_since_last,
            run_duration_seconds=time.time() - started,
            flaky_tests=flaky_tests,
        )
        LOG.info(
            "regression: total=%d pass=%d fail=%d newly_failing=%d "
            "flaky=%d new_since_last=%d duration=%.2fs",
            result.total_tests, result.tests_passing, result.tests_failing,
            len(result.newly_failing), len(result.flaky_tests),
            result.new_tests_since_last_run, result.run_duration_seconds,
        )
        return result

    # ------------------------------------------------------------------
    def _finding_ids_for_vuln(self, vuln_id: str) -> list[str]:
        try:
            return list(self.mcp.findings_for_vuln(vuln_id))
        except Exception as e:  # noqa: BLE001
            LOG.warning("findings_for_vuln(%s) failed: %s", vuln_id, e)
            return []

    # ------------------------------------------------------------------
    def _run_one(self, test: RegressionTest) -> bool:
        try:
            outcome = execute_test_script(
                test.test_script,
                replay_fn=self.replay_fn,
                judge_fn=self.judge_fn,
                policy=self.policy,
                provisioner=self.provisioner,
            )
        except Exception as e:  # noqa: BLE001
            LOG.warning("test %s exploded: %s", test.test_id, e)
            return False
        return bool(outcome.get("passed"))

    # ------------------------------------------------------------------
    def record(self, test_id: str) -> _TestRunRecord:
        """Inspection helper — exposes in-memory state for the pipeline."""
        return self._records.get(test_id, _TestRunRecord())


__all__ = [
    "RegressionRunner",
    "RegressionRunnerConfig",
]
