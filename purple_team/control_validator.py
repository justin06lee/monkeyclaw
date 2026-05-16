"""control_validator — purple-team spec §7.3, §10.

Runs the canonical control corpus against the CURRENT victim build and
reports drift. Two cadences:
  - validate_inline(zone_id): the cycle's-zone subset, every cycle.
  - validate_full(): the entire corpus, on a schedule (spec §10).

A case that regressed from a prior PASS is flagged. Validator failures
(victim unreachable) produce a run with status='errored', never a silent
skip (spec §12).

The case_runner callable maps one PolicyCorpusCase to the victim's
observed decision; it is injected so the validator is testable in mock
mode with zero model credentials.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import ControlValidationRun
from red_team.policy_corpus import PolicyCorpusCase, load_corpus

LOG = logging.getLogger("monkeyclaw.purple.validator")

CaseRunner = Callable[[PolicyCorpusCase], str]


def _now() -> str:
    return datetime.now(UTC).isoformat()


class ControlValidator:
    """Inline + full corpus validation with drift detection."""

    def __init__(
        self,
        mcp: MonkeyClawMCP,
        *,
        corpus: list[PolicyCorpusCase] | None = None,
        case_runner: CaseRunner,
        victim_build_id: str = "mock",
    ) -> None:
        self.mcp = mcp
        self.corpus = corpus if corpus is not None else load_corpus()
        self.case_runner = case_runner
        self.victim_build_id = victim_build_id
        # Per-instance memory of the most recent passing case ids, used to
        # flag a case that regressed from a prior PASS.
        self._last_passing: set[str] = set()

    def validate_inline(self, zone_id: str) -> ControlValidationRun:
        cases = [c for c in self.corpus if c.zone == zone_id]
        return self._run("inline", cases)

    def validate_full(self) -> ControlValidationRun:
        return self._run("full", list(self.corpus))

    # ------------------------------------------------------------------
    def _run(
        self, kind: str, cases: list[PolicyCorpusCase]
    ) -> ControlValidationRun:
        prior_pass = set(self._last_passing)
        passed = 0
        regressions: list[dict] = []
        status = "ok"
        results: dict[str, bool] = {}
        for case in cases:
            try:
                observed = self.case_runner(case)
            except Exception as e:  # noqa: BLE001
                LOG.warning("validation case %s errored: %s", case.case_id, e)
                status = "errored"
                results[case.case_id] = False
                continue
            ok = observed == case.expected_decision
            results[case.case_id] = ok
            if ok:
                passed += 1
            elif case.case_id in prior_pass:
                regressions.append({
                    "case_id": case.case_id, "prior": "PASS", "now": "FAIL"})
        run = ControlValidationRun(
            run_id="",
            kind=kind,
            cases_total=len(cases),
            cases_passed=passed,
            regressions=regressions,
            victim_build_id=self.victim_build_id,
            status=status,
            created_at=_now(),
        )
        run.run_id = self.mcp.log_control_validation_run(run)
        self._last_passing = {cid for cid, ok in results.items() if ok}
        return run


__all__ = ["ControlValidator", "CaseRunner"]
