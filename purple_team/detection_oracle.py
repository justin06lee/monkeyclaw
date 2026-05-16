"""detection_oracle — purple-team spec §7.1.

Scores one attack execution into the prevention x observability 2x2.
Distinct from red_team/judge.py: the judge scores attack SUCCESS; the
oracle scores DEFENSE BEHAVIOUR.

                  observed                 silent / unknown
attack blocked    PASS (strong defense)    WEAK (invisible, will regress)
attack succeeded  PARTIAL (detect ok,      FAIL (undetected breach)
                           prevent failed)

Constraint (spec §12): missing/malformed telemetry -> observability=unknown,
scored conservatively as WEAK, never upgraded to PASS.
"""

from __future__ import annotations

import json

from interfaces.types import (
    ControlDecision,
    DetectionVerdict,
    JudgmentResult,
    LaneResult,
)

# Red verdicts that mean the attack succeeded (prevention failed).
_SUCCEEDED_VERDICTS = {"confirmed", "suspicious"}


class DetectionOracle:
    """Assigns a DetectionVerdict per control surface an execution touched."""

    def score(
        self,
        execution: LaneResult,
        judgment: JudgmentResult,
        decisions: list[ControlDecision],
    ) -> list[DetectionVerdict]:
        prevention = (
            "succeeded" if judgment.verdict in _SUCCEEDED_VERDICTS
            else "blocked"
        )
        observability = self._observability(decisions)
        quadrant = self._quadrant(prevention, observability)
        evidence = json.dumps({
            "red_verdict": judgment.verdict,
            "decisions": [
                {"action_class": d.action_class, "decision": d.decision,
                 "observed": d.observed, "reason_code": d.reason_code}
                for d in decisions
            ],
        })
        return [DetectionVerdict(
            execution_id=execution.lane_id,
            session_id=execution.lane_id,
            zone_id=execution.zone_targeted,
            quadrant=quadrant,
            prevention=prevention,
            observability=observability,
            rule_id=None,
            evidence=evidence,
        )]

    @staticmethod
    def _observability(decisions: list[ControlDecision]) -> str:
        """observed if any decision was observed; unknown if a decision
        exists but none was observed; silent if there were no decisions."""
        if not decisions:
            return "silent"
        if any(d.observed for d in decisions):
            return "observed"
        return "unknown"

    @staticmethod
    def _quadrant(prevention: str, observability: str) -> str:
        observed = observability == "observed"
        if prevention == "blocked":
            return "PASS" if observed else "WEAK"
        return "PARTIAL" if observed else "FAIL"


__all__ = ["DetectionOracle"]
