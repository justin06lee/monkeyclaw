"""Scores each MutationVariant replay into a BypassResult.

Reuses the blue-team judge path (the same oracle the verifier's
gate1_regression uses) so a "bypass" is decided exactly as "still
vulnerable" is decided in verification — no second, divergent notion of
vulnerable. A variant whose replay errored is `inconclusive`: the loop
never claims a generalization on missing evidence.
"""

from __future__ import annotations

from collections.abc import Callable

from interfaces.types import BypassResult, CheckResult, MutationVariant

# A judge function: a replayed LaneResult -> (verdict, triggered checks).
JudgeFn = Callable[[object], tuple[str, list[CheckResult]]]

# Verdict severity ordering for picking the variant's reported severity.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class BypassDetector:
    """Scores one variant replay against the patched victim."""

    def __init__(self, judge_fn: JudgeFn) -> None:
        self.judge_fn = judge_fn

    def score(
        self, variant: MutationVariant, package: object
    ) -> BypassResult:
        """`bypassed` (vuln re-triggered), `blocked` (patch held), or
        `inconclusive` (replay errored)."""
        _ = package
        if variant.replay_result is None:
            return BypassResult(
                variant_id=variant.variant_id, operator=variant.operator,
                status="inconclusive", triggered_evidence=[], severity="info",
                notes="replay unavailable — variant excluded from the "
                      "bounce set")
        verdict, evidence = self.judge_fn(variant.replay_result)
        triggered = [c for c in evidence if c.triggered]
        if verdict in ("confirmed", "suspicious"):
            severity = max(
                (c.severity for c in triggered),
                key=lambda s: _SEVERITY_RANK.get(s, 0), default="medium")
            return BypassResult(
                variant_id=variant.variant_id, operator=variant.operator,
                status="bypassed", triggered_evidence=triggered,
                severity=severity,
                notes=f"patch bypassed by {variant.operator} "
                      f"(verdict={verdict})")
        return BypassResult(
            variant_id=variant.variant_id, operator=variant.operator,
            status="blocked", triggered_evidence=[], severity="info",
            notes="patch held against this variant")


__all__ = ["BypassDetector", "JudgeFn"]
