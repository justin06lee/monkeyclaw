"""Converts a round's most-severe bypass into a re-patch constraint.

A bypassing BypassResult becomes a BypassConstraint and an augmented
FixTask whose recommended_approach gains the constraint directive, so the
next PatchGenerator.generate_for_task call sees the bypass as a first-class
requirement rather than buried prose. No PatchGenerator signature change.
"""

from __future__ import annotations

from dataclasses import replace

from interfaces.types import BypassConstraint, BypassResult, Message

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def build(
    task: object,
    bypass_results: list[BypassResult],
    bypassing_transcripts: dict[str, list[Message]],
) -> tuple[object, BypassConstraint]:
    """Pick the highest-severity confirmed bypass, build a BypassConstraint,
    and return an augmented FixTask. `bypassing_transcripts` maps operator
    name -> the mutated transcript that bypassed the patch."""
    bypassed = [r for r in bypass_results if r.status == "bypassed"]
    if not bypassed:
        raise ValueError("build() requires at least one bypassed result")
    worst = max(bypassed, key=lambda r: _SEVERITY_RANK.get(r.severity, 0))
    transcript = bypassing_transcripts.get(worst.operator, [])
    directive = (
        f"The patch must ALSO block the variant produced by the "
        f"`{worst.operator}` mutation operator "
        f"(severity {worst.severity}): the same attack survived the patch "
        f"after this transformation. Constrain the fix to cover this "
        f"variant, not only the literal original transcript.")
    constraint = BypassConstraint(
        constraint_id=f"BC-{worst.operator}",
        operator=worst.operator,
        bypassing_transcript=transcript,
        directive=directive,
        evidence=worst.triggered_evidence,
    )
    augmented = replace(
        task,
        recommended_approach=(
            f"{getattr(task, 'recommended_approach', '')}\n\n"
            f"[GENERALIZATION CONSTRAINT] {directive}").strip(),
    )
    return augmented, constraint


__all__ = ["build"]
