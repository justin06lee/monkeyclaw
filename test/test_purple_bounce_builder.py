"""Phase 2 — turning a bypass into a re-patch constraint."""

from __future__ import annotations

from dataclasses import dataclass

from interfaces.types import BypassResult, CheckResult, Message
from purple_team.bounce_builder import build


@dataclass
class _StubTask:
    """A minimal FixTask stand-in carrying just recommended_approach."""

    task_id: str = "T1"
    recommended_approach: str = "Block the original key-exfil path."
    severity: str = "high"


def _bypass(operator: str, severity: str) -> BypassResult:
    return BypassResult(
        variant_id="V-" + operator, operator=operator, status="bypassed",
        triggered_evidence=[CheckResult(
            check_name="net", triggered=True, severity=severity)],
        severity=severity, notes="")


def _transcript(operator: str) -> list[Message]:
    return [Message(role="attacker", content=f"mutated via {operator}",
                    timestamp="2026-05-15T00:00:00Z")]


def test_build_picks_the_highest_severity_bypass():
    task = _StubTask()
    results = [_bypass("paraphrase", "medium"),
               _bypass("insert_untrusted_document", "critical")]
    transcripts = {"paraphrase": _transcript("paraphrase"),
                   "insert_untrusted_document":
                       _transcript("insert_untrusted_document")}
    _, constraint = build(task, results, transcripts)
    assert constraint.operator == "insert_untrusted_document"


def test_augmented_task_appends_the_directive_to_recommended_approach():
    task = _StubTask()
    original = task.recommended_approach
    results = [_bypass("paraphrase", "high")]
    new_task, constraint = build(
        task, results, {"paraphrase": _transcript("paraphrase")})
    assert original in new_task.recommended_approach
    assert constraint.directive in new_task.recommended_approach
    assert "paraphrase" in constraint.directive


def test_constraint_carries_the_bypassing_transcript_and_evidence():
    task = _StubTask()
    results = [_bypass("change_persona", "high")]
    _, constraint = build(
        task, results, {"change_persona": _transcript("change_persona")})
    assert constraint.bypassing_transcript == _transcript("change_persona")
    assert constraint.evidence
    assert constraint.evidence[0].triggered is True


def test_build_ignores_blocked_and_inconclusive_results():
    task = _StubTask()
    blocked = BypassResult(
        variant_id="V1", operator="paraphrase", status="blocked",
        triggered_evidence=[], severity="info", notes="")
    bypassed = _bypass("add_benign_framing", "high")
    _, constraint = build(
        task, [blocked, bypassed],
        {"add_benign_framing": _transcript("add_benign_framing")})
    assert constraint.operator == "add_benign_framing"
