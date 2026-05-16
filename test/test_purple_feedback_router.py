"""Phase 4 — feedback_router converts purple findings into steering signals."""

from __future__ import annotations

from interfaces.types import ControlValidationRun, DetectionVerdict
from purple_team.feedback_router import FeedbackRouter


def _verdict(zone: str, quadrant: str) -> DetectionVerdict:
    prevention = "blocked" if quadrant in ("PASS", "WEAK") else "succeeded"
    observability = "observed" if quadrant in ("PASS", "PARTIAL") else "silent"
    return DetectionVerdict(
        execution_id="L1", session_id="L1", zone_id=zone, quadrant=quadrant,
        prevention=prevention, observability=observability,
        rule_id=None, evidence="{}")


def _run(regressions) -> ControlValidationRun:
    return ControlValidationRun(
        run_id="R1", kind="full", cases_total=3,
        cases_passed=3 - len(regressions), regressions=regressions,
        victim_build_id="mock", status="ok",
        created_at="2026-05-15T00:00:00Z")


def test_blind_zone_produces_a_red_priority_boost(server):
    server.log_detection_result(_verdict("SBX-NET", "FAIL"))
    router = FeedbackRouter(server)
    signals = router.route(verdicts=[_verdict("SBX-NET", "FAIL")],
                           validation_run=_run([]))
    gap = router.detection_coverage_gap()
    assert gap["SBX-NET"] > 0.0
    assert any("SBX-NET" in s for s in signals)


def test_partial_quadrant_is_pushed_to_blue_queue(server):
    router = FeedbackRouter(server)
    router.route(verdicts=[_verdict("PROMPT-INJ", "PARTIAL")],
                 validation_run=_run([]))
    # a PARTIAL (detection fired, prevention failed) becomes a blue task.
    assert any("PROMPT-INJ" in t for t in router.blue_tasks())


def test_regression_is_pushed_to_blue_queue(server):
    router = FeedbackRouter(server)
    router.route(verdicts=[],
                 validation_run=_run([{"case_id": "T02", "prior": "PASS",
                                       "now": "FAIL"}]))
    assert any("T02" in t for t in router.blue_tasks())


def test_routing_failure_does_not_raise(server):
    # a None validation_run must be tolerated (best-effort, spec §12).
    router = FeedbackRouter(server)
    signals = router.route(verdicts=[_verdict("SBX-FS", "PASS")],
                           validation_run=None)
    assert isinstance(signals, list)


def test_pass_only_cycle_routes_no_blue_tasks(server):
    router = FeedbackRouter(server)
    router.route(verdicts=[_verdict("SBX-FS", "PASS")],
                 validation_run=_run([]))
    assert router.blue_tasks() == []
