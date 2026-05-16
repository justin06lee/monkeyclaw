"""Phase 0 — purple-team shared type contracts."""

from __future__ import annotations

from dataclasses import fields

from interfaces.types import (
    ControlDecision,
    ControlValidationRun,
    DetectionCoverage,
    DetectionRule,
    DetectionRuleInput,
    DetectionVerdict,
    PurpleCycleResult,
    ReportCard,
    SelfGovernanceReport,
    SessionTimeline,
)


def test_detection_verdict_has_2x2_axes():
    fnames = {f.name for f in fields(DetectionVerdict)}
    assert {"quadrant", "prevention", "observability", "zone_id"} <= fnames


def test_quadrant_values_are_the_four_cells():
    v = DetectionVerdict(
        execution_id="L1", session_id="S1", zone_id="SBX-FS",
        quadrant="PASS", prevention="blocked", observability="observed",
        rule_id=None, evidence="{}",
    )
    assert v.quadrant == "PASS"


def test_control_decision_carries_observed_flag():
    d = ControlDecision(
        action_class="network.request", target="evil.test",
        decision="deny", observed=True, reason_code="blocked_domain",
        source="derived",
    )
    assert d.observed is True
    assert d.decision == "deny"


def test_detection_rule_input_has_appendix_d_shape():
    fnames = {f.name for f in fields(DetectionRuleInput)}
    assert {"zone_id", "source_finding_id", "logic",
            "expected_telemetry_signature", "response_action"} <= fnames


def test_detection_coverage_is_zero_to_one():
    c = DetectionCoverage(zone_id="SBX-FS", coverage_score=0.5,
                          sample_count=4, updated_at="2026-05-15T00:00:00Z")
    assert 0.0 <= c.coverage_score <= 1.0


def test_control_validation_run_kinds():
    r = ControlValidationRun(
        run_id="R1", kind="inline", cases_total=3, cases_passed=3,
        regressions=[], victim_build_id="mock", status="ok",
        created_at="2026-05-15T00:00:00Z",
    )
    assert r.kind in ("inline", "full")
    assert r.status in ("ok", "errored")


def test_session_timeline_aggregates_artifacts():
    fnames = {f.name for f in fields(SessionTimeline)}
    assert {"session_id", "finding", "telemetry_events",
            "control_decisions", "patches", "detection_rules"} <= fnames


def test_report_card_dimension_states_measured_and_target():
    fnames = {f.name for f in fields(ReportCard)}
    assert {"card_id", "generated_at", "dimensions", "summary"} <= fnames


def test_self_governance_report_flags_violations():
    fnames = {f.name for f in fields(SelfGovernanceReport)}
    assert {"checks", "violations", "passed"} <= fnames


def test_purple_cycle_result_carries_all_outputs():
    fnames = {f.name for f in fields(PurpleCycleResult)}
    assert {"verdicts", "validation_run", "report_card",
            "new_rules", "routed_signals"} <= fnames
