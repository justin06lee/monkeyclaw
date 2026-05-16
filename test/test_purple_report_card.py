"""Phase 3 — report_card produces a measured-vs-target security report card."""

from __future__ import annotations

from interfaces.types import DetectionVerdict
from purple_team.report_card import ReportCardGenerator

RUBRIC_DIMENSIONS = {
    "secret_protection",
    "network_governance",
    "approval_precision",
    "mcp_governance",
    "prompt_injection_handling",
    "audit_completeness",
    "developer_usability",
}


def _verdict(zone: str, quadrant: str) -> DetectionVerdict:
    prevention = "blocked" if quadrant in ("PASS", "WEAK") else "succeeded"
    observability = "observed" if quadrant in ("PASS", "PARTIAL") else "silent"
    return DetectionVerdict(
        execution_id="L1", session_id="L1", zone_id=zone, quadrant=quadrant,
        prevention=prevention, observability=observability,
        rule_id=None, evidence="{}")


def test_report_card_has_all_seven_rubric_dimensions(server):
    card = ReportCardGenerator(server).generate()
    assert {d.name for d in card.dimensions} == RUBRIC_DIMENSIONS


def test_every_dimension_states_a_target_labelled_aspirational(server):
    card = ReportCardGenerator(server).generate()
    for d in card.dimensions:
        # constraint 3: a target is never asserted as a verified fact.
        assert d.target_is_aspirational is True
        assert 0.0 <= d.measured <= 1.0
        assert 0.0 <= d.target <= 1.0


def test_measured_value_reflects_detection_results(server):
    # network_governance maps from SBX-NET detection results.
    server.log_detection_result(_verdict("SBX-NET", "PASS"))
    server.log_detection_result(_verdict("SBX-NET", "PASS"))
    server.log_detection_result(_verdict("SBX-NET", "FAIL"))
    card = ReportCardGenerator(server).generate()
    net = next(d for d in card.dimensions if d.name == "network_governance")
    # 2 of 3 observed -> measured 0.666...
    assert abs(net.measured - 2 / 3) < 1e-6
    assert net.evidence_count == 3


def test_dimension_with_no_evidence_is_zero_measured(server):
    card = ReportCardGenerator(server).generate()
    sp = next(d for d in card.dimensions if d.name == "secret_protection")
    assert sp.measured == 0.0
    assert sp.evidence_count == 0


def test_report_card_is_persisted_and_retrievable(server):
    ReportCardGenerator(server).generate()
    assert server.get_latest_report_card() is not None


def test_summary_never_asserts_a_target_as_fact(server):
    card = ReportCardGenerator(server).generate()
    lowered = card.summary.lower()
    assert "verified" not in lowered or "target" in lowered
