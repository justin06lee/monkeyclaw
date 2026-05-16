"""Phase 0 — migration 0005 creates the five purple-team tables."""

from __future__ import annotations

from infra.database import Database

PURPLE_TABLES = {
    "detection_rules",
    "detection_results",
    "detection_coverage",
    "control_validation_runs",
    "report_cards",
}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall(
        "SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_purple_tables(db: Database):
    assert PURPLE_TABLES <= _table_names(db)


def test_detection_results_has_quadrant_column(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(detection_results)")}
    assert {"quadrant", "prevention", "observability",
            "zone_id", "session_id"} <= cols


def test_control_validation_runs_records_kind_and_status(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(control_validation_runs)")}
    assert {"kind", "status", "regressions", "victim_build_id"} <= cols


def test_mcp_logs_and_reads_detection_result(server):
    from interfaces.types import DetectionVerdict

    server.log_detection_result(DetectionVerdict(
        execution_id="L1", session_id="S1", zone_id="SBX-FS",
        quadrant="FAIL", prevention="succeeded", observability="silent",
        rule_id=None, evidence='{"k": 1}',
    ))
    rows = server.get_detection_results(zone_id="SBX-FS")
    assert len(rows) == 1
    assert rows[0].quadrant == "FAIL"


def test_mcp_logs_detection_rule_and_assigns_id(server):
    from interfaces.types import DetectionRuleInput

    rid = server.log_detection_rule(DetectionRuleInput(
        zone_id="SBX-NET", source_finding_id="F1",
        logic="net.request to non-allowlisted domain",
        expected_telemetry_signature="agent.network.request decision=deny",
        response_action="block_and_alert",
    ))
    assert rid.startswith("RULE")
    rules = server.get_detection_rules(zone_id="SBX-NET")
    assert len(rules) == 1 and rules[0].rule_id == rid


def test_mcp_upserts_detection_coverage(server):
    from interfaces.types import DetectionCoverage

    server.upsert_detection_coverage(DetectionCoverage(
        zone_id="SBX-FS", coverage_score=0.4, sample_count=2,
        updated_at="2026-05-15T00:00:00Z"))
    server.upsert_detection_coverage(DetectionCoverage(
        zone_id="SBX-FS", coverage_score=0.6, sample_count=5,
        updated_at="2026-05-15T01:00:00Z"))
    cov = server.get_detection_coverage("SBX-FS")
    assert cov.coverage_score == 0.6 and cov.sample_count == 5


def test_mcp_logs_and_reads_validation_run(server):
    from interfaces.types import ControlValidationRun

    server.log_control_validation_run(ControlValidationRun(
        run_id="", kind="inline", cases_total=3, cases_passed=2,
        regressions=[{"case_id": "T01", "prior": "PASS", "now": "FAIL"}],
        victim_build_id="mock", status="ok", created_at=""))
    runs = server.get_control_validation_runs(kind="inline")
    assert len(runs) == 1 and runs[0].cases_total == 3


def test_mcp_logs_and_reads_report_card(server):
    from interfaces.types import ReportCard, ReportCardDimension

    cid = server.log_report_card(ReportCard(
        card_id="", generated_at="",
        dimensions=[ReportCardDimension(
            name="secret_protection", measured=0.9, target=1.0,
            target_is_aspirational=True, evidence_count=10)],
        summary="ok"))
    assert cid.startswith("CARD")
    latest = server.get_latest_report_card()
    assert latest is not None and latest.summary == "ok"
