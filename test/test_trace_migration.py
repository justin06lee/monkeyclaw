"""Phase 0 — migration 0017 creates the trace + pairwise tables."""

from __future__ import annotations

from infra.database import Database

TRACE_TABLES = {"attempt_traces", "pairwise_labels"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_trace_tables(db: Database):
    assert TRACE_TABLES <= _table_names(db)


def test_attempt_traces_has_feature_and_label_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(attempt_traces)")}
    assert {"trace_id", "idea_id", "cycle_id", "zone_id",
            "feature_schema_version", "idea_summary", "tactic_tags",
            "mutation_operator", "interaction_style", "progress_dims",
            "judge_scores", "token_cost", "repro_outcome", "judge_verdict",
            "search_score", "archive_niche", "usefulness_label"} <= cols


def test_pairwise_labels_has_preference_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(pairwise_labels)")}
    assert {"pair_id", "trace_a", "trace_b", "preferred",
            "judge_confidence"} <= cols


def test_feature_schema_version_recorded(db: Database):
    rows = db.fetchall(
        "SELECT value FROM schema_meta WHERE key='feature_schema_version'")
    assert rows and int(rows[0]["value"]) >= 1


def _trace_input(idea_id="IDEA1", zone="PROMPT-INJ", verdict="clean"):
    from interfaces.types import AttemptTraceInput

    return AttemptTraceInput(
        idea_id=idea_id, cycle_id=1, zone_id=zone, feature_schema_version=1,
        idea_summary="probe the victim", tactic_tags=["roleplay"],
        mutation_operator="paraphrase", interaction_style="direct",
        progress_dims={"risk_stage": 3.0, "boundary_erosion": 2.0},
        judge_scores={"safety": 0.4, "progress": 0.6}, token_cost=120,
        judge_verdict=verdict, search_score=4.2,
        archive_niche=f"{zone}|direct|partial_compliance",
        usefulness_label=0.55)


def test_mcp_logs_and_reads_attempt_trace(server):
    tid = server.log_attempt_trace(_trace_input())
    assert tid.startswith("TRC")
    rows = server.get_attempt_traces(zone_id="PROMPT-INJ")
    assert len(rows) == 1
    assert rows[0].judge_verdict == "clean"
    assert rows[0].progress_dims["risk_stage"] == 3.0


def test_mcp_attaches_repro_outcome(server):
    tid = server.log_attempt_trace(_trace_input())
    server.attach_repro_outcome(tid, "reproduced")
    row = server.get_attempt_traces()[0]
    assert row.repro_outcome == "reproduced"


def test_mcp_logs_pairwise_label(server):
    from interfaces.types import PreferenceInput

    a = server.log_attempt_trace(_trace_input(idea_id="A"))
    b = server.log_attempt_trace(_trace_input(idea_id="B"))
    pid = server.log_pairwise_label(PreferenceInput(
        trace_a=a, trace_b=b, preferred="a", judge_confidence=0.8))
    assert pid.startswith("PRF")
    prefs = server.get_pairwise_labels()
    assert len(prefs) == 1 and prefs[0].preferred == "a"
