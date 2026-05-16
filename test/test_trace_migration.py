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
