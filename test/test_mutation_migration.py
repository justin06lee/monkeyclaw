"""Phase 0 — mutation-operator-learning migration + MCP round-trip."""

from __future__ import annotations

from infra.database import Database

NEW_TABLES = {"mutation_operator_stats_by_zone", "mutation_attempts"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_new_tables(db: Database):
    assert NEW_TABLES <= _table_names(db)


def test_mutation_operator_stats_has_new_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(mutation_operator_stats)")}
    assert {"squared_score", "last_lift"} <= cols


def test_mutation_attempts_has_lift_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(mutation_attempts)")}
    assert {"operator", "parent_idea_id", "child_idea_id",
            "parent_score", "child_score", "lift", "improved",
            "child_verdict"} <= cols


def test_schema_version_is_at_least_three(db: Database):
    row = db.fetchone(
        "SELECT value FROM schema_meta WHERE key='schema_version'")
    assert int(row["value"]) >= 3
