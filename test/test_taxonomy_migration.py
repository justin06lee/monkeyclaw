"""Phase 0 — migration 0005 creates the three technique tables."""

from __future__ import annotations

from infra.database import Database

TECHNIQUE_TABLES = {
    "idea_techniques",
    "finding_techniques",
    "technique_coverage",
}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_technique_tables(db: Database):
    assert TECHNIQUE_TABLES <= _table_names(db)


def test_idea_techniques_has_resolved_by_column(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(idea_techniques)")}
    assert {"idea_id", "technique_kind", "technique_id",
            "corpus_version", "resolved_by", "created_at"} <= cols


def test_technique_coverage_primary_key(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(technique_coverage)")}
    assert {"zone_id", "technique_kind", "technique_id",
            "attempts", "confirmations", "last_seen_at"} <= cols
