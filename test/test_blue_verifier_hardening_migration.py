"""Phase 0 — migration creates the two hardening tables."""

from __future__ import annotations

from infra.database import Database

HARDENING_TABLES = {
    "patch_variant_results",
    "patch_detection_results",
}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_hardening_tables(db: Database):
    assert HARDENING_TABLES <= _table_names(db)


def test_patch_variant_results_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(patch_variant_results)")}
    assert {"result_id", "patch_id", "vuln_id", "operator",
            "variant_hash", "blocked", "judge_verdict"} <= cols


def test_patch_detection_results_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(patch_detection_results)")}
    assert {"result_id", "patch_id", "vuln_id", "zone_id", "quadrant",
            "observability", "prevention", "passed", "evidence"} <= cols
