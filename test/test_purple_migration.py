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
