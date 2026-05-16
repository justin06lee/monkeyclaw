"""Phase 0 — migration 0005 creates the two trajectory tables."""

from __future__ import annotations

from infra.database import Database

TRAJECTORY_TABLES = {"trajectory_scores", "near_misses"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_trajectory_tables(db: Database):
    assert TRAJECTORY_TABLES <= _table_names(db)


def test_trajectory_scores_has_shape_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(trajectory_scores)")}
    assert {"trajectory_id", "lane_id", "idea_id", "zone_id", "max_stage",
            "final_stage", "erosion_slope", "stalled_at_turn", "monotonic",
            "turn_scores"} <= cols


def test_near_misses_has_consumed_flag(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(near_misses)")}
    assert {"near_miss_id", "idea_id", "zone_id", "max_stage",
            "stalled_at_turn", "erosion_excerpt", "useful_components",
            "mutation_seeds", "consumed"} <= cols


def test_schema_version_bumped(db: Database):
    row = db.fetchall(
        "SELECT value FROM schema_meta WHERE key='schema_version'")[0]
    assert int(row["value"]) >= 3
