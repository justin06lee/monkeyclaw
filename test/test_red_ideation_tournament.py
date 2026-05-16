"""Model ideation tournament — schema + head-to-head tests
(model-ideation-tournament spec §8, §9)."""

from __future__ import annotations

from infra.database import Database

NEW_TABLES = {"model_zone_winrate", "model_tournament_rounds"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_tournament_tables(db: Database):
    assert NEW_TABLES <= _table_names(db)


def test_model_zone_winrate_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(model_zone_winrate)")}
    assert {"zone_id", "model_label", "role", "h2h_wins", "h2h_comparisons",
            "confirmed", "suspicious", "ideas_executed", "winrate"} <= cols


def test_model_tournament_rounds_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(model_tournament_rounds)")}
    assert {"round_id", "cycle_id", "zone_id", "entrants",
            "pairwise", "winner_label"} <= cols


def test_schema_version_advanced_for_tournament(db: Database):
    row = db.fetchone(
        "SELECT value FROM schema_meta WHERE key='schema_version'")
    assert int(row["value"]) >= 13
