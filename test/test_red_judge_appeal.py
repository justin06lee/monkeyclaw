"""Judge ensemble — appeal path tests (judge-ensemble spec §7.2, §8)."""

from __future__ import annotations

from infra.database import Database

NEW_TABLES = {"appeal_verdicts", "attack_elo"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_appeal_and_elo_tables(db: Database):
    assert NEW_TABLES <= _table_names(db)


def test_appeal_verdicts_has_disagreement_columns(db: Database):
    cols = {r["name"] for r in db.fetchall("PRAGMA table_info(appeal_verdicts)")}
    assert {"appeal_id", "lane_id", "ensemble_verdict", "appeal_verdict",
            "disagreement", "ensemble_confidence", "appeal_confidence",
            "sided_with_roles", "errored"} <= cols


def test_attack_elo_has_rating_columns(db: Database):
    cols = {r["name"] for r in db.fetchall("PRAGMA table_info(attack_elo)")}
    assert {"zone_id", "attack_id", "rating", "comparisons",
            "wins", "losses"} <= cols


def test_judge_votes_gains_appeal_columns(db: Database):
    cols = {r["name"] for r in db.fetchall("PRAGMA table_info(judge_votes)")}
    assert {"is_appeal", "weight", "model"} <= cols


def test_schema_version_advances_past_migration(db: Database):
    # schema_meta is a key/value table; the migration runner sets
    # 'schema_version' to the highest applied ordinal.
    row = db.fetchone(
        "SELECT value FROM schema_meta WHERE key='schema_version'")
    assert int(row["value"]) >= 5
