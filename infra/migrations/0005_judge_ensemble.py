"""0005 — judge-ensemble appeal + Elo tables (judge-ensemble spec §8).

Adds appeal_verdicts + attack_elo tables and three columns to judge_votes.
Forward-only. ALTER TABLE ADD COLUMN is not idempotent, so probe
PRAGMA table_info first — this migration must be a verified no-op on a
fresh DB already bootstrapped from the up-to-date schema.sql, and a real
delta on an existing schema_version-4 DB.
"""

from __future__ import annotations

import sqlite3

_APPEAL_VERDICTS = """\
CREATE TABLE IF NOT EXISTS appeal_verdicts (
    appeal_id           TEXT PRIMARY KEY,
    lane_id             TEXT NOT NULL,
    ensemble_verdict    TEXT NOT NULL,
    appeal_verdict      TEXT NOT NULL,
    disagreement        REAL NOT NULL,
    ensemble_confidence REAL NOT NULL,
    appeal_confidence   REAL NOT NULL,
    failure_class       TEXT NOT NULL DEFAULT 'none',
    severity            TEXT NOT NULL DEFAULT 'low',
    sided_with_roles    TEXT NOT NULL DEFAULT '[]',
    reasoning           TEXT NOT NULL DEFAULT '',
    model               TEXT NOT NULL DEFAULT '',
    errored             INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
)"""

_ATTACK_ELO = """\
CREATE TABLE IF NOT EXISTS attack_elo (
    zone_id      TEXT NOT NULL,
    attack_id    TEXT NOT NULL,
    rating       REAL NOT NULL DEFAULT 1000.0,
    comparisons  INTEGER NOT NULL DEFAULT 0,
    wins         INTEGER NOT NULL DEFAULT 0,
    losses       INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (zone_id, attack_id)
)"""

_JUDGE_VOTES_COLUMNS = (
    ("is_appeal", "INTEGER NOT NULL DEFAULT 0"),
    ("weight", "REAL NOT NULL DEFAULT 1.0"),
    ("model", "TEXT NOT NULL DEFAULT ''"),
)


def migrate(conn: sqlite3.Connection) -> None:
    conn.execute(_APPEAL_VERDICTS)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_appeal_verdicts_lane "
        "ON appeal_verdicts(lane_id)")
    conn.execute(_ATTACK_ELO)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attack_elo_zone "
        "ON attack_elo(zone_id, rating)")

    cols = {row[1] for row in conn.execute(
        "PRAGMA table_info(judge_votes)").fetchall()}
    for name, decl in _JUDGE_VOTES_COLUMNS:
        if name not in cols:
            conn.execute(f"ALTER TABLE judge_votes ADD COLUMN {name} {decl}")
