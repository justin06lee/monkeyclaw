"""0009 — mutation operator learning (mutation-operator-learning §8).

Adds squared_score / last_lift columns to mutation_operator_stats and creates
the mutation_operator_stats_by_zone and mutation_attempts tables. Forward-only
and idempotent: ALTER TABLE ADD COLUMN is not idempotent, so probe
PRAGMA table_info first — schema.sql already carries these on a fresh bootstrap.
The runner wraps this body in its own transaction.
"""

from __future__ import annotations

import sqlite3


def migrate(conn: sqlite3.Connection) -> None:
    cols = {row[1] for row in conn.execute(
        "PRAGMA table_info(mutation_operator_stats)").fetchall()}
    if "squared_score" not in cols:
        conn.execute(
            "ALTER TABLE mutation_operator_stats "
            "ADD COLUMN squared_score REAL NOT NULL DEFAULT 0.0"
        )
    if "last_lift" not in cols:
        conn.execute(
            "ALTER TABLE mutation_operator_stats "
            "ADD COLUMN last_lift REAL NOT NULL DEFAULT 0.0"
        )

    conn.execute(
        "CREATE TABLE IF NOT EXISTS mutation_operator_stats_by_zone ("
        "    operator      TEXT NOT NULL,"
        "    zone_id       TEXT NOT NULL,"
        "    uses          INTEGER NOT NULL DEFAULT 0,"
        "    successes     INTEGER NOT NULL DEFAULT 0,"
        "    avg_score     REAL NOT NULL DEFAULT 0.0,"
        "    squared_score REAL NOT NULL DEFAULT 0.0,"
        "    last_lift     REAL NOT NULL DEFAULT 0.0,"
        "    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),"
        "    PRIMARY KEY (operator, zone_id)"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS mutation_attempts ("
        "    attempt_id       TEXT PRIMARY KEY,"
        "    cycle_id         INTEGER NOT NULL,"
        "    zone_id          TEXT NOT NULL,"
        "    operator         TEXT NOT NULL,"
        "    parent_idea_id   TEXT NOT NULL,"
        "    child_idea_id    TEXT NOT NULL,"
        "    parent_score     REAL NOT NULL,"
        "    child_score      REAL NOT NULL,"
        "    lift             REAL NOT NULL,"
        "    improved         INTEGER NOT NULL DEFAULT 0,"
        "    child_verdict    TEXT NOT NULL,"
        "    created_at       TEXT NOT NULL DEFAULT (datetime('now'))"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_mutation_attempts_op "
        "ON mutation_attempts(operator, zone_id, created_at)"
    )
