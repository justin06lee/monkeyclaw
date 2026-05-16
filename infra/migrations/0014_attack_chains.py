"""0014 — cross-zone attack chaining (cross-zone-attack-chaining spec §8).

Adds three tables — attack_chains, chain_findings, chain_step_results — for
kill chains, their cross-zone findings, and the per-step execution trace;
plus an additive nullable back-reference column findings.chain_id so a
single-zone finding can name its parent chain.

Forward-only and idempotent: ALTER TABLE ADD COLUMN is not idempotent, so
probe PRAGMA table_info first — schema.sql already carries findings.chain_id
on a fresh bootstrap. The runner wraps this body in its own transaction.

Ordinal 0014: assigned at merge time after the model ideation tournament
migration (0013).
"""

from __future__ import annotations

import sqlite3


def migrate(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS attack_chains ("
        "    chain_id        TEXT PRIMARY KEY,"
        "    cycle_id        INTEGER NOT NULL,"
        "    title           TEXT NOT NULL,"
        "    zones           TEXT NOT NULL DEFAULT '[]',"
        "    primary_zone    TEXT NOT NULL,"
        "    steps           TEXT NOT NULL DEFAULT '[]',"
        "    builds_on       TEXT NOT NULL DEFAULT '[]',"
        "    estimated_turns INTEGER NOT NULL DEFAULT 15,"
        "    created_at      TEXT NOT NULL DEFAULT (datetime('now'))"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attack_chains_cycle "
        "ON attack_chains(cycle_id)"
    )

    conn.execute(
        "CREATE TABLE IF NOT EXISTS chain_findings ("
        "    chain_finding_id TEXT PRIMARY KEY,"
        "    chain_id         TEXT NOT NULL,"
        "    cycle_id         INTEGER NOT NULL,"
        "    zones_traversed  TEXT NOT NULL DEFAULT '[]',"
        "    terminal_zone    TEXT NOT NULL,"
        "    severity         TEXT NOT NULL,"
        "    verdict          TEXT NOT NULL,"
        "    landed_steps     TEXT NOT NULL DEFAULT '[]',"
        "    evidence         TEXT NOT NULL DEFAULT '{}',"
        "    repro_status     TEXT NOT NULL DEFAULT 'pending',"
        "    created_at       TEXT NOT NULL DEFAULT (datetime('now'))"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_chain_findings_chain "
        "ON chain_findings(chain_id)"
    )

    conn.execute(
        "CREATE TABLE IF NOT EXISTS chain_step_results ("
        "    chain_id        TEXT NOT NULL,"
        "    step_index      INTEGER NOT NULL,"
        "    zone_id         TEXT NOT NULL,"
        "    landed          INTEGER NOT NULL DEFAULT 0,"
        "    produced_tokens TEXT NOT NULL DEFAULT '[]',"
        "    turn_span       TEXT NOT NULL DEFAULT '[0,0]',"
        "    progress_score  REAL NOT NULL DEFAULT 0.0,"
        "    PRIMARY KEY (chain_id, step_index)"
        ")"
    )

    cols = {row[1] for row in conn.execute(
        "PRAGMA table_info(findings)").fetchall()}
    if "chain_id" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN chain_id TEXT")
