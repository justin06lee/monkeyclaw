"""0007 — add idea_archive_cells.niche_descriptors. MAP-Elites persistence fidelity.

Adds a JSON column carrying the secondary descriptors of a cell's elite
(turn_bucket, transfer_score, tactic_tags, model) so the persistent grid is a
faithful mirror of the in-memory ArchiveEntry and load_from_cells can rehydrate
it. Backward compatible: existing rows read as '{}'.

ALTER TABLE ADD COLUMN is not idempotent, so probe PRAGMA table_info first —
the same pattern as 0004 (a fresh schema.sql bootstrap already has the column).
"""

from __future__ import annotations

import sqlite3


def migrate(conn: sqlite3.Connection) -> None:
    cols = {row[1] for row in conn.execute(
        "PRAGMA table_info(idea_archive_cells)").fetchall()}
    if "niche_descriptors" not in cols:
        conn.execute(
            "ALTER TABLE idea_archive_cells "
            "ADD COLUMN niche_descriptors TEXT NOT NULL DEFAULT '{}'"
        )
