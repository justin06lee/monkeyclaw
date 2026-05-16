"""0004 — add regression_tests.run_state and backfill from last_run_result.

pass -> passing; fail/error -> failing; NULL -> untested.
ALTER TABLE ADD COLUMN is not idempotent, so probe PRAGMA table_info first.
"""

from __future__ import annotations

import sqlite3


def migrate(conn: sqlite3.Connection) -> None:
    cols = {row[1] for row in conn.execute(
        "PRAGMA table_info(regression_tests)").fetchall()}
    if "run_state" not in cols:
        conn.execute(
            "ALTER TABLE regression_tests "
            "ADD COLUMN run_state TEXT NOT NULL DEFAULT 'untested'"
        )
    conn.execute(
        "UPDATE regression_tests SET run_state = "
        "CASE "
        "  WHEN last_run_result = 'pass' THEN 'passing' "
        "  WHEN last_run_result IN ('fail', 'error') THEN 'failing' "
        "  ELSE 'untested' "
        "END"
    )
