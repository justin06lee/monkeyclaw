"""§9.5 invariant: a DB built from schema.sql and a DB built by applying every
migration to an empty DB must have identical sqlite_master (tables, indexes,
columns)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import sqlite_vec

from infra.database import SCHEMA_PATH
from infra.migrations import MIGRATIONS_DIR, run_pending


def _connect(path: Path) -> sqlite3.Connection:
    """A connection with sqlite-vec loaded — schema.sql uses vec0 tables."""
    conn = sqlite3.connect(path)
    conn.enable_load_extension(True)
    sqlite_vec.load(conn)
    conn.enable_load_extension(False)
    return conn


def _schema_signature(conn: sqlite3.Connection) -> set[tuple[str, str]]:
    rows = conn.execute(
        "SELECT type, name FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL"
    ).fetchall()
    sig: set[tuple[str, str]] = set()
    for typ, name in rows:
        if typ == "table":
            cols = conn.execute(f"PRAGMA table_info({name})").fetchall()
            for col in cols:
                sig.add(("column", f"{name}.{col[1]} {col[2]}"))
        sig.add((typ, name))
    return sig


def test_schema_sql_matches_migrated_from_empty(tmp_path: Path) -> None:
    bootstrap = _connect(tmp_path / "bootstrap.db")
    bootstrap.executescript(SCHEMA_PATH.read_text())

    migrated = _connect(tmp_path / "migrated.db")
    migrated.executescript(SCHEMA_PATH.read_text())
    migrated.execute("DELETE FROM schema_meta WHERE key LIKE 'migration:%'")
    run_pending(migrated, MIGRATIONS_DIR)

    boot_sig = _schema_signature(bootstrap)
    mig_sig = _schema_signature(migrated)
    assert boot_sig == mig_sig, (
        f"only in schema.sql: {boot_sig - mig_sig}\n"
        f"only in migrations: {mig_sig - boot_sig}"
    )
    bootstrap.close()
    migrated.close()
