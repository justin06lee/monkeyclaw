"""Phase 0 — migration 0014 adds the chain tables + findings.chain_id."""

from __future__ import annotations

from infra.database import Database


def _tables(db: Database) -> set[str]:
    return {r["name"] for r in db.fetchall(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(db: Database, table: str) -> set[str]:
    return {r["name"] for r in db.fetchall(f"PRAGMA table_info({table})")}


def test_chain_tables_created(tmp_path):
    db = Database(str(tmp_path / "mc.db"))
    try:
        tables = _tables(db)
        assert {"attack_chains", "chain_findings",
                "chain_step_results"} <= tables
    finally:
        db.close()


def test_findings_gains_chain_id_column(tmp_path):
    db = Database(str(tmp_path / "mc.db"))
    try:
        assert "chain_id" in _columns(db, "findings")
    finally:
        db.close()


def test_chain_id_is_nullable(tmp_path):
    db = Database(str(tmp_path / "mc.db"))
    try:
        cols = {r["name"]: r for r in db.fetchall("PRAGMA table_info(findings)")}
        assert cols["chain_id"]["notnull"] == 0
    finally:
        db.close()


def test_migration_0014_recorded(tmp_path):
    db = Database(str(tmp_path / "mc.db"))
    try:
        keys = {r["key"] for r in db.fetchall(
            "SELECT key FROM schema_meta WHERE key LIKE 'migration:%'")}
        assert "migration:0014" in keys
    finally:
        db.close()
