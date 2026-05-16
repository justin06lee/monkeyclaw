"""Phase 0 — migration creates the real-provisioner tables."""

from __future__ import annotations

from infra.database import Database

PROVISIONER_TABLES = {"victim_snapshots", "sandbox_runs"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_provisioner_tables(db: Database):
    assert PROVISIONER_TABLES <= _table_names(db)


def test_sandbox_runs_has_mode_and_capabilities(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(sandbox_runs)")}
    assert {"run_id", "instance_id", "lane_id", "mode", "deterministic",
            "patch_applied", "capabilities"} <= cols


def test_victim_snapshots_has_patched_and_base(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(victim_snapshots)")}
    assert {"snapshot_id", "name", "sandbox_id", "deterministic",
            "patched", "base_snapshot"} <= cols
