"""Phase 0 — approval_events migration creates the audit table."""

from __future__ import annotations

from infra.database import Database


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_approval_events(db: Database):
    assert "approval_events" in _table_names(db)


def test_approval_events_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(approval_events)")}
    assert {"event_id", "request_id", "patch_id", "vuln_ids", "zone_id",
            "severity", "decision", "posture", "approver", "reason",
            "ask_expiry", "grant_expiry", "generalization_status",
            "pr_url", "created_at"} <= cols
