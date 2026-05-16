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


def test_mcp_logs_and_reads_approval_event(server):
    from interfaces.types import ApprovalEventInput

    server.log_approval_event(ApprovalEventInput(
        request_id="R1", patch_id="P1", vuln_ids=["MC-1"], zone_id="SBX-FS",
        severity="low", decision="allow", posture="auto_allow",
        approver="system", reason="auto-allow: severity=low",
    ))
    events = server.get_approval_events(patch_id="P1")
    assert len(events) == 1
    assert events[0].decision == "allow"
    assert events[0].vuln_ids == ["MC-1"]


def test_mcp_pending_request_is_an_ask_with_no_resolution(server):
    from interfaces.types import ApprovalEventInput

    server.log_approval_event(ApprovalEventInput(
        request_id="R2", patch_id="P2", vuln_ids=["MC-2"], zone_id="SBX-NET",
        severity="high", decision="ask", posture="require_approval",
        approver="system", reason="awaiting human review",
        ask_expiry="2099-01-01T00:00:00Z",
    ))
    pending = server.get_pending_approvals()
    assert any(p.request_id == "R2" and p.status == "pending"
               for p in pending)


def test_mcp_resolved_request_drops_out_of_pending(server):
    from interfaces.types import ApprovalEventInput

    server.log_approval_event(ApprovalEventInput(
        request_id="R3", patch_id="P3", vuln_ids=["MC-3"], zone_id="SBX-FS",
        severity="high", decision="ask", posture="require_approval",
        approver="system", reason="ask",
        ask_expiry="2099-01-01T00:00:00Z"))
    server.log_approval_event(ApprovalEventInput(
        request_id="R3", patch_id="P3", vuln_ids=["MC-3"], zone_id="SBX-FS",
        severity="high", decision="allow", posture="require_approval",
        approver="operator", reason="approved"))
    pending_ids = {p.request_id for p in server.get_pending_approvals()}
    assert "R3" not in pending_ids
