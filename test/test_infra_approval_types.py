"""Phase 0 — approval-service shared type contracts."""

from __future__ import annotations

from dataclasses import fields

from interfaces.types import (
    ApprovalEvent,
    ApprovalEventInput,
    ApprovalOutcome,
    ApprovalRequest,
    PullRequestDraft,
)


def test_approval_request_has_lifecycle_fields():
    fnames = {f.name for f in fields(ApprovalRequest)}
    assert {"request_id", "patch_id", "vuln_ids", "zone_id", "severity",
            "posture", "ask_expiry", "generalization_status",
            "created_at", "status"} <= fnames


def test_approval_event_carries_decision_and_approver():
    e = ApprovalEvent(
        event_id="E1", request_id="R1", patch_id="P1", vuln_ids=["MC-1"],
        zone_id="SBX-FS", severity="high", decision="allow",
        posture="require_approval", approver="operator", reason="reviewed",
        ask_expiry=None, grant_expiry=None, generalization_status=None,
        pr_url=None, created_at="2026-05-15T00:00:00Z",
    )
    assert e.decision == "allow"
    assert e.approver == "operator"


def test_approval_event_input_is_the_write_shape():
    fnames = {f.name for f in fields(ApprovalEventInput)}
    # event_id + created_at are server-filled, so absent from the write shape.
    assert "event_id" not in fnames
    assert {"request_id", "patch_id", "vuln_ids", "zone_id", "severity",
            "decision", "posture", "approver", "reason"} <= fnames


def test_approval_outcome_kinds():
    o = ApprovalOutcome(decision="PENDING", request_id="R1", event=None)
    assert o.decision in ("ALLOW", "DENY", "PENDING")


def test_pull_request_draft_shape():
    fnames = {f.name for f in fields(PullRequestDraft)}
    assert {"branch", "pr_url", "commit_sha", "created_at"} <= fnames


def test_approvals_config_defaults():
    from interfaces.config_schema import MonkeyClawConfig

    cfg = MonkeyClawConfig()
    ap = cfg.approvals
    assert ap.posture.critical == "require_approval"
    assert ap.posture.high == "require_approval"
    assert ap.posture.medium == "auto_allow"
    assert ap.posture.low == "auto_allow"
    assert ap.ask_expiry_hours == 72
    assert ap.grant_expiry_hours == 0
    assert ap.auto_pr is False
    assert ap.operator_id == "operator"
    assert ap.pr_base_branch == "master"
