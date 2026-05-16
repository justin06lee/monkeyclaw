"""Phase 1 — the approval service: request / resolve / expire."""

from __future__ import annotations

from infra.approval_service import ApprovalService
from interfaces.config_schema import ApprovalsConfig
from interfaces.types import PatchCandidate


def _patch(patch_id: str = "P1", zone: str = "SBX-FS") -> PatchCandidate:
    return PatchCandidate(
        patch_id=patch_id, vuln_ids=["MC-2026-0001"], zone_id=zone,
        approach="bounds-check", invasiveness="low", diff="--- a\n+++ b\n",
        explanation="fix", side_effects="none", status="approved",
    )


class _StubDispatcher:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send(self, message: str, severity: str) -> None:
        self.sent.append((message, severity))


class _RaisingDispatcher:
    def send(self, message: str, severity: str) -> None:
        raise RuntimeError("telegram down")


def _service(server, dispatcher=None, cfg=None) -> ApprovalService:
    return ApprovalService(
        mcp=server,
        dispatcher=dispatcher or _StubDispatcher(),
        cfg=cfg or ApprovalsConfig(),
    )


def test_auto_allow_records_a_single_allow_event(server):
    svc = _service(server)
    outcome = svc.request(_patch(), severity="low")
    assert outcome.decision == "ALLOW"
    assert outcome.event is not None
    events = server.get_approval_events(patch_id="P1")
    assert len(events) == 1
    assert events[0].decision == "allow"
    assert events[0].approver == "system"
    assert events[0].posture == "auto_allow"


def test_require_approval_creates_a_pending_request(server):
    disp = _StubDispatcher()
    svc = _service(server, dispatcher=disp)
    outcome = svc.request(_patch("P2"), severity="high")
    assert outcome.decision == "PENDING"
    pending = svc.list_pending()
    assert any(r.patch_id == "P2" for r in pending)
    # A notification was routed at the patch severity.
    assert disp.sent and disp.sent[0][1] == "high"
    assert "approvals resolve" in disp.sent[0][0]


def test_unconverged_forces_require_approval_for_low_severity(server):
    svc = _service(server)
    outcome = svc.request(_patch("P3"), severity="low",
                          generalization="unconverged")
    assert outcome.decision == "PENDING"


def test_notification_failure_leaves_request_pending(server):
    svc = _service(server, dispatcher=_RaisingDispatcher())
    outcome = svc.request(_patch("P4"), severity="critical")
    # Delivery failed but the request still exists and is pending.
    assert outcome.decision == "PENDING"
    assert any(r.patch_id == "P4" for r in svc.list_pending())


def test_resolve_allow_writes_resolution_event(server):
    svc = _service(server)
    outcome = svc.request(_patch("P5"), severity="high")
    event = svc.resolve(outcome.request_id, decision="allow",
                        approver="alice", reason="reviewed the diff")
    assert event.decision == "allow"
    assert event.approver == "alice"
    # The request is no longer pending.
    assert not any(r.request_id == outcome.request_id
                   for r in svc.list_pending())


def test_resolve_deny_writes_deny_event(server):
    svc = _service(server)
    outcome = svc.request(_patch("P6"), severity="critical")
    event = svc.resolve(outcome.request_id, decision="deny",
                        approver="bob", reason="weakens the control plane")
    assert event.decision == "deny"


def test_second_resolve_on_same_request_is_rejected(server):
    svc = _service(server)
    outcome = svc.request(_patch("P7"), severity="high")
    svc.resolve(outcome.request_id, decision="allow",
                approver="alice", reason="ok")
    try:
        svc.resolve(outcome.request_id, decision="deny",
                    approver="alice", reason="changed my mind")
    except ValueError as e:
        assert "already resolved" in str(e).lower()
    else:
        raise AssertionError("expected ValueError on double-resolve")


def test_expire_stale_lapses_an_overdue_ask(server):
    from datetime import UTC, datetime, timedelta

    cfg = ApprovalsConfig(ask_expiry_hours=1)
    svc = _service(server, cfg=cfg)
    outcome = svc.request(_patch("P8"), severity="high")
    # Sweep with a "now" two hours in the future -> the ask has lapsed.
    future = datetime.now(UTC) + timedelta(hours=2)
    expired = svc.expire_stale(now=future)
    assert any(e.request_id == outcome.request_id and e.decision == "expired"
               for e in expired)
    assert not any(r.request_id == outcome.request_id
                   for r in svc.list_pending())


def test_expire_stale_lapses_an_overdue_grant(server):
    from datetime import UTC, datetime, timedelta

    cfg = ApprovalsConfig(grant_expiry_hours=1)
    svc = _service(server, cfg=cfg)
    outcome = svc.request(_patch("P9"), severity="high")
    svc.resolve(outcome.request_id, decision="allow",
                approver="alice", reason="ok")
    future = datetime.now(UTC) + timedelta(hours=2)
    expired = svc.expire_stale(now=future)
    assert any(e.request_id == outcome.request_id and e.decision == "expired"
               for e in expired)
