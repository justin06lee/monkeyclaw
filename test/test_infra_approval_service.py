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
