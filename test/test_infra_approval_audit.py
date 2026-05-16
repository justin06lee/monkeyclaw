"""Phase 1 — approval_events is an append-only audit log."""

from __future__ import annotations

from infra.approval_service import ApprovalService
from interfaces.config_schema import ApprovalsConfig
from interfaces.types import PatchCandidate


def _patch(patch_id: str) -> PatchCandidate:
    return PatchCandidate(
        patch_id=patch_id, vuln_ids=["MC-2026-0042"], zone_id="SBX-FS",
        approach="bounds-check", invasiveness="low", diff="--- a\n+++ b\n",
        explanation="fix", side_effects="none", status="approved",
    )


class _StubDispatcher:
    def send(self, message: str, severity: str) -> None:
        pass


def _service(server) -> ApprovalService:
    return ApprovalService(mcp=server, dispatcher=_StubDispatcher(),
                           cfg=ApprovalsConfig())


def test_every_state_change_adds_a_row(server):
    svc = _service(server)
    outcome = svc.request(_patch("PA"), severity="high")
    svc.resolve(outcome.request_id, decision="allow",
                approver="alice", reason="ok")
    events = server.get_approval_events(patch_id="PA")
    # ask + allow = exactly two rows; nothing mutated in place.
    assert len(events) == 2
    assert [e.decision for e in events] == ["ask", "allow"]


def test_auto_allow_writes_one_row_with_no_ask(server):
    svc = _service(server)
    svc.request(_patch("PB"), severity="low")
    events = server.get_approval_events(patch_id="PB")
    assert len(events) == 1
    assert events[0].decision == "allow"
    assert events[0].posture == "auto_allow"


def test_lifecycle_reconstructs_from_request_id(server):
    svc = _service(server)
    outcome = svc.request(_patch("PC"), severity="critical")
    svc.resolve(outcome.request_id, decision="deny",
                approver="bob", reason="unsafe")
    events = [e for e in server.get_approval_events(patch_id="PC")
              if e.request_id == outcome.request_id]
    decisions = [e.decision for e in events]
    # The full lifecycle of one request_id is recoverable from its rows.
    assert decisions == ["ask", "deny"]
