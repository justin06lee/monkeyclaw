"""Phase 2 — the monkeyclaw approvals CLI subcommand."""

from __future__ import annotations

import pytest

from infra.approval_service import ApprovalService
from infra.cli import main
from infra.database import Database
from infra.mcp_server import MCPServer
from interfaces.config_schema import ApprovalsConfig
from interfaces.types import PatchCandidate


def _patch(patch_id: str) -> PatchCandidate:
    return PatchCandidate(
        patch_id=patch_id, vuln_ids=["MC-2026-0001"], zone_id="SBX-FS",
        approach="bounds-check", invasiveness="low", diff="--- a\n+++ b\n",
        explanation="fix", side_effects="none", status="approved",
    )


class _StubDispatcher:
    def send(self, message: str, severity: str) -> None:
        pass


@pytest.fixture
def cli_server(tmp_path, monkeypatch):
    """An MCPServer whose DB path the CLI's load_config() resolves to."""
    db_path = tmp_path / "approvals.db"
    monkeypatch.setenv("MC_STORAGE__DB_PATH", str(db_path))
    monkeypatch.setenv("MC_LLM_BACKEND", "mock")
    db = Database(db_path)
    server = MCPServer(db)
    yield server
    db.close()


def test_approvals_list_shows_pending(cli_server, capsys):
    svc = ApprovalService(mcp=cli_server, dispatcher=_StubDispatcher(),
                          cfg=ApprovalsConfig())
    svc.request(_patch("P1"), severity="high")
    rc = main(["approvals"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "P1" in out
    assert "pending" in out.lower()


def test_approvals_resolve_records_the_decision(cli_server, capsys):
    svc = ApprovalService(mcp=cli_server, dispatcher=_StubDispatcher(),
                          cfg=ApprovalsConfig())
    outcome = svc.request(_patch("P2"), severity="high")
    rc = main(["approvals", "resolve", outcome.request_id,
               "--allow", "--reason", "looks good"])
    assert rc == 0
    events = cli_server.get_approval_events(patch_id="P2")
    assert any(e.decision == "allow" and e.reason == "looks good"
               for e in events)
