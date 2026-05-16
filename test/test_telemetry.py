import sqlite3
from pathlib import Path

from infra.mock_mcp import MockMCP
from infra.orchestrator import main as orch_main
from infra.telemetry import TelemetryEmitter, bounded_excerpt, content_hash


def test_bounded_excerpt_truncates():
    assert bounded_excerpt("x" * 1000, limit=64) == "x" * 64
    assert bounded_excerpt("short", limit=64) == "short"


def test_content_hash_is_stable_and_not_raw():
    h = content_hash("super-secret-value")
    assert "secret" not in h
    assert h == content_hash("super-secret-value")
    assert len(h) == 64  # sha256 hex


def test_emitter_writes_session_lifecycle():
    mcp = MockMCP(verbose=False)
    em = TelemetryEmitter(mcp, session_id="S1")
    em.session_started(actor="orchestrator", repo="monkeyclaw", branch="main")
    em.file_read(actor="attacker", path="/etc/passwd", data_class="secret",
                 decision="deny", reason_code="denied_host_path")
    em.session_finished(actor="orchestrator", final_status="ok")
    tl = mcp.get_session_timeline("S1")
    assert [e.event_type for e in tl] == [
        "agent.session.started", "agent.file.read", "agent.session.finished"]
    assert tl[1].decision == "deny"


def test_emitter_never_stores_raw_secret():
    mcp = MockMCP(verbose=False)
    em = TelemetryEmitter(mcp, session_id="S2")
    em.file_read(actor="attacker", path="/x", data_class="secret",
                 raw_content="AKIA-EXAMPLE-SECRET-KEY")
    ev = mcp.get_session_timeline("S2")[0]
    assert "AKIA" not in (ev.excerpt or "")
    assert ev.content_hash is not None


def test_mcp_server_emits_invoked_event(server):
    """Any MCP call records an agent.mcp.invoked event when a telemetry
    emitter is attached."""
    server.attach_telemetry(TelemetryEmitter(server, session_id="SVC"))
    server.get_coverage_gaps(3)
    tl = server.get_session_timeline("SVC")
    assert any(e.event_type == "agent.mcp.invoked" for e in tl)


def test_orchestrator_run_produces_session_timeline(tmp_path: Path, monkeypatch):
    """A5 acceptance: a real mock cycle drives the LaneScheduler through the
    orchestrator and lands per-lane session telemetry in the DB.

    This exercises the wiring fixed in orchestrator.py — the LaneScheduler is
    constructed with mcp=rt.mcp, so each lane emits session_started /
    session_finished events to the telemetry_events table.
    """
    db_path = tmp_path / "mc.db"
    monkeypatch.setenv("MC_STORAGE__DB_PATH", str(db_path))
    monkeypatch.setenv("MC_LOGGING__FILE", str(tmp_path / "mc.log"))
    monkeypatch.setenv("MC_LANES__POOL_SIZE", "2")
    monkeypatch.setenv("MC_LANES__LANE_TIMEOUT_SECONDS", "5")
    monkeypatch.setenv("MC_LLM_BACKEND", "mock")

    rc = orch_main(["--use-mock-provisioner", "--max-cycles", "1"])
    assert rc == 0

    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM telemetry_events").fetchone()[0]
        types = {
            r[0] for r in conn.execute(
                "SELECT DISTINCT event_type FROM telemetry_events").fetchall()
        }
    finally:
        conn.close()

    assert count > 0, "mock cycle produced no telemetry events"
    assert "agent.session.started" in types
    assert "agent.session.finished" in types
