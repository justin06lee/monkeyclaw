from infra.mock_mcp import MockMCP
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
