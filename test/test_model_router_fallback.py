import shutil

import pytest

from infra.config import load_config
from interfaces.llm import LLMClient, LLMMessage, LLMResponse
from interfaces.model_router import ModelRouter


class _BoomLLM(LLMClient):
    """Always raises on complete()."""
    name = "boom"

    def complete(self, messages, system="", max_tokens=2000, temperature=0.7):
        raise RuntimeError("provider down")


class _OkLLM(LLMClient):
    """Always returns a fixed response."""
    name = "ok"

    def __init__(self, text="recovered"):
        self._text = text

    def complete(self, messages, system="", max_tokens=2000, temperature=0.7):
        return LLMResponse(text=self._text, input_tokens=10, output_tokens=5)


class _RecordingMCP:
    """Captures log_model_run calls."""

    def __init__(self):
        self.runs = []

    def log_model_run(self, run):
        self.runs.append(run)
        return f"RUN-{len(self.runs)}"


def _router_with_clients(monkeypatch, clients):
    """Build a router whose chain factory yields `clients` in order."""
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    cfg = load_config()
    mcp = _RecordingMCP()
    router = ModelRouter(cfg, mcp=mcp)
    it = iter(clients)
    monkeypatch.setattr(router, "_client_for_route", lambda route: next(it))
    return router, mcp


def test_fallback_returns_second_client_response(monkeypatch):
    router, mcp = _router_with_clients(monkeypatch, [_BoomLLM(), _OkLLM("recovered")])
    client = router.client_for("red_ideation")
    resp = client.complete([LLMMessage(role="user", content="hi")])
    assert resp.text == "recovered"


def test_fallback_writes_two_model_runs_rows(monkeypatch):
    router, mcp = _router_with_clients(monkeypatch, [_BoomLLM(), _OkLLM()])
    client = router.client_for("red_ideation")
    client.complete([LLMMessage(role="user", content="hi")])
    assert len(mcp.runs) == 2
    assert mcp.runs[0].success is False
    assert mcp.runs[0].error and "provider down" in mcp.runs[0].error
    assert mcp.runs[1].success is True
    assert mcp.runs[0].role == "red_ideation"
    assert mcp.runs[1].role == "red_ideation"


def test_exhausted_chain_reraises(monkeypatch):
    router, mcp = _router_with_clients(
        monkeypatch, [_BoomLLM(), _BoomLLM(), _BoomLLM(), _BoomLLM()])
    client = router.client_for("red_ideation")
    with pytest.raises(RuntimeError, match="provider down"):
        client.complete([LLMMessage(role="user", content="hi")])
    # Every attempt was still recorded as a failed row.
    assert len(mcp.runs) >= 2
    assert all(r.success is False for r in mcp.runs)
