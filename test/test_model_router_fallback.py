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


def test_red_pipeline_uses_router_clients():
    from infra.bootstrap import boot
    from red_team.pipeline import Pipeline
    rt = boot(use_mock_provisioner=True)
    try:
        pipe = Pipeline(runtime=rt)
        # Each component holds a RoutedClient bound to its role, not a bare LLM.
        from interfaces.model_router import RoutedClient
        assert isinstance(pipe.ideation.llm, RoutedClient)
        assert pipe.ideation.llm.role == "red_ideation"
        assert isinstance(pipe.execution.llm, RoutedClient)
        assert pipe.execution.llm.role == "red_execution"
        assert isinstance(pipe.judger.llm, RoutedClient)
        assert pipe.judger.llm.role == "semantic_judge"
        assert isinstance(pipe.strategist.llm, RoutedClient)
    finally:
        rt.shutdown()


def test_blue_pipeline_uses_router_clients():
    from infra.bootstrap import boot
    from blue_team.pipeline import Pipeline as BlueTeamPipeline
    from interfaces.model_router import RoutedClient
    rt = boot(use_mock_provisioner=True)
    try:
        pipe = BlueTeamPipeline(runtime=rt)
        assert isinstance(pipe.root_cause.llm, RoutedClient)
        assert pipe.root_cause.llm.role == "root_cause"
        assert isinstance(pipe.cold_verifier.llm, RoutedClient)
        assert pipe.cold_verifier.llm.role == "cold_verification"
        assert isinstance(pipe.patch_generator.llm, RoutedClient)
        assert pipe.patch_generator.llm.role == "patch_generation"
    finally:
        rt.shutdown()
