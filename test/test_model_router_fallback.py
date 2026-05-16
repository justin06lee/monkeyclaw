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
    # _client_for_route returns (client, effective_route).
    monkeypatch.setattr(router, "_client_for_route", lambda route: (next(it), route))
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


def test_real_client_for_route_chain_terminates_on_mock(monkeypatch):
    """Exercise the real _client_for_route -> make_llm path.

    The existing fallback tests monkeypatch _client_for_route. Here we leave it
    real: with no credentials and no `claude` binary, every non-local route
    auto-detects to `mock`, and the chain's appended `mock` terminal link
    guarantees a response — no exhaustion.
    """
    monkeypatch.setattr(shutil, "which", lambda _b: None)  # no claude CLI
    monkeypatch.delenv("MC_LLM_BACKEND", raising=False)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("NIM_API_KEY", raising=False)
    monkeypatch.delenv("MC_NEMOTRON_BASE_URL", raising=False)
    mcp = _RecordingMCP()
    router = ModelRouter(load_config(), mcp=mcp)
    resp = router.client_for("red_ideation").complete(
        [LLMMessage(role="user", content="hi")])
    assert resp.text  # mock always returns something
    assert mcp.runs[-1].success is True


def test_real_client_for_route_falls_through_failing_local_link(monkeypatch):
    """The claude CLI link raises (timeout/non-zero exit) -> falls to mock.

    Drives the real _client_for_route while making the `claude_cli` backend's
    complete() raise, proving the appended unconditional `mock` link catches it
    so the chain still terminates with a response.
    """
    from interfaces import llm as llm_mod
    monkeypatch.setattr(shutil, "which", lambda _b: "/usr/bin/claude")  # CLI "present"
    monkeypatch.delenv("MC_LLM_BACKEND", raising=False)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("NIM_API_KEY", raising=False)
    monkeypatch.delenv("MC_NEMOTRON_BASE_URL", raising=False)

    def _boom(self, messages, system="", max_tokens=2000, temperature=0.7):
        raise RuntimeError("claude CLI timed out after 180s")

    monkeypatch.setattr(llm_mod.ClaudeCLILLM, "complete", _boom)
    mcp = _RecordingMCP()
    router = ModelRouter(load_config(), mcp=mcp)
    resp = router.client_for("red_ideation").complete(
        [LLMMessage(role="user", content="hi")])
    assert resp.text  # the mock terminal link served it
    # At least one failed claude_cli row, and a final successful mock row.
    assert any(r.success is False for r in mcp.runs)
    assert mcp.runs[-1].success is True
    assert mcp.runs[-1].model == "mock"


def test_red_pipeline_uses_router_clients():
    from infra.bootstrap import boot
    from red_team.pipeline import Pipeline
    rt = boot(use_mock_provisioner=True)
    try:
        pipe = Pipeline(runtime=rt)
        # Each component holds a role-bound RoutedClient, wrapped in an
        # ObservedLLM so completions emit live dashboard agent_events.
        from interfaces.llm import ObservedLLM
        from interfaces.model_router import RoutedClient

        def _routed(client):
            inner = client.inner if isinstance(client, ObservedLLM) else client
            assert isinstance(inner, RoutedClient)
            return inner

        assert _routed(pipe.ideation.llm).role == "red_ideation"
        assert _routed(pipe.execution.llm).role == "red_execution"
        assert _routed(pipe.judger.llm).role == "semantic_judge"
        _routed(pipe.strategist.llm)
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
