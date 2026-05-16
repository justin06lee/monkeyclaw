import shutil

from infra.config import load_config
from interfaces.config_schema import ModelRoute
from interfaces.llm import LLMClient, LLMMessage, LLMResponse
from interfaces.model_router import ModelRouter


class _OkLLM(LLMClient):
    name = "ok"

    def __init__(self, in_tok=1_000_000, out_tok=1_000_000):
        self._in, self._out = in_tok, out_tok

    def complete(self, messages, system="", max_tokens=2000, temperature=0.7):
        return LLMResponse(text="done", input_tokens=self._in, output_tokens=self._out)


class _RecordingMCP:
    def __init__(self):
        self.runs = []

    def log_model_run(self, run):
        self.runs.append(run)
        return f"RUN-{len(self.runs)}"


class _BoomMCP:
    def log_model_run(self, run):
        raise RuntimeError("db locked")


def test_success_writes_exactly_one_row(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    mcp = _RecordingMCP()
    router = ModelRouter(load_config(), mcp=mcp)
    monkeypatch.setattr(router, "_client_for_route", lambda route: _OkLLM())
    router.client_for("red_ideation").complete([LLMMessage(role="user", content="x")])
    assert len(mcp.runs) == 1
    row = mcp.runs[0]
    assert row.role == "red_ideation"
    assert row.success is True
    assert row.error is None


def test_cost_matches_pricing_table(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    mcp = _RecordingMCP()
    cfg = load_config()
    router = ModelRouter(cfg, mcp=mcp)
    # Force the resolved chain to a single known-priced route.
    route = ModelRoute(provider="nvidia", model="nvidia/nemotron-3-super-120b-a12b")
    monkeypatch.setattr(router, "resolve", lambda role: [route])
    monkeypatch.setattr(router, "_client_for_route", lambda r: _OkLLM(1_000_000, 1_000_000))
    router.client_for("red_ideation").complete([LLMMessage(role="user", content="x")])
    # 1M input @ 0.30 + 1M output @ 0.90 = 1.20
    assert abs(mcp.runs[0].cost_usd - 1.20) < 1e-6


def test_unknown_model_yields_null_cost(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    mcp = _RecordingMCP()
    router = ModelRouter(load_config(), mcp=mcp)
    route = ModelRoute(provider="nvidia", model="nvidia/some-unpriced-model")
    monkeypatch.setattr(router, "resolve", lambda role: [route])
    monkeypatch.setattr(router, "_client_for_route", lambda r: _OkLLM())
    router.client_for("red_ideation").complete([LLMMessage(role="user", content="x")])
    assert mcp.runs[0].cost_usd is None


def test_log_model_run_failure_is_swallowed(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    router = ModelRouter(load_config(), mcp=_BoomMCP())
    monkeypatch.setattr(router, "_client_for_route", lambda r: _OkLLM())
    # Must NOT raise even though log_model_run raises.
    resp = router.client_for("red_ideation").complete(
        [LLMMessage(role="user", content="x")])
    assert resp.text == "done"


def test_no_mcp_means_no_accounting(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    router = ModelRouter(load_config(), mcp=None)
    monkeypatch.setattr(router, "_client_for_route", lambda r: _OkLLM())
    # Router with no MCP still completes — accounting is just skipped.
    resp = router.client_for("red_ideation").complete(
        [LLMMessage(role="user", content="x")])
    assert resp.text == "done"


def test_per_role_cost_rollup(tmp_path):
    from infra.database import Database
    from infra.mcp_server import MCPServer
    from interfaces.types import ModelRunInput
    db = Database(str(tmp_path / "t.db"))
    mcp = MCPServer(db)
    try:
        mcp.log_model_run(ModelRunInput(
            role="red_ideation", model="m1", provider="nvidia",
            input_tokens=100, output_tokens=50, latency_ms=10, cost_usd=0.5))
        mcp.log_model_run(ModelRunInput(
            role="red_ideation", model="m1", provider="nvidia",
            input_tokens=200, output_tokens=80, latency_ms=12, cost_usd=1.5))
        mcp.log_model_run(ModelRunInput(
            role="patch_generation", model="m2", provider="anthropic_or_openai",
            input_tokens=300, output_tokens=300, latency_ms=40, cost_usd=3.0))
        rollup = mcp.get_model_cost_rollup()
        by_role = {r["role"]: r for r in rollup}
        assert by_role["red_ideation"]["input_tokens"] == 300
        assert by_role["red_ideation"]["output_tokens"] == 130
        assert abs(by_role["red_ideation"]["cost_usd"] - 2.0) < 1e-6
        assert by_role["red_ideation"]["runs"] == 2
        assert abs(by_role["patch_generation"]["cost_usd"] - 3.0) < 1e-6
    finally:
        db.close()


def test_dashboard_cost_panel_uses_model_runs(tmp_path):
    from infra.database import Database
    from infra.mcp_server import MCPServer
    from interfaces.types import ModelRunInput
    db = Database(str(tmp_path / "d.db"))
    mcp = MCPServer(db)
    try:
        mcp.log_model_run(ModelRunInput(
            role="patch_generation", model="frontier-coding",
            provider="anthropic_or_openai", input_tokens=1000,
            output_tokens=1000, latency_ms=50, cost_usd=18.0))
        # The dashboard cost view is a function of get_model_cost_rollup.
        rollup = mcp.get_model_cost_rollup()
        total = sum(r["cost_usd"] for r in rollup)
        assert abs(total - 18.0) < 1e-6
        assert rollup[0]["role"] == "patch_generation"
    finally:
        db.close()
