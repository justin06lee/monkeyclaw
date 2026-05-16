"""Phase 4 — one full cycle with a composed chain against the mock victim.

Adaptation note: the real Pipeline is constructed as Pipeline(mcp=, llm=),
not Pipeline(cfg, mcp=) — the chain config is toggled on the built pipeline's
cfg. make_pipeline_config() supplies a chains-enabled MonkeyClawConfig used
to mirror that toggle; the pipeline tests use the supported ctor form.
"""

from __future__ import annotations

from infra.mock_mcp import MockMCP
from interfaces.llm import MockLLM
from red_team.pipeline import Pipeline


def _pipeline(chains_enabled: bool = True) -> Pipeline:
    pipe = Pipeline(mcp=MockMCP(seed=0, verbose=False), llm=MockLLM())
    pipe.cfg.red.chains.enabled = chains_enabled
    return pipe


def test_generate_ideas_emits_at_least_one_chain_lane():
    """With chains enabled, generate_ideas produces lanes carrying a chain."""
    pipe = _pipeline(chains_enabled=True)
    lanes = pipe.generate_ideas(cycle_id=1, n_lanes=2)
    assert lanes
    chain_lanes = [idea for idea in lanes
                   if getattr(idea, "chain", None) is not None]
    assert chain_lanes, "expected at least one chain-carrying lane"


def test_generate_ideas_falls_back_when_composer_empty(monkeypatch):
    """An empty composer output falls back to the legacy strategist path."""
    pipe = _pipeline(chains_enabled=True)
    monkeypatch.setattr("red_team.chain_composer.compose",
                        lambda *a, **kw: [])
    lanes = pipe.generate_ideas(cycle_id=1, n_lanes=2)
    assert lanes  # legacy single-zone lanes still produced
    assert all(getattr(idea, "chain", None) is None for idea in lanes)


def test_chains_disabled_runs_legacy_path_only():
    pipe = _pipeline(chains_enabled=False)
    lanes = pipe.generate_ideas(cycle_id=1, n_lanes=2)
    assert all(getattr(idea, "chain", None) is None for idea in lanes)


def test_judge_routes_chain_lane_through_attribution():
    """A judged chain lane produces a ChainFinding and per-zone coverage."""
    from test.helpers import make_chain_lane_result

    pipe = _pipeline(chains_enabled=True)
    lanes = pipe.generate_ideas(cycle_id=1, n_lanes=2)
    chain_lane = next(idea for idea in lanes
                      if getattr(idea, "chain", None) is not None)
    lane_result = make_chain_lane_result(chain_lane)  # landed chain trace
    pipe.judge(lane_result)
    assert pipe.mcp.get_attack_chains(cycle_id=1)
    chain_findings = pipe.mcp.get_chain_findings()
    assert len(chain_findings) == 1


def test_judge_routes_plain_lane_through_single_zone_routing():
    from test.helpers import make_plain_lane_result

    pipe = _pipeline(chains_enabled=False)
    lanes = pipe.generate_ideas(cycle_id=1, n_lanes=2)
    pipe.judge(make_plain_lane_result(lanes[0]))
    # Plain lanes never produce a ChainFinding.
    assert pipe.mcp.get_chain_findings() == []
