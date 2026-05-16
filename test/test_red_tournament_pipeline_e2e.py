"""Model ideation tournament — one full red ideation cycle in mock mode with
the tournament enabled (model-ideation-tournament spec §13).

The pipeline surface is `generate_ideas()` (fan-out + head-to-head judging)
followed by per-zone `record_zone_outcomes()` (the post-execution win-rate
fold). These tests drive that surface directly in mock mode, zero
credentials.
"""

from __future__ import annotations

from infra.mock_mcp import MockMCP
from interfaces.llm import MockLLM
from interfaces.types import IdeaObject, JudgmentResult
from red_team.pipeline import Pipeline
from red_team.tournament import (
    Entrant,
    ModelTournament,
    ModelTournamentConfig,
)


def _enabled_tournament():
    return ModelTournament(ModelTournamentConfig(
        enabled=True,
        entrants=[Entrant(role="red_ideation"),
                  Entrant(role="red_code_ideation")]))


def _judgment(idea_id: str, zone_id: str, verdict: str) -> JudgmentResult:
    return JudgmentResult(
        lane_id="L1", idea_id=idea_id, zone_id=zone_id, verdict=verdict,
        tier_that_caught="tier1", failure_class="none", severity="high",
        confidence=0.9, evidence=[], reasoning="r",
        tokens_used_judgment=0, timestamp="")


def test_full_cycle_with_tournament_enabled():
    mcp = MockMCP(seed=0, verbose=False)
    pipeline = Pipeline(mcp=mcp, llm=MockLLM(),
                        tournament=_enabled_tournament())
    ideas = pipeline.generate_ideas(cycle_id=1, n_lanes=2)
    assert ideas  # the cycle still produced ideas

    # a head-to-head round was judged and persisted.
    assert len(mcp._tournament_rounds) >= 1
    rnd = mcp._tournament_rounds[0]

    # drive the post-execution win-rate fold for that zone.
    zone_id = rnd.zone_id
    judged = []
    for label in rnd.entrants:
        idea = IdeaObject(
            idea_id="IDEA-1", cycle_id=1, zone_id=zone_id,
            source_mode="creative", title="t", approach="a",
            success_criteria="s", estimated_turns=3, novelty_notes="")
        idea.model_label = label
        judged.append((idea, _judgment("IDEA-1", zone_id, "confirmed")))
    pipeline.record_zone_outcomes(zone_id, judged)

    # win-rates were written for this zone.
    winrates = mcp.get_model_zone_winrate(zone_id)
    assert len(winrates) >= 1
    assert all(0.0 <= w.winrate <= 1.0 for w in winrates)
    # the pending round was consumed.
    assert zone_id not in pipeline._pending_rounds


def test_disabled_tournament_reproduces_single_model_cycle():
    mcp = MockMCP(seed=0, verbose=False)
    pipeline = Pipeline(mcp=mcp, llm=MockLLM())
    assert pipeline.tournament.enabled is False
    ideas = pipeline.generate_ideas(cycle_id=1, n_lanes=2)
    # no tournament rounds, no win-rate rows — the single-model path.
    assert mcp._tournament_rounds == []
    assert mcp.get_model_zone_winrate() == []
    assert ideas  # the cycle still produced ideas
