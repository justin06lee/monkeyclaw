"""B9 — model tournament hook.

The tournament is disabled by default; when enabled it generates ideas
across multiple entrant models, tags each idea with its source model, and
tracks per-model performance.
"""

from __future__ import annotations

from interfaces.types import IdeaObject
from red_team.tournament import (
    Entrant,
    ModelTournament,
    ModelTournamentConfig,
    load_tournament_config,
)


def _idea(idea_id: str = "IDEA-X") -> IdeaObject:
    return IdeaObject(
        idea_id=idea_id, cycle_id=1, zone_id="PROMPT-INJ",
        source_mode="creative", title="t", approach="a",
        success_criteria="s", estimated_turns=1, novelty_notes="")


def test_disabled_by_default():
    assert load_tournament_config({}).enabled is False
    # A real load from the repo yaml (no red_team section) is also disabled.
    assert load_tournament_config().enabled is False
    assert ModelTournament().enabled is False


def test_loads_entrants_from_nested_config():
    cfg = load_tournament_config({"red_team": {"model_tournament": {
        "enabled": True,
        "entrants": [
            {"role": "red_ideation"},
            {"role": "cyber_specialist_optional"},
            {"role": "frontier_creative_optional"},
        ],
    }}})
    assert cfg.enabled is True
    assert [e.role for e in cfg.entrants] == [
        "red_ideation", "cyber_specialist_optional",
        "frontier_creative_optional"]
    # `_optional` roles are flagged optional.
    assert cfg.entrants[0].optional is False
    assert cfg.entrants[1].optional is True


def test_disabled_tournament_generates_nothing():
    t = ModelTournament(ModelTournamentConfig(
        enabled=False, entrants=[Entrant("red_ideation")]))
    assert t.generate(lambda e: [_idea()]) == []


def test_enabled_tournament_merges_and_tags_ideas():
    cfg = ModelTournamentConfig(enabled=True, entrants=[
        Entrant(role="red_ideation", model="model-a"),
        Entrant(role="creative", model="model-b"),
    ])
    t = ModelTournament(cfg)
    merged = t.generate(
        lambda e: [_idea(f"{e.label}-1"), _idea(f"{e.label}-2")])
    assert len(merged) == 4
    assert {i.model_label for i in merged} == {"model-a", "model-b"}
    assert t.leaderboard()["model-a"]["ideas"] == 2


def test_record_outcome_tracks_per_model_performance():
    t = ModelTournament(ModelTournamentConfig(
        enabled=True, entrants=[Entrant("r", model="m")]))
    t.generate(lambda e: [_idea()])
    t.record_outcome("m", verdict="confirmed", tokens=500)
    t.record_outcome("m", verdict="suspicious", tokens=200)
    t.record_outcome("m", verdict="clean", tokens=100)
    row = t.leaderboard()["m"]
    assert row["confirmed"] == 1
    assert row["suspicious"] == 1
    assert row["tokens"] == 800
    assert "confirmed" in t.summary()


def test_optional_entrant_failure_does_not_break_the_demo():
    cfg = ModelTournamentConfig(enabled=True, entrants=[
        Entrant("good", model="g"),
        Entrant("bad", model="b"),
    ])
    t = ModelTournament(cfg)

    def gen(entrant):
        if entrant.model == "b":
            raise RuntimeError("entrant model unreachable")
        return [_idea()]

    merged = t.generate(gen)
    assert len(merged) == 1  # the healthy entrant still contributed


def test_tournament_ideas_hook_disabled_returns_empty():
    from red_team.ideation import tournament_ideas
    assert tournament_ideas(ModelTournament(), None, None, None, 1) == []
