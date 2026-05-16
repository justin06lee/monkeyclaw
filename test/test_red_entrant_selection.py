"""Model ideation tournament — entrant routing tests
(model-ideation-tournament spec §7.3)."""

from __future__ import annotations

from collections import Counter

from interfaces.types import ModelZoneWinrate
from red_team.entrant_selection import select_entrants, weights
from red_team.tournament import Entrant

ENTRANTS = [Entrant(role="red_ideation"),
            Entrant(role="frontier_creative_optional")]


def _winrates(zone, mapping):
    return [ModelZoneWinrate(zone_id=zone, model_label=label, winrate=wr)
            for label, wr in mapping.items()]


def test_weights_floor_every_entrant():
    wr = _winrates("Z", {"red_ideation": 0.9})
    w = weights("Z", ENTRANTS, wr, exploration_floor=0.2)
    # frontier has no win-rate row -> still gets at least the floor.
    assert w["frontier_creative_optional"] >= 0.2
    assert w["red_ideation"] >= 0.2


def test_no_history_zone_runs_all_entrants():
    selected = select_entrants("Z", ENTRANTS, [], exploration_floor=0.2,
                               seed=1)
    assert {e.label for e in selected} == {e.label for e in ENTRANTS}


def test_selection_is_deterministic_under_seed():
    wr = _winrates("Z", {"red_ideation": 0.8,
                         "frontier_creative_optional": 0.2})
    a = select_entrants("Z", ENTRANTS, wr, exploration_floor=0.1, seed=42)
    b = select_entrants("Z", ENTRANTS, wr, exploration_floor=0.1, seed=42)
    assert [e.label for e in a] == [e.label for e in b]


def test_high_winrate_entrant_selected_more_often():
    wr = _winrates("Z", {"red_ideation": 0.9,
                         "frontier_creative_optional": 0.1})
    counts = Counter()
    for s in range(400):
        for e in select_entrants("Z", ENTRANTS, wr,
                                 exploration_floor=0.05, seed=s):
            counts[e.label] += 1
    assert counts["red_ideation"] > counts["frontier_creative_optional"]


def test_exploration_floor_guarantees_minimum_sampling():
    wr = _winrates("Z", {"red_ideation": 0.99,
                         "frontier_creative_optional": 0.01})
    counts = Counter()
    for s in range(400):
        for e in select_entrants("Z", ENTRANTS, wr,
                                 exploration_floor=0.25, seed=s):
            counts[e.label] += 1
    # the weak entrant is sampled in a meaningful fraction of draws.
    assert counts["frontier_creative_optional"] > 0.15 * 400
