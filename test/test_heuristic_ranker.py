"""Phase 1 — the HeuristicRanker (learned-ranking-model spec §6.4)."""

from __future__ import annotations

from interfaces.ranker import Ranker, RankerInput
from red_team.heuristic_ranker import HeuristicRanker
from red_team.mutations import MUTATION_OPERATORS, MutationStats


def _input(zone="PROMPT-INJ", risk=3.0, summary="probe") -> RankerInput:
    return RankerInput(
        idea_summary=summary, zone_id=zone, tactic_tags=["roleplay"],
        trajectory_features={"risk_stage": risk, "progress_delta": 1.0,
                             "steerability": 2.0, "novelty": 2.0,
                             "transfer_likelihood": 1.0, "robustness": 2.0,
                             "refusal_strength": 1.0, "turn_cost": 3.0,
                             "boundary_erosion": 2.0},
        judge_scores={"safety": 0.5}, token_cost=100,
        mutation_operator="paraphrase")


def test_heuristic_ranker_satisfies_the_protocol():
    assert isinstance(HeuristicRanker(), Ranker)


def test_predict_returns_bounded_usefulness():
    out = HeuristicRanker().predict(_input())
    assert 0.0 <= out.usefulness <= 1.0
    assert out.archive_niche.count("|") == 2
    assert out.likely_failure_mode


def test_rank_orders_higher_risk_first():
    ranker = HeuristicRanker()
    inputs = [_input(risk=1.0), _input(risk=5.0), _input(risk=3.0)]
    order = ranker.rank(inputs)
    # The risk-5 input (index 1) must rank first.
    assert order[0] == 1


def test_likely_mutation_operators_match_mutation_stats(server):
    stats = MutationStats()
    stats.record("change_persona", improved=True, score=0.9)
    ranker = HeuristicRanker(mutation_stats=stats)
    out = ranker.predict(_input())
    assert out.likely_mutation_operators == stats.rank()
    assert all(op in MUTATION_OPERATORS
               for op in out.likely_mutation_operators)
