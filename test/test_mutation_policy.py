"""Phase 2 — bandit selection policy over mutation operators."""

from __future__ import annotations

import pytest

from red_team.mutation_policy import MutationPolicy
from red_team.mutations import MUTATION_OPERATORS, MutationStats


def test_select_returns_k_distinct_operators():
    pol = MutationPolicy(MutationStats(), kind="greedy")
    picked = pol.select(3)
    assert len(picked) == 3
    assert len(set(picked)) == 3
    assert set(picked) <= set(MUTATION_OPERATORS)


def test_greedy_policy_matches_mutationstats_rank():
    stats = MutationStats()
    for _ in range(8):
        stats.record("paraphrase", improved=True, score=0.9, lift=0.4)
    for _ in range(8):
        stats.record("change_persona", improved=False, score=0.1, lift=-0.3)
    pol = MutationPolicy(stats, kind="greedy")
    assert pol.select(12) == stats.rank()


def test_select_honours_the_exclude_set():
    pol = MutationPolicy(MutationStats(), kind="greedy")
    picked = pol.select(3, exclude={"paraphrase", "add_benign_framing"})
    assert "paraphrase" not in picked
    assert "add_benign_framing" not in picked


def test_unknown_kind_raises():
    with pytest.raises(ValueError):
        MutationPolicy(MutationStats(), kind="not_a_policy")


def test_thompson_is_deterministic_under_a_fixed_seed():
    stats = MutationStats()
    a = MutationPolicy(stats, kind="thompson", seed=42).select(5)
    b = MutationPolicy(stats, kind="thompson", seed=42).select(5)
    assert a == b


def test_thompson_explores_a_strong_operator_more_often():
    stats = MutationStats()
    # paraphrase: a strong arm — 20 wins.
    for _ in range(20):
        stats.record("paraphrase", improved=True, score=0.95, lift=0.5)
    # change_persona: a weak arm — 20 losses.
    for _ in range(20):
        stats.record("change_persona", improved=False, score=0.05, lift=-0.4)
    pol = MutationPolicy(stats, kind="thompson", seed=7)
    para_picked = persona_picked = 0
    for _ in range(200):
        top = pol.select(1)[0]
        para_picked += top == "paraphrase"
        persona_picked += top == "change_persona"
    assert para_picked > persona_picked


def test_thompson_explain_returns_a_value_per_operator():
    pol = MutationPolicy(MutationStats(), kind="thompson", seed=1)
    pol.select(3)
    vals = pol.explain()
    assert set(vals) == set(MUTATION_OPERATORS)
    assert all(0.0 <= v <= 1.0 for v in vals.values())


def test_epsilon_greedy_explores_at_roughly_the_configured_rate():
    stats = MutationStats()
    for _ in range(20):
        stats.record("paraphrase", improved=True, score=0.95, lift=0.5)
    pol = MutationPolicy(stats, kind="epsilon_greedy", seed=3, epsilon=0.5)
    # With epsilon=0.5 the greedy top arm ("paraphrase") is NOT always first.
    tops = [pol.select(1)[0] for _ in range(100)]
    non_greedy = sum(1 for t in tops if t != "paraphrase")
    assert non_greedy > 10  # exploration happens


def test_epsilon_greedy_zero_epsilon_is_pure_greedy():
    stats = MutationStats()
    for _ in range(8):
        stats.record("paraphrase", improved=True, score=0.95, lift=0.5)
    pol = MutationPolicy(stats, kind="epsilon_greedy", seed=9, epsilon=0.0)
    assert pol.select(12) == stats.rank()
