"""Phase 1 — durable, zone-scoped MutationStats."""

from __future__ import annotations

import pytest

from interfaces.types import MutationOperatorStat
from red_team.mutations import MUTATION_OPERATORS, MutationStats


def test_record_accumulates_squared_score_and_last_lift():
    stats = MutationStats()
    stats.record("paraphrase", improved=True, score=0.8, lift=0.3)
    stats.record("paraphrase", improved=False, score=0.4, lift=-0.1)
    s = stats.stats_for("paraphrase")
    # squared_score = 0.8^2 + 0.4^2 = 0.64 + 0.16 = 0.80
    assert s["squared_score"] == pytest.approx(0.80)
    # last_lift is the most recent observation.
    assert s["last_lift"] == pytest.approx(-0.1)


def test_lift_defaults_to_zero_for_back_compat():
    """record() keeps its signature usable without lift (Phase 0 callers)."""
    stats = MutationStats()
    stats.record("paraphrase", improved=True, score=0.8)
    assert stats.stats_for("paraphrase")["last_lift"] == pytest.approx(0.0)


def test_to_rows_serializes_every_operator():
    stats = MutationStats()
    stats.record("paraphrase", improved=True, score=0.8, lift=0.3)
    rows = stats.to_rows()
    assert {r.operator for r in rows} == set(MUTATION_OPERATORS)
    assert all(isinstance(r, MutationOperatorStat) for r in rows)
    para = next(r for r in rows if r.operator == "paraphrase")
    assert para.uses == 1 and para.successes == 1
    assert para.zone_id == ""  # a global (unscoped) MutationStats


def test_load_from_to_rows_round_trip():
    src = MutationStats()
    src.record("paraphrase", improved=True, score=0.9, lift=0.4)
    src.record("change_persona", improved=False, score=0.1, lift=-0.2)
    rehydrated = MutationStats()
    rehydrated.load_from(src.to_rows())
    assert rehydrated.stats_for("paraphrase") == src.stats_for("paraphrase")
    assert rehydrated.stats_for("change_persona") == \
        src.stats_for("change_persona")


def test_load_from_ignores_unknown_operators():
    stats = MutationStats()
    stats.load_from([MutationOperatorStat(
        operator="not_a_real_operator", zone_id="", uses=9, successes=9,
        avg_score=1.0, squared_score=9.0, last_lift=1.0)])
    # Unknown rows are skipped; known operators stay at the neutral prior.
    assert stats.stats_for("paraphrase")["uses"] == 0


def test_posterior_returns_beta_alpha_beta():
    stats = MutationStats()
    for _ in range(3):
        stats.record("paraphrase", improved=True, score=0.9, lift=0.3)
    stats.record("paraphrase", improved=False, score=0.2, lift=-0.1)
    alpha, beta = stats.posterior("paraphrase")
    # Beta(1 + successes, 1 + failures) = Beta(1+3, 1+1).
    assert alpha == pytest.approx(4.0)
    assert beta == pytest.approx(2.0)


def test_posterior_of_unused_operator_is_uniform_prior():
    stats = MutationStats()
    assert stats.posterior("split_into_multi_turn") == (1.0, 1.0)


def test_zone_scoped_stats_carry_their_zone_id():
    stats = MutationStats(zone_id="PROMPT-INJ")
    stats.record("paraphrase", improved=True, score=0.9, lift=0.4)
    rows = stats.to_rows()
    assert all(r.zone_id == "PROMPT-INJ" for r in rows)


def test_global_and_zone_stats_are_independent_instances():
    global_stats = MutationStats()
    zone_stats = MutationStats(zone_id="SBX-NET")
    zone_stats.record("paraphrase", improved=True, score=0.9, lift=0.4)
    # The global instance is untouched by a per-zone record.
    assert global_stats.stats_for("paraphrase")["uses"] == 0
    assert zone_stats.stats_for("paraphrase")["uses"] == 1


def test_default_zone_id_is_empty_string():
    assert MutationStats().zone_id == ""
