"""Phase 1 — per-round mutation operator budget."""

from __future__ import annotations

from purple_team.operator_budget import budget_for
from red_team.mutations import MUTATION_OPERATORS


def test_round_zero_runs_the_full_twelve_operator_catalogue():
    ops = budget_for(round_index=0, zone_id="PROMPT-INJ",
                     prior_bypass_operators=[])
    assert set(ops) == set(MUTATION_OPERATORS)
    assert len(ops) == 12


def test_later_round_includes_every_prior_bypass_operator():
    ops = budget_for(round_index=1, zone_id="SBX-FS",
                     prior_bypass_operators=["paraphrase"])
    assert "paraphrase" in ops


def test_later_round_includes_zone_relevant_operators():
    ops = budget_for(round_index=1, zone_id="SKILL-SUPPLY",
                     prior_bypass_operators=[])
    assert "move_instruction_into_dependency_metadata" in ops


def test_later_round_budget_is_a_subset_of_the_catalogue():
    ops = budget_for(round_index=2, zone_id="PROMPT-INJ",
                     prior_bypass_operators=["change_persona"])
    assert set(ops) <= set(MUTATION_OPERATORS)
    assert len(ops) == len(set(ops))  # no duplicates


def test_unknown_zone_falls_back_to_a_nonempty_default_budget():
    ops = budget_for(round_index=1, zone_id="NOT-A-ZONE",
                     prior_bypass_operators=[])
    assert ops  # never empty — a focused round still tries something
    assert set(ops) <= set(MUTATION_OPERATORS)
