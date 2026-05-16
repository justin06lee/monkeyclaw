"""Phase 0 — mutation-operator-learning shared type contracts."""

from __future__ import annotations

from dataclasses import fields

from interfaces.types import MutationAttempt, MutationOperatorStat


def test_mutation_operator_stat_has_learning_fields():
    fnames = {f.name for f in fields(MutationOperatorStat)}
    assert {"operator", "zone_id", "uses", "successes", "avg_score",
            "squared_score", "last_lift"} <= fnames


def test_mutation_operator_stat_global_rollup_uses_empty_zone():
    s = MutationOperatorStat(
        operator="paraphrase", zone_id="", uses=4, successes=3,
        avg_score=0.7, squared_score=2.1, last_lift=0.2)
    assert s.zone_id == ""
    assert s.operator == "paraphrase"


def test_mutation_attempt_mirrors_the_row():
    fnames = {f.name for f in fields(MutationAttempt)}
    assert {"attempt_id", "cycle_id", "zone_id", "operator",
            "parent_idea_id", "child_idea_id", "parent_score",
            "child_score", "lift", "improved", "child_verdict"} <= fnames


def test_mutation_attempt_constructs_with_server_filled_id():
    a = MutationAttempt(
        attempt_id="", cycle_id=1, zone_id="PROMPT-INJ",
        operator="paraphrase", parent_idea_id="I1", child_idea_id="I2",
        parent_score=0.4, child_score=0.9, lift=0.5, improved=True,
        child_verdict="confirmed", created_at="")
    assert a.improved is True
    assert a.lift == 0.5
