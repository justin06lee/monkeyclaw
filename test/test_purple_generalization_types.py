"""Phase 0 — patch-generalization-loop shared type contracts."""

from __future__ import annotations

from dataclasses import fields

from interfaces.types import (
    BypassConstraint,
    BypassResult,
    GeneralizationResult,
    GeneralizationRound,
    GeneralizationRoundInput,
    MutationVariant,
)


def test_mutation_variant_carries_operator_and_replay():
    fnames = {f.name for f in fields(MutationVariant)}
    assert {"variant_id", "operator", "mutated_transcript",
            "replay_result"} <= fnames


def test_bypass_result_status_is_the_three_outcomes():
    r = BypassResult(
        variant_id="V1", operator="paraphrase", status="bypassed",
        triggered_evidence=[], severity="high", notes="")
    assert r.status in ("bypassed", "blocked", "inconclusive")


def test_bypass_constraint_has_directive_and_transcript():
    fnames = {f.name for f in fields(BypassConstraint)}
    assert {"constraint_id", "operator", "bypassing_transcript",
            "directive", "evidence"} <= fnames


def test_generalization_round_input_is_the_write_shape():
    fnames = {f.name for f in fields(GeneralizationRoundInput)}
    assert {"patch_id", "finding_id", "vuln_id", "zone_id", "round_index",
            "operators_tried", "variants_total", "variants_bypassed",
            "variants_inconclusive", "bypass_operators", "outcome",
            "repatch_patch_id", "evidence"} <= fnames


def test_generalization_round_adds_read_only_id():
    fnames = {f.name for f in fields(GeneralizationRound)}
    assert {"round_id", "created_at"} <= fnames


def test_generalization_result_carries_status_and_rounds():
    res = GeneralizationResult(
        finding_id="F1", final_patch_id="P1", status="generalized",
        reason=None, rounds=[], open_bypasses=[])
    assert res.status in ("generalized", "unconverged")
    assert res.open_bypasses == []
