"""Phase 0 — chain grammar: token vocabulary, ChainStep, AttackChain."""

from __future__ import annotations

import pytest


def test_capability_tokens_is_a_committed_tuple():
    from red_team.chain_tokens import CAPABILITY_TOKENS

    assert isinstance(CAPABILITY_TOKENS, tuple)
    assert 10 <= len(CAPABILITY_TOKENS) <= 20
    assert "foothold.instruction_executed" in CAPABILITY_TOKENS
    assert "secret.value_captured" in CAPABILITY_TOKENS
    assert "egress.channel_open" in CAPABILITY_TOKENS


def test_validate_tokens_accepts_known_tokens():
    from red_team.chain_tokens import validate_tokens

    validate_tokens(["foothold.instruction_executed", "secret.value_captured"])


def test_validate_tokens_rejects_unknown_token():
    from red_team.chain_tokens import validate_tokens

    with pytest.raises(ValueError, match="unknown capability token"):
        validate_tokens(["foothold.instruction_executed", "bogus.token"])


def test_validate_tokens_accepts_empty_list():
    from red_team.chain_tokens import validate_tokens

    validate_tokens([])


def _step(idx, zone, produces, requires=None):
    from interfaces.types import ChainStep

    return ChainStep(
        step_index=idx, zone_id=zone, objective=f"objective {idx}",
        primitive_ref=f"I{idx}", approach=f"approach {idx}",
        requires=requires or [], produces=produces,
        success_signal=f"signal {idx}",
    )


def test_chain_step_construction():
    s = _step(0, "PROMPT-INJ", ["foothold.instruction_executed"])
    assert s.step_index == 0
    assert s.produces == ["foothold.instruction_executed"]
    assert s.requires == []


def test_attack_chain_carries_ordered_steps_and_zones():
    from interfaces.types import AttackChain

    chain = AttackChain(
        chain_id="CHAIN-1", cycle_id=1, title="kill chain",
        zones=["PROMPT-INJ", "PRV-LEAK"], primary_zone="PRV-LEAK",
        steps=[
            _step(0, "PROMPT-INJ", ["foothold.instruction_executed"]),
            _step(1, "PRV-LEAK", ["secret.value_captured"],
                  requires=["foothold.instruction_executed"]),
        ],
        builds_on=["I0", "I1"], estimated_turns=12, rationale="why",
    )
    assert chain.zones == ["PROMPT-INJ", "PRV-LEAK"]
    assert chain.primary_zone == "PRV-LEAK"
    assert len(chain.steps) == 2


def test_chain_skeleton_pairs_zone_and_objective():
    from interfaces.types import ChainSkeleton

    sk = ChainSkeleton(
        title="t", cycle_id=1,
        step_specs=[("PROMPT-INJ", "get a foothold", "I0"),
                    ("PRV-LEAK", "read the secret", "ARCH:SBX-FS|direct|refusal")],
        rationale="r", estimated_turns=10,
    )
    assert sk.step_specs[0][0] == "PROMPT-INJ"


def test_chain_finding_and_attribution_shapes():
    from dataclasses import fields

    from interfaces.types import ChainAttribution, ChainFinding, ChainStepResult

    cf_fields = {f.name for f in fields(ChainFinding)}
    assert {"chain_finding_id", "chain_id", "zones_traversed",
            "terminal_zone", "severity", "verdict", "landed_steps"} <= cf_fields
    ca_fields = {f.name for f in fields(ChainAttribution)}
    assert {"chain_finding", "per_zone_findings", "coverage_deltas"} <= ca_fields
    csr_fields = {f.name for f in fields(ChainStepResult)}
    assert {"chain_id", "step_index", "zone_id", "landed",
            "produced_tokens", "progress_score"} <= csr_fields
