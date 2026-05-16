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
