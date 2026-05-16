"""Phase 0 — verifier-hardening shared type contracts."""

from __future__ import annotations

from dataclasses import fields

from interfaces.types import VariantResult


def test_variant_result_has_operator_and_verdict():
    fnames = {f.name for f in fields(VariantResult)}
    assert {"operator", "variant_hash", "blocked",
            "judge_verdict"} <= fnames


def test_variant_result_constructs():
    vr = VariantResult(
        operator="paraphrase", variant_hash="abc123",
        blocked=True, judge_verdict="blocked")
    assert vr.operator == "paraphrase"
    assert vr.blocked is True
