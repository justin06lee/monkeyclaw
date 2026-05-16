"""Phase 0 — corpus-driven ideation shared type contracts."""

from __future__ import annotations

from dataclasses import fields

from interfaces.types import TechniqueCoverage, TechniqueRef


def test_technique_ref_has_kind_and_corpus_version():
    fnames = {f.name for f in fields(TechniqueRef)}
    assert {"kind", "technique_id", "name",
            "corpus_version", "resolved_by"} <= fnames


def test_technique_ref_constructs():
    ref = TechniqueRef(
        kind="atlas", technique_id="AML.T0051",
        name="LLM Prompt Injection",
        corpus_version="atlas-5.4.0+owasp-2025", resolved_by="model")
    assert ref.kind == "atlas"
    assert ref.resolved_by == "model"


def test_technique_coverage_has_both_ratios():
    fnames = {f.name for f in fields(TechniqueCoverage)}
    assert {"zone_id", "total", "exercised", "confirmed",
            "exercised_ratio", "confirmed_ratio",
            "gap_technique_ids"} <= fnames


def test_technique_coverage_ratios_are_zero_to_one():
    cov = TechniqueCoverage(
        zone_id="PROMPT-INJ", total=4, exercised=2, confirmed=1,
        exercised_ratio=0.5, confirmed_ratio=0.25,
        gap_technique_ids=["AML.T0051.001"])
    assert 0.0 <= cov.exercised_ratio <= 1.0
    assert 0.0 <= cov.confirmed_ratio <= 1.0
