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


def test_load_taxonomy_loads_the_vendored_corpus():
    from red_team.taxonomy import load_taxonomy

    tax = load_taxonomy()
    assert tax.version == "atlas-5.4.0+owasp-2025"
    assert tax.technique("AML.T0051") is not None
    assert tax.technique("AML.T0051").is_agentic is True


def test_techniques_for_zone_returns_mapped_techniques():
    from red_team.taxonomy import load_taxonomy

    tax = load_taxonomy()
    techs = tax.techniques_for_zone("PROMPT-INJ")
    ids = {t.technique_id for t in techs}
    assert {"AML.T0051", "AML.T0051.000", "AML.T0051.001"} <= ids


def test_owasp_for_zone_returns_mapped_categories():
    from red_team.taxonomy import load_taxonomy

    tax = load_taxonomy()
    cats = tax.owasp_for_zone("PRV-LEAK")
    assert {c.category_id for c in cats} == {"LLM02", "LLM07"}


def test_every_mapped_technique_exists_in_atlas_snapshot():
    from red_team.taxonomy import load_taxonomy

    tax = load_taxonomy()
    for zone_id in tax.zone_ids():
        for t in tax.techniques_for_zone(zone_id):
            assert tax.technique(t.technique_id) is not None


def test_unknown_zone_in_mapping_raises(tmp_path):
    from red_team.taxonomy import load_taxonomy

    bad = tmp_path / "corpora"
    bad.mkdir()
    import shutil
    from pathlib import Path
    src = Path("red_team/corpora")
    for f in src.glob("*.yaml"):
        shutil.copy(f, bad / f.name)
    mapping = bad / "zone_atlas_mapping.yaml"
    mapping.write_text(
        "zones:\n  - {zone_id: NOT-A-ZONE, atlas: [AML.T0051], owasp: [LLM01]}\n")
    import pytest
    with pytest.raises(ValueError, match="unknown zone"):
        load_taxonomy(bad)


def test_technique_id_absent_from_atlas_raises(tmp_path):
    from red_team.taxonomy import load_taxonomy

    bad = tmp_path / "corpora"
    bad.mkdir()
    import shutil
    from pathlib import Path
    for f in Path("red_team/corpora").glob("*.yaml"):
        shutil.copy(f, bad / f.name)
    (bad / "zone_atlas_mapping.yaml").write_text(
        "zones:\n  - {zone_id: PROMPT-INJ, atlas: [AML.T9999], owasp: [LLM01]}\n")
    import pytest
    with pytest.raises(ValueError, match="not in the ATLAS snapshot"):
        load_taxonomy(bad)
