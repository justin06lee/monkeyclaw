"""Phase 6 — offline refresh tool (spec §6.5, §11)."""

from __future__ import annotations

from scripts.refresh_taxonomy_corpus import diff_summary, validate_regenerated


def test_diff_summary_flags_added_and_removed_techniques():
    old = {"AML.T0051": "LLM Prompt Injection", "AML.T0057": "LLM Data Leakage"}
    new = {"AML.T0051": "LLM Prompt Injection", "AML.T0099": "New Technique"}
    summary = diff_summary(old, new)
    assert "AML.T0099" in summary["added"]
    assert "AML.T0057" in summary["removed"]
    assert summary["renamed"] == {}


def test_diff_summary_flags_renames():
    old = {"AML.T0051": "Old Name"}
    new = {"AML.T0051": "New Name"}
    summary = diff_summary(old, new)
    assert summary["renamed"] == {"AML.T0051": ("Old Name", "New Name")}


def test_validate_regenerated_accepts_the_vendored_corpus():
    # The currently-vendored corpus must validate clean.
    assert validate_regenerated("red_team/corpora") is True


def test_unmapped_new_technique_is_flagged(tmp_path):
    from scripts.refresh_taxonomy_corpus import unmapped_techniques

    techniques = {"AML.T0051", "AML.T0099"}
    mapped = {"AML.T0051"}
    assert unmapped_techniques(techniques, mapped) == {"AML.T0099"}
