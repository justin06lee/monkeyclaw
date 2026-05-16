"""Preloaded attack-skill corpus + loader. No network, no LLM."""

from __future__ import annotations

import textwrap

import pytest

from red_team.attack_skills_loader import (
    FAILURE_CLASSES,
    AttackSkill,
    content_hash,
    load_attack_skills,
    skills_for_zone,
)
from red_team.ideation import (
    INTERACTION_STYLES,
    OBSERVABLE_KINDS,
    TARGET_DEFENSES,
)
from red_team.policy_corpus import KNOWN_ZONES

_SEVERITIES = {"critical", "high", "medium", "low"}


# ---------------------------------------------------------------------------
# Corpus shape
# ---------------------------------------------------------------------------


def test_corpus_loads():
    skills = load_attack_skills()
    assert len(skills) == 35
    assert all(isinstance(s, AttackSkill) for s in skills)


def test_skill_ids_unique():
    skills = load_attack_skills()
    ids = [s.skill_id for s in skills]
    assert len(ids) == len(set(ids))


def test_all_eighteen_zones_covered():
    """Every attack-surface zone must have at least one pattern skill."""
    skills = load_attack_skills()
    covered: set[str] = set()
    for s in skills:
        if s.kind == "pattern":
            covered |= set(s.zone_ids)
    assert covered == set(KNOWN_ZONES), (
        f"zones with no skill: {sorted(set(KNOWN_ZONES) - covered)}"
    )


def test_corpus_field_values_are_valid():
    """load_attack_skills validates enums; assert the corpus actually uses
    only known vocabulary so a typo can never ship silently."""
    for s in load_attack_skills():
        assert s.interaction_style in INTERACTION_STYLES
        assert s.target_defense in TARGET_DEFENSES
        assert s.failure_class in FAILURE_CLASSES
        assert s.severity_hint in _SEVERITIES
        assert all(o in OBSERVABLE_KINDS for o in s.expected_observables)


def test_provenance_sources_consistency():
    for s in load_attack_skills():
        if s.provenance == "research":
            assert s.sources, f"{s.skill_id}: research skill needs sources"
        else:
            assert s.provenance == "extrapolated"


def test_modifier_skills_are_cross_zone():
    skills = load_attack_skills()
    modifiers = [s for s in skills if s.kind == "modifier"]
    assert modifiers, "expected at least one modifier skill"
    for m in modifiers:
        assert m.zone_ids == ["ALL"]


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def test_skills_for_zone_includes_patterns_and_modifiers():
    skills = load_attack_skills()
    found = skills_for_zone("SBX-FS", skills, include_modifiers=True)
    ids = {s.skill_id for s in found}
    assert "AS-FS-ESCAPE" in ids                 # the SBX-FS pattern
    assert "AS-DECLARATIVE-FRAMING" in ids        # the cross-cutting modifier
    assert all(
        s.is_modifier or "SBX-FS" in s.zone_ids for s in found
    )


def test_skills_for_zone_can_exclude_modifiers():
    skills = load_attack_skills()
    found = skills_for_zone("SBX-FS", skills, include_modifiers=False)
    assert all(not s.is_modifier for s in found)
    assert found, "SBX-FS should still have its pattern skill"


# ---------------------------------------------------------------------------
# Hashing — supports idempotent seeding
# ---------------------------------------------------------------------------


def test_content_hash_is_deterministic():
    a = load_attack_skills()
    b = load_attack_skills()
    by_id_b = {s.skill_id: s for s in b}
    for skill in a:
        assert content_hash(skill) == content_hash(by_id_b[skill.skill_id])


def test_content_hash_changes_with_content():
    skill = load_attack_skills()[0]
    before = content_hash(skill)
    skill.technique += " (edited)"
    assert content_hash(skill) != before


# ---------------------------------------------------------------------------
# Validation — malformed corpus is rejected
# ---------------------------------------------------------------------------


def _write(tmp_path, name, body):
    (tmp_path / name).write_text(textwrap.dedent(body), encoding="utf-8")


def test_unknown_zone_is_rejected(tmp_path):
    _write(tmp_path, "bad.yaml", """
        skill_id: AS-BAD
        name: Bad
        kind: pattern
        provenance: extrapolated
        sources: []
        zone_ids: [NOT-A-ZONE]
        failure_class: secrets_exposure
        interaction_style: direct
        target_defense: identity
        severity_hint: low
        technique: t
        approach_template: a
        success_criteria_template: s
    """)
    with pytest.raises(ValueError, match="unknown zone"):
        load_attack_skills(tmp_path)


def test_research_provenance_requires_sources(tmp_path):
    _write(tmp_path, "bad.yaml", """
        skill_id: AS-BAD
        name: Bad
        kind: pattern
        provenance: research
        sources: []
        zone_ids: [PROMPT-INJ]
        failure_class: secrets_exposure
        interaction_style: direct
        target_defense: identity
        severity_hint: low
        technique: t
        approach_template: a
        success_criteria_template: s
    """)
    with pytest.raises(ValueError, match="no.*sources"):
        load_attack_skills(tmp_path)


def test_modifier_must_be_all_zones(tmp_path):
    _write(tmp_path, "bad.yaml", """
        skill_id: AS-BAD
        name: Bad
        kind: modifier
        provenance: extrapolated
        sources: []
        zone_ids: [PROMPT-INJ]
        failure_class: secrets_exposure
        interaction_style: direct
        target_defense: identity
        severity_hint: low
        technique: t
        approach_template: a
        success_criteria_template: s
    """)
    with pytest.raises(ValueError, match="modifier"):
        load_attack_skills(tmp_path)


def test_missing_directory_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        load_attack_skills(tmp_path / "does-not-exist")
