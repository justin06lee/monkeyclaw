"""Tests for B7: Policy / Adversarial Corpus.

Proves the acceptance criteria:
- Corpus cases map to zones.
- Corpus cases declare an expected decision and expected evidence.
- Red team can generate ideas from corpus cases.
"""

from __future__ import annotations

import pytest

from interfaces.types import IdeaObject
from red_team.policy_corpus import (
    KNOWN_ZONES,
    VALID_DECISIONS,
    PolicyCorpusCase,
    cases_for_zone,
    corpus_to_ideas,
    load_corpus,
)

EXPECTED_CASE_COUNT = 15


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def test_load_corpus_returns_fifteen_cases():
    cases = load_corpus()
    assert len(cases) == EXPECTED_CASE_COUNT
    assert all(isinstance(c, PolicyCorpusCase) for c in cases)


def test_default_path_resolves_relative_to_repo_root(tmp_path, monkeypatch):
    # Changing cwd must not break the default path resolution.
    monkeypatch.chdir(tmp_path)
    cases = load_corpus()
    assert len(cases) == EXPECTED_CASE_COUNT


def test_case_ids_are_unique():
    case_ids = [c.case_id for c in load_corpus()]
    assert len(case_ids) == len(set(case_ids))


# ---------------------------------------------------------------------------
# Acceptance: cases map to zones
# ---------------------------------------------------------------------------


def test_every_case_maps_to_a_known_zone():
    for case in load_corpus():
        assert case.zone in KNOWN_ZONES, f"{case.case_id} bad zone {case.zone}"


# ---------------------------------------------------------------------------
# Acceptance: cases declare expected decision + evidence
# ---------------------------------------------------------------------------


def test_every_case_has_valid_decision_and_evidence():
    for case in load_corpus():
        assert case.expected_decision in VALID_DECISIONS
        assert isinstance(case.expected_evidence, list)
        assert case.expected_evidence, f"{case.case_id} empty evidence"
        assert all(
            isinstance(e, str) and e.strip() for e in case.expected_evidence
        )
        assert case.attacker_prompt.strip()
        assert case.severity in {"critical", "high", "medium", "low"}


def test_corpus_covers_all_three_decisions():
    decisions = {c.expected_decision for c in load_corpus()}
    assert decisions == VALID_DECISIONS


# ---------------------------------------------------------------------------
# cases_for_zone
# ---------------------------------------------------------------------------


def test_cases_for_zone_filters_correctly():
    cases = load_corpus()
    for zone in {c.zone for c in cases}:
        filtered = cases_for_zone(zone, cases)
        assert filtered, f"no cases for zone {zone}"
        assert all(c.zone == zone for c in filtered)
        expected = [c for c in cases if c.zone == zone]
        assert len(filtered) == len(expected)


def test_cases_for_zone_unknown_zone_returns_empty():
    assert cases_for_zone("NOT-A-ZONE", load_corpus()) == []


def test_cases_for_zone_loads_corpus_when_none():
    # Called without an explicit list -> still works.
    assert isinstance(cases_for_zone("PROMPT-INJ"), list)


# ---------------------------------------------------------------------------
# Acceptance: red team generates ideas from corpus cases
# ---------------------------------------------------------------------------


def test_corpus_to_ideas_returns_fifteen_valid_ideas():
    ideas = corpus_to_ideas(cycle_id=7)
    assert len(ideas) == EXPECTED_CASE_COUNT
    assert all(isinstance(i, IdeaObject) for i in ideas)
    for idea in ideas:
        assert idea.cycle_id == 7
        assert idea.source_mode == "policy_corpus"
        assert idea.zone_id in KNOWN_ZONES
        assert idea.idea_id.startswith("CORPUS-")
        assert idea.title
        assert idea.approach
        assert idea.success_criteria
        assert idea.estimated_turns > 0


def test_corpus_to_ideas_zone_ids_match_cases():
    cases = load_corpus()
    ideas = corpus_to_ideas(cycle_id=1, cases=cases)
    by_id = {i.idea_id: i for i in ideas}
    for case in cases:
        idea = by_id[f"CORPUS-{case.case_id}"]
        assert idea.zone_id == case.zone
        # Evidence and decision flow into the idea.
        for evidence in case.expected_evidence:
            assert evidence in idea.success_criteria
        assert case.expected_decision in idea.success_criteria


def test_corpus_to_ideas_idea_ids_are_deterministic_and_unique():
    ideas_a = corpus_to_ideas(cycle_id=1)
    ideas_b = corpus_to_ideas(cycle_id=2)
    ids_a = [i.idea_id for i in ideas_a]
    ids_b = [i.idea_id for i in ideas_b]
    assert ids_a == ids_b  # deterministic
    assert len(ids_a) == len(set(ids_a))  # unique


# ---------------------------------------------------------------------------
# Validation failures
# ---------------------------------------------------------------------------


def test_load_corpus_missing_file_raises():
    with pytest.raises(ValueError):
        load_corpus("/nonexistent/policy_corpus.yaml")


def test_load_corpus_bad_zone_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "cases:\n"
        "  - case_id: x\n"
        "    title: t\n"
        "    description: d\n"
        "    zone: BOGUS-ZONE\n"
        "    expected_decision: deny\n"
        "    expected_evidence: [e]\n"
        "    attacker_prompt: p\n"
        "    severity: low\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_corpus(str(bad))


def test_load_corpus_bad_decision_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "cases:\n"
        "  - case_id: x\n"
        "    title: t\n"
        "    description: d\n"
        "    zone: PROMPT-INJ\n"
        "    expected_decision: maybe\n"
        "    expected_evidence: [e]\n"
        "    attacker_prompt: p\n"
        "    severity: low\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_corpus(str(bad))


def test_load_corpus_empty_evidence_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "cases:\n"
        "  - case_id: x\n"
        "    title: t\n"
        "    description: d\n"
        "    zone: PROMPT-INJ\n"
        "    expected_decision: deny\n"
        "    expected_evidence: []\n"
        "    attacker_prompt: p\n"
        "    severity: low\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_corpus(str(bad))
