"""Phase 2 — _parse_ideas technique tagging (spec §6.3, §11)."""

from __future__ import annotations

import json

from interfaces.types import CoverageGap
from red_team.ideation import IdeationEngine, techniques_for
from red_team.taxonomy import load_taxonomy

_TAX = load_taxonomy()
_ZONE = CoverageGap(
    zone_id="PROMPT-INJ", zone_name="Prompt Injection",
    coverage_score=0.1, priority_score=0.9, vulns_open=0,
    last_tested_at=None, severity_weight=1.0,
    description="Direct + indirect prompt injection.")


def _engine(monkeypatch, raw_json):
    from interfaces.llm import LLMClient

    class _FakeLLM(LLMClient):
        def complete(self, **kwargs):
            from interfaces.llm import LLMResponse
            return LLMResponse(text=raw_json, model="fake",
                               prompt_tokens=1, completion_tokens=1)

    class _FakeMCP:
        def get_recent_summaries(self, n):
            return []

    return IdeationEngine(_FakeLLM(), _FakeMCP())


def test_self_reported_clean_ids_are_kept(monkeypatch):
    raw = json.dumps([{
        "title": "Indirect inject via doc", "approach": "x", "impact": "high",
        "success_criteria": "y", "estimated_turns": 3, "novelty_notes": "z",
        "atlas_technique_ids": ["AML.T0051.001"], "owasp_category_ids": ["LLM01"],
    }])
    engine = _engine(monkeypatch, raw)
    ideas = engine._parse_ideas(raw, _ZONE, 1, source_mode="creative",
                                taxonomy=_TAX)
    refs = techniques_for(ideas[0])
    ids = {r.technique_id for r in refs}
    assert "AML.T0051.001" in ids and "LLM01" in ids
    assert any(r.resolved_by == "model" for r in refs)


def test_garbled_id_is_dropped_and_backfilled(monkeypatch):
    raw = json.dumps([{
        "title": "An LLM prompt injection trick", "approach": "x",
        "impact": "high", "success_criteria": "y", "estimated_turns": 3,
        "novelty_notes": "n", "atlas_technique_ids": ["AML.T9999"],
    }])
    engine = _engine(monkeypatch, raw)
    ideas = engine._parse_ideas(raw, _ZONE, 1, source_mode="creative",
                                taxonomy=_TAX)
    refs = techniques_for(ideas[0])
    ids = {r.technique_id for r in refs}
    assert "AML.T9999" not in ids
    assert "AML.T0051" in ids  # backfilled by resolve()


def test_untagged_idea_survives_with_empty_tag_set(monkeypatch):
    raw = json.dumps([{
        "title": "zxqv plover widget", "approach": "x", "impact": "low",
        "success_criteria": "y", "estimated_turns": 3, "novelty_notes": "n",
    }])
    engine = _engine(monkeypatch, raw)
    ideas = engine._parse_ideas(raw, _ZONE, 1, source_mode="creative",
                                taxonomy=_TAX)
    assert len(ideas) == 1
    assert techniques_for(ideas[0]) == []


def test_tags_are_folded_into_novelty_notes(monkeypatch):
    raw = json.dumps([{
        "title": "t", "approach": "x", "impact": "high",
        "success_criteria": "y", "estimated_turns": 3, "novelty_notes": "n",
        "atlas_technique_ids": ["AML.T0051"], "owasp_category_ids": ["LLM01"],
    }])
    engine = _engine(monkeypatch, raw)
    ideas = engine._parse_ideas(raw, _ZONE, 1, source_mode="creative",
                                taxonomy=_TAX)
    assert "atlas=AML.T0051" in ideas[0].novelty_notes
    assert "owasp=LLM01" in ideas[0].novelty_notes


def test_technique_context_block_lists_zone_techniques():
    from red_team.ideation import _technique_context_block

    block = _technique_context_block(_ZONE, _TAX, gap_ids={"AML.T0051.001"})
    assert "AML.T0051" in block
    assert "LLM01" in block
    assert "under-covered" in block.lower()
    assert "AML.T0051.001" in block


def test_technique_context_block_empty_for_unmapped_zone():
    from interfaces.types import CoverageGap
    from red_team.ideation import _technique_context_block

    unmapped = CoverageGap(
        zone_id="SBX-FS", zone_name="fs", coverage_score=0.0,
        priority_score=0.0, vulns_open=0, last_tested_at=None,
        severity_weight=1.0, description="")
    block = _technique_context_block(unmapped, _TAX, gap_ids=set())
    assert "AML.T0072" in block  # SBX-FS is mapped
