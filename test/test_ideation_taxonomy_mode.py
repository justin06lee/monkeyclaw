"""Phase 4 — Mode D taxonomy ideation (spec §6.3, §7)."""

from __future__ import annotations

import json

from interfaces.types import CoverageGap
from red_team.ideation import IdeationEngine, techniques_for
from red_team.taxonomy import load_taxonomy
from red_team.technique_coverage import TechniqueCoverageModel

_TAX = load_taxonomy()
_ZONE = CoverageGap(
    zone_id="PROMPT-INJ", zone_name="Prompt Injection", coverage_score=0.1,
    priority_score=0.9, vulns_open=0, last_tested_at=None,
    severity_weight=1.0, description="Direct + indirect prompt injection.")


class _FakeLLM:
    """Returns one idea per call, echoing the technique id it was prompted on."""

    def complete(self, *, messages, system, max_tokens, temperature):
        from interfaces.llm import LLMResponse
        prompt = messages[-1].content
        # Match the most specific (longest) technique id present so that
        # 'AML.T0051' does not shadow 'AML.T0051.000'.
        matches = sorted(
            (t.technique_id
             for t in _TAX.techniques_for_zone("PROMPT-INJ")
             if t.technique_id in prompt),
            key=len, reverse=True)
        tid = matches[0] if matches else "AML.T0051"
        body = json.dumps([{
            "title": f"Instantiate {tid}", "approach": "a", "impact": "high",
            "success_criteria": "s", "estimated_turns": 3, "novelty_notes": "n",
            "atlas_technique_ids": [tid],
        }])
        return LLMResponse(text=body, input_tokens=1, output_tokens=1)


def test_mode_d_produces_one_idea_per_gap_technique(server):
    cov = TechniqueCoverageModel(server, _TAX)
    engine = IdeationEngine(_FakeLLM(), object(), technique_coverage=cov)
    ideas = engine._mode_taxonomy(_ZONE, cycle_id=1, gap_top_n=3)
    assert len(ideas) == 3
    for idea in ideas:
        assert idea.source_mode == "taxonomy"
        assert len(techniques_for(idea)) >= 1


def test_mode_d_targets_the_least_covered_techniques(server):
    cov = TechniqueCoverageModel(server, _TAX)
    # Exercise AML.T0051 so it is NOT a gap.
    from interfaces.types import TechniqueRef
    cov.record_attempt("PROMPT-INJ", [TechniqueRef(
        kind="atlas", technique_id="AML.T0051", name="x",
        corpus_version=_TAX.version, resolved_by="model")])
    engine = IdeationEngine(_FakeLLM(), object(), technique_coverage=cov)
    ideas = engine._mode_taxonomy(_ZONE, cycle_id=1, gap_top_n=2)
    tagged = {r.technique_id for i in ideas for r in techniques_for(i)}
    assert "AML.T0051" not in tagged


def test_generate_for_zone_includes_taxonomy_mode(server):
    cov = TechniqueCoverageModel(server, _TAX)
    engine = IdeationEngine(_FakeLLM(), object(), technique_coverage=cov)
    ideas = engine.generate_for_zone(
        _ZONE, cycle_id=1, modes=("taxonomy",))
    assert ideas and all(i.source_mode == "taxonomy" for i in ideas)
