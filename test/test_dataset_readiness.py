"""Phase 2 — the dataset-readiness gate (learned-ranking-model spec §8)."""

from __future__ import annotations

from interfaces.types import AttemptTrace
from red_team.dataset_readiness import GateResult, evaluate_readiness

_ZONES = [f"Z{i:02d}" for i in range(14)]
_MODES = ["hard_refusal", "soft_refusal", "partial_compliance",
          "observable_movement"]
_VERDICTS = ["confirmed", "suspicious", "clean"]


def _trace(i, zone, verdict, fmode="clean") -> AttemptTrace:
    return AttemptTrace(
        trace_id=f"T{i}", idea_id=f"idea-{i}", finding_id=None, cycle_id=1,
        zone_id=zone, feature_schema_version=1, idea_summary="x",
        tactic_tags=[], mutation_operator=None, interaction_style="direct",
        progress_dims={"failure_mode_key": fmode}, judge_scores={},
        token_cost=10, repro_outcome="reproduced", judge_verdict=verdict,
        search_score=1.0, archive_niche=f"{zone}|direct|{fmode}",
        usefulness_label=0.5, created_at=f"2026-05-15T00:{i % 60:02d}:00Z")


def _good_dataset() -> list[AttemptTrace]:
    """1000 traces meeting all five criteria."""
    traces = []
    for i in range(1000):
        zone = _ZONES[i % len(_ZONES)]
        verdict = _VERDICTS[i % len(_VERDICTS)]
        fmode = _MODES[i % len(_MODES)]
        traces.append(_trace(i, zone, verdict, fmode))
    return traces


def _good_pairs() -> list:
    from interfaces.types import Preference

    return [
        Preference(pair_id=f"P{i}", trace_a="a", trace_b="b",
                   preferred="a", judge_confidence=0.7,
                   created_at="2026-05-15T00:00:00Z")
        for i in range(350)
    ]


def test_gate_passes_on_a_complete_dataset():
    result = evaluate_readiness(_good_dataset(), _good_pairs())
    assert isinstance(result, GateResult)
    assert result.ready is True
    assert result.failures == []


def test_gate_fails_on_too_few_traces():
    result = evaluate_readiness(_good_dataset()[:200], _good_pairs())
    assert result.ready is False
    assert any("volume" in f.lower() for f in result.failures)


def test_gate_fails_on_too_few_zones():
    traces = [_trace(i, "Z00", _VERDICTS[i % 3], _MODES[i % 4])
              for i in range(1000)]
    result = evaluate_readiness(traces, _good_pairs())
    assert result.ready is False
    assert any("zone" in f.lower() for f in result.failures)


def test_gate_fails_on_too_few_pairwise_labels():
    result = evaluate_readiness(_good_dataset(), _good_pairs()[:50])
    assert result.ready is False
    assert any("pairwise" in f.lower() for f in result.failures)
