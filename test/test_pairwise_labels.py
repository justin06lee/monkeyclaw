"""Phase 2 — pairwise preference labelling (learned-ranking spec §6.3)."""

from __future__ import annotations

from interfaces.types import AttemptTrace
from red_team.pairwise_labels import PairwiseLabeller


def _trace(trace_id, zone="PROMPT-INJ", verdict="suspicious") -> AttemptTrace:
    return AttemptTrace(
        trace_id=trace_id, idea_id=f"idea-{trace_id}", finding_id=None,
        cycle_id=1, zone_id=zone, feature_schema_version=1,
        idea_summary="probe", tactic_tags=["roleplay"],
        mutation_operator="paraphrase", interaction_style="direct",
        progress_dims={"risk_stage": 3.0}, judge_scores={"safety": 0.5},
        token_cost=100, repro_outcome="pending", judge_verdict=verdict,
        search_score=4.0, archive_niche=f"{zone}|direct|partial_compliance",
        usefulness_label=0.5, created_at="2026-05-15T00:00:00Z")


class _StubJudge:
    """A judge ensemble stub that always prefers trace_a."""

    def compare_pair(self, summary_a, summary_b):  # noqa: ANN001
        return {"preferred": "a", "confidence": 0.75}


def test_sample_pairs_stays_within_zone_failure_buckets():
    traces = [
        _trace("T1", zone="PROMPT-INJ"),
        _trace("T2", zone="PROMPT-INJ"),
        _trace("T3", zone="SBX-FS"),
    ]
    labeller = PairwiseLabeller(_StubJudge())
    pairs = labeller.sample_pairs(traces, budget=4)
    for a, b in pairs:
        assert a.zone_id == b.zone_id
        assert a.judge_verdict == b.judge_verdict


def test_sample_pairs_respects_the_budget():
    traces = [_trace(f"T{i}", zone="PROMPT-INJ") for i in range(20)]
    labeller = PairwiseLabeller(_StubJudge())
    assert len(labeller.sample_pairs(traces, budget=3)) <= 3


def test_compare_records_a_preference(server):
    a = _trace("TA")
    b = _trace("TB")
    labeller = PairwiseLabeller(_StubJudge())
    pref = labeller.compare(a, b)
    assert pref.preferred == "a"
    assert 0.0 <= pref.judge_confidence <= 1.0


def test_compare_skipped_when_judge_unavailable():
    class _DownJudge:
        def compare_pair(self, summary_a, summary_b):  # noqa: ANN001
            raise RuntimeError("judge LLM unavailable")

    labeller = PairwiseLabeller(_DownJudge())
    # A judge failure is skipped, not retried into a cost spike (spec §11).
    assert labeller.compare(_trace("TA"), _trace("TB")) is None
