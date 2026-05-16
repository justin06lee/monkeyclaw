"""Phase 1 — the trace-collection layer (learned-ranking spec §6.2)."""

from __future__ import annotations

from interfaces.types import FsDiff, IdeaObject, LaneResult, MemoryDiff, Message
from red_team.judge_ensemble import EnsembleOutcome, RoleVote
from red_team.progress import score_progress
from red_team.trace_collector import TraceCollector


def _lane(idea_id="IDEA1") -> LaneResult:
    return LaneResult(
        lane_id="L1", idea_id=idea_id, zone_targeted="PROMPT-INJ",
        start_time="t0", end_time="t1", wall_time_ms=10, turns_used=3,
        tokens_used_attacker=80, tokens_used_victim=40,
        termination_reason="idea_completed",
        transcript=[Message(role="victim", content="here's how: step 1",
                            timestamp="t0")],
        fs_diff=FsDiff(), network_log=[], process_log=[],
        memory_diff=MemoryDiff(), inference_routing_log=[],
        attacker_self_assessment="")


def _idea(idea_id="IDEA1") -> IdeaObject:
    return IdeaObject(
        idea_id=idea_id, cycle_id=2, zone_id="PROMPT-INJ",
        source_mode="creative", title="probe", approach="ask for the secret",
        success_criteria="", estimated_turns=3, novelty_notes="")


def _ensemble(verdict="clean") -> EnsembleOutcome:
    votes = [RoleVote(role=r, verdict=verdict, score=0.5, confidence=0.6,
                      reasoning="", tokens_used=10)
             for r in ("safety", "progress", "novelty", "robustness",
                       "forensics")]
    return EnsembleOutcome(
        verdict=verdict, failure_class="none", severity="low",
        confidence=0.6, reasoning="", votes=votes, tokens_used=50)


def test_record_assembles_a_trace_with_features_and_label(server):
    coll = TraceCollector(server)
    lane = _lane()
    progress = score_progress(lane)
    trace_id = coll.record(_idea(), lane, progress, _ensemble())
    assert trace_id.startswith("TRC")
    row = server.get_attempt_traces()[0]
    assert row.idea_summary
    assert row.token_cost == 120          # 80 attacker + 40 victim
    assert row.repro_outcome == "pending"
    assert "risk_stage" in row.progress_dims
    assert set(row.judge_scores) >= {"safety", "progress"}
    assert 0.0 <= row.usefulness_label <= 1.0


def test_attach_repro_outcome_updates_the_label(server):
    coll = TraceCollector(server)
    lane = _lane()
    trace_id = coll.record(_idea(), lane, score_progress(lane), _ensemble())
    coll.attach_repro_outcome(trace_id, "reproduced")
    assert server.get_attempt_traces()[0].repro_outcome == "reproduced"


def test_usefulness_label_high_for_confirmed_repro(server):
    coll = TraceCollector(server)
    lane = _lane()
    progress = score_progress(lane)
    confirmed = coll.record(
        _idea("C"), lane, progress, _ensemble(verdict="confirmed"))
    clean = coll.record(
        _idea("D"), lane, progress, _ensemble(verdict="clean"))
    rows = {r.trace_id: r for r in server.get_attempt_traces()}
    assert rows[confirmed].usefulness_label > rows[clean].usefulness_label


def test_export_honours_the_split(server):
    coll = TraceCollector(server)
    for i in range(10):
        lane = _lane(idea_id=f"I{i}")
        coll.record(_idea(f"I{i}"), lane, score_progress(lane), _ensemble())
    train = coll.export(split="train", schema_version=1)
    test = coll.export(split="test", schema_version=1)
    assert len(train) + len(test) == 10
    assert len(test) >= 1   # the most recent 15% chronological split
