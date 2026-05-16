"""Phase 3 — purple pipeline selects the telemetry adapter by config.

The derived adapter stays the default; `telemetry_adapter="native"` swaps
in the NativeEventAdapter and the pipeline ingests the OpenClaw hook-event
JSONL before scoring. The oracle is unchanged either way (spec §3, §8).
"""

from __future__ import annotations

import json

from interfaces.types import (
    FsDiff,
    JudgmentResult,
    LaneResult,
    MemoryDiff,
)
from purple_team.derived_adapter import DerivedEvidenceAdapter
from purple_team.native_event_adapter import NativeEventAdapter
from purple_team.pipeline import CycleContext, PurplePipeline
from red_team.policy_corpus import PolicyCorpusCase

CORPUS = [PolicyCorpusCase(
    case_id="T01", title="t", description="d", zone="SBX-NET",
    expected_decision="deny", expected_evidence=["evt"],
    attacker_prompt="p", severity="high", tactic_tags=[])]


def _lane(session: str) -> LaneResult:
    return LaneResult(
        lane_id=session, idea_id="I1", zone_targeted="SBX-NET",
        start_time="2026-05-16T00:00:00Z", end_time="2026-05-16T00:01:00Z",
        wall_time_ms=1000, turns_used=1, tokens_used_attacker=0,
        tokens_used_victim=0, termination_reason="idea_completed",
        transcript=[], fs_diff=FsDiff(), network_log=[], process_log=[],
        memory_diff=MemoryDiff(), inference_routing_log=[],
        attacker_self_assessment="")


def _judgment(session: str) -> JudgmentResult:
    return JudgmentResult(
        lane_id=session, idea_id="I1", zone_id="SBX-NET", verdict="clean",
        tier_that_caught="programmatic", failure_class="sandbox_escape",
        severity="high", confidence=1.0, evidence=[], reasoning="",
        tokens_used_judgment=0, timestamp="2026-05-16T00:01:00Z")


def test_pipeline_defaults_to_derived_adapter(server):
    pipe = PurplePipeline(
        server, corpus=CORPUS, case_runner=lambda c: c.expected_decision)
    assert isinstance(pipe.adapter, DerivedEvidenceAdapter)


def test_pipeline_selects_native_adapter_by_config(server, tmp_path):
    pipe = PurplePipeline(
        server, corpus=CORPUS, case_runner=lambda c: c.expected_decision,
        telemetry_adapter="native",
        native_event_source=str(tmp_path / "telemetry.jsonl"),
        native_offset_store=str(tmp_path / "telemetry.offset"))
    assert isinstance(pipe.adapter, NativeEventAdapter)


def test_native_pipeline_ingests_hook_jsonl_before_scoring(server, tmp_path):
    src = tmp_path / "telemetry.jsonl"
    src.write_text(
        json.dumps({"hook": "session_start", "ts": 1,
                    "payload": {"sessionKey": "L1"}}) + "\n"
        + json.dumps({"hook": "after_tool_call", "ts": 2,
                      "payload": {"sessionKey": "L1",
                                  "toolName": "file_write"}}) + "\n",
        encoding="utf-8")
    offset = tmp_path / "telemetry.offset"
    pipe = PurplePipeline(
        server, corpus=CORPUS, case_runner=lambda c: c.expected_decision,
        telemetry_adapter="native",
        native_event_source=str(src), native_offset_store=str(offset))
    ctx = CycleContext(
        cycle_id=1, zone_id="SBX-NET",
        executions=[(_lane("L1"), _judgment("L1"))])
    result = pipe.run(ctx)
    assert result.verdicts  # the cycle scored without touching the oracle
    # The adapter ingested the hook events for session L1.
    assert pipe.adapter.telemetry_for(_lane("L1"))
    # The offset was persisted for a resumable next tail.
    assert offset.exists()
    assert int(offset.read_text().strip()) > 0
