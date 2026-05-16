"""NativeEventAdapter — OpenClaw hook-event ingest (native-event-adapter spec).

Covers: the §6 mapping table for every hook, after_tool_call polymorphism,
the 4 decision hooks -> ControlDecision, malformed-line / unknown-hook
handling, offset-resumable tailing, and contract parity with the derived
adapter. All mock mode, zero credentials.
"""

from __future__ import annotations

import json
from pathlib import Path

from interfaces.control_telemetry import ControlTelemetryAdapter
from interfaces.types import FsDiff, LaneResult, MemoryDiff
from purple_team.derived_adapter import DerivedEvidenceAdapter
from purple_team.native_event_adapter import NativeEventAdapter

# --- fixture helpers -------------------------------------------------------

# One JSONL line per OpenClaw hook (spec §6). The 4 decision hooks carry a
# `decision`. session = "S1" via sessionKey on every payload.
_HOOK_LINES: list[dict] = [
    {"hook": "session_start", "ts": 1, "payload": {"sessionKey": "S1"}},
    {"hook": "session_resume", "ts": 2, "payload": {"sessionKey": "S1"}},
    {"hook": "session_end", "ts": 3, "payload": {"sessionKey": "S1"}},
    {"hook": "before_agent_run", "ts": 4, "payload": {"sessionKey": "S1"},
     "decision": {"decision": "allow"}},
    {"hook": "llm_input", "ts": 5, "payload": {"sessionKey": "S1"}},
    {"hook": "model_call_started", "ts": 6, "payload": {"sessionKey": "S1"}},
    {"hook": "model_call_ended", "ts": 7, "payload": {"sessionKey": "S1"}},
    {"hook": "llm_output", "ts": 8, "payload": {"sessionKey": "S1"}},
    {"hook": "before_tool_call", "ts": 9,
     "payload": {"sessionKey": "S1", "toolName": "file_read"},
     "decision": {"decision": "allow"}},
    {"hook": "after_tool_call", "ts": 10,
     "payload": {"sessionKey": "S1", "toolName": "file_read"}},
    {"hook": "subagent_spawning", "ts": 11, "payload": {"sessionKey": "S1"},
     "decision": {"decision": "allow"}},
    {"hook": "subagent_spawned", "ts": 12, "payload": {"sessionKey": "S1"}},
    {"hook": "subagent_ended", "ts": 13, "payload": {"sessionKey": "S1"}},
    {"hook": "agent_end", "ts": 14, "payload": {"sessionKey": "S1"}},
    {"hook": "outbound_dispatch", "ts": 15, "payload": {"sessionKey": "S1"},
     "decision": {"decision": "allow"}},
    {"hook": "message_delivery", "ts": 16, "payload": {"sessionKey": "S1"}},
    {"hook": "network.request.blocked", "ts": 17,
     "payload": {"sessionKey": "S1"}},
]


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def _lane(session: str = "S1") -> LaneResult:
    return LaneResult(
        lane_id=session, idea_id="I1", zone_targeted="SBX-FS",
        start_time="2026-05-16T00:00:00Z", end_time="2026-05-16T00:01:00Z",
        wall_time_ms=1000, turns_used=1, tokens_used_attacker=0,
        tokens_used_victim=0, termination_reason="idea_completed",
        transcript=[], fs_diff=FsDiff(), network_log=[], process_log=[],
        memory_diff=MemoryDiff(), inference_routing_log=[],
        attacker_self_assessment="")


# --- contract parity -------------------------------------------------------


def test_native_adapter_satisfies_the_contract():
    assert isinstance(NativeEventAdapter(), ControlTelemetryAdapter)


def test_both_adapters_satisfy_the_same_contract():
    for adapter in (DerivedEvidenceAdapter(), NativeEventAdapter()):
        assert isinstance(adapter, ControlTelemetryAdapter)


# --- mapping ---------------------------------------------------------------


def test_every_hook_maps_without_skips(tmp_path):
    src = tmp_path / "telemetry.jsonl"
    _write_jsonl(src, _HOOK_LINES)
    result = NativeEventAdapter().ingest(src)
    assert result.lines_read == len(_HOOK_LINES)
    assert result.skipped == 0
    assert result.unknown_hooks == 0


def test_session_hooks_map_to_session_events(tmp_path):
    src = tmp_path / "t.jsonl"
    _write_jsonl(src, _HOOK_LINES)
    adapter = NativeEventAdapter()
    adapter.ingest(src)
    types = {e.event_type for e in adapter.telemetry_for(_lane())}
    assert "agent.session.start" in types
    assert "agent.session.end" in types
    assert "agent.turn.start" in types
    assert "agent.turn.end" in types
    assert "agent.llm.request" in types
    assert "agent.llm.response" in types
    assert "agent.subagent.spawn" in types
    assert "agent.message.out" in types
    assert "agent.network.blocked" in types


def test_decision_hooks_yield_control_decisions(tmp_path):
    src = tmp_path / "t.jsonl"
    _write_jsonl(src, _HOOK_LINES)
    adapter = NativeEventAdapter()
    adapter.ingest(src)
    decisions = adapter.decisions_for(_lane())
    # The 4 decision hooks: before_agent_run, before_tool_call,
    # subagent_spawning, outbound_dispatch.
    assert len(decisions) == 4
    assert all(d.observed is True for d in decisions)
    assert all(d.source == "native" for d in decisions)
    actions = {d.action_class for d in decisions}
    assert {"agent.run", "subagent.spawn", "message.dispatch"} <= actions


def test_after_tool_call_polymorphism(tmp_path):
    cases = [
        ("file_read", "agent.file.read"),
        ("file_write", "agent.file.write"),
        ("file_delete", "agent.file.delete"),
        ("bash", "agent.shell.ended"),
        ("exec", "agent.shell.ended"),
        ("shell", "agent.shell.ended"),
        ("browser_navigate", "agent.browser.navigate"),
        ("mcp_github", "agent.mcp.invoked"),
        ("some_other_tool", "agent.tool.ended"),
    ]
    for tool, expected in cases:
        src = tmp_path / f"{tool}.jsonl"
        _write_jsonl(src, [{
            "hook": "after_tool_call", "ts": 1,
            "payload": {"sessionKey": "S1", "toolName": tool}}])
        adapter = NativeEventAdapter()
        adapter.ingest(src)
        events = adapter.telemetry_for(_lane())
        assert [e.event_type for e in events] == [expected], tool


def test_blocked_shell_tool_emits_shell_blocked(tmp_path):
    src = tmp_path / "t.jsonl"
    _write_jsonl(src, [{
        "hook": "before_tool_call", "ts": 1,
        "payload": {"sessionKey": "S1", "toolName": "bash"},
        "decision": {"decision": "block"}}])
    adapter = NativeEventAdapter()
    adapter.ingest(src)
    events = adapter.telemetry_for(_lane())
    assert any(e.event_type == "agent.shell.blocked" for e in events)
    decisions = adapter.decisions_for(_lane())
    assert decisions[0].decision == "deny"


def test_blocked_mcp_tool_emits_mcp_blocked(tmp_path):
    src = tmp_path / "t.jsonl"
    _write_jsonl(src, [{
        "hook": "before_tool_call", "ts": 1,
        "payload": {"sessionKey": "S1", "toolName": "mcp_filesystem"},
        "decision": {"decision": "block"}}])
    adapter = NativeEventAdapter()
    adapter.ingest(src)
    assert any(e.event_type == "agent.mcp.blocked"
               for e in adapter.telemetry_for(_lane()))


def test_require_approval_emits_approval_requested(tmp_path):
    src = tmp_path / "t.jsonl"
    _write_jsonl(src, [{
        "hook": "before_tool_call", "ts": 1,
        "payload": {"sessionKey": "S1", "toolName": "file_write"},
        "decision": {"decision": "requireApproval"}}])
    adapter = NativeEventAdapter()
    adapter.ingest(src)
    assert any(e.event_type == "agent.approval.requested"
               for e in adapter.telemetry_for(_lane()))
    assert adapter.decisions_for(_lane())[0].decision == "ask"


# --- error handling --------------------------------------------------------


def test_malformed_line_is_skipped_and_counted(tmp_path):
    src = tmp_path / "t.jsonl"
    src.write_text(
        '{"hook": "session_start", "ts": 1, "payload": {"sessionKey": "S1"}}\n'
        "this is not json\n"
        '{"hook": "session_end", "ts": 2, "payload": {"sessionKey": "S1"}}\n',
        encoding="utf-8")
    adapter = NativeEventAdapter()
    result = adapter.ingest(src)
    assert result.skipped == 1
    assert result.lines_read == 3
    # ingest never aborts — both good lines still mapped.
    assert len(adapter.telemetry_for(_lane())) == 2


def test_unknown_hook_is_skipped_and_counted(tmp_path):
    src = tmp_path / "t.jsonl"
    _write_jsonl(src, [
        {"hook": "session_start", "ts": 1, "payload": {"sessionKey": "S1"}},
        {"hook": "brand_new_hook_v2", "ts": 2, "payload": {"sessionKey": "S1"}},
    ])
    adapter = NativeEventAdapter()
    result = adapter.ingest(src)
    assert result.unknown_hooks == 1
    assert result.skipped == 0
    assert len(adapter.telemetry_for(_lane())) == 1


def test_missing_source_yields_empty_result(tmp_path):
    result = NativeEventAdapter().ingest(tmp_path / "does-not-exist.jsonl")
    assert result.lines_read == 0
    assert result.events == []
    assert result.decisions == []


def test_empty_source_yields_no_events(tmp_path):
    src = tmp_path / "t.jsonl"
    src.write_text("", encoding="utf-8")
    result = NativeEventAdapter().ingest(src)
    assert result.lines_read == 0
    assert result.events == []


# --- offset-resumable tailing ----------------------------------------------


def test_offset_resume_only_reads_new_lines(tmp_path):
    src = tmp_path / "t.jsonl"
    _write_jsonl(src, [
        {"hook": "session_start", "ts": 1, "payload": {"sessionKey": "S1"}}])
    adapter = NativeEventAdapter()
    first = adapter.ingest(src, since_offset=0)
    assert first.lines_read == 1

    # The plugin appends two more lines.
    with src.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(
            {"hook": "llm_input", "ts": 2,
             "payload": {"sessionKey": "S1"}}) + "\n")
        fh.write(json.dumps(
            {"hook": "session_end", "ts": 3,
             "payload": {"sessionKey": "S1"}}) + "\n")

    second = adapter.ingest(src, since_offset=first.offset)
    assert second.lines_read == 2  # only the new lines
    assert second.offset > first.offset
    # All three events accumulated across the two passes.
    assert len(adapter.telemetry_for(_lane())) == 3


def test_records_threaded_by_session(tmp_path):
    src = tmp_path / "t.jsonl"
    _write_jsonl(src, [
        {"hook": "session_start", "ts": 1, "payload": {"sessionKey": "S1"}},
        {"hook": "session_start", "ts": 2, "payload": {"sessionKey": "S2"}},
    ])
    adapter = NativeEventAdapter()
    adapter.ingest(src)
    assert len(adapter.telemetry_for(_lane("S1"))) == 1
    assert len(adapter.telemetry_for(_lane("S2"))) == 1
