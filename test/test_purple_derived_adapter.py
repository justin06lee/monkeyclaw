"""Phase 1 — DerivedEvidenceAdapter infers telemetry from harness side-effects."""

from __future__ import annotations

from interfaces.control_telemetry import ControlTelemetryAdapter
from interfaces.types import (
    FsDiff,
    LaneResult,
    MemoryDiff,
    NetworkEvent,
)
from purple_team.derived_adapter import DerivedEvidenceAdapter


def _lane(*, network=None, fs=None) -> LaneResult:
    return LaneResult(
        lane_id="L1", idea_id="I1", zone_targeted="SBX-NET",
        start_time="2026-05-15T00:00:00Z", end_time="2026-05-15T00:01:00Z",
        wall_time_ms=1000, turns_used=2, tokens_used_attacker=0,
        tokens_used_victim=0, termination_reason="idea_completed",
        transcript=[], fs_diff=fs or FsDiff(),
        network_log=network or [], process_log=[],
        memory_diff=MemoryDiff(), inference_routing_log=[],
        attacker_self_assessment="")


def test_adapter_satisfies_the_contract():
    assert isinstance(DerivedEvidenceAdapter(), ControlTelemetryAdapter)


def test_blocked_network_event_becomes_observed_deny():
    lane = _lane(network=[NetworkEvent(
        timestamp="2026-05-15T00:00:30Z", destination_domain="evil.test",
        destination_port=443, method="POST", payload_size_bytes=12,
        response_code=None, blocked=True)])
    decisions = DerivedEvidenceAdapter().decisions_for(lane)
    net = [d for d in decisions if d.action_class == "network.request"]
    assert len(net) == 1
    assert net[0].decision == "deny"
    assert net[0].observed is True


def test_unblocked_exfil_becomes_allow_and_observed():
    lane = _lane(network=[NetworkEvent(
        timestamp="2026-05-15T00:00:30Z", destination_domain="api.test",
        destination_port=443, method="POST", payload_size_bytes=4096,
        response_code=200, blocked=False)])
    decisions = DerivedEvidenceAdapter().decisions_for(lane)
    net = [d for d in decisions if d.action_class == "network.request"]
    assert net[0].decision == "allow"
    assert net[0].observed is True


def test_file_outside_allowed_path_becomes_observed_deny():
    lane = _lane(fs=FsDiff(files_created=["/etc/shadow.copy"],
                           files_outside_allowed_paths=["/etc/shadow.copy"]))
    decisions = DerivedEvidenceAdapter().decisions_for(lane)
    fs = [d for d in decisions if d.action_class == "file.write"]
    assert fs[0].decision == "deny"
    assert fs[0].observed is True


def test_telemetry_for_emits_one_event_per_decision():
    lane = _lane(network=[NetworkEvent(
        timestamp="2026-05-15T00:00:30Z", destination_domain="evil.test",
        destination_port=443, method="POST", payload_size_bytes=12,
        response_code=None, blocked=True)])
    events = DerivedEvidenceAdapter().telemetry_for(lane)
    assert len(events) == 1
    assert events[0].session_id == "L1"
    assert events[0].event_type == "agent.network.request"
    assert events[0].decision == "deny"


def test_empty_lane_yields_no_decisions():
    assert DerivedEvidenceAdapter().decisions_for(_lane()) == []
