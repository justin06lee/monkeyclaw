"""Phase 2 — correlator builds the unified evidence/decision timeline."""

from __future__ import annotations

from interfaces.types import FindingInput, TelemetryEventInput
from purple_team.correlator import Correlator


def _seed_finding(server) -> str:
    return server.log_finding(FindingInput(
        cycle_id=1, idea_id="I1", zone_id="SBX-NET", source_mode="creative",
        idea_summary="exfil attempt", verdict="confirmed",
        tier_caught="programmatic", failure_class="sandbox_escape",
        severity="high", evidence="[]"))


def test_timeline_joins_finding_and_telemetry(server):
    server.log_telemetry_event(TelemetryEventInput(
        session_id="L1", event_type="agent.network.request", actor="victim",
        action_class="network.request", target="evil.test", decision="deny"))
    _seed_finding(server)
    tl = Correlator(server).timeline("L1")
    assert tl.session_id == "L1"
    assert len(tl.telemetry_events) == 1
    assert tl.telemetry_events[0].decision == "deny"


def test_timeline_derives_control_decisions_from_events(server):
    server.log_telemetry_event(TelemetryEventInput(
        session_id="L2", event_type="agent.network.request", actor="victim",
        action_class="network.request", target="evil.test", decision="deny",
        reason_code="blocked_domain"))
    tl = Correlator(server).timeline("L2")
    assert len(tl.control_decisions) == 1
    assert tl.control_decisions[0].decision == "deny"
    assert tl.control_decisions[0].observed is True


def test_timeline_empty_session_is_well_formed(server):
    tl = Correlator(server).timeline("NOPE")
    assert tl.session_id == "NOPE"
    assert tl.telemetry_events == []
    assert tl.finding is None


def test_timeline_attaches_detection_rules_for_the_zone(server):
    from interfaces.types import DetectionRuleInput

    server.log_telemetry_event(TelemetryEventInput(
        session_id="L3", event_type="agent.network.request", actor="victim",
        action_class="network.request", target="x", decision="deny"))
    server.log_detection_rule(DetectionRuleInput(
        zone_id="SBX-NET", source_finding_id="F1", logic="l",
        expected_telemetry_signature="s", response_action="block"))
    tl = Correlator(server, zone_for_session=lambda s: "SBX-NET").timeline("L3")
    assert len(tl.detection_rules) == 1
