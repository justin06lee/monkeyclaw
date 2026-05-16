"""Phase 3 — detection_synthesizer turns a confirmed finding into a rule."""

from __future__ import annotations

from interfaces.types import FindingRecord
from purple_team.detection_synthesizer import DetectionSynthesizer


def _finding(zone: str, failure_class: str, verdict: str = "confirmed"
             ) -> FindingRecord:
    return FindingRecord(
        finding_id="F1", cycle_id=1, idea_id="I1", zone_id=zone,
        source_mode="creative", idea_summary="exfil via curl",
        verdict=verdict, tier_caught="programmatic",
        failure_class=failure_class, severity="high",
        evidence="[]", repro_rate=1.0, patch_status="open",
        reusability=0.7, created_at="2026-05-15T00:00:00Z")


def test_synthesize_produces_appendix_d_shaped_rule(server):
    synth = DetectionSynthesizer(server)
    rule = synth.synthesize(_finding("SBX-NET", "sandbox_escape"))
    assert rule.zone_id == "SBX-NET"
    assert rule.source_finding_id == "F1"
    assert rule.logic
    assert rule.expected_telemetry_signature
    assert rule.response_action


def test_synthesized_rule_is_persisted(server):
    synth = DetectionSynthesizer(server)
    synth.synthesize(_finding("SBX-FS", "sandbox_escape"))
    rules = server.get_detection_rules(zone_id="SBX-FS")
    assert len(rules) == 1


def test_signature_reflects_the_failure_class(server):
    synth = DetectionSynthesizer(server)
    net = synth.synthesize(_finding("SBX-NET", "sandbox_escape"))
    pii = synth.synthesize(_finding("PRV-LEAK", "pii_leak"))
    assert "network" in net.expected_telemetry_signature.lower()
    assert "pii" in pii.expected_telemetry_signature.lower() \
        or "data" in pii.expected_telemetry_signature.lower()


def test_clean_finding_is_not_synthesized(server):
    synth = DetectionSynthesizer(server)
    rule = synth.synthesize(_finding("SBX-FS", "none", verdict="clean"))
    assert rule is None
    assert server.get_detection_rules(zone_id="SBX-FS") == []
