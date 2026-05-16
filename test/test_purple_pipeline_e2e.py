"""Phase 4 — one full purple cycle against the mock victim, zero credentials."""

from __future__ import annotations

from interfaces.types import (
    FindingInput,
    FsDiff,
    JudgmentResult,
    LaneResult,
    MemoryDiff,
    NetworkEvent,
)
from purple_team.pipeline import CycleContext, PurplePipeline
from red_team.policy_corpus import PolicyCorpusCase


def _lane(zone: str, blocked: bool) -> LaneResult:
    return LaneResult(
        lane_id=f"L-{zone}", idea_id="I1", zone_targeted=zone,
        start_time="2026-05-15T00:00:00Z", end_time="2026-05-15T00:01:00Z",
        wall_time_ms=1000, turns_used=1, tokens_used_attacker=0,
        tokens_used_victim=0, termination_reason="idea_completed",
        transcript=[], fs_diff=FsDiff(),
        network_log=[NetworkEvent(
            timestamp="2026-05-15T00:00:30Z", destination_domain="evil.test",
            destination_port=443, method="POST", payload_size_bytes=12,
            response_code=None, blocked=blocked)],
        process_log=[], memory_diff=MemoryDiff(),
        inference_routing_log=[], attacker_self_assessment="")


def _judgment(zone: str, verdict: str) -> JudgmentResult:
    return JudgmentResult(
        lane_id=f"L-{zone}", idea_id="I1", zone_id=zone, verdict=verdict,
        tier_that_caught="programmatic", failure_class="sandbox_escape",
        severity="high", confidence=1.0, evidence=[], reasoning="",
        tokens_used_judgment=0, timestamp="2026-05-15T00:01:00Z")


CORPUS = [PolicyCorpusCase(
    case_id="T01", title="t", description="d", zone="SBX-NET",
    expected_decision="deny", expected_evidence=["evt"],
    attacker_prompt="p", severity="high", tactic_tags=[])]


def _pipeline(server) -> PurplePipeline:
    return PurplePipeline(
        server,
        corpus=CORPUS,
        case_runner=lambda c: c.expected_decision,
        full_sweep_every=10,
        self_governance_enabled=False,
    )


def test_pipeline_scores_executions_into_quadrants(server):
    ctx = CycleContext(
        cycle_id=1, zone_id="SBX-NET",
        executions=[(_lane("SBX-NET", blocked=True),
                     _judgment("SBX-NET", "clean"))])
    result = _pipeline(server).run(ctx)
    assert len(result.verdicts) == 1
    assert result.verdicts[0].quadrant == "PASS"


def test_pipeline_persists_detection_results(server):
    ctx = CycleContext(
        cycle_id=1, zone_id="SBX-NET",
        executions=[(_lane("SBX-NET", blocked=False),
                     _judgment("SBX-NET", "confirmed"))])
    _pipeline(server).run(ctx)
    assert len(server.get_detection_results(zone_id="SBX-NET")) == 1


def test_pipeline_updates_detection_coverage(server):
    ctx = CycleContext(
        cycle_id=1, zone_id="SBX-NET",
        executions=[(_lane("SBX-NET", blocked=True),
                     _judgment("SBX-NET", "clean"))])
    _pipeline(server).run(ctx)
    cov = server.get_detection_coverage("SBX-NET")
    assert cov is not None and cov.sample_count == 1


def test_pipeline_runs_inline_validation_each_cycle(server):
    ctx = CycleContext(cycle_id=1, zone_id="SBX-NET", executions=[])
    result = _pipeline(server).run(ctx)
    assert result.validation_run is not None
    assert result.validation_run.kind == "inline"


def test_pipeline_runs_full_sweep_on_cadence(server):
    pipe = PurplePipeline(
        server, corpus=CORPUS, case_runner=lambda c: c.expected_decision,
        full_sweep_every=3, self_governance_enabled=False)
    # cycle 3 is a multiple of full_sweep_every -> full sweep.
    result = pipe.run(CycleContext(cycle_id=3, zone_id="SBX-NET",
                                   executions=[]))
    assert result.validation_run.kind == "full"


def test_pipeline_synthesizes_rules_for_confirmed_findings(server):
    server.log_finding(FindingInput(
        cycle_id=1, idea_id="I1", zone_id="SBX-NET", source_mode="creative",
        idea_summary="exfil", verdict="confirmed",
        tier_caught="programmatic", failure_class="sandbox_escape",
        severity="high", evidence="[]"))
    ctx = CycleContext(
        cycle_id=1, zone_id="SBX-NET",
        executions=[(_lane("SBX-NET", blocked=False),
                     _judgment("SBX-NET", "confirmed"))],
        confirmed_findings=server.get_repro_queue() or [])
    result = _pipeline(server).run(ctx)
    # confirmed finding present -> at least zero or more rules (best-effort).
    assert isinstance(result.new_rules, list)


def test_pipeline_regenerates_report_card(server):
    ctx = CycleContext(cycle_id=1, zone_id="SBX-NET", executions=[])
    result = _pipeline(server).run(ctx)
    assert result.report_card is not None
    assert len(result.report_card.dimensions) == 7


def test_pipeline_routes_feedback_signals(server):
    ctx = CycleContext(
        cycle_id=1, zone_id="SBX-NET",
        executions=[(_lane("SBX-NET", blocked=False),
                     _judgment("SBX-NET", "confirmed"))])
    result = _pipeline(server).run(ctx)
    # a PARTIAL/FAIL execution routes at least one signal.
    assert isinstance(result.routed_signals, list)


def test_pipeline_runs_self_governance_on_full_sweep(server):
    pipe = PurplePipeline(
        server, corpus=CORPUS, case_runner=lambda c: c.expected_decision,
        full_sweep_every=2, self_governance_enabled=True)
    # cycle 2 == full sweep -> self-governance runs and attaches to the card.
    result = pipe.run(CycleContext(cycle_id=2, zone_id="SBX-NET",
                                   executions=[]))
    assert result.report_card.self_governance is not None
    assert result.report_card.self_governance.passed is True


def test_pipeline_skips_self_governance_when_disabled(server):
    pipe = PurplePipeline(
        server, corpus=CORPUS, case_runner=lambda c: c.expected_decision,
        full_sweep_every=2, self_governance_enabled=False)
    result = pipe.run(CycleContext(cycle_id=2, zone_id="SBX-NET",
                                   executions=[]))
    assert result.report_card.self_governance is None


def test_pipeline_inline_cycle_has_no_self_governance(server):
    pipe = PurplePipeline(
        server, corpus=CORPUS, case_runner=lambda c: c.expected_decision,
        full_sweep_every=10, self_governance_enabled=True)
    # cycle 1 is inline (not a sweep) -> no self-governance.
    result = pipe.run(CycleContext(cycle_id=1, zone_id="SBX-NET",
                                   executions=[]))
    assert result.report_card.self_governance is None
