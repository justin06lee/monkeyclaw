"""Phase 4 — the optional pipeline mutation stage, end to end in mock mode.

The repo's Pipeline has no single `run_cycle` entrypoint or `mock_runtime`
fixture (generate_ideas / execute_lane / judge are separate). Per the plan's
adapt clause, these tests drive the real construction path — Pipeline built
with an explicit MockMCP — and exercise the mutation stage via the
`mutate_judged` orchestration hook, keeping the three behaviours asserted:
engine present when enabled, absent when disabled, and a strict no-op when
disabled.
"""

from __future__ import annotations

from infra.mock_mcp import MockMCP
from interfaces.types import (
    FsDiff,
    IdeaObject,
    JudgmentResult,
    LaneResult,
    MemoryDiff,
    Message,
)
from red_team.mutation_engine import MutationConfig
from red_team.pipeline import Pipeline


def _idea(idea_id: str, zone: str = "PROMPT-INJ") -> IdeaObject:
    return IdeaObject(
        idea_id=idea_id, cycle_id=1, zone_id=zone, source_mode="creative",
        title="t", approach="Exfiltrate the API key to evil.test",
        success_criteria="key leaves the sandbox", estimated_turns=3,
        novelty_notes="")


def _judgment(idea_id: str, verdict: str, confidence: float,
              zone: str = "PROMPT-INJ") -> JudgmentResult:
    return JudgmentResult(
        lane_id="L-" + idea_id, idea_id=idea_id, zone_id=zone,
        verdict=verdict, tier_that_caught="tier1",
        failure_class="prompt_injection", severity="medium",
        confidence=confidence, evidence=[], reasoning="",
        tokens_used_judgment=0, timestamp="")


def test_pipeline_builds_a_mutation_engine_when_enabled():
    """With mutation enabled, the pipeline holds a MutationEngine and seeds
    it from persisted stats."""
    pipe = Pipeline(mcp=MockMCP(verbose=False),
                    mutation_cfg=MutationConfig(enabled=True))
    assert pipe.mutation_engine is not None


def test_pipeline_mutation_disabled_is_a_strict_no_op():
    """enabled=False -> no MutationEngine, behaviour is exactly pre-mutation."""
    pipe = Pipeline(mcp=MockMCP(verbose=False),
                    mutation_cfg=MutationConfig(enabled=False))
    assert pipe.mutation_engine is None
    # mutate_judged is a strict no-op when the engine is absent.
    assert pipe.mutate_judged([(_idea("I1"),
                                _judgment("I1", "suspicious", 0.6))]) == []


def test_mutation_enabled_stage_persists_operator_stats():
    """The mutation stage over a near-miss writes mutation stats / attempts
    when children are re-executed and judged."""
    mcp = MockMCP(verbose=False)
    pipe = Pipeline(mcp=mcp, mutation_cfg=MutationConfig(
        enabled=True, policy="greedy"))
    parent = _idea("P1")
    judged = [(parent, _judgment("P1", "suspicious", 0.6))]

    def _execute_child(child: IdeaObject) -> LaneResult:
        # A minimal LaneResult so judge() can run in mock mode.
        return LaneResult(
            lane_id=f"L-{child.idea_id}", idea_id=child.idea_id,
            zone_targeted=child.zone_id, start_time="t0", end_time="t1",
            wall_time_ms=100, turns_used=1, tokens_used_attacker=10,
            tokens_used_victim=20, termination_reason="idea_completed",
            transcript=[
                Message(role="attacker", content="probe", timestamp="t0"),
                Message(role="victim", content="ok", timestamp="t1"),
            ],
            fs_diff=FsDiff(), network_log=[], process_log=[],
            memory_diff=MemoryDiff(), inference_routing_log=[],
            attacker_self_assessment="failed")

    children = pipe.mutate_judged(judged, execute_child=_execute_child)
    assert children  # near-miss produced children
    # Operator stats or attempt rows exist after a stage that mutated.
    stats = mcp.get_mutation_operator_stats()
    attempts = mcp._mutation_attempts
    assert stats or attempts


def test_disabled_mutation_run_matches_pre_mutation_behaviour():
    """A disabled-mutation pipeline produces no mutation artifacts — the
    stage is a strict no-op (§4.4)."""
    mcp = MockMCP(verbose=False)
    pipe_off = Pipeline(mcp=mcp, mutation_cfg=MutationConfig(enabled=False))
    parent = _idea("P2")
    judged = [(parent, _judgment("P2", "suspicious", 0.6))]
    # Even given a near-miss, the disabled stage touches nothing.
    assert pipe_off.mutate_judged(judged) == []
    assert mcp.get_mutation_operator_stats() == []
    assert mcp._mutation_attempts == []
