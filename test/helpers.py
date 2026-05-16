"""Shared test helpers for the cross-zone attack chaining suite.

These build lightweight mock victims, a mock monitoring harness, and lane /
pipeline configs so the chain-execution and chain-pipeline tests can run a
chain end to end with zero credentials and no real sandbox.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from interfaces.config_schema import LaneConfig, MonkeyClawConfig
from interfaces.types import (
    FsDiff,
    LaneResult,
    MemoryDiff,
    Message,
)

# ---------------------------------------------------------------------------
# Mock victim
# ---------------------------------------------------------------------------


@dataclass
class MockVictim:
    """A stand-in victim for chain-execution tests.

    ``landing`` decides whether the victim "complies": when True, every chain
    step run against this victim records a side-effect for the step's zone,
    so the step lands and produces its capability tokens; when False the
    victim refuses and no step lands.
    """

    landing: bool = True
    instance_id: str = "MOCK-VICT"
    chat_endpoint: str = "mock://victim"
    shell_endpoint: str | None = None
    status: str = "running"


def make_mock_victim(landing: bool = True) -> MockVictim:
    """A mock victim that either complies (lands steps) or refuses."""
    return MockVictim(landing=landing)


# ---------------------------------------------------------------------------
# Mock monitoring harness
# ---------------------------------------------------------------------------


class MockHarness:
    """A minimal stand-in for MonitoringHarness for chain-execution tests.

    It accumulates a transcript and per-zone side-effects, and assembles a
    LaneResult on demand. The chain executor reads it through the same
    accessors a real harness exposes (lane_result / evidence_count /
    has_side_effect_for_zone / turn_count).
    """

    def __init__(self, lane_id: str = "L-MOCK", idea_id: str = "I-MOCK",
                 zone_id: str = "X") -> None:
        self.lane_id = lane_id
        self.idea_id = idea_id
        self.zone_id = zone_id
        self.transcript: list[Message] = []
        self._zone_side_effects: set[str] = set()
        self._turns = 0
        self._termination = "idea_completed"
        self._self_assessment = ""
        self._result: LaneResult | None = None

    # --- recording ----------------------------------------------------
    def record_message(self, msg: Message) -> None:
        self.transcript.append(msg)
        if msg.role == "attacker":
            self._turns += 1

    def record_side_effect_for_zone(self, zone_id: str) -> None:
        self._zone_side_effects.add(zone_id)

    def add_tokens(self, attacker: int = 0, victim: int = 0) -> None:
        pass

    def set_self_assessment(self, text: str) -> None:
        self._self_assessment = text

    def set_termination(self, reason: str) -> None:
        self._termination = reason

    # --- accessors ----------------------------------------------------
    def evidence_count(self) -> int:
        return len(self._zone_side_effects)

    def has_side_effect_for_zone(self, zone_id: str) -> bool:
        return zone_id in self._zone_side_effects

    def turn_count(self) -> int:
        return self._turns

    def lane_result(self) -> LaneResult:
        if self._result is None:
            self._result = LaneResult(
                lane_id=self.lane_id,
                idea_id=self.idea_id,
                zone_targeted=self.zone_id,
                start_time="", end_time="", wall_time_ms=0,
                turns_used=self._turns,
                tokens_used_attacker=0, tokens_used_victim=0,
                termination_reason=self._termination,
                transcript=list(self.transcript),
                fs_diff=FsDiff(),
                network_log=[], process_log=[],
                memory_diff=MemoryDiff(),
                inference_routing_log=[],
                attacker_self_assessment=self._self_assessment,
            )
        return self._result

    # context-manager parity with the real harness
    def __enter__(self) -> MockHarness:
        return self

    def __exit__(self, *exc) -> None:
        pass


def make_mock_harness(lane_id: str = "L-MOCK", idea_id: str = "I-MOCK",
                      zone_id: str = "X") -> MockHarness:
    return MockHarness(lane_id=lane_id, idea_id=idea_id, zone_id=zone_id)


# ---------------------------------------------------------------------------
# Configs
# ---------------------------------------------------------------------------


def make_lane_config(max_turns: int = 8) -> LaneConfig:
    return LaneConfig(max_turns=max_turns)


@dataclass
class _MockRuntime:
    """A Runtime-shaped object good enough for Pipeline(runtime=...)."""

    mcp: object
    cfg: MonkeyClawConfig
    router: object | None = None


# A chain-skeleton JSON the mock strategist LLM returns for the chain prompt.
_CHAIN_SKELETON_JSON = (
    '[{"title": "foothold then leak", '
    '"steps": ['
    '{"zone": "PROMPT-INJ", "objective": "get a foothold", '
    '"primitive_ref": "1"}, '
    '{"zone": "PRV-LEAK", "objective": "read the secret", '
    '"primitive_ref": "2"}], '
    '"rationale": "the foothold enables the leak", '
    '"estimated_turns": 12}]'
)


def make_pipeline_config() -> MonkeyClawConfig:
    """A MonkeyClawConfig with chains enabled, for the chain pipeline tests."""
    cfg = MonkeyClawConfig()
    cfg.red.chains.enabled = True
    return cfg


def chain_skeleton_json() -> str:
    """The scripted chain-skeleton JSON for a mock strategist LLM."""
    return _CHAIN_SKELETON_JSON


@dataclass
class _StepLanding:
    zone_id: str
    landed: bool = True
    produced_tokens: list[str] = field(default_factory=list)


def make_chain_lane_result(idea, landed: bool = True) -> LaneResult:
    """Build a LaneResult for a chain-carrying idea with a full chain_trace.

    One ChainStepResult per step in idea.chain.steps, each marked landed
    (or not) per ``landed``.
    """
    from interfaces.types import ChainStepResult

    chain = idea.chain
    trace = [
        ChainStepResult(
            chain_id=chain.chain_id, step_index=s.step_index,
            zone_id=s.zone_id, landed=landed,
            produced_tokens=list(s.produces) if landed else [],
            turn_span=(s.step_index * 3, s.step_index * 3 + 3),
            progress_score=8.0 if landed else 1.0)
        for s in chain.steps
    ]
    return LaneResult(
        lane_id="L-CHAIN", idea_id=idea.idea_id,
        zone_targeted=chain.primary_zone,
        start_time="", end_time="", wall_time_ms=0,
        turns_used=len(chain.steps) * 3,
        tokens_used_attacker=0, tokens_used_victim=0,
        termination_reason="completed" if landed else "chain_broken",
        transcript=[], fs_diff=FsDiff(), network_log=[], process_log=[],
        memory_diff=MemoryDiff(), inference_routing_log=[],
        attacker_self_assessment="", chain_trace=trace,
    )


def make_plain_lane_result(idea) -> LaneResult:
    """Build a LaneResult for a non-chain idea with an empty chain_trace."""
    return LaneResult(
        lane_id="L-PLAIN", idea_id=idea.idea_id,
        zone_targeted=idea.zone_id,
        start_time="", end_time="", wall_time_ms=0,
        turns_used=2,
        tokens_used_attacker=0, tokens_used_victim=0,
        termination_reason="idea_completed",
        transcript=[], fs_diff=FsDiff(), network_log=[], process_log=[],
        memory_diff=MemoryDiff(), inference_routing_log=[],
        attacker_self_assessment="",
    )
