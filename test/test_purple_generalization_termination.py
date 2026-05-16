"""Phase 2 — the loop provably terminates within max_rounds + 1 rounds."""

from __future__ import annotations

import itertools
from dataclasses import dataclass

from infra.mock_mcp import MockMCP
from interfaces.types import (CheckResult, FsDiff, LaneResult, MemoryDiff,
                              Message)
from purple_team.generalization_loop import (GeneralizationConfig,
                                             GeneralizationLoop)


@dataclass
class _Patch:
    patch_id: str = "P0"
    zone_id: str = "PROMPT-INJ"
    vuln_ids: tuple = ("MC-2026-0001",)


@dataclass
class _Task:
    task_id: str = "T1"
    recommended_approach: str = "Block it."
    severity: str = "high"


class _Package:
    def __init__(self) -> None:
        self.transcripts = {"minimal": [Message(
            role="attacker", content="attack", timestamp="t")]}
        self.affected_zone = "PROMPT-INJ"
        self.finding_id = "F1"
        self.vuln_id = "MC-2026-0001"


def _lane(transcript) -> LaneResult:  # noqa: ANN001
    return LaneResult(
        lane_id="L1", idea_id="I1", zone_targeted="PROMPT-INJ",
        start_time="", end_time="", wall_time_ms=1, turns_used=1,
        tokens_used_attacker=0, tokens_used_victim=0,
        termination_reason="completed", transcript=transcript,
        fs_diff=FsDiff(), network_log=[], process_log=[],
        memory_diff=MemoryDiff(), inference_routing_log=[],
        attacker_self_assessment="")


class _Gen:
    def generate_for_task(self, task):  # noqa: ANN001
        return [_Patch(patch_id="P-next")]


def test_loop_terminates_for_every_judge_verifier_combination():
    """Across the cross-product of judge verdicts and verifier approvals the
    loop always returns within max_rounds + 1 persisted rounds."""
    verdicts = ["confirmed", "suspicious", "clean"]
    approves = [True, False]
    for verdict, approve in itertools.product(verdicts, approves):
        mcp = MockMCP()

        @dataclass
        class _Outcome:
            approved: bool

        class _Ver:
            def __init__(self, approved: bool) -> None:
                self._approved = approved

            def verify(self, *, patch, package, test_pair):  # noqa: ANN001
                return _Outcome(approved=self._approved)

        ev = [] if verdict == "clean" else [CheckResult(
            check_name="x", triggered=True, severity="high")]
        loop = GeneralizationLoop(
            mcp=mcp, replay_fn=_lane,
            judge_fn=lambda lane, v=verdict, e=ev: (v, e),
            patch_generator=_Gen(), patch_verifier=_Ver(approve),
            cfg=GeneralizationConfig(max_rounds=3))
        result = loop.run(_Patch(), _Package(), test_pair=None, task=_Task())
        assert result.status in ("generalized", "unconverged")
        # round 0 plus at most max_rounds bounce rounds.
        assert 1 <= len(result.rounds) <= 4
