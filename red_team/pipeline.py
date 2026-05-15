"""Red-team pipeline — the orchestrator entrypoint.

Conforms to `infra.orchestrator.RedTeamPipeline` Protocol:

    class Pipeline:
        def generate_ideas(self, cycle_id: int, n_lanes: int) -> list[IdeaObject]
        def execute_lane(self, idea, victim, harness, lane_cfg) -> None
        def judge(self, lane_result: LaneResult) -> None

Wires:
- IdeationEngine (3 prompt modes) → DedupOutcome[] → PrioritizedIdea[]
- ExecutionAgent runs inside each lane
- Judge (Tier 1 + Tier 2) → routing

Usage from the orchestrator CLI:
    uv run python -m infra.orchestrator \\
        --red red_team.pipeline:Pipeline \\
        --use-mock-provisioner --max-cycles 1
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass

from infra.bootstrap import Runtime
from infra.monitoring_harness import MonitoringHarness
from interfaces.config_schema import LaneConfig, MonkeyClawConfig
from interfaces.llm import LLMClient, make_llm
from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.provisioning import VictimInstance
from interfaces.types import (
    AgentPolicy,
    CoverageGap,
    CycleSummaryInput,
    IdeaObject,
    LaneResult,
    PolicyConfig,
    SeccompProfile,
)

from red_team.dedup import deduplicate_and_log
from red_team.execution_agent import ExecutionAgent, ExecutionConfig
from red_team.ideation import IdeationConfig, IdeationEngine
from red_team.judge import Judge, JudgeConfig
from red_team.priority import select_top_n
from red_team.routing import route_judgment

LOG = logging.getLogger("monkeyclaw.red.pipeline")


# ---------------------------------------------------------------------------
# Policy construction — derived from the runtime config
# ---------------------------------------------------------------------------


DEFAULT_CLOUD_DOMAINS = [
    # Allowlist of standard cloud-LLM endpoints. They're permitted for
    # non-PII content; PII routed to them is still caught by
    # check_pii_in_cloud_route. Without these in allowed_domains the
    # network check would flag every legitimate cloud inference call.
    "*.anthropic.com",
    "*.openai.com",
    "*.googleapis.com",
    "api.nemoclaw.local",
]


def policy_from_config(cfg: MonkeyClawConfig) -> PolicyConfig:
    """Map MonkeyClawConfig.nemoclaw into a PolicyConfig for Tier 1 checks."""
    return PolicyConfig(
        allowed_paths=list(cfg.nemoclaw.allowed_paths),
        allowed_domains=list(DEFAULT_CLOUD_DOMAINS),
        seccomp_profile=SeccompProfile(
            allowed_syscalls=[],
            blocked_syscalls=["execve", "ptrace", "kexec_load",
                              "init_module", "delete_module"],
            default_action="deny",
        ),
        agent_policy=AgentPolicy(
            agent_id="nemoclaw_default",
            allowed_capabilities=["chat", "read_files:/tmp/openshell"],
            denied_capabilities=["install_skill:unsigned", "exec:privileged"],
        ),
        policy_paths=[cfg.nemoclaw.default_policy_path],
    )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


@dataclass
class _PerIdeaContext:
    """We need to remember each idea by ID to pair lane results with its
    source on judgment. Built when generate_ideas runs, consulted in judge()."""
    idea: IdeaObject


class Pipeline:
    """Person 2's pipeline. Bound via `--red red_team.pipeline:Pipeline`."""

    def __init__(
        self,
        runtime: Runtime | None = None,
        *,
        mcp: MonkeyClawMCP | None = None,
        llm: LLMClient | None = None,
        policy: PolicyConfig | None = None,
        ideation_cfg: IdeationConfig | None = None,
        execution_cfg: ExecutionConfig | None = None,
        judge_cfg: JudgeConfig | None = None,
        alert_severity_floor: str = "high",
    ) -> None:
        if runtime is not None:
            self.mcp = runtime.mcp
            self.cfg = runtime.cfg
        else:
            if mcp is None:
                raise ValueError(
                    "Pipeline needs either a Runtime or explicit `mcp=`. "
                    "When loaded by the orchestrator, the runtime is passed automatically."
                )
            self.mcp = mcp
            # Build a default config view good enough for tests.
            self.cfg = MonkeyClawConfig()

        self.llm = llm or make_llm()
        self.policy = policy or policy_from_config(self.cfg)
        ideation_cfg = ideation_cfg or IdeationConfig(
            temperature=self.cfg.ideation.temperature,
            max_tokens_per_mode=self.cfg.ideation.max_tokens_per_mode,
            retry_max=self.cfg.ideation.retry_max,
        )
        execution_cfg = execution_cfg or ExecutionConfig(
            max_turns=self.cfg.lanes.max_turns,
            temperature=0.7,
        )
        judge_cfg = judge_cfg or JudgeConfig(
            tier2_zones=set(self.cfg.judgment.tier2_zones),
            tier2_confidence_threshold=self.cfg.judgment.tier2_confidence_threshold,
        )
        self.ideation = IdeationEngine(self.llm, self.mcp, ideation_cfg)
        self.execution = ExecutionAgent(self.llm, execution_cfg)
        self.judger = Judge(self.llm, self.policy, judge_cfg)
        self.alert_severity_floor = alert_severity_floor

        # idea_id → IdeaObject so judge() can look up the source.
        self._idea_book: dict[str, IdeaObject] = {}
        self._book_lock = threading.Lock()

        # Cycle accounting for log_cycle_summary on the next generate_ideas
        # call (orchestrator updates the summary itself, but Person 2 owns
        # the deduplicated/executed counts).
        self._last_cycle_metrics: dict[str, int] = {}

    # ------------------------------------------------------------------
    # generate_ideas
    # ------------------------------------------------------------------
    def generate_ideas(self, cycle_id: int, n_lanes: int) -> list[IdeaObject]:
        """Run all 3 modes on the top-priority zone(s), dedup, score, take top-N."""
        gaps = self.mcp.get_coverage_gaps(top_n=max(3, n_lanes))
        if not gaps:
            LOG.warning("no coverage gaps returned; cannot generate ideas")
            return []
        # Strategy: pull from the highest-priority zone first. If after dedup
        # we still don't have enough ideas, dip into the next-priority zone.
        candidates: list[IdeaObject] = []
        zones_by_id: dict[str, CoverageGap] = {g.zone_id: g for g in gaps}
        zones_targeted: list[str] = []
        ideas_generated = 0
        ideas_deduped = 0

        for gap in gaps:
            zones_targeted.append(gap.zone_id)
            new_ideas = self.ideation.generate_for_zone(gap, cycle_id)
            ideas_generated += len(new_ideas)
            candidates.extend(new_ideas)
            # Estimate when we have enough — dedup typically halves the
            # pool, so chase 2.5× n_lanes before stopping.
            if len(candidates) >= max(int(n_lanes * 2.5), n_lanes + 2):
                break

        if not candidates:
            return []

        outcomes = deduplicate_and_log(
            candidates,
            self.mcp,
            dedup_threshold=self.cfg.ideation.dedup_threshold,
            near_dup_threshold=self.cfg.ideation.near_dup_threshold,
        )
        ideas_deduped = sum(1 for o in outcomes if not o.keep)

        # Retry loop — if dedup chopped us below n_lanes, generate "unlike"
        # ideas. Bounded by retry_max.
        attempts = 0
        while (
            sum(1 for o in outcomes if o.keep) < n_lanes
            and attempts < self.cfg.ideation.retry_max
        ):
            attempts += 1
            unlike_zone = gaps[0]
            extra = self.ideation.generate_for_zone(unlike_zone, cycle_id)
            ideas_generated += len(extra)
            if not extra:
                break
            extra_outcomes = deduplicate_and_log(
                extra,
                self.mcp,
                dedup_threshold=self.cfg.ideation.dedup_threshold,
                near_dup_threshold=self.cfg.ideation.near_dup_threshold,
            )
            ideas_deduped += sum(1 for o in extra_outcomes if not o.keep)
            outcomes.extend(extra_outcomes)

        prioritized = select_top_n(outcomes, zones_by_id, n_lanes)
        chosen = [p.idea for p in prioritized]

        # Remember each idea for judge()
        with self._book_lock:
            for i in chosen:
                self._idea_book[i.idea_id] = i

        self._last_cycle_metrics = {
            "cycle_id": cycle_id,
            "ideas_generated": ideas_generated,
            "ideas_deduplicated": ideas_deduped,
            "zones_targeted": len(set(zones_targeted)),
        }

        LOG.info(
            "cycle %d: generated=%d deduped=%d chosen=%d "
            "zones=%s",
            cycle_id, ideas_generated, ideas_deduped, len(chosen),
            list(set(zones_targeted))[:5],
        )
        return chosen

    # ------------------------------------------------------------------
    # execute_lane
    # ------------------------------------------------------------------
    def execute_lane(
        self,
        idea: IdeaObject,
        victim: VictimInstance,
        harness: MonitoringHarness,
        lane_cfg: LaneConfig,
    ) -> None:
        self.execution.execute(idea, victim, harness, lane_cfg)

    # ------------------------------------------------------------------
    # judge
    # ------------------------------------------------------------------
    def judge(self, lane_result: LaneResult) -> None:
        with self._book_lock:
            idea = self._idea_book.get(lane_result.idea_id)
        if idea is None:
            # Reconstruct a minimal IdeaObject from the lane result fields
            # so routing can still produce a sane FindingRecord. This path
            # is hit if the orchestrator restarts mid-cycle.
            idea = IdeaObject(
                idea_id=lane_result.idea_id,
                cycle_id=0,
                zone_id=lane_result.zone_targeted,
                source_mode="creative",
                title="(reconstructed)",
                approach="(idea metadata lost)",
                success_criteria="",
                estimated_turns=0,
                novelty_notes="",
            )

        judgment = self.judger.judge(
            lane_result,
            idea_summary=f"{idea.title}: {idea.approach}",
            success_criteria=idea.success_criteria,
        )
        finding_id = route_judgment(
            judgment, idea, self.mcp,
            alert_severity_floor=self.alert_severity_floor,
        )
        LOG.info(
            "judge: lane=%s zone=%s verdict=%s tier=%s severity=%s finding=%s",
            lane_result.lane_id, lane_result.zone_targeted,
            judgment.verdict, judgment.tier_that_caught, judgment.severity,
            finding_id,
        )


__all__ = ["Pipeline", "policy_from_config"]
