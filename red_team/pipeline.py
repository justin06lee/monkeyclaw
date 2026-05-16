"""Red-team pipeline — the orchestrator entrypoint.

Conforms to `infra.orchestrator.RedTeamPipeline` Protocol:

    class Pipeline:
        def generate_ideas(self, cycle_id: int, n_lanes: int) -> list[IdeaObject]
        def execute_lane(self, idea, victim, harness, lane_cfg) -> None
        def judge(self, lane_result: LaneResult) -> None

Wires:
- IdeationEngine (3 prompt modes) → DedupOutcome[] → scored ideas
- Strategist synthesizes the scored ideas into N deep-dive attack chains
- ExecutionAgent deep-dives one chain inside each lane
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
from interfaces.nemoclaw_policy import nemoclaw_policy_config
from interfaces.provisioning import VictimInstance
from interfaces.types import (
    CoverageGap,
    CycleSummaryInput,
    IdeaInput,
    IdeaObject,
    LaneResult,
    PolicyConfig,
)

from red_team.archive import EliteArchive
from red_team.dedup import deduplicate_and_log
from red_team.execution_agent import ExecutionAgent, ExecutionConfig
from red_team.ideation import IdeationConfig, IdeationEngine, tournament_ideas
from red_team.judge import Judge, JudgeConfig
from red_team.priority import score_ideas
from red_team.progress import score_progress, search_score
from red_team.routing import route_judgment
from red_team.strategist import Strategist
from red_team.tournament import ModelTournament, load_tournament_config

LOG = logging.getLogger("monkeyclaw.red.pipeline")


# ---------------------------------------------------------------------------
# Policy construction
# ---------------------------------------------------------------------------


def policy_from_config(cfg: MonkeyClawConfig) -> PolicyConfig:
    """The Tier 1 checks judge against the live NemoClaw sandbox policy —
    its real Landlock allow-set and network allowlist (see
    `interfaces.nemoclaw_policy`)."""
    return nemoclaw_policy_config()


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
            min_turns_before_giveup=self.cfg.lanes.min_turns_before_giveup,
            temperature=0.7,
        )
        judge_cfg = judge_cfg or JudgeConfig(
            tier2_zones=set(self.cfg.judgment.tier2_zones),
            tier2_confidence_threshold=self.cfg.judgment.tier2_confidence_threshold,
        )
        self.ideation = IdeationEngine(self.llm, self.mcp, ideation_cfg)
        self._ideation_cfg = ideation_cfg
        # B9 — model tournament. Disabled unless `red_team.model_tournament`
        # is configured; when enabled, extra entrants also ideate per zone.
        self.tournament = ModelTournament(load_tournament_config())
        self.strategist = Strategist(self.llm)
        self.execution = ExecutionAgent(self.llm, execution_cfg)
        self.judger = Judge(self.llm, self.policy, judge_cfg, mcp=self.mcp)
        self.alert_severity_floor = alert_severity_floor

        # idea_id → IdeaObject (the synthesized chain) so judge() can look up
        # the source of a lane result.
        self._idea_book: dict[str, IdeaObject] = {}
        self._book_lock = threading.Lock()
        # MAP-Elites archive of diverse high-performing attempts (spec B5/B8);
        # routing maps every judged attempt into a niche cell.
        self._archive = EliteArchive()

        # Cycle accounting for log_cycle_summary on the next generate_ideas
        # call (orchestrator updates the summary itself, but Person 2 owns
        # the deduplicated/executed counts).
        self._last_cycle_metrics: dict[str, int] = {}

    # ------------------------------------------------------------------
    def _llm_for_entrant(self, entrant) -> object:
        """Resolve an LLM client for one model-tournament entrant."""
        return make_llm(
            backend=entrant.provider or None,
            model=entrant.model or None,
            role=entrant.role or None,
            cfg=self.cfg,
        )

    # ------------------------------------------------------------------
    # generate_ideas
    # ------------------------------------------------------------------
    def generate_ideas(self, cycle_id: int, n_lanes: int) -> list[IdeaObject]:
        """Run all 3 modes on the top-priority zone(s), dedup, score, then have
        the strategist synthesize the batch into `n_lanes` deep-dive chains."""
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
            # B9 — when the model tournament is enabled, extra entrant models
            # ideate the same zone; their ideas join the pool for dedup +
            # priority. A disabled tournament returns [] (no-op).
            t_ideas = tournament_ideas(
                self.tournament, self._llm_for_entrant, self.mcp, gap,
                cycle_id, self._ideation_cfg)
            ideas_generated += len(t_ideas)
            candidates.extend(t_ideas)
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

        # Score every kept idea, then hand the whole batch to the strategist.
        # It synthesizes the raw ideas into `n_lanes` distinct deep-dive
        # attack chains — one chain per lane.
        prioritized = score_ideas(outcomes, zones_by_id)
        kept_ideas = [p.idea for p in prioritized]
        if not kept_ideas:
            return []

        chains = self.strategist.synthesize(
            kept_ideas, zones_by_id, cycle_id, n_lanes)

        # Fallback — if the strategist under-delivered, pad with the
        # highest-priority raw ideas so every lane still gets a target.
        if len(chains) < n_lanes:
            have = {id(c) for c in chains}
            for idea in kept_ideas:
                if len(chains) >= n_lanes:
                    break
                if id(idea) not in have:
                    chains.append(idea)
        chains = chains[:n_lanes]

        # Persist freshly-synthesized chains so they get a real idea_id and
        # appear on the dashboard. Raw-idea fallbacks were already logged
        # during dedup, so only the `CHAIN-LOCAL-` ones need logging.
        for ch in chains:
            if ch.idea_id.startswith("CHAIN-LOCAL-"):
                ch.idea_id = self.mcp.log_idea(IdeaInput(
                    cycle_id=ch.cycle_id,
                    zone_id=ch.zone_id,
                    source_mode=ch.source_mode,
                    title=ch.title,
                    approach=ch.approach,
                    success_criteria=ch.success_criteria,
                    estimated_turns=ch.estimated_turns,
                    novelty_notes=ch.novelty_notes,
                    priority_score=ch.priority_score,
                    deduplicated=False,
                    builds_on=ch.builds_on,
                    variation_notes=ch.variation_notes,
                ))

        # Remember each chain for judge().
        with self._book_lock:
            for ch in chains:
                self._idea_book[ch.idea_id] = ch

        self._last_cycle_metrics = {
            "cycle_id": cycle_id,
            "ideas_generated": ideas_generated,
            "ideas_deduplicated": ideas_deduped,
            "zones_targeted": len(set(zones_targeted)),
        }

        LOG.info(
            "cycle %d: generated=%d deduped=%d kept=%d chains=%d zones=%s",
            cycle_id, ideas_generated, ideas_deduped, len(kept_ideas),
            len(chains), list(set(zones_targeted))[:5],
        )
        return chains

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
        # One lane, one chain, one dedicated agent that deep-dives it.
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
        # B3/B8 — derive a calibrated progress score and route with it, so
        # near-misses feed the MAP-Elites archive and the repro queue only
        # receives confirmed/suspicious findings.
        progress = score_progress(lane_result)
        finding_id = route_judgment(
            judgment, idea, self.mcp,
            progress=progress,
            archive=self._archive,
            alert_severity_floor=self.alert_severity_floor,
        )
        LOG.info(
            "judge: lane=%s zone=%s verdict=%s tier=%s severity=%s "
            "progress=%.2f finding=%s",
            lane_result.lane_id, lane_result.zone_targeted,
            judgment.verdict, judgment.tier_that_caught, judgment.severity,
            search_score(progress), finding_id,
        )


__all__ = ["Pipeline", "policy_from_config"]
