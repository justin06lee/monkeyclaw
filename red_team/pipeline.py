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
from collections.abc import Callable
from dataclasses import dataclass

from infra.bootstrap import Runtime
from infra.monitoring_harness import MonitoringHarness
from interfaces.config_schema import LaneConfig, MonkeyClawConfig
from interfaces.llm import LLMClient
from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.model_router import ModelRouter
from interfaces.nemoclaw_policy import nemoclaw_policy_config
from interfaces.provisioning import VictimInstance
from interfaces.types import (
    CoverageGap,
    CycleSummaryInput,
    IdeaInput,
    IdeaObject,
    JudgmentResult,
    LaneResult,
    PolicyConfig,
)

from red_team import archive_seed
from red_team.archive import EliteArchive
from red_team.dedup import deduplicate_and_log
from red_team.execution_agent import ExecutionAgent, ExecutionConfig
from red_team.ideation import IdeationConfig, IdeationEngine, tournament_ideas
from red_team.judge import Judge, JudgeConfig
from red_team.mutation_engine import (
    MutationConfig,
    MutationEngine,
    load_mutation_config,
)
from red_team.mutation_policy import MutationPolicy
from red_team.mutations import MutationStats
from red_team.priority import score_ideas
from red_team.progress import score_progress, search_score
from red_team.near_miss import extract_near_misses
from red_team import chain_composer
from red_team.chain_attribution import attribute as attribute_chain
from red_team.routing import route_chain_judgment, route_judgment
from red_team.trajectory import score_trajectory
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
        router: ModelRouter | None = None,
        policy: PolicyConfig | None = None,
        ideation_cfg: IdeationConfig | None = None,
        execution_cfg: ExecutionConfig | None = None,
        judge_cfg: JudgeConfig | None = None,
        alert_severity_floor: str = "high",
        mutation_cfg: MutationConfig | None = None,
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

        # The router is the single LLM construction point. From a Runtime it
        # is taken directly; otherwise built from cfg+mcp here. An explicit
        # `llm=` (test injection) still wins per component: when given, every
        # component shares that one client; otherwise each gets its
        # role-bound RoutedClient.
        if router is not None:
            self.router = router
        elif runtime is not None:
            self.router = runtime.router
        else:
            self.router = ModelRouter(self.cfg, mcp=self.mcp)

        def _client(role: str) -> LLMClient:
            return llm if llm is not None else self.router.client_for(role)

        self.llm = llm or self.router.client_for("red_execution")
        self.policy = policy or policy_from_config(self.cfg)
        ideation_cfg = ideation_cfg or IdeationConfig(
            temperature=self.cfg.ideation.temperature,
            max_tokens_per_mode=self.cfg.ideation.max_tokens_per_mode,
            retry_max=self.cfg.ideation.retry_max,
            taxonomy_mode=self.cfg.ideation.taxonomy_mode,
            taxonomy_gap_top_n=self.cfg.ideation.taxonomy_gap_top_n,
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
        from red_team.taxonomy import load_taxonomy
        from red_team.technique_coverage import TechniqueCoverageModel
        self._technique_coverage = TechniqueCoverageModel(
            self.mcp, load_taxonomy())
        self.ideation = IdeationEngine(
            _client("red_ideation"), self.mcp, ideation_cfg,
            technique_coverage=self._technique_coverage)
        self._ideation_cfg = ideation_cfg
        # B9 — model tournament. Disabled unless `red_team.model_tournament`
        # is configured; when enabled, extra entrants also ideate per zone.
        self.tournament = ModelTournament(load_tournament_config())
        self.strategist = Strategist(_client("red_ideation"))
        self.execution = ExecutionAgent(_client("red_execution"), execution_cfg)
        self.judger = Judge(_client("semantic_judge"), self.policy, judge_cfg, mcp=self.mcp)
        self.alert_severity_floor = alert_severity_floor

        # idea_id → IdeaObject (the synthesized chain) so judge() can look up
        # the source of a lane result.
        self._idea_book: dict[str, IdeaObject] = {}
        # idea_id → dedup novelty_score, so judge() can feed score_progress
        # a real novelty measurement instead of the self-assessment proxy.
        self._idea_novelty: dict[str, float] = {}
        self._book_lock = threading.Lock()
        # MAP-Elites archive of diverse high-performing attempts (spec B5/B8);
        # routing maps every judged attempt into a niche cell.
        # B5 — rehydrate the MAP-Elites grid from the persistent store so the
        # niche archive survives process restarts. A failure here is a cold
        # archive for this run, never a crash (spec §10).
        try:
            cells = self.mcp.get_archive_cells(zone=None)
            self._archive = EliteArchive.load_from_cells(cells)
            LOG.info("rehydrated MAP-Elites archive: %d cell(s)",
                     self._archive.cell_count())
        except Exception as e:  # noqa: BLE001
            LOG.warning("archive rehydration failed (%s) — starting cold", e)
            self._archive = EliteArchive()

        # Cycle accounting for log_cycle_summary on the next generate_ideas
        # call (orchestrator updates the summary itself, but Person 2 owns
        # the deduplicated/executed counts).
        self._last_cycle_metrics: dict[str, int] = {}

        # Optional mutation stage (mutation-operator-learning spec §7.4).
        # A strict no-op when disabled — `mutation_engine` stays None and no
        # mutation code path is reachable.
        self.mutation_cfg = mutation_cfg or load_mutation_config()
        self.mutation_engine: MutationEngine | None = None
        if self.mutation_cfg.enabled:
            global_stats = MutationStats()
            try:
                global_stats.load_from(self.mcp.get_mutation_operator_stats())
            except Exception as e:  # noqa: BLE001
                LOG.warning("could not load persisted mutation stats: %s — "
                            "starting from the neutral prior", e)
            policy = MutationPolicy(
                global_stats, kind=self.mutation_cfg.policy,
                epsilon=self.mutation_cfg.epsilon)
            self.mutation_engine = MutationEngine(
                policy=policy, stats_by_zone={}, global_stats=global_stats,
                mcp=self.mcp, cfg=self.mutation_cfg)

    # ------------------------------------------------------------------
    def _llm_for_entrant(self, entrant) -> object:
        """Resolve a routed LLM client for one model-tournament entrant.

        Tournament entrants key by `role`, so they go through the same router
        as every other call — accounted and fallback-protected. An entrant
        with an explicit provider/model still resolves via its role's chain;
        per-entrant model pinning is out of scope for this spec (see the
        model-ideation-tournament spec).
        """
        return self.router.client_for(entrant.role)

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
            try:
                seed = archive_seed.render_seed(
                    archive_seed.build_seed(
                        self._archive, gap.zone_id, cfg=self.cfg.red.archive))
            except Exception as e:  # noqa: BLE001
                LOG.warning("archive seed build failed for %s (%s) — "
                            "ideation runs unseeded", gap.zone_id, e)
                seed = ""
            new_ideas = self.ideation.generate_for_zone(
                gap, cycle_id, seed=seed)
            from red_team.ideation import taxonomy_ideas
            tax_ideas = taxonomy_ideas(self.ideation, gap, cycle_id)
            if tax_ideas:
                LOG.info("ideation taxonomy mode produced %d ideas",
                         len(tax_ideas))
                new_ideas.extend(tax_ideas)
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
            try:
                seed = archive_seed.render_seed(
                    archive_seed.build_seed(
                        self._archive, unlike_zone.zone_id,
                        cfg=self.cfg.red.archive))
            except Exception as e:  # noqa: BLE001
                LOG.warning("archive seed build failed for %s (%s) — "
                            "ideation runs unseeded", unlike_zone.zone_id, e)
                seed = ""
            extra = self.ideation.generate_for_zone(
                unlike_zone, cycle_id, seed=seed)
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

        # Record each kept idea's dedup novelty so judge() can feed
        # score_progress a real novelty measurement (trajectory spec §6.2).
        for oc in outcomes:
            if oc.keep:
                self._idea_novelty[oc.idea.idea_id] = oc.novelty_score
                if oc.logged_idea_id:
                    self._idea_novelty[oc.logged_idea_id] = oc.novelty_score

        # Score every kept idea, then hand the whole batch to the strategist.
        # It synthesizes the raw ideas into `n_lanes` distinct deep-dive
        # attack chains — one chain per lane.
        prioritized = score_ideas(outcomes, zones_by_id, archive=self._archive)
        kept_ideas = [p.idea for p in prioritized]
        if not kept_ideas:
            return []

        # Cross-zone chaining — compose multi-zone kill-chain lanes from the
        # cycle's primitives + archive elites. An empty composer output falls
        # back entirely to the legacy single-zone strategist path (spec §5).
        chain_lanes: list[IdeaObject] = []
        if self.cfg.red.chains.enabled and kept_ideas:
            try:
                skeletons = self.strategist.synthesize_chains(
                    kept_ideas, self._archive, zones_by_id, cycle_id,
                    self.cfg.red.chains.n_chains)
                ideas_by_id = {i.idea_id: i for i in kept_ideas}
                composed = chain_composer.compose(
                    skeletons, ideas_by_id, self._archive, cycle_id)
                for ch in composed[:self.cfg.red.chains.n_chains]:
                    self.mcp.log_attack_chain(ch)
                    lane_idea = IdeaObject(
                        idea_id=ch.chain_id, cycle_id=cycle_id,
                        zone_id=ch.primary_zone, source_mode="creative",
                        title=f"Chain: {ch.title}",
                        approach=ch.rationale,
                        success_criteria="Cross-zone kill chain breach.",
                        estimated_turns=ch.estimated_turns,
                        novelty_notes="", priority_score=1.0,
                        builds_on=ch.builds_on or None)
                    lane_idea.chain = ch
                    chain_lanes.append(lane_idea)
            except Exception as e:  # noqa: BLE001
                LOG.warning("chain composition failed (%s) — legacy path", e)
                chain_lanes = []

        # Chain lanes first, then legacy single-zone chains/ideas fill the
        # remaining lanes (spec §5: a cycle may mix chain and idea lanes;
        # an empty composer output falls back to the legacy path entirely).
        chains: list[IdeaObject] = list(chain_lanes[:n_lanes])
        if len(chains) < n_lanes:
            legacy = self.strategist.synthesize(
                kept_ideas, zones_by_id, cycle_id, n_lanes - len(chains))
            for ch in legacy:
                if len(chains) >= n_lanes:
                    break
                chains.append(ch)
            # Fallback padding with raw ideas, as today.
            have = {id(x) for x in chains}
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
    def judge(self, lane_result: LaneResult) -> JudgmentResult:
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

        chain = getattr(idea, "chain", None)
        if chain is not None:
            # Cross-zone chain lane — attribute the chain across its zones.
            try:
                judgment = self.judger.judge(
                    lane_result,
                    idea_summary=f"{idea.title}: {idea.approach}",
                    success_criteria=idea.success_criteria)
                attribution = attribute_chain(chain, lane_result, judgment)
                chain_finding_id = route_chain_judgment(
                    attribution, chain, self.mcp,
                    archive=self._archive,
                    alert_severity_floor=self.alert_severity_floor)
                LOG.info(
                    "judge: chain lane=%s chain=%s verdict=%s zones=%d "
                    "finding=%s",
                    lane_result.lane_id, chain.chain_id, judgment.verdict,
                    len(attribution.chain_finding.zones_traversed),
                    chain_finding_id)
                return judgment
            except Exception as e:  # noqa: BLE001
                # Per-lane isolation — a chain attribution failure must not
                # abort the cycle (spec §12).
                LOG.exception("chain attribution failed for lane %s: %s",
                              lane_result.lane_id, e)
                return None  # type: ignore[return-value]

        judgment = self.judger.judge(
            lane_result,
            idea_summary=f"{idea.title}: {idea.approach}",
            success_criteria=idea.success_criteria,
        )
        # B3/B8 — derive the per-turn trajectory, then a calibrated progress
        # score, and route with both. The trajectory feeds three rubric
        # dimensions; near-misses feed the MAP-Elites archive; the repro
        # queue only receives confirmed/suspicious findings.
        try:
            trajectory = score_trajectory(lane_result, judgment)
        except Exception as e:  # noqa: BLE001
            LOG.warning("trajectory scoring failed for lane %s: %s — "
                        "routing with trajectory=None", lane_result.lane_id, e)
            trajectory = None
        novelty_score = self._idea_novelty.get(lane_result.idea_id)
        progress = score_progress(
            lane_result, trajectory=trajectory, novelty_score=novelty_score)
        near_misses = []
        try:
            near_misses = extract_near_misses(
                idea, lane_result, progress, trajectory, judgment)
        except Exception as e:  # noqa: BLE001
            LOG.warning("near-miss extraction failed for lane %s: %s",
                        lane_result.lane_id, e)
        finding_id = route_judgment(
            judgment, idea, self.mcp,
            progress=progress,
            trajectory=trajectory,
            near_misses=near_misses,
            archive=self._archive,
            technique_coverage=self._technique_coverage,
            alert_severity_floor=self.alert_severity_floor,
        )
        LOG.info(
            "judge: lane=%s zone=%s verdict=%s tier=%s severity=%s "
            "progress=%.2f finding=%s",
            lane_result.lane_id, lane_result.zone_targeted,
            judgment.verdict, judgment.tier_that_caught, judgment.severity,
            search_score(progress), finding_id,
        )
        return judgment

    # ------------------------------------------------------------------
    # Optional mutation stage (mutation-operator-learning spec §7.4)
    # ------------------------------------------------------------------
    def mutate_judged(
        self,
        judged: list[tuple[IdeaObject, JudgmentResult]],
        *,
        execute_child: Callable[[IdeaObject], LaneResult | None] | None = None,
    ) -> list[IdeaObject]:
        """Run the optional mutation stage over a batch of judged attempts.

        A strict no-op when the mutation engine is disabled (returns []).
        For each near-miss parent, mutated children are produced via the
        learned policy. When `execute_child` is supplied it re-runs each
        child through the existing execute+judge path so a real lift signal
        is recorded; otherwise only the candidate children are returned (the
        caller owns lane budget / dedup). Children also re-enter the
        existing `judge` -> `route_judgment` path through `execute_child`.
        """
        if self.mutation_engine is None:
            return []
        engine = self.mutation_engine
        judged_by_idea = {idea.idea_id: j for idea, j in judged}
        all_children: list[IdeaObject] = []
        for parent in engine.mutation_candidates(judged):
            parent_judgment = judged_by_idea[parent.idea_id]
            for child in engine.mutate(parent):
                all_children.append(child)
                if execute_child is None:
                    continue
                child_lane = execute_child(child)
                if child_lane is None:
                    continue  # execution failed — no stats recorded
                child_judgment = self.judge(child_lane)
                engine.record_outcome(child, child_judgment, parent_judgment)
        return all_children


__all__ = ["Pipeline", "policy_from_config"]
