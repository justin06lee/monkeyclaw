"""B6 — mutation engine: select -> apply -> judge-lift -> persist.

Orchestrates one mutation round. `mutations.py` owns operators + stats;
`mutation_policy.py` owns selection; this module owns orchestration and the
§5 lift signal. The operators stay deterministic and LLM-free — only the
selection policy learns.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import yaml

from interfaces.types import IdeaObject, JudgmentResult, MutationAttempt
from red_team.mutation_policy import MutationPolicy
from red_team.mutations import MutationStats, apply_operator

LOG = logging.getLogger("monkeyclaw.red.mutation_engine")


def attack_score(judgment: JudgmentResult) -> float:
    """The [0,1] attack score for one judged execution (§5):
    confirmed -> 1.0, suspicious -> the judge confidence, clean -> 0.0."""
    verdict = judgment.verdict
    if verdict == "confirmed":
        return 1.0
    if verdict == "suspicious":
        return max(0.0, min(1.0, float(judgment.confidence)))
    return 0.0


def compute_lift(
    parent: JudgmentResult,
    child: JudgmentResult,
    *,
    improvement_epsilon: float = 0.05,
) -> tuple[float, bool]:
    """Lift = child_score - parent_score, clamped to [-1, 1]. `improved` is
    True when lift clears `improvement_epsilon` — a meaningful positive
    movement, not noise."""
    lift = attack_score(child) - attack_score(parent)
    lift = max(-1.0, min(1.0, lift))
    improved = lift > improvement_epsilon
    return lift, improved


@dataclass
class MutationConfig:
    """Red-team-local mutation config (read from configs/monkeyclaw.yaml's
    red_team.mutation block — the tournament.py precedent)."""

    enabled: bool = True
    policy: str = "thompson"
    epsilon: float = 0.1
    children_per_parent: int = 2
    near_miss_threshold: float = 0.4
    improvement_epsilon: float = 0.05
    max_lineage_depth: int = 2


class MutationEngine:
    """Orchestrates one mutation round: select -> apply -> lift -> persist."""

    def __init__(
        self,
        policy: MutationPolicy,
        stats_by_zone: dict[str, MutationStats],
        global_stats: MutationStats,
        mcp: object,
        cfg: MutationConfig,
    ) -> None:
        self.policy = policy
        self.stats_by_zone = stats_by_zone
        self.global_stats = global_stats
        self.mcp = mcp
        self.cfg = cfg

    def mutation_candidates(
        self, judged: list[tuple[IdeaObject, JudgmentResult]]
    ) -> list[IdeaObject]:
        """Parents worth mutating: a `suspicious` verdict, or a `clean`
        verdict whose confidence clears `near_miss_threshold`. `confirmed`
        attacks have no headroom; deeply `clean` ones rarely respond to
        mutation — both are skipped to conserve budget."""
        out: list[IdeaObject] = []
        for idea, judgment in judged:
            if getattr(idea, "mutation_depth", 0) >= self.cfg.max_lineage_depth:
                continue
            if judgment.verdict == "suspicious":
                out.append(idea)
            elif (judgment.verdict == "clean"
                  and judgment.confidence >= self.cfg.near_miss_threshold):
                out.append(idea)
        return out

    def mutate(self, parent: IdeaObject) -> list[IdeaObject]:
        """Produce up to `children_per_parent` mutated child ideas from
        `parent`. Each child gets a fresh operator (none re-used on the
        lineage), `source_mode="mutation"`, a `parent_idea_id`, and the
        appended `mutation_lineage`. A child whose mutated string equals its
        parent's is dropped; depth past `max_lineage_depth` is refused."""
        depth = getattr(parent, "mutation_depth", 0)
        if depth >= self.cfg.max_lineage_depth:
            return []
        lineage = list(getattr(parent, "mutation_lineage", []))
        operators = self.policy.select(
            self.cfg.children_per_parent, exclude=frozenset(lineage))
        children: list[IdeaObject] = []
        for i, operator in enumerate(operators):
            mutated = apply_operator(operator, parent.approach)
            if mutated == parent.approach:
                continue  # degenerate — operator was a no-op on this string
            child = IdeaObject(
                idea_id=f"{parent.idea_id}-m{depth + 1}-{i}",
                cycle_id=parent.cycle_id,
                zone_id=parent.zone_id,
                source_mode="mutation",
                title=f"[mut:{operator}] {parent.title}",
                approach=mutated,
                success_criteria=parent.success_criteria,
                estimated_turns=parent.estimated_turns,
                novelty_notes=f"mutation of {parent.idea_id} via {operator}",
            )
            child.parent_idea_id = parent.idea_id
            child.mutation_lineage = lineage + [operator]
            child.mutation_depth = depth + 1
            children.append(child)
        return children

    def _zone_stats(self, zone_id: str) -> MutationStats:
        """The per-zone MutationStats instance, created on first use."""
        if zone_id not in self.stats_by_zone:
            self.stats_by_zone[zone_id] = MutationStats(zone_id=zone_id)
        return self.stats_by_zone[zone_id]

    def record_outcome(
        self,
        child: IdeaObject,
        child_judgment: JudgmentResult,
        parent_judgment: JudgmentResult,
    ) -> MutationAttempt:
        """Compute lift (§5), update the global + per-zone MutationStats,
        persist both stat tables and one mutation_attempts row. MCP writes
        are best-effort: a failure is logged, never raised, so the cycle
        never aborts."""
        operator = child.mutation_lineage[-1]
        zone_id = child.zone_id
        parent_score = attack_score(parent_judgment)
        child_score = attack_score(child_judgment)
        lift, improved = compute_lift(
            parent_judgment, child_judgment,
            improvement_epsilon=self.cfg.improvement_epsilon)

        zone_stats = self._zone_stats(zone_id)
        for stats in (self.global_stats, zone_stats):
            stats.record(operator, improved=improved, score=child_score,
                         lift=lift)

        attempt = MutationAttempt(
            attempt_id="", cycle_id=child.cycle_id, zone_id=zone_id,
            operator=operator, parent_idea_id=child.parent_idea_id,
            child_idea_id=child.idea_id, parent_score=parent_score,
            child_score=child_score, lift=lift, improved=improved,
            child_verdict=child_judgment.verdict, created_at="")

        try:
            global_row = next(
                r for r in self.global_stats.to_rows() if r.operator == operator)
            self.mcp.update_mutation_operator_stats(global_row)
            zone_row = next(
                r for r in zone_stats.to_rows() if r.operator == operator)
            self.mcp.update_mutation_operator_stats(zone_row)
            self.mcp.log_mutation_attempt(attempt)
        except Exception as e:  # noqa: BLE001
            LOG.warning("mutation persistence failed for %s/%s: %s — "
                        "in-memory learning retained", operator, zone_id, e)
        return attempt


def load_mutation_config(
    source: dict | str | Path | None = None,
) -> MutationConfig:
    """Load the `red_team.mutation` block. `source` may be a parsed dict, a
    YAML path, or None (the main monkeyclaw.yaml). A missing block yields the
    safe defaults."""
    data: object = source
    if source is None or isinstance(source, (str, Path)):
        path = Path(source) if source else (
            Path(__file__).resolve().parents[1] / "configs" / "monkeyclaw.yaml")
        if not path.is_file():
            return MutationConfig()
        data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        return MutationConfig()
    block = data.get("mutation")
    if block is None and isinstance(data.get("red_team"), dict):
        block = data["red_team"].get("mutation")
    if not isinstance(block, dict):
        return MutationConfig()
    defaults = MutationConfig()
    return MutationConfig(
        enabled=bool(block.get("enabled", defaults.enabled)),
        policy=str(block.get("policy", defaults.policy)),
        epsilon=float(block.get("epsilon", defaults.epsilon)),
        children_per_parent=int(
            block.get("children_per_parent", defaults.children_per_parent)),
        near_miss_threshold=float(
            block.get("near_miss_threshold", defaults.near_miss_threshold)),
        improvement_epsilon=float(
            block.get("improvement_epsilon", defaults.improvement_epsilon)),
        max_lineage_depth=int(
            block.get("max_lineage_depth", defaults.max_lineage_depth)),
    )


__all__ = [
    "MutationConfig",
    "MutationEngine",
    "attack_score",
    "compute_lift",
    "load_mutation_config",
]
