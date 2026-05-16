"""Deduplication — embedding-similarity check against prior ideas.

Per .agents/person_2_redteam.md Deliverable 2:

1. Embed title+approach (server-side now — we pass raw text to MCP).
2. Call `check_duplicate(text, zone, threshold)`.
3. Bands:
   - similarity > 0.92 (configurable): discard, log with deduplicated=true
   - similarity in [0.80, 0.92): near-dup, keep but halve novelty
   - similarity < 0.80: fully novel, keep at full novelty

Output: a list of `DedupOutcome` parallel to the input idea list. Each entry
carries the idea, its DupResult, and a `keep` flag.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import DupResult, IdeaInput, IdeaObject

LOG = logging.getLogger("monkeyclaw.red.dedup")


@dataclass
class DedupOutcome:
    idea: IdeaObject
    dup: DupResult
    keep: bool          # False → discarded as a duplicate
    near_dup: bool      # True → kept but novelty halved
    novelty_score: float
    logged_idea_id: str  # idea_id returned by `log_idea` (None-coerced to "")


def _dedup_text(idea: IdeaObject) -> str:
    return f"{idea.title}\n{idea.approach}"


def deduplicate_and_log(
    ideas: list[IdeaObject],
    mcp: MonkeyClawMCP,
    *,
    dedup_threshold: float = 0.92,
    near_dup_threshold: float = 0.80,
) -> list[DedupOutcome]:
    """Run check_duplicate + log_idea for every candidate idea.

    Every idea (kept or discarded) is logged via `log_idea` so the dedup
    history table accumulates a complete record — per spec §5.5.
    """
    if not (0 <= near_dup_threshold <= dedup_threshold <= 1.0):
        raise ValueError(
            f"thresholds out of order: near={near_dup_threshold} dedup={dedup_threshold}"
        )

    outcomes: list[DedupOutcome] = []
    for idea in ideas:
        text = _dedup_text(idea)
        dup = mcp.check_duplicate(text=text, zone=idea.zone_id, threshold=dedup_threshold)
        sim = max(0.0, min(1.0, dup.max_similarity))

        if sim >= dedup_threshold:
            keep = False
            near_dup = False
            novelty = 0.0
        elif sim >= near_dup_threshold:
            keep = True
            near_dup = True
            novelty = (1.0 - sim) * 0.5  # halve novelty
        else:
            keep = True
            near_dup = False
            novelty = 1.0 - sim

        # Persist the idea (deduplicated flag mirrors `keep`). Coerce a None
        # return to "" — `IdeaObject.idea_id` is typed `str` and must never
        # become None if `log_idea` fails to return an ID.
        logged_id = mcp.log_idea(IdeaInput(
            cycle_id=idea.cycle_id,
            zone_id=idea.zone_id,
            source_mode=idea.source_mode,
            title=idea.title,
            approach=idea.approach,
            success_criteria=idea.success_criteria,
            estimated_turns=idea.estimated_turns,
            novelty_notes=idea.novelty_notes,
            priority_score=idea.priority_score,
            deduplicated=not keep,
            relevant_files=idea.relevant_files,
            code_weakness=idea.code_weakness,
            builds_on=idea.builds_on,
            variation_notes=idea.variation_notes,
        )) or ""
        idea.idea_id = logged_id  # adopt the server-assigned ID

        if not keep:
            LOG.info(
                "dedup discard idea=%r zone=%s sim=%.3f matches=%s",
                idea.title, idea.zone_id, sim, dup.matching_idea_id,
            )
        elif near_dup:
            LOG.info(
                "dedup near-dup idea=%r zone=%s sim=%.3f novelty=%.3f",
                idea.title, idea.zone_id, sim, novelty,
            )

        outcomes.append(DedupOutcome(
            idea=idea, dup=dup, keep=keep, near_dup=near_dup,
            novelty_score=novelty, logged_idea_id=logged_id,
        ))
    return outcomes


__all__ = ["DedupOutcome", "deduplicate_and_log"]
