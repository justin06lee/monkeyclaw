"""Pairwise preference labelling (learned-ranking-model spec §6.3).

Where absolute usefulness is too noisy to label cleanly, asks the judge
ensemble in pairwise mode — "is attempt A more useful to the search than
attempt B?" — and records the preference. Pairs are sampled within a
(zone, judge_verdict) bucket so comparisons are meaningful. Runs on a strict
per-cycle budget so it does not reintroduce the LLM cost the learned ranker
is meant to remove (spec §6.3 note).
"""

from __future__ import annotations

import itertools
import logging
import random

from interfaces.types import AttemptTrace, PreferenceInput

LOG = logging.getLogger("monkeyclaw.red.pairwise_labels")


class PairwiseLabeller:
    """Samples trace pairs and turns judge comparisons into preferences."""

    def __init__(self, judge, seed: int = 1234) -> None:
        # `judge` exposes compare_pair(summary_a, summary_b) -> {"preferred",
        # "confidence"}; in practice this is JudgeEnsemble's pairwise mode.
        self._judge = judge
        self._rng = random.Random(seed)

    def sample_pairs(
        self, traces: list[AttemptTrace], budget: int
    ) -> list[tuple[AttemptTrace, AttemptTrace]]:
        """Sample up to `budget` pairs, each within one (zone, verdict) bucket."""
        buckets: dict[tuple[str, str], list[AttemptTrace]] = {}
        for t in traces:
            buckets.setdefault((t.zone_id, t.judge_verdict), []).append(t)

        candidates: list[tuple[AttemptTrace, AttemptTrace]] = []
        for members in buckets.values():
            if len(members) >= 2:
                candidates.extend(itertools.combinations(members, 2))

        self._rng.shuffle(candidates)
        return candidates[:max(0, budget)]

    def compare(
        self, trace_a: AttemptTrace, trace_b: AttemptTrace
    ) -> PreferenceInput | None:
        """Ask the judge which trace is more useful; None if the judge fails."""
        try:
            result = self._judge.compare_pair(
                trace_a.idea_summary, trace_b.idea_summary)
        except Exception as e:  # noqa: BLE001
            LOG.warning("pairwise compare skipped — judge unavailable: %s", e)
            return None
        preferred = result.get("preferred", "tie")
        if preferred not in ("a", "b", "tie"):
            preferred = "tie"
        return PreferenceInput(
            trace_a=trace_a.trace_id,
            trace_b=trace_b.trace_id,
            preferred=preferred,
            judge_confidence=float(result.get("confidence", 0.0)),
        )


__all__ = ["PairwiseLabeller"]
