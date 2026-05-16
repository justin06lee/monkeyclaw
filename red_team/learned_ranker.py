"""The learned Ranker (learned-ranking-model spec §6.6) — gated.

LearnedRanker loads a versioned artifact written by scripts/train_ranker.py.
The artifact carries its dataset snapshot id and feature-schema version; on a
missing, corrupt, or mismatched artifact LearnedRanker.load returns the
supplied fallback (HeuristicRanker) so the loop never stops for a ranker
problem (spec constraint §4.3, §11).

The artifact format and the trained-prediction path are the gated Phase 4
follow-up; until a trained artifact exists, load() always returns the
fallback. This module ships now so the config path and the call sites are
ready and the swap is a config change, not a code change.
"""

from __future__ import annotations

import json
import logging

from interfaces.ranker import Ranker, RankerInput, RankerOutput

from red_team.trace_collector import FEATURE_SCHEMA_VERSION

LOG = logging.getLogger("monkeyclaw.red.learned_ranker")


class LearnedRanker:
    """A Ranker backed by a trained artifact; falls back to the heuristic."""

    def __init__(self, artifact: dict, fallback: Ranker) -> None:
        self._artifact = artifact
        self._fallback = fallback

    @classmethod
    def load(cls, artifact_path: str, *, fallback: Ranker) -> Ranker:
        """Load a trained artifact, or return the fallback on any problem."""
        try:
            with open(artifact_path, encoding="utf-8") as fh:
                artifact = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            LOG.warning("learned ranker artifact unavailable (%s) — "
                        "fallback to HeuristicRanker", e)
            return fallback

        version = artifact.get("feature_schema_version")
        if version != FEATURE_SCHEMA_VERSION:
            LOG.warning("learned ranker feature-schema mismatch "
                        "(artifact=%s, runtime=%s) — fallback to "
                        "HeuristicRanker", version, FEATURE_SCHEMA_VERSION)
            return fallback

        # A matching, well-formed artifact exists. The trained-prediction
        # path is the gated Phase 4 follow-up — until it lands, an otherwise
        # valid artifact still defers to the proven heuristic so no untested
        # model can serve.
        LOG.info("learned ranker artifact loaded; trained prediction is the "
                 "gated Phase 4 follow-up — serving HeuristicRanker")
        return cls(artifact, fallback)

    def predict(self, ranker_input: RankerInput) -> RankerOutput:
        return self._fallback.predict(ranker_input)

    def rank(self, inputs: list[RankerInput]) -> list[int]:
        return self._fallback.rank(inputs)


__all__ = ["LearnedRanker"]
