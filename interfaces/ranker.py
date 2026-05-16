"""The Ranker contract — learned-ranking-model spec §6.1.

Every pre-ranking and mutation-selection call site imports only this module.
HeuristicRanker and LearnedRanker are interchangeable behind the Ranker
Protocol; swapping them is a config change, not a code change at the call
sites (spec constraint §4.2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class RankerInput:
    """The structured inputs the architecture report names.

    trajectory_features / judge_scores / repro_outcome / mutation_operator are
    absent (None / empty) for a not-yet-executed idea — the ranker handles
    both the pre-execution and post-execution cases.
    """

    idea_summary: str
    zone_id: str
    tactic_tags: list[str] = field(default_factory=list)
    trajectory_features: dict[str, float] | None = None
    judge_scores: dict[str, float] | None = None
    repro_outcome: str | None = None
    token_cost: int = 0
    mutation_operator: str | None = None


@dataclass
class RankerOutput:
    """The structured outputs the architecture report names."""

    usefulness: float                       # 0..1
    likely_mutation_operators: list[str]     # ranked, from MUTATION_OPERATORS
    archive_niche: str                       # zone|interaction_style|response_movement
    likely_failure_mode: str                 # one of progress.FAILURE_MODES


@runtime_checkable
class Ranker(Protocol):
    """Predicts idea/component usefulness for steering the red search."""

    def predict(self, ranker_input: RankerInput) -> RankerOutput:
        """The full prediction for one input."""
        ...

    def rank(self, inputs: list[RankerInput]) -> list[int]:
        """Argsort of inputs by descending predicted usefulness."""
        ...


__all__ = ["Ranker", "RankerInput", "RankerOutput"]
