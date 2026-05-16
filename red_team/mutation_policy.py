"""B6 — bandit selection policy over mutation operators.

`MutationStats` (red_team/mutations.py) owns the per-operator posteriors;
this module decides *which* operator(s) to apply next. Each operator is an
arm of a multi-armed bandit. Three policies, selectable by config:

- `thompson` (default) — draw one Beta sample per operator from its
  posterior and take the highest. Wide posteriors (under-sampled operators)
  are explored; consistently strong operators are exploited.
- `greedy` — delegate to `MutationStats.rank()` (today's behaviour).
- `epsilon_greedy` — rank with probability 1-epsilon, else uniform random.

Deterministic when `seed` is set — required for the tests.
"""

from __future__ import annotations

import random

from red_team.mutations import MUTATION_OPERATORS, MutationStats

_POLICY_KINDS = ("thompson", "greedy", "epsilon_greedy")


class MutationPolicy:
    """Selects which mutation operator(s) to apply next."""

    def __init__(
        self,
        stats: MutationStats,
        kind: str = "thompson",
        *,
        seed: int | None = None,
        epsilon: float = 0.1,
    ) -> None:
        if kind not in _POLICY_KINDS:
            raise ValueError(
                f"unknown policy kind {kind!r}; expected one of {_POLICY_KINDS}")
        self.stats = stats
        self.kind = kind
        self.epsilon = epsilon
        self._rng = random.Random(seed)
        self._last_values: dict[str, float] = {}

    def select(
        self, k: int = 1, *, exclude: frozenset[str] | set[str] = frozenset()
    ) -> list[str]:
        """Return up to `k` operator names, best-first, none in `exclude`."""
        if k < 0:
            raise ValueError("k must be >= 0")
        pool = [op for op in MUTATION_OPERATORS if op not in exclude]
        if self.kind == "greedy":
            ranked = [op for op in self.stats.rank() if op not in exclude]
            self._last_values = {op: float(len(ranked) - i)
                                 for i, op in enumerate(ranked)}
            return ranked[:k]
        if self.kind == "epsilon_greedy":
            if self._rng.random() < self.epsilon:
                shuffled = list(pool)
                self._rng.shuffle(shuffled)
                self._last_values = {op: self._rng.random() for op in pool}
                return shuffled[:k]
            ranked = [op for op in self.stats.rank() if op not in exclude]
            self._last_values = {op: float(len(ranked) - i)
                                 for i, op in enumerate(ranked)}
            return ranked[:k]
        # thompson
        draws: dict[str, float] = {}
        for op in pool:
            alpha, beta = self.stats.posterior(op)
            draws[op] = self._rng.betavariate(alpha, beta)
        self._last_values = draws
        return sorted(pool, key=lambda op: -draws[op])[:k]

    def explain(self) -> dict[str, float]:
        """Per-operator sampled value from the last select() — for the
        dashboard and tests."""
        return dict(self._last_values)


__all__ = ["MutationPolicy"]
