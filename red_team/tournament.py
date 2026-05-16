"""B9 — model tournament hook.

Lets the red team draw idea diversity from several models without making
the demo fragile. The tournament is **disabled by default**; with it off,
ideation runs exactly as before on the single configured model.

When enabled, each entrant model generates ideas, every idea is normalized
to the same `IdeaObject` (and tagged with `idea.model_label`), the merged
pool is deduplicated together, and confirmed-finding / token counts are
tracked per model so the leaderboard can be logged.

Config shape (red-team-local — read directly, not through the Pydantic
schema, so Person B does not have to touch `interfaces/`):

    red_team:
      model_tournament:
        enabled: false
        entrants:
          - role: red_ideation
          - role: cyber_specialist_optional
          - role: frontier_creative_optional
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

from interfaces.types import IdeaObject

LOG = logging.getLogger("monkeyclaw.red.tournament")

_DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parents[1] / "configs" / "monkeyclaw.yaml"
)


@dataclass
class Entrant:
    """One model in the tournament. `role` keys into the models config;
    `provider`/`model` may override the resolved route."""
    role: str
    provider: str = ""
    model: str = ""
    optional: bool = False

    @property
    def label(self) -> str:
        return self.model or self.role


@dataclass
class ModelTournamentConfig:
    enabled: bool = False
    entrants: list[Entrant] = field(default_factory=list)


def _coerce_config(raw: object) -> ModelTournamentConfig:
    """Build a config from the parsed `red_team.model_tournament` mapping."""
    if not isinstance(raw, dict):
        return ModelTournamentConfig()
    entrants: list[Entrant] = []
    for item in raw.get("entrants") or []:
        if isinstance(item, dict) and item.get("role"):
            entrants.append(Entrant(
                role=str(item["role"]),
                provider=str(item.get("provider", "")),
                model=str(item.get("model", "")),
                optional="optional" in str(item["role"]).lower()
                or bool(item.get("optional", False)),
            ))
        elif isinstance(item, str):
            entrants.append(Entrant(role=item))
    return ModelTournamentConfig(
        enabled=bool(raw.get("enabled", False)),
        entrants=entrants,
    )


def load_tournament_config(
    source: dict | str | Path | None = None,
) -> ModelTournamentConfig:
    """Load the tournament config.

    `source` may be a pre-parsed dict (the whole config or just the
    `model_tournament` block), a YAML path, or None — in which case the
    main monkeyclaw.yaml is consulted. A missing `red_team.model_tournament`
    section yields a disabled config (the safe default)."""
    data: object = source
    if source is None:
        path = _DEFAULT_CONFIG_PATH
        if not path.is_file():
            return ModelTournamentConfig()
        data = yaml.safe_load(path.read_text()) or {}
    elif isinstance(source, (str, Path)):
        p = Path(source)
        if not p.is_file():
            return ModelTournamentConfig()
        data = yaml.safe_load(p.read_text()) or {}

    if not isinstance(data, dict):
        return ModelTournamentConfig()
    # Accept either the full config, the `red_team` block, or the
    # `model_tournament` block directly.
    if "model_tournament" in data:
        return _coerce_config(data["model_tournament"])
    if isinstance(data.get("red_team"), dict):
        return _coerce_config(data["red_team"].get("model_tournament"))
    if "entrants" in data or "enabled" in data:
        return _coerce_config(data)
    return ModelTournamentConfig()


class ModelTournament:
    """Runs ideation across entrant models and tracks per-model performance."""

    def __init__(self, cfg: ModelTournamentConfig | None = None) -> None:
        self.cfg = cfg or ModelTournamentConfig()
        # model label -> {"ideas", "confirmed", "suspicious", "tokens"}
        self._stats: dict[str, dict[str, int]] = {}

    @property
    def enabled(self) -> bool:
        return self.cfg.enabled and len(self.cfg.entrants) > 0

    def _bump(self, label: str, **deltas: int) -> None:
        row = self._stats.setdefault(
            label, {"ideas": 0, "confirmed": 0, "suspicious": 0, "tokens": 0})
        for k, v in deltas.items():
            row[k] = row.get(k, 0) + v

    def generate(
        self, generate_fn: Callable[[Entrant], list[IdeaObject]],
    ) -> list[IdeaObject]:
        """Run `generate_fn` for every entrant, tag each idea with its source
        model on `idea.model_label`, and return the merged pool.

        The caller then dedups the merged list together (the existing
        `deduplicate_and_log` is model-agnostic) and runs the normal
        priority / strategist stages."""
        if not self.enabled:
            return []
        merged: list[IdeaObject] = []
        for entrant in self.cfg.entrants:
            try:
                ideas = generate_fn(entrant)
            except Exception as e:  # noqa: BLE001
                # An optional entrant must never break the demo.
                LOG.warning("tournament entrant %s failed: %s — skipped",
                            entrant.label, e)
                continue
            for idea in ideas:
                idea.model_label = entrant.label
            self._bump(entrant.label, ideas=len(ideas))
            merged.extend(ideas)
            LOG.info("tournament entrant %s produced %d idea(s)",
                     entrant.label, len(ideas))
        return merged

    def record_outcome(
        self, model_label: str, *, verdict: str, tokens: int = 0,
    ) -> None:
        """Record a judged outcome against the model that produced the idea."""
        self._bump(
            model_label,
            confirmed=1 if verdict == "confirmed" else 0,
            suspicious=1 if verdict == "suspicious" else 0,
            tokens=tokens,
        )

    def leaderboard(self) -> dict[str, dict[str, int]]:
        """Per-model performance snapshot (for logging / the dashboard)."""
        return {label: dict(row) for label, row in self._stats.items()}

    def summary(self) -> str:
        if not self._stats:
            return "model tournament: no entrants recorded"
        parts = [
            f"{label}: {row['confirmed']} confirmed / {row['ideas']} ideas, "
            f"{row['tokens']} tokens"
            for label, row in sorted(self._stats.items())
        ]
        return "model tournament — " + "; ".join(parts)


__all__ = [
    "Entrant",
    "ModelTournament",
    "ModelTournamentConfig",
    "load_tournament_config",
]
