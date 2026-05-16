"""Win-rate-driven entrant routing — model-ideation-tournament spec §7.3.

Future ideation for a zone draws entrants in proportion to their per-zone
win-rate, but every configured entrant keeps an exploration-floor probability
so a new or currently-weak entrant is sampled often enough to discover a zone
where it is actually strong. A zone with no win-rate history runs ALL
entrants — a cold start is full competition.

`random` only; deterministic under `seed`.
"""

from __future__ import annotations

import random

from interfaces.types import ModelZoneWinrate
from red_team.tournament import Entrant

_NEUTRAL_WINRATE = 0.5


def _winrate_index(
    zone_id: str, winrates: list[ModelZoneWinrate],
) -> dict[str, float]:
    """Per-model win-rate for one zone, from the persisted rows."""
    return {w.model_label: w.winrate
            for w in winrates if w.zone_id == zone_id}


def weights(
    zone_id: str, all_entrants: list[Entrant],
    winrates: list[ModelZoneWinrate], *, exploration_floor: float = 0.1,
) -> dict[str, float]:
    """Routing weight per entrant label: its per-zone win-rate (neutral prior
    when unknown), floored at `exploration_floor` so no entrant is starved."""
    idx = _winrate_index(zone_id, winrates)
    return {
        e.label: max(idx.get(e.label, _NEUTRAL_WINRATE), exploration_floor)
        for e in all_entrants
    }


def select_entrants(
    zone_id: str, all_entrants: list[Entrant],
    winrates: list[ModelZoneWinrate], *, exploration_floor: float = 0.1,
    seed: int | None = None,
) -> list[Entrant]:
    """Pick which entrants run this cycle for `zone_id`.

    A no-history zone runs every entrant (cold start = full competition).
    Otherwise each entrant is included independently with probability equal
    to its routing weight, and the exploration floor guarantees every
    configured entrant a minimum inclusion rate. The result is never empty:
    if no entrant is drawn, the highest-weighted one is forced in."""
    if not _winrate_index(zone_id, winrates):
        return list(all_entrants)
    rng = random.Random(seed)
    w = weights(zone_id, all_entrants, winrates,
                exploration_floor=exploration_floor)
    selected = [e for e in all_entrants if rng.random() < w[e.label]]
    if not selected:
        selected = [max(all_entrants, key=lambda e: w[e.label])]
    return selected


__all__ = ["select_entrants", "weights"]
