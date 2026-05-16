"""B5: niche-aware ideation seeding from the MAP-Elites archive.

Turns the EliteArchive into prompt seed context for the IdeationEngine. Three
strategies, combined into one ArchiveSeed:

- elite recall — the zone's best elites, plus a small cross-zone sample of
  elites sharing an interaction_style with the zone's occupied cells;
- cross-cell combination — pairs of elites from DIFFERENT cells, the
  MAP-Elites recombination operator;
- empty-niche targets — the unfilled (style, movement) keys for the zone.

Pure shaping: no LLM, no IO, unit-testable. ArchiveSeed is a red-team-local
dataclass — it never crosses a package boundary, so it is not an interfaces/
type (same rationale as IdeaTactics).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from red_team.archive import (
    INTERACTION_STYLES,
    RESPONSE_MOVEMENTS,
    ArchiveEntry,
    EliteArchive,
)


@dataclass
class ArchiveSeed:
    """Structured niche-aware seed for one zone's ideation."""

    zone_id: str
    zone_elites: list[ArchiveEntry] = field(default_factory=list)
    cross_zone_elites: list[ArchiveEntry] = field(default_factory=list)
    combination_pairs: list[tuple[ArchiveEntry, ArchiveEntry]] = field(
        default_factory=list)
    empty_niches: list[tuple[str, str, str]] = field(default_factory=list)


def build_seed(
    archive: EliteArchive,
    zone_id: str,
    *,
    cfg,
) -> ArchiveSeed:
    """Read the archive and produce the structured ArchiveSeed for ``zone_id``.

    Never raises on archive contents — an empty archive yields a seed whose
    only content is the full set of open niches.
    """
    zone_elites = archive.elites_for_zone(zone_id)

    # Cross-zone recall: elites of other zones that share an interaction_style
    # with one of this zone's occupied cells. Highest-scoring first, capped.
    occupied_styles = {e.interaction_style for e in zone_elites}
    cross_zone_count = max(0, int(getattr(cfg, "seed_cross_zone_count", 2)))
    cross_zone: list[ArchiveEntry] = []
    if occupied_styles and cross_zone_count:
        others = [
            e for e in archive.all_elites()
            if e.zone != zone_id and e.interaction_style in occupied_styles
        ]
        cross_zone = others[:cross_zone_count]

    # Cross-cell combination pairs: consecutive elites guaranteed to come from
    # different cells (the MAP-Elites recombination operator).
    pairs: list[tuple[ArchiveEntry, ArchiveEntry]] = []
    for i in range(len(zone_elites) - 1):
        a, b = zone_elites[i], zone_elites[i + 1]
        if a.cell_key != b.cell_key:
            pairs.append((a, b))

    empty = archive.empty_cells(zone_id, INTERACTION_STYLES, RESPONSE_MOVEMENTS)

    return ArchiveSeed(
        zone_id=zone_id,
        zone_elites=zone_elites,
        cross_zone_elites=cross_zone,
        combination_pairs=pairs,
        empty_niches=empty,
    )


__all__ = ["ArchiveSeed", "build_seed"]
