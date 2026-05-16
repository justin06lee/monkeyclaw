"""Offline taxonomy-corpus refresh tool (corpus-driven-ideation spec §6.5).

Human-run, NEVER invoked by the loop. Fetches the current ATLAS + OWASP
sources, normalises them into the red_team/corpora/ file shapes, bumps
corpus_meta.yaml, and prints a diff summary for the operator to review.
It does NOT auto-commit and does NOT touch zone_atlas_mapping.yaml — a new
technique is flagged 'unmapped' so a human extends the mapping deliberately.

Usage:
    python scripts/refresh_taxonomy_corpus.py [--dry-run]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from red_team.taxonomy import load_taxonomy


def diff_summary(
    old: dict[str, str], new: dict[str, str]
) -> dict[str, object]:
    """Compare old vs. new {technique_id: name}; report added/removed/renamed."""
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    renamed = {tid: (old[tid], new[tid]) for tid in set(old) & set(new)
               if old[tid] != new[tid]}
    return {"added": added, "removed": removed, "renamed": renamed}


def unmapped_techniques(
    techniques: set[str], mapped: set[str]
) -> set[str]:
    """Techniques present in the corpus but absent from the zone mapping."""
    return techniques - mapped


def validate_regenerated(corpus_dir: str | Path) -> bool:
    """Validate a regenerated corpus by loading it through the taxonomy
    loader. Returns True on success; re-raises ValueError on bad data."""
    load_taxonomy(corpus_dir)
    return True


def _fetch_upstream() -> None:  # pragma: no cover - network, operator only
    """Fetch ATLAS + OWASP upstream sources. Operator's machine only —
    the loop never reaches the network for taxonomy data."""
    raise NotImplementedError(
        "wire the upstream ATLAS/OWASP fetch here when refreshing the corpus")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="report the diff without writing corpora/")
    args = parser.parse_args(argv)

    corpus_dir = Path("red_team/corpora")
    current = load_taxonomy(corpus_dir)
    old_names: dict[str, str] = {}
    for zone_id in current.zone_ids():
        for tech in current.techniques_for_zone(zone_id):
            old_names[tech.technique_id] = tech.name
    print(f"current corpus version: {current.version}")
    print(f"current technique count: {len(old_names)}")
    if args.dry_run:
        print("--dry-run: no upstream fetch, no files written")
        return 0
    print("refresh requires wiring _fetch_upstream() to the live sources;")
    print("the loop keeps using the vendored snapshot until then.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
