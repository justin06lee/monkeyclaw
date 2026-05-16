"""Phase 2 — niche-aware ideation seeding from the MAP-Elites archive."""

from __future__ import annotations

from red_team.archive import ArchiveEntry, EliteArchive
from red_team.archive_seed import ArchiveSeed, build_seed


class _Cfg:
    seed_cross_zone_count = 2


def _arch_with(*entries: ArchiveEntry) -> EliteArchive:
    arch = EliteArchive()
    for e in entries:
        arch.consider(e)
    return arch


def test_build_seed_returns_zone_elites():
    arch = _arch_with(
        ArchiveEntry(zone="SBX-FS", interaction_style="direct",
                     response_movement="refusal", score=4.0, idea_id="I1",
                     idea_title="fs direct"),
        ArchiveEntry(zone="SBX-FS", interaction_style="roleplay",
                     response_movement="partial_compliance", score=7.0,
                     idea_id="I2", idea_title="fs roleplay"),
    )
    seed = build_seed(arch, "SBX-FS", cfg=_Cfg())
    assert isinstance(seed, ArchiveSeed)
    ids = {e.idea_id for e in seed.zone_elites}
    assert ids == {"I1", "I2"}


def test_build_seed_combination_pairs_are_from_different_cells():
    arch = _arch_with(
        ArchiveEntry(zone="SBX-FS", interaction_style="direct",
                     response_movement="refusal", score=4.0, idea_id="I1"),
        ArchiveEntry(zone="SBX-FS", interaction_style="roleplay",
                     response_movement="partial_compliance", score=7.0,
                     idea_id="I2"),
    )
    seed = build_seed(arch, "SBX-FS", cfg=_Cfg())
    assert seed.combination_pairs
    for a, b in seed.combination_pairs:
        assert a.cell_key != b.cell_key


def test_build_seed_lists_empty_niche_targets():
    arch = _arch_with(
        ArchiveEntry(zone="SBX-FS", interaction_style="direct",
                     response_movement="refusal", score=4.0, idea_id="I1"),
    )
    seed = build_seed(arch, "SBX-FS", cfg=_Cfg())
    assert seed.empty_niches
    assert ("SBX-FS", "direct", "refusal") not in seed.empty_niches


def test_build_seed_includes_cross_zone_elites_sharing_a_style():
    arch = _arch_with(
        ArchiveEntry(zone="SBX-FS", interaction_style="roleplay",
                     response_movement="refusal", score=3.0, idea_id="I1"),
        ArchiveEntry(zone="PROMPT-INJ", interaction_style="roleplay",
                     response_movement="strong_compliance", score=9.0,
                     idea_id="I2", idea_title="inj roleplay"),
    )
    seed = build_seed(arch, "SBX-FS", cfg=_Cfg())
    assert any(e.idea_id == "I2" for e in seed.cross_zone_elites)


def test_build_seed_empty_archive_is_valid():
    seed = build_seed(EliteArchive(), "SBX-FS", cfg=_Cfg())
    assert seed.zone_elites == []
    assert seed.combination_pairs == []
    assert seed.empty_niches  # the whole grid is open
