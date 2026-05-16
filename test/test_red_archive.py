"""B5: MAP-Elites archive tests.

Acceptance criteria proven explicitly:
  1. The archive stores multiple diverse elites simultaneously.
  2. A high-scoring `direct` attempt does NOT erase a lower-scoring elite in a
     different style niche (`multi_turn` / `tool_use`).
"""

from __future__ import annotations

import pytest

from red_team.archive import (
    INTERACTION_STYLES,
    RESPONSE_MOVEMENTS,
    ArchiveEntry,
    EliteArchive,
    turn_bucket,
)


def _entry(
    zone: str = "z1",
    style: str = "direct",
    movement: str = "partial_compliance",
    score: float = 0.5,
    idea_id: str = "idea-1",
    **kw,
) -> ArchiveEntry:
    return ArchiveEntry(
        zone=zone,
        interaction_style=style,
        response_movement=movement,
        score=score,
        idea_id=idea_id,
        **kw,
    )


# --- axis constants --------------------------------------------------------

def test_axis_constants_have_exact_values():
    assert INTERACTION_STYLES == (
        "direct",
        "indirect",
        "roleplay",
        "multi_turn",
        "tool_use",
        "context_injection",
    )
    assert RESPONSE_MOVEMENTS == (
        "refusal",
        "soft_refusal",
        "abstract_engagement",
        "partial_compliance",
        "strong_compliance",
        "programmatic_violation",
    )


# --- cell creation ---------------------------------------------------------

def test_consider_creates_cell_and_returns_true():
    arc = EliteArchive()
    assert arc.consider(_entry()) is True
    assert arc.cell_count() == 1
    assert len(arc) == 1
    elite = arc.get_elite("z1", "direct", "partial_compliance")
    assert elite is not None
    assert elite.idea_id == "idea-1"


def test_get_elite_returns_none_for_empty_cell():
    arc = EliteArchive()
    assert arc.get_elite("z1", "tool_use", "refusal") is None


# --- elite replacement -----------------------------------------------------

def test_higher_score_replaces_incumbent():
    arc = EliteArchive()
    arc.consider(_entry(score=0.4, idea_id="low"))
    won = arc.consider(_entry(score=0.9, idea_id="high"))
    assert won is True
    assert arc.cell_count() == 1  # same cell, replaced not added
    assert arc.get_elite("z1", "direct", "partial_compliance").idea_id == "high"


def test_lower_score_is_rejected():
    arc = EliteArchive()
    arc.consider(_entry(score=0.9, idea_id="high"))
    won = arc.consider(_entry(score=0.4, idea_id="low"))
    assert won is False
    assert arc.get_elite("z1", "direct", "partial_compliance").idea_id == "high"


def test_equal_score_does_not_replace():
    arc = EliteArchive()
    arc.consider(_entry(score=0.5, idea_id="first"))
    won = arc.consider(_entry(score=0.5, idea_id="second"))
    assert won is False
    assert arc.get_elite("z1", "direct", "partial_compliance").idea_id == "first"


# --- ACCEPTANCE 1: multiple diverse elites stored simultaneously ----------

def test_archive_stores_multiple_diverse_elites():
    arc = EliteArchive()
    arc.consider(_entry(style="direct", movement="refusal", idea_id="a"))
    arc.consider(_entry(style="multi_turn", movement="partial_compliance", idea_id="b"))
    arc.consider(_entry(style="tool_use", movement="strong_compliance", idea_id="c"))
    arc.consider(_entry(style="roleplay", movement="soft_refusal", idea_id="d"))

    assert arc.cell_count() == 4
    ids = {e.idea_id for e in arc.all_elites()}
    assert ids == {"a", "b", "c", "d"}


# --- ACCEPTANCE 2: cross-niche isolation ----------------------------------

def test_high_direct_does_not_erase_other_niche_elites():
    arc = EliteArchive()
    # Low-scoring elites in distinct style niches.
    arc.consider(_entry(style="multi_turn", movement="partial_compliance",
                         score=0.20, idea_id="mt"))
    arc.consider(_entry(style="tool_use", movement="programmatic_violation",
                         score=0.15, idea_id="tu"))

    # A very high-scoring `direct` attempt arrives.
    won = arc.consider(_entry(style="direct", movement="strong_compliance",
                              score=0.99, idea_id="direct-star"))
    assert won is True

    # The direct attempt occupies its own cell; it did NOT erase the others.
    assert arc.cell_count() == 3
    mt = arc.get_elite("z1", "multi_turn", "partial_compliance")
    tu = arc.get_elite("z1", "tool_use", "programmatic_violation")
    assert mt is not None and mt.idea_id == "mt" and mt.score == 0.20
    assert tu is not None and tu.idea_id == "tu" and tu.score == 0.15
    assert arc.get_elite("z1", "direct", "strong_compliance").idea_id == "direct-star"


# --- elites_for_zone -------------------------------------------------------

def test_elites_for_zone_filters_by_zone_and_sorts_by_score():
    arc = EliteArchive()
    arc.consider(_entry(zone="zA", style="direct", score=0.3, idea_id="a1"))
    arc.consider(_entry(zone="zA", style="roleplay", score=0.8, idea_id="a2"))
    arc.consider(_entry(zone="zB", style="tool_use", score=0.9, idea_id="b1"))

    za = arc.elites_for_zone("zA")
    assert [e.idea_id for e in za] == ["a2", "a1"]  # sorted high -> low
    assert all(e.zone == "zA" for e in za)

    zb = arc.elites_for_zone("zB")
    assert [e.idea_id for e in zb] == ["b1"]

    assert arc.elites_for_zone("missing") == []


def test_same_style_different_zone_are_distinct_cells():
    arc = EliteArchive()
    arc.consider(_entry(zone="zA", style="direct", idea_id="a"))
    arc.consider(_entry(zone="zB", style="direct", idea_id="b"))
    assert arc.cell_count() == 2


# --- validation ------------------------------------------------------------

def test_bad_interaction_style_raises():
    with pytest.raises(ValueError):
        _entry(style="telepathy")


def test_bad_response_movement_raises():
    with pytest.raises(ValueError):
        _entry(movement="exploded")


def test_get_elite_rejects_bad_axis_values():
    arc = EliteArchive()
    with pytest.raises(ValueError):
        arc.get_elite("z1", "nope", "refusal")
    with pytest.raises(ValueError):
        arc.get_elite("z1", "direct", "nope")


# --- turn_bucket helper ----------------------------------------------------

@pytest.mark.parametrize(
    "turns,expected",
    [(0, "0-2"), (2, "0-2"), (3, "3-7"), (7, "3-7"),
     (8, "8-15"), (15, "8-15"), (16, "16+"), (99, "16+")],
)
def test_turn_bucket(turns, expected):
    assert turn_bucket(turns) == expected


def test_turn_bucket_rejects_negative():
    with pytest.raises(ValueError):
        turn_bucket(-1)


# --- secondary descriptors round-trip --------------------------------------

def test_secondary_descriptors_preserved():
    arc = EliteArchive()
    e = _entry(
        turn_bucket="3-7",
        tactic_tags=["obfuscation", "persona"],
        model="claude-victim",
        severity="high",
        transfer_score=0.72,
        idea_title="probe X",
    )
    arc.consider(e)
    got = arc.get_elite("z1", "direct", "partial_compliance")
    assert got.tactic_tags == ["obfuscation", "persona"]
    assert got.model == "claude-victim"
    assert got.severity == "high"
    assert got.transfer_score == 0.72
    assert got.idea_title == "probe X"


def test_archive_cell_carries_niche_descriptors():
    from dataclasses import fields

    from interfaces.types import ArchiveCell

    fnames = {f.name for f in fields(ArchiveCell)}
    assert "niche_descriptors" in fnames


def test_archive_update_input_niche_descriptors_defaults_empty():
    from interfaces.types import ArchiveUpdateInput

    upd = ArchiveUpdateInput(
        zone_id="SBX-FS", interaction_style="direct",
        response_movement="refusal", idea_id="I1", score=4.0,
    )
    assert upd.niche_descriptors == {}
