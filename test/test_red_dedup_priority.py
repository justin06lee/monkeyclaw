"""Dedup + priority scoring against the mock MCP."""

from __future__ import annotations

import random

from infra.mock_mcp import MockMCP
from interfaces.types import CoverageGap, IdeaObject
from red_team.dedup import deduplicate_and_log
from red_team.priority import (
    estimate_impact,
    score_ideas,
    select_top_n,
    severity_weight_for,
)


def _idea(zone: str, title: str, novelty_hint: str = "") -> IdeaObject:
    return IdeaObject(
        idea_id="(unassigned)",
        cycle_id=1,
        zone_id=zone,
        source_mode="creative",
        title=title,
        approach="approach text",
        success_criteria="success",
        estimated_turns=3,
        novelty_notes=novelty_hint,
    )


def _gap(zone: str, coverage: float = 0.2, severity: float = 1.0) -> CoverageGap:
    return CoverageGap(
        zone_id=zone, zone_name=zone, coverage_score=coverage,
        priority_score=0.0, vulns_open=0, last_tested_at=None,
        description="", severity_weight=severity,
    )


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------


def test_deduplicate_keeps_all_when_mock_returns_novel():
    """MockMCP's check_duplicate is randomized — pin the seed to a known-novel run."""
    mcp = MockMCP(seed=1, verbose=False)
    ideas = [_idea("PROMPT-INJ", f"idea {i}") for i in range(4)]
    outcomes = deduplicate_and_log(ideas, mcp)
    assert len(outcomes) == 4
    # With seed=1 the mock should produce mostly novel responses
    assert sum(1 for o in outcomes if o.keep) >= 3


def test_deduplicate_thresholds():
    """When the dup result is in [0.80, 0.92), novelty is halved."""
    class FixedMCP(MockMCP):
        def __init__(self):
            super().__init__(seed=0, verbose=False)
            self._fixed_sim = 0.85
        def check_duplicate(self, text, zone, threshold):
            from interfaces.types import DupResult
            return DupResult(
                is_duplicate=False, max_similarity=self._fixed_sim,
                matching_idea_id=None,
            )
    mcp = FixedMCP()
    [oc] = deduplicate_and_log([_idea("PROMPT-INJ", "x")], mcp)
    assert oc.keep is True
    assert oc.near_dup is True
    # novelty = (1-0.85)/2 = 0.075
    assert 0.07 < oc.novelty_score < 0.08


def test_deduplicate_discards_above_threshold():
    class FixedMCP(MockMCP):
        def check_duplicate(self, text, zone, threshold):
            from interfaces.types import DupResult
            return DupResult(
                is_duplicate=True, max_similarity=0.97,
                matching_idea_id="OLD-IDEA",
            )
    mcp = FixedMCP(seed=0, verbose=False)
    [oc] = deduplicate_and_log([_idea("PROMPT-INJ", "x")], mcp)
    assert oc.keep is False
    assert oc.novelty_score == 0.0


# ---------------------------------------------------------------------------
# Priority scoring
# ---------------------------------------------------------------------------


def test_estimate_impact_from_annotation():
    idea = _idea("SBX-FS", "x", novelty_hint="[impact=critical] something")
    assert estimate_impact(idea) == 1.0


def test_estimate_impact_keyword_fallback_sandbox_escape():
    idea = IdeaObject(
        idea_id="x", cycle_id=1, zone_id="SBX-FS", source_mode="creative",
        title="t", approach="exploit something",
        success_criteria="sandbox escape via symlink", estimated_turns=2,
        novelty_notes="",
    )
    assert estimate_impact(idea) == 1.0


def test_severity_weight_fallback_when_zero():
    g = _gap("SBX-FS", severity=0.0)
    assert severity_weight_for(g) == 1.0


def test_score_ideas_sorts_descending():
    from red_team.dedup import DedupOutcome
    from interfaces.types import DupResult
    outcomes = [
        DedupOutcome(
            idea=_idea("SBX-FS", "low", "[impact=low] x"),
            dup=DupResult(False, 0.0, None),
            keep=True, near_dup=False, novelty_score=1.0,
            logged_idea_id="A",
        ),
        DedupOutcome(
            idea=_idea("SBX-FS", "crit", "[impact=critical] x"),
            dup=DupResult(False, 0.0, None),
            keep=True, near_dup=False, novelty_score=1.0,
            logged_idea_id="B",
        ),
    ]
    zones = {"SBX-FS": _gap("SBX-FS", coverage=0.0, severity=1.0)}
    ranked = score_ideas(outcomes, zones)
    assert ranked[0].idea.title == "crit"
    assert ranked[1].idea.title == "low"
    assert ranked[0].priority > ranked[1].priority


def test_select_top_n_skips_discarded():
    from red_team.dedup import DedupOutcome
    from interfaces.types import DupResult
    outcomes = [
        DedupOutcome(_idea("SBX-FS", "kept"), DupResult(False, 0.0, None),
                      keep=True, near_dup=False, novelty_score=1.0, logged_idea_id="A"),
        DedupOutcome(_idea("SBX-FS", "discarded"), DupResult(True, 0.99, "x"),
                      keep=False, near_dup=False, novelty_score=0.0, logged_idea_id="B"),
    ]
    zones = {"SBX-FS": _gap("SBX-FS")}
    top = select_top_n(outcomes, zones, n=5)
    assert len(top) == 1
    assert top[0].idea.title == "kept"


def test_score_ideas_accepts_detection_coverage_gap_boost():
    from interfaces.types import CoverageGap, DupResult, IdeaObject
    from red_team.dedup import DedupOutcome
    from red_team.priority import score_ideas

    idea = IdeaObject(
        idea_id="I1", cycle_id=1, zone_id="SBX-FS", source_mode="creative",
        title="t", approach="generic probe", success_criteria="c",
        estimated_turns=3, novelty_notes="-")
    outcome = DedupOutcome(
        idea=idea, dup=DupResult(False, 0.5, None), keep=True,
        near_dup=False, novelty_score=0.5, logged_idea_id="I1")
    zone = CoverageGap(zone_id="SBX-FS", zone_name="Sandbox / FS",
                       coverage_score=0.5, priority_score=0.0, vulns_open=0,
                       last_tested_at=None, severity_weight=1.0)

    baseline = score_ideas([outcome], {"SBX-FS": zone})[0].priority
    boosted = score_ideas([outcome], {"SBX-FS": zone},
                          detection_coverage_gap={"SBX-FS": 1.0})[0].priority
    # a blind zone (detection gap 1.0) ranks strictly higher.
    assert boosted > baseline


def test_score_ideas_absent_detection_signal_is_unchanged():
    from interfaces.types import CoverageGap, DupResult, IdeaObject
    from red_team.dedup import DedupOutcome
    from red_team.priority import score_ideas

    idea = IdeaObject(
        idea_id="I1", cycle_id=1, zone_id="SBX-FS", source_mode="creative",
        title="t", approach="generic probe", success_criteria="c",
        estimated_turns=3, novelty_notes="-")
    outcome = DedupOutcome(
        idea=idea, dup=DupResult(False, 0.5, None), keep=True,
        near_dup=False, novelty_score=0.5, logged_idea_id="I1")
    zone = CoverageGap(zone_id="SBX-FS", zone_name="Sandbox / FS",
                       coverage_score=0.5, priority_score=0.0, vulns_open=0,
                       last_tested_at=None, severity_weight=1.0)
    a = score_ideas([outcome], {"SBX-FS": zone})[0].priority
    b = score_ideas([outcome], {"SBX-FS": zone},
                    detection_coverage_gap=None)[0].priority
    assert a == b


# ---------------------------------------------------------------------------
# niche_gap — archive-driven priority factor
# ---------------------------------------------------------------------------


def _priority_fixture():
    """A simple kept-outcome + zone fixture for the archive-absent regression."""
    from red_team.dedup import DedupOutcome
    from interfaces.types import DupResult

    outcomes = [
        DedupOutcome(
            idea=_idea("SBX-FS", "a", "[impact=high] x"),
            dup=DupResult(False, 0.0, None),
            keep=True, near_dup=False, novelty_score=1.0, logged_idea_id="A"),
        DedupOutcome(
            idea=_idea("SBX-FS", "b", "[impact=low] x"),
            dup=DupResult(False, 0.0, None),
            keep=True, near_dup=False, novelty_score=0.8, logged_idea_id="B"),
    ]
    zones = {"SBX-FS": _gap("SBX-FS", coverage=0.2, severity=1.0)}
    return outcomes, zones


def _priority_fixture_two_styles():
    """Two kept ideas in SBX-FS — one 'direct', one 'roleplay', else identical."""
    from red_team.dedup import DedupOutcome
    from red_team.ideation import IdeaTactics
    from interfaces.types import DupResult

    direct = _idea("SBX-FS", "direct attack", "[impact=high] x")
    direct.idea_id = "IDEA-DIRECT"
    direct.tactics = IdeaTactics(interaction_style="direct")
    roleplay = _idea("SBX-FS", "roleplay attack", "[impact=high] x")
    roleplay.idea_id = "IDEA-ROLEPLAY"
    roleplay.tactics = IdeaTactics(interaction_style="roleplay")
    outcomes = [
        DedupOutcome(idea=direct, dup=DupResult(False, 0.0, None),
                     keep=True, near_dup=False, novelty_score=1.0,
                     logged_idea_id="A"),
        DedupOutcome(idea=roleplay, dup=DupResult(False, 0.0, None),
                     keep=True, near_dup=False, novelty_score=1.0,
                     logged_idea_id="B"),
    ]
    zones = {"SBX-FS": _gap("SBX-FS", coverage=0.2, severity=1.0)}
    return outcomes, zones


def test_score_ideas_without_archive_is_byte_identical():
    """Regression guard — absent an archive, scores are exactly today's."""
    outcomes, zones = _priority_fixture()

    baseline = score_ideas(outcomes, zones)
    with_none = score_ideas(outcomes, zones, archive=None)
    assert [p.priority for p in baseline] == [p.priority for p in with_none]
    assert all("niche_gap" not in p.components for p in with_none)


def test_niche_gap_boosts_idea_in_empty_style_column():
    from red_team.archive import RESPONSE_MOVEMENTS, ArchiveEntry, EliteArchive

    outcomes, zones = _priority_fixture_two_styles()
    arch = EliteArchive()
    # Saturate the 'direct' column of SBX-FS — every response_movement filled
    # so the column's empty fraction is 0 and niche_gap is damped below 1.0.
    for movement in RESPONSE_MOVEMENTS:
        arch.consider(ArchiveEntry(
            zone="SBX-FS", interaction_style="direct",
            response_movement=movement, score=9.0, idea_id=f"E-{movement}"))
    scored = {p.idea.idea_id: p for p in score_ideas(outcomes, zones,
                                                     archive=arch)}
    direct = scored["IDEA-DIRECT"]
    roleplay = scored["IDEA-ROLEPLAY"]
    assert roleplay.components["niche_gap"] > 1.0
    assert direct.components["niche_gap"] < 1.0
    assert roleplay.priority > direct.priority


def test_niche_gap_stays_within_bounds():
    from red_team.archive import EliteArchive

    outcomes, zones = _priority_fixture_two_styles()
    scored = score_ideas(outcomes, zones, archive=EliteArchive())
    for p in scored:
        assert 0.5 <= p.components["niche_gap"] <= 1.5
