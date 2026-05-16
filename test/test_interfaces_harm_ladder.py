"""Phase 0 — trajectory shared types + the single harm-ladder vocabulary."""

from __future__ import annotations

from dataclasses import fields

from interfaces.types import (
    FAILURE_MODE_TO_STAGE,
    HARM_LADDER,
    STAGE_TO_RESPONSE_MOVEMENT,
    NearMiss,
    NearMissInput,
    Trajectory,
    TurnScore,
)
from red_team.archive import RESPONSE_MOVEMENTS
from red_team.progress import FAILURE_MODES


def test_harm_ladder_has_six_ordered_stages():
    assert HARM_LADDER == (
        "HARD_REFUSAL",
        "SOFT_REFUSAL",
        "ABSTRACT_ENGAGEMENT",
        "PARTIAL_COMPLIANCE",
        "STRONG_COMPLIANCE",
        "PROGRAMMATIC_VIOLATION",
    )


def test_every_failure_mode_maps_to_a_stage():
    for mode in FAILURE_MODES:
        assert mode in FAILURE_MODE_TO_STAGE
        assert 0 <= FAILURE_MODE_TO_STAGE[mode] <= 5


def test_every_stage_maps_to_a_response_movement():
    for stage in range(len(HARM_LADDER)):
        assert stage in STAGE_TO_RESPONSE_MOVEMENT
        assert STAGE_TO_RESPONSE_MOVEMENT[stage] in RESPONSE_MOVEMENTS


def test_turn_score_carries_stage_and_signal_counts():
    fnames = {f.name for f in fields(TurnScore)}
    assert {"turn_index", "stage", "stage_delta", "refusal_hits",
            "hedge_hits", "compliance_hits", "specificity_hits",
            "secret_hits", "note"} <= fnames


def test_trajectory_aggregates_shape_fields():
    fnames = {f.name for f in fields(Trajectory)}
    assert {"lane_id", "idea_id", "zone_id", "turn_scores", "max_stage",
            "final_stage", "erosion_slope", "stalled_at_turn",
            "monotonic"} <= fnames


def test_near_miss_input_is_write_side():
    fnames = {f.name for f in fields(NearMissInput)}
    assert {"idea_id", "lane_id", "zone_id", "max_stage", "stalled_at_turn",
            "erosion_excerpt", "useful_components", "mutation_seeds"} <= fnames
    assert "near_miss_id" not in fnames


def test_near_miss_read_side_has_id_and_consumed():
    fnames = {f.name for f in fields(NearMiss)}
    assert {"near_miss_id", "consumed", "created_at"} <= fnames
