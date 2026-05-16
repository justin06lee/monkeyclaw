"""Phase 0 — migration 0005 creates the two trajectory tables."""

from __future__ import annotations

from infra.database import Database

TRAJECTORY_TABLES = {"trajectory_scores", "near_misses"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_trajectory_tables(db: Database):
    assert TRAJECTORY_TABLES <= _table_names(db)


def test_trajectory_scores_has_shape_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(trajectory_scores)")}
    assert {"trajectory_id", "lane_id", "idea_id", "zone_id", "max_stage",
            "final_stage", "erosion_slope", "stalled_at_turn", "monotonic",
            "turn_scores"} <= cols


def test_near_misses_has_consumed_flag(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(near_misses)")}
    assert {"near_miss_id", "idea_id", "zone_id", "max_stage",
            "stalled_at_turn", "erosion_excerpt", "useful_components",
            "mutation_seeds", "consumed"} <= cols


def test_schema_version_bumped(db: Database):
    row = db.fetchall(
        "SELECT value FROM schema_meta WHERE key='schema_version'")[0]
    assert int(row["value"]) >= 3


def test_mcp_logs_and_reads_trajectory(server):
    from interfaces.types import Trajectory, TurnScore

    tid = server.log_trajectory(Trajectory(
        lane_id="L1", idea_id="IDEA1", zone_id="PROMPT-INJ",
        turn_scores=[TurnScore(turn_index=0, stage=0, stage_delta=0),
                     TurnScore(turn_index=1, stage=3, stage_delta=3)],
        max_stage=3, final_stage=3, erosion_slope=1.5,
        stalled_at_turn=1, monotonic=True))
    assert tid.startswith("TRJ")
    rows = server.get_trajectories(zone_id="PROMPT-INJ")
    assert len(rows) == 1
    assert rows[0].max_stage == 3
    assert len(rows[0].turn_scores) == 2
    assert rows[0].turn_scores[1].stage == 3


def test_mcp_logs_near_miss_and_assigns_id(server):
    from interfaces.types import NearMissInput

    nid = server.log_near_miss(NearMissInput(
        idea_id="IDEA1", lane_id="L1", zone_id="PROMPT-INJ",
        max_stage=3, stalled_at_turn=2, erosion_excerpt="here's how you...",
        useful_components=["multi_turn_drift"],
        mutation_seeds=["add_more_turns"]))
    assert nid.startswith("NMS")
    misses = server.search_near_misses(
        zone="PROMPT-INJ", only_unconsumed=True, top_k=10)
    assert len(misses) == 1
    assert misses[0].near_miss_id == nid
    assert misses[0].consumed is False


def test_mcp_marks_near_miss_consumed(server):
    from interfaces.types import NearMissInput

    nid = server.log_near_miss(NearMissInput(
        idea_id="IDEA1", lane_id="L1", zone_id="SBX-FS",
        max_stage=4, stalled_at_turn=3, erosion_excerpt="x",
        useful_components=[], mutation_seeds=[]))
    server.mark_near_miss_consumed(nid)
    unconsumed = server.search_near_misses(
        zone="SBX-FS", only_unconsumed=True, top_k=10)
    assert unconsumed == []
    everything = server.search_near_misses(
        zone="SBX-FS", only_unconsumed=False, top_k=10)
    assert len(everything) == 1 and everything[0].consumed is True
