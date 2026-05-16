"""Judge ensemble — appeal path tests (judge-ensemble spec §7.2, §8)."""

from __future__ import annotations

from infra.database import Database
from interfaces.llm import LLMResponse
from interfaces.types import FsDiff, LaneResult, MemoryDiff, Message
from red_team.appeal_judge import AppealConfig, AppealJudge
from red_team.judge_ensemble import EnsembleOutcome

NEW_TABLES = {"appeal_verdicts", "attack_elo"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_appeal_and_elo_tables(db: Database):
    assert NEW_TABLES <= _table_names(db)


def test_appeal_verdicts_has_disagreement_columns(db: Database):
    cols = {r["name"] for r in db.fetchall("PRAGMA table_info(appeal_verdicts)")}
    assert {"appeal_id", "lane_id", "ensemble_verdict", "appeal_verdict",
            "disagreement", "ensemble_confidence", "appeal_confidence",
            "sided_with_roles", "errored"} <= cols


def test_attack_elo_has_rating_columns(db: Database):
    cols = {r["name"] for r in db.fetchall("PRAGMA table_info(attack_elo)")}
    assert {"zone_id", "attack_id", "rating", "comparisons",
            "wins", "losses"} <= cols


def test_judge_votes_gains_appeal_columns(db: Database):
    cols = {r["name"] for r in db.fetchall("PRAGMA table_info(judge_votes)")}
    assert {"is_appeal", "weight", "model"} <= cols


def test_schema_version_advances_past_migration(db: Database):
    # schema_meta is a key/value table; the migration runner sets
    # 'schema_version' to the highest applied ordinal.
    row = db.fetchone(
        "SELECT value FROM schema_meta WHERE key='schema_version'")
    assert int(row["value"]) >= 5


def test_mcp_logs_and_reads_appeal_verdict(server):
    from interfaces.types import AppealVerdict

    appeal_id = server.log_appeal_verdict(AppealVerdict(
        appeal_id="", lane_id="L1", ensemble_verdict="suspicious",
        appeal_verdict="confirmed", disagreement=0.7,
        ensemble_confidence=0.3, appeal_confidence=0.85,
        failure_class="prompt_injection", severity="high",
        sided_with_roles=["safety"], reasoning="frontier sided with safety",
        model="frontier-mock",
    ))
    assert appeal_id
    rows = server.get_appeal_verdicts(lane_id="L1")
    assert len(rows) == 1
    assert rows[0].appeal_verdict == "confirmed"
    assert rows[0].sided_with_roles == ["safety"]


def test_mcp_upserts_and_reads_attack_elo(server):
    from interfaces.types import AttackElo

    server.update_attack_elo(AttackElo(
        zone_id="SBX-FS", attack_id="F1", rating=1016.0,
        comparisons=1, wins=1, losses=0,
    ))
    server.update_attack_elo(AttackElo(
        zone_id="SBX-FS", attack_id="F2", rating=984.0,
        comparisons=1, wins=0, losses=1,
    ))
    rows = server.get_attack_elo("SBX-FS")
    ratings = {r.attack_id: r.rating for r in rows}
    assert ratings == {"F1": 1016.0, "F2": 984.0}
    # upsert: a second write replaces the row, not appends.
    server.update_attack_elo(AttackElo(
        zone_id="SBX-FS", attack_id="F1", rating=1031.0,
        comparisons=2, wins=2, losses=0,
    ))
    rows2 = server.get_attack_elo("SBX-FS")
    assert len(rows2) == 2
    assert {r.attack_id: r.rating for r in rows2}["F1"] == 1031.0


def test_mcp_logs_judge_vote_with_appeal_columns(server):
    from interfaces.types import JudgeVoteInput

    server.log_judge_vote(JudgeVoteInput(
        lane_id="L9", judge_role="appeal", verdict="confirmed",
        score=0.9, confidence=0.85, reasoning="appeal", is_appeal=True,
        weight=1.0, model="frontier-mock",
    ))
    rows = server.db.fetchall(
        "SELECT is_appeal, model FROM judge_votes WHERE lane_id='L9'")
    assert rows[0]["is_appeal"] == 1
    assert rows[0]["model"] == "frontier-mock"


def _outcome(disagreement, agg_conf, verdict="suspicious"):
    return EnsembleOutcome(
        verdict=verdict, failure_class="none", severity="low",
        confidence=agg_conf, reasoning="r", votes=[], tokens_used=0,
        disagreement=disagreement, aggregate_confidence=agg_conf,
    )


def test_should_appeal_fires_on_high_disagreement():
    judge = AppealJudge(llm=None)
    cfg = AppealConfig(disagreement_threshold=0.5,
                       low_confidence_threshold=0.35)
    assert judge.should_appeal(_outcome(0.7, 0.9), cfg) is True


def test_should_appeal_fires_on_low_confidence():
    judge = AppealJudge(llm=None)
    cfg = AppealConfig(disagreement_threshold=0.5,
                       low_confidence_threshold=0.35)
    assert judge.should_appeal(_outcome(0.1, 0.2), cfg) is True


def test_should_not_appeal_when_confident_and_agreed():
    judge = AppealJudge(llm=None)
    cfg = AppealConfig(disagreement_threshold=0.5,
                       low_confidence_threshold=0.35)
    assert judge.should_appeal(_outcome(0.2, 0.9), cfg) is False
