"""Model ideation tournament — schema + head-to-head tests
(model-ideation-tournament spec §8, §9)."""

from __future__ import annotations

from infra.database import Database
from interfaces.llm import LLMResponse
from interfaces.types import ModelZoneWinrate, TournamentRound
from red_team.ideation_tournament import IdeationTournamentJudge

NEW_TABLES = {"model_zone_winrate", "model_tournament_rounds"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_tournament_tables(db: Database):
    assert NEW_TABLES <= _table_names(db)


def test_model_zone_winrate_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(model_zone_winrate)")}
    assert {"zone_id", "model_label", "role", "h2h_wins", "h2h_comparisons",
            "confirmed", "suspicious", "ideas_executed", "winrate"} <= cols


def test_model_tournament_rounds_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(model_tournament_rounds)")}
    assert {"round_id", "cycle_id", "zone_id", "entrants",
            "pairwise", "winner_label"} <= cols


def test_schema_version_advanced_for_tournament(db: Database):
    row = db.fetchone(
        "SELECT value FROM schema_meta WHERE key='schema_version'")
    assert int(row["value"]) >= 13


def test_mcp_upserts_and_reads_model_zone_winrate(server):
    from interfaces.types import ModelZoneWinrate

    server.update_model_zone_winrate(ModelZoneWinrate(
        zone_id="SBX-FS", model_label="nemotron", role="red_ideation",
        h2h_wins=2, h2h_comparisons=3, confirmed=1, suspicious=0,
        ideas_executed=4, winrate=0.62))
    rows = server.get_model_zone_winrate("SBX-FS")
    assert len(rows) == 1
    assert rows[0].winrate == 0.62
    # upsert: a second write replaces, not appends.
    server.update_model_zone_winrate(ModelZoneWinrate(
        zone_id="SBX-FS", model_label="nemotron", role="red_ideation",
        h2h_wins=3, h2h_comparisons=4, confirmed=2, suspicious=0,
        ideas_executed=5, winrate=0.71))
    rows2 = server.get_model_zone_winrate("SBX-FS")
    assert len(rows2) == 1
    assert rows2[0].winrate == 0.71


def test_mcp_get_model_zone_winrate_all_zones(server):
    from interfaces.types import ModelZoneWinrate

    server.update_model_zone_winrate(ModelZoneWinrate(
        zone_id="SBX-FS", model_label="a"))
    server.update_model_zone_winrate(ModelZoneWinrate(
        zone_id="SBX-NET", model_label="b"))
    assert len(server.get_model_zone_winrate()) == 2


def test_mcp_logs_and_reads_tournament_round(server):
    from interfaces.types import TournamentRound

    round_id = server.log_tournament_round(TournamentRound(
        round_id="", cycle_id=7, zone_id="SBX-FS",
        entrants=["nemotron", "frontier"],
        pairwise=[{"a": "nemotron", "b": "frontier",
                   "winner": "frontier", "margin": 0.4}],
        winner_label="frontier"))
    assert round_id
    rows = server.db.fetchall(
        "SELECT * FROM model_tournament_rounds WHERE zone_id='SBX-FS'")
    assert rows[0]["winner_label"] == "frontier"
    assert rows[0]["cycle_id"] == 7


class _Idea:
    def __init__(self, title):
        self.title = title
        self.approach = "approach text"
        self.novelty_note = "novel"
        self.tactic_tags = ["t1"]


class _ScriptedLLM:
    """Returns 'A' as winner each call unless told to fail."""

    def __init__(self, raise_exc=None):
        self.raise_exc = raise_exc
        self.calls = 0

    def complete(self, *, messages, system, max_tokens, temperature):
        self.calls += 1
        if self.raise_exc is not None:
            raise self.raise_exc
        return LLMResponse(text=(
            '{"winner": "A", "margin": 0.5, '
            '"reasoning": "A is more distinct"}'),
            input_tokens=5, output_tokens=10)


def test_judge_round_two_entrants_runs_one_comparison():
    llm = _ScriptedLLM()
    judge = IdeationTournamentJudge(llm)
    idea_sets = {"nemotron": [_Idea("i1")], "frontier": [_Idea("i2")]}
    rnd = judge.judge_round(zone_id="SBX-FS", cycle_id=1,
                            idea_sets=idea_sets)
    assert llm.calls == 1
    assert len(rnd.pairwise) == 1
    assert rnd.winner_label in ("nemotron", "frontier")


def test_judge_round_three_entrants_runs_round_robin():
    llm = _ScriptedLLM()
    judge = IdeationTournamentJudge(llm)
    idea_sets = {"a": [_Idea("x")], "b": [_Idea("y")], "c": [_Idea("z")]}
    rnd = judge.judge_round(zone_id="Z", cycle_id=1, idea_sets=idea_sets)
    assert llm.calls == 3  # round-robin of 3 entrants -> 3 comparisons
    assert len(rnd.pairwise) == 3


def test_judge_round_treats_empty_idea_set_as_forfeit():
    llm = _ScriptedLLM()
    judge = IdeationTournamentJudge(llm)
    idea_sets = {"nemotron": [_Idea("i1")], "frontier": []}
    rnd = judge.judge_round(zone_id="Z", cycle_id=1, idea_sets=idea_sets)
    # the entrant with ideas wins by forfeit; no LLM call needed.
    assert llm.calls == 0
    assert rnd.pairwise[0]["winner"] == "nemotron"


def test_judge_round_survives_a_failed_pairwise_call():
    llm = _ScriptedLLM(raise_exc=RuntimeError("judge down"))
    judge = IdeationTournamentJudge(llm)
    idea_sets = {"a": [_Idea("x")], "b": [_Idea("y")]}
    rnd = judge.judge_round(zone_id="Z", cycle_id=1, idea_sets=idea_sets)
    # the failed comparison is dropped, the round still returns.
    assert rnd.pairwise == []


def _round(zone, pairwise, entrants):
    return TournamentRound(round_id="r1", cycle_id=1, zone_id=zone,
                           entrants=entrants, pairwise=pairwise,
                           winner_label="")


def test_update_winrate_folds_h2h_and_execution_signals():
    judge = IdeationTournamentJudge(llm=None, h2h_weight=0.6)
    rnd = _round("Z",
                 [{"a": "nemotron", "b": "frontier",
                   "winner": "nemotron", "margin": 0.5}],
                 ["nemotron", "frontier"])
    # nemotron: 1 confirmed of 2 executed -> exec_rate 0.5; h2h 1/1 = 1.0
    # winrate = 0.6*1.0 + 0.4*0.5 = 0.8
    outcomes = {"nemotron": {"confirmed": 1, "suspicious": 0,
                             "ideas_executed": 2},
                "frontier": {"confirmed": 0, "suspicious": 0,
                             "ideas_executed": 2}}
    rows = judge.update_winrate(rnd, outcomes,
                                prior={})
    by_label = {r.model_label: r for r in rows}
    assert abs(by_label["nemotron"].winrate - 0.8) < 1e-9
    # frontier: h2h 0/1 = 0.0; exec 0/2 = 0.0 -> winrate 0.0
    assert abs(by_label["frontier"].winrate - 0.0) < 1e-9


def test_update_winrate_neutral_prior_for_no_history_entrant():
    judge = IdeationTournamentJudge(llm=None, h2h_weight=0.6)
    # an entrant in the round but with no comparisons and no execution.
    rnd = _round("Z", [], ["lonely"])
    rows = judge.update_winrate(rnd, execution_outcomes={}, prior={})
    by_label = {r.model_label: r for r in rows}
    # no h2h evidence, no execution evidence -> neutral prior preserved.
    assert by_label["lonely"].winrate == 0.5


def test_update_winrate_accumulates_onto_prior():
    judge = IdeationTournamentJudge(llm=None, h2h_weight=0.6)
    prior = {("Z", "nemotron"): ModelZoneWinrate(
        zone_id="Z", model_label="nemotron", h2h_wins=1,
        h2h_comparisons=1, confirmed=1, suspicious=0, ideas_executed=2)}
    rnd = _round("Z",
                 [{"a": "nemotron", "b": "frontier",
                   "winner": "nemotron", "margin": 0.5}],
                 ["nemotron", "frontier"])
    outcomes = {"nemotron": {"confirmed": 1, "suspicious": 0,
                             "ideas_executed": 2}}
    rows = judge.update_winrate(rnd, outcomes, prior=prior)
    nemotron = {r.model_label: r for r in rows}["nemotron"]
    # counters accumulate: 2 h2h comparisons, 2 h2h wins, 4 ideas executed.
    assert nemotron.h2h_comparisons == 2
    assert nemotron.h2h_wins == 2
    assert nemotron.ideas_executed == 4
