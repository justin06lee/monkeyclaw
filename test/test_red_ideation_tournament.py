"""Model ideation tournament — schema + head-to-head tests
(model-ideation-tournament spec §8, §9)."""

from __future__ import annotations

from infra.database import Database

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
