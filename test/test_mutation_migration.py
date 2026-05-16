"""Phase 0 — mutation-operator-learning migration + MCP round-trip."""

from __future__ import annotations

from infra.database import Database

NEW_TABLES = {"mutation_operator_stats_by_zone", "mutation_attempts"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_new_tables(db: Database):
    assert NEW_TABLES <= _table_names(db)


def test_mutation_operator_stats_has_new_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(mutation_operator_stats)")}
    assert {"squared_score", "last_lift"} <= cols


def test_mutation_attempts_has_lift_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(mutation_attempts)")}
    assert {"operator", "parent_idea_id", "child_idea_id",
            "parent_score", "child_score", "lift", "improved",
            "child_verdict"} <= cols


def test_schema_version_is_at_least_three(db: Database):
    row = db.fetchone(
        "SELECT value FROM schema_meta WHERE key='schema_version'")
    assert int(row["value"]) >= 3


def test_mcp_updates_and_reads_global_operator_stats(server):
    from interfaces.types import MutationOperatorStat

    server.update_mutation_operator_stats(MutationOperatorStat(
        operator="paraphrase", zone_id="", uses=3, successes=2,
        avg_score=0.6, squared_score=1.2, last_lift=0.3))
    rows = server.get_mutation_operator_stats()
    by_op = {r.operator: r for r in rows}
    assert by_op["paraphrase"].uses == 3
    assert by_op["paraphrase"].zone_id == ""


def test_mcp_update_is_an_upsert(server):
    from interfaces.types import MutationOperatorStat

    server.update_mutation_operator_stats(MutationOperatorStat(
        operator="paraphrase", zone_id="", uses=1, successes=1,
        avg_score=0.5, squared_score=0.25, last_lift=0.1))
    server.update_mutation_operator_stats(MutationOperatorStat(
        operator="paraphrase", zone_id="", uses=5, successes=4,
        avg_score=0.8, squared_score=3.2, last_lift=0.4))
    rows = {r.operator: r for r in server.get_mutation_operator_stats()}
    assert rows["paraphrase"].uses == 5
    assert rows["paraphrase"].successes == 4


def test_mcp_writes_per_zone_stats_when_zone_set(server):
    from interfaces.types import MutationOperatorStat

    server.update_mutation_operator_stats(MutationOperatorStat(
        operator="paraphrase", zone_id="PROMPT-INJ", uses=2, successes=2,
        avg_score=0.9, squared_score=1.62, last_lift=0.5))
    zone_rows = server.get_mutation_operator_stats(zone_id="PROMPT-INJ")
    assert any(r.operator == "paraphrase" and r.uses == 2 for r in zone_rows)
    # The global rollup is untouched by a per-zone write.
    assert server.get_mutation_operator_stats() == []


def test_mcp_logs_mutation_attempt_and_assigns_id(server):
    from interfaces.types import MutationAttempt

    aid = server.log_mutation_attempt(MutationAttempt(
        attempt_id="", cycle_id=1, zone_id="PROMPT-INJ",
        operator="paraphrase", parent_idea_id="I1", child_idea_id="I2",
        parent_score=0.4, child_score=0.9, lift=0.5, improved=True,
        child_verdict="confirmed", created_at=""))
    assert aid.startswith("MUT")
