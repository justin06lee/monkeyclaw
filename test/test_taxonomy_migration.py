"""Phase 0 — migration 0005 creates the three technique tables."""

from __future__ import annotations

from infra.database import Database

TECHNIQUE_TABLES = {
    "idea_techniques",
    "finding_techniques",
    "technique_coverage",
}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_technique_tables(db: Database):
    assert TECHNIQUE_TABLES <= _table_names(db)


def test_idea_techniques_has_resolved_by_column(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(idea_techniques)")}
    assert {"idea_id", "technique_kind", "technique_id",
            "corpus_version", "resolved_by", "created_at"} <= cols


def test_technique_coverage_primary_key(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(technique_coverage)")}
    assert {"zone_id", "technique_kind", "technique_id",
            "attempts", "confirmations", "last_seen_at"} <= cols


def test_mcp_logs_and_reads_idea_techniques(server):
    from interfaces.types import TechniqueRef

    server.log_idea_techniques("IDEA-1", [
        TechniqueRef(kind="atlas", technique_id="AML.T0051",
                     name="LLM Prompt Injection",
                     corpus_version="atlas-5.4.0+owasp-2025",
                     resolved_by="model"),
        TechniqueRef(kind="owasp", technique_id="LLM01",
                     name="Prompt Injection",
                     corpus_version="atlas-5.4.0+owasp-2025",
                     resolved_by="keyword"),
    ])
    refs = server.get_idea_techniques("IDEA-1")
    assert len(refs) == 2
    assert {r.technique_id for r in refs} == {"AML.T0051", "LLM01"}


def test_mcp_logs_finding_techniques(server):
    from interfaces.types import TechniqueRef

    server.log_finding_techniques("F-1", [
        TechniqueRef(kind="atlas", technique_id="AML.T0070",
                     name="Agent Memory Manipulation",
                     corpus_version="atlas-5.4.0+owasp-2025",
                     resolved_by="model"),
    ])
    refs = server.get_finding_techniques("F-1")
    assert len(refs) == 1 and refs[0].technique_id == "AML.T0070"


def test_mcp_bumps_and_reads_technique_coverage(server):
    server.bump_technique_coverage(
        "PROMPT-INJ", "atlas", "AML.T0051", attempts=1, confirmations=0)
    server.bump_technique_coverage(
        "PROMPT-INJ", "atlas", "AML.T0051", attempts=1, confirmations=1)
    rows = server.get_technique_coverage_rows("PROMPT-INJ")
    assert len(rows) == 1
    assert rows[0]["attempts"] == 2 and rows[0]["confirmations"] == 1
