"""Phase 1 — index_symbol_graph extracts symbols and call edges."""

from __future__ import annotations

from pathlib import Path

from infra.codebase_indexer import index_codebase, index_symbol_graph
from infra.database import Database

FIXTURE = Path(__file__).parent / "fixtures" / "rc_repo"


def _index(db: Database) -> dict:
    index_codebase(db, FIXTURE)
    return index_symbol_graph(db, root=FIXTURE)


def test_symbols_cover_every_function(db: Database):
    _index(db)
    names = {r["symbol_name"] for r in db.fetchall(
        "SELECT symbol_name FROM code_symbols")}
    assert {"handler", "resolve_path", "policy_check",
            "write_file", "format_banner"} <= names


def test_call_edge_handler_to_resolve_path(db: Database):
    _index(db)
    rows = db.fetchall(
        "SELECT e.dst_name, e.resolved FROM code_edges e "
        "JOIN code_symbols s ON s.symbol_id = e.src_symbol_id "
        "WHERE s.symbol_name = 'handler'")
    dst_names = {r["dst_name"] for r in rows}
    assert {"resolve_path", "policy_check", "write_file"} <= dst_names


def test_resolved_edge_has_dst_symbol_id(db: Database):
    _index(db)
    rows = db.fetchall(
        "SELECT e.dst_symbol_id FROM code_edges e "
        "JOIN code_symbols s ON s.symbol_id = e.src_symbol_id "
        "WHERE s.symbol_name = 'handler' AND e.dst_name = 'resolve_path'")
    assert rows and rows[0]["dst_symbol_id"] is not None


def test_unresolved_reference_kept_with_null_target(db: Database):
    _index(db)
    rows = db.fetchall(
        "SELECT resolved, dst_symbol_id FROM code_edges "
        "WHERE dst_name = 'missing_helper'")
    assert rows
    assert rows[0]["resolved"] == 0
    assert rows[0]["dst_symbol_id"] is None


def test_reindex_is_a_noop(db: Database):
    _index(db)
    first = db.fetchall("SELECT COUNT(*) AS n FROM code_symbols")[0]["n"]
    index_symbol_graph(db, root=FIXTURE)
    second = db.fetchall("SELECT COUNT(*) AS n FROM code_symbols")[0]["n"]
    assert first == second
