"""Phase 0 — code-graph migration creates the three tables."""

from __future__ import annotations

from infra.database import Database

GRAPH_TABLES = {"code_symbols", "code_edges", "executed_paths"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_graph_tables(db: Database):
    assert GRAPH_TABLES <= _table_names(db)


def test_code_symbols_has_location_columns(db: Database):
    cols = {r["name"] for r in db.fetchall("PRAGMA table_info(code_symbols)")}
    assert {"symbol_id", "chunk_id", "file_path", "symbol_name",
            "symbol_kind", "line_start", "line_end", "language"} <= cols


def test_code_edges_records_resolution(db: Database):
    cols = {r["name"] for r in db.fetchall("PRAGMA table_info(code_edges)")}
    assert {"src_symbol_id", "dst_symbol_id", "dst_name",
            "edge_kind", "resolved"} <= cols


def test_executed_paths_records_backend_and_degraded(db: Database):
    cols = {r["name"] for r in db.fetchall("PRAGMA table_info(executed_paths)")}
    assert {"path_id", "finding_id", "zone_id", "anchor_symbols",
            "sink_symbols", "node_count", "backend", "degraded"} <= cols
