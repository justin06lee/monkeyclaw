"""Phase 1 — PythonCodeGraph reads code_symbols / code_edges."""

from __future__ import annotations

from pathlib import Path

from blue_team.code_graph_sqlite import PythonCodeGraph
from infra.codebase_indexer import index_codebase, index_symbol_graph
from infra.database import Database

FIXTURE = Path(__file__).parent / "fixtures" / "rc_repo"


def _graph(db: Database) -> PythonCodeGraph:
    index_codebase(db, FIXTURE)
    index_symbol_graph(db, root=FIXTURE)
    return PythonCodeGraph(db)


def test_available_false_on_empty_db(db: Database):
    assert PythonCodeGraph(db).available() is False


def test_available_true_after_index(db: Database):
    assert _graph(db).available() is True


def test_find_symbols_by_name(db: Database):
    g = _graph(db)
    syms = g.find_symbols("policy_check")
    assert len(syms) == 1
    assert syms[0].symbol_name == "policy_check"


def test_symbol_at_line(db: Database):
    g = _graph(db)
    handler = g.find_symbols("handler")[0]
    mid = (handler.line_start + handler.line_end) // 2
    found = g.symbol_at(handler.file_path, mid)
    assert found is not None and found.symbol_name == "handler"


def test_shortest_path_handler_to_policy_check(db: Database):
    g = _graph(db)
    handler = g.find_symbols("handler")[0]
    policy = g.find_symbols("policy_check")[0]
    paths = g.shortest_paths(handler.symbol_id, policy.symbol_id, max_hops=6)
    assert paths
    # handler -> policy_check is a direct call edge.
    assert paths[0][-1].dst_symbol_id == policy.symbol_id


def test_callees_of_handler(db: Database):
    g = _graph(db)
    handler = g.find_symbols("handler")[0]
    callee_names = {e.dst_name for e in g.callees(handler.symbol_id)}
    assert {"resolve_path", "policy_check", "write_file"} <= callee_names
