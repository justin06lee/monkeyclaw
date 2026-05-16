"""Phase 0 — real-root-cause shared type contracts."""

from __future__ import annotations

from dataclasses import fields

from interfaces.types import (
    CodeEdge,
    CodeSymbol,
    ExecutedPath,
    PathNode,
)


def test_code_symbol_has_location_fields():
    fnames = {f.name for f in fields(CodeSymbol)}
    assert {"symbol_id", "file_path", "symbol_name", "symbol_kind",
            "line_start", "line_end", "language"} <= fnames


def test_code_edge_carries_unresolved_target():
    e = CodeEdge(
        src_symbol_id="S1", dst_symbol_id=None, dst_name="policy_check",
        edge_kind="call", resolved=False,
    )
    assert e.resolved is False
    assert e.dst_symbol_id is None
    assert e.dst_name == "policy_check"


def test_path_node_scores_are_floats():
    sym = CodeSymbol(
        symbol_id="S1", file_path="a.py", symbol_name="handler",
        symbol_kind="function", line_start=1, line_end=9, language="python",
    )
    n = PathNode(symbol=sym, proximity=0.8, centrality=0.5,
                 evidence_touch=True, rank_score=0.72)
    assert 0.0 <= n.rank_score <= 1.0
    assert n.evidence_touch is True


def test_executed_path_is_ranked_with_anchors_and_sinks():
    fnames = {f.name for f in fields(ExecutedPath)}
    assert {"nodes", "anchors", "sinks", "backend", "degraded"} <= fnames


def test_code_graph_config_defaults():
    from interfaces.config_schema import MonkeyClawConfig

    cfg = MonkeyClawConfig()
    cg = cfg.repro.code_graph
    assert cg.enabled is True
    assert cg.max_hops == 6
    assert abs(cg.path_rank_weight - 0.5) < 1e-9
    assert abs(cg.llm_conf_weight - 0.5) < 1e-9
