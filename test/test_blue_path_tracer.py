"""Phase 2 — PathTracer reconstructs and ranks the executed path."""

from __future__ import annotations

from pathlib import Path

from blue_team.code_graph_sqlite import PythonCodeGraph
from blue_team.path_tracer import PathTracer
from infra.codebase_indexer import index_codebase, index_symbol_graph
from infra.database import Database
from interfaces.types import CheckResult, CodeChunk

FIXTURE = Path(__file__).parent / "fixtures" / "rc_repo"


def _evidence() -> list[CheckResult]:
    return [CheckResult(
        check_name="policy_check",
        triggered=True,
        severity="high",
        evidence={"writes_outside_allowed": [{"path": "/etc/passwd"}]},
    )]


class _StubMCP:
    """search_codebase returns the policy.py sink chunk."""

    def search_codebase(self, query: str, top_k: int) -> list[CodeChunk]:  # noqa: ARG002
        return [CodeChunk(
            file_path="policy.py", function_name="write_file",
            line_range="L4-L6", language="python",
            content="def write_file(path, body): ...", score=0.9,
        )]


def _trace_with_graph(db: Database):
    index_codebase(db, FIXTURE)
    index_symbol_graph(db, root=FIXTURE)
    graph = PythonCodeGraph(db)
    tracer = PathTracer(graph=graph, mcp=_StubMCP())
    return tracer.trace(
        zone_id="SBX-FS", evidence=_evidence(),
        transcript=[], victim_logs=[])


def test_traced_path_is_not_degraded(db: Database):
    path = _trace_with_graph(db)
    assert path.degraded is False
    assert path.backend == "python"


def test_violation_site_outranks_off_path_symbol(db: Database):
    path = _trace_with_graph(db)
    by_name = {n.symbol.symbol_name: n.rank_score for n in path.nodes}
    assert "policy_check" in by_name
    assert by_name.get("format_banner", 0.0) < by_name["policy_check"]


def test_on_path_symbol_present(db: Database):
    path = _trace_with_graph(db)
    names = {n.symbol.symbol_name for n in path.nodes}
    # resolve_path is on the handler -> write sink path.
    assert "resolve_path" in names or "policy_check" in names


def test_degraded_path_when_graph_unavailable(db: Database):
    # Empty DB — code_symbols is empty, so the graph is unavailable.
    graph = PythonCodeGraph(db)
    tracer = PathTracer(graph=graph, mcp=_StubMCP())
    path = tracer.trace(zone_id="SBX-FS", evidence=_evidence(),
                        transcript=[], victim_logs=[])
    assert path.degraded is True
    # Degraded path still yields the semantic-search hit as a node.
    assert any(n.symbol.symbol_name == "write_file" for n in path.nodes)
