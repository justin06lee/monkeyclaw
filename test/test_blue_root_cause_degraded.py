"""Phase 3 — with no graph the locator behaves like the keyword locator."""

from __future__ import annotations

from pathlib import Path

from blue_team.code_graph_sqlite import PythonCodeGraph
from blue_team.path_tracer import PathTracer
from blue_team.root_cause import RootCauseConfig, RootCauseLocator
from infra.database import Database
from interfaces.types import CheckResult, CodeChunk

FIXTURE = Path(__file__).parent / "fixtures" / "rc_repo"


class _StubMCP:
    def search_codebase(self, query: str, top_k: int) -> list[CodeChunk]:  # noqa: ARG002
        return [CodeChunk(
            file_path="policy.py", function_name="write_file",
            line_range="L4-L6", language="python",
            content="def write_file(p, b): ...", score=0.8)]


class _StubLLM:
    def complete(self, **kwargs):  # noqa: ANN003
        class _R:
            text = ('[{"file": "policy.py", "function": "write_file", '
                    '"line_range": "L4-L6", "explanation": "sink", '
                    '"confidence": 0.8}]')
        return _R()


def test_locate_degrades_cleanly_with_no_graph(db: Database):
    # code_symbols is empty -> graph unavailable -> tracer degrades.
    tracer = PathTracer(graph=PythonCodeGraph(db), mcp=_StubMCP(), db=db)
    loc = RootCauseLocator(llm=_StubLLM(), mcp=_StubMCP(),
                           cfg=RootCauseConfig(), tracer=tracer)
    res = loc.locate(zone_id="SBX-FS", severity="high",
                     minimal_transcript=[],
                     evidence=[CheckResult("policy_check", True, "high", {})])
    # Never crashes; produces a real fix site from the semantic hit.
    assert res.candidate_fix_sites
    assert res.candidate_fix_sites[0].file == "policy.py"


def test_locate_without_tracer_uses_legacy_path(db: Database):
    loc = RootCauseLocator(llm=_StubLLM(), mcp=_StubMCP(),
                           cfg=RootCauseConfig())  # no tracer injected
    res = loc.locate(zone_id="SBX-FS", severity="high",
                     minimal_transcript=[],
                     evidence=[CheckResult("policy_check", True, "high", {})])
    assert res.candidate_fix_sites[0].file == "policy.py"
