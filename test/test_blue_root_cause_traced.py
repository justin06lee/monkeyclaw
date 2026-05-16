"""Phase 3 — RootCauseLocator consumes the ExecutedPath."""

from __future__ import annotations

from blue_team.root_cause import RootCauseConfig, RootCauseLocator
from interfaces.code_graph import CodeSymbol, ExecutedPath, PathNode
from interfaces.types import CheckResult


def _symbol(name: str, file: str = "policy.py") -> CodeSymbol:
    return CodeSymbol(symbol_id=f"S-{name}", file_path=file, symbol_name=name,
                      symbol_kind="function", line_start=1, line_end=9,
                      language="python")


class _FakeTracer:
    def __init__(self, path: ExecutedPath) -> None:
        self._path = path

    def trace(self, **kwargs):  # noqa: ANN003
        return self._path


class _StubLLM:
    """Returns a fix site for whatever the first node's file is."""

    def __init__(self, text: str) -> None:
        self._text = text

    def complete(self, **kwargs):  # noqa: ANN003
        class _R:
            text = self._text
        return _R()


def _path_with_sites() -> ExecutedPath:
    nodes = [
        PathNode(symbol=_symbol("policy_check"), proximity=1.0,
                 centrality=1.0, evidence_touch=True, rank_score=0.9),
        PathNode(symbol=_symbol("resolve_path"), proximity=0.6,
                 centrality=0.5, evidence_touch=False, rank_score=0.55),
    ]
    return ExecutedPath(nodes=nodes, anchors=[_symbol("handler", "handler.py")],
                        sinks=[_symbol("policy_check")], backend="python",
                        degraded=False)


def test_fix_sites_drawn_only_from_executed_path():
    llm = _StubLLM(
        '[{"trace": "entry to violation"}, '
        '{"file": "policy.py", "function": "policy_check", '
        '"line_range": "L1-L9", "explanation": "the policy gate", '
        '"confidence": 0.8}]')
    loc = RootCauseLocator(llm=llm, mcp=object(), cfg=RootCauseConfig(),
                           tracer=_FakeTracer(_path_with_sites()))
    res = loc.locate(zone_id="SBX-FS", severity="high",
                     minimal_transcript=[],
                     evidence=[CheckResult("policy_check", True, "high", {})])
    assert res.candidate_fix_sites
    assert all(s.file == "policy.py" for s in res.candidate_fix_sites)


def test_llm_cited_file_outside_path_is_rejected():
    llm = _StubLLM(
        '[{"file": "evil_invented.py", "function": "x", '
        '"line_range": "L1", "explanation": "hallucinated", '
        '"confidence": 0.95}]')
    loc = RootCauseLocator(llm=llm, mcp=object(), cfg=RootCauseConfig(),
                           tracer=_FakeTracer(_path_with_sites()))
    res = loc.locate(zone_id="SBX-FS", severity="high",
                     minimal_transcript=[],
                     evidence=[CheckResult("policy_check", True, "high", {})])
    # The off-path file is dropped; fallback to (unknown).
    assert all(s.file != "evil_invented.py" for s in res.candidate_fix_sites)


def test_confidence_is_path_llm_blend():
    llm = _StubLLM(
        '[{"file": "policy.py", "function": "policy_check", '
        '"line_range": "L1-L9", "explanation": "gate", "confidence": 0.6}]')
    cfg = RootCauseConfig(path_rank_weight=0.5, llm_conf_weight=0.5)
    loc = RootCauseLocator(llm=llm, mcp=object(), cfg=cfg,
                           tracer=_FakeTracer(_path_with_sites()))
    res = loc.locate(zone_id="SBX-FS", severity="high",
                     minimal_transcript=[],
                     evidence=[CheckResult("policy_check", True, "high", {})])
    site = res.candidate_fix_sites[0]
    # 0.5 * path_rank(0.9) + 0.5 * llm(0.6) = 0.75
    assert abs(site.confidence - 0.75) < 0.01


def test_unknown_fallback_when_path_has_no_site():
    empty = ExecutedPath(nodes=[], anchors=[], sinks=[], backend="python",
                         degraded=False)
    loc = RootCauseLocator(llm=_StubLLM("[]"), mcp=object(),
                           cfg=RootCauseConfig(), tracer=_FakeTracer(empty))
    res = loc.locate(zone_id="SBX-FS", severity="high",
                     minimal_transcript=[],
                     evidence=[CheckResult("policy_check", True, "high", {})])
    assert res.candidate_fix_sites[0].file == "(unknown)"
