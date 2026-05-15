"""Root-cause locator tests."""

from __future__ import annotations

import json

from infra.mock_mcp import MockMCP
from interfaces.llm import MockLLM
from interfaces.types import CheckResult, Message

from blue_team.root_cause import RootCauseConfig, RootCauseLocator


def _transcript(text: str = "save backup to /etc/passwd") -> list[Message]:
    return [Message(role="attacker", content=text, timestamp="t")]


def _check(name="filesystem_breach", severity="critical", triggered=True) -> CheckResult:
    return CheckResult(
        check_name=name, triggered=triggered, severity=severity,
        evidence={"writes_outside_allowed": ["/etc/passwd"]},
    )


# ---------------------------------------------------------------------------
# Severity gate
# ---------------------------------------------------------------------------


def test_root_cause_skipped_below_threshold():
    llm = MockLLM()
    mcp = MockMCP(seed=0, verbose=False)
    locator = RootCauseLocator(llm, mcp, cfg=RootCauseConfig(severity_threshold="high"))
    result = locator.locate(
        zone_id="SBX-FS", severity="medium",
        minimal_transcript=_transcript(),
        evidence=[_check()],
    )
    assert result.skipped is True
    assert result.candidate_fix_sites == []


# ---------------------------------------------------------------------------
# Happy path — high-confidence parse
# ---------------------------------------------------------------------------


def test_root_cause_parses_candidates_above_threshold():
    llm = MockLLM()
    llm.queue(json.dumps([
        {"trace": "attacker → fs.write → policy bypass at file.ts:120"},
        {
            "file": "src/commands/sandbox/create.ts",
            "function": "createSandbox",
            "line_range": "L120-L168",
            "explanation": "Path is not canonicalized before allowed_paths check",
            "confidence": 0.85,
        },
        {
            "file": "src/lib/inference/router.ts",
            "function": "routeInference",
            "line_range": "L42-L98",
            "explanation": "Tangentially related",
            "confidence": 0.45,
        },
    ]))
    mcp = MockMCP(seed=0, verbose=False)
    locator = RootCauseLocator(llm, mcp)
    result = locator.locate(
        zone_id="SBX-FS", severity="critical",
        minimal_transcript=_transcript(),
        evidence=[_check()],
    )
    assert result.skipped is False
    assert result.root_cause_confidence >= 0.85
    assert len(result.candidate_fix_sites) == 2
    # The lower-confidence one is marked speculative.
    assert any(s.confidence < 0.5 and s.explanation.startswith("(speculative)")
                for s in result.candidate_fix_sites)
    assert "create.ts" in result.execution_trace or result.execution_trace


# ---------------------------------------------------------------------------
# Hallucination floor — emits 'undetermined' when nothing meets threshold
# ---------------------------------------------------------------------------


def test_root_cause_emits_undetermined_when_below_floor():
    llm = MockLLM()
    llm.queue(json.dumps([
        {"file": "src/x.ts", "function": "f", "line_range": "L1-L10",
          "explanation": "guess", "confidence": 0.2},
    ]))
    mcp = MockMCP(seed=0, verbose=False)
    locator = RootCauseLocator(llm, mcp, cfg=RootCauseConfig(min_confidence=0.3))
    result = locator.locate(
        zone_id="SBX-FS", severity="critical",
        minimal_transcript=_transcript(),
        evidence=[_check()],
    )
    assert result.root_cause_confidence == 0.0
    [site] = result.candidate_fix_sites
    assert site.file == "(unknown)"


def test_root_cause_handles_unparseable_llm():
    llm = MockLLM()
    llm.queue("not json at all")
    mcp = MockMCP(seed=0, verbose=False)
    locator = RootCauseLocator(llm, mcp)
    result = locator.locate(
        zone_id="SBX-FS", severity="critical",
        minimal_transcript=_transcript(),
        evidence=[_check()],
    )
    assert result.root_cause_confidence == 0.0
    assert "JSON" in result.notes


def test_root_cause_query_includes_evidence_signals():
    """The search query should mention check names + key evidence fields."""
    captured: dict[str, str] = {}

    class CapturingMCP(MockMCP):
        def search_codebase(self, query, top_k):
            captured["query"] = query
            return super().search_codebase(query, top_k)

    llm = MockLLM()
    llm.queue("[]")  # empty list → undetermined, but we only care about the query
    mcp = CapturingMCP(seed=0, verbose=False)
    locator = RootCauseLocator(llm, mcp)
    locator.locate(
        zone_id="SBX-FS", severity="critical",
        zone_description="Sandbox filesystem boundary",
        minimal_transcript=_transcript(),
        evidence=[_check()],
    )
    assert "SBX-FS" in captured["query"]
    assert "filesystem_breach" in captured["query"]
