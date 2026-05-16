"""Patch generator tests."""

from __future__ import annotations

import json

from infra.mock_mcp import MockMCP
from interfaces.llm import MockLLM
from interfaces.types import FixSite, ReproPackage

from blue_team.patch_generator import (
    PatchGenerator,
    PatchGeneratorConfig,
    _looks_like_diff,
)
from blue_team.triage import FixTask


def _package(zone="SBX-FS") -> ReproPackage:
    return ReproPackage(
        package_id="PKG-1", finding_id="FND-1", vuln_id="MC-2026-0001",
        title="Symlink escape via /tmp", severity="critical",
        repro_rate=1.0, minimal_steps=[],
        affected_zone=zone,
        affected_paths=[FixSite(
            file="src/sandbox/create.ts", function="createSandbox",
            line_range="L120-L168", explanation="canonicalize",
            confidence=0.85,
        )],
        ideas_used=["IDEA-1"], transcripts={}, suggested_mitigations=[],
        repro_document_md="(doc)",
        cold_verified=True, ready_for_blue=True,
        blue_team_status="queued", created_at="t",
    )


def _task(severity="critical") -> FixTask:
    p = _package()
    p.severity = severity
    return FixTask(
        task_id="FT-001", packages=[p], severity=severity, score=1.0,
        recommended_approach="Canonicalize paths",
    )


_GOOD_DIFF = (
    "--- a/src/sandbox/create.ts\n"
    "+++ b/src/sandbox/create.ts\n"
    "@@ -120,3 +120,4 @@\n"
    " function createSandbox(policy) {\n"
    "+  const canonical = path.resolve(policy.root);\n"
    "   return openshell.create({ resolved: canonical });\n"
    " }\n"
)


# ---------------------------------------------------------------------------
# Diff sanity check
# ---------------------------------------------------------------------------


def test_looks_like_diff_accepts_valid():
    assert _looks_like_diff(_GOOD_DIFF) is True


def test_looks_like_diff_rejects_prose():
    assert _looks_like_diff("just add canonicalization") is False
    assert _looks_like_diff("") is False
    assert _looks_like_diff("@@ but no file headers @@") is False


# ---------------------------------------------------------------------------
# Happy path — critical severity → multiple alts
# ---------------------------------------------------------------------------


def test_patch_generator_emits_multiple_alts_for_high_severity():
    llm = MockLLM()
    llm.queue(json.dumps([
        {"label": "Canonicalize", "invasiveness": "low",
          "diff": _GOOD_DIFF,
          "explanation": "resolve symlinks", "side_effects": "none"},
        {"label": "Reject symlinks entirely", "invasiveness": "medium",
          "diff": _GOOD_DIFF.replace("create.ts", "policy.ts"),
          "explanation": "deny all symlinks", "side_effects": "may break shortcuts"},
        {"label": "Rewrite policy engine", "invasiveness": "high",
          "diff": _GOOD_DIFF.replace("create.ts", "engine.ts"),
          "explanation": "redesign", "side_effects": "deep"},
    ]))
    mcp = MockMCP(seed=0, verbose=False)
    gen = PatchGenerator(llm, mcp, cfg=PatchGeneratorConfig(high_severity_alt_count=3))
    candidates = gen.generate_for_task(_task("critical"))
    assert len(candidates) == 3
    # Ordered least → most invasive
    assert [c.invasiveness for c in candidates] == ["low", "medium", "high"]
    assert all(c.diff for c in candidates)
    assert candidates[0].vuln_ids == ["MC-2026-0001"]
    assert candidates[0].zone_id == "SBX-FS"


def test_patch_generator_carries_expected_tests_and_confidence():
    """Spec C5: each candidate must include expected tests + confidence."""
    llm = MockLLM()
    llm.queue(json.dumps([
        {"label": "Canonicalize", "invasiveness": "low", "diff": _GOOD_DIFF,
          "explanation": "resolve symlinks", "side_effects": "none",
          "expected_tests": ["symlink escape blocked",
                              "normal write still works"],
          "confidence": 0.8},
    ]))
    mcp = MockMCP(seed=0, verbose=False)
    gen = PatchGenerator(llm, mcp)
    [c] = gen.generate_for_task(_task("low"))
    assert c.expected_tests == [
        "symlink escape blocked", "normal write still works"]
    assert c.confidence == 0.8


def test_patch_generator_defaults_missing_expected_tests_and_confidence():
    llm = MockLLM()
    llm.queue(json.dumps([
        {"label": "x", "invasiveness": "low", "diff": _GOOD_DIFF,
          "explanation": "x", "side_effects": "x"},
    ]))
    gen = PatchGenerator(llm, MockMCP(seed=0, verbose=False))
    [c] = gen.generate_for_task(_task("low"))
    assert c.expected_tests == []
    assert 0.0 <= c.confidence <= 1.0


def test_patch_generator_one_alt_for_low_severity():
    llm = MockLLM()
    llm.queue(json.dumps([
        {"label": "Add log", "invasiveness": "low",
          "diff": _GOOD_DIFF, "explanation": "log", "side_effects": "none"},
    ]))
    mcp = MockMCP(seed=0, verbose=False)
    gen = PatchGenerator(llm, mcp)
    candidates = gen.generate_for_task(_task("low"))
    assert len(candidates) == 1


# ---------------------------------------------------------------------------
# Robustness — drops malformed diffs
# ---------------------------------------------------------------------------


def test_patch_generator_drops_candidates_without_diff():
    llm = MockLLM()
    llm.queue(json.dumps([
        {"label": "no diff", "invasiveness": "low", "diff": "just text",
          "explanation": "ignore me", "side_effects": ""},
        {"label": "good", "invasiveness": "low", "diff": _GOOD_DIFF,
          "explanation": "real", "side_effects": "none"},
    ]))
    mcp = MockMCP(seed=0, verbose=False)
    gen = PatchGenerator(llm, mcp)
    candidates = gen.generate_for_task(_task())
    assert len(candidates) == 1
    assert candidates[0].approach == "good"


def test_patch_generator_handles_unparseable_response():
    llm = MockLLM()
    llm.queue("definitely not json")
    mcp = MockMCP(seed=0, verbose=False)
    gen = PatchGenerator(llm, mcp)
    assert gen.generate_for_task(_task()) == []


def test_patch_generator_handles_wrapping_object():
    llm = MockLLM()
    llm.queue(json.dumps({
        "patches": [
            {"label": "ok", "invasiveness": "low", "diff": _GOOD_DIFF,
              "explanation": "x", "side_effects": "x"},
        ],
    }))
    mcp = MockMCP(seed=0, verbose=False)
    gen = PatchGenerator(llm, mcp)
    candidates = gen.generate_for_task(_task())
    assert len(candidates) == 1
