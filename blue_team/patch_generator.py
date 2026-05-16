"""Patch generator — Deliverable 6.

Produces candidate code patches (in unified-diff format) for each fix task
from the triage agent. For severity ≥ high, generates 2-3 alternatives
ranked by invasiveness (least invasive first). Does NOT auto-apply — that's
the patch verifier's job (Deliverable 8).

The model is asked for STRUCTURED JSON only — no raw diffs in prose. Each
candidate carries:
- label (short approach name)
- invasiveness ("low" | "medium" | "high")
- diff (unified diff string)
- explanation (why this works)
- side_effects (what this might also change)

We validate the diff loosely (must contain at least one `@@` hunk header
and one file marker). Patches that don't parse are dropped — we never feed
malformed diffs into the verifier.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

from interfaces.llm import LLMClient, LLMMessage, extract_json
from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import CodeChunk, PatchCandidate

from blue_team._common import SEVERITY_ORDER, random_id
from blue_team.triage import FixTask

LOG = logging.getLogger("monkeyclaw.blue.patch_gen")


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------


_PATCH_SYSTEM_TEMPLATE = """\
You are a senior security engineer writing defensive patches for the
NemoClaw codebase. You will be given:

- A vulnerability description (zone, severity, transcript excerpt,
  triggered checks, suggested mitigations).
- One or more candidate fix sites with file paths and source snippets.
- (Optional) recommended approach copy from the triage agent.

Your task:
1. Propose 1-__N_ALT__ concrete patches in **unified diff format**.
2. Each patch must be self-contained — produce a complete `diff` block
   that could be fed into `git apply`.
3. Order patches from LEAST to MOST invasive.
4. For severity >= high, you MUST produce at least 2 alternatives.

Each alternative must include:
- `label`: short approach name (≤ 8 words).
- `invasiveness`: one of "low", "medium", "high".
- `diff`: unified diff string with `--- a/...`, `+++ b/...`, and `@@` hunks.
- `explanation`: one paragraph — why this patch eliminates the
   vulnerability.
- `side_effects`: one paragraph — what legitimate behavior changes, what
   downstream systems might be affected, performance impact if any.
- `expected_tests`: a JSON array of short strings naming the test
   scenarios this patch should satisfy (the positive regression that
   should now pass, the functionality that must still work, any policy
   /telemetry assertion).
- `confidence`: a number in [0, 1] — your confidence that this patch
   eliminates the vulnerability without regressions.

Output JSON only, no prose, no fences:

[
  {
    "label": "...",
    "invasiveness": "low",
    "diff": "--- a/path ...",
    "explanation": "...",
    "side_effects": "...",
    "expected_tests": ["...", "..."],
    "confidence": 0.0
  }
]

Do not auto-apply patches. Do not include any text outside the JSON array.
"""


def _render_system(n_alt: int) -> str:
    return _PATCH_SYSTEM_TEMPLATE.replace("__N_ALT__", str(n_alt))


# Loose validators — we accept dirty diffs (we're testing the SHAPE, not
# correctness; the verifier executes the regression test, not `git apply`).
_DIFF_HUNK_RE = re.compile(r"^@@\s+-\d+", re.MULTILINE)
_DIFF_FILE_RE = re.compile(r"^(?:diff --git|---|\+\+\+)\s+\S", re.MULTILINE)


def _looks_like_diff(text: str) -> bool:
    if not text:
        return False
    return bool(_DIFF_HUNK_RE.search(text) and _DIFF_FILE_RE.search(text))


def _coerce_expected_tests(value: object) -> list[str]:
    """Normalize the model's `expected_tests` field into a list[str]."""
    if isinstance(value, list):
        return [str(v).strip()[:300] for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()[:300]]
    return []


def _coerce_confidence(value: object) -> float:
    """Clamp the model's `confidence` field into [0.0, 1.0]."""
    try:
        c = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(c, 1.0))


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class PatchGeneratorConfig:
    high_severity_alt_count: int = 3
    low_severity_alt_count: int = 1
    top_k_extra_code: int = 4
    max_tokens: int = 3000
    temperature: float = 0.2

    @classmethod
    def from_blue_team_cfg(cls, blue_cfg) -> "PatchGeneratorConfig":
        return cls(
            high_severity_alt_count=getattr(blue_cfg, "high_severity_alt_count", 3),
        )


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class PatchGenerator:
    def __init__(
        self,
        llm: LLMClient,
        mcp: MonkeyClawMCP,
        *,
        cfg: PatchGeneratorConfig | None = None,
    ) -> None:
        self.llm = llm
        self.mcp = mcp
        self.cfg = cfg or PatchGeneratorConfig()

    # ------------------------------------------------------------------
    def generate_for_task(self, task: FixTask) -> list[PatchCandidate]:
        n_alt = (
            self.cfg.high_severity_alt_count
            if SEVERITY_ORDER.get(task.severity, 0) >= SEVERITY_ORDER["high"]
            else self.cfg.low_severity_alt_count
        )

        # Source context: per-fix-site snippets if root cause is available;
        # otherwise zone-based search.
        chunks = self._gather_source(task)
        prompt = self._build_prompt(task, chunks, n_alt)

        try:
            resp = self.llm.complete(
                messages=[LLMMessage(role="user", content=prompt)],
                system=_render_system(n_alt),
                max_tokens=self.cfg.max_tokens,
                temperature=self.cfg.temperature,
            )
        except Exception as e:  # noqa: BLE001
            LOG.warning("patch_gen LLM failed for task %s: %s", task.task_id, e)
            return []

        return self._parse_response(resp.text, task)

    # ------------------------------------------------------------------
    def _gather_source(self, task: FixTask) -> list[CodeChunk]:
        # Prefer fix sites from the root cause — those are the spots the
        # LLM most likely needs to read.
        sites = []
        for pkg in task.packages:
            if pkg.affected_paths:
                sites.extend(pkg.affected_paths)
        if sites:
            # We don't have a "fetch a specific file slice" MCP tool; use
            # search_codebase with a tight query targeting the file path.
            queries = sorted({s.file for s in sites if s.file and s.file != "(unknown)"})
            chunks: list[CodeChunk] = []
            for q in queries[:3]:
                try:
                    chunks.extend(self.mcp.search_codebase(query=q, top_k=2))
                except Exception as e:  # noqa: BLE001
                    LOG.debug("search_codebase failed for %r: %s", q, e)
            if chunks:
                return chunks[: self.cfg.top_k_extra_code]
        # Fallback: zone-based search
        zone = task.primary_package.affected_zone
        try:
            return list(self.mcp.search_codebase(query=zone, top_k=self.cfg.top_k_extra_code))
        except Exception as e:  # noqa: BLE001
            LOG.debug("zone-based search_codebase failed: %s", e)
            return []

    # ------------------------------------------------------------------
    def _build_prompt(
        self, task: FixTask, chunks: list[CodeChunk], n_alt: int
    ) -> str:
        primary = task.primary_package
        repro_excerpt = primary.repro_document_md[:4000]
        sites_block = self._render_sites(task)
        chunks_block = self._render_chunks(chunks)
        mitigation_block = "\n".join(f"- {m}" for m in primary.suggested_mitigations) or "(none)"
        return (
            f"# Fix Task\n"
            f"- task_id: {task.task_id}\n"
            f"- severity: {task.severity}\n"
            f"- vuln_ids: {', '.join(task.vuln_ids)}\n"
            f"- zone: {primary.affected_zone}\n"
            f"- recommended approach: {task.recommended_approach}\n\n"
            f"# Repro Document (excerpt)\n{repro_excerpt}\n\n"
            f"# Candidate Fix Sites (from root cause)\n{sites_block}\n\n"
            f"# Source Files\n{chunks_block}\n\n"
            f"# Suggested Mitigations\n{mitigation_block}\n\n"
            f"Produce {n_alt} patch alternative(s) ranked least to most "
            f"invasive. Output JSON only."
        )

    @staticmethod
    def _render_sites(task: FixTask) -> str:
        sites: list[str] = []
        for pkg in task.packages:
            if not pkg.affected_paths:
                continue
            for s in pkg.affected_paths:
                if s.file == "(unknown)":
                    continue
                sites.append(
                    f"- `{s.file}`{(':' + s.line_range) if s.line_range else ''}"
                    f"{' — `' + s.function + '`' if s.function else ''}"
                    f" (confidence {s.confidence:.2f}): {s.explanation[:300]}"
                )
        return "\n".join(sites) or "(no root-cause sites available)"

    @staticmethod
    def _render_chunks(chunks: list[CodeChunk]) -> str:
        if not chunks:
            return "(no source snippets retrieved)"
        parts = []
        for c in chunks:
            parts.append(
                f"## {c.file_path}:{c.line_range}"
                f"{' — ' + c.function_name if c.function_name else ''}"
                f" ({c.language})\n"
                f"```{c.language}\n{c.content.strip()[:1500]}\n```"
            )
        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    def _parse_response(self, raw: str, task: FixTask) -> list[PatchCandidate]:
        try:
            data = extract_json(raw)
        except ValueError:
            LOG.warning("patch_gen: unparseable JSON for task %s", task.task_id)
            return []
        if not isinstance(data, list):
            if isinstance(data, dict) and isinstance(data.get("patches"), list):
                data = data["patches"]
            else:
                return []

        candidates: list[PatchCandidate] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            diff = str(entry.get("diff", "")).strip()
            if not _looks_like_diff(diff):
                LOG.info("patch_gen: dropping candidate without a real diff "
                          "(task=%s label=%r)", task.task_id, entry.get("label"))
                continue
            invasiveness = str(entry.get("invasiveness", "medium")).lower()
            if invasiveness not in {"low", "medium", "high"}:
                invasiveness = "medium"
            candidates.append(PatchCandidate(
                patch_id=random_id("PCH"),
                vuln_ids=list(task.vuln_ids),
                zone_id=task.primary_package.affected_zone,
                approach=str(entry.get("label", ""))[:200] or "(unlabeled)",
                invasiveness=invasiveness,
                diff=diff,
                explanation=str(entry.get("explanation", ""))[:4000],
                side_effects=str(entry.get("side_effects", ""))[:2000],
                status="proposed",
                expected_tests=_coerce_expected_tests(
                    entry.get("expected_tests")),
                confidence=_coerce_confidence(entry.get("confidence")),
            ))

        # Sort: low → medium → high invasiveness (spec wants least invasive
        # tried first by the verifier).
        order = {"low": 0, "medium": 1, "high": 2}
        candidates.sort(key=lambda c: order.get(c.invasiveness, 99))
        return candidates


__all__ = [
    "PatchGenerator",
    "PatchGeneratorConfig",
]
