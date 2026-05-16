"""Argyph code-context adapter — optional backend for `search_codebase`.

Argyph (github.com/ezzy1630/Argyph) is a read-only Rust MCP server: a
tree-sitter symbol graph plus hybrid BM25+vector search. This adapter shells
out to the `argyph` CLI; when the binary is absent, callers fall back to the
Python indexer.

CLI status (Argyph v0.1.0): the `index` and `search` subcommands are stubbed
in the shipped milestone — they print "<cmd>: not implemented in this
milestone" and exit 0. Only `status` returns real data. This adapter therefore
targets Argyph's *documented* `search_code` MCP response shape — a JSON object
with a `hits` array (see Argyph docs/tools-reference.md) — so that it works
unchanged once the CLI gains a real `search` implementation. Against today's
stub output `_parse_search` simply yields an empty list, which is the correct
graceful-degradation behaviour.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess

from interfaces.types import CodeChunk

LOG = logging.getLogger("monkeyclaw.argyph")

_FALLBACK_BINARY = "/Volumes/Neural/Argyph/target/release/argyph"

# Map common file extensions to Argyph-style language names, used when the
# search payload omits an explicit `language` field.
_EXT_LANGUAGE = {
    ".py": "python",
    ".rs": "rust",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".go": "go",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".rb": "ruby",
    ".sh": "shell",
}


def argyph_binary(configured: str | None = None) -> str | None:
    """Resolve the argyph binary: explicit config > PATH > known build path."""
    if configured:
        return configured
    found = shutil.which("argyph")
    if found:
        return found
    if os.path.exists(_FALLBACK_BINARY):
        return _FALLBACK_BINARY
    return None


def _language_for(path: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    _, ext = os.path.splitext(path)
    return _EXT_LANGUAGE.get(ext.lower(), "unknown")


def _line_range(raw: object) -> str:
    """Normalise an Argyph line range to CodeChunk's "L<start>-L<end>" string."""
    if isinstance(raw, (list, tuple)) and len(raw) >= 2:
        return f"L{raw[0]}-L{raw[1]}"
    return ""


class ArgyphIndex:
    """Thin wrapper over the `argyph` CLI."""

    def __init__(self, binary: str | None = None, timeout_s: int = 120) -> None:
        self.binary = binary or argyph_binary()
        self.timeout_s = timeout_s

    @property
    def available(self) -> bool:
        return bool(self.binary and os.path.exists(self.binary))

    def index(self, repo_path: str) -> None:
        """Build/refresh the Argyph index for `repo_path`.

        `argyph index` indexes the current working directory and takes no
        arguments, so the repo path is passed via `cwd`.
        """
        if not self.available:
            raise RuntimeError("argyph binary not available")
        self._run(["index"], cwd=repo_path)

    def search(self, query: str, top_k: int, repo_path: str) -> list[CodeChunk]:
        """Semantic search; returns CodeChunk list. Empty list on any failure."""
        if not self.available:
            return []
        try:
            out = self._run(["search", query], cwd=repo_path)
        except Exception:  # noqa: BLE001 - search must degrade, not crash
            LOG.exception("argyph search failed")
            return []
        return self._parse_search(out, top_k)

    def _run(self, args: list[str], cwd: str) -> str:
        proc = subprocess.run(
            [self.binary, *args],
            capture_output=True,
            text=True,
            timeout=self.timeout_s,
            cwd=cwd,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"argyph {args[0]} exited {proc.returncode}: "
                f"{proc.stderr.strip()[:300]}"
            )
        return proc.stdout

    @staticmethod
    def _parse_search(output: str, top_k: int) -> list[CodeChunk]:
        """Map argyph search output to a list of CodeChunk.

        Accepts Argyph's documented `search_code` response — a JSON object with
        a `hits` array (preferred) or `spans` array — and also tolerates a
        bare JSON array or newline-delimited JSON objects. Any non-JSON output
        (e.g. the current CLI stub) or malformed entry is skipped, never raised.
        """
        text = (output or "").strip()
        if not text:
            return []

        records: list[dict] = []
        # Try a single JSON document first (object or array).
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            doc = None

        if isinstance(doc, dict):
            hits = doc.get("hits")
            if not isinstance(hits, list):
                hits = doc.get("spans")
            if isinstance(hits, list):
                records = [h for h in hits if isinstance(h, dict)]
        elif isinstance(doc, list):
            records = [h for h in doc if isinstance(h, dict)]
        else:
            # Fall back to JSON-lines: one object per line.
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if isinstance(obj, dict):
                    records.append(obj)

        chunks: list[CodeChunk] = []
        for rec in records:
            file_path = rec.get("file") or rec.get("file_path") or rec.get("path")
            if not file_path:
                continue
            content = (
                rec.get("chunk_text")
                or rec.get("text")
                or rec.get("content")
                or ""
            )
            raw_range = rec.get("line_range")
            if raw_range is None and "start_line" in rec and "end_line" in rec:
                raw_range = [rec.get("start_line"), rec.get("end_line")]
            try:
                score = float(rec.get("score", 0.0) or 0.0)
            except (TypeError, ValueError):
                score = 0.0
            chunks.append(
                CodeChunk(
                    file_path=str(file_path),
                    function_name=rec.get("symbol") or rec.get("function_name"),
                    line_range=_line_range(raw_range),
                    content=str(content),
                    language=_language_for(str(file_path), rec.get("language")),
                    score=score,
                )
            )
            if len(chunks) >= top_k:
                break
        return chunks
