"""Index the NemoClaw source tree into the vector store.

For each source file we extract function/class chunks. The implementation
prefers tree-sitter where it's available (TS/JS/Python/Go/Rust), and falls
back to a heuristic chunker (top-level lines + 60-line windows) for anything
unsupported.

Outputs land in `code_chunks` + `code_chunks_vec`. Re-running with the same
content is a no-op (sha256 dedup).
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from infra.database import Database, EmbeddingModel

LOG = logging.getLogger("monkeyclaw.indexer")

SUPPORTED_EXTS = {
    ".ts": "typescript",
    ".tsx": "tsx",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".sh": "bash",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".md": "markdown",
}

EXCLUDE_DIRS = {
    "node_modules", ".git", "dist", "build", "out", "target",
    ".venv", "venv", "__pycache__", ".next", ".turbo",
    "coverage", ".cache",
}

MAX_FILE_BYTES = 250_000
CHUNK_MAX_LINES = 200
HEURISTIC_WINDOW = 60
BATCH_SIZE = 32


@dataclass
class Chunk:
    file_path: str
    function_name: str | None
    line_start: int
    line_end: int
    language: str
    content: str


def _iter_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # prune
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS and not d.startswith(".")]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() not in SUPPORTED_EXTS:
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            out.append(p)
    return out


# ---------------------------------------------------------------------------
# Tree-sitter — wrap once
# ---------------------------------------------------------------------------


_TS_PARSERS: dict[str, object] = {}


def _ts_parser(lang: str):
    """Return a tree-sitter Parser for the given language, or None if unavailable."""
    if lang in _TS_PARSERS:
        return _TS_PARSERS[lang]
    try:
        from tree_sitter_language_pack import get_parser
        parser = get_parser(lang)
    except Exception:
        parser = None
    _TS_PARSERS[lang] = parser
    return parser


_FN_NODE_TYPES = {
    "typescript": {"function_declaration", "method_definition", "class_declaration",
                    "arrow_function", "function_expression"},
    "tsx": {"function_declaration", "method_definition", "class_declaration",
             "arrow_function", "function_expression"},
    "javascript": {"function_declaration", "method_definition", "class_declaration",
                    "arrow_function", "function_expression"},
    "python": {"function_definition", "class_definition", "async_function_definition"},
    "go": {"function_declaration", "method_declaration", "type_declaration"},
    "rust": {"function_item", "impl_item", "struct_item", "enum_item"},
    "java": {"method_declaration", "class_declaration", "interface_declaration"},
}


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


def _extract_name(node, src: bytes) -> str | None:
    for c in node.children:
        if c.type in ("identifier", "property_identifier", "type_identifier", "field_identifier"):
            return src[c.start_byte:c.end_byte].decode("utf-8", errors="ignore")
    return None


def _treesitter_chunks(text: str, lang: str, file_path: str) -> list[Chunk]:
    parser = _ts_parser(lang)
    if parser is None:
        return []
    src = text.encode("utf-8", errors="ignore")
    try:
        tree = parser.parse(src)
    except Exception:
        return []
    types = _FN_NODE_TYPES.get(lang, set())
    chunks: list[Chunk] = []
    for n in _walk(tree.root_node):
        if n.type not in types:
            continue
        start_line = n.start_point[0] + 1
        end_line = n.end_point[0] + 1
        if end_line - start_line < 1:
            continue
        if end_line - start_line + 1 > CHUNK_MAX_LINES:
            # Skip giant top-level classes — heuristic chunker can window them
            continue
        body = src[n.start_byte:n.end_byte].decode("utf-8", errors="ignore")
        chunks.append(Chunk(
            file_path=file_path,
            function_name=_extract_name(n, src),
            line_start=start_line,
            line_end=end_line,
            language=lang,
            content=body,
        ))
    return chunks


def _heuristic_chunks(text: str, lang: str, file_path: str) -> list[Chunk]:
    """Window the file in fixed-line slices. Used when tree-sitter declines."""
    lines = text.splitlines()
    n = len(lines)
    if n == 0:
        return []
    chunks: list[Chunk] = []
    step = HEURISTIC_WINDOW
    for start in range(0, n, step):
        end = min(n, start + step)
        body = "\n".join(lines[start:end])
        if not body.strip():
            continue
        chunks.append(Chunk(
            file_path=file_path,
            function_name=None,
            line_start=start + 1,
            line_end=end,
            language=lang,
            content=body,
        ))
    return chunks


def _chunk_file(path: Path, root: Path) -> list[Chunk]:
    lang = SUPPORTED_EXTS.get(path.suffix.lower(), "text")
    rel = path.relative_to(root).as_posix()
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    chunks = _treesitter_chunks(text, lang, rel) if lang in _FN_NODE_TYPES else []
    if not chunks:
        chunks = _heuristic_chunks(text, lang, rel)
    return chunks


# ---------------------------------------------------------------------------
# Indexer
# ---------------------------------------------------------------------------


def index_codebase(db: Database, root: Path, embedder: EmbeddingModel | None = None,
                    progress_every: int = 200) -> dict:
    """Walk `root`, chunk every supported file, embed each chunk, upsert.

    Returns a small summary dict.
    """
    embedder = embedder or EmbeddingModel.shared()
    files = _iter_files(root)
    LOG.info("indexing %d files under %s", len(files), root)
    total_chunks = 0
    seen_hashes: set[str] = set()

    # Preload existing hashes to avoid re-embedding unchanged content.
    rows = db.fetchall("SELECT content_sha256 FROM code_chunks")
    existing = {r["content_sha256"] for r in rows}

    pending_meta: list[tuple] = []
    pending_text: list[str] = []
    pending_keys: list[str] = []

    def flush() -> None:
        nonlocal pending_meta, pending_text, pending_keys, total_chunks
        if not pending_text:
            return
        embs = embedder.encode(pending_text)
        with db.lock():
            for meta, key, emb in zip(pending_meta, pending_keys, embs, strict=True):
                db.execute(
                    "INSERT OR REPLACE INTO code_chunks(chunk_id, file_path, function_name, "
                    "line_start, line_end, language, content, content_sha256, indexed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))", meta,
                )
                db.upsert_vector("code_chunks_vec", "chunk_id", key, emb.tolist())
        total_chunks += len(pending_text)
        pending_meta = []
        pending_text = []
        pending_keys = []

    started = time.time()
    for i, path in enumerate(files):
        for ch in _chunk_file(path, root):
            sha = hashlib.sha256(ch.content.encode("utf-8")).hexdigest()
            if sha in existing or sha in seen_hashes:
                continue
            seen_hashes.add(sha)
            cid = f"CHK-{uuid.uuid4().hex[:14]}"
            pending_meta.append((cid, ch.file_path, ch.function_name, ch.line_start,
                                  ch.line_end, ch.language, ch.content, sha))
            pending_text.append(ch.content)
            pending_keys.append(cid)
            if len(pending_text) >= BATCH_SIZE:
                flush()
        if (i + 1) % progress_every == 0:
            LOG.info("indexed %d/%d files (%d chunks)", i + 1, len(files), total_chunks)
    flush()
    elapsed = time.time() - started
    LOG.info("done: %d new chunks in %.1fs", total_chunks, elapsed)
    return {"files": len(files), "new_chunks": total_chunks, "seconds": elapsed}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Index NemoClaw source into MonkeyClaw DB")
    parser.add_argument("--root", default=os.path.expanduser("~/NemoClaw"))
    parser.add_argument("--db", default="data/monkeyclaw.db")
    parser.add_argument("--limit-files", type=int, default=0,
                        help="If >0, cap the number of files indexed (smoke runs).")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    root = Path(args.root).expanduser()
    if not root.exists():
        LOG.error("root %s does not exist", root)
        return 1
    db = Database(args.db)

    if args.limit_files > 0:
        global _iter_files  # noqa: PLW0603
        _original_iter = _iter_files
        _limit = args.limit_files

        def _iter_files(r: str, _o=_original_iter, _n=_limit) -> list:  # type: ignore[assignment]
            return _o(r)[:_n]

    summary = index_codebase(db, root)
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
