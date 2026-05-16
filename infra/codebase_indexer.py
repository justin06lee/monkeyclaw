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
import re
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


# ---------------------------------------------------------------------------
# Symbol/call-graph extraction — real-root-cause spec §7
#
# Uses tree_sitter_language_pack's structure analysis (`process`) to recover
# functions/methods/classes with their spans. Call edges are extracted with a
# language-agnostic identifier-before-paren scan over each symbol body — robust
# and dependency-free. No Argyph dependency.
# ---------------------------------------------------------------------------

# Identifier immediately followed by an opening paren — a call site.
_CALL_RE = re.compile(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*\(")

# Keywords that look like calls but are not.
_CALL_KEYWORDS = {
    "if", "for", "while", "return", "with", "switch", "catch", "print",
    "and", "or", "not", "in", "is", "elif", "else", "def", "class",
    "lambda", "yield", "await", "assert", "del", "raise", "except",
    "function", "new", "typeof", "instanceof", "len", "range", "str",
    "int", "float", "list", "dict", "set", "tuple", "bool",
}

# Span kinds that count as a definable symbol.
_SYMBOL_KINDS = {"Function", "Method", "Class"}


def _structure_symbols(text: str, lang: str):
    """Yield (name, kind, line_start, line_end, body_text) for each top-level
    and nested function/method/class in `text`. Empty when the parser declines.
    """
    try:
        from tree_sitter_language_pack import ProcessConfig, process
    except Exception:  # noqa: BLE001
        return
    try:
        result = process(
            source=text,
            config=ProcessConfig(language=lang, structure=True),
        )
    except Exception:  # noqa: BLE001
        return
    src = text.encode("utf-8", errors="ignore")

    def _emit(items):
        for it in items:
            kind = str(getattr(it, "kind", ""))
            name = getattr(it, "name", None)
            span = getattr(it, "span", None)
            if name and kind in _SYMBOL_KINDS and span is not None:
                body_span = getattr(it, "body_span", None) or span
                body = src[body_span.start_byte:body_span.end_byte].decode(
                    "utf-8", errors="ignore")
                yield (name, kind.lower(), span.start_line, span.end_line,
                       body)
            yield from _emit(getattr(it, "children", []) or [])

    yield from _emit(result.structure)


def _extract_call_names(body: str) -> list[str]:
    """Best-effort callee names referenced inside a symbol body."""
    names: list[str] = []
    for m in _CALL_RE.finditer(body):
        name = m.group(1)
        if name in _CALL_KEYWORDS:
            continue
        names.append(name)
    return names


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


def index_symbol_graph(db: Database, *, root: Path) -> dict:
    """Second pass: extract a symbol/call graph from the indexed source.

    Runs after `index_codebase`. Re-parses each tree-sitter-supported source
    file under `root`, records every function/method/class in `code_symbols`
    (joined to the `code_chunks` row covering its file), and writes one
    `code_edges` row per referenced name (resolved name-based within the
    indexed repo, else kept unresolved). Gated on file_path so a re-index is
    a no-op.
    """
    # One representative chunk_id per file, so code_symbols.chunk_id is set.
    chunk_for_file: dict[str, str] = {}
    for r in db.fetchall(
            "SELECT chunk_id, file_path FROM code_chunks "
            "ORDER BY line_start ASC"):
        chunk_for_file.setdefault(r["file_path"], r["chunk_id"])

    # Files already in the symbol graph — skip them (re-index no-op).
    done_files = {r["file_path"] for r in db.fetchall(
        "SELECT DISTINCT file_path FROM code_symbols")}

    new_symbols = 0
    new_edges = 0
    name_index: dict[str, str] = {}  # symbol_name -> symbol_id (first wins)
    pending: list[tuple[str, str, list[str]]] = []  # (symbol_id, name, refs)

    with db.lock():
        for path in _iter_files(root):
            lang = SUPPORTED_EXTS.get(path.suffix.lower(), "text")
            if lang not in _FN_NODE_TYPES:
                continue
            rel = path.relative_to(root).as_posix()
            if rel in done_files:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            chunk_id = chunk_for_file.get(rel, f"FILE:{rel}")
            for name, kind, ls, le, body in _structure_symbols(text, lang):
                sid = f"SYM-{uuid.uuid4().hex[:14]}"
                db.execute(
                    "INSERT OR REPLACE INTO code_symbols(symbol_id, chunk_id, "
                    "file_path, symbol_name, symbol_kind, line_start, "
                    "line_end, language, indexed_at) "
                    "VALUES (?,?,?,?,?,?,?,?,datetime('now'))",
                    (sid, chunk_id, rel, name, kind, ls, le, lang),
                )
                new_symbols += 1
                name_index.setdefault(name, sid)
                refs = _extract_call_names(body)
                if refs:
                    pending.append((sid, name, refs))

        for sid, owner_name, refs in pending:
            for name in refs:
                if name == owner_name:
                    continue  # skip self-recursion noise
                dst = name_index.get(name)
                eid = f"EDG-{uuid.uuid4().hex[:14]}"
                db.execute(
                    "INSERT INTO code_edges(edge_id, src_symbol_id, "
                    "dst_symbol_id, dst_name, edge_kind, resolved, indexed_at) "
                    "VALUES (?,?,?,?,?,?,datetime('now'))",
                    (eid, sid, dst, name, "call", 1 if dst else 0),
                )
                new_edges += 1

    LOG.info("symbol graph: %d new symbols, %d new edges", new_symbols, new_edges)
    return {"new_symbols": new_symbols, "new_edges": new_edges}


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

    # Optional Argyph backend: when configured AND a binary is available, let
    # Argyph build its own index instead of the Python tree-sitter walk. The
    # Python indexer remains the default and the fallback.
    from infra.config import load_config  # noqa: PLC0415
    cfg = load_config()
    if cfg.code_context.backend == "argyph":
        from infra.argyph_index import ArgyphIndex  # noqa: PLC0415
        argyph = ArgyphIndex(binary=cfg.code_context.argyph_binary)
        if argyph.available:
            LOG.info("code-context backend: argyph (%s)", argyph.binary)
            try:
                argyph.index(str(root))
                return 0
            except Exception as exc:
                LOG.warning("argyph indexing failed (%s); falling back to python indexer", exc)
        else:
            LOG.info("code-context backend: argyph configured but binary "
                     "unavailable; falling back to python indexer")
    else:
        LOG.info("code-context backend: python tree-sitter indexer")

    if args.limit_files > 0:
        global _iter_files  # noqa: PLW0603
        _original_iter = _iter_files
        _limit = args.limit_files

        def _iter_files(r: str, _o=_original_iter, _n=_limit) -> list:  # type: ignore[assignment]
            return _o(r)[:_n]

    summary = index_codebase(db, root)
    graph_summary = index_symbol_graph(db, root=root)
    summary["symbol_graph"] = graph_summary
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
