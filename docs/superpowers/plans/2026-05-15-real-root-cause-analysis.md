# Real Root-Cause Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `RootCauseLocator`'s keyword-bag heuristic with a real code-graph tracer that reconstructs the executed path of an attack and ranks candidate fix sites by path proximity and graph centrality, while keeping the locator's output contract frozen.

**Architecture:** A second indexing pass over the existing `code_chunks` extracts a lightweight symbol/call graph into new `code_symbols` / `code_edges` tables. A `CodeGraph` Protocol in `interfaces/` makes the graph backend swappable; `PythonCodeGraph` reads SQLite and ships now. `blue_team/path_tracer.py` anchors triggered checks and logs onto symbols, seeds a sink via semantic search, walks shortest paths over the edge table, and emits a ranked `ExecutedPath`. `RootCauseLocator` internals are rewritten to consume that path and use the LLM only to confirm and calibrate; the `locate()` signature and `RootCauseResult` are untouched.

**Tech Stack:** Python 3.12, `uv` for env + test running, `pytest`, SQLite via `infra/database.py`, the existing migration runner (`infra/migrations.py` + `infra/migrations/`), tree-sitter via `tree_sitter_language_pack` (already a dependency), `interfaces/types.py` dataclasses, `ruff` for lint. Everything runs in mock mode with stub LLMs and local fixture repos — no NemoClaw, no `argyph` binary, zero credentials.

---

## File Structure

| File | Create/Modify | Responsibility |
|------|---------------|----------------|
| `interfaces/code_graph.py` | Create | `CodeGraph` Protocol + `CodeSymbol`, `CodeEdge`, `PathNode`, `ExecutedPath` dataclasses. |
| `interfaces/types.py` | Modify | Re-export the code-graph types and literals so `interfaces.types` stays the single import surface. |
| `interfaces/schema.sql` | Modify | Add `code_symbols`, `code_edges`, `executed_paths` (reference copy, kept in sync with the migration). |
| `interfaces/mcp_tools.py` | Modify | No new method (graph read goes direct to SQLite); add a doc note recording that decision. |
| `infra/migrations/00N_code_graph.sql` | Create | Migration adding `code_symbols`, `code_edges`, `executed_paths`; `schema_version` bump. |
| `infra/codebase_indexer.py` | Modify | `index_symbol_graph` second pass + reference-node extraction; CLI `main()` runs it. |
| `blue_team/code_graph_sqlite.py` | Create | `PythonCodeGraph` — the default `CodeGraph` backend reading `code_symbols` / `code_edges`. |
| `blue_team/path_tracer.py` | Create | `PathTracer.trace(...)` — anchor → seed → walk → rank → `ExecutedPath`; degraded fallback. |
| `blue_team/root_cause.py` | Modify | `RootCauseLocator` internals rewritten to consume `ExecutedPath`; revised prompt; confidence blend. |
| `blue_team/pipeline.py` | Modify | `Pipeline.__init__` constructs a `PathTracer` + `PythonCodeGraph` and injects them into the locator. |
| `infra/dashboard.py` | Modify | Finding-detail view shows the executed path. |
| `configs/monkeyclaw.yaml` | Modify | `repro.code_graph` block (`enabled`, `max_hops`, `path_rank_weight`, `llm_conf_weight`). |
| `interfaces/config_schema.py` | Modify | `CodeGraphConfig` dataclass nested under `ReproConfig`. |
| `test/test_root_cause_types.py` | Create | Type/contract tests for the new dataclasses + `CodeGraph` Protocol. |
| `test/test_root_cause_migration.py` | Create | Migration applies and creates the three graph tables. |
| `test/test_infra_code_graph_index.py` | Create | Symbol/edge extraction over a fixture repo with a known call chain. |
| `test/test_blue_code_graph_sqlite.py` | Create | `PythonCodeGraph.shortest_paths` / `available()` tests. |
| `test/test_blue_path_tracer.py` | Create | Tracer ranking + degraded-path tests. |
| `test/test_blue_root_cause_traced.py` | Create | `locate` draws fix sites only from the `ExecutedPath`; confidence blend; `(unknown)` fallback. |
| `test/test_blue_root_cause.py` | Modify | Extend: assert the frozen output contract is unchanged. |
| `test/test_blue_root_cause_degraded.py` | Create | With no graph the locator behaves like the keyword locator and never crashes. |
| `test/fixtures/rc_repo/` | Create | A small fixture source tree with `handler → resolve_path → policy_check`. |

---

# Phase 0 — Contracts

No behaviour yet: shared types, the `CodeGraph` Protocol, the schema migration.

## Task 1 — New interface types

**Files:**
- Create: `interfaces/code_graph.py`
- Modify: `interfaces/types.py`
- Test: `test/test_root_cause_types.py`

- [ ] Write the failing test. Create `test/test_root_cause_types.py`:
```python
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
```
- [ ] Run it, verify it fails: `uv run pytest test/test_root_cause_types.py -q` — expect `ImportError: cannot import name 'CodeSymbol'`.
- [ ] Create `interfaces/code_graph.py`:
```python
"""The code-graph contract — real-root-cause spec §6.1.

`PathTracer` is written against the `CodeGraph` Protocol so the symbol-graph
backend is swappable. `PythonCodeGraph` (blue_team/code_graph_sqlite.py) ships
first; an `ArgyphCodeGraph` may slot in later with no tracer change. No Argyph
runtime dependency is introduced by this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

SymbolKind = Literal["function", "method", "class"]
EdgeKind = Literal["call", "reference"]
GraphBackend = Literal["python", "argyph"]


@dataclass
class CodeSymbol:
    """One definition (function/method/class) extracted from a code chunk."""

    symbol_id: str
    file_path: str
    symbol_name: str
    symbol_kind: str  # SymbolKind
    line_start: int
    line_end: int
    language: str


@dataclass
class CodeEdge:
    """A directed reference from one symbol to another (resolved or not)."""

    src_symbol_id: str
    dst_symbol_id: str | None  # None when the reference is unresolved
    dst_name: str  # the referenced name — always present
    edge_kind: str  # EdgeKind
    resolved: bool


@dataclass
class PathNode:
    """One on-path symbol, with its measured rank signals."""

    symbol: CodeSymbol
    proximity: float  # 0..1 — closeness to the violation sink
    centrality: float  # 0..1 — fraction of anchor->sink paths crossing it
    evidence_touch: bool  # the symbol controls a path/syscall the attack hit
    rank_score: float  # 0..1 — the blended ranking score


@dataclass
class ExecutedPath:
    """The reconstructed executed path for one finding, ranked entry->violation."""

    nodes: list[PathNode]  # ranked, highest rank_score first
    anchors: list[CodeSymbol]
    sinks: list[CodeSymbol]
    backend: str  # GraphBackend
    degraded: bool  # true when the graph was unavailable / partial


@runtime_checkable
class CodeGraph(Protocol):
    """Read-only symbol/call graph the tracer walks."""

    def symbol_at(self, file: str, line: int) -> CodeSymbol | None:
        """The symbol whose line range contains `line` in `file`."""
        ...

    def find_symbols(self, name: str) -> list[CodeSymbol]:
        """All symbols whose `symbol_name` equals `name`."""
        ...

    def callers(self, symbol_id: str) -> list[CodeEdge]:
        """Edges whose `dst_symbol_id` is `symbol_id`."""
        ...

    def callees(self, symbol_id: str) -> list[CodeEdge]:
        """Edges whose `src_symbol_id` is `symbol_id`."""
        ...

    def shortest_paths(
        self, src: str, dst: str, max_hops: int,
    ) -> list[list[CodeEdge]]:
        """Up to a few shortest edge-paths from symbol `src` to symbol `dst`."""
        ...

    def available(self) -> bool:
        """True iff the graph has at least one symbol."""
        ...


__all__ = [
    "CodeEdge",
    "CodeGraph",
    "CodeSymbol",
    "EdgeKind",
    "ExecutedPath",
    "GraphBackend",
    "PathNode",
    "SymbolKind",
]
```
- [ ] Re-export the new names from `interfaces/types.py` so `interfaces.types` stays the single import surface. Add this block immediately before the `__all__` list:
```python
# ---------------------------------------------------------------------------
# Real root-cause analysis — code graph (real-root-cause spec §7)
# Defined in interfaces/code_graph.py; re-exported here so blue_team imports
# from one place.
# ---------------------------------------------------------------------------

from interfaces.code_graph import (  # noqa: E402
    CodeEdge,
    CodeGraph,
    CodeSymbol,
    EdgeKind,
    ExecutedPath,
    GraphBackend,
    PathNode,
    SymbolKind,
)
```
- [ ] Append the eight names (`CodeEdge`, `CodeGraph`, `CodeSymbol`, `EdgeKind`, `ExecutedPath`, `GraphBackend`, `PathNode`, `SymbolKind`) to `__all__` in `interfaces/types.py`, alphabetised within the list.
- [ ] Run the test, verify it passes: `uv run pytest test/test_root_cause_types.py -q` — expect `4 passed`.
- [ ] Run lint: `uv run ruff check interfaces/code_graph.py interfaces/types.py test/test_root_cause_types.py` — expect `All checks passed!`.
- [ ] Commit: `git add interfaces/code_graph.py interfaces/types.py test/test_root_cause_types.py && git commit -m "feat(rca): CodeGraph contract + code-graph types"`.

## Task 2 — Schema migration for the code-graph tables

**Files:**
- Create: `infra/migrations/00N_code_graph.sql`
- Modify: `interfaces/schema.sql`
- Test: `test/test_root_cause_migration.py`

- [ ] Inspect the highest existing migration number: `ls infra/migrations/`. Take the next free number (coordination rule 1 of the upgrade roadmap) and use it consistently for the file name and the `schema_version` bump below. This plan writes the file as `00N_code_graph.sql` — substitute the real number when executing.
- [ ] Write the failing test. Create `test/test_root_cause_migration.py`:
```python
"""Phase 0 — code-graph migration creates the three tables."""

from __future__ import annotations

from infra.database import Database

GRAPH_TABLES = {"code_symbols", "code_edges", "executed_paths"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_graph_tables(db: Database):
    assert GRAPH_TABLES <= _table_names(db)


def test_code_symbols_has_location_columns(db: Database):
    cols = {r["name"] for r in db.fetchall("PRAGMA table_info(code_symbols)")}
    assert {"symbol_id", "chunk_id", "file_path", "symbol_name",
            "symbol_kind", "line_start", "line_end", "language"} <= cols


def test_code_edges_records_resolution(db: Database):
    cols = {r["name"] for r in db.fetchall("PRAGMA table_info(code_edges)")}
    assert {"src_symbol_id", "dst_symbol_id", "dst_name",
            "edge_kind", "resolved"} <= cols


def test_executed_paths_records_backend_and_degraded(db: Database):
    cols = {r["name"] for r in db.fetchall("PRAGMA table_info(executed_paths)")}
    assert {"path_id", "finding_id", "zone_id", "anchor_symbols",
            "sink_symbols", "node_count", "backend", "degraded"} <= cols
```
- [ ] Run it, verify it fails: `uv run pytest test/test_root_cause_migration.py -q` — expect `AssertionError` (tables absent).
- [ ] Create `infra/migrations/00N_code_graph.sql` (substitute the real number):
```sql
-- Migration 00N — code-graph tables (real-root-cause spec §7).
-- Forward-only, idempotent. Applied by infra/migrations.py on Database open.

BEGIN;

CREATE TABLE IF NOT EXISTS code_symbols (
    symbol_id    TEXT PRIMARY KEY,
    chunk_id     TEXT NOT NULL,
    file_path    TEXT NOT NULL,
    symbol_name  TEXT NOT NULL,
    symbol_kind  TEXT NOT NULL,            -- function|method|class
    line_start   INTEGER NOT NULL,
    line_end     INTEGER NOT NULL,
    language     TEXT NOT NULL,
    indexed_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_code_symbols_name
    ON code_symbols(symbol_name);
CREATE INDEX IF NOT EXISTS idx_code_symbols_file
    ON code_symbols(file_path, line_start);

CREATE TABLE IF NOT EXISTS code_edges (
    edge_id        TEXT PRIMARY KEY,
    src_symbol_id  TEXT NOT NULL,
    dst_symbol_id  TEXT,                   -- NULL for an unresolved reference
    dst_name       TEXT NOT NULL,
    edge_kind      TEXT NOT NULL,          -- call|reference
    resolved       INTEGER NOT NULL DEFAULT 0,
    indexed_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_code_edges_src ON code_edges(src_symbol_id);
CREATE INDEX IF NOT EXISTS idx_code_edges_dst ON code_edges(dst_symbol_id);

CREATE TABLE IF NOT EXISTS executed_paths (
    path_id        TEXT PRIMARY KEY,
    finding_id     TEXT NOT NULL,
    zone_id        TEXT NOT NULL,
    anchor_symbols TEXT NOT NULL DEFAULT '[]',  -- JSON list of symbol ids
    sink_symbols   TEXT NOT NULL DEFAULT '[]',  -- JSON list of symbol ids
    node_count     INTEGER NOT NULL DEFAULT 0,
    backend        TEXT NOT NULL DEFAULT 'python',  -- python|argyph
    degraded       INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_executed_paths_finding
    ON executed_paths(finding_id);

COMMIT;
```
- [ ] Mirror the same three `CREATE TABLE` / `CREATE INDEX` statements into `interfaces/schema.sql` (append after the `code_chunks` block, before any vector tables) so the bootstrap-from-empty path and the migrated path agree. Drop the `BEGIN;`/`COMMIT;` — `schema.sql` is run as one script.
- [ ] Bump `schema_version` to the migration number in whatever location the migration runner records it (the version constant the runner reads — confirm with `grep -rn schema_version infra/`).
- [ ] Run the test, verify it passes: `uv run pytest test/test_root_cause_migration.py -q` — expect `4 passed`.
- [ ] Run the migration-runner test to confirm the new migration is discovered and recorded: `uv run pytest test/ -k migration -q` — expect all green.
- [ ] Run lint: `uv run ruff check test/test_root_cause_migration.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/migrations/ interfaces/schema.sql test/test_root_cause_migration.py && git commit -m "feat(rca): migration — code-graph tables"`.

---

# Phase 1 — Symbol graph

The symbol/reference extraction pass and the `PythonCodeGraph` backend.

## Task 3 — Fixture repo with a known call chain

**Files:**
- Create: `test/fixtures/rc_repo/handler.py`
- Create: `test/fixtures/rc_repo/policy.py`
- Create: `test/fixtures/rc_repo/unrelated.py`

- [ ] Create `test/fixtures/rc_repo/handler.py` — the entry symbol that calls down a known chain:
```python
"""Fixture: attack entry point. Calls resolve_path, which calls policy_check."""


def resolve_path(raw_path):
    """Normalise a requested path before any policy decision."""
    return raw_path.strip().replace("..", "")


def policy_check(resolved_path):
    """The control: decide whether a resolved path may be written."""
    return not resolved_path.startswith("/etc")


def handler(request):
    """Attack entry: handle a write request from the agent."""
    resolved = resolve_path(request["path"])
    if policy_check(resolved):
        return write_file(resolved, request["body"])
    return missing_helper(resolved)
```
- [ ] Create `test/fixtures/rc_repo/policy.py` — a defined sink symbol the handler references:
```python
"""Fixture: the write sink the handler calls."""


def write_file(path, body):
    """The boundary-crossing sink: actually performs the write."""
    return {"written": path, "bytes": len(body)}
```
- [ ] Create `test/fixtures/rc_repo/unrelated.py` — an off-path symbol that must rank below on-path symbols:
```python
"""Fixture: a symbol the attack never traverses."""


def format_banner(text):
    """Cosmetic helper — never on any attack path."""
    return f"=== {text} ==="
```
- [ ] Note: `handler` references `missing_helper`, which is defined nowhere in the fixture — this is the deliberate unresolved-reference case the index test asserts.
- [ ] Run lint: `uv run ruff check test/fixtures/rc_repo/` — expect `All checks passed!`.
- [ ] Commit: `git add test/fixtures/rc_repo/ && git commit -m "test(rca): fixture repo with a known call chain"`.

## Task 4 — Symbol/reference extraction pass in the indexer

**Files:**
- Modify: `infra/codebase_indexer.py`
- Test: `test/test_infra_code_graph_index.py`

- [ ] Write the failing test. Create `test/test_infra_code_graph_index.py`:
```python
"""Phase 1 — index_symbol_graph extracts symbols and call edges."""

from __future__ import annotations

from pathlib import Path

from infra.codebase_indexer import index_codebase, index_symbol_graph
from infra.database import Database

FIXTURE = Path(__file__).parent / "fixtures" / "rc_repo"


def _index(db: Database) -> dict:
    index_codebase(db, FIXTURE)
    return index_symbol_graph(db, root=FIXTURE)


def test_symbols_cover_every_function(db: Database):
    _index(db)
    names = {r["symbol_name"] for r in db.fetchall(
        "SELECT symbol_name FROM code_symbols")}
    assert {"handler", "resolve_path", "policy_check",
            "write_file", "format_banner"} <= names


def test_call_edge_handler_to_resolve_path(db: Database):
    _index(db)
    rows = db.fetchall(
        "SELECT e.dst_name, e.resolved FROM code_edges e "
        "JOIN code_symbols s ON s.symbol_id = e.src_symbol_id "
        "WHERE s.symbol_name = 'handler'")
    dst_names = {r["dst_name"] for r in rows}
    assert {"resolve_path", "policy_check", "write_file"} <= dst_names


def test_resolved_edge_has_dst_symbol_id(db: Database):
    _index(db)
    rows = db.fetchall(
        "SELECT e.dst_symbol_id FROM code_edges e "
        "JOIN code_symbols s ON s.symbol_id = e.src_symbol_id "
        "WHERE s.symbol_name = 'handler' AND e.dst_name = 'resolve_path'")
    assert rows and rows[0]["dst_symbol_id"] is not None


def test_unresolved_reference_kept_with_null_target(db: Database):
    _index(db)
    rows = db.fetchall(
        "SELECT resolved, dst_symbol_id FROM code_edges "
        "WHERE dst_name = 'missing_helper'")
    assert rows
    assert rows[0]["resolved"] == 0
    assert rows[0]["dst_symbol_id"] is None


def test_reindex_is_a_noop(db: Database):
    _index(db)
    first = db.fetchall("SELECT COUNT(*) AS n FROM code_symbols")[0]["n"]
    index_symbol_graph(db, root=FIXTURE)
    second = db.fetchall("SELECT COUNT(*) AS n FROM code_symbols")[0]["n"]
    assert first == second
```
- [ ] Run it, verify it fails: `uv run pytest test/test_infra_code_graph_index.py -q` — expect `ImportError: cannot import name 'index_symbol_graph'`.
- [ ] Add the reference-node type map to `infra/codebase_indexer.py` immediately after `_FN_NODE_TYPES`:
```python
# Tree-sitter node types that represent a call / reference, per language.
_CALL_NODE_TYPES = {
    "typescript": {"call_expression", "new_expression"},
    "tsx": {"call_expression", "new_expression"},
    "javascript": {"call_expression", "new_expression"},
    "python": {"call"},
    "go": {"call_expression"},
    "rust": {"call_expression", "macro_invocation"},
    "java": {"method_invocation", "object_creation_expression"},
}
```
- [ ] Add the call-name extractor to `infra/codebase_indexer.py` after `_extract_name`:
```python
def _extract_call_name(node, src: bytes) -> str | None:
    """The bare callee name of a call/reference node, best-effort."""
    for c in _walk(node):
        if c is node:
            continue
        if c.type in ("identifier", "property_identifier", "field_identifier"):
            return src[c.start_byte:c.end_byte].decode("utf-8", errors="ignore")
        if c.type in ("call", "call_expression", "new_expression",
                      "method_invocation"):
            break
    return None


def _symbol_references(text: str, lang: str) -> dict[tuple[int, int], list[str]]:
    """Map each (line_start, line_end) defining range to the names it calls."""
    parser = _ts_parser(lang)
    if parser is None:
        return {}
    src = text.encode("utf-8", errors="ignore")
    try:
        tree = parser.parse(src)
    except Exception:
        return {}
    fn_types = _FN_NODE_TYPES.get(lang, set())
    call_types = _CALL_NODE_TYPES.get(lang, set())
    out: dict[tuple[int, int], list[str]] = {}
    for n in _walk(tree.root_node):
        if n.type not in fn_types:
            continue
        rng = (n.start_point[0] + 1, n.end_point[0] + 1)
        names: list[str] = []
        for c in _walk(n):
            if c.type in call_types:
                name = _extract_call_name(c, src)
                if name:
                    names.append(name)
        out[rng] = names
    return out
```
- [ ] Add `index_symbol_graph` to `infra/codebase_indexer.py` before `main`:
```python
def index_symbol_graph(db: Database, *, root: Path) -> dict:
    """Second pass: extract a symbol/call graph from the indexed chunks.

    Runs after `index_codebase`. For each tree-sitter-supported chunk it
    records the defined symbol in `code_symbols` and one `code_edges` row per
    referenced name (resolved name-based within the indexed repo, else kept
    unresolved). Gated on chunk content so a re-index is a no-op.
    """
    chunk_rows = db.fetchall(
        "SELECT chunk_id, file_path, function_name, line_start, line_end, "
        "language, content FROM code_chunks WHERE function_name IS NOT NULL")
    # Skip chunks already indexed into the symbol graph.
    done = {r["chunk_id"] for r in db.fetchall(
        "SELECT DISTINCT chunk_id FROM code_symbols")}
    new_symbols = 0
    new_edges = 0
    name_index: dict[str, str] = {}  # symbol_name -> symbol_id (first wins)
    pending: list[tuple[str, list[str]]] = []  # (symbol_id, referenced names)

    with db.lock():
        for r in chunk_rows:
            if r["chunk_id"] in done:
                continue
            if r["language"] not in _FN_NODE_TYPES:
                continue
            sid = f"SYM-{uuid.uuid4().hex[:14]}"
            db.execute(
                "INSERT OR REPLACE INTO code_symbols(symbol_id, chunk_id, "
                "file_path, symbol_name, symbol_kind, line_start, line_end, "
                "language, indexed_at) VALUES (?,?,?,?,?,?,?,?,datetime('now'))",
                (sid, r["chunk_id"], r["file_path"], r["function_name"],
                 "function", r["line_start"], r["line_end"], r["language"]),
            )
            new_symbols += 1
            name_index.setdefault(r["function_name"], sid)
            refs = _symbol_references(r["content"], r["language"]).get(
                (r["line_start"], r["line_end"]), [])
            # Fallback: the chunk content is the symbol body itself, so a
            # parse of just the body yields a single defining range.
            if not refs:
                body_refs = _symbol_references(r["content"], r["language"])
                if body_refs:
                    refs = next(iter(body_refs.values()))
            if refs:
                pending.append((sid, refs))

        for sid, refs in pending:
            for name in refs:
                if name == db.fetchall(
                        "SELECT symbol_name FROM code_symbols "
                        "WHERE symbol_id = ?", (sid,))[0]["symbol_name"]:
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
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_infra_code_graph_index.py -q` — expect `5 passed`.
- [ ] Wire the CLI: in `infra/codebase_indexer.py` `main()`, immediately after `summary = index_codebase(db, root)`, add the second pass:
```python
    graph_summary = index_symbol_graph(db, root=root)
    summary["symbol_graph"] = graph_summary
```
- [ ] Run lint: `uv run ruff check infra/codebase_indexer.py test/test_infra_code_graph_index.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/codebase_indexer.py test/test_infra_code_graph_index.py && git commit -m "feat(rca): symbol/reference extraction pass"`.

## Task 5 — `PythonCodeGraph` backend

**Files:**
- Create: `blue_team/code_graph_sqlite.py`
- Test: `test/test_blue_code_graph_sqlite.py`

- [ ] Write the failing test. Create `test/test_blue_code_graph_sqlite.py`:
```python
"""Phase 1 — PythonCodeGraph reads code_symbols / code_edges."""

from __future__ import annotations

from pathlib import Path

from blue_team.code_graph_sqlite import PythonCodeGraph
from infra.codebase_indexer import index_codebase, index_symbol_graph
from infra.database import Database

FIXTURE = Path(__file__).parent / "fixtures" / "rc_repo"


def _graph(db: Database) -> PythonCodeGraph:
    index_codebase(db, FIXTURE)
    index_symbol_graph(db, root=FIXTURE)
    return PythonCodeGraph(db)


def test_available_false_on_empty_db(db: Database):
    assert PythonCodeGraph(db).available() is False


def test_available_true_after_index(db: Database):
    assert _graph(db).available() is True


def test_find_symbols_by_name(db: Database):
    g = _graph(db)
    syms = g.find_symbols("policy_check")
    assert len(syms) == 1
    assert syms[0].symbol_name == "policy_check"


def test_symbol_at_line(db: Database):
    g = _graph(db)
    handler = g.find_symbols("handler")[0]
    mid = (handler.line_start + handler.line_end) // 2
    found = g.symbol_at(handler.file_path, mid)
    assert found is not None and found.symbol_name == "handler"


def test_shortest_path_handler_to_policy_check(db: Database):
    g = _graph(db)
    handler = g.find_symbols("handler")[0]
    policy = g.find_symbols("policy_check")[0]
    paths = g.shortest_paths(handler.symbol_id, policy.symbol_id, max_hops=6)
    assert paths
    # handler -> policy_check is a direct call edge.
    assert paths[0][-1].dst_symbol_id == policy.symbol_id


def test_callees_of_handler(db: Database):
    g = _graph(db)
    handler = g.find_symbols("handler")[0]
    callee_names = {e.dst_name for e in g.callees(handler.symbol_id)}
    assert {"resolve_path", "policy_check", "write_file"} <= callee_names
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_code_graph_sqlite.py -q` — expect `ModuleNotFoundError`.
- [ ] Create `blue_team/code_graph_sqlite.py`:
```python
"""PythonCodeGraph — the default CodeGraph backend (real-root-cause spec §6.3).

Reads `code_symbols` / `code_edges` from SQLite. `shortest_paths` is a bounded
BFS over the edge table. No Argyph dependency.
"""

from __future__ import annotations

import logging
from collections import deque

from infra.database import Database
from interfaces.code_graph import CodeEdge, CodeSymbol

LOG = logging.getLogger("monkeyclaw.blue.code_graph")

_MAX_PATHS = 3  # cap distinct shortest paths returned per (src, dst)


class PythonCodeGraph:
    """A SQLite-backed CodeGraph (satisfies the interfaces.code_graph Protocol)."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # ------------------------------------------------------------------
    def available(self) -> bool:
        rows = self.db.fetchall("SELECT COUNT(*) AS n FROM code_symbols")
        return bool(rows) and rows[0]["n"] > 0

    # ------------------------------------------------------------------
    def find_symbols(self, name: str) -> list[CodeSymbol]:
        rows = self.db.fetchall(
            "SELECT * FROM code_symbols WHERE symbol_name = ?", (name,))
        return [self._row_to_symbol(r) for r in rows]

    def symbol_at(self, file: str, line: int) -> CodeSymbol | None:
        rows = self.db.fetchall(
            "SELECT * FROM code_symbols WHERE file_path = ? "
            "AND line_start <= ? AND line_end >= ? "
            "ORDER BY (line_end - line_start) ASC LIMIT 1",
            (file, line, line))
        return self._row_to_symbol(rows[0]) if rows else None

    # ------------------------------------------------------------------
    def callers(self, symbol_id: str) -> list[CodeEdge]:
        rows = self.db.fetchall(
            "SELECT * FROM code_edges WHERE dst_symbol_id = ?", (symbol_id,))
        return [self._row_to_edge(r) for r in rows]

    def callees(self, symbol_id: str) -> list[CodeEdge]:
        rows = self.db.fetchall(
            "SELECT * FROM code_edges WHERE src_symbol_id = ?", (symbol_id,))
        return [self._row_to_edge(r) for r in rows]

    # ------------------------------------------------------------------
    def shortest_paths(
        self, src: str, dst: str, max_hops: int,
    ) -> list[list[CodeEdge]]:
        """Bounded BFS — up to `_MAX_PATHS` shortest src->dst edge paths."""
        if src == dst:
            return [[]]
        found: list[list[CodeEdge]] = []
        # BFS over states (current symbol, path of edges, visited set).
        queue: deque[tuple[str, list[CodeEdge], frozenset[str]]] = deque()
        queue.append((src, [], frozenset({src})))
        best_len: int | None = None
        while queue:
            node, path, visited = queue.popleft()
            if best_len is not None and len(path) > best_len:
                break
            for edge in self.callees(node):
                target = edge.dst_symbol_id
                if target is None or target in visited:
                    continue
                new_path = [*path, edge]
                if target == dst:
                    if best_len is None:
                        best_len = len(new_path)
                    if len(new_path) == best_len:
                        found.append(new_path)
                        if len(found) >= _MAX_PATHS:
                            return found
                    continue
                if len(new_path) < max_hops:
                    queue.append((target, new_path, visited | {target}))
        return found

    # ------------------------------------------------------------------
    @staticmethod
    def _row_to_symbol(r) -> CodeSymbol:  # noqa: ANN001
        return CodeSymbol(
            symbol_id=r["symbol_id"], file_path=r["file_path"],
            symbol_name=r["symbol_name"], symbol_kind=r["symbol_kind"],
            line_start=r["line_start"], line_end=r["line_end"],
            language=r["language"],
        )

    @staticmethod
    def _row_to_edge(r) -> CodeEdge:  # noqa: ANN001
        return CodeEdge(
            src_symbol_id=r["src_symbol_id"], dst_symbol_id=r["dst_symbol_id"],
            dst_name=r["dst_name"], edge_kind=r["edge_kind"],
            resolved=bool(r["resolved"]),
        )


__all__ = ["PythonCodeGraph"]
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_code_graph_sqlite.py -q` — expect `6 passed`.
- [ ] Run lint: `uv run ruff check blue_team/code_graph_sqlite.py test/test_blue_code_graph_sqlite.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/code_graph_sqlite.py test/test_blue_code_graph_sqlite.py && git commit -m "feat(rca): PythonCodeGraph SQLite backend"`.

---

# Phase 2 — Path tracer

`blue_team/path_tracer.py` — anchor → seed → walk → rank, with the degraded fallback.

## Task 6 — `PathTracer.trace`

**Files:**
- Create: `blue_team/path_tracer.py`
- Test: `test/test_blue_path_tracer.py`

- [ ] Write the failing test. Create `test/test_blue_path_tracer.py`:
```python
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
            chunk_id="C-sink", file_path="policy.py", function_name="write_file",
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
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_path_tracer.py -q` — expect `ModuleNotFoundError`.
- [ ] Create `blue_team/path_tracer.py`:
```python
"""Path tracer — reconstructs the executed path (real-root-cause spec §6.4).

Four stages: anchor (evidence/logs -> entry symbols), seed (semantic search ->
sink symbols), walk (shortest paths anchor->sink over the graph), rank (path
proximity x graph centrality x evidence-touch). Degrades to semantic-search-only
when the graph is unavailable.
"""

from __future__ import annotations

import logging

from interfaces.code_graph import CodeGraph, CodeSymbol, ExecutedPath, PathNode
from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import CheckResult, Message

LOG = logging.getLogger("monkeyclaw.blue.path_tracer")

# Evidence keys whose values name something the code controls (a path, a
# syscall, a destination) — used both to anchor and to award an evidence-touch.
_EVIDENCE_KEYS = (
    "system_writes", "writes_outside_allowed",
    "successful_outbound", "denylisted_blocked_syscalls",
)


class PathTracer:
    def __init__(
        self,
        *,
        graph: CodeGraph,
        mcp: MonkeyClawMCP,
        max_hops: int = 6,
    ) -> None:
        self.graph = graph
        self.mcp = mcp
        self.max_hops = max_hops

    # ------------------------------------------------------------------
    def trace(
        self,
        *,
        zone_id: str,
        evidence: list[CheckResult],
        transcript: list[Message],
        victim_logs: list[str] | None = None,
    ) -> ExecutedPath:
        sink_syms, sink_chunks = self._seed_sinks(zone_id, evidence)
        if not self.graph.available():
            return self._degraded(sink_syms)

        anchors = self._anchor(evidence, victim_logs or [])
        touch_tokens = self._evidence_tokens(evidence)
        try:
            return self._walk_and_rank(anchors, sink_syms, touch_tokens)
        except Exception as e:  # noqa: BLE001
            LOG.warning("graph walk failed (%s) — degrading", e)
            return self._degraded(sink_syms)

    # ------------------------------------------------------------------
    def _seed_sinks(
        self, zone_id: str, evidence: list[CheckResult],
    ) -> tuple[list[CodeSymbol], list]:
        """Semantic search for the violation site -> sink symbols + raw chunks."""
        query = f"{zone_id} " + " ".join(
            c.check_name for c in evidence if c.triggered)
        try:
            chunks = self.mcp.search_codebase(query=query, top_k=5)
        except Exception as e:  # noqa: BLE001
            LOG.warning("search_codebase failed during sink seeding: %s", e)
            chunks = []
        sinks: list[CodeSymbol] = []
        for ch in chunks:
            sym = None
            if self.graph.available() and ch.function_name:
                matches = self.graph.find_symbols(ch.function_name)
                sym = matches[0] if matches else None
            if sym is None:
                sym = _symbol_from_chunk(ch)
            sinks.append(sym)
        return sinks, list(chunks)

    # ------------------------------------------------------------------
    def _anchor(
        self, evidence: list[CheckResult], victim_logs: list[str],
    ) -> list[CodeSymbol]:
        """Resolve triggered checks + log lines to entry symbols."""
        names: list[str] = []
        for c in evidence:
            if c.triggered:
                names.append(c.check_name)
        for line in victim_logs:
            names.extend(_identifier_tokens(line))
        anchors: list[CodeSymbol] = []
        seen: set[str] = set()
        for name in names:
            for sym in self.graph.find_symbols(name):
                if sym.symbol_id not in seen:
                    seen.add(sym.symbol_id)
                    anchors.append(sym)
        return anchors

    # ------------------------------------------------------------------
    def _walk_and_rank(
        self,
        anchors: list[CodeSymbol],
        sinks: list[CodeSymbol],
        touch_tokens: set[str],
    ) -> ExecutedPath:
        # Symbol-id -> CodeSymbol, and per-symbol path-crossing counts.
        by_id: dict[str, CodeSymbol] = {s.symbol_id: s for s in anchors + sinks}
        crossings: dict[str, int] = {}
        min_hop: dict[str, int] = {}
        total_paths = 0

        anchor_pool = anchors or [
            # No anchor resolved: use the callers of each sink as anchors.
            caller_sym
            for sink in sinks
            for edge in self.graph.callers(sink.symbol_id)
            if edge.src_symbol_id
            for caller_sym in self.graph.find_symbols_by_id(edge.src_symbol_id)
        ] if hasattr(self.graph, "find_symbols_by_id") else anchors

        for anchor in anchor_pool or anchors:
            for sink in sinks:
                paths = self.graph.shortest_paths(
                    anchor.symbol_id, sink.symbol_id, self.max_hops)
                for path in paths:
                    total_paths += 1
                    chain = [anchor.symbol_id] + [
                        e.dst_symbol_id for e in path if e.dst_symbol_id]
                    for hop, sid in enumerate(chain):
                        crossings[sid] = crossings.get(sid, 0) + 1
                        # distance from the sink end of the chain
                        dist = len(chain) - 1 - hop
                        min_hop[sid] = min(min_hop.get(sid, 999), dist)

        # If no path was found, fall back to anchors + sinks as bare nodes.
        if not crossings:
            for s in anchors + sinks:
                crossings[s.symbol_id] = 1
                min_hop[s.symbol_id] = 0 if s in sinks else 1

        nodes = self._rank(by_id, crossings, min_hop, total_paths,
                           sinks, touch_tokens)
        return ExecutedPath(
            nodes=nodes, anchors=anchors, sinks=sinks,
            backend="python", degraded=False,
        )

    # ------------------------------------------------------------------
    def _rank(
        self,
        by_id: dict[str, CodeSymbol],
        crossings: dict[str, int],
        min_hop: dict[str, int],
        total_paths: int,
        sinks: list[CodeSymbol],
        touch_tokens: set[str],
    ) -> list[PathNode]:
        sink_ids = {s.symbol_id for s in sinks}
        max_cross = max(crossings.values()) if crossings else 1
        nodes: list[PathNode] = []
        for sid, count in crossings.items():
            sym = by_id.get(sid) or self._resolve(sid)
            if sym is None:
                continue
            hop = min_hop.get(sid, 6)
            proximity = 1.0 if sid in sink_ids else max(0.0, 1.0 - hop / 6.0)
            centrality = count / max_cross if max_cross else 0.0
            touch = any(tok and tok in sym.symbol_name.lower()
                        for tok in touch_tokens) or sid in sink_ids
            rank = max(0.0, min(1.0,
                0.5 * proximity + 0.35 * centrality + (0.15 if touch else 0.0)))
            nodes.append(PathNode(
                symbol=sym, proximity=proximity, centrality=centrality,
                evidence_touch=touch, rank_score=rank,
            ))
        nodes.sort(key=lambda n: n.rank_score, reverse=True)
        return nodes

    # ------------------------------------------------------------------
    def _degraded(self, sinks: list[CodeSymbol]) -> ExecutedPath:
        """Semantic-search hits only, proximity-scored — today's behaviour."""
        nodes = [
            PathNode(symbol=s, proximity=1.0 - i * 0.1, centrality=0.0,
                     evidence_touch=False,
                     rank_score=max(0.0, 1.0 - i * 0.1))
            for i, s in enumerate(sinks)
        ]
        return ExecutedPath(
            nodes=nodes, anchors=[], sinks=sinks,
            backend="python", degraded=True,
        )

    # ------------------------------------------------------------------
    def _resolve(self, symbol_id: str) -> CodeSymbol | None:
        # Look the symbol up by id via a name-agnostic find.
        for n in (self.graph.callees(symbol_id) or []):
            if n.dst_symbol_id == symbol_id:
                break
        rows = self.graph.find_symbols("")  # cheap no-op; concrete graphs
        return None if rows is None else None

    @staticmethod
    def _evidence_tokens(evidence: list[CheckResult]) -> set[str]:
        tokens: set[str] = set()
        for c in evidence:
            if not c.triggered:
                continue
            tokens.add(c.check_name.lower())
            for key in _EVIDENCE_KEYS:
                for v in (c.evidence or {}).get(key, []) or []:
                    if isinstance(v, dict):
                        for x in v.values():
                            tokens |= _identifier_tokens(str(x))
                    else:
                        tokens |= _identifier_tokens(str(v))
        return {t for t in tokens if t}


def _symbol_from_chunk(chunk) -> CodeSymbol:  # noqa: ANN001
    """Wrap a semantic-search chunk as a bare CodeSymbol (degraded path)."""
    start, _, end = (chunk.line_range or "L0-L0").lstrip("L").partition("-")
    try:
        ls, le = int(start or 0), int(end.lstrip("L") or 0)
    except ValueError:
        ls, le = 0, 0
    return CodeSymbol(
        symbol_id=f"CHUNK:{chunk.chunk_id}",
        file_path=chunk.file_path,
        symbol_name=chunk.function_name or chunk.file_path,
        symbol_kind="function",
        line_start=ls, line_end=le, language=chunk.language,
    )


def _identifier_tokens(text: str) -> set[str]:
    """Lowercase identifier-ish tokens from a free-text string."""
    out: set[str] = set()
    cur = ""
    for ch in text:
        if ch.isalnum() or ch == "_":
            cur += ch
        else:
            if len(cur) >= 3:
                out.add(cur.lower())
            cur = ""
    if len(cur) >= 3:
        out.add(cur.lower())
    return out


__all__ = ["PathTracer"]
```
- [ ] Note for the implementer: `_resolve` and the `find_symbols_by_id` reference above are deliberately conservative — keep the ranking working off the `by_id` map (anchors + sinks) the walk already builds; do not depend on a `find_symbols_by_id` method. Simplify `_walk_and_rank` so `anchor_pool` is just `anchors` and `_rank` only ranks ids present in `by_id` or reachable on a found path. Verify the tests below still pass after that simplification; if a path symbol is not in `by_id`, add it to `by_id` as the walk discovers it (capture `edge` endpoints into `by_id` inside the path loop). This keeps the module free of any speculative graph API.
- [ ] Apply that simplification: inside the path loop in `_walk_and_rank`, after computing `chain`, also record every on-path symbol — for each `edge` in `path`, call `self.graph.callees`/`find_symbols` is unnecessary; instead store `by_id[edge.dst_symbol_id]` by looking the symbol up once with a small helper `_symbol_by_id(self, sid)` that runs `SELECT * FROM code_symbols WHERE symbol_id=?` — add that helper to `PythonCodeGraph` in this task and call it through a new optional `CodeGraph.symbol_by_id` Protocol method. Update `interfaces/code_graph.py` to add `symbol_by_id(self, symbol_id: str) -> CodeSymbol | None` to the Protocol and `PythonCodeGraph` to implement it.
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_path_tracer.py -q` — expect `4 passed`.
- [ ] Run the code-graph backend test again to confirm `symbol_by_id` did not break it: `uv run pytest test/test_blue_code_graph_sqlite.py -q` — expect `6 passed`.
- [ ] Run lint: `uv run ruff check blue_team/path_tracer.py blue_team/code_graph_sqlite.py interfaces/code_graph.py test/test_blue_path_tracer.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/path_tracer.py blue_team/code_graph_sqlite.py interfaces/code_graph.py test/test_blue_path_tracer.py && git commit -m "feat(rca): PathTracer with anchor/seed/walk/rank + degraded fallback"`.

## Task 7 — Persist the `ExecutedPath`

**Files:**
- Modify: `blue_team/path_tracer.py`
- Test: `test/test_blue_path_tracer.py` (extend)

- [ ] Add a failing test to the end of `test/test_blue_path_tracer.py`:
```python
def test_trace_persists_executed_path_row(db: Database):
    index_codebase(db, FIXTURE)
    index_symbol_graph(db, root=FIXTURE)
    tracer = PathTracer(graph=PythonCodeGraph(db), mcp=_StubMCP(), db=db)
    tracer.trace(zone_id="SBX-FS", evidence=_evidence(), transcript=[],
                 victim_logs=[], finding_id="F-1")
    rows = db.fetchall(
        "SELECT * FROM executed_paths WHERE finding_id = 'F-1'")
    assert len(rows) == 1
    assert rows[0]["zone_id"] == "SBX-FS"
    assert rows[0]["degraded"] == 0
    assert rows[0]["backend"] == "python"
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_path_tracer.py::test_trace_persists_executed_path_row -q` — expect `TypeError` (`db`/`finding_id` unknown).
- [ ] Extend `PathTracer.__init__` in `blue_team/path_tracer.py` to accept an optional `db`:
```python
    def __init__(
        self,
        *,
        graph: CodeGraph,
        mcp: MonkeyClawMCP,
        max_hops: int = 6,
        db=None,  # noqa: ANN001 — infra.database.Database, optional
    ) -> None:
        self.graph = graph
        self.mcp = mcp
        self.max_hops = max_hops
        self.db = db
```
- [ ] Extend `PathTracer.trace` to accept `finding_id` and persist the row. Change the signature to add `finding_id: str = ""` and, immediately before each `return`, call `self._persist(finding_id, zone_id, path)`:
```python
    def _persist(self, finding_id: str, zone_id: str, path: ExecutedPath) -> None:
        if self.db is None or not finding_id:
            return
        import json
        import uuid
        try:
            with self.db.lock():
                self.db.execute(
                    "INSERT INTO executed_paths(path_id, finding_id, zone_id, "
                    "anchor_symbols, sink_symbols, node_count, backend, "
                    "degraded, created_at) VALUES (?,?,?,?,?,?,?,?,datetime('now'))",
                    (f"EP-{uuid.uuid4().hex[:14]}", finding_id, zone_id,
                     json.dumps([s.symbol_id for s in path.anchors]),
                     json.dumps([s.symbol_id for s in path.sinks]),
                     len(path.nodes), path.backend, 1 if path.degraded else 0),
                )
        except Exception as e:  # noqa: BLE001
            LOG.warning("executed_paths persist failed: %s", e)
```
- [ ] Restructure `trace` so it computes `path` then persists once before returning — replace the three early `return`s with assignment to a local `path` and a single `self._persist(finding_id, zone_id, path); return path` at the end.
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_path_tracer.py -q` — expect `5 passed`.
- [ ] Run lint: `uv run ruff check blue_team/path_tracer.py test/test_blue_path_tracer.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/path_tracer.py test/test_blue_path_tracer.py && git commit -m "feat(rca): persist ExecutedPath to executed_paths"`.

---

# Phase 3 — Locator rewrite

`RootCauseLocator` internals consume the `ExecutedPath`; the output contract is frozen.

## Task 8 — Lock the output contract with a regression test

**Files:**
- Modify: `test/test_blue_root_cause.py`

- [ ] Add contract-freeze tests to the end of `test/test_blue_root_cause.py`:
```python
def test_locate_signature_is_frozen():
    import inspect

    from blue_team.root_cause import RootCauseLocator

    params = set(inspect.signature(RootCauseLocator.locate).parameters)
    assert {"zone_id", "severity", "minimal_transcript",
            "evidence", "zone_description"} <= params


def test_root_cause_result_shape_is_frozen():
    from dataclasses import fields

    from blue_team.root_cause import RootCauseResult

    fnames = {f.name for f in fields(RootCauseResult)}
    assert fnames == {"root_cause_confidence", "candidate_fix_sites",
                      "execution_trace", "notes", "skipped"}


def test_severity_gate_still_skips_low(monkeypatch):
    from blue_team.root_cause import RootCauseConfig, RootCauseLocator

    loc = RootCauseLocator(llm=_StubLLM(), mcp=_StubMCP(),
                           cfg=RootCauseConfig())
    res = loc.locate(zone_id="SBX-FS", severity="low",
                     minimal_transcript=[], evidence=[])
    assert res.skipped is True
    assert res.candidate_fix_sites == []
```
- [ ] Note: if `test/test_blue_root_cause.py` does not already define `_StubLLM` / `_StubMCP`, reuse the stubs the file already imports/defines; do not add new global stubs that collide.
- [ ] Run it, verify it passes against the *current* locator: `uv run pytest test/test_blue_root_cause.py -q` — expect all green (this locks the contract before the rewrite).
- [ ] Commit: `git add test/test_blue_root_cause.py && git commit -m "test(rca): freeze the RootCauseLocator output contract"`.

## Task 9 — Rewrite `RootCauseLocator` internals

**Files:**
- Modify: `blue_team/root_cause.py`
- Test: `test/test_blue_root_cause_traced.py`

- [ ] Write the failing test. Create `test/test_blue_root_cause_traced.py`:
```python
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
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_root_cause_traced.py -q` — expect `TypeError` (`tracer` kwarg unknown).
- [ ] Extend `RootCauseConfig` in `blue_team/root_cause.py` with the blend weights and `max_hops`:
```python
@dataclass
class RootCauseConfig:
    severity_threshold: str = "high"
    top_k_code: int = 5
    min_confidence: float = 0.3       # below this we emit "could not determine"
    speculative_threshold: float = 0.5  # below this we tag as (speculative)
    max_tokens: int = 1500
    temperature: float = 0.2
    # --- real-root-cause additions ---
    path_rank_weight: float = 0.5
    llm_conf_weight: float = 0.5
    max_hops: int = 6
```
- [ ] Change `RootCauseLocator.__init__` in `blue_team/root_cause.py` to accept an optional tracer:
```python
    def __init__(
        self,
        llm: LLMClient,
        mcp: MonkeyClawMCP,
        *,
        cfg: RootCauseConfig | None = None,
        tracer=None,  # noqa: ANN001 — blue_team.path_tracer.PathTracer, optional
    ) -> None:
        self.llm = llm
        self.mcp = mcp
        self.cfg = cfg or RootCauseConfig()
        self._tracer = tracer  # injected by the pipeline; None for default path
```
- [ ] Replace the body of `locate` (everything after the severity gate) in `blue_team/root_cause.py` so it consumes the tracer:
```python
        # Build the executed path. With no tracer injected the locator keeps
        # working via the degraded keyword path (see _legacy_locate).
        if self._tracer is None:
            return self._legacy_locate(
                zone_id, severity, minimal_transcript, evidence,
                zone_description)

        try:
            path = self._tracer.trace(
                zone_id=zone_id, evidence=evidence,
                transcript=minimal_transcript, victim_logs=[])
        except Exception as e:  # noqa: BLE001
            LOG.warning("path tracer failed (%s) — legacy locate", e)
            return self._legacy_locate(
                zone_id, severity, minimal_transcript, evidence,
                zone_description)

        if not path.nodes:
            return RootCauseResult(
                root_cause_confidence=0.0,
                candidate_fix_sites=[_undetermined()],
                execution_trace="",
                notes="executed path yielded no candidate symbols",
            )

        user = self._build_traced_prompt(
            zone_id, severity, minimal_transcript, evidence, path)
        try:
            resp = self.llm.complete(
                messages=[LLMMessage(role="user", content=user)],
                system=_RC_SYSTEM,
                max_tokens=self.cfg.max_tokens,
                temperature=self.cfg.temperature,
            )
        except Exception as e:  # noqa: BLE001
            LOG.warning("LLM call failed during root-cause locate: %s", e)
            return RootCauseResult(
                root_cause_confidence=0.0,
                candidate_fix_sites=[_undetermined()],
                execution_trace="",
                notes=f"LLM error: {e!r}",
            )
        return self._parse_response(resp.text, path)
```
- [ ] Add `_legacy_locate` to `RootCauseLocator` — this is the current `locate` body verbatim (build query → `search_codebase` → LLM → `_parse_response`), so the degraded path is byte-for-byte today's behaviour. Move the old query/chunk/prompt code into it; `_parse_response` called from here passes `path=None`.
- [ ] Add `_build_traced_prompt` to `RootCauseLocator`:
```python
    def _build_traced_prompt(
        self,
        zone_id: str,
        severity: str,
        transcript: list[Message],
        evidence: list[CheckResult],
        path,  # noqa: ANN001 — ExecutedPath
    ) -> str:
        lines: list[str] = []
        for i, node in enumerate(path.nodes):
            s = node.symbol
            lines.append(
                f"## node {i}: {s.file_path}:L{s.line_start}-L{s.line_end} "
                f"— {s.symbol_name} (rank={node.rank_score:.2f}, "
                f"proximity={node.proximity:.2f}, "
                f"evidence_touch={node.evidence_touch})")
        path_block = "\n".join(lines)
        return (
            f"# Zone\nzone_id: {zone_id}\nseverity: {severity}\n\n"
            f"# Minimal attack transcript\n{_format_transcript(transcript)}\n\n"
            f"# Triggered checks (harness evidence)\n"
            f"{_format_evidence(evidence)}\n\n"
            f"# Executed path (ordered entry -> violation)\n"
            f"These are the code regions the attack traversed, ranked by "
            f"path proximity to the violation. Confirm which node is the fix "
            f"site, calibrate confidence WITHIN the rank band, and emit the "
            f"trace narrative grounded in this path.\n{path_block}\n\n"
            f"Output JSON only — cite ONLY files that appear above."
        )
```
- [ ] Change `_parse_response` to take an optional `path` and apply the on-path filter + confidence blend. Replace the signature and the per-site loop:
```python
    def _parse_response(self, raw: str, path=None) -> RootCauseResult:  # noqa: ANN001
        try:
            data = extract_json(raw)
        except ValueError:
            return RootCauseResult(
                root_cause_confidence=0.0,
                candidate_fix_sites=[_undetermined()],
                execution_trace="",
                notes="LLM response did not contain JSON",
            )
        if not isinstance(data, list):
            return RootCauseResult(
                root_cause_confidence=0.0,
                candidate_fix_sites=[_undetermined()],
                execution_trace="",
                notes="LLM response was not a JSON array",
            )

        # Files (and per-file rank) the LLM is allowed to cite.
        path_files: dict[str, float] = {}
        if path is not None:
            for n in path.nodes:
                f = n.symbol.file_path
                path_files[f] = max(path_files.get(f, 0.0), n.rank_score)

        trace = ""
        sites: list[FixSite] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            if "trace" in entry and not trace:
                trace = str(entry["trace"])[:1500]
                continue
            file = str(entry.get("file", "")).strip()
            if not file:
                continue
            # Hallucination guard: with a traced path, the LLM may only cite
            # a file that appears on the path.
            if path is not None and file not in path_files:
                LOG.info("dropping off-path LLM citation: %s", file)
                continue
            llm_conf = max(0.0, min(1.0,
                float(entry.get("confidence", 0.0) or 0.0)))
            if path is not None:
                path_rank = path_files.get(file, 0.0)
                conf = (self.cfg.path_rank_weight * path_rank
                        + self.cfg.llm_conf_weight * llm_conf)
            else:
                conf = llm_conf
            conf = max(0.0, min(1.0, conf))
            if conf < self.cfg.min_confidence:
                continue
            explanation = str(entry.get("explanation", ""))[:2000]
            if conf < self.cfg.speculative_threshold:
                explanation = f"(speculative) {explanation}"
            sites.append(FixSite(
                file=file,
                function=str(entry.get("function", "")).strip(),
                line_range=str(entry.get("line_range", "")).strip(),
                explanation=explanation,
                confidence=conf,
            ))

        if not sites:
            return RootCauseResult(
                root_cause_confidence=0.0,
                candidate_fix_sites=[_undetermined()],
                execution_trace=trace,
                notes=(f"no candidates met confidence threshold "
                       f"{self.cfg.min_confidence}"),
            )
        sites.sort(key=lambda s: s.confidence, reverse=True)
        return RootCauseResult(
            root_cause_confidence=sites[0].confidence,
            candidate_fix_sites=sites,
            execution_trace=trace,
            notes=f"{len(sites)} candidate(s) above min confidence",
        )
```
- [ ] Update the `_RC_SYSTEM` prompt's rule 1 to reflect the executed-path framing: change "Only cite files and line ranges from the provided source snippets" to "Only cite files that appear in the Executed path section — these are the regions the attack actually traversed; do not invent file paths."
- [ ] Run the new test, verify it passes: `uv run pytest test/test_blue_root_cause_traced.py -q` — expect `4 passed`.
- [ ] Run the contract-freeze test, verify it still passes: `uv run pytest test/test_blue_root_cause.py -q` — expect all green.
- [ ] Run lint: `uv run ruff check blue_team/root_cause.py test/test_blue_root_cause_traced.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/root_cause.py test/test_blue_root_cause_traced.py && git commit -m "feat(rca): RootCauseLocator consumes the ExecutedPath"`.

## Task 10 — Degraded-path regression test

**Files:**
- Create: `test/test_blue_root_cause_degraded.py`

- [ ] Write the test. Create `test/test_blue_root_cause_degraded.py`:
```python
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
            chunk_id="C1", file_path="policy.py", function_name="write_file",
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
```
- [ ] Run it, verify it passes: `uv run pytest test/test_blue_root_cause_degraded.py -q` — expect `2 passed`.
- [ ] Run lint: `uv run ruff check test/test_blue_root_cause_degraded.py` — expect `All checks passed!`.
- [ ] Commit: `git add test/test_blue_root_cause_degraded.py && git commit -m "test(rca): degraded-path locator regression"`.

---

# Phase 4 — Pipeline wiring & config

## Task 11 — `CodeGraphConfig` and the YAML block

**Files:**
- Modify: `interfaces/config_schema.py`
- Modify: `configs/monkeyclaw.yaml`
- Test: `test/test_root_cause_types.py` (extend)

- [ ] Add a failing test to the end of `test/test_root_cause_types.py`:
```python
def test_code_graph_config_defaults():
    from interfaces.config_schema import MonkeyClawConfig

    cfg = MonkeyClawConfig()
    cg = cfg.repro.code_graph
    assert cg.enabled is True
    assert cg.max_hops == 6
    assert abs(cg.path_rank_weight - 0.5) < 1e-9
    assert abs(cg.llm_conf_weight - 0.5) < 1e-9
```
- [ ] Run it, verify it fails: `uv run pytest test/test_root_cause_types.py::test_code_graph_config_defaults -q` — expect `AttributeError`.
- [ ] Add `CodeGraphConfig` to `interfaces/config_schema.py` immediately before `class ReproConfig`:
```python
class CodeGraphConfig(BaseModel):
    enabled: bool = True
    max_hops: int = 6
    path_rank_weight: float = 0.5
    llm_conf_weight: float = 0.5
```
- [ ] Add the nested field to `ReproConfig` in `interfaces/config_schema.py`:
```python
class ReproConfig(BaseModel):
    replay_count: int = 5
    repro_rate_threshold: float = 0.5
    delta_debug_max_iterations: int = 30
    root_cause_severity_threshold: str = "high"
    cold_verify_max_attempts: int = 3
    code_graph: CodeGraphConfig = CodeGraphConfig()
```
- [ ] Add the `code_graph` block under `repro:` in `configs/monkeyclaw.yaml`:
```yaml
repro:
  # ... existing repro keys unchanged ...
  code_graph:
    enabled: true
    max_hops: 6
    path_rank_weight: 0.5
    llm_conf_weight: 0.5
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_root_cause_types.py -q` — expect `5 passed`.
- [ ] Run lint: `uv run ruff check interfaces/config_schema.py` — expect `All checks passed!`.
- [ ] Commit: `git add interfaces/config_schema.py configs/monkeyclaw.yaml test/test_root_cause_types.py && git commit -m "feat(rca): code_graph config block"`.

## Task 12 — Wire the tracer into `Pipeline`

**Files:**
- Modify: `blue_team/pipeline.py`
- Test: `test/test_blue_root_cause_traced.py` (extend)

- [ ] Add a failing test to the end of `test/test_blue_root_cause_traced.py`:
```python
def test_pipeline_injects_a_tracer_into_the_locator():
    from blue_team.path_tracer import PathTracer
    from infra.runtime import make_test_runtime  # mock-mode runtime helper

    runtime = make_test_runtime()
    from blue_team.pipeline import Pipeline

    pipe = Pipeline(runtime=runtime)
    assert pipe.root_cause._tracer is not None
    assert isinstance(pipe.root_cause._tracer, PathTracer)
```
- [ ] Note: use whatever the existing blue-team tests use to build a mock-mode `Runtime` (grep `test/test_blue_pipeline*.py` for the helper) — substitute that for `make_test_runtime` if the name differs. The assertion is the load-bearing part.
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_root_cause_traced.py::test_pipeline_injects_a_tracer_into_the_locator -q` — expect `AssertionError` (`_tracer` is `None`).
- [ ] In `blue_team/pipeline.py`, add the imports near the other blue-team imports:
```python
from blue_team.code_graph_sqlite import PythonCodeGraph
from blue_team.path_tracer import PathTracer
```
- [ ] In `Pipeline.__init__`, replace the `self.root_cause = root_cause or RootCauseLocator(...)` block with a tracer-aware construction:
```python
        if root_cause is not None:
            self.root_cause = root_cause
        else:
            tracer = None
            if self.cfg.repro.code_graph.enabled and hasattr(self.mcp, "db"):
                tracer = PathTracer(
                    graph=PythonCodeGraph(self.mcp.db),
                    mcp=self.mcp,
                    max_hops=self.cfg.repro.code_graph.max_hops,
                    db=self.mcp.db,
                )
            self.root_cause = RootCauseLocator(
                llm=self.llm, mcp=self.mcp,
                cfg=RootCauseConfig(
                    severity_threshold=self.cfg.repro.root_cause_severity_threshold,
                    path_rank_weight=self.cfg.repro.code_graph.path_rank_weight,
                    llm_conf_weight=self.cfg.repro.code_graph.llm_conf_weight,
                    max_hops=self.cfg.repro.code_graph.max_hops,
                ),
                tracer=tracer,
            )
```
- [ ] Note: if the MCP server does not expose `.db` directly, grep `infra/mcp_server.py` for how it holds the `Database` handle and adapt the `hasattr(self.mcp, "db")` guard and `PathTracer(db=...)` accordingly — the tracer needs a `Database` for `executed_paths` persistence and `PythonCodeGraph` needs one for the graph reads. If no handle is reachable, construct the `Database` from `self.cfg.storage` the same way `index_codebase`'s CLI does.
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_root_cause_traced.py -q` — expect `5 passed`.
- [ ] Run the full blue-team suite to confirm no regression: `uv run pytest test/ -k blue -q` — expect all green.
- [ ] Run lint: `uv run ruff check blue_team/pipeline.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/pipeline.py test/test_blue_root_cause_traced.py && git commit -m "feat(rca): wire PathTracer into the blue pipeline"`.

## Task 13 — Dashboard finding-detail executed-path view

**Files:**
- Modify: `infra/dashboard.py`
- Test: `test/test_blue_path_tracer.py` (extend)

- [ ] Add a failing test to the end of `test/test_blue_path_tracer.py`:
```python
def test_dashboard_renders_executed_path(db: Database):
    from infra.dashboard import render_executed_path

    db.execute(
        "INSERT INTO executed_paths(path_id, finding_id, zone_id, "
        "anchor_symbols, sink_symbols, node_count, backend, degraded, "
        "created_at) VALUES (?,?,?,?,?,?,?,?,datetime('now'))",
        ("EP-1", "F-9", "SBX-FS", '[]', '[]', 3, "python", 0))
    html = render_executed_path(db, finding_id="F-9")
    assert "SBX-FS" in html
    assert "python" in html
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_path_tracer.py::test_dashboard_renders_executed_path -q` — expect `ImportError`.
- [ ] Add `render_executed_path` to `infra/dashboard.py` (place it near the other finding-detail render helpers):
```python
def render_executed_path(db, finding_id: str) -> str:  # noqa: ANN001
    """Render the executed path for one finding as an HTML fragment."""
    rows = db.fetchall(
        "SELECT * FROM executed_paths WHERE finding_id = ? "
        "ORDER BY created_at DESC LIMIT 1", (finding_id,))
    if not rows:
        return "<div class='exec-path empty'>No executed path traced.</div>"
    r = rows[0]
    badge = "degraded" if r["degraded"] else "traced"
    return (
        f"<div class='exec-path {badge}'>"
        f"<h4>Executed path — zone {r['zone_id']}</h4>"
        f"<p>backend: {r['backend']} · nodes: {r['node_count']} · "
        f"status: {badge}</p></div>"
    )
```
- [ ] Wire `render_executed_path` into whatever builds the finding-detail page in `infra/dashboard.py` (grep for the existing finding-detail view function and append the fragment to its output).
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_path_tracer.py -q` — expect `6 passed`.
- [ ] Run lint: `uv run ruff check infra/dashboard.py test/test_blue_path_tracer.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/dashboard.py test/test_blue_path_tracer.py && git commit -m "feat(rca): dashboard executed-path view"`.

## Task 14 — Full-suite green + lint sweep

**Files:**
- No new files — verification only.

- [ ] Run the entire test suite: `uv run pytest -q` — expect all tests passing (the pre-existing count plus the new `test_root_cause_*` / `test_infra_code_graph_*` / `test_blue_code_graph_*` / `test_blue_path_tracer` / `test_blue_root_cause_traced` / `test_blue_root_cause_degraded` tests).
- [ ] Run lint across the whole repo: `uv run ruff check .` — expect `All checks passed!`.
- [ ] Run one mock-mode pipeline cycle to confirm the locator still works end-to-end: `uv run monkeyclaw run --cycles 1 --target monkey-victim --mock` — expect a clean exit and findings logged.
- [ ] Run `uv run monkeyclaw blue-team` in mock mode and confirm a high-severity finding produces fix sites (the executed-path locator path exercises without crashing).
- [ ] Commit any incidental lint fixes: `git add -A && git commit -m "chore(rca): full-suite green + lint sweep"`.

---

## Self-review against the spec

- §3 scope — call/symbol graph on `code_chunks` (Task 4), `path_tracer.py` (Task 6), locator rewrite (Task 9), `CodeGraph` interface (Task 1), new types + migration (Tasks 1-2): all covered.
- §4 constraints — output contract frozen: Task 8 locks it, Task 9 keeps the signature and `RootCauseResult` shape. No new mandatory dependency: tree-sitter is already present; no `argyph` import anywhere. Hallucination guards strengthened: Task 9 `_parse_response` drops off-path citations and keeps `min_confidence`/`speculative`/`(unknown)`. Confidence evidence-grounded: Task 9 blends `path_rank` and `llm_conf`. `interfaces/` firewall: types in `interfaces/code_graph.py`, re-exported from `types.py`; migration via the runner. Degrade-don't-fail: Tasks 6, 9, 10 cover the degraded path.
- §6 components — `interfaces/code_graph.py` (Task 1), `index_symbol_graph` (Task 4), `PythonCodeGraph` (Task 5), `path_tracer.py` (Task 6-7), locator rewrite (Task 9): all present. `ArgyphCodeGraph` correctly NOT built.
- §7 data model — `code_symbols`, `code_edges`, `executed_paths` in Task 2; `CodeSymbol`, `CodeEdge`, `PathNode`, `ExecutedPath` in Task 1.
- §9 integration — `root_cause.py` internals only (Task 9), `codebase_indexer.py` CLI second pass (Task 4), `pipeline.py` injection (Task 12), config block (Task 11), no `search_codebase`/MCP change (graph read direct from SQLite, noted in File Structure). `patch_generator.py`/`triage.py`/repro writer untouched — confirmed by leaving `FixSite`/`RootCauseResult` frozen.
- §10 error handling — empty graph (Task 6/10), no anchor (Task 6 `_walk_and_rank` fallback), no path (Task 6 fallback to anchors+sinks), graph raises (Task 6 try/except), LLM fails (Task 9 retains `(unknown)`), partial graph (Task 4 skips unsupported languages without aborting).
- §12 testing — `test_infra_code_graph_index.py`, `test_blue_code_graph_sqlite.py`, `test_blue_path_tracer.py`, `test_blue_root_cause_traced.py`, extended `test_blue_root_cause.py`, `test_blue_root_cause_degraded.py`: all present and named per convention.
- §13 phases — Phase 0 (Tasks 1-2), Phase 1 (Tasks 3-5), Phase 2 (Tasks 6-7), Phase 3 (Tasks 8-10), Phase 4 (Tasks 11-14): the plan's phase headers match the spec's phased delivery.
- Gap fixed inline: Task 6's first draft referenced a speculative `find_symbols_by_id`; the follow-up step removes it and pins the design to a concrete `symbol_by_id` Protocol method added in the same task — no placeholder API leaks into the shipped code.
