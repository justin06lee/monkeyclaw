# Real Root-Cause Analysis — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

For every high-severity finding, the blue team's `RootCauseLocator`
(`blue_team/root_cause.py`) produces ranked, confidence-scored candidate fix
sites. Those fix sites flow straight into `patch_generator.py` — they become
the `# Candidate Fix Sites (from root cause)` block the patch model reads, and
the file paths it searches for source context. The quality of every downstream
patch is bounded by the quality of these fix sites.

Today the locator works like this: it builds a search query by **string-joining
the zone id with raw evidence fields** (touched paths, blocked syscalls,
network destinations), calls `search_codebase` once, and hands the top-k
chunks to an LLM that picks fix sites. There is no notion of the *path the
attack actually executed*. The query is a bag of keywords; whatever the vector
index returns for that bag is the entire candidate pool. The LLM cannot cite a
file the keyword query never surfaced, so a root cause two hops away from any
literal evidence string is structurally unreachable. This is heuristic
fix-site location: it finds code that *mentions* the evidence, not code that
*ran* during the attack.

This spec replaces the heuristic with **real code analysis**: trace the
executed path from the logs and transcripts through the indexed codebase to a
ranked, confidence-scored set of candidate fix sites, so the patch generator
starts from where the failure happened rather than from where the keywords
matched.

## 2. What already exists

Stated precisely so this spec replaces the locator's *internals* and leaves its
*contract* intact.

### 2.1 `blue_team/root_cause.py` — current behavior

`RootCauseLocator.locate(zone_id, severity, minimal_transcript, evidence,
zone_description) -> RootCauseResult`:

- **Severity gate** — fires only for severity ≥ `severity_threshold` (default
  `"high"`); below threshold returns `skipped=True`.
- **`_build_query`** — concatenates `zone_id`, `zone_description`, and, per
  triggered `CheckResult`, the `check_name` plus values pulled from a fixed set
  of evidence keys (`system_writes`, `writes_outside_allowed`,
  `successful_outbound`, `denylisted_blocked_syscalls`). Deduplicated, joined
  with spaces. This is the heuristic core being replaced.
- **One `mcp.search_codebase(query, top_k)` call** — the entire candidate pool.
- **One LLM call** — `_RC_SYSTEM` prompt asks the model to cite fix sites *only
  from the provided snippets*, score each in `[0,1]`, and emit a `trace`
  narrative as the first array element.
- **`_parse_response`** — parses the JSON, drops sites below `min_confidence`
  (0.3), tags `< speculative_threshold` (0.5) sites `(speculative)`, sorts by
  confidence, returns `RootCauseResult(root_cause_confidence,
  candidate_fix_sites, execution_trace, notes, skipped)`.
- **Hallucination guards** — emits a single `(unknown)` `FixSite` when nothing
  clears threshold; never fabricates.

`RootCauseResult` and `FixSite` (`interfaces/types.py`: `file`, `function`,
`line_range`, `explanation`, `confidence`) are the **output contract**. The
pipeline puts `candidate_fix_sites` into `ReproPackageInput.affected_paths` and
`patch_generator._gather_source` reads them. **This spec does not change that
contract** — it changes how the sites are produced.

### 2.2 `infra/codebase_indexer.py` — current behavior

`index_codebase(db, root, embedder)` walks a NemoClaw source tree, chunks every
supported file into function/class units (tree-sitter for TS/JS/Py/Go/Rust/Java
where the language pack is present, a fixed 60-line window otherwise), embeds
each chunk, and upserts into `code_chunks` + `code_chunks_vec` with sha256
dedup. `Chunk` carries `file_path`, `function_name`, `line_start`, `line_end`,
`language`, `content`. Retrieval is via the MCP `search_codebase` tool over the
vector table. The indexer is a **batch index builder + a semantic search
substrate** — it has no concept of call edges, symbol references, or an
executed path. `search_codebase` is the *only* read interface today.

### 2.3 `infra/argyph_index.py` — current behavior, and its role here

`ArgyphIndex` shells out to the optional `argyph` CLI — a read-only Rust MCP
server providing a tree-sitter symbol graph plus hybrid BM25+vector search.
**Argyph's `index`/`search` subcommands are stubbed in the shipped milestone**
(they print "not implemented" and exit 0); only `status` returns real data.
`_parse_search` already targets Argyph's *documented* `search_code` response
shape so it works unchanged once the CLI is real, and degrades to an empty list
against today's stub. The architecture report is explicit: *"Argyph should stay
referenced as a future root-cause/code-analysis helper. Do not add its MCP
server until that project is stable."*

**This spec honors that.** Argyph is named as a **future helper** for the one
capability the Python indexer lacks — a real symbol/call graph — and the
tracer is built behind an interface so an Argyph backend can slot in later. **No
Argyph MCP server is added. No dependency on the Argyph CLI is introduced.**
The first and default backend is built entirely on the existing Python indexer.

## 3. Scope

In scope:

- A **lightweight call/symbol graph** built on top of the existing
  `code_chunks` data, persisted in new `interfaces/` tables. No new parser:
  reuse the tree-sitter chunking the indexer already does, plus a definition/
  reference extraction pass.
- A new `blue_team/path_tracer.py` module: given the attack transcript, the
  triggered `CheckResult` evidence, and (when available) victim logs, it
  reconstructs the **executed path** — the ordered set of code regions the
  attack most plausibly traversed — by anchoring on observable signals and
  walking the symbol graph.
- A rewrite of `RootCauseLocator` internals to consume the traced path:
  candidate fix sites are ranked by *path proximity to the violation* and
  *graph centrality*, then confidence-scored, with the LLM used to *explain and
  calibrate* rather than to *discover from a keyword bag*.
- A `CodeGraph` interface so the symbol-graph backend is swappable (Python
  indexer now; Argyph later).
- New `interfaces/` types and a schema migration.

Explicitly out of scope (YAGNI for this spec):

- An Argyph MCP server, an Argyph runtime dependency, or any code path that
  *requires* the `argyph` binary. Argyph is a documented future backend only.
- Dynamic instrumentation of the victim (real execution-trace capture from a
  running NemoClaw) — the tracer reconstructs the path from logs/transcripts +
  the static graph, not from a live profiler.
- Cross-repo or cross-language whole-program analysis; the graph is
  per-victim-repo and per-file-language, same scope as the indexer.
- Replacing `search_codebase` — semantic search stays as a fallback and a
  graph-seeding aid.
- Root-cause analysis for medium/low findings — the severity gate is retained.

## 4. Design constraints

1. **The locator's output contract is frozen.** `RootCauseLocator.locate(...)`
   keeps its signature and still returns `RootCauseResult` with
   `candidate_fix_sites: list[FixSite]`. Downstream (`pipeline.py`,
   `patch_generator.py`, `triage.py`, the repro writer) is untouched.
2. **No new mandatory dependency.** The graph backend is built from the
   existing tree-sitter chunking and stdlib. The `argyph` binary stays optional
   and absent-by-default; its adapter is a *future* `CodeGraph` implementation,
   not a requirement.
3. **The hallucination guards are kept and strengthened.** The LLM may only
   cite files that appear in the traced path or the graph neighborhood; the
   `min_confidence` / `speculative_threshold` filtering and the `(unknown)`
   fallback all remain. A traced path with no plausible fix site still yields
   `(unknown)`, never a fabricated guess.
4. **Confidence is evidence-grounded.** A fix site's confidence is a function
   of *measured* signals — distance from a triggered check's anchor, graph
   centrality on the path, whether the attack literally touched a path/syscall
   the code controls — not a free-floating LLM number. The LLM calibrates
   within bands; it does not invent the band.
5. **`interfaces/` is the contract firewall.** New shared types (`CodeGraph`
   protocol, `ExecutedPath`, `PathNode`, graph tables) land in `interfaces/`;
   `blue_team/` imports them read-only. The schema delta goes through the
   migration system (`schema_meta` exists).
6. **Degrade, don't fail.** If the graph is empty (codebase not indexed) the
   tracer falls back to the *current* keyword-query behavior, so the locator is
   never worse than today.

## 5. Architecture

```
   infra/codebase_indexer.py  ──chunks──►  code_chunks / code_chunks_vec
            │
            │  new: symbol/reference extraction pass over the same chunks
            ▼
   code_symbols / code_edges  ◄── CodeGraph (interface)
            │                         ├── PythonCodeGraph  (default, ships now)
            │                         └── ArgyphCodeGraph  (future, do not build)
            ▼
   blue_team/path_tracer.py
   ┌──────────────────────────────────────────────┐
   │ 1. anchor: map each triggered CheckResult +   │
   │    log line to a code symbol (entry anchors)  │
   │ 2. seed:   semantic search for the violation  │
   │    site (sink anchors)                        │
   │ 3. walk:   shortest path(s) anchor→sink over  │
   │    code_edges; collect on-path symbols        │
   │ 4. rank:   path proximity × graph centrality  │
   └───────────────────┬──────────────────────────┘
                       ▼  ExecutedPath (ordered PathNodes)
   blue_team/root_cause.py  (RootCauseLocator — internals rewritten)
   ┌──────────────────────────────────────────────┐
   │ LLM calibrates + explains fix sites drawn     │
   │ ONLY from the ExecutedPath / graph neighborhood│
   └───────────────────┬──────────────────────────┘
                       ▼
              RootCauseResult  (unchanged contract)
```

## 6. Components

Each module is one file with one responsibility.

### 6.1 `CodeGraph` interface (`interfaces/code_graph.py`, new)

- **Does:** Defines the read-only symbol-graph contract the tracer is written
  against, so the backend is swappable.
- **Interface (Protocol):**
  - `symbol_at(file: str, line: int) -> CodeSymbol | None`
  - `find_symbols(name: str) -> list[CodeSymbol]`
  - `callers(symbol_id: str) -> list[CodeEdge]`
  - `callees(symbol_id: str) -> list[CodeEdge]`
  - `shortest_paths(src: str, dst: str, max_hops: int) -> list[list[CodeEdge]]`
  - `available() -> bool`
- **Implementations:** `PythonCodeGraph` ships in this spec; `ArgyphCodeGraph`
  is named as a future implementation and **is not built here**.
- **Depends on:** `interfaces/types.py`.

### 6.2 `infra/codebase_indexer.py` — symbol/reference pass (extended)

- **Does:** A second pass after chunk indexing. For each chunk whose language
  has tree-sitter support, it extracts (a) the symbols *defined* in the chunk
  (function/method/class names — `function_name` is already captured) and (b)
  the symbols *referenced* in the chunk body (call expressions, identifier
  references). Definitions become `code_symbols` rows; (referencing symbol →
  resolved-or-unresolved target) becomes `code_edges` rows. Resolution is
  name-based within the indexed repo — coarse but sufficient to seed a path
  walk; unresolved references are kept as edges to a `?` target so the tracer
  can still see "this function calls *something* named X".
- **Interface:** `index_symbol_graph(db, *, root) -> dict` summary; runs after
  `index_codebase`, gated on the same `code_chunks` content sha so a re-index
  is a no-op.
- **Depends on:** the existing tree-sitter parser wrapper in the indexer,
  `infra/database.py`.
- **Note on tree-sitter:** this reuses `_ts_parser` and `_FN_NODE_TYPES`; it
  adds reference-node types (call expressions per language). No new parser, no
  new dependency.

### 6.3 `PythonCodeGraph` (`blue_team/code_graph_sqlite.py`, new)

- **Does:** The default `CodeGraph` backend, reading `code_symbols` /
  `code_edges` from SQLite. `shortest_paths` is a bounded BFS over the edge
  table (`max_hops` small, default 6). `available()` returns true iff
  `code_symbols` is non-empty.
- **Interface:** implements the §6.1 Protocol.
- **Depends on:** `infra/database.py`, `interfaces/code_graph.py`.

### 6.4 `blue_team/path_tracer.py` (new)

- **Does:** Reconstructs the `ExecutedPath`. Four stages:
  1. **Anchor (entry):** each triggered `CheckResult` and each relevant victim
     log line is mapped to a code symbol. Anchors come from the same evidence
     keys the current `_build_query` reads, but instead of becoming query
     keywords they are resolved to symbols via `CodeGraph.find_symbols` /
     `symbol_at` (e.g. a blocked syscall name → the symbol implementing that
     policy check; a write-outside-allowed path → the path-resolution symbol).
  2. **Seed (sink):** a semantic `search_codebase` over the violation
     description identifies the *sink* — where the boundary was crossed. This
     is the one place semantic search is still used, and only to seed a graph
     endpoint.
  3. **Walk:** `CodeGraph.shortest_paths(anchor, sink, max_hops)` for each
     anchor/sink pair; the union of on-path symbols is the executed-path
     candidate set.
  4. **Rank:** each `PathNode` scores on path proximity to the sink, graph
     centrality (how many anchor→sink paths cross it), and an evidence-touch
     bonus (the symbol controls a path/syscall/destination the attack literally
     hit).
- **Interface:** `trace(zone_id, evidence, transcript, victim_logs) ->
  ExecutedPath`.
- **Depends on:** `CodeGraph`, the MCP `search_codebase` tool,
  `interfaces/code_graph.py`.
- **Degradation:** if `CodeGraph.available()` is false, `trace` returns an
  `ExecutedPath` whose nodes are just the semantic-search hits with proximity
  scores only — i.e. the current locator behavior, wrapped in the new type.

### 6.5 `RootCauseLocator` — internals rewritten (`blue_team/root_cause.py`)

- **Does:** `locate(...)` keeps its signature and `RootCauseResult` output.
  Internally:
  1. Severity gate — **unchanged**.
  2. Call `PathTracer.trace(...)` → `ExecutedPath`.
  3. Build the LLM prompt from the *ranked path nodes* (and their source
     snippets) instead of a keyword-query result set. The `_RC_SYSTEM` prompt
     is revised: the model is told these are the regions the attack traversed,
     ordered entry→violation, and asked to (a) confirm which node is the fix
     site, (b) calibrate confidence *within the band the path rank already
     establishes*, and (c) emit the `trace` narrative — which can now be
     grounded in the real path rather than guessed.
  4. `_parse_response` — **largely unchanged**: the `min_confidence` filter,
     `(speculative)` tagging, sort, and `(unknown)` fallback all remain.
     Confidence becomes a blend of the path-rank score and the LLM's
     calibration (`confidence = w_path * path_rank + w_llm * llm_conf`,
     clamped), so a site can never score high purely on LLM say-so.
- **Interface:** unchanged — `locate(...) -> RootCauseResult`.
- **Depends on:** `PathTracer`, the existing `LLMClient` / MCP wiring,
  `RootCauseConfig` (extended with `path_rank_weight`, `llm_conf_weight`,
  `max_hops`).

## 7. Data model additions

All land in `interfaces/schema.sql` via the migration system; this spec ships
`infra/migrations/00X_code_graph.sql` (number sequenced by the migration
runner) and bumps `schema_version`.

- `code_symbols` — `symbol_id`, `chunk_id` (FK → `code_chunks`), `file_path`,
  `symbol_name`, `symbol_kind` (`function` | `method` | `class`), `line_start`,
  `line_end`, `language`, `indexed_at`.
- `code_edges` — `edge_id`, `src_symbol_id`, `dst_symbol_id` (nullable for an
  unresolved reference), `dst_name` (the referenced name, always present),
  `edge_kind` (`call` | `reference`), `resolved` (bool), `indexed_at`.
- `executed_paths` — one row per `locate()` trace: `path_id`, `finding_id`,
  `zone_id`, `anchor_symbols` (JSON), `sink_symbols` (JSON), `node_count`,
  `backend` (`python` | `argyph`), `degraded` (bool), `created_at`.

New `interfaces/types.py` / `interfaces/code_graph.py` types:

- `CodeSymbol` — `symbol_id`, `file_path`, `symbol_name`, `symbol_kind`,
  `line_start`, `line_end`, `language`.
- `CodeEdge` — `src_symbol_id`, `dst_symbol_id`, `dst_name`, `edge_kind`,
  `resolved`.
- `PathNode` — `symbol: CodeSymbol`, `proximity: float`, `centrality: float`,
  `evidence_touch: bool`, `rank_score: float`.
- `ExecutedPath` — `nodes: list[PathNode]` (ranked), `anchors: list[CodeSymbol]`,
  `sinks: list[CodeSymbol]`, `backend: str`, `degraded: bool`.

`FixSite` and `RootCauseResult` are **reused unchanged** — the new types feed
*into* the locator and never escape it.

## 8. Data flow

1. The orchestrator runs the codebase indexer against the victim's source
   (already a setup step). `index_symbol_graph` runs as a second pass →
   `code_symbols`, `code_edges`.
2. A high-severity finding reaches `Pipeline._process_one_finding`; it calls
   `RootCauseLocator.locate(...)` (severity-gated — unchanged).
3. `locate` calls `PathTracer.trace`:
   a. Evidence + logs → entry anchors via `CodeGraph.find_symbols` / `symbol_at`.
   b. Violation description → sink via one `search_codebase` call.
   c. `CodeGraph.shortest_paths` walks anchor→sink → on-path symbols.
   d. Nodes ranked; `ExecutedPath` persisted to `executed_paths`.
4. `locate` builds the LLM prompt from the ranked `ExecutedPath` nodes' source
   snippets, calls the LLM to confirm/calibrate/narrate.
5. `_parse_response` blends path-rank and LLM confidence, filters, tags
   speculative sites, sorts → `RootCauseResult`.
6. The pipeline puts `candidate_fix_sites` into
   `ReproPackageInput.affected_paths` and `patch_generator` consumes them —
   **exactly as today**.
7. **Degraded path:** if `CodeGraph.available()` is false (codebase not
   indexed), `trace` returns semantic-search hits only; `locate` proceeds with
   those, behaving like today's keyword locator. `executed_paths.degraded` is
   true so the regression is visible.

## 9. Integration points

- **`blue_team/root_cause.py`** — internals rewritten; signature and
  `RootCauseResult` unchanged. The only externally visible change is richer,
  more accurate `candidate_fix_sites` and a grounded `execution_trace`.
- **`infra/codebase_indexer.py`** — gains `index_symbol_graph`; the CLI
  `main()` calls it after `index_codebase`. The existing Argyph-backend branch
  in `main()` is untouched — when the (future) Argyph backend is configured it
  builds its own index, and `ArgyphCodeGraph` would read it; until then the
  Python pass runs.
- **`blue_team/pipeline.py`** — `Pipeline.__init__` constructs a `PathTracer`
  with a `PythonCodeGraph` and injects it into the `RootCauseLocator`. One new
  conditional; `RootCauseLocator` keeps a default tracer so existing tests that
  construct it directly still work.
- **`patch_generator.py` / `triage.py` / repro writer** — **no change.** They
  consume `FixSite` / `affected_paths`, whose shape is unchanged.
- **MCP** — `search_codebase` is still used (sink seeding + degraded fallback).
  No new MCP tool — the graph is read directly from SQLite by `PythonCodeGraph`,
  consistent with how the indexer writes `code_chunks` directly. (A future
  `CodeGraph` MCP tool is possible but not required and not in scope.)
- **Config** — `configs/monkeyclaw.yaml` `repro` block gains `code_graph`:
  `enabled` (default true), `max_hops` (default 6), `path_rank_weight` (0.5),
  `llm_conf_weight` (0.5).

## 10. Error handling

- **Codebase not indexed / `code_symbols` empty** → `CodeGraph.available()`
  false → tracer degrades to semantic-search-only; `executed_paths.degraded`
  true; one logged warning. Locator output is no worse than today.
- **No anchor resolves** (evidence maps to no symbol) → the tracer uses the
  sink and its graph neighborhood (callers of the sink) as the candidate set;
  `ExecutedPath` is still produced, lower-confidence.
- **No path found** anchor→sink within `max_hops` → the anchor symbols and the
  sink symbols are returned as separate unconnected nodes; the LLM is told the
  path is broken; confidence is capped in the speculative band.
- **Graph query raises** → caught; tracer degrades to semantic-search-only for
  that finding; alert logged. Never aborts `locate`.
- **LLM call fails** → existing behavior retained: `RootCauseResult` with the
  `(unknown)` `FixSite` and the error in `notes`.
- **Symbol-graph indexing fails for a file** → that file contributes chunks but
  no symbols/edges (logged at debug); the graph is partial, never absent. A
  partial graph still beats a keyword bag.

## 11. Why a graph and not a bigger keyword query

The current locator's ceiling is the recall of one vector query over a keyword
bag. Widening the bag or raising `top_k` adds noise faster than signal — the
root cause is frequently a *policy-check or path-resolution function that
contains none of the evidence strings*, reachable only by following a call edge
from code that does. A symbol graph is the minimum structure that makes that
function *reachable* from the evidence. It is built from data the indexer
already produces (tree-sitter chunks with function names); the only new work is
extracting references and persisting edges. This is the smallest change that
moves fix-site location from "code that mentions the evidence" to "code that
ran".

## 12. Testing strategy

Tests live in `test/` as `test_blue_root_cause_*.py` /
`test_infra_code_graph_*.py`, matching existing conventions.

- `test_infra_code_graph_index.py` — index a small fixture repo with a known
  call chain (`handler → resolve_path → policy_check`); assert `code_symbols`
  and `code_edges` rows match the expected definitions and call edges,
  including one unresolved reference.
- `test_blue_code_graph_sqlite.py` — `PythonCodeGraph.shortest_paths` finds the
  `handler → policy_check` path; `available()` is false on an empty DB.
- `test_blue_path_tracer.py` — given evidence anchored at `handler` and a sink
  at `policy_check`, `trace` returns an `ExecutedPath` whose ranked nodes put
  `policy_check` (the violation site) and `resolve_path` (on the path) above an
  off-path symbol. A second case with an unindexed codebase asserts the
  degraded path (`degraded=True`, semantic hits only).
- `test_blue_root_cause_traced.py` — with a fake `CodeGraph` and a stub LLM,
  assert `locate` returns fix sites drawn only from the `ExecutedPath`, that
  confidence is the path/LLM blend, and that the `(unknown)` fallback still
  fires when the path yields no plausible site.
- `test_blue_root_cause.py` (existing) — extended: assert the locator's output
  contract (`RootCauseResult`, `FixSite` shape, severity gate, speculative
  tagging, `(unknown)` fallback) is unchanged.
- `test_blue_root_cause_degraded.py` — assert that with no graph the locator
  behaves like the current keyword locator and never crashes.
- All tests run in mock mode with stub LLMs and local fixture repos — no
  NemoClaw, no `argyph` binary, zero credentials.

## 13. Phased delivery

- **Phase 0 — contracts:** `interfaces/code_graph.py` (`CodeGraph` Protocol,
  `CodeSymbol`, `CodeEdge`, `PathNode`, `ExecutedPath`), schema migration
  (`code_symbols`, `code_edges`, `executed_paths`), `schema_version` bump. No
  behavior.
- **Phase 1 — symbol graph:** `index_symbol_graph` in the indexer;
  `PythonCodeGraph` backend; indexer CLI runs the second pass. Verifiable via
  `code_symbols` / `code_edges` content.
- **Phase 2 — tracer:** `blue_team/path_tracer.py` with anchor → seed → walk →
  rank; `ExecutedPath` persisted; the degraded fallback.
- **Phase 3 — locator rewrite:** `RootCauseLocator` internals consume the
  `ExecutedPath`; revised `_RC_SYSTEM` prompt; confidence blend. Output
  contract unchanged; the existing root-cause tests still pass.
- **Phase 4 — pipeline wiring:** `Pipeline` constructs and injects the tracer;
  config knobs; dashboard shows the executed path on the finding detail view.
- **Later (not this spec):** an `ArgyphCodeGraph` `CodeGraph` implementation,
  *if and when* the Argyph CLI's `index`/`search` subcommands ship for real.
  Because the tracer is written against the `CodeGraph` Protocol, this is a
  drop-in backend with no tracer or locator change — which is the entire point
  of the interface, and the only role Argyph plays in this design.

## 14. Open questions

1. **Reference resolution fidelity.** Name-based resolution within one repo
   will mis-resolve overloaded names and miss dynamic dispatch. It is good
   enough to *seed* a path the LLM then confirms; if precision proves
   insufficient, a scoped type-aware pass (or the future Argyph backend, which
   has a real symbol graph) is the upgrade — no design change, just a better
   `CodeGraph`.
2. **`max_hops` tuning.** Default 6; too low misses deep paths, too high
   explodes the BFS and the prompt. The right value depends on the victim
   codebase shape and should be tuned on real findings in Phase 4.
3. **Victim log availability.** The tracer consumes victim logs as an anchor
   source when present. Today the only guaranteed signals are the transcript
   and `CheckResult` evidence; richer log anchoring strengthens the trace and
   improves once the real-nemoclaw-provisioner spec lands denser telemetry.
   The tracer works without logs — they are an additive anchor source, not a
   requirement.
