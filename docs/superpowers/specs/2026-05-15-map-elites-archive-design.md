# MAP-Elites Archive — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

MonkeyClaw's red team is a search process. Ideation generates candidate
attacks, priority scores them, execution runs them, and the judge plus
`red_team/progress.py` score how far each one got. The danger in every such
search is **collapse**: once one attack family (say, a `roleplay` framing of a
filesystem read) starts scoring well, history-informed ideation (Mode C) keeps
proposing variations of it, priority keeps ranking those variations highest,
and the loop converges. The architecture report names this directly in
*Source Document Synthesis > DOCX*:

> Use MAP-Elites archives so the system preserves diverse high-performing
> ideas across niches instead of converging on one attack family.

A converged red team has low coverage even when its score is high — it has
found one door and is repeatedly walking through it while seventeen other
zones and five other interaction styles go unprobed. MAP-Elites is the
standard answer: instead of keeping a single ranked population, keep a **grid
of niches** and the single best ("elite") attempt per niche. A breakthrough in
one niche can never displace the elite of another, so diversity is structural,
not a tuning knob.

The grid already exists in three places. This spec **completes** the wiring
between them rather than introducing the archive — see §3 for the precise
already-built vs. new accounting.

## 2. The niche model

A niche is a bin over **behavioural descriptors** of a finished attack — what
the attack *did*, observed after execution, not what the idea *intended*. An
attack lands in exactly one cell. The cell key is:

```
(zone, interaction_style, response_movement)
```

- **`zone`** — one of the 18 attack-surface zones (`SBX-FS`, `PROMPT-INJ`, …).
- **`interaction_style`** — *how* the attack engaged: one of the six values in
  `red_team/archive.INTERACTION_STYLES` (`direct`, `indirect`, `roleplay`,
  `multi_turn`, `tool_use`, `context_injection`). Carried on the idea as
  `IdeaTactics.interaction_style` from ideation.
- **`response_movement`** — *how the victim moved*: one of the six values in
  `red_team/archive.RESPONSE_MOVEMENTS` (`refusal`, `soft_refusal`,
  `abstract_engagement`, `partial_compliance`, `strong_compliance`,
  `programmatic_violation`). Derived post-execution from the
  `ProgressScore.failure_mode` via `routing._FAILURE_TO_MOVEMENT`.

Two further descriptors ride on each archive entry as **secondary metadata**
(not part of the cell key, used for analysis and seeding): `turn_bucket`
(`0-2` / `3-7` / `8-15` / `16+`, from `archive.turn_bucket`) and
`transfer_score`. Promoting either into the cell key is an explicit
out-of-scope decision — see §3.

Within a cell, the **elite** is the entry with the highest `search_score`
(from `red_team/progress.py`). Replacement is strictly within-cell and
strictly score-greater: a higher score in a `direct`/`refusal` cell cannot
evict the `multi_turn`/`partial_compliance` elite.

## 3. Scope — already built vs. new

This subsystem is **partially built**. The spec completes it; it does not
rebuild it.

### Already built (do not re-implement)

- **`red_team/archive.py`** — the in-memory `EliteArchive` class, the
  `ArchiveEntry` dataclass with cell-key validation, `consider()` (place /
  strict-greater replace), `get_elite()`, `elites_for_zone()`, `all_elites()`,
  `snapshot()`, `cell_count()`, and the `turn_bucket()` helper. The two axis
  vocabularies (`INTERACTION_STYLES`, `RESPONSE_MOVEMENTS`) are defined here.
- **`interfaces/schema.sql`** — the `idea_archive_cells` table (`cell_id`,
  `zone_id`, `interaction_style`, `response_movement`, `best_idea_id`,
  `best_score`, `occupancy`, `updated_at`) and the `idea_components` table
  (`component_id`, `idea_id`, `component_type`, `content`, `created_at`), both
  with grid indexes.
- **`interfaces/types.py`** — `ArchiveCell`, `ArchiveUpdateInput`,
  `IdeaComponent`, `IdeaComponentInput`.
- **`interfaces/mcp_tools.py`** — the `update_archive_cell`,
  `get_archive_cells`, `store_idea_components`, `get_idea_components` tool
  signatures.
- **`red_team/routing.py`** — on **every** routed judgment, builds an
  `ArchiveEntry` (`_archive_entry`), calls `archive.consider()`, and mirrors
  the entry into the persistent grid via `_persist_archive` (which calls
  `update_archive_cell` + `store_idea_components`). The in-memory archive
  instance lives on `Pipeline._archive` and is threaded through `route_judgment`.

So: the archive is **updated correctly on every execution**, and it is
**persisted**. What is missing is everything that *reads* it.

### New in this spec

1. **`red_team/archive_seed.py`** — niche-aware ideation seeding: select elites
   from across cells, including cross-cell combination, and shape them into
   prompt context for `IdeationEngine`.
2. **Archive load on startup** — `EliteArchive` is created empty every process.
   It must rehydrate from `idea_archive_cells` so the niche grid survives
   restarts. New `EliteArchive.load_from_cells()` classmethod plus a
   `get_archive_cells` read in `Pipeline.__init__`.
3. **Priority integration** — `red_team/priority.py` gains an optional
   archive-driven `niche_gap` factor so the search is pulled toward empty and
   weak niches, not only low-coverage zones.
4. **Ideation wiring** — `IdeationEngine.generate_for_zone` accepts an optional
   seed block; `red_team/pipeline.py` builds it from the archive each cycle.
5. **One schema delta** — a `niche_descriptors` JSON column on
   `idea_archive_cells` to carry the secondary metadata (`turn_bucket`,
   `transfer_score`, `tactic_tags`, `model`) so the persistent grid is a
   faithful mirror of the in-memory entry. Today those fields are lost on
   persistence.

### Explicitly out of scope (YAGNI)

- Promoting `turn_bucket` or `novelty` into the cell key (a 4-dimensional
  grid). The 3-axis grid is already 18 × 6 × 6 = 648 cells; a 4th axis
  multiplies sparsity before there is data to justify it. Revisit when the
  grid is densely occupied.
- Curiosity / illumination metrics (QD-score, coverage-over-time plots) beyond
  the simple `cell_count()` already exposed.
- A learned model that predicts which niche an idea will land in. The
  trajectory-scoring spec notes this as future work; the archive consumes
  whatever descriptors exist today.
- Archive pruning / aging. Cells are cheap; an elite that stops being
  reproducible is a trajectory-scoring concern (robustness), not an archive
  concern.
- Per-niche execution budgeting in the lane scheduler.

## 4. Design constraints

1. **`interfaces/` stays the contract firewall.** The one schema delta
   (`niche_descriptors`) and any type change land in `interfaces/` via the
   versioned migration system; `schema_meta` already tracks `schema_version`
   (currently `'2'`). `red_team/` imports from `interfaces/` read-only.
2. **The in-memory `EliteArchive` is the source of truth within a process;
   `idea_archive_cells` is its durable mirror.** Reads during a run go to the
   in-memory object (fast, no IO). The persistent grid exists to survive
   restarts and to feed the dashboard. The two must not diverge: every
   `consider()` is followed by a `_persist_archive`, and startup rehydrates
   in-memory from persistent.
3. **Descriptors are observed, never intended.** `response_movement` comes from
   the executed `ProgressScore`, never from the idea's stated goal. An idea
   that *planned* a `programmatic_violation` but only drew a `soft_refusal`
   lands in the `soft_refusal` cell. This is what keeps the grid honest.
4. **The archive never blocks the red/blue path.** A persistence failure logs
   an alert and is swallowed (routing already does this); seeding failure
   degrades to current single-zone ideation.
5. **One module, one responsibility.** Seeding logic is its own file
   (`archive_seed.py`); it does not leak into `archive.py` (the data
   structure) or `ideation.py` (the prompt engine).

## 5. Architecture

```
   ┌──────────────────────── red cycle ─────────────────────────┐
   │                                                            │
   │  archive_seed.build_seed(archive, zone) ──► seed block      │
   │           │                                    │           │
   │           │ elites from sibling cells          ▼           │
   │           │ + cross-cell combinations    IdeationEngine     │
   │           │                              .generate_for_zone │
   │           ▼                                    │           │
   │  priority.score_ideas(..., archive) ◄──────────┘           │
   │           │ niche_gap factor                                │
   │           ▼                                                 │
   │     execution ──► judge ──► progress.score_progress         │
   │                                  │                          │
   │                                  ▼                          │
   │           routing.route_judgment(progress, archive)          │
   │                    │                      │                 │
   │     archive.consider(ArchiveEntry)   _persist_archive        │
   │            (in-memory grid)                │                 │
   └────────────────────────────────────────────┼────────────────┘
                                                 ▼
                              idea_archive_cells  +  idea_components
                                                 │
                          Pipeline startup: EliteArchive.load_from_cells
                                                 │
                                                 ▼
                                  dashboard niche heatmap (additive)
```

## 6. Components

Each module is a single file with one clear responsibility.

### 6.1 `red_team/archive.py` — extended (mostly built)

- **Already does:** the `EliteArchive` data structure and `ArchiveEntry` —
  see §3. No change to `consider()`, `get_elite()`, or the validation logic.
- **New:** two read-side methods and one constructor.
  - `empty_cells(zone, styles, movements) -> list[tuple]` — returns the niche
    keys for `zone` that have **no** elite, given the candidate style/movement
    vocabularies. This is the structural exploration signal.
  - `weak_cells(zone, threshold) -> list[ArchiveEntry]` — elites whose
    `search_score` is below `threshold`; niches that are occupied but only by
    a poor attempt, i.e. worth another push.
  - `load_from_cells(cells: list[ArchiveCell]) -> EliteArchive` — classmethod
    that rebuilds an in-memory archive from persisted rows. Each `ArchiveCell`
    becomes one `ArchiveEntry` reconstructed from `best_idea_id`, `best_score`,
    and the new `niche_descriptors` JSON. Rows whose `best_idea_id` is `NULL`
    (occupied counter but never an elite) are skipped.
- **Interface:** as above plus the existing public surface.
- **Depends on:** stdlib only, `interfaces.types.ArchiveCell` (read-only) for
  `load_from_cells`. The data-structure core stays dependency-light by design.

### 6.2 `red_team/archive_seed.py` — new

- **Does:** turns the archive into ideation **seed context**. Two strategies,
  combined into one seed block:
  - **Elite recall** — pull the top-scoring elites for the target zone via
    `archive.elites_for_zone(zone)`, plus a small diverse sample of elites from
    *other* zones that share an `interaction_style` with the target zone's
    occupied cells. This gives Mode C concrete winners to vary.
  - **Cross-cell combination** — pick pairs of elites from **different cells**
    (different `interaction_style` or different `response_movement`) and emit a
    combination directive: "combine the framing of elite A with the escalation
    of elite B". This is the MAP-Elites recombination operator and the direct
    counterpart to `red_team/mutations._combine_two_ideas`.
  - **Empty-niche prompts** — for each key from `archive.empty_cells(zone, …)`,
    emit a directive naming the unfilled `(interaction_style,
    response_movement)` pair so ideation deliberately aims at blank niches.
- **Interface:**
  - `build_seed(archive, zone_id, *, cfg) -> ArchiveSeed` — produces the
    structured seed (elites, combination pairs, empty-niche targets).
  - `render_seed(seed) -> str` — formats `ArchiveSeed` into the prompt text
    block `IdeationEngine` appends.
  - `ArchiveSeed` is a red-team-local dataclass (not an `interfaces/` type — it
    never crosses a package boundary, same rationale as `IdeaTactics`).
- **Depends on:** `red_team/archive.py`, `red_team/ideation.IdeaTactics` (for
  `interaction_style`). No LLM, no IO — pure shaping, unit-testable.

### 6.3 `red_team/ideation.py` — extended

- **Already does:** the three prompt modes; Mode C already pulls confirmed
  findings and `suspicious`-verdict near-misses via `search_findings`.
- **New:** `generate_for_zone` and the three `_mode_*` methods accept an
  optional `seed: str = ""` argument. When present it is appended to the Mode A
  and Mode C user prompts under a `# Archive — Diverse Elites & Open Niches`
  header, *before* `_JSON_SCHEMA_BLURB`. Mode B (code-grounded) ignores the
  seed — it is grounded in source, not in attack history. Absent seed → exact
  current behaviour (backward compatible).
- **Depends on:** unchanged; `archive_seed` output is passed in as a string by
  the pipeline, so `ideation.py` gains no new import.

### 6.4 `red_team/priority.py` — extended

- **Already does:** `priority = novelty × impact × coverage_gap ×
  severity_weight`, sort descending, `select_top_n`.
- **New:** an optional `archive` parameter to `score_ideas` / `select_top_n`.
  When supplied, a fifth factor `niche_gap ∈ [0.5, 1.5]` multiplies the score:
  - The idea's intended niche key is `(zone_id,
    IdeaTactics.interaction_style, expected response_movement)`. Response
    movement is not yet known pre-execution, so the niche-gap factor is
    computed over the `(zone_id, interaction_style)` **column** of the grid:
    if that column has empty cells, `niche_gap > 1.0` (boost — unexplored
    interaction style); if every cell in the column is occupied by a strong
    elite, `niche_gap < 1.0` (damp — that style is already well-mined).
  - Absent `archive` → `niche_gap = 1.0`, i.e. current behaviour exactly. The
    `components` dict on `PrioritizedIdea` gains a `niche_gap` entry only when
    the archive was supplied.
- **Rationale:** `coverage_gap` steers toward under-tested *zones*;
  `niche_gap` steers toward under-tested *styles within a zone*. Together they
  are the two-dimensional exploration pressure the DOCX vision asks for.
- **Depends on:** `red_team/archive.py` (read-only, optional import guarded so
  `priority` still works archive-free).

### 6.5 `red_team/routing.py` — extended (mostly built)

- **Already does:** builds an `ArchiveEntry` per routed judgment, calls
  `archive.consider()`, mirrors via `_persist_archive` →
  `update_archive_cell` + `store_idea_components`.
- **New:** `_persist_archive` also writes the new `niche_descriptors` JSON
  (`turn_bucket`, `transfer_score`, `tactic_tags`, `model`) on the
  `ArchiveUpdateInput` so the persisted cell can be faithfully rehydrated by
  `load_from_cells`. This requires the §8 schema delta and a one-field
  addition to `ArchiveUpdateInput`.

### 6.6 `red_team/pipeline.py` — extended

- **Already does:** owns `self._archive = EliteArchive()`; threads it into
  `route_judgment`.
- **New:**
  - In `__init__`, after the MCP is available: `cells =
    mcp.get_archive_cells(zone=None)` then `self._archive =
    EliteArchive.load_from_cells(cells)` — rehydrate instead of starting empty.
  - Before ideation for the cycle's zone: `seed =
    archive_seed.render_seed(archive_seed.build_seed(self._archive, zone_id,
    cfg=...))` and pass `seed=seed` into `generate_for_zone`.
  - Pass `archive=self._archive` into `priority.select_top_n`.

## 7. Data flow per cycle

1. **Startup (once):** `Pipeline.__init__` calls `get_archive_cells(None)` and
   `EliteArchive.load_from_cells(...)` — the in-memory grid is rehydrated.
2. Orchestrator selects the lowest-coverage zone (unchanged).
3. `archive_seed.build_seed` reads the in-memory archive: elites for the zone,
   cross-zone elites sharing a style, cross-cell combination pairs, empty-niche
   targets. `render_seed` formats it.
4. `IdeationEngine.generate_for_zone(zone, cycle_id, seed=seed)` runs the three
   modes; Mode A and Mode C see the seed block.
5. Dedup runs (unchanged).
6. `priority.select_top_n(outcomes, zones, n, archive=self._archive)` applies
   the `niche_gap` factor and ranks.
7. Execution and judging run; `progress.score_progress` scores each lane.
8. `routing.route_judgment(judgment, idea, mcp, progress=…,
   archive=self._archive)` builds the `ArchiveEntry`, calls `consider()`
   (in-memory update), and `_persist_archive` mirrors it — now including
   `niche_descriptors`.
9. Next cycle's `build_seed` sees the freshly placed elites — the loop is
   closed and diversity-aware.

## 8. Data model additions

One schema delta, applied through the versioned migration system (bump
`schema_meta.schema_version` from `'2'` to `'3'`):

- **`idea_archive_cells`** — add column
  `niche_descriptors TEXT NOT NULL DEFAULT '{}'`. A JSON object holding the
  secondary descriptors of the cell's current elite: `turn_bucket`,
  `transfer_score`, `tactic_tags` (list), `model`. Nullable-safe via the
  default, so the migration is backward compatible and existing rows read as
  `{}`.

`interfaces/types.py` changes:

- `ArchiveCell` — add `niche_descriptors: dict[str, Any] = field(...)`.
- `ArchiveUpdateInput` — add `niche_descriptors: dict[str, Any] =
  field(default_factory=dict)`.

No new tables. `idea_components` is reused as-is; `routing._persist_archive`
already writes `interaction_style` / `response_movement` / `tactic_tags`
component rows.

`ArchiveSeed` is a red-team-local dataclass in `archive_seed.py` and is
**not** added to `interfaces/` — it never crosses a package boundary.

## 9. Integration points

- **`red_team/pipeline.py`:** three small additions (§6.6). No new module
  imported into the orchestrator.
- **`red_team/ideation.py`:** one optional `seed` argument; backward compatible.
- **`red_team/priority.py`:** one optional `archive` argument; backward
  compatible.
- **`interfaces/mcp_tools.py`:** no signature change — `get_archive_cells`,
  `update_archive_cell`, `store_idea_components` already exist. The mock and
  real MCP implementations gain handling for the new `niche_descriptors` field
  on `ArchiveUpdateInput` / `ArchiveCell`.
- **Dashboard:** one additive view — the niche heatmap (zone × interaction_style
  occupancy and elite scores), read from `get_archive_cells`. The architecture
  report already lists "MAP-Elites archive heatmap" as a planned panel.

## 10. Error handling

- **Persistence failure** (`update_archive_cell` / `store_idea_components`
  raising): already swallowed with an alert in `routing.route_judgment`'s
  archive block; the in-memory archive is still updated, so the cycle is
  unaffected. Unchanged.
- **Rehydration failure** at startup (`get_archive_cells` raising, or a malformed
  `niche_descriptors` JSON): `load_from_cells` logs an alert and returns an
  empty `EliteArchive`. The run proceeds with a cold archive and refills it —
  a worse exploration profile for one run, never a crash.
- **Unknown descriptor value** in a persisted cell (an `interaction_style` that
  is no longer in the vocabulary after a code change): `load_from_cells` skips
  that cell with a logged warning rather than raising — `ArchiveEntry`'s
  `__post_init__` validation would otherwise abort rehydration.
- **Seeding failure** (`build_seed` / `render_seed` raising): caught in
  `pipeline.py`; ideation runs with `seed=""`, i.e. current behaviour.
- **Empty archive** (first ever run): `build_seed` returns an `ArchiveSeed`
  with no elites and all niches "empty"; `render_seed` produces a short block
  that simply lists the open niches — still useful guidance.

## 11. Testing strategy

Tests under `test/`, `test_red_*` naming convention.

- **`test_red_archive.py`** (extends existing coverage of `archive.py`):
  `empty_cells` returns exactly the unoccupied keys; `weak_cells` respects the
  threshold; `load_from_cells` round-trips `snapshot()` output through
  reconstructed `ArchiveCell`s; `load_from_cells` skips `NULL`-elite and
  invalid-vocabulary rows without raising.
- **`test_red_archive_seed.py`:** `build_seed` on a hand-built archive yields
  the expected elites, cross-cell combination pairs (always from *different*
  cells), and empty-niche targets; `render_seed` is deterministic and produces
  no prose outside the documented header; empty-archive path produces a valid
  seed.
- **`test_red_priority.py`** (extends existing): with `archive=None`, scores
  are byte-identical to today (regression guard); with an archive, an idea in
  an empty interaction-style column outranks an otherwise-identical idea in a
  saturated column; `niche_gap` stays within `[0.5, 1.5]`.
- **`test_red_routing.py`** (extends existing): `_persist_archive` now passes
  `niche_descriptors`; assert `turn_bucket` and `tactic_tags` survive a
  persist → `get_archive_cells` → `load_from_cells` round trip.
- **`test_red_pipeline.py`** (extends existing): a two-cycle mock run — assert
  cycle 2's ideation prompt contains the elite placed in cycle 1, and that the
  rehydrated archive at startup is non-empty when the DB has cells.
- All in mock mode, zero model credentials, consistent with the repo's demo
  posture. `score_progress` and `archive` are already pure — seed building and
  priority must stay pure too, so every test runs without an LLM.

## 12. Phased delivery

- **Phase 0 — schema + types:** `niche_descriptors` migration (version 2→3),
  `ArchiveCell` / `ArchiveUpdateInput` field additions, mock/real MCP handling.
  No behaviour change.
- **Phase 1 — persistence fidelity & rehydration:** `routing._persist_archive`
  writes `niche_descriptors`; `EliteArchive.load_from_cells`; `pipeline`
  rehydrates on startup. The persistent grid now faithfully mirrors in-memory
  and survives restarts.
- **Phase 2 — read side:** `archive.empty_cells` / `weak_cells`;
  `red_team/archive_seed.py`; `ideation` gains the `seed` argument; `pipeline`
  builds and passes the seed. Ideation is now niche-aware.
- **Phase 3 — priority pressure:** `priority` gains the optional `archive`
  argument and the `niche_gap` factor; `pipeline` passes the archive in.
- **Phase 4 — visibility:** the dashboard niche heatmap.

Each phase is independently verifiable and leaves the pipeline runnable.

## 13. Open questions

1. **`niche_gap` bounds and curve.** The `[0.5, 1.5]` multiplier band and
   whether the gap is linear or stepped in the column's empty-cell fraction is
   a tuning question. It should be a config value (`red.archive.niche_gap_*`)
   so it can be adjusted without a code change once there is run data.
2. **Cross-zone seed breadth.** How many other-zone elites to include in the
   seed, and whether to weight them by shared `interaction_style` only or also
   by `tactic_tags` overlap. Start with a small fixed count; revisit when the
   grid is dense enough for the choice to matter.
3. **Pre-execution niche prediction.** `response_movement` is only known after
   execution, so `niche_gap` currently works on the `(zone, style)` column.
   A learned model predicting the landing cell from idea features (flagged as
   future work in the trajectory-scoring spec) would let `niche_gap` use the
   full 3-axis key. No design rework is needed to adopt it later.

## 14. Companion documents recommended

- An architecture-report update folding the completed archive read-path into
  the documented red search loop (the report currently lists the archive as a
  gap).
