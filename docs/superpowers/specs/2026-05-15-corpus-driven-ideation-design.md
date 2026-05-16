# Corpus-Driven Ideation — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

MonkeyClaw's ideation engine (`red_team/ideation.py`) generates attack ideas
from three prompt modes — creative divergence, code-grounded, and
history-informed. Each mode is steered by the zone description and, at most,
the failure-class hint from `docs/zone_failure_class_mapping.md`. This produces
plausible attacks, but it leaves two gaps the architecture report
(`docs/monkeyclaw_full_architecture_report.md`, §3 "Target pipeline additions")
calls out explicitly:

> Add OWASP/MITRE/PDF corpus-driven attack generation.

The two gaps:

1. **No externally-credible coverage measurement.** A green zone today means
   "MonkeyClaw exercised this zone N times and the coverage decay model is
   satisfied." It does not mean "MonkeyClaw exercised the *recognised
   adversarial techniques* that apply to this zone." A security buyer, a
   reviewer, or a regression audit cannot map MonkeyClaw's coverage onto any
   standard taxonomy. Coverage is self-referential.

2. **Idea generation is unanchored.** The creative mode is told to avoid
   "textbook attack categories"; the practical effect is that the generator
   has no systematic enumeration of the technique space and re-discovers the
   same families by chance while missing others entirely. There is no forcing
   function that says "you have never tried an ATLAS *LLM Prompt Injection:
   Indirect* technique against `PROMPT-INJ`."

The fix is to seed ideation from two established external adversarial
taxonomies — **MITRE ATLAS** and the **OWASP LLM Top 10** — and to tag every
generated idea and every confirmed finding with the technique IDs / category
IDs it corresponds to. Coverage then has a second, standardised axis:
*technique coverage*. "We have exercised 61 of the 84 ATLAS techniques that map
to our 18 zones" is a claim an outsider can verify.

This is the same shape as the purple-team spec's detection-coverage axis
(`docs/superpowers/specs/2026-05-15-purple-team-design.md`, §7.2): a second
coverage dimension that makes an existing self-referential metric externally
legible.

## 2. The taxonomy-as-corpus model

ATLAS and the OWASP LLM Top 10 are published, versioned documents. MITRE ATLAS
v5.4.0 enumerates 16 tactics, 84 techniques, and 56 sub-techniques, including 14
agent-specific techniques (memory manipulation, prompt-injection variants, tool
abuse, and similar). The OWASP LLM Top 10 enumerates ten risk categories
(LLM01–LLM10). Both update on their own cadence — roughly twice a year.

MonkeyClaw must **not** treat either as a live dependency. The red loop runs
perpetually, often inside a sandbox with restricted egress, and must be
deterministic for the demo. Therefore:

- The taxonomies are vendored as a **local, version-pinned corpus** under
  `red_team/corpora/` — a small set of curated YAML/JSON files committed to the
  repo, exactly the way `demo/attacks/policy_corpus.yaml` is already a
  committed corpus consumed by `red_team/policy_corpus.py`.
- A separate, **offline refresh tool** (`scripts/refresh_taxonomy_corpus.py`,
  run by a human, never by the loop) regenerates those files from the upstream
  sources and bumps a corpus version string. The loop only ever reads the
  vendored snapshot.

This is the same principle the purple-team spec applies to NemoClaw control
specifics (constraint §4.2 there): reuse the *shapes* of external standards
without coupling the runtime to them.

## 3. Scope

In scope:

- A vendored `red_team/corpora/` directory holding the ATLAS and OWASP
  snapshots plus the zone↔technique mapping, all version-pinned.
- A `red_team/taxonomy.py` module: loader, validation, and query API over the
  corpus — peer to the existing `red_team/policy_corpus.py`.
- A zone↔ATLAS-technique mapping for all 18 MonkeyClaw zones, and a
  zone↔OWASP-category mapping, authored once and committed.
- Taxonomy-seeded ideation: a fourth ideation mode (`taxonomy`) that
  systematically walks under-covered techniques for the cycle's zone, plus
  enrichment of the existing three modes with technique context.
- Technique tagging of every `IdeaObject` and every confirmed `FindingRecord`.
- A **technique-coverage** model: a second coverage axis per zone, scored over
  ATLAS technique IDs and OWASP categories.
- An offline `scripts/refresh_taxonomy_corpus.py` refresh tool.
- A companion doc, `docs/zone_atlas_mapping.md`.

Explicitly out of scope (YAGNI for this spec):

- Live API calls to MITRE or OWASP from inside the loop — the corpus is always
  the vendored snapshot.
- Auto-generating the zone↔technique mapping with an LLM — the mapping is
  human-authored and reviewed; it is small (18 zones) and load-bearing.
- Cross-zone technique chaining — that is the cross-zone attack-chaining spec
  (`2026-05-15-cross-zone-attack-chaining-design.md`).
- A learned model that predicts which technique to try next — that is the
  learned-ranking-model spec (`2026-05-15-learned-ranking-model-design.md`);
  until then, technique selection is heuristic (coverage-gap driven).
- PyRIT / other tool integration — ATLAS and OWASP only for this spec.

## 4. Design constraints

1. **The taxonomy corpus is read-only at runtime.** The loop never writes to
   `red_team/corpora/` and never reaches the network for taxonomy data. Only
   the offline refresh tool writes those files.
2. **`interfaces/` stays the contract firewall.** New shared types
   (`TechniqueRef`, `TechniqueCoverage`) and the schema delta land in
   `interfaces/`; `red_team/` imports them read-only, exactly as
   `red_team/policy_corpus.py` imports `IdeaObject` today.
3. **Tagging degrades gracefully.** An idea or finding with no resolvable
   technique tag is still valid — it is recorded with an empty tag set and
   surfaces as "untagged" in the coverage view. Ideation never fails because a
   technique could not be matched.
4. **The corpus is versioned and the version is recorded.** Every technique tag
   carries the corpus version that produced it, so a coverage report is
   reproducible and a taxonomy refresh is auditable.
5. **Build on what exists, do not replace it.** `red_team/policy_corpus.py`
   already loads a committed adversarial corpus and lifts it into `IdeaObject`s;
   `red_team/playbooks.py` already loads committed YAML attacks. The taxonomy
   module follows the same pattern and the same file layout. The three existing
   ideation modes are *enriched*, not rewritten.

## 5. Architecture

```
  red_team/corpora/  (vendored, version-pinned, read-only at runtime)
    atlas_v5.4.0.yaml          OWASP_llm_top10.yaml
    zone_atlas_mapping.yaml    corpus_meta.yaml
            │
            ▼
     taxonomy.py  ── load + validate + query API
       │      │
       │      └────────────► technique_coverage.py
       │                       (2nd coverage axis per zone)
       ▼
   ideation.py
     mode A/B/C  ──enriched with technique context──┐
     mode "taxonomy"  ──walks under-covered techniques┤
                                                      ▼
                                              IdeaObject + TechniqueRef[]
                                                      │
                                          dedup → priority → strategist → execute
                                                      │
                                              judge → routing
                                                      │
                                       FindingRecord tagged with TechniqueRef[]
                                                      │
                                          technique_coverage.update(...)

  scripts/refresh_taxonomy_corpus.py  ──(human-run, offline)──► rewrites corpora/
```

## 6. Components

Each module is a single file with one clear responsibility.

### 6.1 `red_team/corpora/` — the vendored corpus

- **Is:** A directory of committed data files, not code. Four files:
  - `atlas_v5.4.0.yaml` — the ATLAS snapshot: every tactic, technique, and
    sub-technique as `{id, name, tactic, parent_id, description, is_agentic}`.
    `is_agentic` flags the 14 agent-specific techniques.
  - `owasp_llm_top10.yaml` — the ten OWASP LLM categories as
    `{id, name, description}` (`LLM01` … `LLM10`).
  - `zone_atlas_mapping.yaml` — for each of the 18 zones, the list of ATLAS
    technique IDs and OWASP category IDs that apply (see §10).
  - `corpus_meta.yaml` — `{atlas_version, owasp_version, refreshed_at,
    refreshed_by, source_urls}`. This is the corpus version recorded on every
    tag.
- **Why a directory of data, not constants in a module:** it is regenerated by
  an offline tool, diffs cleanly in review, and matches the existing
  `demo/attacks/` convention.

### 6.2 `red_team/taxonomy.py` — corpus loader and query API

- **Does:** Loads and validates the four corpus files into in-memory
  dataclasses; exposes a query API. Validation rejects: unknown zone IDs,
  technique IDs in the mapping that are absent from the ATLAS snapshot, OWASP
  IDs outside `LLM01`–`LLM10`, and a missing `corpus_meta.yaml`. This mirrors
  `red_team/policy_corpus.py`'s `_validate_case` discipline.
- **Interface:**
  - `load_taxonomy(path=None) -> Taxonomy` — parse + validate; raises
    `ValueError` on malformed data.
  - `Taxonomy.techniques_for_zone(zone_id) -> list[Technique]`
  - `Taxonomy.owasp_for_zone(zone_id) -> list[OwaspCategory]`
  - `Taxonomy.technique(technique_id) -> Technique | None`
  - `Taxonomy.resolve(text) -> list[TechniqueRef]` — best-effort match of a
    free-text idea title/approach to technique IDs, by name and keyword; used
    to tag LLM-generated ideas that did not self-report a clean ID.
  - `Taxonomy.version -> str` — the `corpus_meta` version string.
- **Depends on:** `interfaces/types.py` (`TechniqueRef`), PyYAML (already a
  dependency via `playbooks.py`).

### 6.3 `red_team/ideation.py` — enriched, plus a fourth mode (COMPLETES existing module)

`red_team/ideation.py` already exists with the three modes A/B/C and the
`IdeaTactics` enrichment object. This spec adds to it; it does not rewrite it.

- **Enrichment of modes A/B/C:** each mode's user prompt gains a *technique
  context block* — the ATLAS techniques and OWASP categories mapped to the
  cycle's zone, with the under-covered ones marked. The `_JSON_SCHEMA_BLURB`
  gains two optional fields the model is asked to populate:
  `atlas_technique_ids` (list) and `owasp_category_ids` (list). When the model
  omits or garbles them, `Taxonomy.resolve()` backfills from the idea text —
  the same backfill pattern Mode B already uses for `relevant_files`
  (`ideation.py` lines 292–297).
- **New `taxonomy` mode (Mode D):** a deterministic, low-temperature mode that
  is *not* free brainstorming. It asks `technique_coverage` for the cycle
  zone's least-covered techniques, and for each one prompts the model to
  instantiate that specific ATLAS technique against the zone. This is the
  forcing function: it guarantees systematic walk of the technique space rather
  than chance re-discovery. It is structurally analogous to
  `red_team/policy_corpus.py::corpus_to_ideas` — corpus entry in, `IdeaObject`
  out — but here the corpus entry is a technique and the model fills the gap
  between the technique and a concrete zone attack.
- **Tagging:** `_parse_ideas` is extended to attach a `list[TechniqueRef]` to
  each `IdeaObject` (see §8 for the type). Tags are folded into `novelty_notes`
  with a sentinel — `[atlas=AML.T0051,AML.T0051.000; owasp=LLM01]` — exactly
  the way `IdeaTactics` is folded in today (`ideation.py` lines 433–441), so
  the tags survive `log_idea` persistence without a contract change to
  `IdeaObject`.
- **Interface:** unchanged public surface — `IdeationEngine.generate_for_zone`
  still returns `list[IdeaObject]`; the new mode is added to the default
  `modes` tuple. A new module-level helper, `taxonomy_ideas(...)`, parallels
  the existing `playbook_ideas(...)` and `tournament_ideas(...)` hooks.
- **Depends on:** `red_team/taxonomy.py`, `red_team/technique_coverage.py`.

### 6.4 `red_team/technique_coverage.py` — the second coverage axis

- **Does:** Maintains, per zone, a **technique-coverage** score: of the ATLAS
  techniques and OWASP categories mapped to a zone, how many have been
  *exercised* (an idea tagged with that technique was executed) and how many
  have been *confirmed* (a finding tagged with that technique). Produces the
  technique-coverage map the dashboard and report consume.
- **Interface:**
  - `record_attempt(zone_id, technique_refs)` — called from routing for every
    judged attempt.
  - `record_confirmation(zone_id, technique_refs)` — called for confirmed
    findings.
  - `coverage(zone_id) -> TechniqueCoverage` — exercised / confirmed / total
    counts and the ratio.
  - `gaps(zone_id, top_n) -> list[TechniqueRef]` — the least-covered techniques
    for a zone; this is what Mode D consumes.
  - `map() -> list[TechniqueCoverage]` — the whole-surface view.
- **Depends on:** `red_team/taxonomy.py`, the `technique_coverage` and
  `idea_techniques` tables (§8).

### 6.5 `scripts/refresh_taxonomy_corpus.py` — offline refresh tool

- **Does:** A standalone, human-run script (never invoked by the loop) that
  fetches the current ATLAS and OWASP sources, normalises them into the
  `red_team/corpora/` file shapes, bumps `corpus_meta.yaml`, and prints a diff
  summary (techniques added/removed/renamed) for the operator to review before
  committing. It does **not** auto-commit and does **not** touch
  `zone_atlas_mapping.yaml` — when a refresh adds a new technique, the script
  flags it as "unmapped" so a human extends the mapping deliberately.
- **Interface:** CLI — `python scripts/refresh_taxonomy_corpus.py [--dry-run]`.
- **Depends on:** network access (operator's machine only), `red_team/taxonomy.py`
  for validation of the regenerated files.

## 7. Data flow per cycle

1. Orchestrator picks the lowest-coverage zone (unchanged).
2. `IdeationEngine.generate_for_zone` runs modes A/B/C, each enriched with the
   zone's technique context block from `taxonomy.py`.
3. Mode D (`taxonomy`) asks `technique_coverage.gaps(zone_id, top_n)` for the
   least-covered techniques and generates one idea per gap technique.
4. Every `IdeaObject` is tagged with `list[TechniqueRef]` — from the model's
   self-reported IDs, validated against the corpus, with `Taxonomy.resolve()`
   backfill for the untagged.
5. Dedup → priority → strategist → execution run unchanged. The strategist
   carries the union of its source ideas' tags onto the synthesized chain.
6. On judgment, `routing.py` calls `technique_coverage.record_attempt(...)` for
   every judged attempt and `record_confirmation(...)` for confirmed findings,
   and writes the tags into `idea_techniques` / onto the finding.
7. Persistence: `log_idea` stores the tags (folded into `novelty_notes` and,
   first-class, into the `idea_techniques` table); confirmed findings store
   their tags so the technique-coverage map is rebuildable from the DB.

## 8. Data model additions

All land in `interfaces/schema.sql` via the migration system (`schema_meta`
already exists; `schema_version` is currently `'2'`). New tables:

- `idea_techniques` — `(idea_id TEXT, technique_kind TEXT, technique_id TEXT,
  corpus_version TEXT, resolved_by TEXT, created_at TEXT)`. `technique_kind` is
  `atlas` or `owasp`; `resolved_by` is `model` (self-reported) or `keyword`
  (backfilled by `Taxonomy.resolve()`). Composite index on `(idea_id)` and on
  `(technique_kind, technique_id)`.
- `finding_techniques` — same shape keyed by `finding_id`. Populated for
  confirmed/suspicious findings so the confirmed-coverage axis is durable.
- `technique_coverage` — `(zone_id TEXT, technique_kind TEXT, technique_id TEXT,
  attempts INTEGER, confirmations INTEGER, last_seen_at TEXT)`, primary key
  `(zone_id, technique_kind, technique_id)`. The materialised second coverage
  axis; rebuildable from `idea_techniques` + `finding_techniques` if dropped.

New `interfaces/types.py` dataclasses:

- `TechniqueRef` — `{kind: str, technique_id: str, name: str,
  corpus_version: str, resolved_by: str}`. The unit attached to ideas and
  findings and passed across the coverage API.
- `TechniqueCoverage` — `{zone_id, total, exercised, confirmed,
  exercised_ratio, confirmed_ratio, gap_technique_ids}`. The per-zone view.

`IdeaObject` is **not** changed — tags ride on the instance as
`idea.techniques` (a `list[TechniqueRef]`) exactly as `idea.tactics` and
`idea.playbook` already do, and survive persistence via the `novelty_notes`
sentinel plus the `idea_techniques` table. This keeps the merge surface with
the `interfaces/` contract minimal, consistent with how `IdeaTactics` was
handled (`ideation.py` §B2 comment).

The migration also bumps `schema_meta.schema_version` and inserts a
`taxonomy_corpus_version` row mirroring `corpus_meta.yaml`, so the DB records
which corpus produced its tags.

## 9. Integration points

- **`red_team/ideation.py`:** the only module materially changed — three modes
  enriched, one mode added, `_parse_ideas` extended. Public API unchanged.
- **`red_team/pipeline.py`:** `generate_ideas` already aggregates modes; the
  `taxonomy` mode joins the default mode tuple. The strategist already carries
  `builds_on`; it additionally unions source-idea `techniques` onto chains. One
  new line in `judge()` to call `technique_coverage` via routing.
- **`red_team/routing.py`:** gains two calls — `record_attempt` and
  `record_confirmation` — alongside the existing `update_zone_coverage` and
  archive-update calls. Best-effort: a coverage-update failure logs and does not
  abort routing, consistent with the archive-update handling there.
- **`interfaces/`:** new types + schema migration. No change to existing types.
- **Dashboard:** one new view — the technique-coverage heatmap (zones × ATLAS
  tactics), additive, alongside the existing attack-coverage heatmap.
- **`red_team/policy_corpus.py`:** unchanged, but `corpus_to_ideas` ideas now
  also flow through the tagging step in `_parse_ideas`' equivalent, so policy
  corpus cases get technique tags too.

## 10. The zone ↔ ATLAS mapping

The 18 zones map to ATLAS techniques and OWASP categories in
`zone_atlas_mapping.yaml`, authored once and reviewed. The mapping is the
counterpart to the existing `docs/zone_failure_class_mapping.md`. Indicative
anchors (the committed file is the authority, and uses ATLAS v5.4.0 IDs):

| Zone | ATLAS technique families | OWASP |
|------|--------------------------|-------|
| `PROMPT-INJ` | LLM Prompt Injection (direct + indirect, agentic) | LLM01 |
| `PRV-LEAK` | LLM Sensitive Information Disclosure | LLM02, LLM06 |
| `PRV-ROUTE` | Exfiltration via Inference API; agentic data routing | LLM02 |
| `SKILL-SUPPLY` | ML Supply Chain Compromise | LLM03 |
| `SKILL-INSTALL` | ML Supply Chain Compromise; tool/plugin abuse | LLM03 |
| `SKILL-EXEC` | LLM Plugin Compromise; agentic tool abuse | LLM07 |
| `MEM-STATE` | Agent memory manipulation (agentic technique) | LLM08 |
| `MEM-SHARED` | Agent memory manipulation; cross-context bleed | LLM08 |
| `SBX-NET` | Exfiltration; Command and Scripting Interpreter | LLM02 |
| `SBX-FS` / `SBX-PROC` / `SBX-IPC` | Execution / sandbox-escape techniques | LLM07 |
| `PERM-MODEL` / `PERM-RUNTIME` | Privilege escalation; defense evasion | LLM07 |
| `INF-ROUTE` / `INF-LOCAL` | Model-serving MITM; ML model swap | LLM05 |
| `AGENT-COMM` | Agent impersonation / spoofing (agentic technique) | LLM08 |
| `SOCIAL-ENG` | LLM-based multi-turn manipulation | LLM09 |

`docs/zone_atlas_mapping.md` is the human-readable companion, rendered from the
YAML, mirroring how `docs/zone_failure_class_mapping.md` documents the
whitepaper mapping.

## 11. Error handling

- A missing or malformed corpus file is a hard error at `load_taxonomy` — the
  loop will not start with a broken taxonomy, the same posture
  `red_team/policy_corpus.py` takes on a malformed `policy_corpus.yaml`.
- A technique ID the model self-reports that is absent from the corpus is
  dropped with a logged warning; `Taxonomy.resolve()` then attempts a keyword
  backfill. The idea is never discarded for a bad tag.
- An idea that resolves to zero techniques is recorded with an empty tag set
  and counted as "untagged" in the coverage view — visible, not silently lost.
- `technique_coverage` write failures in routing are best-effort: logged, never
  cycle-aborting.
- The offline refresh tool failing (network down, upstream format change)
  affects only the operator running it; the loop keeps using the last vendored
  snapshot.

## 12. Testing strategy

Tests live in `test/`, `test_taxonomy_*.py` / `test_ideation_*.py`, matching
the existing `test_<area>_*.py` convention.

- `test_taxonomy_loader.py` — load + validate the vendored corpus; assert every
  mapped technique ID exists in the ATLAS snapshot and every OWASP ID is
  `LLM01`–`LLM10`; assert a deliberately corrupt fixture raises `ValueError`.
- `test_taxonomy_resolve.py` — table-driven: known attack phrasings resolve to
  the expected technique IDs; gibberish resolves to an empty list.
- `test_ideation_tagging.py` — a mock LLM returns ideas with and without
  self-reported IDs; assert clean ones are kept, garbled ones are backfilled,
  untagged ones survive with an empty tag set.
- `test_ideation_taxonomy_mode.py` — Mode D given a zone with known coverage
  gaps produces one idea per gap technique, tagged with that technique.
- `test_technique_coverage.py` — `record_attempt` / `record_confirmation` move
  the ratios; `gaps()` returns the least-covered first; the map rebuilds from
  `idea_techniques` + `finding_techniques`.
- `test_taxonomy_migration.py` — the schema migration applies cleanly on a v2
  DB and bumps `schema_version`.
- All runs in mock mode, zero model credentials, consistent with the repo's
  demo posture.

## 13. Phased delivery

- **Phase 0 — corpus + contracts:** vendor `red_team/corpora/`, author
  `zone_atlas_mapping.yaml`, add `TechniqueRef` / `TechniqueCoverage` types and
  the schema migration. No behaviour change.
- **Phase 1 — taxonomy module:** `red_team/taxonomy.py` — loader, validation,
  query API, `resolve()`. Fully unit-tested against the vendored corpus.
- **Phase 2 — tagging:** extend `ideation.py::_parse_ideas` to attach
  `TechniqueRef`s; persist via `idea_techniques`. The three existing modes gain
  technique context blocks. Ideas now carry tags end-to-end.
- **Phase 3 — coverage axis:** `red_team/technique_coverage.py`; wire
  `record_attempt` / `record_confirmation` into `routing.py`.
- **Phase 4 — Mode D:** the `taxonomy` ideation mode, driven by coverage gaps;
  add it to the default mode tuple.
- **Phase 5 — surfacing:** the dashboard technique-coverage heatmap and
  `docs/zone_atlas_mapping.md`.
- **Phase 6 — refresh tool:** `scripts/refresh_taxonomy_corpus.py`. Independent
  of the loop; can land last.

## 14. Open questions

1. **ATLAS sub-technique granularity.** Coverage is scored at technique
   granularity initially; sub-techniques are stored on `TechniqueRef` but not
   separately scored. If technique-level coverage saturates and sub-technique
   distinctions become useful, the coverage model can drop to sub-technique
   granularity without a schema change (`idea_techniques` already stores full
   dotted IDs).
2. **Resolve() precision vs. an LLM tagger.** `Taxonomy.resolve()` is keyword
   matching — cheap, deterministic, and good enough for backfill. If backfill
   precision proves a problem, a small LLM tagging call is a candidate; that
   call would itself be a future consumer of the learned ranking model rather
   than a new frontier-model dependency.
3. **OWASP versioning.** The OWASP LLM Top 10 renumbers categories between
   editions. `corpus_meta.owasp_version` pins the edition; a refresh that
   renumbers categories is a reviewed migration, not a silent corpus swap.
