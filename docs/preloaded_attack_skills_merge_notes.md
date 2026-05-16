# Preloaded Attack Skills — Merge & Breaking-Change Notes

Date: 2026-05-16
Branch: `worktree-preloaded-attack-skills`
Base: `origin/master`

This document lists every change on the branch that can collide with parallel
work, so a merge can be resolved **without losing either feature**. Read the
"Resolution" column before resolving any conflict marker.

The branch is 4 commits ahead of `origin/master`:

| Commit | Scope |
|--------|-------|
| `cedf742` | Adds the two research markdown source files |
| `ac628ea` | Locale-encoding fix (`utf-8` on text reads) |
| `014f346` | Preloaded attack skills: corpus + loader + Mode D ideation |
| `a682ee0` | `attack_skills` DB table + bootstrap seeder |

---

## 1. New files — zero conflict risk

These files did not exist on `origin/master`. They cannot produce a conflict
unless another branch creates a file with the identical path.

- `red_team/attack_skills_loader.py`
- `red_team/attack_skills/*.yaml` — 35 corpus files
- `infra/seed_attack_skills.py`
- `test/test_red_attack_skills.py`
- `test/test_attack_skills_seed.py`
- `.agents/research/AI Agent Prompt Injection Research.md`
- `.agents/research/deep-research-report.md`
- `docs/preloaded_attack_skills_merge_notes.md` (this file)

**Action on merge:** none. Take them as-is.

---

## 2. Shared-file changes — conflict risk

Every edit below is **additive** — no existing line was removed or rewritten
except the five one-line encoding fixes. If git flags a conflict, keep *both*
sides; nothing here replaces existing behaviour.

| File | Owner | Change | Risk | Resolution |
|------|-------|--------|------|------------|
| `interfaces/schema.sql` | Person A | Adds `attack_skills` table + `attack_skills_vec` virtual table, inserted just before the `schema_meta` section | **High** — schema.sql is the contract file; any parallel schema edit conflicts here | Keep both blocks. The new tables use `CREATE TABLE IF NOT EXISTS`; placement is cosmetic — put the `attack_skills` block anywhere before `schema_meta`. Do **not** drop another branch's tables. |
| `infra/database.py` | Person A | Adds `"attack_skills_vec": "skill_id"` to the `_VEC_TABLES` allow-list (1 line) | Medium | Keep all dict entries from both sides. The allow-list is a union — order is irrelevant. |
| `infra/bootstrap.py` | Person A | Adds a ~13-line seeding block after the persistent-memory banner, before `dispatcher = AlertDispatcher(...)` | Medium | Keep the seeding block. If another branch also inserts there, keep both inserts; they are independent. |
| `red_team/ideation.py` | Person B | +112 lines: Mode D method, dispatch case, `IdeaTactics.derived_from_skill`, `IdeationConfig.research_grounded_skills`, JSON-schema blurb line, default `modes` tuple | Medium — large surface; the audit commit already touched this file | See §3 — the `modes` tuple is the one semantically-loaded change. All other edits are additive; keep both sides. |
| `infra/config.py` | Person A | Encoding fix: `p.open()` → `p.open(encoding="utf-8")` (1 line) | Low | Keep `encoding="utf-8"`. If another branch fixed the same line identically, accept either. |
| `red_team/playbooks.py` | Person B | Encoding fix: `read_text()` → `read_text(encoding="utf-8")` (1 line) | Low | Keep `encoding="utf-8"`. |
| `red_team/tournament.py` | Person B | Encoding fix on 2 `read_text()` calls | Low | Keep `encoding="utf-8"` on both. |
| `test/test_red_ideation.py` | Person B | Appends a "Mode D" test section at end of file | Low | Keep the appended block; merge alongside any other appended tests. |

---

## 3. Semantic / behavioural breaking changes

These will **not** show up as git conflict markers. Review them by hand — they
change runtime behaviour, not just text.

### 3.1 `generate_for_zone` runs a 4th mode by default

`IdeationEngine.generate_for_zone`'s default `modes` tuple changed from:

```python
("creative", "code_grounded", "history_informed")
```

to:

```python
("creative", "code_grounded", "history_informed", "research_grounded")
```

**Impact:** every cycle now also runs Mode D, producing extra ideas. Callers
that pass an explicit `modes=` argument are unaffected. Callers relying on a
fixed idea count, or on exactly three `source_mode` values, will see more
ideas and a new value.

**Resolution:** intended. If a parallel branch also edited the default tuple,
union the modes — do not drop `research_grounded`.

### 3.2 New `source_mode` value: `"research_grounded"`

Mode D ideas carry `IdeaObject.source_mode == "research_grounded"`. This value
flows into the `ideas` table, dedup, priority scoring, the MAP-Elites archive,
and `findings`.

**Impact:** any code that switches on `source_mode` against a *closed* set of
`{creative, code_grounded, history_informed}` (and raises/drops on an unknown
value) will mishandle Mode D ideas.

**Resolution:** audit `source_mode` consumers (priority, archive, routing,
dashboard) and ensure they treat it as an open set. The DB column is plain
`TEXT`, so no schema change is needed.

### 3.3 Bootstrap now seeds the corpus

`infra.bootstrap.boot()` calls `seed_attack_skills(db)` once per boot. The
first boot embeds 35 skills (loads `sentence-transformers`, a few seconds);
later boots are no-ops (content-hash match). A seeding failure is caught and
logged — it does not abort boot.

**Impact:** first-boot startup is slightly slower; a new embedding-model load
happens during boot rather than first ideation cycle.

### 3.4 Text files are now read as UTF-8

`ac628ea` pins five text reads (`schema.sql`, config / tournament / playbook
YAML) to `encoding="utf-8"` instead of the OS locale encoding. This is a bug
fix — on a non-UTF-8 locale the prior code raised `UnicodeDecodeError`. No
caller should depend on locale decoding; flagged only for completeness.

---

## 4. Schema / DB notes

- `CURRENT_SCHEMA_VERSION` in `infra/database.py` is **unchanged** (still `2`).
  No bump is needed: `_apply_schema` runs the full `schema.sql` on every open,
  and `CREATE TABLE IF NOT EXISTS` adds `attack_skills` to pre-existing
  databases as well as fresh ones.
- `attack_skills_vec` is a `vec0` virtual table at `FLOAT[384]`, matching
  `EMBEDDING_DIM`. If a parallel branch migrates the embedding model/dimension,
  `attack_skills_vec` must be re-created at the new dimension and the corpus
  re-seeded (delete the table, re-run `seed_attack_skills`).
- The seeder is idempotent and keyed on `content_hash`; re-running it after a
  merge is safe and cheap.

---

## 5. Not done — no collision, but track it

- **`get_attack_skills` MCP tool** — not implemented. Mode D reads the corpus
  via `attack_skills_loader` directly. Adding the tool later touches
  `interfaces/mcp_tools.py`, `infra/mcp_server.py`, `infra/mock_mcp.py` — none
  touched by this branch, so no conflict today.
- **B7 policy-corpus T-cases** (T11, T13–T15, T17–T18, T21–T24) — a separate
  follow-up against `demo/attacks/policy_corpus.yaml`; not on this branch.

---

## 6. Recommended merge procedure

1. Merge Person A's `interfaces/` + `infra/` changes first (project convention).
2. Merge this branch. Expect conflicts only in the §2 files; resolve each by
   **keeping both sides** (all changes are additive).
3. After resolving, re-run the seeder check and the suite:
   ```
   uv run pytest test/test_red_attack_skills.py test/test_attack_skills_seed.py \
                  test/test_red_ideation.py -q
   ```
4. Hand-review §3 — confirm no `source_mode` consumer rejects the new value.
5. Full suite: `uv run pytest -q`. Pre-existing Windows path-semantics failures
   in `test_red_checks` / `test_red_execution` are unrelated to this branch.
