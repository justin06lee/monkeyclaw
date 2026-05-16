# Model Routing — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

MonkeyClaw runs a dozen distinct LLM-driven tasks — creative ideation, code-
grounded ideation, semantic judging, content-safety judging, multi-turn attack
execution, replay/cold-verification following, root-cause analysis, patch
generation, test generation, and summarization. They have wildly different
profiles. Ideation wants breadth and tolerates noise. The semantic judge wants
calibration. Patch generation and root-cause analysis are low-hallucination-
tolerance code reasoning. Summarization and structured extraction are cheap,
high-volume work.

The architecture report is explicit:

> Do not use one model for everything. Use model routing by task risk and
> complexity. […] The current model config is too coarse; role-based routing
> is needed. ("Model Routing Recommendation", "Key Gaps")

Today the *config* already names a per-role map (`models.roles` in
`config_schema.py` and `configs/monkeyclaw.yaml`), and `make_llm(role=...)`
resolves a model from it. But that map is **descriptive, not operative**: only
the red ideation/tournament path threads a `role` through, every other caller
constructs `make_llm()` with no role at all and lands on the single global
`DEFAULT_MODEL`. There is no routing *policy* (no notion of task risk picking a
tier), no fallback chain (a provider outage aborts the cycle), and no per-role
cost accounting even though the `model_runs` table and `log_model_run` MCP tool
exist and are essentially unused. This spec makes the existing role map
operative and adds the policy, fallback, and accounting around it.

## 2. Scope

In scope:

- An operative per-role model registry covering every LLM task in the
  pipeline, not just ideation: `red_ideation`, `red_code_ideation`,
  `red_execution`, `semantic_judge`, `safety_judge`, `mutation`,
  `cold_verification`, `summarization`, `root_cause`, `patch_generation`,
  `test_generation`, `cheap_extraction`.
- A **routing policy** that selects a role's model by task risk/complexity
  tier (Nemotron Nano / Super / Ultra split; frontier models for patch and
  root-cause), so a role's effective model can be derived from a tier rather
  than hard-named where that is cleaner.
- **Fallback chains** per role: an ordered list of `ModelRoute`s tried in
  sequence on provider error / timeout, ending in a guaranteed-available local
  route so a cycle never aborts on a single model's outage.
- **Per-role token & cost accounting** written to the existing `model_runs`
  table via `log_model_run`, with a pricing table and a per-cycle / per-role
  cost rollup the dashboard already wants.
- A single routing entrypoint (`interfaces/model_router.py`) that every LLM
  caller uses in place of bare `make_llm()`.

Explicitly out of scope (YAGNI for this spec):

- Training a learned router or ranking model. The architecture report says
  "Do not train first" — this spec is the heuristic-policy phase that produces
  the labelled `model_runs` data a future learned router would need.
- Auto-tuning tier thresholds from outcome data. Tiers are config-declared.
- Streaming, batch, or prompt-caching support — `LLMClient.complete` stays a
  single-shot call.
- Multi-model *ensembles* for a single task. The red judge ensemble and the
  red model tournament already exist as separate features; this spec routes
  each of their member calls but does not change ensemble logic.
- A new embedding model. Embedding routing stays in `EmbeddingConfig`; the
  architecture report defers a 768/1536-dim migration to a schema version.

## 3. What already exists vs. what is new

Already built — this spec completes, not rebuilds:

- `interfaces/config_schema.py`: `ModelRoute` (`provider`, `model`),
  `ModelsConfig` with a `roles: dict[str, ModelRoute]` map, and
  `_default_model_roles()` seeding eight roles (`cheap_extraction`,
  `red_ideation`, `red_execution`, `semantic_judge`, `safety_judge`,
  `root_cause`, `patch_generation`, `codex_code_work`).
- `configs/monkeyclaw.yaml`: the same eight roles materialised, plus a
  `model_tournament` block (disabled by default).
- `interfaces/llm.py`: `make_llm(backend, model, role, cfg)` already resolves a
  model from `cfg.models.roles[role]` when `role` is passed; three backends
  (`NemotronLLM`, `ClaudeCLILLM`, `MockLLM`); auto-detect precedence.
- `interfaces/types.py`: `ModelRunRecord` / `ModelRunInput` dataclasses.
- `interfaces/schema.sql`: the `model_runs` table (`role`, `model`,
  `provider`, `input_tokens`, `output_tokens`, `latency_ms`, `cost_usd`,
  `success`, `error`) and `idx_model_runs_role`.
- `infra/mcp_server.py`: `log_model_run` insert.
- `red_team/tournament.py` + `red_team/pipeline.py`: the *only* current
  consumers of role-based resolution — the tournament resolves an entrant's
  `role` to a model via `make_llm(role=...)`.
- `test/test_model_routing.py`: asserts the eight roles exist and
  `make_llm(role=...)` resolves under the mock backend.

What is **missing** and is this spec's work:

- Every non-tournament caller (`red_team/pipeline.py:111`,
  `blue_team/pipeline.py:138`, `infra/cli.py:359,571`, `red_team/judge.py`,
  `red_team/ideation.py`, `red_team/strategist.py`, `blue_team/cold_verifier.py`,
  `blue_team/patch_generator.py`, `blue_team/root_cause.py`,
  `blue_team/test_generator.py`) calls `make_llm()` with **no role** — so the
  role map is dead config for them.
- No roles for `red_code_ideation`, `mutation`, `cold_verification`,
  `summarization`, `test_generation` — the tasks exist, the routes do not.
- No tier abstraction, no risk→model policy.
- No fallback chain — `make_llm` returns one client; a provider error inside
  `complete()` propagates and (per the orchestrator's per-stage `try/except`)
  drops that lane/finding.
- `log_model_run` exists but is called nowhere — `model_runs` is empty, and the
  dashboard cost panel uses "a blended token-price estimate" (README).
- No pricing table, so `cost_usd` cannot be populated.

## 4. Design constraints

1. **`interfaces/` stays the contract firewall.** The router
   (`interfaces/model_router.py`), the expanded `ModelsConfig`, the tier
   declarations, and the pricing config all land in `interfaces/`. `red_team/`
   and `blue_team/` import the router read-only, exactly as they import
   `llm.py` today.
2. **Backward compatible.** `make_llm()` with no role keeps working and keeps
   resolving `DEFAULT_MODEL`. The eight existing role keys keep their meaning.
   Adding roles and adding fields to `ModelRoute` is non-breaking per the
   `types.py` / config conventions. An existing `monkeyclaw.yaml` with no
   routing block runs unchanged on built-in defaults.
3. **The router is the single LLM construction point.** After this spec, no
   pipeline code calls `make_llm()` directly; all go through
   `ModelRouter.client_for(role)`. `make_llm` remains the low-level backend
   factory the router itself uses. A grep test enforces this.
4. **Routing never blocks the loop.** Fallback chains guarantee every role
   ends in a route that is available in the current environment (the mock or
   `claude_cli` backend when no NVIDIA key is set). A model outage degrades
   quality, never halts the cycle.
5. **Accounting is mandatory and free.** Every `complete()` through the router
   writes one `model_runs` row. Callers do not opt in; the router wraps the
   call. A failed `log_model_run` is logged and swallowed — accounting never
   breaks a pipeline.
6. **Risk tiers are declarative.** The Nano/Super/Ultra/frontier split lives in
   config as named tiers; the routing policy maps role → tier → route. No risk
   heuristic is computed at runtime beyond what config declares.

## 5. The routing model

### 5.1 Risk/complexity tiers

Four tiers, mirroring the architecture report's recommendation:

| Tier | Default route | For |
|------|---------------|-----|
| `cheap` | Nemotron 3 Nano | summarization, structured extraction, log normalization, cold-verifier following, mutation/triage prefilter |
| `workhorse` | Nemotron 3 Super (120B/12B MoE) | ideation, semantic judging, attack execution, repro writing — the high-volume agent work |
| `heavy` | Nemotron 3 Ultra | hard long-horizon agent planning when local frontier-like reasoning is needed |
| `frontier` | frontier coding/reasoning model (Claude Opus / GPT-5.3-Codex per provider config) | patch generation, high-severity root-cause analysis, complex code-grounded ideation, difficult semantic-judgment appeals |

`safety_judge` is a special auxiliary route — Nemotron content-safety
reasoning 4B — declared directly, not via a tier, because the report is
explicit it is a specialised classifier rather than a tier on the
quality/cost curve.

### 5.2 Role → tier mapping (the policy)

The routing policy is the role→tier table. Default policy:

| Role | Tier | Rationale |
|------|------|-----------|
| `red_ideation` | workhorse | breadth, noise-tolerant |
| `red_code_ideation` | frontier | code-grounded; needs low hallucination |
| `red_execution` | workhorse | multi-turn agent planning |
| `semantic_judge` | workhorse | calibration over the bulk of judgments |
| `semantic_judge_appeal` | frontier | only the low-confidence appeals |
| `safety_judge` | (direct: content-safety 4B) | specialised classifier |
| `mutation` | cheap | operator prefilter, high volume |
| `cold_verification` | cheap | "simple cold-verifier following" |
| `summarization` | cheap | cycle summaries, log normalization |
| `root_cause` | frontier | high-severity code analysis |
| `patch_generation` | frontier | code changes, low hallucination tolerance |
| `test_generation` | frontier | behaviour-preserving code generation |
| `cheap_extraction` | cheap | structured extraction |

A role's effective `ModelRoute` is resolved as: explicit per-role override in
`models.roles` if present → else the route for the role's tier. This keeps the
existing eight `models.roles` entries authoritative (they act as overrides) and
lets the five new roles ride the tier defaults without every deployment
re-listing them.

### 5.3 Fallback chains

Each role resolves not to one route but to an **ordered chain**:

```
[ primary route ] → [ tier-default route ] → [ guaranteed-local route ]
```

The guaranteed-local route is `claude_cli` when its binary is present, else
`mock` — the same auto-detect `make_llm` already does, so a credential-free
environment still runs. On a `complete()` raising a provider/timeout error,
the router constructs the next client in the chain and retries the same
request. The chain is exhausted-then-raise only if even the local route fails
(effectively never). Each attempt — including failed ones — writes a
`model_runs` row, so the dashboard shows fallback activations.

Chains are config-declared per role (`fallback` list on the role entry); an
absent `fallback` yields the implicit two-step chain `[role route, local]`.

## 6. Architecture

```
        configs/monkeyclaw.yaml ──► interfaces/config_schema.py
                                     ModelsConfig
                                       ├─ tiers:   {cheap, workhorse, heavy, frontier}
                                       ├─ roles:   {role: ModelRoute}        (overrides)
                                       ├─ policy:  {role: tier}
                                       └─ pricing: {model: PriceRow}
                                            │ read-only
                                            ▼
        interfaces/model_router.py ── ModelRouter
          ├─ resolve(role) -> [ModelRoute, ...]      (chain: override|tier → … → local)
          ├─ client_for(role) -> RoutedClient
          └─ RoutedClient.complete(...)
                ├─ try chain[0] → on error → chain[1] → …
                ├─ cost = pricing[model].apply(usage)
                └─ mcp.log_model_run(ModelRunInput(role, model, …, cost_usd))
                            │
                            ▼
        interfaces/llm.py  make_llm(backend, model)   (low-level factory, unchanged surface)

   consumers (red_team/, blue_team/, infra/cli.py) ── ModelRouter.client_for(role)
                                                        │
                                                        ▼
                                              model_runs table  ──► dashboard cost panel
```

## 7. Components

### 7.1 `interfaces/model_router.py` (new)

- **Does:** Owns role→chain resolution, fallback execution, and accounting.
  `ModelRouter` is constructed once at bootstrap from `MonkeyClawConfig` and an
  optional `MonkeyClawMCP` handle (for `log_model_run`). `client_for(role)`
  returns a `RoutedClient` — an `LLMClient` wrapper bound to a role's chain.
- **Interface:**
  ```python
  class ModelRouter:
      def __init__(self, cfg: MonkeyClawConfig,
                    mcp: MonkeyClawMCP | None = None) -> None: ...
      def resolve(self, role: str) -> list[ModelRoute]: ...
      def client_for(self, role: str) -> RoutedClient: ...

  class RoutedClient(LLMClient):
      """Wraps the fallback chain. `complete()` walks the chain on
      error, applies pricing, and logs one model_runs row per attempt."""
  ```
- **Depends on:** `interfaces/llm.py` (`make_llm`, `LLMClient`),
  `interfaces/config_schema.py`, `interfaces/types.py` (`ModelRunInput`),
  `interfaces/mcp_tools.py` (`log_model_run`).

### 7.2 `ModelsConfig` expansion in `interfaces/config_schema.py`

- **Does:** Adds the tier table, the role→tier policy map, and the pricing
  table to the existing `ModelsConfig`. New fields are all
  `Field(default_factory=...)` so an old config still validates.
- **Interface (new fields):**
  ```python
  class ModelTier(BaseModel):
      route: ModelRoute
      fallback: list[ModelRoute] = []

  class PriceRow(BaseModel):
      input_per_mtok_usd: float
      output_per_mtok_usd: float

  class ModelRoute(BaseModel):           # extended
      provider: str
      model: str
      fallback: list["ModelRoute"] = []  # additive, optional

  class ModelsConfig(BaseModel):         # extended
      roles: dict[str, ModelRoute]       = Field(default_factory=_default_model_roles)
      tiers: dict[str, ModelTier]        = Field(default_factory=_default_tiers)
      policy: dict[str, str]             = Field(default_factory=_default_policy)
      pricing: dict[str, PriceRow]       = Field(default_factory=_default_pricing)
  ```
- **Depends on:** nothing new — pure config.

### 7.3 Pricing table

- **Does:** Maps a model name to per-million-token input/output USD prices.
  `RoutedClient` computes `cost_usd` from `LLMResponse.input_tokens` /
  `output_tokens`. An unknown model → `cost_usd = None` (the column is
  nullable) and a one-time warning. This replaces the dashboard's "blended
  token-price estimate" (README) with a real per-role figure.
- **Depends on:** declared in config (`models.pricing`).

### 7.4 `make_llm` adjustment in `interfaces/llm.py`

- **Does:** No surface change. `make_llm` keeps resolving a role from
  `cfg.models.roles` for backward compatibility, but the router is now the
  preferred caller and passes an explicit `model`. The auto-detect local
  backend logic is reused by the router to construct the guaranteed-local
  fallback link.
- **Depends on:** unchanged.

## 8. Data model additions

No new tables. This spec **activates** existing schema:

- `model_runs` — already defined; this spec is its first real producer.
  `RoutedClient` writes one row per `complete()` attempt with `role`, `model`,
  `provider`, token counts, `latency_ms`, `cost_usd`, `success`, and `error`.
- `cost_usd` becomes meaningfully populated via the pricing table.

No `interfaces/types.py` change is required — `ModelRunInput` already carries
every field. Config additions (§7.2) are the only "data model" delta and they
live in `config_schema.py`, not the DB schema, so the migration system (see the
data-integrity spec) is not involved.

## 9. Data flow

### 9.1 Bootstrap

```
load_config() → MonkeyClawConfig (with tiers/policy/pricing defaults or YAML)
boot() → ModelRouter(cfg, mcp)        # constructed once, shared
Runtime carries the router alongside mcp / provisioner
```

### 9.2 Per LLM call

```
caller: router.client_for("patch_generation").complete(messages, ...)
  → resolve("patch_generation")
       → models.roles["patch_generation"] override? yes → primary route
       → + policy tier "frontier" route + guaranteed-local  → chain
  → RoutedClient.complete:
       attempt chain[0]  → provider error/timeout?
            ├ no  → LLMResponse; cost = pricing[model](usage)
            │       log_model_run(role, model, tokens, latency, cost, success=True)
            │       return
            └ yes → log_model_run(..., success=False, error=...)
                    attempt chain[1] … (same)
```

### 9.3 Per-cycle rollup

The orchestrator's `_finalize_cycle` already aggregates `total_tokens_used`
from `LaneResult`s. With `model_runs` now populated, the cycle summary and the
dashboard gain a **per-role** breakdown: a `SELECT role, SUM(input_tokens),
SUM(output_tokens), SUM(cost_usd) FROM model_runs WHERE …` grouped by role.
This is read-only reporting; no schema change.

## 10. Integration points

- **`infra/bootstrap.py`:** constructs the `ModelRouter` once and exposes it on
  `Runtime` (peer to `mcp`, `provisioner`, `cfg`).
- **`red_team/pipeline.py` / `blue_team/pipeline.py`:** both already accept a
  `Runtime` and an injectable `llm`. They gain an injectable `router` and use
  `router.client_for(role)` for each component instead of one shared
  `make_llm()`. The `llm=` test-injection point is kept (a test can still pass
  a `MockLLM`); when a `router` is present it wins per role.
- **Component constructors** (`PatchGenerator`, `RootCauseLocator`,
  `ColdVerifier`, `TestGenerator`, ideation, judge, strategist, mutations):
  each is handed the `RoutedClient` for its role rather than a generic client.
  This is a constructor-argument change, not a logic change.
- **`red_team/tournament.py`:** already role-aware; it switches from
  `make_llm(role=...)` to `router.client_for(role)` so tournament entrants are
  also accounted and fallback-protected.
- **`infra/cli.py`:** the two bare `make_llm()` calls (probe / ad-hoc paths)
  route through `router.client_for("red_execution")` (probe is an execution-
  style chat).
- **Dashboard:** the cost panel switches from the blended estimate to a
  `model_runs`-backed per-role rollup. Additive — a new panel query.
- **`configs/monkeyclaw.yaml`:** gains `models.tiers`, `models.policy`,
  `models.pricing` blocks. Existing `models.roles` stays and acts as overrides.

## 11. Error handling

- **Provider/timeout error inside `complete()`** — caught by `RoutedClient`,
  logged as a failed `model_runs` row, the next chain link is tried. Only an
  exhausted chain (local backend also failing) re-raises; the orchestrator's
  existing per-stage `try/except` then isolates that lane/finding.
- **Unknown role passed to `client_for`** — raises `ValueError` immediately
  (a bug, like an unknown FSM entity in the data-integrity spec). Roles are a
  closed set.
- **Unknown model in the pricing table** — `cost_usd = None`, one-time
  `LOG.warning`. Accounting still records tokens; only the dollar figure is
  absent.
- **`log_model_run` failure** — logged and swallowed (constraint 5).
  Accounting never breaks a pipeline.
- **Missing NVIDIA key** — the guaranteed-local fallback link (`claude_cli` or
  `mock`) is always last in every chain, so a credential-free run resolves
  every role without error, exactly as the demo posture requires.

## 12. Testing strategy

Tests live in `test/`, extending the existing `test_model_routing.py`.

- `test_model_routing.py` (extend): the role set now includes the five new
  roles; `policy` covers every role; every `policy` tier exists in `tiers`;
  every `roles`/`tiers`/`fallback` route's `provider` is in
  `guardrails.model_route_allowlist`.
- `test_model_router_resolve.py` — `resolve(role)` returns a chain ending in a
  guaranteed-local route; a per-role `models.roles` override beats the tier
  default; the implicit two-step chain is produced when `fallback` is absent.
- `test_model_router_fallback.py` — a fake `LLMClient` that raises on the
  primary and succeeds on the fallback; assert `RoutedClient.complete` returns
  the fallback's response and writes two `model_runs` rows (one `success=0`,
  one `success=1`).
- `test_model_router_accounting.py` — a successful `complete()` writes exactly
  one `model_runs` row with the right `role`/`model` and a `cost_usd` matching
  the pricing table; an unknown model yields `cost_usd = None`.
- `test_model_router_no_bare_make_llm.py` — greps `red_team/`, `blue_team/`,
  `infra/` for `make_llm(` calls outside `interfaces/` and `model_router.py`;
  asserts none remain (enforces constraint 3).
- Existing red/blue e2e suites must pass unchanged under the `mock` backend —
  the router resolves every role to the mock fallback, behaviour is identical.

## 13. Phased delivery

- **Phase 0 — config.** Extend `ModelsConfig` with `tiers`, `policy`,
  `pricing`, and `ModelRoute.fallback`; add the five new roles to
  `_default_model_roles` / `monkeyclaw.yaml`. Extend `test_model_routing.py`.
  No behaviour change — pure config, validated by tests.
- **Phase 1 — the router.** `interfaces/model_router.py`: `resolve`,
  `client_for`, `RoutedClient` with chain-walking and `model_runs` accounting.
  Router-level tests. Not yet wired into pipelines.
- **Phase 2 — wire consumers.** Construct the router in `infra/bootstrap.py`,
  expose on `Runtime`; convert `red_team/pipeline.py`, `blue_team/pipeline.py`,
  their component constructors, `tournament.py`, and `infra/cli.py` to
  `router.client_for(role)`. Run the no-bare-`make_llm` test.
- **Phase 3 — reporting.** Per-role cost rollup query; replace the dashboard's
  blended token-price estimate with the `model_runs`-backed panel; add the
  per-role breakdown to the cycle summary.

Each phase is independently verifiable and keeps the suite green.

## 14. Open questions

1. **Frontier provider binding.** `_default_model_roles` uses the placeholder
   `provider="anthropic_or_openai", model="frontier-coding"`. A deployment
   with neither an Anthropic nor an OpenAI key resolves `frontier` roles to the
   local fallback — acceptable for the demo, but the placeholder should be
   replaced with a concrete provider+model in any non-demo config. The router
   does not invent a binding; it follows config.
2. **`semantic_judge_appeal` activation.** The policy declares a frontier tier
   for low-confidence judgment appeals, but the red judge does not currently
   route appeals to a second model. Wiring the appeal path is left to the red-
   team search-dynamics work; this spec only reserves the role so the route
   exists when that lands.
3. **Heavy (Ultra) tier usage.** No role defaults to `heavy` — Ultra is
   reserved per the architecture report for "hard long-horizon planning … when
   infrastructure can support it". The tier is declared so a deployment can
   re-point `red_execution` or `root_cause` at it via the `policy` map without
   code change; no role uses it out of the box.
