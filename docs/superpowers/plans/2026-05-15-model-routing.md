# Model Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing per-role model config operative by adding a routing policy (risk tiers), per-role fallback chains, and per-role token/cost accounting behind a single `ModelRouter` entrypoint every LLM caller uses.

**Architecture:** `interfaces/config_schema.py` gains declarative `tiers`, `policy`, and `pricing` blocks plus an additive `ModelRoute.fallback` field; five new roles join the existing eight. `interfaces/model_router.py` (new) resolves a role to an ordered `ModelRoute` chain (override-or-tier → tier-default → guaranteed-local), and `RoutedClient` walks that chain on provider error, applies pricing, and writes one `model_runs` row per `complete()` attempt via `log_model_run`. The router is constructed once in `infra/bootstrap.py`, carried on `Runtime`, and every `red_team`/`blue_team`/`infra` caller switches from bare `make_llm()` to `router.client_for(role)`.

**Tech Stack:** Python 3.12, Pydantic v2 (config schema), SQLite (`model_runs` table, already defined), `uv` for env/test, `pytest`, `ruff`.

---

## File Structure

| File | Create/Modify | Responsibility |
|------|---------------|----------------|
| `interfaces/config_schema.py` | Modify | Add `ModelTier`, `PriceRow`; extend `ModelRoute` with `fallback`; extend `ModelsConfig` with `tiers`/`policy`/`pricing`; add `_default_tiers`/`_default_policy`/`_default_pricing`; add five new roles to `_default_model_roles`. |
| `configs/monkeyclaw.yaml` | Modify | Materialise `models.tiers`, `models.policy`, `models.pricing`; add the five new roles under `models.roles`. |
| `interfaces/model_router.py` | Create | `ModelRouter` (`resolve`, `client_for`) + `RoutedClient` (chain-walking `complete`, pricing, `model_runs` accounting). |
| `interfaces/llm.py` | Modify | Export `_have_nvidia_key` and `DEFAULT_CLI_BINARY` usage stays; add `local_backend_name()` helper the router uses for the guaranteed-local link. |
| `infra/bootstrap.py` | Modify | Construct `ModelRouter` once; add `router` field to `Runtime`. |
| `red_team/pipeline.py` | Modify | Accept injectable `router`; build it from `runtime` when absent; hand each component its `RoutedClient`. |
| `blue_team/pipeline.py` | Modify | Same: accept `router`, hand `RoutedClient` to root-cause, cold-verifier, patch-generator. |
| `red_team/tournament.py` | Modify | `ModelTournament.generate` resolves entrants via `router.client_for(entrant.role)` instead of `make_llm`. |
| `infra/cli.py` | Modify | Two bare `make_llm()` calls route through `router.client_for("red_execution")`. |
| `test/test_model_routing.py` | Modify | Extend: 13-role set, `policy` covers every role, every policy tier exists, every route provider is allowlisted. |
| `test/test_model_router_resolve.py` | Create | Chain resolution: ends in guaranteed-local, override beats tier, implicit two-step chain. |
| `test/test_model_router_fallback.py` | Create | Fallback execution: primary raises → fallback succeeds → response returned + two `model_runs` rows. |
| `test/test_model_router_accounting.py` | Create | Accounting: one row per success, `cost_usd` from pricing, unknown model → `None`, `log_model_run` failure swallowed. |
| `test/test_model_router_no_bare_make_llm.py` | Create | Grep guard: no `make_llm(` in `red_team/`, `blue_team/`, `infra/` outside `interfaces/`. |

---

## Task 1 — Config: extend `ModelsConfig` with tiers, policy, pricing, and new roles

**Files:**
- Modify: `interfaces/config_schema.py`
- Modify: `configs/monkeyclaw.yaml`
- Test: `test/test_model_routing.py`

### Steps

- [ ] **Write failing test** — replace the body of `test/test_model_routing.py` with the new role set and policy/tier/pricing assertions:

```python
from infra.config import load_config

ALL_ROLES = (
    "cheap_extraction", "red_ideation", "red_code_ideation", "red_execution",
    "semantic_judge", "semantic_judge_appeal", "safety_judge", "mutation",
    "cold_verification", "summarization", "root_cause", "patch_generation",
    "test_generation", "codex_code_work",
)


def test_models_config_has_all_roles():
    cfg = load_config()
    roles = cfg.models.roles
    for role in ALL_ROLES:
        assert role in roles, f"missing model role {role}"
        assert roles[role].provider
        assert roles[role].model


def test_make_llm_resolves_role(monkeypatch):
    monkeypatch.setenv("MC_LLM_BACKEND", "mock")
    from interfaces.llm import make_llm
    client = make_llm(role="red_ideation")
    assert client.name == "mock"


def test_tiers_declared():
    cfg = load_config()
    for tier in ("cheap", "workhorse", "heavy", "frontier"):
        assert tier in cfg.models.tiers, f"missing tier {tier}"
        assert cfg.models.tiers[tier].route.provider


def test_policy_covers_every_routed_role():
    # safety_judge is a direct route (no tier); every other role has a tier.
    cfg = load_config()
    for role in ALL_ROLES:
        if role == "safety_judge":
            assert role not in cfg.models.policy
            continue
        assert role in cfg.models.policy, f"role {role} missing from policy"


def test_every_policy_tier_exists():
    cfg = load_config()
    for role, tier in cfg.models.policy.items():
        assert tier in cfg.models.tiers, f"role {role} -> unknown tier {tier}"


def test_every_route_provider_is_allowlisted():
    cfg = load_config()
    allowed = set(cfg.guardrails.model_route_allowlist)
    routes = list(cfg.models.roles.values())
    for tier in cfg.models.tiers.values():
        routes.append(tier.route)
        routes.extend(tier.fallback)
    for r in cfg.models.roles.values():
        routes.extend(r.fallback)
    for route in routes:
        assert route.provider in allowed, f"provider {route.provider} not allowlisted"


def test_pricing_table_present():
    cfg = load_config()
    assert "nvidia/nemotron-3-super-120b-a12b" in cfg.models.pricing
    row = cfg.models.pricing["nvidia/nemotron-3-super-120b-a12b"]
    assert row.input_per_mtok_usd >= 0
    assert row.output_per_mtok_usd >= 0
```

- [ ] **Run it, verify it fails** — `uv run pytest test/test_model_routing.py -q`. Expect failures: `test_models_config_has_all_roles` (missing `red_code_ideation` etc.), `test_tiers_declared`, `test_policy_*`, `test_pricing_table_present` raise `AttributeError: 'ModelsConfig' object has no attribute 'tiers'`.

- [ ] **Implement** — in `interfaces/config_schema.py`, replace the `ModelRoute` class and `_default_model_roles` function and `ModelsConfig` class with:

```python
class ModelRoute(BaseModel):
    provider: str
    model: str
    # Additive, optional: an explicit ordered fallback chain for this route.
    # Absent -> the router appends only the tier default + guaranteed-local.
    fallback: list["ModelRoute"] = Field(default_factory=list)


class ModelTier(BaseModel):
    """A risk/complexity tier: the route to use plus an optional fallback chain."""
    route: ModelRoute
    fallback: list[ModelRoute] = Field(default_factory=list)


class PriceRow(BaseModel):
    """Per-million-token USD prices for one model."""
    input_per_mtok_usd: float
    output_per_mtok_usd: float


def _default_model_roles() -> dict[str, ModelRoute]:
    return {
        "cheap_extraction": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-nano"),
        "red_ideation": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-super-120b-a12b"),
        "red_code_ideation": ModelRoute(provider="anthropic_or_openai", model="frontier-coding"),
        "red_execution": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-super-120b-a12b"),
        "semantic_judge": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-super-120b-a12b"),
        "semantic_judge_appeal": ModelRoute(provider="anthropic_or_openai", model="frontier-coding"),
        "safety_judge": ModelRoute(provider="nvidia", model="nvidia/nemotron-content-safety-reasoning-4b"),
        "mutation": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-nano"),
        "cold_verification": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-nano"),
        "summarization": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-nano"),
        "root_cause": ModelRoute(provider="anthropic_or_openai", model="frontier-coding"),
        "patch_generation": ModelRoute(provider="anthropic_or_openai", model="frontier-coding"),
        "test_generation": ModelRoute(provider="anthropic_or_openai", model="frontier-coding"),
        "codex_code_work": ModelRoute(provider="openai", model="gpt-5.3-codex"),
    }


def _default_tiers() -> dict[str, ModelTier]:
    return {
        "cheap": ModelTier(route=ModelRoute(provider="nvidia", model="nvidia/nemotron-3-nano")),
        "workhorse": ModelTier(
            route=ModelRoute(provider="nvidia", model="nvidia/nemotron-3-super-120b-a12b")),
        "heavy": ModelTier(route=ModelRoute(provider="nvidia", model="nvidia/nemotron-3-ultra")),
        "frontier": ModelTier(
            route=ModelRoute(provider="anthropic_or_openai", model="frontier-coding")),
    }


def _default_policy() -> dict[str, str]:
    # safety_judge is intentionally absent — it is a direct specialised route.
    return {
        "red_ideation": "workhorse",
        "red_code_ideation": "frontier",
        "red_execution": "workhorse",
        "semantic_judge": "workhorse",
        "semantic_judge_appeal": "frontier",
        "mutation": "cheap",
        "cold_verification": "cheap",
        "summarization": "cheap",
        "root_cause": "frontier",
        "patch_generation": "frontier",
        "test_generation": "frontier",
        "cheap_extraction": "cheap",
        "codex_code_work": "frontier",
    }


def _default_pricing() -> dict[str, PriceRow]:
    # Approximate public list prices; replace per deployment.
    return {
        "nvidia/nemotron-3-nano": PriceRow(input_per_mtok_usd=0.04, output_per_mtok_usd=0.16),
        "nvidia/nemotron-3-super-120b-a12b": PriceRow(
            input_per_mtok_usd=0.30, output_per_mtok_usd=0.90),
        "nvidia/nemotron-3-ultra": PriceRow(input_per_mtok_usd=0.90, output_per_mtok_usd=2.70),
        "nvidia/nemotron-content-safety-reasoning-4b": PriceRow(
            input_per_mtok_usd=0.02, output_per_mtok_usd=0.08),
        "frontier-coding": PriceRow(input_per_mtok_usd=3.00, output_per_mtok_usd=15.00),
        "gpt-5.3-codex": PriceRow(input_per_mtok_usd=3.00, output_per_mtok_usd=15.00),
    }


class ModelsConfig(BaseModel):
    roles: dict[str, ModelRoute] = Field(default_factory=_default_model_roles)
    tiers: dict[str, ModelTier] = Field(default_factory=_default_tiers)
    policy: dict[str, str] = Field(default_factory=_default_policy)
    pricing: dict[str, PriceRow] = Field(default_factory=_default_pricing)
```

- [ ] **Run it, verify it passes** — `uv run pytest test/test_model_routing.py -q`. Expect `7 passed`.

- [ ] **Materialise the YAML** — in `configs/monkeyclaw.yaml`, replace the `models:` block (lines under `models:` up to but not including `guardrails:`) with:

```yaml
models:
  roles:
    cheap_extraction:
      provider: nvidia
      model: nvidia/nemotron-3-nano
    red_ideation:
      provider: nvidia
      model: nvidia/nemotron-3-super-120b-a12b
    red_code_ideation:
      provider: anthropic_or_openai
      model: frontier-coding
    red_execution:
      provider: nvidia
      model: nvidia/nemotron-3-super-120b-a12b
    semantic_judge:
      provider: nvidia
      model: nvidia/nemotron-3-super-120b-a12b
    semantic_judge_appeal:
      provider: anthropic_or_openai
      model: frontier-coding
    safety_judge:
      provider: nvidia
      model: nvidia/nemotron-content-safety-reasoning-4b
    mutation:
      provider: nvidia
      model: nvidia/nemotron-3-nano
    cold_verification:
      provider: nvidia
      model: nvidia/nemotron-3-nano
    summarization:
      provider: nvidia
      model: nvidia/nemotron-3-nano
    root_cause:
      provider: anthropic_or_openai
      model: frontier-coding
    patch_generation:
      provider: anthropic_or_openai
      model: frontier-coding
    test_generation:
      provider: anthropic_or_openai
      model: frontier-coding
    codex_code_work:
      provider: openai
      model: gpt-5.3-codex
  # Risk/complexity tiers — the routing policy maps a role to one of these.
  tiers:
    cheap:
      route: {provider: nvidia, model: nvidia/nemotron-3-nano}
    workhorse:
      route: {provider: nvidia, model: nvidia/nemotron-3-super-120b-a12b}
    heavy:
      route: {provider: nvidia, model: nvidia/nemotron-3-ultra}
    frontier:
      route: {provider: anthropic_or_openai, model: frontier-coding}
  # Role -> tier. safety_judge is omitted: it is a direct specialised route.
  policy:
    red_ideation: workhorse
    red_code_ideation: frontier
    red_execution: workhorse
    semantic_judge: workhorse
    semantic_judge_appeal: frontier
    mutation: cheap
    cold_verification: cheap
    summarization: cheap
    root_cause: frontier
    patch_generation: frontier
    test_generation: frontier
    cheap_extraction: cheap
    codex_code_work: frontier
  # Per-million-token USD prices for cost accounting.
  pricing:
    nvidia/nemotron-3-nano: {input_per_mtok_usd: 0.04, output_per_mtok_usd: 0.16}
    nvidia/nemotron-3-super-120b-a12b: {input_per_mtok_usd: 0.30, output_per_mtok_usd: 0.90}
    nvidia/nemotron-3-ultra: {input_per_mtok_usd: 0.90, output_per_mtok_usd: 2.70}
    nvidia/nemotron-content-safety-reasoning-4b: {input_per_mtok_usd: 0.02, output_per_mtok_usd: 0.08}
    frontier-coding: {input_per_mtok_usd: 3.00, output_per_mtok_usd: 15.00}
    gpt-5.3-codex: {input_per_mtok_usd: 3.00, output_per_mtok_usd: 15.00}
```

- [ ] **Run it, verify still green** — `uv run pytest test/test_model_routing.py -q` → `7 passed` (YAML now confirms the defaults). Run `uv run ruff check interfaces/config_schema.py` → `All checks passed!`.

- [ ] **Commit** — `git add interfaces/config_schema.py configs/monkeyclaw.yaml test/test_model_routing.py && git commit -m "feat(config): add model tiers, routing policy, pricing, and five new roles"`.

---

## Task 2 — `make_llm` helper for the guaranteed-local backend

**Files:**
- Modify: `interfaces/llm.py`
- Test: `test/test_model_router_resolve.py` (the helper is exercised here in Task 3; this task adds it minimally with its own test).

### Steps

- [ ] **Write failing test** — create `test/test_model_router_resolve.py` with this first test only (more added in Task 3):

```python
import shutil

from interfaces.llm import local_backend_name


def test_local_backend_name_picks_mock_when_no_cli(monkeypatch):
    monkeypatch.delenv("MC_LLM_BACKEND", raising=False)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("NIM_API_KEY", raising=False)
    monkeypatch.delenv("MC_NEMOTRON_BASE_URL", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    assert local_backend_name() == "mock"


def test_local_backend_name_picks_claude_cli_when_present(monkeypatch):
    monkeypatch.delenv("MC_LLM_BACKEND", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _b: "/usr/bin/claude")
    assert local_backend_name() == "claude_cli"
```

- [ ] **Run it, verify it fails** — `uv run pytest test/test_model_router_resolve.py -q`. Expect `ImportError: cannot import name 'local_backend_name'`.

- [ ] **Implement** — in `interfaces/llm.py`, add this function directly after `_have_nvidia_key`:

```python
def local_backend_name() -> str:
    """The guaranteed-available backend in the current environment.

    `claude_cli` when its binary is on PATH, else `mock`. This is the last
    link of every router fallback chain, so a credential-free run always
    resolves every role. It deliberately ignores the NVIDIA path — the local
    link must not depend on a network model.
    """
    if shutil.which(DEFAULT_CLI_BINARY):
        return "claude_cli"
    return "mock"
```

  Then add `"local_backend_name"` to the `__all__` list (keep it alphabetically sorted, so between `"extract_json"` and `"make_llm"`).

- [ ] **Run it, verify it passes** — `uv run pytest test/test_model_router_resolve.py -q` → `2 passed`. Run `uv run ruff check interfaces/llm.py` → `All checks passed!`.

- [ ] **Commit** — `git add interfaces/llm.py test/test_model_router_resolve.py && git commit -m "feat(llm): add local_backend_name helper for the guaranteed-local fallback link"`.

---

## Task 3 — `ModelRouter.resolve` — role → fallback chain

**Files:**
- Create: `interfaces/model_router.py`
- Test: `test/test_model_router_resolve.py`

### Steps

- [ ] **Write failing test** — append to `test/test_model_router_resolve.py`:

```python
import pytest

from infra.config import load_config
from interfaces.config_schema import ModelRoute
from interfaces.model_router import ModelRouter


def test_resolve_chain_ends_in_local(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: None)  # no claude cli
    router = ModelRouter(load_config())
    chain = router.resolve("red_ideation")
    assert isinstance(chain, list) and len(chain) >= 2
    assert all(isinstance(r, ModelRoute) for r in chain)
    # Last link is the guaranteed-local route.
    assert chain[-1].provider == "local"
    assert chain[-1].model == "mock"


def test_resolve_override_beats_tier():
    # red_code_ideation has an explicit roles[] entry (frontier-coding) AND a
    # policy tier (frontier). The explicit override is chain[0].
    router = ModelRouter(load_config())
    chain = router.resolve("red_code_ideation")
    assert chain[0].provider == "anthropic_or_openai"
    assert chain[0].model == "frontier-coding"


def test_resolve_implicit_two_step_chain(monkeypatch):
    # A role with no explicit fallback and no tier still yields [route, local].
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    router = ModelRouter(load_config())
    chain = router.resolve("safety_judge")  # direct route, no policy tier
    assert len(chain) == 2
    assert chain[0].model == "nvidia/nemotron-content-safety-reasoning-4b"
    assert chain[-1].provider == "local"


def test_resolve_includes_tier_default():
    # cheap_extraction: roles[] route is nano; tier "cheap" route is also nano.
    # The chain is dedup-free per the spec: override -> tier -> local.
    router = ModelRouter(load_config())
    chain = router.resolve("cheap_extraction")
    assert chain[0].model == "nvidia/nemotron-3-nano"


def test_resolve_explicit_fallback_threaded(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    cfg = load_config()
    cfg.models.roles["red_ideation"].fallback = [
        ModelRoute(provider="nvidia", model="nvidia/nemotron-3-nano"),
    ]
    router = ModelRouter(cfg)
    chain = router.resolve("red_ideation")
    # primary, explicit fallback, tier default, local
    assert chain[0].model == "nvidia/nemotron-3-super-120b-a12b"
    assert chain[1].model == "nvidia/nemotron-3-nano"
    assert chain[-1].provider == "local"


def test_resolve_unknown_role_raises():
    router = ModelRouter(load_config())
    with pytest.raises(ValueError, match="unknown model role"):
        router.resolve("not_a_real_role")
```

- [ ] **Run it, verify it fails** — `uv run pytest test/test_model_router_resolve.py -q`. Expect `ModuleNotFoundError: No module named 'interfaces.model_router'`.

- [ ] **Implement** — create `interfaces/model_router.py` with the module docstring, imports, and the `resolve` half of `ModelRouter` (the `RoutedClient` and `client_for` come in Task 4):

```python
"""Model router — operative per-role routing, fallback chains, accounting.

Lives in `interfaces/` like `llm.py`: the contract firewall. `red_team/` and
`blue_team/` import `ModelRouter` read-only and never call `make_llm` directly.

`ModelRouter` is constructed once at bootstrap from `MonkeyClawConfig` (and an
optional MCP handle for `log_model_run`). `client_for(role)` returns a
`RoutedClient` bound to that role's fallback chain.

A role resolves to an ordered chain of `ModelRoute`s:

    [ override-or-tier route ] -> [ explicit fallback... ] ->
    [ tier-default route ] -> [ guaranteed-local route ]

The guaranteed-local route always succeeds in a credential-free environment,
so a model outage degrades quality but never halts the cycle.
"""

from __future__ import annotations

import logging
import time

from interfaces.config_schema import ModelRoute, MonkeyClawConfig
from interfaces.llm import LLMClient, LLMMessage, LLMResponse, local_backend_name, make_llm
from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import ModelRunInput

LOG = logging.getLogger("monkeyclaw.model_router")

# Routes whose provider is one of these never go to make_llm's nemotron path —
# the router maps them to the local backend (the placeholder frontier provider
# resolves to whatever local model is available; see spec §14 open question 1).
_LOCAL_PROVIDER = "local"


class ModelRouter:
    """Resolves roles to fallback chains and constructs routed clients."""

    def __init__(self, cfg: MonkeyClawConfig, mcp: MonkeyClawMCP | None = None) -> None:
        self.cfg = cfg
        self.mcp = mcp
        self._warned_models: set[str] = set()

    def _local_route(self) -> ModelRoute:
        """The guaranteed-available last link of every chain."""
        backend = local_backend_name()
        # `claude_cli` -> model name "claude_cli"; `mock` -> "mock". The
        # provider is the synthetic "local" marker so accounting/allowlist
        # logic can recognise the fallback link.
        return ModelRoute(provider=_LOCAL_PROVIDER, model=backend)

    def resolve(self, role: str) -> list[ModelRoute]:
        """Return the ordered fallback chain for `role`.

        Raises ValueError for an unknown role — roles are a closed set.
        """
        roles = self.cfg.models.roles
        policy = self.cfg.models.policy
        tiers = self.cfg.models.tiers
        if role not in roles and role not in policy:
            raise ValueError(f"unknown model role: {role!r}")

        chain: list[ModelRoute] = []

        def _add(route: ModelRoute) -> None:
            key = (route.provider, route.model)
            if key not in {(r.provider, r.model) for r in chain}:
                chain.append(route)

        # 1) explicit per-role override (authoritative when present).
        primary = roles.get(role)
        if primary is not None:
            _add(primary)
            for fb in primary.fallback:
                _add(fb)

        # 2) the route for the role's policy tier.
        tier_name = policy.get(role)
        if tier_name is not None:
            tier = tiers.get(tier_name)
            if tier is not None:
                _add(tier.route)
                for fb in tier.fallback:
                    _add(fb)

        # 3) guaranteed-local last link.
        _add(self._local_route())
        return chain
```

- [ ] **Run it, verify it passes** — `uv run pytest test/test_model_router_resolve.py -q` → `8 passed`. Run `uv run ruff check interfaces/model_router.py` → `All checks passed!`.

- [ ] **Commit** — `git add interfaces/model_router.py test/test_model_router_resolve.py && git commit -m "feat(router): ModelRouter.resolve builds the per-role fallback chain"`.

---

## Task 4 — `RoutedClient` — chain-walking `complete` with fallback

**Files:**
- Modify: `interfaces/model_router.py`
- Test: `test/test_model_router_fallback.py`

### Steps

- [ ] **Write failing test** — create `test/test_model_router_fallback.py`:

```python
import shutil

import pytest

from infra.config import load_config
from interfaces.config_schema import ModelRoute
from interfaces.llm import LLMClient, LLMMessage, LLMResponse
from interfaces.model_router import ModelRouter


class _BoomLLM(LLMClient):
    """Always raises on complete()."""
    name = "boom"

    def complete(self, messages, system="", max_tokens=2000, temperature=0.7):
        raise RuntimeError("provider down")


class _OkLLM(LLMClient):
    """Always returns a fixed response."""
    name = "ok"

    def __init__(self, text="recovered"):
        self._text = text

    def complete(self, messages, system="", max_tokens=2000, temperature=0.7):
        return LLMResponse(text=self._text, input_tokens=10, output_tokens=5)


class _RecordingMCP:
    """Captures log_model_run calls."""

    def __init__(self):
        self.runs = []

    def log_model_run(self, run):
        self.runs.append(run)
        return f"RUN-{len(self.runs)}"


def _router_with_clients(monkeypatch, clients):
    """Build a router whose chain factory yields `clients` in order."""
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    cfg = load_config()
    mcp = _RecordingMCP()
    router = ModelRouter(cfg, mcp=mcp)
    it = iter(clients)
    monkeypatch.setattr(router, "_client_for_route", lambda route: next(it))
    return router, mcp


def test_fallback_returns_second_client_response(monkeypatch):
    router, mcp = _router_with_clients(monkeypatch, [_BoomLLM(), _OkLLM("recovered")])
    client = router.client_for("red_ideation")
    resp = client.complete([LLMMessage(role="user", content="hi")])
    assert resp.text == "recovered"


def test_fallback_writes_two_model_runs_rows(monkeypatch):
    router, mcp = _router_with_clients(monkeypatch, [_BoomLLM(), _OkLLM()])
    client = router.client_for("red_ideation")
    client.complete([LLMMessage(role="user", content="hi")])
    assert len(mcp.runs) == 2
    assert mcp.runs[0].success is False
    assert mcp.runs[0].error and "provider down" in mcp.runs[0].error
    assert mcp.runs[1].success is True
    assert mcp.runs[0].role == "red_ideation"
    assert mcp.runs[1].role == "red_ideation"


def test_exhausted_chain_reraises(monkeypatch):
    router, mcp = _router_with_clients(
        monkeypatch, [_BoomLLM(), _BoomLLM(), _BoomLLM(), _BoomLLM()])
    client = router.client_for("red_ideation")
    with pytest.raises(RuntimeError, match="provider down"):
        client.complete([LLMMessage(role="user", content="hi")])
    # Every attempt was still recorded as a failed row.
    assert len(mcp.runs) >= 2
    assert all(r.success is False for r in mcp.runs)
```

- [ ] **Run it, verify it fails** — `uv run pytest test/test_model_router_fallback.py -q`. Expect `AttributeError: 'ModelRouter' object has no attribute 'client_for'`.

- [ ] **Implement** — append to `interfaces/model_router.py`, after the `resolve` method (still inside the class), the `_client_for_route`, `_price`, and `client_for` methods; then add the `RoutedClient` class at module level:

```python
    def _client_for_route(self, route: ModelRoute) -> LLMClient:
        """Construct the low-level LLMClient for one route.

        The synthetic `local` provider maps to the auto-detected local
        backend; every other provider goes through make_llm with an explicit
        model. make_llm's own auto-detect picks the nemotron/claude_cli/mock
        backend, so a credential-free run still resolves real-provider routes
        to the local backend.
        """
        if route.provider == _LOCAL_PROVIDER:
            return make_llm(backend=route.model)
        return make_llm(model=route.model)

    def _price(self, model: str, resp: LLMResponse) -> float | None:
        """Compute USD cost from the pricing table; None for an unknown model."""
        row = self.cfg.models.pricing.get(model)
        if row is None:
            if model not in self._warned_models:
                LOG.warning("no pricing for model %r; cost_usd will be null", model)
                self._warned_models.add(model)
            return None
        return (
            resp.input_tokens / 1_000_000 * row.input_per_mtok_usd
            + resp.output_tokens / 1_000_000 * row.output_per_mtok_usd
        )

    def client_for(self, role: str) -> RoutedClient:
        """Return a RoutedClient bound to `role`'s fallback chain."""
        chain = self.resolve(role)  # raises ValueError for unknown role
        return RoutedClient(role=role, chain=chain, router=self)


class RoutedClient(LLMClient):
    """An LLMClient that walks a role's fallback chain.

    `complete()` tries each route in order; on a provider/timeout error it
    logs a failed `model_runs` row and advances to the next route. A
    successful attempt logs a `success=True` row with token counts and cost.
    Only an exhausted chain re-raises.
    """

    name = "routed"

    def __init__(self, role: str, chain: list[ModelRoute], router: ModelRouter) -> None:
        self.role = role
        self.chain = chain
        self._router = router

    def _log(self, route: ModelRoute, resp: LLMResponse | None,
             latency_ms: int, error: str | None) -> None:
        """Write one model_runs row; never let accounting break the pipeline."""
        mcp = self._router.mcp
        if mcp is None:
            return
        cost = (
            self._router._price(route.model, resp)
            if resp is not None else None
        )
        try:
            mcp.log_model_run(ModelRunInput(
                role=self.role,
                model=route.model,
                provider=route.provider,
                input_tokens=resp.input_tokens if resp else 0,
                output_tokens=resp.output_tokens if resp else 0,
                latency_ms=latency_ms,
                cost_usd=cost,
                success=error is None,
                error=error,
            ))
        except Exception as e:  # noqa: BLE001 - accounting is best-effort
            LOG.warning("log_model_run failed for role %s: %s", self.role, e)

    def complete(
        self,
        messages: list[LLMMessage],
        system: str = "",
        max_tokens: int = 2000,
        temperature: float = 0.7,
    ) -> LLMResponse:
        last_error: Exception | None = None
        for i, route in enumerate(self.chain):
            client = self._router._client_for_route(route)
            t0 = time.monotonic()
            try:
                resp = client.complete(
                    messages, system=system,
                    max_tokens=max_tokens, temperature=temperature,
                )
            except Exception as e:  # noqa: BLE001 - fall through to next link
                latency = int((time.monotonic() - t0) * 1000)
                self._log(route, None, latency, error=str(e)[:500])
                last_error = e
                LOG.warning(
                    "route %s/%s failed for role %s (%d/%d): %s",
                    route.provider, route.model, self.role,
                    i + 1, len(self.chain), e,
                )
                continue
            latency = int((time.monotonic() - t0) * 1000)
            self._log(route, resp, latency, error=None)
            return resp
        # Chain exhausted — even the local link failed.
        assert last_error is not None
        raise last_error
```

  Add `RoutedClient` to a module `__all__` at the end of the file:

```python
__all__ = ["ModelRouter", "RoutedClient"]
```

- [ ] **Run it, verify it passes** — `uv run pytest test/test_model_router_fallback.py -q` → `3 passed`. Run `uv run pytest test/test_model_router_resolve.py -q` → `8 passed` (no regression). Run `uv run ruff check interfaces/model_router.py` → `All checks passed!`.

- [ ] **Commit** — `git add interfaces/model_router.py test/test_model_router_fallback.py && git commit -m "feat(router): RoutedClient walks the fallback chain with model_runs accounting"`.

---

## Task 5 — Accounting correctness: one row per success, pricing, unknown model

**Files:**
- Test: `test/test_model_router_accounting.py`

### Steps

- [ ] **Write failing test** — create `test/test_model_router_accounting.py`:

```python
import shutil

from infra.config import load_config
from interfaces.config_schema import ModelRoute
from interfaces.llm import LLMClient, LLMMessage, LLMResponse
from interfaces.model_router import ModelRouter


class _OkLLM(LLMClient):
    name = "ok"

    def __init__(self, in_tok=1_000_000, out_tok=1_000_000):
        self._in, self._out = in_tok, out_tok

    def complete(self, messages, system="", max_tokens=2000, temperature=0.7):
        return LLMResponse(text="done", input_tokens=self._in, output_tokens=self._out)


class _RecordingMCP:
    def __init__(self):
        self.runs = []

    def log_model_run(self, run):
        self.runs.append(run)
        return f"RUN-{len(self.runs)}"


class _BoomMCP:
    def log_model_run(self, run):
        raise RuntimeError("db locked")


def test_success_writes_exactly_one_row(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    mcp = _RecordingMCP()
    router = ModelRouter(load_config(), mcp=mcp)
    monkeypatch.setattr(router, "_client_for_route", lambda route: _OkLLM())
    router.client_for("red_ideation").complete([LLMMessage(role="user", content="x")])
    assert len(mcp.runs) == 1
    row = mcp.runs[0]
    assert row.role == "red_ideation"
    assert row.success is True
    assert row.error is None


def test_cost_matches_pricing_table(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    mcp = _RecordingMCP()
    cfg = load_config()
    router = ModelRouter(cfg, mcp=mcp)
    # Force the resolved chain to a single known-priced route.
    route = ModelRoute(provider="nvidia", model="nvidia/nemotron-3-super-120b-a12b")
    monkeypatch.setattr(router, "resolve", lambda role: [route])
    monkeypatch.setattr(router, "_client_for_route", lambda r: _OkLLM(1_000_000, 1_000_000))
    router.client_for("red_ideation").complete([LLMMessage(role="user", content="x")])
    # 1M input @ 0.30 + 1M output @ 0.90 = 1.20
    assert abs(mcp.runs[0].cost_usd - 1.20) < 1e-6


def test_unknown_model_yields_null_cost(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    mcp = _RecordingMCP()
    router = ModelRouter(load_config(), mcp=mcp)
    route = ModelRoute(provider="nvidia", model="nvidia/some-unpriced-model")
    monkeypatch.setattr(router, "resolve", lambda role: [route])
    monkeypatch.setattr(router, "_client_for_route", lambda r: _OkLLM())
    router.client_for("red_ideation").complete([LLMMessage(role="user", content="x")])
    assert mcp.runs[0].cost_usd is None


def test_log_model_run_failure_is_swallowed(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    router = ModelRouter(load_config(), mcp=_BoomMCP())
    monkeypatch.setattr(router, "_client_for_route", lambda r: _OkLLM())
    # Must NOT raise even though log_model_run raises.
    resp = router.client_for("red_ideation").complete(
        [LLMMessage(role="user", content="x")])
    assert resp.text == "done"


def test_no_mcp_means_no_accounting(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    router = ModelRouter(load_config(), mcp=None)
    monkeypatch.setattr(router, "_client_for_route", lambda r: _OkLLM())
    # Router with no MCP still completes — accounting is just skipped.
    resp = router.client_for("red_ideation").complete(
        [LLMMessage(role="user", content="x")])
    assert resp.text == "done"
```

- [ ] **Run it, verify it passes** — `uv run pytest test/test_model_router_accounting.py -q`. This task adds no implementation — it verifies Task 4's `RoutedClient` already satisfies the accounting contract. Expect `5 passed`. If `test_cost_matches_pricing_table` fails, fix `_price` in `interfaces/model_router.py`; if `test_log_model_run_failure_is_swallowed` fails, confirm the `except Exception` in `_log`.

- [ ] **Run ruff** — `uv run ruff check test/test_model_router_accounting.py` → `All checks passed!`.

- [ ] **Commit** — `git add test/test_model_router_accounting.py && git commit -m "test(router): pin RoutedClient accounting, pricing, and swallowed-log behaviour"`.

---

## Task 6 — Wire `ModelRouter` into `infra/bootstrap.py` and `Runtime`

**Files:**
- Modify: `infra/bootstrap.py`
- Test: `test/test_model_router_resolve.py` (add a bootstrap test)

### Steps

- [ ] **Write failing test** — append to `test/test_model_router_resolve.py`:

```python
def test_boot_exposes_router_on_runtime():
    from infra.bootstrap import boot
    from interfaces.model_router import ModelRouter
    rt = boot(use_mock_provisioner=True)
    try:
        assert isinstance(rt.router, ModelRouter)
        # The router shares the runtime's mcp handle for accounting.
        assert rt.router.mcp is rt.mcp
        # It resolves a role end to end.
        chain = rt.router.resolve("patch_generation")
        assert len(chain) >= 2
    finally:
        rt.shutdown()
```

- [ ] **Run it, verify it fails** — `uv run pytest test/test_model_router_resolve.py::test_boot_exposes_router_on_runtime -q`. Expect `AttributeError: 'Runtime' object has no attribute 'router'`.

- [ ] **Implement** — in `infra/bootstrap.py`:
  - Add the import after the existing `from infra.provisioning_nemoclaw import ...` line: `from interfaces.model_router import ModelRouter`.
  - Add a `router` field to the `Runtime` dataclass (after `enforcer`):

```python
@dataclass
class Runtime:
    """Container of all bootstrapped components."""
    cfg: MonkeyClawConfig
    db: Database
    mcp: MCPServer
    provisioner: VictimProvisioner
    alert_dispatcher: AlertDispatcher
    enforcer: PolicyEnforcer
    router: ModelRouter
```

  - In `boot`, after `enforcer = PolicyEnforcer(cfg.guardrails)` and before the `return`, construct the router and pass it:

```python
    enforcer = PolicyEnforcer(cfg.guardrails)
    # The single LLM construction point — every pipeline component routes
    # through this instead of bare make_llm(). Shares the mcp handle so each
    # complete() writes a model_runs row.
    router = ModelRouter(cfg, mcp=mcp)
    return Runtime(cfg=cfg, db=db, mcp=mcp, provisioner=provisioner,
                    alert_dispatcher=dispatcher, enforcer=enforcer, router=router)
```

- [ ] **Run it, verify it passes** — `uv run pytest test/test_model_router_resolve.py -q` → `9 passed`.

- [ ] **Run the broader suite for regressions** — `uv run pytest test/ -q -k "bootstrap or runtime or smoke"`. Expect all passing (any test constructing `Runtime(...)` positionally would break — `router` is the last field, and existing callers use `boot()` which now supplies it). If a test constructs `Runtime` directly, add `router=ModelRouter(cfg)` there.

- [ ] **Commit** — `git add infra/bootstrap.py test/test_model_router_resolve.py && git commit -m "feat(bootstrap): construct ModelRouter and expose it on Runtime"`.

---

## Task 7 — Route the red-team pipeline through `ModelRouter`

**Files:**
- Modify: `red_team/pipeline.py`
- Modify: `red_team/tournament.py`
- Test: existing `test/test_red_*.py` suites (must stay green)

### Steps

- [ ] **Write failing test** — append to `test/test_model_router_fallback.py` a test that the red pipeline accepts and uses a router:

```python
def test_red_pipeline_uses_router_clients():
    from infra.bootstrap import boot
    from red_team.pipeline import RedTeamPipeline
    rt = boot(use_mock_provisioner=True)
    try:
        pipe = RedTeamPipeline(runtime=rt)
        # Each component holds a RoutedClient bound to its role, not a bare LLM.
        from interfaces.model_router import RoutedClient
        assert isinstance(pipe.ideation.llm, RoutedClient)
        assert pipe.ideation.llm.role == "red_ideation"
        assert isinstance(pipe.execution.llm, RoutedClient)
        assert pipe.execution.llm.role == "red_execution"
        assert isinstance(pipe.judger.llm, RoutedClient)
        assert pipe.judger.llm.role == "semantic_judge"
        assert isinstance(pipe.strategist.llm, RoutedClient)
    finally:
        rt.shutdown()
```

- [ ] **Run it, verify it fails** — `uv run pytest test/test_model_router_fallback.py::test_red_pipeline_uses_router_clients -q`. Expect failure: `pipe.ideation.llm` is a `MockLLM`, not a `RoutedClient`.

- [ ] **Implement — pipeline constructor** — in `red_team/pipeline.py`:
  - Change the import line `from interfaces.llm import LLMClient, make_llm` to `from interfaces.llm import LLMClient, make_llm` plus add `from interfaces.model_router import ModelRouter, RoutedClient`.
  - Add a `router: ModelRouter | None = None` parameter to the `__init__` signature (place it right after `llm: LLMClient | None = None`).
  - Replace the `self.llm = llm or make_llm()` line and the component-construction block. New logic — after the `runtime`/`mcp` resolution block:

```python
        # The router is the single LLM construction point. From a Runtime it
        # is taken directly; otherwise built from cfg+mcp here. An explicit
        # `llm=` (test injection) still wins per component: when given, every
        # component shares that one client; otherwise each gets its
        # role-bound RoutedClient.
        if router is not None:
            self.router = router
        elif runtime is not None:
            self.router = runtime.router
        else:
            self.router = ModelRouter(self.cfg, mcp=self.mcp)

        def _client(role: str) -> LLMClient:
            return llm if llm is not None else self.router.client_for(role)

        self.llm = llm or self.router.client_for("red_execution")
```

  - Update the component construction lines to use `_client(role)`:

```python
        self.ideation = IdeationEngine(_client("red_ideation"), self.mcp, ideation_cfg)
        self._ideation_cfg = ideation_cfg
        self.tournament = ModelTournament(load_tournament_config())
        self.strategist = Strategist(_client("red_ideation"))
        self.execution = ExecutionAgent(_client("red_execution"), execution_cfg)
        self.judger = Judge(_client("semantic_judge"), self.policy, judge_cfg, mcp=self.mcp)
```

  Note: `Strategist` is idea-synthesis work — `red_ideation` is the correct role (it is breadth/workhorse, matching the spec's ideation profile).

- [ ] **Implement — tournament entrant resolution** — `red_team/pipeline.py` `_llm_for_entrant` currently calls `make_llm`. Replace it so entrants route through the router:

```python
    def _llm_for_entrant(self, entrant) -> object:
        """Resolve a routed LLM client for one model-tournament entrant.

        Tournament entrants key by `role`, so they go through the same router
        as every other call — accounted and fallback-protected. An entrant
        with an explicit provider/model still resolves via its role's chain;
        per-entrant model pinning is out of scope for this spec (see the
        model-ideation-tournament spec).
        """
        return self.router.client_for(entrant.role)
```

  Confirm `red_team/tournament.py` itself needs no change — `ModelTournament.generate` calls the injected `generate_fn`, and the pipeline supplies `_llm_for_entrant`. If `red_team/tournament.py` imports or calls `make_llm` directly, remove that import; the grep test in Task 10 will catch any remaining reference.

- [ ] **Run the targeted test, verify it passes** — `uv run pytest test/test_model_router_fallback.py::test_red_pipeline_uses_router_clients -q` → `1 passed`.

- [ ] **Run the red-team suites for regressions** — `uv run pytest test/test_red_routing.py test/test_red_tournament.py test/test_red_routing_progress.py -q`. Expect all passing — under the mock backend the router resolves every role to the mock fallback, so behaviour is identical. If a test passed `llm=MockLLM()`, it still works (the `_client` shim returns that shared client). If a test asserted on `pipe.ideation.llm` being a `MockLLM`, update it to unwrap `RoutedClient` or pass `llm=` explicitly.

- [ ] **Commit** — `git add red_team/pipeline.py red_team/tournament.py test/test_model_router_fallback.py && git commit -m "feat(red): route every red-team component through ModelRouter"`.

---

## Task 8 — Route the blue-team pipeline through `ModelRouter`

**Files:**
- Modify: `blue_team/pipeline.py`
- Test: existing `test/test_blue_*.py` suites

### Steps

- [ ] **Write failing test** — append to `test/test_model_router_fallback.py`:

```python
def test_blue_pipeline_uses_router_clients():
    from infra.bootstrap import boot
    from blue_team.pipeline import BlueTeamPipeline
    from interfaces.model_router import RoutedClient
    rt = boot(use_mock_provisioner=True)
    try:
        pipe = BlueTeamPipeline(runtime=rt)
        assert isinstance(pipe.root_cause.llm, RoutedClient)
        assert pipe.root_cause.llm.role == "root_cause"
        assert isinstance(pipe.cold_verifier.llm, RoutedClient)
        assert pipe.cold_verifier.llm.role == "cold_verification"
        assert isinstance(pipe.patch_generator.llm, RoutedClient)
        assert pipe.patch_generator.llm.role == "patch_generation"
    finally:
        rt.shutdown()
```

- [ ] **Run it, verify it fails** — `uv run pytest test/test_model_router_fallback.py::test_blue_pipeline_uses_router_clients -q`. Expect failure: components hold a `MockLLM`, not a `RoutedClient`.

- [ ] **Implement** — in `blue_team/pipeline.py`:
  - Change the import `from interfaces.llm import LLMClient, make_llm` and add `from interfaces.model_router import ModelRouter`.
  - Add `router: ModelRouter | None = None` to `__init__` (right after `llm: LLMClient | None = None`).
  - After the runtime/mcp resolution block, replace `self.llm = llm or make_llm()`:

```python
        if router is not None:
            self.router = router
        elif runtime is not None:
            self.router = runtime.router
        else:
            self.router = ModelRouter(self.cfg, mcp=self.mcp)

        def _client(role: str) -> LLMClient:
            return llm if llm is not None else self.router.client_for(role)

        # Default `self.llm` kept for any code path still reading it directly.
        self.llm = llm or self.router.client_for("patch_generation")
```

  - Update the three LLM-bearing component constructions to use `_client(role)`:

```python
        self.root_cause = root_cause or RootCauseLocator(
            llm=_client("root_cause"), mcp=self.mcp,
            cfg=RootCauseConfig(
                severity_threshold=self.cfg.repro.root_cause_severity_threshold,
            ),
        )
        self.cold_verifier = cold_verifier or ColdVerifier(
            llm=_client("cold_verification"), provisioner=self.provisioner,
            cfg=ColdVerifierConfig.from_runtime_cfg(
                self.cfg.repro, self.cfg.nemoclaw,
            ),
            policy=self.policy,
        )
```

  and:

```python
        self.patch_generator = patch_generator or PatchGenerator(
            llm=_client("patch_generation"), mcp=self.mcp,
            cfg=PatchGeneratorConfig.from_blue_team_cfg(self.cfg.blue_team),
        )
```

  Leave `TestGenerator()` and `TriageAgent()` unchanged — they take no `llm` in the current constructors; `test_generation` is reserved in the role map for when `TestGenerator` gains an LLM (spec §5.2 lists the role; the constructor change is YAGNI until `TestGenerator` uses a model).

- [ ] **Run the targeted test, verify it passes** — `uv run pytest test/test_model_router_fallback.py::test_blue_pipeline_uses_router_clients -q` → `1 passed`.

- [ ] **Run the blue-team suites for regressions** — `uv run pytest test/ -q -k blue`. Expect all passing under the mock backend. Fix any test that asserted directly on a component's `.llm` type as in Task 7.

- [ ] **Commit** — `git add blue_team/pipeline.py test/test_model_router_fallback.py && git commit -m "feat(blue): route blue-team components through ModelRouter"`.

---

## Task 9 — Route `infra/cli.py` bare `make_llm()` calls through the router

**Files:**
- Modify: `infra/cli.py`
- Test: `test/test_model_router_no_bare_make_llm.py` (created in Task 10 — this task makes it pass)

### Steps

- [ ] **Inspect** — the two CLI sites are `infra/cli.py:359` (`llm = make_llm()`) and `infra/cli.py:571` (`llm = make_llm()`), both in probe/ad-hoc-chat paths that already `boot()` a `Runtime` (`rt`). Both are execution-style chats.

- [ ] **Implement — first site (probe / ad-hoc, ~line 347-359)** — replace the local import `from interfaces.llm import make_llm` with nothing (delete the import line; the router comes from `rt`), and replace `llm = make_llm()` with:

```python
    llm = rt.router.client_for("red_execution")
    print(f"LLM backend: {llm.name}")
```

  `llm.name` for a `RoutedClient` is `"routed"`; that is acceptable for the banner. If the banner must show the underlying backend, use `local_backend_name()` from `interfaces.llm` instead — but `"routed"` is fine and honest.

- [ ] **Implement — second site (Telegram red-team, ~line 553-571)** — same change: delete the `from interfaces.llm import make_llm` import line, replace `llm = make_llm()` with:

```python
    llm = rt.router.client_for("red_execution")
    print(f"=== MonkeyClaw — Telegram red-team vs @{bot} ===")
    print(f"LLM backend: {llm.name}\n")
```

- [ ] **Check for any other `make_llm(` in `infra/`** — `grep -rn "make_llm(" infra/ --include='*.py'`. Expect zero matches outside comments. If `infra/cli.py` still constructs `make_llm` anywhere (e.g. a `--backend` override path), route it through `rt.router.client_for("red_execution")` likewise, or if it genuinely needs the low-level factory, that is the one exemption — but the spec wants the router everywhere, so prefer the router.

- [ ] **Run the CLI smoke** — `uv run pytest test/ -q -k cli`. Expect all passing. Then a manual smoke: `uv run monkeyclaw run --cycles 1 --target monkey-victim --mock` — must complete a cycle without error (the router resolves every role to the mock backend).

- [ ] **Commit** — `git add infra/cli.py && git commit -m "feat(cli): route probe and Telegram red-team chats through ModelRouter"`.

---

## Task 10 — Guard test: no bare `make_llm(` outside `interfaces/`

**Files:**
- Create: `test/test_model_router_no_bare_make_llm.py`

### Steps

- [ ] **Write the guard test** — create `test/test_model_router_no_bare_make_llm.py`:

```python
"""Constraint 3 enforcement: the router is the single LLM construction point.

No code in red_team/, blue_team/, or infra/ may call make_llm() directly.
make_llm stays the low-level factory the router itself uses, so calls inside
interfaces/ (llm.py, model_router.py) are exempt.
"""

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SCANNED_DIRS = ("red_team", "blue_team", "infra")
# A call site looks like `make_llm(` — an import line `import make_llm` or a
# `from interfaces.llm import ... make_llm` is allowed (the router needs it).
_CALL_RE = re.compile(r"\bmake_llm\s*\(")


def _offending_lines(path: Path) -> list[str]:
    out = []
    for n, line in enumerate(path.read_text().splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _CALL_RE.search(line):
            out.append(f"{path.relative_to(_ROOT)}:{n}: {stripped}")
    return out


def test_no_bare_make_llm_calls_outside_interfaces():
    offenders: list[str] = []
    for d in _SCANNED_DIRS:
        for py in (_ROOT / d).rglob("*.py"):
            offenders.extend(_offending_lines(py))
    assert not offenders, (
        "make_llm() called outside interfaces/ — route through "
        "ModelRouter.client_for(role) instead:\n" + "\n".join(offenders)
    )
```

- [ ] **Run it, verify it passes** — `uv run pytest test/test_model_router_no_bare_make_llm.py -q`. Expect `1 passed` (Tasks 7-9 removed every `make_llm(` call site). If it fails, the failure message lists the remaining call sites — convert each to `router.client_for(role)`.

- [ ] **Run ruff** — `uv run ruff check test/test_model_router_no_bare_make_llm.py` → `All checks passed!`.

- [ ] **Commit** — `git add test/test_model_router_no_bare_make_llm.py && git commit -m "test(router): guard against bare make_llm calls outside interfaces"`.

---

## Task 11 — Per-role cost rollup query on the MCP server

**Files:**
- Modify: `infra/mcp_server.py`
- Modify: `interfaces/mcp_tools.py`
- Test: `test/test_model_router_accounting.py` (extend)

### Steps

- [ ] **Write failing test** — append to `test/test_model_router_accounting.py`:

```python
def test_per_role_cost_rollup(tmp_path):
    from infra.database import Database
    from infra.mcp_server import MCPServer
    from interfaces.types import ModelRunInput
    db = Database(str(tmp_path / "t.db"))
    mcp = MCPServer(db)
    try:
        mcp.log_model_run(ModelRunInput(
            role="red_ideation", model="m1", provider="nvidia",
            input_tokens=100, output_tokens=50, latency_ms=10, cost_usd=0.5))
        mcp.log_model_run(ModelRunInput(
            role="red_ideation", model="m1", provider="nvidia",
            input_tokens=200, output_tokens=80, latency_ms=12, cost_usd=1.5))
        mcp.log_model_run(ModelRunInput(
            role="patch_generation", model="m2", provider="anthropic_or_openai",
            input_tokens=300, output_tokens=300, latency_ms=40, cost_usd=3.0))
        rollup = mcp.get_model_cost_rollup()
        by_role = {r["role"]: r for r in rollup}
        assert by_role["red_ideation"]["input_tokens"] == 300
        assert by_role["red_ideation"]["output_tokens"] == 130
        assert abs(by_role["red_ideation"]["cost_usd"] - 2.0) < 1e-6
        assert by_role["red_ideation"]["runs"] == 2
        assert abs(by_role["patch_generation"]["cost_usd"] - 3.0) < 1e-6
    finally:
        db.close()
```

- [ ] **Run it, verify it fails** — `uv run pytest test/test_model_router_accounting.py::test_per_role_cost_rollup -q`. Expect `AttributeError: 'MCPServer' object has no attribute 'get_model_cost_rollup'`.

- [ ] **Implement — server method** — in `infra/mcp_server.py`, add directly after `log_model_run`:

```python
    def get_model_cost_rollup(self) -> list[dict]:
        """Per-role token & cost rollup over all model_runs rows.

        Read-only reporting for the cycle summary and the dashboard cost
        panel — replaces the dashboard's blended token-price estimate.
        """
        rows = self.db.fetchall(
            "SELECT role, "
            "COUNT(*) AS runs, "
            "SUM(input_tokens) AS input_tokens, "
            "SUM(output_tokens) AS output_tokens, "
            "SUM(COALESCE(cost_usd, 0)) AS cost_usd, "
            "SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failures "
            "FROM model_runs GROUP BY role ORDER BY cost_usd DESC"
        )
        return [
            {
                "role": r["role"],
                "runs": r["runs"] or 0,
                "input_tokens": r["input_tokens"] or 0,
                "output_tokens": r["output_tokens"] or 0,
                "cost_usd": float(r["cost_usd"] or 0.0),
                "failures": r["failures"] or 0,
            }
            for r in rows
        ]
```

  If `Database` exposes `fetchall` differently (check `infra/database.py` — it has `fetchone`; confirm a `fetchall` exists, otherwise use `self.db.execute(...).fetchall()` consistent with how other read methods in `mcp_server.py` query). Match the existing read-method idiom in the file.

- [ ] **Implement — protocol declaration** — in `interfaces/mcp_tools.py`, add to the `MonkeyClawMCP` protocol, in the "Model run accounting" section after `log_model_run`:

```python
    def get_model_cost_rollup(self) -> list[dict]:
        """Per-role token & cost rollup over model_runs. Read-only reporting."""
        ...
```

- [ ] **Run it, verify it passes** — `uv run pytest test/test_model_router_accounting.py -q` → `6 passed`.

- [ ] **Run ruff** — `uv run ruff check infra/mcp_server.py interfaces/mcp_tools.py` → `All checks passed!`.

- [ ] **Commit** — `git add infra/mcp_server.py interfaces/mcp_tools.py test/test_model_router_accounting.py && git commit -m "feat(mcp): per-role model cost rollup query over model_runs"`.

---

## Task 12 — Dashboard cost panel + cycle-summary per-role breakdown

**Files:**
- Modify: the dashboard module (find with `grep -rln "blended" infra/`) and the cycle-summary path (find with `grep -rln "_finalize_cycle" infra/`)
- Test: `test/test_model_router_accounting.py` (extend) or the existing dashboard test file

### Steps

- [ ] **Locate the dashboard cost panel** — run `grep -rn "blended\|token.price\|cost" infra/dashboard*.py infra/*.py 2>/dev/null | grep -i cost`. Identify the function that renders the cost panel (it currently computes a blended token-price estimate, per the README).

- [ ] **Write failing test** — append to `test/test_model_router_accounting.py` a test asserting the dashboard cost panel reads `get_model_cost_rollup`. Adapt the exact import to the dashboard module name found above; the pattern:

```python
def test_dashboard_cost_panel_uses_model_runs(tmp_path):
    from infra.database import Database
    from infra.mcp_server import MCPServer
    from interfaces.types import ModelRunInput
    db = Database(str(tmp_path / "d.db"))
    mcp = MCPServer(db)
    try:
        mcp.log_model_run(ModelRunInput(
            role="patch_generation", model="frontier-coding",
            provider="anthropic_or_openai", input_tokens=1000,
            output_tokens=1000, latency_ms=50, cost_usd=18.0))
        # The dashboard cost view is a function of get_model_cost_rollup.
        rollup = mcp.get_model_cost_rollup()
        total = sum(r["cost_usd"] for r in rollup)
        assert abs(total - 18.0) < 1e-6
        assert rollup[0]["role"] == "patch_generation"
    finally:
        db.close()
```

- [ ] **Run it, verify it passes** — `uv run pytest test/test_model_router_accounting.py::test_dashboard_cost_panel_uses_model_runs -q` → `1 passed` (it depends only on Task 11's method).

- [ ] **Implement — dashboard panel** — in the dashboard cost-panel function, replace the blended-estimate computation with a call to `mcp.get_model_cost_rollup()`. Render: a row per role with `runs`, `input_tokens`, `output_tokens`, `cost_usd`, `failures`, plus a total `cost_usd` footer. Keep the panel's existing HTML/JSON shape — only the data source changes. If the panel had no `model_runs` data before, an empty rollup must render an empty panel cleanly (no division by zero).

- [ ] **Implement — cycle summary breakdown** — locate `_finalize_cycle` (`grep -rn "_finalize_cycle" infra/`). Where it builds the `CycleSummaryInput` / human-readable summary string, append a per-role line from `mcp.get_model_cost_rollup()`, e.g.:

```python
        rollup = self.mcp.get_model_cost_rollup()
        if rollup:
            cost_lines = "; ".join(
                f"{r['role']}: {r['cost_usd']:.4f} USD / {r['runs']} runs"
                for r in rollup
            )
            summary_text += f"\nModel cost by role — {cost_lines}"
```

  Adapt variable names to the actual `_finalize_cycle` body. This is additive — `total_tokens_used` on `CycleSummaryInput` is unchanged; no schema change.

- [ ] **Run the dashboard + orchestrator suites** — `uv run pytest test/ -q -k "dashboard or cycle or orchestrator"`. Expect all passing.

- [ ] **Commit** — `git add -A && git commit -m "feat(dashboard): model_runs-backed per-role cost panel and cycle-summary breakdown"`.

---

## Task 13 — Full-suite verification and cleanup

**Files:**
- None (verification only)

### Steps

- [ ] **Run the full test suite** — `uv run pytest -q`. Expect every test passing — the README baseline plus the new `test_model_router_*` tests. If anything is red, fix it before proceeding (most likely a test that asserted on a component's bare `.llm` type — unwrap `RoutedClient` or pass `llm=` explicitly).

- [ ] **Run ruff over the whole repo** — `uv run ruff check .`. Expect `All checks passed!`. Fix any lint (unused imports left from removed `make_llm` imports are the likely offender).

- [ ] **Smoke the demo** — `uv run monkeyclaw run --cycles 1 --target monkey-victim --mock` then `uv run monkeyclaw blue-team`. Both must complete without error. Then `uv run monkeyclaw dashboard` and open `http://127.0.0.1:8787` — confirm the cost panel renders the per-role rollup (populated because the mock cycle wrote `model_runs` rows).

- [ ] **Confirm `model_runs` is populated** — after the smoke run: `sqlite3 data/monkeyclaw-mock.db "SELECT role, COUNT(*), SUM(input_tokens) FROM model_runs GROUP BY role;"`. Expect rows for `red_ideation`, `red_execution`, `semantic_judge`, etc. — proving accounting is live (the table was empty before this spec).

- [ ] **Commit** — `git add -A && git commit -m "chore(routing): final verification — full suite green, model_runs populated"`.

---

## Spec coverage self-review

Section-by-section check that every spec requirement is covered:

- **§2 scope — all 12+ roles operative:** Task 1 adds `red_code_ideation`, `mutation`, `cold_verification`, `summarization`, `test_generation` to `_default_model_roles` + YAML; `semantic_judge_appeal` is in `policy`/`roles` too (13 roles in `ALL_ROLES`).
- **§2 — routing policy by tier:** Task 1 adds `tiers` + `policy` maps; Task 3 `resolve` uses them.
- **§2 — fallback chains ending in guaranteed-local:** Task 2 `local_backend_name`, Task 3 `resolve` appends `_local_route()` last, Task 4 `RoutedClient.complete` walks the chain.
- **§2 — per-role token & cost accounting via `log_model_run` + pricing:** Task 1 `pricing`, Task 4 `_price`/`_log`, Task 11 rollup.
- **§2 — single entrypoint `interfaces/model_router.py`:** Tasks 3-4 create it; Tasks 7-9 convert callers; Task 10 enforces.
- **§3 — completes not rebuilds:** `ModelRoute`/`ModelsConfig` extended additively (Task 1); `make_llm` surface unchanged (Task 2 only adds a helper).
- **§4.1 contract firewall:** router, config, pricing all in `interfaces/` (Tasks 1-4).
- **§4.2 backward compatible:** new fields all `default_factory`; old `make_llm()` no-role still resolves `DEFAULT_MODEL` (untouched). Existing 8 roles keep meaning (Task 1 keeps them).
- **§4.3 single construction point + grep test:** Tasks 7-10.
- **§4.4 routing never blocks the loop:** guaranteed-local link (Tasks 2-3); `test_exhausted_chain_reraises` and the mock-backend regression runs confirm a credential-free run resolves every role.
- **§4.5 accounting mandatory & free, failures swallowed:** Task 4 `_log` wraps every attempt; `test_log_model_run_failure_is_swallowed` (Task 5).
- **§4.6 declarative tiers:** Task 1 — tiers/policy are config, `resolve` does no runtime heuristic.
- **§5.1 four tiers:** `_default_tiers` has `cheap`/`workhorse`/`heavy`/`frontier` (Task 1); `test_tiers_declared`.
- **§5.1 `safety_judge` direct route, no tier:** `_default_policy` omits it; `test_policy_covers_every_routed_role` asserts the omission; `resolve` handles a role-without-tier (`test_resolve_implicit_two_step_chain`).
- **§5.2 role→tier table:** `_default_policy` reproduces every row of the spec table including `semantic_judge_appeal: frontier`.
- **§5.2 override beats tier:** `resolve` adds the explicit `roles[]` route first; `test_resolve_override_beats_tier`.
- **§5.3 ordered chain `[primary]→[tier]→[local]` + config-declared `fallback` + implicit two-step:** `resolve` order (Task 3); `test_resolve_explicit_fallback_threaded`, `test_resolve_implicit_two_step_chain`. Each attempt writes a row (`test_fallback_writes_two_model_runs_rows`).
- **§7.1 `ModelRouter`/`RoutedClient` interface:** Tasks 3-4 match the spec signatures exactly (`__init__(cfg, mcp=None)`, `resolve→list[ModelRoute]`, `client_for→RoutedClient`).
- **§7.2 `ModelTier`/`PriceRow`/extended `ModelRoute`/`ModelsConfig`:** Task 1 (uses `Field(default_factory=...)` per spec).
- **§7.3 pricing table, unknown model → `None` + one-time warning:** `_price` (Task 4); `test_unknown_model_yields_null_cost`; `_warned_models` set gives one-time warning.
- **§7.4 `make_llm` no surface change:** Task 2 only adds `local_backend_name`; `make_llm` body untouched.
- **§8 no new tables, `model_runs` first real producer, `cost_usd` populated:** no schema edit; Tasks 4 & 11.
- **§9.1 bootstrap constructs router once on `Runtime`:** Task 6.
- **§9.2 per-call flow:** Task 4 `RoutedClient.complete` implements the exact attempt→price→log→fallback flow.
- **§9.3 per-cycle rollup query grouped by role:** Task 11 `get_model_cost_rollup`; Task 12 cycle-summary line.
- **§10 integration points:** bootstrap (T6), red pipeline (T7), blue pipeline (T8), component constructors (T7/T8 via `_client(role)`), tournament (T7), `infra/cli.py` (T9), dashboard (T12), YAML (T1).
- **§11 error handling:** provider error → next link (T4); unknown role → `ValueError` (`test_resolve_unknown_role_raises`, T3); unknown model → `cost_usd=None`+warn (T4/T5); `log_model_run` failure swallowed (T4/T5); missing NVIDIA key → guaranteed-local link (T2/T3, mock-backend regression runs).
- **§12 testing strategy:** every named test file is created — `test_model_routing.py` extended (T1), `test_model_router_resolve.py` (T2/T3/T6), `test_model_router_fallback.py` (T4/T7/T8), `test_model_router_accounting.py` (T5/T11/T12), `test_model_router_no_bare_make_llm.py` (T10). Existing red/blue e2e suites kept green under mock (T7/T8/T13).
- **§13 phased delivery:** Phase 0 = T1; Phase 1 = T2-T6; Phase 2 = T7-T10; Phase 3 = T11-T12; T13 = final verification. Each task ends green.
- **§14 open questions:** (1) frontier placeholder `provider="anthropic_or_openai"` kept as-is and resolved to the local link in credential-free envs — `_client_for_route` sends real providers through `make_llm`'s auto-detect, which lands on the local backend; no binding invented. (2) `semantic_judge_appeal` role reserved in `roles`/`policy` (T1) but no appeal wiring — left to the red-team search-dynamics work, as the spec directs. (3) `heavy`/Ultra tier declared (`_default_tiers`) but no role maps to it in `_default_policy` — a deployment can re-point a role via the `policy` map without code change.

All spec sections are covered. **Total: 13 tasks.**
