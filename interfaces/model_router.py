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


__all__ = ["ModelRouter", "RoutedClient"]
