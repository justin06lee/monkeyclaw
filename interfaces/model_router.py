"""Model router — operative per-role routing, fallback chains, accounting.

Lives in `interfaces/` like `llm.py`: the contract firewall. `red_team/` and
`blue_team/` import `ModelRouter` read-only and never call `make_llm` directly.

`ModelRouter` is constructed once at bootstrap from `MonkeyClawConfig` (and an
optional MCP handle for `log_model_run`). `client_for(role)` returns a
`RoutedClient` bound to that role's fallback chain.

A role resolves to an ordered chain of `ModelRoute`s:

    [ override-or-tier route ] -> [ explicit fallback... ] ->
    [ tier-default route ] -> [ local route ] -> [ mock route ]

A model outage degrades quality but never halts the cycle: the chain falls
through to the local backend (`claude_cli` when its binary is on PATH, else
`mock`). The local backend can still fail — `ClaudeCLILLM.complete` raises on
timeout or a non-zero exit — so `mock` is appended as a final, unconditional
terminal link. `mock` needs no credentials and never fails, so the chain is
genuinely guaranteed to terminate with a response.
"""

from __future__ import annotations

import logging
import time

from interfaces.config_schema import ModelRoute, MonkeyClawConfig
from interfaces.llm import LLMClient, LLMMessage, LLMResponse, local_backend_name, make_llm
from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import ModelRunInput

LOG = logging.getLogger("monkeyclaw.model_router")

# The synthetic provider string marking a route as a local-backend link
# rather than a real frontier/NVIDIA route. A route with this provider is
# constructed via an explicit `make_llm(backend=...)` call instead of going
# through make_llm's model-based auto-detect.
_LOCAL_PROVIDER = "local"


class ModelRouter:
    """Resolves roles to fallback chains and constructs routed clients."""

    def __init__(self, cfg: MonkeyClawConfig, mcp: MonkeyClawMCP | None = None) -> None:
        self.cfg = cfg
        self.mcp = mcp
        self._warned_models: set[str] = set()

    def _local_route(self) -> ModelRoute:
        """The local-backend link of every chain.

        `claude_cli` -> model name "claude_cli"; `mock` -> "mock". The provider
        is the synthetic "local" marker so accounting/allowlist logic can
        recognise the fallback link. This link can still fail (the claude CLI
        raises on timeout / non-zero exit), so `resolve()` appends a `mock`
        route after it as the unconditional terminal link.
        """
        backend = local_backend_name()
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

        # 3) local-backend link (claude_cli when available, else mock).
        _add(self._local_route())
        # 4) unconditional terminal link. The local link above can still fail
        #    (the claude CLI raises on timeout / non-zero exit), so `mock` —
        #    which needs no credentials and never fails — guarantees the chain
        #    always terminates with a response. Deduped away when the local
        #    link already resolved to `mock`.
        _add(ModelRoute(provider=_LOCAL_PROVIDER, model="mock"))
        return chain

    # Backend names that are local/auto-detected, not real frontier providers.
    # When a non-local route's constructed client reports one of these, the
    # run was served by a local backend that ignores the requested model — so
    # accounting must log it under the backend that actually served it.
    _LOCAL_BACKENDS = frozenset({"claude_cli", "mock"})

    def _client_for_route(self, route: ModelRoute) -> tuple[LLMClient, ModelRoute]:
        """Construct the low-level LLMClient for one route.

        Returns the client and the *effective* route — the route that
        accounting should log and price. The synthetic `local` provider maps
        to the auto-detected local backend; every other provider goes through
        make_llm with an explicit model. make_llm's own auto-detect picks the
        nemotron/claude_cli/mock backend, so a credential-free run still
        resolves real-provider routes to a local backend.

        When a non-local route is served by an auto-detected local backend
        (`claude_cli`/`mock`), the constructed client ignores the requested
        frontier model entirely. Logging/pricing under `route.model` would be
        fictional, so the effective route is rewritten to the synthetic
        `local` provider and the actual backend name as the model (an unpriced
        model -> null cost, which `_price` already handles).
        """
        if route.provider == _LOCAL_PROVIDER:
            return make_llm(backend=route.model), route
        client = make_llm(model=route.model)
        if client.name in self._LOCAL_BACKENDS:
            # The frontier route fell back to a local backend; log/price under
            # what actually served the request, not the requested model.
            return client, ModelRoute(provider=_LOCAL_PROVIDER, model=client.name)
        return client, route

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
            # `effective` is the route accounting logs/prices — it differs
            # from `route` when a frontier route is served by an auto-detected
            # local backend (see `_client_for_route`).
            client, effective = self._router._client_for_route(route)
            t0 = time.monotonic()
            try:
                resp = client.complete(
                    messages, system=system,
                    max_tokens=max_tokens, temperature=temperature,
                )
            except Exception as e:  # noqa: BLE001 - fall through to next link
                latency = int((time.monotonic() - t0) * 1000)
                self._log(effective, None, latency, error=str(e)[:500])
                last_error = e
                LOG.warning(
                    "route %s/%s failed for role %s (%d/%d): %s",
                    effective.provider, effective.model, self.role,
                    i + 1, len(self.chain), e,
                )
                continue
            latency = int((time.monotonic() - t0) * 1000)
            self._log(effective, resp, latency, error=None)
            return resp
        # Chain exhausted — even the local link failed.
        assert last_error is not None
        raise last_error


__all__ = ["ModelRouter", "RoutedClient"]
