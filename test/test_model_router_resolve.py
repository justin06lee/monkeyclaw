import shutil

import pytest

from infra.config import load_config
from interfaces.config_schema import ModelRoute
from interfaces.llm import local_backend_name
from interfaces.model_router import ModelRouter


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
