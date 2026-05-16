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
