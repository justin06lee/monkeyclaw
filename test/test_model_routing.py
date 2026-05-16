from infra.config import load_config
from interfaces.llm import LLMMessage

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


def test_router_resolves_role_to_client(monkeypatch):
    # Role-aware construction belongs to ModelRouter, not make_llm.
    monkeypatch.setenv("MC_LLM_BACKEND", "mock")
    from interfaces.model_router import ModelRouter, RoutedClient
    router = ModelRouter(load_config())
    client = router.client_for("red_ideation")
    assert isinstance(client, RoutedClient)
    assert client.role == "red_ideation"


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


def test_make_llm_defaults_to_nemotron_when_credentials_present(monkeypatch):
    # With no explicit backend, make_llm auto-selects: an NVIDIA credential
    # (or base URL) resolves to the nemotron backend.
    monkeypatch.delenv("MC_LLM_BACKEND", raising=False)
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    from interfaces.llm import make_llm

    client = make_llm()
    assert client.name == "nemotron"


def test_claude_flag_backend_uses_subprocess_harness(tmp_path, monkeypatch):
    bin_path = tmp_path / "claude"
    args_path = tmp_path / "args.txt"
    bin_path.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$@\" > {args_path}\n"
        "printf 'harness ok'\n",
        encoding="utf-8",
    )
    bin_path.chmod(0o755)
    monkeypatch.setenv("MC_CLAUDE_BINARY", str(bin_path))

    from interfaces.llm import make_llm

    client = make_llm(backend="claude")
    resp = client.complete(
        [LLMMessage(role="user", content="hello")],
        system="system",
    )

    assert client.name == "claude_code"
    assert resp.text == "harness ok"
    args = args_path.read_text(encoding="utf-8")
    assert "--print" in args
    assert "--model" in args and "sonnet" in args
    assert "--thinking" in args and "adaptive" in args


def test_codex_and_opencode_backend_names(tmp_path, monkeypatch):
    for env_name, binary in (
        ("MC_CODEX_BINARY", "codex"),
        ("MC_OPENCODE_BINARY", "opencode"),
    ):
        path = tmp_path / binary
        path.write_text("#!/bin/sh\nprintf 'ok'\n", encoding="utf-8")
        path.chmod(0o755)
        monkeypatch.setenv(env_name, str(path))

    from interfaces.llm import make_llm

    assert make_llm(backend="codex").name == "codex"
    assert make_llm(backend="opencode").name == "opencode"


def test_codex_backend_uses_stdin_and_last_message_file(tmp_path, monkeypatch):
    bin_path = tmp_path / "codex"
    stdin_path = tmp_path / "stdin.txt"
    args_path = tmp_path / "args.txt"
    bin_path.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$@\" > {args_path}\n"
        f"cat > {stdin_path}\n"
        "out=''\n"
        "prev=''\n"
        "for arg in \"$@\"; do\n"
        "  if [ \"$prev\" = '--output-last-message' ]; then out=\"$arg\"; fi\n"
        "  prev=\"$arg\"\n"
        "done\n"
        "printf 'final only' > \"$out\"\n"
        "printf 'banner noise\\nfinal only\\n'\n",
        encoding="utf-8",
    )
    bin_path.chmod(0o755)
    monkeypatch.setenv("MC_CODEX_BINARY", str(bin_path))

    from interfaces.llm import make_llm

    resp = make_llm(backend="codex").complete(
        [LLMMessage(role="user", content="hello")],
        system="system",
    )

    assert resp.text == "final only"
    assert "[SYSTEM]" in stdin_path.read_text(encoding="utf-8")
    args = args_path.read_text(encoding="utf-8")
    assert "--output-last-message" in args
    assert args.rstrip().endswith("-")


def test_observed_llm_logs_agent_events_and_model_runs():
    from infra.mock_mcp import MockMCP
    from interfaces.llm import MockLLM, ObservedLLM

    mcp = MockMCP(verbose=False)
    inner = MockLLM()
    inner.queue("hello from agent")
    client = ObservedLLM(
        inner,
        mcp,
        agent_id="red-ideation",
        agent_kind="llm",
        role="red_ideation",
    )
    resp = client.complete([LLMMessage(role="user", content="make ideas")])

    assert resp.text == "hello from agent"
    state = mcp.dump_state()
    assert state["agent_events"] == 2
    assert state["model_runs"] == 1
