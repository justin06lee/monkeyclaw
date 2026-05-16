from infra.config import load_config
from interfaces.llm import LLMMessage


def test_models_config_has_nine_roles():
    cfg = load_config()
    roles = cfg.models.roles
    for role in ("cheap_extraction", "red_ideation", "red_execution",
                 "semantic_judge", "safety_judge", "root_cause",
                 "patch_generation", "codex_code_work"):
        assert role in roles, f"missing model role {role}"
        assert roles[role].provider
        assert roles[role].model


def test_make_llm_resolves_role(monkeypatch):
    monkeypatch.setenv("MC_LLM_BACKEND", "mock")
    from interfaces.llm import make_llm
    client = make_llm(role="red_ideation")
    assert client.name == "mock"


def test_make_llm_defaults_to_nemotron(monkeypatch):
    monkeypatch.delenv("MC_LLM_BACKEND", raising=False)
    monkeypatch.delenv("MC_NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("NIM_API_KEY", raising=False)
    monkeypatch.delenv("MC_NEMOTRON_BASE_URL", raising=False)

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
    assert "--thinking" in args and "medium" in args


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
