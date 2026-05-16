from infra.config import load_config


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
