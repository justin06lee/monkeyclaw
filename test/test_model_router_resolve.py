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
