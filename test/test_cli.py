import subprocess
import sys


def _cli(*args, env_extra=None, timeout=180):
    import os
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["PATH"] = os.path.expanduser("~/.local/bin") + ":" + env.get("PATH", "")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "infra.cli", *args],
        capture_output=True, text=True, timeout=timeout, env=env,
        cwd=repo_root)


def test_cli_help_lists_demo_command():
    r = _cli("--help")
    assert r.returncode == 0
    assert "demo" in r.stdout


def test_cli_demo_runs_planted_profile(tmp_path):
    r = _cli("demo", "--profile", "planted-filesystem",
             env_extra={"MC_STORAGE__DB_PATH": str(tmp_path / "demo.db"),
                        "MC_LLM_BACKEND": "mock"})
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"


def test_cli_demo_unknown_profile_fails(tmp_path):
    r = _cli("demo", "--profile", "not-a-real-profile",
             env_extra={"MC_STORAGE__DB_PATH": str(tmp_path / "demo.db"),
                        "MC_LLM_BACKEND": "mock"})
    assert r.returncode != 0


def test_cli_run_mock_cycle(tmp_path):
    r = _cli("run", "--cycles", "1", "--target", "planted-filesystem", "--mock",
             env_extra={"MC_STORAGE__DB_PATH": str(tmp_path / "run.db"),
                        "MC_LLM_BACKEND": "mock"})
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"


def test_cli_status_on_fresh_db(tmp_path):
    r = _cli("status",
             env_extra={"MC_STORAGE__DB_PATH": str(tmp_path / "status.db")})
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
