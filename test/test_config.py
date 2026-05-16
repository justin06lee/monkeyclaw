"""Config loading and env override behavior."""

from __future__ import annotations

from infra.config import load_config


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("MC_LANES__POOL_SIZE", "12")
    monkeypatch.setenv("MC_ORCHESTRATOR__AUTO_COMMIT_PATCHES", "true")
    monkeypatch.setenv("MC_IDEATION__DEDUP_THRESHOLD", "0.95")
    cfg = load_config()
    assert cfg.lanes.pool_size == 12
    assert cfg.ideation.dedup_threshold == 0.95


def test_defaults_load():
    cfg = load_config()
    # Deep-dive lanes run one synthesized attack chain to depth, so the
    # per-lane timeout is widened past the spec §14.1 default of 600s.
    assert cfg.lanes.lane_timeout_seconds == 1200
    assert cfg.nemoclaw.repo_path
    assert "PROMPT-INJ" in cfg.judgment.tier2_zones


def test_purple_config_defaults():
    cfg = load_config()
    assert cfg.purple.enabled is True
    assert cfg.purple.full_sweep_every == 10
    assert cfg.purple.self_governance_enabled is True
