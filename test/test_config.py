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


def test_judge_config_block_present():
    import yaml
    from pathlib import Path
    cfg = yaml.safe_load(
        Path("configs/monkeyclaw.yaml").read_text())
    judge = cfg["red_team"]["judge"]
    assert judge["disagreement_threshold"] == 0.5
    assert judge["low_confidence_threshold"] == 0.35
    assert judge["appeal"]["enabled"] is False
    assert judge["appeal"]["per_cycle_cap"] == 3
    assert "elo_noise_band" in judge
    assert "elo_k" in judge
    assert "pairwise_compare_budget" in judge
