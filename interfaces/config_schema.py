"""Config schema (Pydantic) — single source of truth for runtime knobs.

Defaults mirror spec §14.1. Values are loaded from `configs/monkeyclaw.yaml`
via `infra.config.load_config`.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class EmbeddingConfig(BaseModel):
    model: str = "sentence-transformers/all-MiniLM-L6-v2"
    dim: int = 384


class IdeationConfig(BaseModel):
    model: str = "claude-sonnet-4-6"
    temperature: float = 0.75
    max_tokens_per_mode: int = 2000
    modes: list[str] = ["creative", "code_grounded", "history_informed"]
    dedup_threshold: float = 0.92
    near_dup_threshold: float = 0.80
    retry_max: int = 3


class LaneConfig(BaseModel):
    pool_size: int = 4
    lane_timeout_seconds: int = 600
    max_turns: int = 50
    psutil_interval_seconds: float = 0.5


class JudgmentConfig(BaseModel):
    tier2_zones: list[str] = [
        "PROMPT-INJ", "SOCIAL-ENG", "MEM-STATE", "MEM-SHARED",
    ]
    tier2_model: str = "claude-sonnet-4-6"
    tier2_confidence_threshold: float = 0.5


class ReproConfig(BaseModel):
    replay_count: int = 5
    repro_rate_threshold: float = 0.5
    delta_debug_max_iterations: int = 30
    root_cause_severity_threshold: str = "high"
    cold_verify_max_attempts: int = 3


class BlueTeamConfig(BaseModel):
    patch_verify_max_attempts: int = 3
    auto_commit_patches: bool = False
    high_severity_alt_count: int = 3


class OrchestratorConfig(BaseModel):
    red_team_batch_size: int = 50
    regression_before_batch: bool = True
    graceful_shutdown_timeout_s: int = 30
    persist_queue_state: bool = True


class NotificationsConfig(BaseModel):
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    webhook_urls: list[str] = []
    alert_severity_floor: str = "high"


class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: str | None = "logs/monkeyclaw.log"
    rotate_max_bytes: int = 50_000_000
    rotate_backups: int = 14


class StorageConfig(BaseModel):
    db_path: str = "data/monkeyclaw.db"
    backup_dir: str = "data/backups"
    backup_interval_minutes: int = 30


class NemoClawConfig(BaseModel):
    repo_path: str = "~/NemoClaw"
    cli_binary: str = "nemoclaw"
    version: str = "alpha"
    sandbox_create_timeout_s: int = 120
    default_policy_path: str = "configs/default_policy.yaml"
    default_agent_config_path: str = "configs/default_agent.yaml"
    monitored_paths: list[str] = ["/tmp/openshell", "~/.nemoclaw"]
    allowed_paths: list[str] = ["/tmp/openshell"]


class MonkeyClawConfig(BaseModel):
    embedding: EmbeddingConfig = Field(default_factory=EmbeddingConfig)
    ideation: IdeationConfig = Field(default_factory=IdeationConfig)
    lanes: LaneConfig = Field(default_factory=LaneConfig)
    judgment: JudgmentConfig = Field(default_factory=JudgmentConfig)
    repro: ReproConfig = Field(default_factory=ReproConfig)
    blue_team: BlueTeamConfig = Field(default_factory=BlueTeamConfig)
    orchestrator: OrchestratorConfig = Field(default_factory=OrchestratorConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    nemoclaw: NemoClawConfig = Field(default_factory=NemoClawConfig)
