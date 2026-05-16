"""Config schema (Pydantic) — single source of truth for runtime knobs.

Defaults mirror spec §14.1. Values are loaded from `configs/monkeyclaw.yaml`
via `infra.config.load_config`.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from interfaces.nemoclaw_policy import NEMOCLAW_MONITORED_PATHS


class EmbeddingConfig(BaseModel):
    model: str = "sentence-transformers/all-MiniLM-L6-v2"
    dim: int = 384


class IdeationConfig(BaseModel):
    model: str = "nvidia/nemotron-3-super-120b-a12b"
    temperature: float = 0.7
    max_tokens_per_mode: int = 2000
    modes: list[str] = ["creative", "code_grounded", "history_informed"]
    dedup_threshold: float = 0.92
    near_dup_threshold: float = 0.80
    retry_max: int = 3
    taxonomy_mode: bool = True
    taxonomy_gap_top_n: int = 4


class LaneConfig(BaseModel):
    # One lane per synthesized attack chain — the strategist produces
    # `pool_size` chains per cycle and each gets its own deep-dive agent.
    pool_size: int = 5
    lane_timeout_seconds: int = 1800
    max_turns: int = 50
    psutil_interval_seconds: float = 0.5
    # Deep-dive execution: the lane's agent fully commits to its chain and
    # may not emit the give-up sentinel before this many real attacker turns.
    min_turns_before_giveup: int = 8


class JudgmentConfig(BaseModel):
    tier2_zones: list[str] = [
        "PROMPT-INJ", "SOCIAL-ENG", "MEM-STATE", "MEM-SHARED",
    ]
    tier2_model: str = "nvidia/nemotron-3-super-120b-a12b"
    tier2_confidence_threshold: float = 0.5


class CodeGraphConfig(BaseModel):
    enabled: bool = True
    max_hops: int = 6
    path_rank_weight: float = 0.5
    llm_conf_weight: float = 0.5


class ReproConfig(BaseModel):
    replay_count: int = 5
    repro_rate_threshold: float = 0.5
    delta_debug_max_iterations: int = 30
    root_cause_severity_threshold: str = "high"
    cold_verify_max_attempts: int = 3
    code_graph: CodeGraphConfig = Field(default_factory=CodeGraphConfig)


class PatchIsolationConfig(BaseModel):
    enabled: bool = False                       # mock fallback is the default
    nemoclaw_repo_path: str | None = None
    base_ref: str = "HEAD"
    build_timeout_s: int = 900
    worktree_root: str = "/tmp"


class BlueTeamConfig(BaseModel):
    patch_verify_max_attempts: int = 3
    auto_commit_patches: bool = False
    high_severity_alt_count: int = 3
    # Verifier gate hardening — mutation robustness + detection gate.
    mutation_gate_enabled: bool = True
    mutation_operators: list[str] = []
    mutation_max_variants: int = 8
    detection_gate_enabled: bool = True
    detection_strictness: str = "observed_only"
    patch_isolation: PatchIsolationConfig = PatchIsolationConfig()


class OrchestratorConfig(BaseModel):
    red_team_batch_size: int = 50
    regression_before_batch: bool = True
    graceful_shutdown_timeout_s: int = 30
    persist_queue_state: bool = True
    # A repro can replay several lanes; default the stale-claim timeout to
    # 2 x the lane timeout. A processing repro_queue row older than this is
    # treated as a crashed worker and requeued.
    stale_claim_timeout_s: int = 3600


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
    # Single source of truth: the harness fs-diff roots are defined once in
    # interfaces/nemoclaw_policy.py. `default_factory` copies the list so a
    # config instance cannot mutate the shared policy constant.
    monitored_paths: list[str] = Field(
        default_factory=lambda: list(NEMOCLAW_MONITORED_PATHS))
    allowed_paths: list[str] = ["/tmp/openshell"]
    # --- live snapshot-based sandbox (the `monkey-victim` instance) ---
    # The real provisioner resets this sandbox to a clean snapshot per lane
    # rather than create/destroy. teardown is a no-op.
    sandbox_name: str = "monkey-victim"
    sandbox_namespace: str = "openshell"
    clean_snapshot: str = "clean-baseline"
    # The immutable clean image name — distinct from clean_snapshot, which is
    # the per-lane restore target. Defaults to the same name; an operator
    # points it at a separate baseline once snapshots are buildable.
    baseline_snapshot: str = "clean-baseline"
    # Disposable per-lane clone location. teardown_victim discards under here.
    work_area_dir: str = "/tmp/monkeyclaw-work"
    # Upper bound on a per-candidate patch rebuild.
    patch_build_timeout_s: int = 900
    gateway_endpoint: str = "ws://localhost:18789/"
    gateway_container: str = "openshell-cluster-nemoclaw"
    snapshot_restore_timeout_s: int = 180
    # `recover` restarts the gateway + agent; after a state restore the agent
    # reloads on a CPU-bound host, so this is deliberately generous.
    recover_timeout_s: int = 600


class ModelRoute(BaseModel):
    provider: str
    model: str
    # Additive, optional: an explicit ordered fallback chain for this route.
    # Absent -> the router appends only the tier default + guaranteed-local.
    fallback: list[ModelRoute] = Field(default_factory=list)


class ModelTier(BaseModel):
    """A risk/complexity tier: the route to use plus an optional fallback chain."""
    route: ModelRoute
    fallback: list[ModelRoute] = Field(default_factory=list)


class PriceRow(BaseModel):
    """Per-million-token USD prices for one model."""
    input_per_mtok_usd: float
    output_per_mtok_usd: float


def _default_model_roles() -> dict[str, ModelRoute]:
    # Forward-provisioned roles: `safety_judge`, `cheap_extraction`, and
    # `semantic_judge_appeal` are configured here but have no `client_for(...)`
    # caller yet. They are consumed by imminent Wave 1 plans — the
    # judge-ensemble plan wires `safety_judge` and the appeal path
    # (`semantic_judge_appeal`), and other Wave 1 plans use `cheap_extraction`.
    # They are intentionally NOT yet routed; this comment exists so the config
    # does not silently mislead.
    return {
        "cheap_extraction": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-nano"),
        "red_ideation": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-super-120b-a12b"),
        "red_code_ideation": ModelRoute(provider="anthropic_or_openai", model="frontier-coding"),
        "red_execution": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-super-120b-a12b"),
        "semantic_judge": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-super-120b-a12b"),
        "semantic_judge_appeal": ModelRoute(provider="anthropic_or_openai", model="frontier-coding"),
        "safety_judge": ModelRoute(provider="nvidia", model="nvidia/nemotron-content-safety-reasoning-4b"),
        "mutation": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-nano"),
        "cold_verification": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-nano"),
        "summarization": ModelRoute(provider="nvidia", model="nvidia/nemotron-3-nano"),
        "root_cause": ModelRoute(provider="anthropic_or_openai", model="frontier-coding"),
        "patch_generation": ModelRoute(provider="anthropic_or_openai", model="frontier-coding"),
        "test_generation": ModelRoute(provider="anthropic_or_openai", model="frontier-coding"),
        "codex_code_work": ModelRoute(provider="openai", model="gpt-5.3-codex"),
    }


def _default_tiers() -> dict[str, ModelTier]:
    return {
        "cheap": ModelTier(route=ModelRoute(provider="nvidia", model="nvidia/nemotron-3-nano")),
        "workhorse": ModelTier(
            route=ModelRoute(provider="nvidia", model="nvidia/nemotron-3-super-120b-a12b")),
        # `heavy` is forward-provisioned (Nemotron Ultra) for future
        # heavy-reasoning roles — no role maps to it in `_default_policy()` yet.
        "heavy": ModelTier(route=ModelRoute(provider="nvidia", model="nvidia/nemotron-3-ultra")),
        "frontier": ModelTier(
            route=ModelRoute(provider="anthropic_or_openai", model="frontier-coding")),
    }


def _default_policy() -> dict[str, str]:
    # safety_judge is intentionally absent — it is a direct specialised route.
    return {
        "red_ideation": "workhorse",
        "red_code_ideation": "frontier",
        "red_execution": "workhorse",
        "semantic_judge": "workhorse",
        "semantic_judge_appeal": "frontier",
        "mutation": "cheap",
        "cold_verification": "cheap",
        "summarization": "cheap",
        "root_cause": "frontier",
        "patch_generation": "frontier",
        "test_generation": "frontier",
        "cheap_extraction": "cheap",
        "codex_code_work": "frontier",
    }


def _default_pricing() -> dict[str, PriceRow]:
    # Approximate public list prices; replace per deployment.
    return {
        "nvidia/nemotron-3-nano": PriceRow(input_per_mtok_usd=0.04, output_per_mtok_usd=0.16),
        "nvidia/nemotron-3-super-120b-a12b": PriceRow(
            input_per_mtok_usd=0.30, output_per_mtok_usd=0.90),
        "nvidia/nemotron-3-ultra": PriceRow(input_per_mtok_usd=0.90, output_per_mtok_usd=2.70),
        "nvidia/nemotron-content-safety-reasoning-4b": PriceRow(
            input_per_mtok_usd=0.02, output_per_mtok_usd=0.08),
        "frontier-coding": PriceRow(input_per_mtok_usd=3.00, output_per_mtok_usd=15.00),
        "gpt-5.3-codex": PriceRow(input_per_mtok_usd=3.00, output_per_mtok_usd=15.00),
    }


class ModelsConfig(BaseModel):
    roles: dict[str, ModelRoute] = Field(default_factory=_default_model_roles)
    tiers: dict[str, ModelTier] = Field(default_factory=_default_tiers)
    policy: dict[str, str] = Field(default_factory=_default_policy)
    pricing: dict[str, PriceRow] = Field(default_factory=_default_pricing)


class GuardrailsConfig(BaseModel):
    """MonkeyClaw self-containment limits — deliverable A8."""

    artifact_dir: str = "data/artifacts"
    denied_host_paths: list[str] = [
        "~/.ssh", "~/.aws", "~/.config/gcloud", "/etc/shadow",
    ]
    network_allowlist: dict[str, list[str]] = Field(default_factory=lambda: {
        "default": ["localhost", "127.0.0.1"],
        "analysis": ["docs.anthropic.com"],
    })
    model_route_allowlist: list[str] = ["nvidia", "openai", "anthropic_or_openai"]
    mcp_tool_allowlist: list[str] = ["argyph", "github-readonly", "docs-search"]
    max_lanes_per_cycle: int = 64
    max_tokens_per_cycle: int = 5_000_000
    emergency_stop: bool = False


class CodeContextConfig(BaseModel):
    """Code-context search backend — Python indexer or Argyph."""

    backend: str = "python"          # "python" | "argyph"
    argyph_binary: str | None = None  # explicit path; None = autodetect


class PurpleConfig(BaseModel):
    """Purple-team cadence + toggles (purple-team spec §10, §7.8)."""

    enabled: bool = True
    # Run validate_full() + self_governance every N cycles (spec §10).
    full_sweep_every: int = 10
    self_governance_enabled: bool = True
    # Telemetry adapter selector (native-event-adapter spec §8). The derived
    # adapter stays the default so mock mode runs with zero credentials;
    # "native" selects the OpenClaw hook-event NativeEventAdapter.
    telemetry_adapter: str = "derived"  # "derived" | "native"
    native_event_source: str = "~/.openclaw/logs/purple-telemetry.jsonl"
    native_offset_store: str = "~/.openclaw/logs/purple-telemetry.offset"


class ArchiveConfig(BaseModel):
    """B5 — MAP-Elites archive tuning. See map-elites-archive spec §13."""

    niche_gap_low: float = 0.5
    niche_gap_high: float = 1.5
    seed_cross_zone_count: int = 2


class ChainConfig(BaseModel):
    """Cross-zone attack chaining. See cross-zone-attack-chaining spec §15."""

    enabled: bool = True
    n_chains: int = 2
    max_turns: int = 30


class RankerConfig(BaseModel):
    """Ranker selection — learned-ranking-model spec §10."""

    mode: str = "heuristic"        # "heuristic" | "learned"
    artifact_path: str = "data/ranker_artifact.json"
    pairwise_budget: int = 4       # max pairwise comparisons per cycle


class RedConfig(BaseModel):
    """Red-team subsystem tuning."""

    archive: ArchiveConfig = Field(default_factory=ArchiveConfig)
    chains: ChainConfig = Field(default_factory=ChainConfig)
    ranker: RankerConfig = Field(default_factory=RankerConfig)


class ApprovalPostureConfig(BaseModel):
    """Per-severity gate posture for the approval service (approval spec §10)."""

    critical: str = "require_approval"
    high: str = "require_approval"
    medium: str = "auto_allow"
    low: str = "auto_allow"


class ApprovalsConfig(BaseModel):
    """Severity-gated approval service tuning (approval spec §10)."""

    posture: ApprovalPostureConfig = Field(default_factory=ApprovalPostureConfig)
    ask_expiry_hours: int = 72
    grant_expiry_hours: int = 0  # 0 = no expiry
    auto_pr: bool = False
    operator_id: str = "operator"
    pr_base_branch: str = "master"


class MonkeyClawConfig(BaseModel):
    embedding: EmbeddingConfig = Field(default_factory=EmbeddingConfig)
    red: RedConfig = Field(default_factory=RedConfig)
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
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    guardrails: GuardrailsConfig = Field(default_factory=GuardrailsConfig)
    code_context: CodeContextConfig = Field(default_factory=CodeContextConfig)
    purple: PurpleConfig = Field(default_factory=PurpleConfig)
    approvals: ApprovalsConfig = Field(default_factory=ApprovalsConfig)
