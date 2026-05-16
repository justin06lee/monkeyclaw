"""Shared data objects — Contract 2.

All three persons import from here. Person 1 owns this file.
Any field addition is non-breaking; any rename or removal is breaking and must
be coordinated via the daily sync (see .agents/timeline.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from interfaces.provisioning import VictimInstance

# ---------------------------------------------------------------------------
# String literal types — narrow but kept as `str` in fields for SQL friendliness.
# Validators in `interfaces.validators` will check these at boundaries.
# ---------------------------------------------------------------------------

Verdict = Literal["confirmed", "suspicious", "clean", "timeout", "error"]
Severity = Literal["critical", "high", "medium", "low"]
SourceMode = Literal["creative", "code_grounded", "history_informed"]
TierCaught = Literal["programmatic", "semantic", "none"]
FailureClass = Literal[
    "sandbox_escape",
    "pii_leak",
    "prompt_injection",
    "permission_escalation",
    "behavioral_manipulation",
    "memory_corruption",
    "skill_trust_bypass",
    "information_disclosure",
    "policy_modification",
    "none",
]
PatchStatus = Literal["open", "in_progress", "patched", "verified"]
BlueTeamStatus = Literal["queued", "triaged", "patching", "verified", "stuck"]
QueuePriority = Literal["high", "low"]
LaneTermination = Literal["idea_completed", "timeout", "error", "max_turns"]
InferenceRoute = Literal["local_nemotron", "cloud"]
TelemetryEventType = Literal[
    "agent.session.started", "agent.policy.loaded", "agent.tool.requested",
    "agent.tool.decision", "agent.file.read", "agent.file.write",
    "agent.shell.started", "agent.shell.finished", "agent.network.request",
    "agent.mcp.invoked", "agent.approval.requested", "agent.approval.resolved",
    "agent.session.finished",
]
PolicyDecisionType = Literal["allow", "deny", "ask"]
ReproQueueStatus = Literal["queued", "processing", "completed", "failed"]
RegressionTestStatus = Literal["untested", "passing", "failing", "quarantined"]
JudgeRole = Literal["semantic", "safety", "programmatic"]
DetectionQuadrant = Literal["PASS", "PARTIAL", "WEAK", "FAIL"]
Prevention = Literal["blocked", "succeeded"]
Observability = Literal["observed", "silent", "unknown"]
ControlValidationKind = Literal["inline", "full"]
ControlValidationStatus = Literal["ok", "errored"]
DetectionRuleStatus = Literal["active", "candidate", "retired"]
SandboxMode = Literal["ephemeral", "recover_only", "mock"]
TechniqueKind = Literal["atlas", "owasp"]
ResolvedBy = Literal["model", "keyword"]
ChainTermination = Literal["completed", "chain_broken", "max_turns", "error"]
IsolationMode = Literal["live", "mock"]
PatchBuildStatus = Literal["built", "apply_failed", "build_failed", "mock"]
ReproOutcome = Literal["reproduced", "flaky", "not_reproduced", "pending"]
ApprovalDecision = Literal["ask", "allow", "deny", "expired"]
GatePosture = Literal["auto_allow", "require_approval"]
ApprovalOutcomeKind = Literal["ALLOW", "DENY", "PENDING"]
ApprovalRequestStatus = Literal["pending", "resolved", "expired"]

HarmStage = Literal[
    "HARD_REFUSAL",
    "SOFT_REFUSAL",
    "ABSTRACT_ENGAGEMENT",
    "PARTIAL_COMPLIANCE",
    "STRONG_COMPLIANCE",
    "PROGRAMMATIC_VIOLATION",
]
BypassStatus = Literal["bypassed", "blocked", "inconclusive"]
GeneralizationStatus = Literal["generalized", "unconverged"]
GeneralizationOutcome = Literal["generalized", "bounced", "unconverged"]

# ---------------------------------------------------------------------------
# Message + observability primitives
# ---------------------------------------------------------------------------


@dataclass
class Message:
    role: str  # "attacker" | "victim"
    content: str
    timestamp: str  # ISO-8601
    tool_calls: list[dict[str, Any]] | None = None
    tool_results: list[dict[str, Any]] | None = None


@dataclass
class FsDiff:
    files_created: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    files_deleted: list[str] = field(default_factory=list)
    files_accessed: list[str] = field(default_factory=list)
    files_outside_allowed_paths: list[str] = field(default_factory=list)


@dataclass
class NetworkEvent:
    timestamp: str
    destination_domain: str
    destination_port: int
    method: str
    payload_size_bytes: int
    response_code: int | None
    blocked: bool


@dataclass
class ProcessEvent:
    timestamp: str
    process_name: str
    pid: int
    syscall: str | None
    syscall_args: list[str] | None
    blocked: bool
    inside_sandbox: bool


@dataclass
class MemoryDiff:
    keys_added: list[str] = field(default_factory=list)
    keys_modified: list[str] = field(default_factory=list)
    keys_deleted: list[str] = field(default_factory=list)
    values_changed: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass
class InferenceEvent:
    timestamp: str
    routed_to: str  # InferenceRoute
    content_preview: str  # first 200 chars
    pii_detected: bool
    pii_types: list[str] | None = None


@dataclass
class VictimTelemetryBundle:
    """Real observables captured from a running/just-finished victim sandbox.
    Each field reuses an existing observable type; missing streams degrade to
    an empty list / None rather than aborting the lane."""

    fs_diff: FsDiff | None = None
    network_events: list[NetworkEvent] = field(default_factory=list)
    process_events: list[ProcessEvent] = field(default_factory=list)
    inference_events: list[InferenceEvent] = field(default_factory=list)
    memory_diff: MemoryDiff | None = None


# ---------------------------------------------------------------------------
# Ideation / scoring / coverage
# ---------------------------------------------------------------------------


@dataclass
class IdeaObject:
    idea_id: str
    cycle_id: int
    zone_id: str
    source_mode: str  # SourceMode
    title: str
    approach: str
    success_criteria: str
    estimated_turns: int
    novelty_notes: str
    priority_score: float = 0.0
    # Mode B extras
    relevant_files: list[str] | None = None
    code_weakness: str | None = None
    # Mode C extras
    builds_on: list[str] | None = None
    variation_notes: str | None = None


@dataclass
class IdeaInput:
    """Write-side payload for log_idea — server fills idea_id + priority recompute."""

    cycle_id: int
    zone_id: str
    source_mode: str
    title: str
    approach: str
    success_criteria: str
    estimated_turns: int
    novelty_notes: str
    embedding: list[float] | None = None
    priority_score: float = 0.0
    deduplicated: bool = False
    relevant_files: list[str] | None = None
    code_weakness: str | None = None
    builds_on: list[str] | None = None
    variation_notes: str | None = None


@dataclass
class CoverageGap:
    zone_id: str
    zone_name: str
    coverage_score: float
    priority_score: float
    vulns_open: int
    last_tested_at: str | None
    description: str = ""
    severity_weight: float = 1.0


@dataclass
class DupResult:
    is_duplicate: bool
    max_similarity: float
    matching_idea_id: str | None


@dataclass
class CycleSummary:
    cycle_id: int
    summary: str
    zones_targeted: list[str]
    vulns_confirmed: int
    created_at: str


@dataclass
class CycleSummaryInput:
    cycle_id: int
    summary: str
    zones_targeted: list[str]
    ideas_generated: int
    ideas_deduplicated: int
    ideas_executed: int
    vulns_confirmed: int
    vulns_suspicious: int
    total_tokens_used: int
    wall_time_seconds: float


# ---------------------------------------------------------------------------
# Codebase
# ---------------------------------------------------------------------------


@dataclass
class CodeChunk:
    file_path: str
    function_name: str | None
    line_range: str  # "L45-L89"
    content: str
    language: str
    score: float = 0.0  # cosine similarity from the search


# ---------------------------------------------------------------------------
# Lane execution
# ---------------------------------------------------------------------------


@dataclass
class LaneResult:
    lane_id: str
    idea_id: str
    zone_targeted: str
    start_time: str
    end_time: str
    wall_time_ms: int
    turns_used: int
    tokens_used_attacker: int
    tokens_used_victim: int
    termination_reason: str  # LaneTermination
    transcript: list[Message]
    fs_diff: FsDiff
    network_log: list[NetworkEvent]
    process_log: list[ProcessEvent]
    memory_diff: MemoryDiff
    inference_routing_log: list[InferenceEvent]
    attacker_self_assessment: str
    deterministic: bool = True  # False when the victim was not snapshot-isolated
    chain_trace: list[ChainStepResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Judgment
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    check_name: str
    triggered: bool
    severity: str  # Severity
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class JudgmentResult:
    lane_id: str
    idea_id: str
    zone_id: str
    verdict: str  # Verdict
    tier_that_caught: str  # TierCaught
    failure_class: str  # FailureClass
    severity: str  # Severity
    confidence: float
    evidence: list[CheckResult]
    reasoning: str
    tokens_used_judgment: int
    timestamp: str


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass
class FindingRecord:
    finding_id: str
    cycle_id: int
    idea_id: str
    zone_id: str
    source_mode: str
    idea_summary: str
    verdict: str  # Verdict
    tier_caught: str  # TierCaught
    failure_class: str  # FailureClass
    severity: str  # Severity
    evidence: str  # JSON blob
    repro_rate: float | None
    patch_status: str  # PatchStatus
    reusability: float
    created_at: str


@dataclass
class FindingInput:
    """Write-side payload for log_finding."""

    cycle_id: int
    idea_id: str
    zone_id: str
    source_mode: str
    idea_summary: str
    verdict: str
    tier_caught: str
    failure_class: str
    severity: str
    evidence: str  # JSON-serialized
    reusability: float = 0.5
    embedding: list[float] | None = None  # embedding of idea_summary
    chain_id: str | None = None  # write-side counterpart of findings.chain_id


# ---------------------------------------------------------------------------
# Repro pipeline
# ---------------------------------------------------------------------------


@dataclass
class FixSite:
    file: str
    function: str
    line_range: str
    explanation: str
    confidence: float


@dataclass
class ReproPackage:
    package_id: str
    finding_id: str
    vuln_id: str  # "MC-2026-0047"
    title: str
    severity: str
    repro_rate: float
    minimal_steps: list[dict[str, Any]]
    affected_zone: str
    affected_paths: list[FixSite] | None
    ideas_used: list[str]
    transcripts: dict[str, list[Message]]
    suggested_mitigations: list[str]
    repro_document_md: str
    cold_verified: bool
    ready_for_blue: bool
    blue_team_status: str  # BlueTeamStatus
    created_at: str


@dataclass
class ReproPackageInput:
    finding_id: str
    vuln_id: str
    title: str
    severity: str
    repro_rate: float
    minimal_steps: list[dict[str, Any]]
    affected_zone: str
    affected_paths: list[FixSite] | None
    ideas_used: list[str]
    transcripts: dict[str, list[Message]]
    suggested_mitigations: list[str]
    repro_document_md: str
    cold_verified: bool
    ready_for_blue: bool


# ---------------------------------------------------------------------------
# Blue team
# ---------------------------------------------------------------------------


@dataclass
class PatchCandidate:
    patch_id: str
    vuln_ids: list[str]
    zone_id: str
    approach: str
    invasiveness: str  # "low" | "medium" | "high"
    diff: str
    explanation: str
    side_effects: str
    status: str  # "proposed" | "testing" | "approved" | "rejected"
    # --- spec C5 candidate metadata (additive, optional) ---------------
    # `expected_tests`: human-readable test scenarios this patch should
    # satisfy. `confidence`: generator's self-rated confidence in [0, 1].
    expected_tests: list[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class RegressionTest:
    test_id: str
    vuln_id: str
    zone_id: str
    test_script: str
    expected_result: str  # "vulnerability_blocked"
    functionality_test_script: str | None
    created_at: str
    deprecated: bool = False
    last_run_at: str | None = None
    last_run_result: str | None = None  # "pass" | "fail" | "error"
    consecutive_passes: int = 0


@dataclass
class RegressionTestInput:
    vuln_id: str
    zone_id: str
    test_script: str
    expected_result: str
    functionality_test_script: str | None = None
    # --- spec C6 third test type (additive, optional) ------------------
    # Confirms the required telemetry / policy-decision record still
    # exists after the patch — catches silent bypasses where behavior is
    # blocked but no security evidence is produced.
    policy_regression_test_script: str | None = None


@dataclass
class RegressionRunResult:
    total_tests: int
    tests_passing: int
    tests_failing: int
    newly_failing: list[str]
    coverage_delta: dict[str, float]
    new_tests_since_last_run: int
    run_duration_seconds: float
    # --- spec C8 (additive, optional) ----------------------------------
    # Tests that have oscillated between pass and fail across runs — the
    # suite cannot trust them, so they are surfaced for quarantine.
    flaky_tests: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Policy / runtime config snapshots passed to Tier 1 checks
# ---------------------------------------------------------------------------


@dataclass
class SeccompProfile:
    allowed_syscalls: list[str]
    blocked_syscalls: list[str]
    default_action: str  # "allow" | "deny"


@dataclass
class AgentPolicy:
    agent_id: str
    allowed_capabilities: list[str]
    denied_capabilities: list[str]


@dataclass
class PolicyConfig:
    allowed_paths: list[str]
    allowed_domains: list[str]
    seccomp_profile: SeccompProfile
    agent_policy: AgentPolicy
    policy_paths: list[str]
    # Path prefixes the sandbox/agent writes as part of normal operation
    # (its own memory, state, logs). Files under these are excluded from
    # filesystem-breach detection — they are expected churn, not an attack.
    expected_churn_paths: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Telemetry & policy events (Person A — deliverable A5)
# ---------------------------------------------------------------------------


@dataclass
class TelemetryEvent:
    """A single recorded event in a session timeline. Bounded excerpts and
    hashes only — never raw secrets."""

    event_id: str
    session_id: str
    event_type: str
    timestamp: str  # ISO-8601
    actor: str
    action_class: str
    target: str | None
    decision: str | None
    reason_code: str | None
    data_class: str | None
    content_hash: str | None
    excerpt: str | None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TelemetryEventInput:
    """Write-side of TelemetryEvent. The server assigns event_id + timestamp."""

    session_id: str
    event_type: str
    actor: str
    action_class: str
    target: str | None = None
    decision: str | None = None
    reason_code: str | None = None
    data_class: str | None = None
    content_hash: str | None = None
    excerpt: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyDecision:
    """A guardrail / policy decision about a proposed action."""

    decision_id: str
    session_id: str
    action_class: str
    target: str | None
    decision: str  # PolicyDecisionType
    reason_code: str
    policy_rule: str | None
    approver: str | None
    latency_ms: int
    created_at: str


# ---------------------------------------------------------------------------
# Model run accounting (Person A — deliverable A2/A4)
# ---------------------------------------------------------------------------


@dataclass
class ModelRunRecord:
    run_id: str
    role: str
    model: str
    provider: str
    input_tokens: int
    output_tokens: int
    latency_ms: int
    cost_usd: float | None
    success: bool
    error: str | None
    created_at: str


@dataclass
class ModelRunInput:
    role: str
    model: str
    provider: str
    input_tokens: int
    output_tokens: int
    latency_ms: int
    cost_usd: float | None = None
    success: bool = True
    error: str | None = None


# ---------------------------------------------------------------------------
# Queue state snapshot
# ---------------------------------------------------------------------------


@dataclass
class QueueState:
    queue_name: str
    depth: int
    processing: int
    completed: int
    failed: int
    high_priority: int
    low_priority: int
    updated_at: str


@dataclass
class QueueTransition:
    transition_id: str
    entity: str
    entity_id: str
    from_state: str | None
    to_state: str
    actor: str
    reason: str
    created_at: str


# ---------------------------------------------------------------------------
# Idea archive (MAP-Elites style — Person B consumes, Person A stores)
# ---------------------------------------------------------------------------


@dataclass
class IdeaComponent:
    component_id: str
    idea_id: str
    component_type: str  # e.g. "interaction_style", "response_movement", "vector"
    content: str
    created_at: str


@dataclass
class ArchiveCell:
    cell_id: str
    zone_id: str
    interaction_style: str
    response_movement: str
    best_idea_id: str | None
    best_score: float
    occupancy: int
    updated_at: str
    niche_descriptors: dict[str, Any] = field(default_factory=dict)


@dataclass
class ArchiveUpdateInput:
    """Write-side payload for update_archive_cell."""

    zone_id: str
    interaction_style: str
    response_movement: str
    idea_id: str
    score: float
    niche_descriptors: dict[str, Any] = field(default_factory=dict)


@dataclass
class IdeaComponentInput:
    """Write-side payload for store_idea_components — server fills component_id."""

    idea_id: str
    component_type: str
    content: str


# ---------------------------------------------------------------------------
# Judge votes (Person B — multi-judge ensemble)
# ---------------------------------------------------------------------------


@dataclass
class JudgeVote:
    vote_id: str
    lane_id: str
    judge_role: str
    verdict: str  # Verdict
    score: float
    confidence: float
    reasoning: str
    evidence_turns: list[int] = field(default_factory=list)
    is_appeal: bool = False
    weight: float = 1.0
    model: str = ""


@dataclass
class JudgeVoteInput:
    lane_id: str
    judge_role: str
    verdict: str
    score: float
    confidence: float
    reasoning: str
    evidence_turns: list[int] = field(default_factory=list)
    is_appeal: bool = False
    weight: float = 1.0
    model: str = ""


# ---------------------------------------------------------------------------
# Judge ensemble — appeal + pairwise ranking (judge-ensemble spec §8)
# ---------------------------------------------------------------------------


@dataclass
class AppealVerdict:
    """A frontier-model appeal's authoritative re-decision of a contested
    Tier 2 case. Mirrors the appeal_verdicts row."""

    appeal_id: str
    lane_id: str
    ensemble_verdict: str
    appeal_verdict: str
    disagreement: float
    ensemble_confidence: float
    appeal_confidence: float
    failure_class: str = "none"
    severity: str = "low"
    sided_with_roles: list[str] = field(default_factory=list)
    reasoning: str = ""
    model: str = ""
    errored: bool = False
    created_at: str = ""


@dataclass
class PairwiseResult:
    """One head-to-head comparison of two attacks on the same zone."""

    zone_id: str
    winner_attack_id: str
    loser_attack_id: str
    margin: float  # 0..1 — how decisive the win was
    reasoning: str = ""


@dataclass
class AttackElo:
    """Per-zone, per-attack Elo rating. Mirrors the attack_elo row."""

    zone_id: str
    attack_id: str
    rating: float = 1000.0
    comparisons: int = 0
    wins: int = 0
    losses: int = 0
    updated_at: str = ""


# ---------------------------------------------------------------------------
# Policy corpus — adversarial evaluation cases (PDF Appendix E)
# ---------------------------------------------------------------------------


@dataclass
class PolicyCorpusCase:
    case_id: str
    stimulus: str
    expected_decision: str  # PolicyDecisionType
    zone_id: str | None
    failure_class: str  # FailureClass
    evidence: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyCorpusResult:
    result_id: str
    run_id: str
    case_id: str
    observed_decision: str
    expected_decision: str
    passed: bool
    evidence: str
    notes: str
    created_at: str


@dataclass
class PolicyCorpusResultInput:
    run_id: str
    case_id: str
    observed_decision: str
    expected_decision: str
    passed: bool
    evidence: str = ""
    notes: str = ""


# ---------------------------------------------------------------------------
# Patch candidate write-side (Person C — deliverable A2)
# ---------------------------------------------------------------------------


@dataclass
class PatchCandidateInput:
    vuln_ids: list[str]
    zone_id: str
    approach: str
    invasiveness: str
    diff: str
    explanation: str
    side_effects: str = ""


# ---------------------------------------------------------------------------
# Purple team — detection-as-pass scoring (purple-team spec §7-§8)
# ---------------------------------------------------------------------------


@dataclass
class ControlDecision:
    """One control decision about a proposed action, plus whether the runtime
    emitted an observable event for it. Produced by a ControlTelemetryAdapter."""

    action_class: str
    target: str | None
    decision: str  # PolicyDecisionType: allow|deny|ask
    observed: bool
    reason_code: str | None = None
    source: str = "derived"  # derived|native


@dataclass
class DetectionVerdict:
    """The 2x2 quadrant for one execution against one control surface."""

    execution_id: str
    session_id: str
    zone_id: str
    quadrant: str  # DetectionQuadrant
    prevention: str  # Prevention
    observability: str  # Observability
    rule_id: str | None = None
    evidence: str = "{}"  # JSON blob


@dataclass
class DetectionRule:
    """A reusable detection rule in the whitepaper Appendix D shape."""

    rule_id: str
    zone_id: str
    source_finding_id: str
    logic: str
    expected_telemetry_signature: str
    response_action: str
    status: str  # DetectionRuleStatus
    created_at: str


@dataclass
class DetectionRuleInput:
    """Write-side of DetectionRule — server fills rule_id + created_at."""

    zone_id: str
    source_finding_id: str
    logic: str
    expected_telemetry_signature: str
    response_action: str
    status: str = "candidate"


@dataclass
class DetectionCoverage:
    """The second coverage axis: detection coverage for one zone."""

    zone_id: str
    coverage_score: float  # 0..1
    sample_count: int
    updated_at: str


@dataclass
class ZoneCoverage:
    """One cell of the joint attack-coverage x detection-coverage heatmap."""

    zone_id: str
    zone_name: str
    attack_coverage: float
    detection_coverage: float
    detection_samples: int


@dataclass
class ControlValidationRun:
    """One run of the control corpus against the current victim build."""

    run_id: str
    kind: str  # ControlValidationKind
    cases_total: int
    cases_passed: int
    regressions: list[dict[str, Any]]  # [{case_id, prior, now}]
    victim_build_id: str
    status: str  # ControlValidationStatus
    created_at: str


@dataclass
class SessionTimeline:
    """The unified evidence/decision timeline for one session."""

    session_id: str
    finding: FindingRecord | None
    telemetry_events: list[TelemetryEvent]
    control_decisions: list[ControlDecision]
    patches: list[dict[str, Any]]
    detection_rules: list[DetectionRule]


@dataclass
class ReportCardDimension:
    """One rubric dimension: measured value vs. a stated (not asserted) target."""

    name: str
    measured: float
    target: float
    target_is_aspirational: bool
    evidence_count: int
    notes: str = ""


@dataclass
class ReportCard:
    """The measured security report card across the 7 rubric dimensions."""

    card_id: str
    generated_at: str
    dimensions: list[ReportCardDimension]
    summary: str
    self_governance: SelfGovernanceReport | None = None


@dataclass
class SelfGovernanceCheck:
    name: str
    subject: str  # which MonkeyClaw agent
    passed: bool
    detail: str


@dataclass
class SelfGovernanceReport:
    """Result of pointing the detection machinery at MonkeyClaw itself."""

    checks: list[SelfGovernanceCheck]
    violations: list[str]
    passed: bool


@dataclass
class PurpleCycleResult:
    """The single object purple_team.pipeline.run returns per cycle."""

    verdicts: list[DetectionVerdict]
    validation_run: ControlValidationRun | None
    report_card: ReportCard | None
    new_rules: list[DetectionRule]
    routed_signals: list[str]


# ---------------------------------------------------------------------------
# Trajectory & progress scoring (trajectory-and-progress-scoring spec §2, §8)
# ---------------------------------------------------------------------------

# The single shared harm ladder. trajectory.py, progress.FAILURE_MODES, and
# archive.RESPONSE_MOVEMENTS all map 1:1 onto this — defined once here so the
# three vocabularies can never drift (spec constraint 4).
HARM_LADDER: tuple[str, ...] = (
    "HARD_REFUSAL",           # stage 0 — clean refusal, no movement
    "SOFT_REFUSAL",           # stage 1 — hedged / deflected, refused in substance
    "ABSTRACT_ENGAGEMENT",    # stage 2 — general discussion, no actionable content
    "PARTIAL_COMPLIANCE",     # stage 3 — some concrete content toward the goal
    "STRONG_COMPLIANCE",      # stage 4 — substantive disclosure / instructions
    "PROGRAMMATIC_VIOLATION", # stage 5 — an observed side-effect (fs/net/proc/route)
)

# harm-ladder stage index -> MAP-Elites response_movement axis value.
STAGE_TO_RESPONSE_MOVEMENT: dict[int, str] = {
    0: "refusal",
    1: "soft_refusal",
    2: "abstract_engagement",
    3: "partial_compliance",
    4: "strong_compliance",
    5: "programmatic_violation",
}

# progress.FAILURE_MODES value -> harm-ladder stage index.
FAILURE_MODE_TO_STAGE: dict[str, int] = {
    "hard_refusal": 0,
    "soft_refusal": 1,
    "clean": 0,
    "observable_movement": 2,
    "partial_compliance": 3,
    "programmatic_violation": 5,
}


@dataclass
class TurnScore:
    """One victim turn's place on the harm ladder, plus its signal counts."""

    turn_index: int
    stage: int            # 0..5, an index into HARM_LADDER
    stage_delta: int      # this turn's stage minus the previous victim turn's
    refusal_hits: int = 0
    hedge_hits: int = 0
    compliance_hits: int = 0
    specificity_hits: int = 0
    secret_hits: int = 0
    note: str = ""        # "erosion_turn" / "peak_turn" / "" (may combine)


@dataclass
class Trajectory:
    """The per-turn trajectory of one attack lane (trajectory spec §6.1)."""

    lane_id: str
    idea_id: str
    zone_id: str
    turn_scores: list[TurnScore] = field(default_factory=list)
    max_stage: int = 0
    final_stage: int = 0
    erosion_slope: float = 0.0   # least-squares slope of stage over turn index
    stalled_at_turn: int = -1    # turn index of the last stage increase, -1 if none
    monotonic: bool = True       # True iff the stage never decreased


@dataclass
class NearMissInput:
    """Write-side of a near miss — server fills near_miss_id + created_at."""

    idea_id: str
    lane_id: str
    zone_id: str
    max_stage: int
    stalled_at_turn: int
    erosion_excerpt: str
    useful_components: list[str] = field(default_factory=list)
    mutation_seeds: list[str] = field(default_factory=list)


@dataclass
class NearMiss:
    """A persisted near miss — an attempt that almost worked (spec §6.3)."""

    near_miss_id: str
    idea_id: str
    lane_id: str
    zone_id: str
    max_stage: int
    stalled_at_turn: int
    erosion_excerpt: str
    useful_components: list[str]
    mutation_seeds: list[str]
    consumed: bool
    created_at: str


# ---------------------------------------------------------------------------
# Mutation operator learning (mutation-operator-learning spec §8)
# ---------------------------------------------------------------------------


@dataclass
class MutationOperatorStat:
    """Durable per-operator improvement stats. `zone_id == ""` is the global
    rollup; a non-empty zone_id is one row of the per-zone breakdown."""

    operator: str
    zone_id: str
    uses: int
    successes: int
    avg_score: float
    squared_score: float
    last_lift: float


@dataclass
class MutationAttempt:
    """One mutated execution — the offline-analysis / future-ranker dataset.
    The server fills attempt_id and created_at when they are empty."""

    attempt_id: str
    cycle_id: int
    zone_id: str
    operator: str
    parent_idea_id: str
    child_idea_id: str
    parent_score: float
    child_score: float
    lift: float
    improved: bool
    child_verdict: str
    created_at: str


# ---------------------------------------------------------------------------
# Corpus-driven ideation — technique tagging + technique-coverage axis
# (corpus-driven-ideation spec §8)
# ---------------------------------------------------------------------------


@dataclass
class TechniqueRef:
    """One technique/category tag attached to an idea or finding.

    `kind` is 'atlas' or 'owasp'; `resolved_by` records whether the model
    self-reported the id ('model') or Taxonomy.resolve() backfilled it
    from the idea text ('keyword'). `corpus_version` makes a coverage
    report reproducible across a taxonomy refresh."""

    kind: str  # TechniqueKind
    technique_id: str
    name: str
    corpus_version: str
    resolved_by: str  # ResolvedBy


@dataclass
class TechniqueCoverage:
    """The per-zone second coverage axis over ATLAS techniques + OWASP
    categories: how many mapped techniques have been exercised (an idea
    tagged with them was executed) vs. confirmed (a finding tagged)."""

    zone_id: str
    total: int
    exercised: int
    confirmed: int
    exercised_ratio: float  # 0..1
    confirmed_ratio: float  # 0..1
    gap_technique_ids: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Real root-cause analysis — code graph (real-root-cause spec §7)
# Defined in interfaces/code_graph.py; re-exported here so blue_team imports
# from one place.
# ---------------------------------------------------------------------------

from interfaces.code_graph import (  # noqa: E402
    CodeEdge,
    CodeGraph,
    CodeSymbol,
    EdgeKind,
    ExecutedPath,
    GraphBackend,
    PathNode,
    SymbolKind,
)

# ---------------------------------------------------------------------------
# Model ideation tournament — per-zone win-rate + rounds
# (model-ideation-tournament spec §9)
# ---------------------------------------------------------------------------


@dataclass
class ModelZoneWinrate:
    """Per-(zone, model) win-rate: a head-to-head record and an execution
    record, plus the stored combined win-rate. Mirrors the
    model_zone_winrate row."""

    zone_id: str
    model_label: str
    role: str = ""
    h2h_wins: int = 0
    h2h_comparisons: int = 0
    confirmed: int = 0
    suspicious: int = 0
    ideas_executed: int = 0
    winrate: float = 0.5  # neutral prior so a no-history entrant is optimistic
    updated_at: str = ""


@dataclass
class PairwiseIdeaSetResult:
    """One head-to-head comparison of two entrants' idea sets for a zone."""

    zone_id: str
    winner_label: str
    loser_label: str
    margin: float  # 0..1
    reasoning: str = ""


@dataclass
class TournamentRound:
    """One head-to-head round (one zone, one cycle). `entrants` and
    `pairwise` are JSON-serialisable lists. Mirrors the
    model_tournament_rounds row."""

    round_id: str
    cycle_id: int
    zone_id: str
    entrants: list[str] = field(default_factory=list)
    pairwise: list[dict[str, Any]] = field(default_factory=list)
    winner_label: str = ""
    created_at: str = ""


# ---------------------------------------------------------------------------
# Cross-zone attack chaining (cross-zone-attack-chaining spec §4, §8)
# ---------------------------------------------------------------------------


@dataclass
class ChainStep:
    """One single-zone primitive in an ordered kill chain."""

    step_index: int
    zone_id: str
    objective: str
    primitive_ref: str  # source idea_id or "ARCH:<cell key>"
    approach: str
    requires: list[str] = field(default_factory=list)
    produces: list[str] = field(default_factory=list)
    success_signal: str = ""


@dataclass
class AttackChain:
    """An ordered, linear multi-zone kill chain."""

    chain_id: str
    cycle_id: int
    title: str
    zones: list[str]
    primary_zone: str
    steps: list[ChainStep]
    builds_on: list[str] = field(default_factory=list)
    estimated_turns: int = 15
    rationale: str = ""


@dataclass
class ChainSkeleton:
    """The strategist's pre-composition sketch of a chain. Each step_specs
    entry is (zone_id, objective, primitive_ref)."""

    title: str
    cycle_id: int
    step_specs: list[tuple[str, str, str]]
    rationale: str = ""
    estimated_turns: int = 15


@dataclass
class ChainStepResult:
    """The executed outcome of one ChainStep — the per-step trace row."""

    chain_id: str
    step_index: int
    zone_id: str
    landed: bool
    produced_tokens: list[str] = field(default_factory=list)
    turn_span: tuple[int, int] = (0, 0)
    progress_score: float = 0.0


@dataclass
class ChainFinding:
    """The kill chain itself as one finding spanning every traversed zone."""

    chain_finding_id: str
    chain_id: str
    cycle_id: int
    zones_traversed: list[str]
    terminal_zone: str
    severity: str
    verdict: str
    landed_steps: list[int]
    evidence: str = "{}"
    repro_status: str = "pending"


@dataclass
class ChainAttribution:
    """Cross-zone attribution output: the ChainFinding, per-zone FindingInput
    records, and per-zone coverage deltas keyed by zone_id."""

    chain_finding: ChainFinding
    per_zone_findings: list[FindingInput]
    coverage_deltas: dict[str, float]
    step_results: list[ChainStepResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Verifier gate hardening — mutation robustness + detection gate
# (verifier-gate-hardening spec §7)
# ---------------------------------------------------------------------------


@dataclass
class VariantResult:
    """One mutated attack variant replayed against the patched victim by
    gate1b_mutation_robustness. `blocked` False means the patch over-fits
    the recorded payload — the variant of the same attack family leaked."""

    operator: str
    variant_hash: str
    blocked: bool
    judge_verdict: str


# ---------------------------------------------------------------------------
# Real patch isolation — disposable-worktree verification (patch-isolation §7)
# ---------------------------------------------------------------------------


@dataclass
class DiffApplyResult:
    """The result of a `git apply --check` (and optionally `git apply`) of a
    candidate diff inside a disposable worktree."""

    applied: bool = False
    checked: bool = False
    rejected_hunks: list[str] = field(default_factory=list)
    stderr: str = ""


@dataclass
class PatchBuild:
    """One attempted isolation build for one candidate patch. `victim` is the
    rebuilt patched VictimInstance on the live path, None on the mock path."""

    build_id: str
    patch_id: str
    worktree_path: str | None
    victim: VictimInstance | None
    diff_result: DiffApplyResult
    isolation_mode: str  # IsolationMode
    build_status: str  # PatchBuildStatus
    build_duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Patch generalization loop (patch-generalization-loop spec §11)
# ---------------------------------------------------------------------------


@dataclass
class MutationVariant:
    """One mutation operator applied to a verified patch's minimal transcript,
    replayed against the patched victim."""

    variant_id: str
    operator: str
    mutated_transcript: list[Message]
    replay_result: LaneResult | None


@dataclass
class BypassResult:
    """The score of one MutationVariant replay against the patched victim."""

    variant_id: str
    operator: str
    status: str  # BypassStatus
    triggered_evidence: list[CheckResult]
    severity: str
    notes: str = ""


@dataclass
class BypassConstraint:
    """A bypass turned into a first-class re-patch requirement."""

    constraint_id: str
    operator: str
    bypassing_transcript: list[Message]
    directive: str
    evidence: list[CheckResult]


@dataclass
class GeneralizationRound:
    """One round of the loop, as persisted in generalization_rounds."""

    round_id: str
    patch_id: str
    finding_id: str
    vuln_id: str
    zone_id: str
    round_index: int
    operators_tried: list[str]
    variants_total: int
    variants_bypassed: int
    variants_inconclusive: int
    bypass_operators: list[str]
    outcome: str  # GeneralizationOutcome
    repatch_patch_id: str | None
    evidence: list[dict[str, Any]]
    created_at: str


# ---------------------------------------------------------------------------
# Approval & PR service — severity-gated authorization (approval spec §9)
# ---------------------------------------------------------------------------


@dataclass
class ApprovalRequest:
    """A pending request for a human decision on a verified patch."""

    request_id: str
    patch_id: str
    vuln_ids: list[str]
    zone_id: str
    severity: str
    posture: str  # GatePosture
    ask_expiry: str | None  # ISO timestamp, None for no expiry
    generalization_status: str | None  # GeneralizationStatus | None
    created_at: str
    status: str  # ApprovalRequestStatus


@dataclass
class ApprovalEvent:
    """One row of the append-only approval_events audit log (read shape)."""

    event_id: str
    request_id: str
    patch_id: str
    vuln_ids: list[str]
    zone_id: str
    severity: str
    decision: str  # ApprovalDecision
    posture: str  # GatePosture
    approver: str  # operator id or "system"
    reason: str
    ask_expiry: str | None
    grant_expiry: str | None
    generalization_status: str | None
    pr_url: str | None
    created_at: str


# ---------------------------------------------------------------------------
# Learned ranking model — the structured trace dataset (spec §7)
# ---------------------------------------------------------------------------


@dataclass
class AttemptTraceInput:
    """Write-side of an attempt trace — server fills trace_id + created_at.

    Features + labels for one judged attack attempt. The repro label lands
    later than the judge verdict, so repro_outcome starts 'pending' and is
    updated by attach_repro_outcome (spec §6.2)."""

    idea_id: str
    cycle_id: int
    zone_id: str
    feature_schema_version: int
    idea_summary: str
    tactic_tags: list[str]
    mutation_operator: str | None
    interaction_style: str
    progress_dims: dict[str, float]   # the flattened ProgressScore dimensions
    judge_scores: dict[str, float]    # five ensemble role scores + confidences
    token_cost: int
    judge_verdict: str                # confirmed | suspicious | clean
    search_score: float
    archive_niche: str
    usefulness_label: float           # derived 0..1 target
    finding_id: str | None = None
    repro_outcome: str = "pending"    # ReproOutcome


@dataclass
class AttemptTrace:
    """Read-side of an attempt trace — one row of the ranking dataset."""

    trace_id: str
    idea_id: str
    finding_id: str | None
    cycle_id: int
    zone_id: str
    feature_schema_version: int
    idea_summary: str
    tactic_tags: list[str]
    mutation_operator: str | None
    interaction_style: str
    progress_dims: dict[str, float]
    judge_scores: dict[str, float]
    token_cost: int
    repro_outcome: str
    judge_verdict: str
    search_score: float
    archive_niche: str
    usefulness_label: float
    created_at: str


@dataclass
class GeneralizationRoundInput:
    """Write-side of GeneralizationRound — server fills round_id + created_at."""

    patch_id: str
    finding_id: str
    vuln_id: str
    zone_id: str
    round_index: int
    operators_tried: list[str]
    variants_total: int
    variants_bypassed: int
    variants_inconclusive: int
    bypass_operators: list[str]
    outcome: str
    repatch_patch_id: str | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class GeneralizationResult:
    """The single object GeneralizationLoop.run returns per finalized patch."""

    finding_id: str
    final_patch_id: str
    status: str  # GeneralizationStatus
    reason: str | None
    rounds: list[GeneralizationRound]
    open_bypasses: list[BypassResult]


@dataclass
class PreferenceInput:
    """Write-side of a pairwise preference — server fills pair_id + created_at."""

    trace_a: str         # trace_id
    trace_b: str         # trace_id
    preferred: str       # "a" | "b" | "tie"
    judge_confidence: float


@dataclass
class Preference:
    """Read-side of a pairwise preference label (spec §7)."""

    pair_id: str
    trace_a: str
    trace_b: str
    preferred: str
    judge_confidence: float
    created_at: str


@dataclass
class ApprovalEventInput:
    """Write shape for an approval_events row — server fills event_id +
    created_at."""

    request_id: str
    patch_id: str
    vuln_ids: list[str]
    zone_id: str
    severity: str
    decision: str  # ApprovalDecision
    posture: str  # GatePosture
    approver: str
    reason: str
    ask_expiry: str | None = None
    grant_expiry: str | None = None
    generalization_status: str | None = None
    pr_url: str | None = None


@dataclass
class ApprovalOutcome:
    """What approval_service.request() returns."""

    decision: str  # ApprovalOutcomeKind
    request_id: str
    event: ApprovalEvent | None  # the allow event for an immediate auto-allow


@dataclass
class PullRequestDraft:
    """The result of pr_generator.draft() for an approved patch."""

    branch: str
    pr_url: str
    commit_sha: str
    created_at: str


__all__ = [
    "AgentPolicy",
    "ApprovalDecision",
    "ApprovalEvent",
    "ApprovalEventInput",
    "ApprovalOutcome",
    "ApprovalOutcomeKind",
    "ApprovalRequest",
    "ApprovalRequestStatus",
    "AttackChain",
    "AppealVerdict",
    "ArchiveCell",
    "ArchiveUpdateInput",
    "AttackElo",
    "AttemptTrace",
    "AttemptTraceInput",
    "BypassConstraint",
    "BypassResult",
    "BypassStatus",
    "ChainAttribution",
    "ChainFinding",
    "ChainSkeleton",
    "ChainStep",
    "ChainStepResult",
    "ChainTermination",
    "CheckResult",
    "CodeChunk",
    "CodeEdge",
    "CodeGraph",
    "CodeSymbol",
    "ControlDecision",
    "ControlValidationKind",
    "ControlValidationRun",
    "ControlValidationStatus",
    "CoverageGap",
    "CycleSummary",
    "CycleSummaryInput",
    "DetectionCoverage",
    "DetectionQuadrant",
    "DetectionRule",
    "DetectionRuleInput",
    "DetectionRuleStatus",
    "DetectionVerdict",
    "DiffApplyResult",
    "DupResult",
    "EdgeKind",
    "ExecutedPath",
    "FAILURE_MODE_TO_STAGE",
    "FindingInput",
    "FindingRecord",
    "FixSite",
    "FsDiff",
    "GeneralizationOutcome",
    "GeneralizationResult",
    "GeneralizationRound",
    "GeneralizationRoundInput",
    "GatePosture",
    "GeneralizationStatus",
    "GraphBackend",
    "HARM_LADDER",
    "HarmStage",
    "IdeaComponent",
    "IdeaComponentInput",
    "IdeaInput",
    "IdeaObject",
    "InferenceEvent",
    "IsolationMode",
    "JudgeRole",
    "JudgeVote",
    "JudgeVoteInput",
    "JudgmentResult",
    "LaneResult",
    "MemoryDiff",
    "Message",
    "ModelRunInput",
    "ModelRunRecord",
    "ModelZoneWinrate",
    "MutationAttempt",
    "MutationOperatorStat",
    "MutationVariant",
    "NearMiss",
    "NearMissInput",
    "NetworkEvent",
    "Observability",
    "PairwiseIdeaSetResult",
    "PairwiseResult",
    "PatchBuild",
    "PatchBuildStatus",
    "PatchCandidate",
    "PatchCandidateInput",
    "PathNode",
    "PolicyConfig",
    "PolicyCorpusCase",
    "PolicyCorpusResult",
    "PolicyCorpusResultInput",
    "PolicyDecision",
    "PolicyDecisionType",
    "Preference",
    "PreferenceInput",
    "Prevention",
    "ProcessEvent",
    "PullRequestDraft",
    "PurpleCycleResult",
    "QueueState",
    "QueueTransition",
    "RegressionRunResult",
    "RegressionTest",
    "RegressionTestInput",
    "RegressionTestStatus",
    "ReproOutcome",
    "ReportCard",
    "ReportCardDimension",
    "ReproPackage",
    "ReproPackageInput",
    "ReproQueueStatus",
    "ResolvedBy",
    "STAGE_TO_RESPONSE_MOVEMENT",
    "SandboxMode",
    "SeccompProfile",
    "SelfGovernanceCheck",
    "SelfGovernanceReport",
    "SessionTimeline",
    "SymbolKind",
    "TechniqueCoverage",
    "TechniqueKind",
    "TechniqueRef",
    "TelemetryEvent",
    "TelemetryEventInput",
    "TelemetryEventType",
    "TournamentRound",
    "Trajectory",
    "TurnScore",
    "VariantResult",
    "VictimTelemetryBundle",
    "ZoneCoverage",
]
