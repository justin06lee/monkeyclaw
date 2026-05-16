"""Shared data objects — Contract 2.

All three persons import from here. Person 1 owns this file.
Any field addition is non-breaking; any rename or removal is breaking and must
be coordinated via the daily sync (see .agents/timeline.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

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


@dataclass
class ArchiveUpdateInput:
    """Write-side payload for update_archive_cell."""

    zone_id: str
    interaction_style: str
    response_movement: str
    idea_id: str
    score: float


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


@dataclass
class JudgeVoteInput:
    lane_id: str
    judge_role: str
    verdict: str
    score: float
    confidence: float
    reasoning: str
    evidence_turns: list[int] = field(default_factory=list)


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


__all__ = [
    "AgentPolicy",
    "ArchiveCell",
    "ArchiveUpdateInput",
    "CheckResult",
    "CodeChunk",
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
    "DupResult",
    "FindingInput",
    "FindingRecord",
    "FixSite",
    "FsDiff",
    "IdeaComponent",
    "IdeaComponentInput",
    "IdeaInput",
    "IdeaObject",
    "InferenceEvent",
    "JudgeRole",
    "JudgeVote",
    "JudgeVoteInput",
    "JudgmentResult",
    "LaneResult",
    "MemoryDiff",
    "Message",
    "ModelRunInput",
    "ModelRunRecord",
    "NetworkEvent",
    "Observability",
    "PatchCandidate",
    "PatchCandidateInput",
    "PolicyConfig",
    "PolicyCorpusCase",
    "PolicyCorpusResult",
    "PolicyCorpusResultInput",
    "PolicyDecision",
    "PolicyDecisionType",
    "Prevention",
    "ProcessEvent",
    "PurpleCycleResult",
    "QueueState",
    "QueueTransition",
    "RegressionRunResult",
    "RegressionTest",
    "RegressionTestInput",
    "RegressionTestStatus",
    "ReportCard",
    "ReportCardDimension",
    "ReproPackage",
    "ReproPackageInput",
    "ReproQueueStatus",
    "SandboxMode",
    "SeccompProfile",
    "SelfGovernanceCheck",
    "SelfGovernanceReport",
    "SessionTimeline",
    "TelemetryEvent",
    "TelemetryEventInput",
    "TelemetryEventType",
    "VictimTelemetryBundle",
    "ZoneCoverage",
]
