# Interface Contracts — The Merge-Conflict Firewall

These are the ONLY shared artifacts in the codebase. Person 1 writes them. Persons 2 & 3 consume them as read-only imports. If these are right, there are zero merge conflicts. Ever.

---

## Contract 1: MCP Tool Ownership Map

Person 1 implements ALL tools. Persons 2 & 3 only call them.

| MCP Tool | Called By | Purpose |
|----------|-----------|---------|
| `get_coverage_gaps` | Person 2 | Ideation zone selection |
| `search_findings` | Person 2 | Ideation Mode C — history-informed ideas |
| `log_finding` | Person 2 | Post-judgment storage of all attack outcomes |
| `get_recent_summaries` | Person 2 | Ideation Mode A context — recent cycle summaries |
| `check_duplicate` | Person 2 | Idea deduplication via cosine similarity |
| `update_zone_coverage` | Person 2 + Person 3 | After judgment (P2) + after regression runs (P3) |
| `push_to_repro_queue` | Person 2 | Post-judgment routing of confirmed/suspicious findings |
| `get_repro_queue` | Person 3 | Repro pipeline input — pull next finding to reproduce |
| `push_repro_package` | Person 3 | Completed repro output — publish verified package |
| `get_blue_team_queue` | Person 3 | Triage input — pull repro packages ready for patching |
| `search_codebase` | Person 2 + Person 3 | Mode B ideation (P2) + root-cause locator + patch generator (P3) |
| `log_cycle_summary` | Person 2 | End-of-cycle compression — store 2-3 sentence summary |
| `get_regression_suite` | Person 3 | Regression runner — pull all active tests |
| `add_regression_test` | Person 3 | Post-patch — add new test to permanent suite |
| `log_idea` | Person 2 | Idea tracking — store for dedup history |
| `send_alert` | Person 2 + Person 3 | Telegram/webhook notifications on confirmed vulns and completed patches |

---

## Contract 2: Shared Data Objects

These type definitions live in `interfaces/types.py`. All three persons import from here. Person 1 owns this file.

### Read-side dataclasses (returned by MCP tools)

The dataclasses below describe what readers get back. Their write-side `*Input` counterparts (see "Write-side payloads") carry only the fields a writer is allowed to set — server-assigned IDs, timestamps, and lifecycle fields like `blue_team_status` are omitted from the input variants.

### IdeaObject
```python
@dataclass
class IdeaObject:
    idea_id: str              # UUID, auto-generated
    cycle_id: int
    zone_id: str              # e.g. "SBX-FS"
    source_mode: str          # "creative" | "code_grounded" | "history_informed"
    title: str                # Short descriptive title
    approach: str             # 2-3 sentence description of the attack strategy
    success_criteria: str     # What constitutes a successful exploit
    estimated_turns: int      # Estimated number of interaction turns needed
    novelty_notes: str        # Why this is different from standard approaches
    priority_score: float     # Computed after dedup
    # Mode B extras (optional)
    relevant_files: list[str] | None       # e.g. ["path/to/file.py:L45-L89"]
    code_weakness: str | None              # Description of code-level weakness
    # Mode C extras (optional)
    builds_on: list[str] | None            # finding_ids this idea extends
    variation_notes: str | None            # How this differs from prior findings
```

### LaneResult
```python
@dataclass
class LaneResult:
    lane_id: str
    idea_id: str
    zone_targeted: str
    start_time: str           # ISO-8601
    end_time: str             # ISO-8601
    wall_time_ms: int
    turns_used: int
    tokens_used_attacker: int
    tokens_used_victim: int
    termination_reason: str   # "idea_completed" | "timeout" | "error" | "max_turns"
    transcript: list[Message]
    fs_diff: FsDiff
    network_log: list[NetworkEvent]
    process_log: list[ProcessEvent]
    memory_diff: MemoryDiff
    inference_routing_log: list[InferenceEvent]
    attacker_self_assessment: str
```

### JudgmentResult
```python
@dataclass
class JudgmentResult:
    lane_id: str
    idea_id: str
    zone_id: str
    verdict: str              # "confirmed" | "suspicious" | "clean"
    tier_that_caught: str     # "programmatic" | "semantic" | "none"
    failure_class: str        # "sandbox_escape" | "pii_leak" | "prompt_injection" | "permission_escalation" | "behavioral_manipulation" | "memory_corruption" | "skill_trust_bypass" | "information_disclosure" | "policy_modification" | "none"
    severity: str             # "critical" | "high" | "medium" | "low"
    confidence: float         # 0.0 - 1.0 (1.0 for programmatic checks)
    evidence: list[CheckResult]
    reasoning: str            # Tier 2 only — judge's explanation
    tokens_used_judgment: int # 0 for Tier 1
    timestamp: str            # ISO-8601
```

### CheckResult
```python
@dataclass
class CheckResult:
    check_name: str           # e.g. "filesystem_breach"
    triggered: bool
    severity: str             # "critical" | "high" | "medium" | "low"
    evidence: dict            # Check-specific details (file_path, domain, syscall, etc.)
```

### FindingRecord
```python
@dataclass
class FindingRecord:
    finding_id: str
    cycle_id: int
    idea_id: str
    zone_id: str
    source_mode: str
    idea_summary: str
    verdict: str
    tier_caught: str
    failure_class: str
    severity: str
    evidence: str             # JSON blob
    repro_rate: float | None
    patch_status: str         # "open" | "in_progress" | "patched" | "verified"
    reusability: float
    created_at: str
```

### ReproPackage
```python
@dataclass
class ReproPackage:
    package_id: str
    finding_id: str
    vuln_id: str              # Human-readable, e.g. "MC-2026-0047"
    title: str
    severity: str
    repro_rate: float
    minimal_steps: list[dict] # Ordered list of reproduction steps
    affected_zone: str
    affected_paths: list[FixSite] | None  # From root-cause locator
    ideas_used: list[str]     # idea_ids
    transcripts: dict         # {"original": [...], "minimal": [...]}
    suggested_mitigations: list[str]
    repro_document_md: str    # The full markdown document
    cold_verified: bool
    ready_for_blue: bool
    blue_team_status: str     # "queued" | "triaged" | "patching" | "verified"
    created_at: str
```

### RegressionTest
```python
@dataclass
class RegressionTest:
    test_id: str
    vuln_id: str
    zone_id: str
    test_script: str          # Shell or Python script content
    expected_result: str      # "vulnerability_blocked"
    functionality_test_script: str | None
    created_at: str
    deprecated: bool
    last_run_at: str | None
    last_run_result: str | None   # "pass" | "fail" | "error"
    consecutive_passes: int
```

### PatchCandidate
```python
@dataclass
class PatchCandidate:
    patch_id: str
    vuln_ids: list[str]       # Vuln IDs this patch addresses
    zone_id: str
    approach: str             # Label, e.g. "Symlink pre-resolution"
    invasiveness: str         # "low" | "medium" | "high"
    diff: str                 # Unified diff format
    explanation: str
    side_effects: str
    status: str               # "proposed" | "testing" | "approved" | "rejected"
```

### Supporting Types
```python
@dataclass
class CoverageGap:
    zone_id: str
    zone_name: str
    coverage_score: float
    priority_score: float     # severity × (1-coverage) × (1+vulns_open×0.2)
    vulns_open: int
    last_tested_at: str | None

@dataclass
class CycleSummary:
    cycle_id: int
    summary: str              # 2-3 sentence compressed summary
    zones_targeted: list[str]
    vulns_confirmed: int
    created_at: str

@dataclass
class CodeChunk:
    file_path: str
    function_name: str | None
    line_range: str           # e.g. "L45-L89"
    content: str
    language: str

@dataclass
class DupResult:
    is_duplicate: bool
    max_similarity: float
    matching_idea_id: str | None

@dataclass
class FixSite:
    file: str
    function: str
    line_range: str
    explanation: str
    confidence: float

@dataclass
class Message:
    role: str                 # "attacker" | "victim"
    content: str
    timestamp: str
    tool_calls: list[dict] | None
    tool_results: list[dict] | None

@dataclass
class FsDiff:
    files_created: list[str]
    files_modified: list[str]
    files_deleted: list[str]
    files_accessed: list[str]
    files_outside_allowed_paths: list[str]

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
    keys_added: list[str]
    keys_modified: list[str]
    keys_deleted: list[str]
    values_changed: dict[str, dict]  # key → {old, new}

@dataclass
class InferenceEvent:
    timestamp: str
    routed_to: str            # "local_nemotron" | "cloud"
    content_preview: str      # First 200 chars of the request
    pii_detected: bool
    pii_types: list[str] | None
```

### Write-side payloads

Every MCP tool that writes takes one of these `*Input` dataclasses (see Contract 1 signatures). They omit server-assigned IDs, timestamps, and lifecycle fields. The server fills those in and returns the generated ID.

```python
@dataclass
class IdeaInput:
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
class FindingInput:
    cycle_id: int
    idea_id: str
    zone_id: str
    source_mode: str
    idea_summary: str
    verdict: str
    tier_caught: str
    failure_class: str
    severity: str
    evidence: str             # JSON-serialized
    reusability: float = 0.5
    embedding: list[float] | None = None  # embedding of idea_summary

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

@dataclass
class ReproPackageInput:
    finding_id: str
    vuln_id: str
    title: str
    severity: str
    repro_rate: float
    minimal_steps: list[dict]
    affected_zone: str
    affected_paths: list[FixSite] | None
    ideas_used: list[str]
    transcripts: dict[str, list[Message]]
    suggested_mitigations: list[str]
    repro_document_md: str
    cold_verified: bool
    ready_for_blue: bool

@dataclass
class RegressionTestInput:
    vuln_id: str
    zone_id: str
    test_script: str
    expected_result: str
    functionality_test_script: str | None = None
```

### Policy snapshots (consumed by Tier 1 checks)

The Tier 1 check runner takes a `PolicyConfig` (or a plain dict with the same field names — see Contract 4). These are pure value objects that capture the runtime policy at the moment a lane runs.

```python
@dataclass
class SeccompProfile:
    allowed_syscalls: list[str]
    blocked_syscalls: list[str]
    default_action: str       # "allow" | "deny"

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
```

### Regression run output

```python
@dataclass
class RegressionRunResult:
    total_tests: int
    tests_passing: int
    tests_failing: int
    newly_failing: list[str]
    coverage_delta: dict[str, float]
    new_tests_since_last_run: int
    run_duration_seconds: float
```

### String-literal aliases

`interfaces/types.py` also exports `Literal[...]` aliases for the closed sets of valid string values: `Verdict`, `Severity`, `SourceMode`, `TierCaught`, `FailureClass`, `PatchStatus`, `BlueTeamStatus`, `QueuePriority`, `LaneTermination`, `InferenceRoute`. Dataclass fields keep `str` for SQL friendliness; the aliases are for validators and type hints.

---

## Contract 3: Victim Provisioning API

Both Person 2 (execution lanes) and Person 3 (replay, cold verification, patch verification) need to spin up fresh NemoClaw victim instances. Person 1 provides a single provisioning interface:

```python
# interfaces/provisioning.py

@dataclass
class VictimConfig:
    """Inputs for spinning up a single fresh NemoClaw victim instance."""
    nemoclaw_version: str            # From global config
    policy_path: str                 # Path to NemoClaw policy YAML
    agent_type: str                  # "coding_assistant" | "general_purpose" | custom
    agent_config_path: str           # Path to victim agent config
    enable_monitoring: bool = True   # Whether to attach the monitoring harness
    patch_diff: str | None = None    # Optional: apply this patch before starting
    nemoclaw_repo_path: str | None = None  # Override location of NemoClaw checkout
    env: dict[str, str] = field(default_factory=dict)
    inference_routing: str = "default"  # "default" | "force_local" | "force_cloud"

@dataclass
class VictimInstance:
    """Connection details for a running victim. teardown_victim(instance_id) cleans up."""
    instance_id: str
    chat_endpoint: str               # URL or socket path for chat-style attacks
    shell_endpoint: str | None       # For sandbox-level attacks
    status: str                      # "running" | "stopped" | "error"
    sandbox_id: str | None = None    # NemoClaw sandbox identifier, if any
    pid: int | None = None
    started_at: str = ""             # ISO-8601
    metadata: dict[str, str] = field(default_factory=dict)


@runtime_checkable
class VictimProvisioner(Protocol):
    """Abstract provisioning surface. Implemented by:

    - `infra.provisioning_nemoclaw.NemoClawProvisioner` — real (shells to `nemoclaw`)
    - `infra.provisioning_mock.MockProvisioner`         — for tests
    """
    def provision_victim(self, config: VictimConfig) -> VictimInstance: ...
    def teardown_victim(self, instance_id: str) -> None: ...
    def list_victims(self) -> list[VictimInstance]: ...


class ProvisioningError(RuntimeError):
    """Raised when a victim cannot be provisioned."""


# Module-level convenience: code that just calls `provision_victim(...)` /
# `teardown_victim(...)` gets the configured backend via a process-wide
# singleton. `infra.bootstrap` calls `set_provisioner(...)` once at startup.

def set_provisioner(p: VictimProvisioner) -> None: ...
def get_provisioner() -> VictimProvisioner: ...
def provision_victim(config: VictimConfig) -> VictimInstance: ...
def teardown_victim(instance_id: str) -> None: ...
```

Person 2 calls this via Person 1's lane scheduler (the scheduler handles provisioning automatically). Person 3 calls it directly for replays, cold verification, and patch verification — either through the module-level convenience functions or by holding a `VictimProvisioner` reference passed in at construction time.

---

## Contract 4: Cross-Boundary Code Dependencies

Two — and only two — modules may be imported across the red_team / blue_team / infra boundary. Anything else is a contract violation.

### 4a. `red_team/checks.py` — Tier 1 programmatic judgment

Person 2 packages the 6 Tier 1 checks as a standalone importable module. Person 3 imports it for replay verification and patch testing.

**Rules:**
- Single file with pure functions
- NO imports from the rest of `red_team/`
- NO side effects (no database writes, no network calls, no file modifications)
- All inputs and outputs use types from `interfaces/types.py`

**Functions Person 3 imports:**
```python
def check_filesystem_breach(fs_diff: FsDiff, allowed_paths: list[str]) -> CheckResult
def check_network_violation(network_log: list[NetworkEvent], allowed_domains: list[str]) -> CheckResult
def check_process_escape(process_log: list[ProcessEvent], seccomp_profile: SeccompProfile | dict) -> CheckResult
def check_permission_escalation(memory_diff: MemoryDiff, process_log: list[ProcessEvent], policy: AgentPolicy | dict) -> CheckResult
def check_pii_in_cloud_route(inference_routing_log: list[InferenceEvent]) -> CheckResult
def check_policy_modification(fs_diff: FsDiff, policy_paths: list[str]) -> CheckResult
def run_all_tier1_checks(lane_result: LaneResult, policy_config: PolicyConfig | dict) -> list[CheckResult]
```

Each check accepts the corresponding `PolicyConfig` field as either the typed dataclass (`SeccompProfile`, `AgentPolicy`, `PolicyConfig`) or a plain dict with matching keys — convenient for tests that synthesize policies inline.

**Timeline:** Person 2 publishes function signatures (with stub implementations that return empty results) by Day 3. Person 3 can import and mock from that point. Real implementations filled in by Day 5.

### 4b. `interfaces/victim_client.py` — shared victim transport

A transport-agnostic chat client both red and blue need: red_team's execution agent uses it to drive the victim during a lane; blue_team's replay-minimizer and cold-verifier use it to drive a victim during replay. Since the client itself contains no team-specific logic, it lives in `interfaces/` and is owned by Person 1.

**Rules:**
- Pure transport: `mock://` (in-process registry), `http(s)://` (POST `{"message": ...}` → `{"reply": ...}`), `ipc:///path/to.sock` (newline-delimited JSON).
- NO imports from `red_team/` or `blue_team/`. Depends only on stdlib + `httpx` + `interfaces/types.py`.
- Test fixtures (the planted-vulnerability `MockVictim`) live in `red_team/mock_victim.py` and register themselves with the shared registry exposed here.

**Public surface:**
```python
# interfaces/victim_client.py

class VictimError(RuntimeError): ...

@dataclass
class TurnSideEffects:
    fs_files_written: list[str]
    network_events: list[NetworkEvent]
    inference_events: list[InferenceEvent]
    revealed_secret: bool

@runtime_checkable
class MockVictimProtocol(Protocol):
    def chat(self, message: str) -> tuple[str, TurnSideEffects]: ...

# Process-wide mock-victim registry, keyed by chat_endpoint
def register(endpoint: str, victim: MockVictimProtocol) -> None: ...
def unregister(endpoint: str) -> None: ...
def lookup(endpoint: str) -> MockVictimProtocol | None: ...
def reset_all() -> None: ...

class VictimClient:
    def __init__(self, chat_endpoint: str, timeout_s: float = 30.0) -> None: ...
    def send(self, message: str) -> tuple[str, TurnSideEffects | None]: ...
    def close(self) -> None: ...
    # also a context manager

def estimate_tokens(s: str) -> int: ...
```

`red_team/mock_victim.py` re-exports `TurnSideEffects`, `register`, `unregister`, `lookup`, and `reset_all` from this module so existing test code that reaches them via `red_team.mock_victim.<name>` keeps working.
