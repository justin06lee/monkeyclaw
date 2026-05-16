"""MCP tool signatures — Contract 1.

Every MCP tool is declared as a Protocol method. Both the mock MCP server and
the real MCP server implement this protocol. Persons 2 and 3 type their MCP
clients against `MonkeyClawMCP` and never need to know which implementation is
bound.

Naming convention:
- Functions that read return either a dataclass, a list, or a primitive.
- Functions that write take an `*Input` dataclass and return the generated ID
  (or None for void writes).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from interfaces.types import (
    AppealVerdict,
    ArchiveCell,
    ArchiveUpdateInput,
    AttackElo,
    CodeChunk,
    ControlValidationRun,
    CoverageGap,
    CycleSummary,
    CycleSummaryInput,
    DetectionCoverage,
    DetectionRule,
    DetectionRuleInput,
    DetectionVerdict,
    DupResult,
    FindingInput,
    FindingRecord,
    IdeaComponent,
    IdeaComponentInput,
    IdeaInput,
    JudgeVoteInput,
    ModelRunInput,
    ModelZoneWinrate,
    MutationAttempt,
    MutationOperatorStat,
    NearMiss,
    NearMissInput,
    PatchCandidateInput,
    PolicyCorpusResult,
    PolicyCorpusResultInput,
    RegressionTest,
    RegressionTestInput,
    ReportCard,
    ReproPackage,
    ReproPackageInput,
    TechniqueRef,
    TelemetryEvent,
    TelemetryEventInput,
    TournamentRound,
    Trajectory,
)


@runtime_checkable
class MonkeyClawMCP(Protocol):
    """The full MCP surface. Implemented by `infra.mock_mcp.MockMCP` and
    `infra.mcp_server.MCPServer`."""

    # ------------------------------------------------------------------
    # Coverage / surface map
    # ------------------------------------------------------------------
    def get_coverage_gaps(self, top_n: int) -> list[CoverageGap]:
        """Top-N zones sorted by priority = severity × (1-coverage) × (1+vulns_open×0.2)."""
        ...

    def update_zone_coverage(self, zone_id: str, delta: float) -> None:
        """Adjust coverage score. Positive = tested. Negative = decay. Bounded [0, 1].

        Per spec §4.4: on test, coverage += 0.05 × (1 - current).
        On patch: reset to 0.3. On NemoClaw version change: reset to 0.0.
        """
        ...

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def log_finding(self, finding: FindingInput) -> str:
        """Write a judgment result to findings. Returns generated finding_id."""
        ...

    def search_findings(
        self, query: str, zone: str | None, top_k: int
    ) -> list[FindingRecord]:
        """Vector search over past findings. Optional zone filter."""
        ...

    # ------------------------------------------------------------------
    # Cycle summaries
    # ------------------------------------------------------------------
    def get_recent_summaries(self, n: int) -> list[CycleSummary]:
        """Last N cycle summaries ordered by recency (newest first)."""
        ...

    def log_cycle_summary(self, summary: CycleSummaryInput) -> None:
        """Write a compressed cycle summary."""
        ...

    # ------------------------------------------------------------------
    # Ideation
    # ------------------------------------------------------------------
    def check_duplicate(
        self, text: str, zone: str, threshold: float
    ) -> DupResult:
        """Cosine similarity against all prior ideas for this zone.

        The server embeds the text with the configured embedding model and
        compares it against the vector index for the given zone. Keeping the
        embedding model server-side means red_team/ and blue_team/ never need
        to import sentence-transformers.

        Returns max similarity + matching idea_id if above threshold.
        """
        ...

    def log_idea(self, idea: IdeaInput) -> str:
        """Persist an idea (including deduplicated ones). Returns idea_id."""
        ...

    # ------------------------------------------------------------------
    # Repro queue (red → blue handoff)
    # ------------------------------------------------------------------
    def push_to_repro_queue(self, finding_id: str, priority: str) -> None:
        """Enqueue a finding for repro. priority: 'high' | 'low'."""
        ...

    def get_repro_queue(self) -> list[FindingRecord]:
        """Atomically dequeue the next finding(s). Marks status='processing'.

        Returns up to 1 record. Callers are expected to call this repeatedly,
        each call serving a distinct lane/worker.
        """
        ...

    def sweep_stale_claims(self, older_than_seconds: int) -> int:
        """Requeue processing repro_queue rows past the timeout. Returns count."""
        ...

    # ------------------------------------------------------------------
    # Repro packages
    # ------------------------------------------------------------------
    def push_repro_package(self, package: ReproPackageInput) -> str:
        """Publish a completed repro package. Returns package_id."""
        ...

    def get_blue_team_queue(self) -> list[ReproPackage]:
        """All repro packages with ready_for_blue=true and blue_team_status='queued'."""
        ...

    def findings_for_vuln(self, vuln_id: str) -> list[str]:
        """finding_ids of every repro package minted for this vuln_id."""
        ...

    # ------------------------------------------------------------------
    # Regression suite
    # ------------------------------------------------------------------
    def get_regression_suite(self) -> list[RegressionTest]:
        """All active (non-deprecated) regression tests."""
        ...

    def add_regression_test(self, test: RegressionTestInput) -> str:
        """Append a new test to the permanent suite. Returns test_id."""
        ...

    def record_regression_run(
        self, test_id: str, result: str, *, flaky: bool = False,
    ) -> str:
        """Persist a regression test run, transition run_state, return it."""
        ...

    def reopen_finding(self, finding_id: str, reason: str) -> None:
        """Reopen a verified finding (verified->open) — a permanent
        regression test that newly fails means the vuln is live again."""
        ...

    # ------------------------------------------------------------------
    # Codebase search
    # ------------------------------------------------------------------
    def search_codebase(self, query: str, top_k: int) -> list[CodeChunk]:
        """Vector search over NemoClaw source. Returns file path, line range, content."""
        ...

    # NOTE (real-root-cause spec §7): the code-graph tables (code_symbols /
    # code_edges / executed_paths) are intentionally NOT exposed as MCP tools.
    # PythonCodeGraph and PathTracer read them directly from SQLite — the graph
    # walk is latency-sensitive and the consumer (blue_team) already holds a
    # Database handle, so a tool round-trip would add cost with no benefit.

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------
    def send_alert(self, message: str, severity: str) -> None:
        """Telegram/webhook notification. severity in critical|high|medium|low|info."""
        ...

    # ------------------------------------------------------------------
    # Telemetry & policy events (deliverable A5)
    # ------------------------------------------------------------------
    def log_telemetry_event(self, event: TelemetryEventInput) -> str:
        """Append a telemetry event. Returns the generated event_id."""
        ...

    def get_session_timeline(self, session_id: str) -> list[TelemetryEvent]:
        """All telemetry events for a session, ordered by timestamp."""
        ...

    # ------------------------------------------------------------------
    # Model run accounting
    # ------------------------------------------------------------------
    def log_model_run(self, run: ModelRunInput) -> str:
        """Record one LLM call's tokens/latency/cost. Returns run_id."""
        ...

    def get_model_cost_rollup(self) -> list[dict]:
        """Per-role token & cost rollup over model_runs. Read-only reporting."""
        ...

    # ------------------------------------------------------------------
    # Model ideation tournament — per-zone win-rate + rounds
    # ------------------------------------------------------------------
    def get_model_zone_winrate(
        self, zone_id: str | None = None,
    ) -> list[ModelZoneWinrate]:
        """All win-rate rows, or one zone's, for routing decisions."""
        ...

    def update_model_zone_winrate(self, row: ModelZoneWinrate) -> None:
        """Upsert one (zone_id, model_label) win-rate row."""
        ...

    def log_tournament_round(self, round: TournamentRound) -> str:
        """Record one head-to-head round. Returns round_id."""
        ...

    # ------------------------------------------------------------------
    # Judge votes
    # ------------------------------------------------------------------
    def log_judge_vote(self, vote: JudgeVoteInput) -> str:
        """Record one judge's vote on a lane. Returns vote_id."""
        ...

    # ------------------------------------------------------------------
    # Judge ensemble — appeal verdicts + attack Elo
    # ------------------------------------------------------------------
    def log_appeal_verdict(self, verdict: AppealVerdict) -> str:
        """Record one frontier-model appeal verdict. Returns appeal_id."""
        ...

    def get_appeal_verdicts(
        self, lane_id: str | None = None,
    ) -> list[AppealVerdict]:
        """All appeal verdicts, or one lane's, for the dashboard / analysis."""
        ...

    def get_attack_elo(self, zone_id: str) -> list[AttackElo]:
        """The per-zone attack Elo ranking, rating-sorted descending."""
        ...

    def update_attack_elo(self, elo: AttackElo) -> None:
        """Upsert one (zone_id, attack_id) Elo row."""
        ...

    # ------------------------------------------------------------------
    # Policy corpus
    # ------------------------------------------------------------------
    def log_policy_corpus_result(self, result: PolicyCorpusResultInput) -> str:
        """Record the outcome of one adversarial corpus case. Returns result_id."""
        ...

    def get_policy_corpus_results(self, run_id: str) -> list[PolicyCorpusResult]:
        """All corpus results for a given evaluation run."""
        ...

    # ------------------------------------------------------------------
    # Purple team — detection-as-pass scoring (purple-team spec §8)
    # ------------------------------------------------------------------
    def log_detection_result(self, verdict: DetectionVerdict) -> str:
        """Persist one DetectionVerdict into detection_results; return result_id."""
        ...

    def get_detection_results(
        self, zone_id: str | None = None
    ) -> list[DetectionVerdict]:
        """All detection results, optionally filtered to one zone."""
        ...

    def log_detection_rule(self, rule: DetectionRuleInput) -> str:
        """Persist one detection rule; return rule_id."""
        ...

    def get_detection_rules(
        self, zone_id: str | None = None
    ) -> list[DetectionRule]:
        """Active + candidate detection rules, optionally filtered to a zone."""
        ...

    def upsert_detection_coverage(self, coverage: DetectionCoverage) -> None:
        """Insert or replace the detection-coverage row for a zone."""
        ...

    def get_detection_coverage(self, zone_id: str) -> DetectionCoverage | None:
        """The current detection-coverage row for a zone, or None."""
        ...

    def log_control_validation_run(self, run: ControlValidationRun) -> str:
        """Persist a control-validation run; return run_id."""
        ...

    def get_control_validation_runs(
        self, kind: str | None = None
    ) -> list[ControlValidationRun]:
        """Validation runs newest-first, optionally filtered by kind."""
        ...

    def log_report_card(self, card: ReportCard) -> str:
        """Persist a report card; return card_id."""
        ...

    def get_latest_report_card(self) -> ReportCard | None:
        """The most recently generated report card, or None."""
        ...

    # ------------------------------------------------------------------
    # Queue / package / patch status transitions
    # ------------------------------------------------------------------
    def mark_repro_queue_status(
        self, finding_id: str, status: str, worker_id: str | None = None
    ) -> None:
        """Transition a repro_queue row: queued|processing|completed|failed."""
        ...

    def mark_repro_package_status(
        self, package_id: str, blue_team_status: str
    ) -> None:
        """Transition a repro package's blue_team_status."""
        ...

    def log_patch_candidate(self, patch: PatchCandidateInput) -> str:
        """Persist a candidate patch. Returns patch_id."""
        ...

    def mark_patch_status(
        self, patch_id: str, status: str,
        verification_results: dict | None = None,
    ) -> None:
        """Transition a patch's status and optionally store verification results."""
        ...

    def mark_finding_patched(self, finding_id: str) -> None:
        """Advance a finding in_progress->patched->verified after approval."""
        ...

    # ------------------------------------------------------------------
    # MAP-Elites archive
    # ------------------------------------------------------------------
    def update_archive_cell(self, update: ArchiveUpdateInput) -> ArchiveCell:
        """Upsert a MAP-Elites cell. occupancy increments on every call; the
        idea becomes the cell's elite iff the cell was empty or
        update.score > best_score. Returns the resulting cell."""
        ...

    def get_archive_cells(self, zone: str | None) -> list[ArchiveCell]:
        """All archive cells, optionally filtered to a single zone."""
        ...

    def store_idea_components(
        self, idea_id: str, components: list[IdeaComponentInput]
    ) -> list[str]:
        """Persist building-block rows for an idea. Returns generated component_ids."""
        ...

    def get_idea_components(self, idea_id: str) -> list[IdeaComponent]:
        """All component rows for an idea, oldest first."""
        ...

    # ------------------------------------------------------------------
    # Trajectory & near-miss scoring (trajectory spec §8)
    # ------------------------------------------------------------------
    def log_trajectory(self, trajectory: Trajectory) -> str:
        """Persist a Trajectory into trajectory_scores; return trajectory_id."""
        ...

    def get_trajectories(
        self, zone_id: str | None = None
    ) -> list[Trajectory]:
        """Trajectories newest-first, optionally filtered to one zone."""
        ...

    def log_near_miss(self, near_miss: NearMissInput) -> str:
        """Persist a near miss into near_misses; return near_miss_id."""
        ...

    def search_near_misses(
        self, zone: str | None, *, only_unconsumed: bool, top_k: int
    ) -> list[NearMiss]:
        """Near misses, newest-first, optionally filtered to a zone and to
        unconsumed rows, capped at top_k."""
        ...

    def mark_near_miss_consumed(self, near_miss_id: str) -> None:
        """Set consumed=1 on a near miss once a mutation has been seeded."""
        ...

    # ------------------------------------------------------------------
    # Mutation operator learning (mutation-operator-learning spec §8)
    # ------------------------------------------------------------------
    def get_mutation_operator_stats(
        self, zone_id: str | None = None
    ) -> list[MutationOperatorStat]:
        """Global rollup rows (zone_id=None) or one zone's per-zone rows."""
        ...

    def update_mutation_operator_stats(
        self, stat: MutationOperatorStat
    ) -> None:
        """Upsert one operator stat row. zone_id="" -> global table;
        a non-empty zone_id -> the per-zone table."""
        ...

    def log_mutation_attempt(self, attempt: MutationAttempt) -> str:
        """Insert one mutation_attempts row; return attempt_id."""
        ...

    # ------------------------------------------------------------------
    # Corpus-driven ideation — technique tags + coverage axis
    # ------------------------------------------------------------------
    def log_idea_techniques(
        self, idea_id: str, refs: list[TechniqueRef]
    ) -> None:
        """Persist technique tags for one idea into idea_techniques."""
        ...

    def get_idea_techniques(self, idea_id: str) -> list[TechniqueRef]:
        """Technique tags for one idea."""
        ...

    def log_finding_techniques(
        self, finding_id: str, refs: list[TechniqueRef]
    ) -> None:
        """Persist technique tags for one finding into finding_techniques."""
        ...

    def get_finding_techniques(self, finding_id: str) -> list[TechniqueRef]:
        """Technique tags for one finding."""
        ...

    def bump_technique_coverage(
        self, zone_id: str, technique_kind: str, technique_id: str,
        *, attempts: int = 0, confirmations: int = 0,
    ) -> None:
        """Increment the technique_coverage row for one (zone, technique)."""
        ...

    def get_technique_coverage_rows(
        self, zone_id: str | None = None
    ) -> list[dict]:
        """technique_coverage rows, optionally filtered to one zone."""
        ...


__all__ = ["MonkeyClawMCP"]
