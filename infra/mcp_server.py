"""Real MCP server backed by SQLite + sqlite-vec.

Implements every method of `interfaces.mcp_tools.MonkeyClawMCP` against the
real database. Coverage math follows spec §4.4. Queues use atomic SQL updates
to prevent double-dequeue across multiple workers.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from infra.database import Database, EmbeddingModel
from interfaces.mcp_tools import MonkeyClawMCP

if TYPE_CHECKING:
    from infra.state_machine import TransitionEngine
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
    TelemetryEvent,
    TelemetryEventInput,
    Trajectory,
    TurnScore,
)

LOG = logging.getLogger("monkeyclaw.mcp")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _vuln_id() -> str:
    """Human-readable vulnerability ID, MC-YYYY-NNNN."""
    return f"MC-{datetime.now(UTC).year}-{uuid.uuid4().int % 10000:04d}"


class MCPServer(MonkeyClawMCP):
    def __init__(self, db: Database, embedder: EmbeddingModel | None = None,
                 alert_sink=None) -> None:
        self.db = db
        self.embedder = embedder or EmbeddingModel.shared()
        self.alert_sink = alert_sink  # Callable[[str, str], None] | None
        self._telemetry = None
        self._code_backend = "python"
        self._argyph = None
        self._repo_path = "."

    @property
    def transitions(self) -> TransitionEngine:
        """The shared transition engine for this server's DB."""
        eng = getattr(self, "_transition_engine", None)
        if eng is None:
            from infra.state_machine import TransitionEngine
            eng = TransitionEngine(self.db)
            self._transition_engine = eng
        return eng

    def set_code_context(self, backend: str = "python",
                         argyph_binary: str | None = None,
                         repo_path: str = ".") -> None:
        """Configure the code-context backend (called by bootstrap)."""
        self._code_backend = backend
        self._repo_path = repo_path
        if backend == "argyph":
            from infra.argyph_index import ArgyphIndex  # noqa: PLC0415
            self._argyph = ArgyphIndex(binary=argyph_binary)
        else:
            self._argyph = None

    def attach_telemetry(self, emitter) -> None:
        """Attach a TelemetryEmitter so MCP calls emit agent.mcp.invoked.

        Attached lazily by the orchestrator/scheduler so contract tests that
        construct a bare MCPServer are unaffected.
        """
        self._telemetry = emitter

    def _emit_invoked(self, tool: str) -> None:
        if self._telemetry is not None:
            self._telemetry.mcp_invoked("mcp-client", tool=tool)

    # ------------------------------------------------------------------
    # Coverage / surface map
    # ------------------------------------------------------------------
    def get_coverage_gaps(self, top_n: int) -> list[CoverageGap]:
        self._emit_invoked("get_coverage_gaps")
        rows = self.db.fetchall(
            "SELECT zone_id, name, description, severity_weight, coverage_score, "
            "vulns_open, last_tested_at "
            "FROM surface_zones"
        )
        gaps: list[CoverageGap] = []
        for r in rows:
            priority = r["severity_weight"] * (1 - r["coverage_score"]) * (1 + r["vulns_open"] * 0.2)
            gaps.append(CoverageGap(
                zone_id=r["zone_id"],
                zone_name=r["name"],
                coverage_score=r["coverage_score"],
                priority_score=priority,
                vulns_open=r["vulns_open"],
                last_tested_at=r["last_tested_at"],
                description=r["description"],
                severity_weight=r["severity_weight"],
            ))
        gaps.sort(key=lambda g: g.priority_score, reverse=True)
        return gaps[:top_n]

    def update_zone_coverage(self, zone_id: str, delta: float) -> None:
        """Spec §4.4: positive delta = tested, increment by `delta * (1 - current)`.
        Negative delta = decay, simple add. Bounded [0, 1]."""
        with self.db.lock():
            row = self.db.fetchone(
                "SELECT coverage_score FROM surface_zones WHERE zone_id = ?",
                (zone_id,),
            )
            if row is None:
                raise KeyError(f"unknown zone {zone_id}")
            cur = row["coverage_score"]
            if delta >= 0:
                new = min(1.0, cur + delta * (1 - cur))
            else:
                new = max(0.0, cur + delta)
            self.db.execute(
                "UPDATE surface_zones SET coverage_score = ?, last_tested_at = ?, "
                "total_cycles = total_cycles + 1 "
                "WHERE zone_id = ?",
                (new, _now(), zone_id),
            )

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def log_finding(self, finding: FindingInput) -> str:
        self._emit_invoked("log_finding")
        fid = _new_id("FND")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO findings(finding_id, cycle_id, idea_id, zone_id, source_mode, "
                "idea_summary, verdict, tier_caught, failure_class, severity, evidence, "
                "reusability, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (fid, finding.cycle_id, finding.idea_id, finding.zone_id,
                 finding.source_mode, finding.idea_summary, finding.verdict,
                 finding.tier_caught, finding.failure_class, finding.severity,
                 finding.evidence, finding.reusability, _now()),
            )
            if finding.verdict == "confirmed":
                self.db.execute(
                    "UPDATE surface_zones SET vulns_found = vulns_found + 1, "
                    "vulns_open = vulns_open + 1 WHERE zone_id = ?",
                    (finding.zone_id,),
                )
            emb = finding.embedding or self.embedder.encode_one(finding.idea_summary).tolist()
            self.db.upsert_vector("findings_vec", "finding_id", fid, emb)
        return fid

    def search_findings(
        self, query: str, zone: str | None, top_k: int
    ) -> list[FindingRecord]:
        emb = self.embedder.encode_one(query)
        # Vec search over findings, then re-join to base table for full rows
        candidates = self.db.vector_search("findings_vec", "finding_id", emb, top_k * 3)
        if not candidates:
            return []
        ids = [c[0] for c in candidates]
        placeholders = ",".join("?" * len(ids))
        zone_clause = " AND zone_id = ? " if zone else " "
        params: tuple = (*ids, zone) if zone else tuple(ids)
        rows = self.db.fetchall(
            f"SELECT * FROM findings WHERE finding_id IN ({placeholders}) {zone_clause}",
            params,
        )
        # preserve KNN order
        by_id = {r["finding_id"]: r for r in rows}
        out: list[FindingRecord] = []
        for fid, _dist in candidates:
            r = by_id.get(fid)
            if r is None:
                continue
            out.append(_finding_row_to_record(r))
            if len(out) >= top_k:
                break
        return out

    # ------------------------------------------------------------------
    # Cycle summaries
    # ------------------------------------------------------------------
    def get_recent_summaries(self, n: int) -> list[CycleSummary]:
        rows = self.db.fetchall(
            "SELECT cycle_id, summary, zones_targeted, vulns_confirmed, created_at "
            "FROM cycle_log ORDER BY created_at DESC LIMIT ?",
            (n,),
        )
        return [
            CycleSummary(
                cycle_id=r["cycle_id"],
                summary=r["summary"],
                zones_targeted=json.loads(r["zones_targeted"]),
                vulns_confirmed=r["vulns_confirmed"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def log_cycle_summary(self, summary: CycleSummaryInput) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO cycle_log(cycle_id, summary, zones_targeted, "
            "ideas_generated, ideas_deduplicated, ideas_executed, vulns_confirmed, "
            "vulns_suspicious, total_tokens_used, wall_time_seconds, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (summary.cycle_id, summary.summary, json.dumps(summary.zones_targeted),
             summary.ideas_generated, summary.ideas_deduplicated, summary.ideas_executed,
             summary.vulns_confirmed, summary.vulns_suspicious,
             summary.total_tokens_used, summary.wall_time_seconds, _now()),
        )

    # ------------------------------------------------------------------
    # Ideation
    # ------------------------------------------------------------------
    def check_duplicate(
        self, text: str, zone: str, threshold: float
    ) -> DupResult:
        # Embed server-side so callers don't need the model.
        embedding = self.embedder.encode_one(text).tolist()
        # KNN against only ideas in this zone. We don't have a filter inside vec0
        # so we widen the KNN, then post-filter by zone.
        candidates = self.db.vector_search("ideas_vec", "idea_id", embedding, top_k=20)
        if not candidates:
            return DupResult(False, 0.0, None)
        ids = [c[0] for c in candidates]
        placeholders = ",".join("?" * len(ids))
        rows = self.db.fetchall(
            f"SELECT idea_id, zone_id FROM ideas WHERE idea_id IN ({placeholders}) AND zone_id = ?",
            (*ids, zone),
        )
        same_zone = {r["idea_id"] for r in rows}
        for iid, dist in candidates:
            if iid in same_zone:
                similarity = 1.0 - dist  # vec0 returns squared L2 for normalized -> ~cosine
                similarity = max(0.0, min(1.0, similarity))
                return DupResult(
                    is_duplicate=similarity >= threshold,
                    max_similarity=similarity,
                    matching_idea_id=iid if similarity >= threshold else None,
                )
        return DupResult(False, 0.0, None)

    def log_idea(self, idea: IdeaInput) -> str:
        self._emit_invoked("log_idea")
        iid = _new_id("IDEA")
        emb = idea.embedding or self.embedder.encode_one(f"{idea.title}\n{idea.approach}").tolist()
        with self.db.lock():
            self.db.execute(
                "INSERT INTO ideas(idea_id, cycle_id, zone_id, source_mode, title, approach, "
                "success_criteria, estimated_turns, novelty_notes, relevant_files, code_weakness, "
                "builds_on, variation_notes, priority_score, deduplicated, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (iid, idea.cycle_id, idea.zone_id, idea.source_mode, idea.title,
                 idea.approach, idea.success_criteria, idea.estimated_turns, idea.novelty_notes,
                 json.dumps(idea.relevant_files) if idea.relevant_files else None,
                 idea.code_weakness,
                 json.dumps(idea.builds_on) if idea.builds_on else None,
                 idea.variation_notes,
                 idea.priority_score, 1 if idea.deduplicated else 0, _now()),
            )
            self.db.upsert_vector("ideas_vec", "idea_id", iid, emb)
            self.db.execute(
                "UPDATE surface_zones SET unique_ideas_tried = unique_ideas_tried + 1 "
                "WHERE zone_id = ?",
                (idea.zone_id,),
            )
        return iid

    # ------------------------------------------------------------------
    # Repro queue — atomic dequeue
    # ------------------------------------------------------------------
    def push_to_repro_queue(self, finding_id: str, priority: str) -> None:
        if priority not in ("high", "low"):
            raise ValueError(f"priority must be 'high' or 'low', got {priority!r}")
        # Verify the finding exists
        if self.db.fetchone("SELECT 1 FROM findings WHERE finding_id = ?", (finding_id,)) is None:
            raise KeyError(f"unknown finding_id {finding_id}")
        from infra.state_machine import new_transition_id  # noqa: PLC0415
        with self.db.lock():
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute(
                    "INSERT OR REPLACE INTO repro_queue("
                    "finding_id, priority, status, enqueued_at) "
                    "VALUES (?, ?, 'queued', ?)",
                    (finding_id, priority, _now()),
                )
                self.db.execute(
                    "INSERT INTO queue_transitions(transition_id, entity, "
                    "entity_id, from_state, to_state, actor, reason) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (new_transition_id(), "repro_queue", finding_id,
                     None, "queued", "routing", f"enqueued ({priority})"),
                )
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def get_repro_queue(self) -> list[FindingRecord]:
        """Atomically claim the next queued finding. Returns 0 or 1 record."""
        worker = os.environ.get("MC_WORKER_ID") or _new_id("WK")
        fid = self.transitions.claim_next_repro(worker)
        if fid is None:
            return []
        finding_row = self.db.fetchone(
            "SELECT * FROM findings WHERE finding_id = ?", (fid,))
        if finding_row is None:
            return []
        return [_finding_row_to_record(finding_row)]

    def sweep_stale_claims(self, older_than_seconds: int) -> int:
        """Requeue repro_queue rows stranded in 'processing' by a crashed
        worker. Returns the count requeued."""
        return self.transitions.sweep_stale_claims(older_than_seconds)

    # ------------------------------------------------------------------
    # Repro packages
    # ------------------------------------------------------------------
    def push_repro_package(self, package: ReproPackageInput) -> str:
        self._emit_invoked("push_repro_package")
        pid = _new_id("PKG")
        vuln_id = package.vuln_id or _vuln_id()
        # `mint_vuln_id` on the blue side is a process-local counter, so
        # separate runs re-mint the same id (MC-2026-0001, ...). The DB's
        # `vuln_id` column is UNIQUE — re-mint until we land a free one.
        while self.db.fetchone(
            "SELECT 1 FROM repro_packages WHERE vuln_id = ?", (vuln_id,)
        ) is not None:
            vuln_id = _vuln_id()
        affected_paths = (
            json.dumps([asdict(p) for p in package.affected_paths])
            if package.affected_paths is not None else None
        )
        transcripts = json.dumps({
            k: [asdict(m) for m in v] for k, v in package.transcripts.items()
        })
        # The package INSERT, the findings.repro_rate UPDATE and both
        # audited lifecycle transitions (repro_queue ->completed, finding
        # ->in_progress) commit or roll back together as one atomic unit —
        # a crash mid-way can no longer leave a package without its
        # lifecycle transitions. The queue row may legally already be
        # 'processing' (claimed): processing->completed is a valid edge.
        insert_sql = (
            "INSERT INTO repro_packages(package_id, finding_id, "
            "vuln_id, title, severity, repro_rate, minimal_steps, "
            "affected_zone, affected_paths, ideas_used, transcripts, "
            "suggested_mitigations, repro_document_md, cold_verified, "
            "ready_for_blue, blue_team_status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        insert_params = (
            pid, package.finding_id, vuln_id, package.title,
            package.severity, package.repro_rate,
            json.dumps(package.minimal_steps), package.affected_zone,
            affected_paths, json.dumps(package.ideas_used),
            transcripts, json.dumps(package.suggested_mitigations),
            package.repro_document_md,
            1 if package.cold_verified else 0,
            1 if package.ready_for_blue else 0, "queued", _now(),
        )
        self.transitions.store_repro_package(
            insert_sql=insert_sql,
            insert_params=insert_params,
            finding_id=package.finding_id,
            finding_repro_rate=package.repro_rate,
            package_id=pid,
        )
        return pid

    def get_blue_team_queue(self) -> list[ReproPackage]:
        rows = self.db.fetchall(
            "SELECT * FROM repro_packages "
            "WHERE ready_for_blue = 1 AND blue_team_status = 'queued' "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 ELSE 3 END, created_at"
        )
        return [_repro_row_to_package(r) for r in rows]

    # ------------------------------------------------------------------
    # Regression suite
    # ------------------------------------------------------------------
    def get_regression_suite(self) -> list[RegressionTest]:
        rows = self.db.fetchall(
            "SELECT * FROM regression_tests WHERE deprecated = 0 ORDER BY created_at"
        )
        return [_regression_row_to_test(r) for r in rows]

    def add_regression_test(self, test: RegressionTestInput) -> str:
        tid = _new_id("RT")
        self.db.execute(
            "INSERT INTO regression_tests(test_id, vuln_id, zone_id, test_script, "
            "expected_result, functionality_test_script, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tid, test.vuln_id, test.zone_id, test.test_script,
             test.expected_result, test.functionality_test_script, _now()),
        )
        return tid

    def record_regression_run(
        self, test_id: str, result: str, *, flaky: bool = False,
    ) -> str:
        """Persist one regression test run. `result` is 'pass'|'fail'|'error'.
        Transitions run_state via REGRESSION_FSM (pass->passing,
        fail/error->failing) and writes last_run_at/last_run_result/
        consecutive_passes. If `flaky`, the test is moved to 'quarantined'
        instead. Returns the new run_state. Idempotent on the FSM: a
        same-state run is recorded but writes no transition."""
        row = self.db.fetchone(
            "SELECT run_state, consecutive_passes FROM regression_tests "
            "WHERE test_id = ?", (test_id,))
        if row is None:
            raise KeyError(f"unknown regression test {test_id!r}")
        current = row["run_state"]
        passed = result == "pass"
        target = "quarantined" if flaky else ("passing" if passed else "failing")
        new_passes = (row["consecutive_passes"] + 1) if passed else 0
        # The run-fields UPDATE and the run_state FSM transition commit or
        # roll back together — a crash can't leave last_run_result written
        # without its matching run_state edge.
        self.transitions.record_regression_run(
            test_id=test_id,
            update_sql=(
                "UPDATE regression_tests SET last_run_at = ?, "
                "last_run_result = ?, consecutive_passes = ? "
                "WHERE test_id = ?"
            ),
            update_params=(_now(), result, new_passes, test_id),
            target=target,
            current=current,
            reason=f"run result={result} flaky={flaky}",
        )
        return target

    def reopen_finding(self, finding_id: str, reason: str) -> None:
        """verified -> open: a regression for this finding's vuln failed."""
        self.transitions.transition(
            entity="finding", entity_id=finding_id, to_state="open",
            actor="regression_runner", reason=reason,
        )

    def findings_for_vuln(self, vuln_id: str) -> list[str]:
        """finding_ids of every repro package minted for this vuln_id."""
        rows = self.db.fetchall(
            "SELECT finding_id FROM repro_packages WHERE vuln_id = ?",
            (vuln_id,))
        return [r["finding_id"] for r in rows]

    # ------------------------------------------------------------------
    # Codebase search
    # ------------------------------------------------------------------
    def search_codebase(self, query: str, top_k: int) -> list[CodeChunk]:
        self._emit_invoked("search_codebase")
        if self._code_backend == "argyph" and self._argyph is not None \
                and self._argyph.available:
            chunks = self._argyph.search(query, top_k, self._repo_path)
            if chunks:
                return chunks
            # fall through to the Python indexer on empty/failed Argyph search
        emb = self.embedder.encode_one(query)
        candidates = self.db.vector_search("code_chunks_vec", "chunk_id", emb, top_k)
        if not candidates:
            return []
        ids = [c[0] for c in candidates]
        placeholders = ",".join("?" * len(ids))
        rows = self.db.fetchall(
            f"SELECT * FROM code_chunks WHERE chunk_id IN ({placeholders})",
            tuple(ids),
        )
        by_id = {r["chunk_id"]: r for r in rows}
        out: list[CodeChunk] = []
        for cid, dist in candidates:
            r = by_id.get(cid)
            if r is None:
                continue
            similarity = max(0.0, 1.0 - dist)
            out.append(CodeChunk(
                file_path=r["file_path"],
                function_name=r["function_name"],
                line_range=f"L{r['line_start']}-L{r['line_end']}",
                content=r["content"],
                language=r["language"],
                score=similarity,
            ))
        return out

    # ------------------------------------------------------------------
    # Telemetry & policy events
    # ------------------------------------------------------------------
    def log_telemetry_event(self, event: TelemetryEventInput) -> str:
        eid = _new_id("EVT")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO telemetry_events(event_id, session_id, event_type, "
                "timestamp, actor, action_class, target, decision, reason_code, "
                "data_class, content_hash, excerpt, metadata) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (eid, event.session_id, event.event_type, _now(), event.actor,
                 event.action_class, event.target, event.decision,
                 event.reason_code, event.data_class, event.content_hash,
                 event.excerpt, json.dumps(event.metadata)),
            )
        return eid

    def get_session_timeline(self, session_id: str) -> list[TelemetryEvent]:
        rows = self.db.fetchall(
            "SELECT * FROM telemetry_events WHERE session_id=? "
            "ORDER BY timestamp, event_id",
            (session_id,),
        )
        return [TelemetryEvent(
            event_id=r["event_id"], session_id=r["session_id"],
            event_type=r["event_type"], timestamp=r["timestamp"],
            actor=r["actor"], action_class=r["action_class"],
            target=r["target"], decision=r["decision"],
            reason_code=r["reason_code"], data_class=r["data_class"],
            content_hash=r["content_hash"], excerpt=r["excerpt"],
            metadata=json.loads(r["metadata"]),
        ) for r in rows]

    # ------------------------------------------------------------------
    # Model run accounting
    # ------------------------------------------------------------------
    def log_model_run(self, run: ModelRunInput) -> str:
        rid = _new_id("RUN")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO model_runs(run_id, role, model, provider, "
                "input_tokens, output_tokens, latency_ms, cost_usd, success, "
                "error, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (rid, run.role, run.model, run.provider, run.input_tokens,
                 run.output_tokens, run.latency_ms, run.cost_usd,
                 1 if run.success else 0, run.error, _now()),
            )
        return rid

    def get_model_cost_rollup(self) -> list[dict]:
        """Per-role token & cost rollup over all model_runs rows.

        Read-only reporting for the cycle summary and the dashboard cost
        panel — replaces the dashboard's blended token-price estimate.
        """
        rows = self.db.fetchall(
            "SELECT role, "
            "COUNT(*) AS runs, "
            "SUM(input_tokens) AS input_tokens, "
            "SUM(output_tokens) AS output_tokens, "
            "SUM(COALESCE(cost_usd, 0)) AS cost_usd, "
            "SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failures "
            "FROM model_runs GROUP BY role ORDER BY cost_usd DESC"
        )
        return [
            {
                "role": r["role"],
                "runs": r["runs"] or 0,
                "input_tokens": r["input_tokens"] or 0,
                "output_tokens": r["output_tokens"] or 0,
                "cost_usd": float(r["cost_usd"] or 0.0),
                "failures": r["failures"] or 0,
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Judge votes
    # ------------------------------------------------------------------
    def log_judge_vote(self, vote: JudgeVoteInput) -> str:
        vid = _new_id("VOTE")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO judge_votes(vote_id, lane_id, judge_role, verdict, "
                "score, confidence, reasoning, evidence_turns, is_appeal, "
                "weight, model, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (vid, vote.lane_id, vote.judge_role, vote.verdict, vote.score,
                 vote.confidence, vote.reasoning,
                 json.dumps(list(vote.evidence_turns)),
                 1 if vote.is_appeal else 0, vote.weight, vote.model, _now()),
            )
        return vid

    # ------------------------------------------------------------------
    # Judge ensemble — appeal verdicts + attack Elo
    # ------------------------------------------------------------------
    def log_appeal_verdict(self, verdict: AppealVerdict) -> str:
        appeal_id = verdict.appeal_id or f"appeal-{uuid.uuid4().hex[:12]}"
        with self.db.lock():
            self.db.execute(
                "INSERT INTO appeal_verdicts"
                "(appeal_id, lane_id, ensemble_verdict, appeal_verdict, "
                "disagreement, ensemble_confidence, appeal_confidence, "
                "failure_class, severity, sided_with_roles, reasoning, "
                "model, errored, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (appeal_id, verdict.lane_id, verdict.ensemble_verdict,
                 verdict.appeal_verdict, verdict.disagreement,
                 verdict.ensemble_confidence, verdict.appeal_confidence,
                 verdict.failure_class, verdict.severity,
                 json.dumps(list(verdict.sided_with_roles)), verdict.reasoning,
                 verdict.model, 1 if verdict.errored else 0, _now()),
            )
        return appeal_id

    def get_appeal_verdicts(
        self, lane_id: str | None = None,
    ) -> list[AppealVerdict]:
        if lane_id is None:
            rows = self.db.fetchall(
                "SELECT * FROM appeal_verdicts ORDER BY created_at DESC")
        else:
            rows = self.db.fetchall(
                "SELECT * FROM appeal_verdicts WHERE lane_id=? "
                "ORDER BY created_at DESC", (lane_id,))
        return [AppealVerdict(
            appeal_id=r["appeal_id"], lane_id=r["lane_id"],
            ensemble_verdict=r["ensemble_verdict"],
            appeal_verdict=r["appeal_verdict"], disagreement=r["disagreement"],
            ensemble_confidence=r["ensemble_confidence"],
            appeal_confidence=r["appeal_confidence"],
            failure_class=r["failure_class"], severity=r["severity"],
            sided_with_roles=json.loads(r["sided_with_roles"] or "[]"),
            reasoning=r["reasoning"], model=r["model"],
            errored=bool(r["errored"]), created_at=r["created_at"],
        ) for r in rows]

    def get_attack_elo(self, zone_id: str) -> list[AttackElo]:
        rows = self.db.fetchall(
            "SELECT * FROM attack_elo WHERE zone_id=? ORDER BY rating DESC",
            (zone_id,))
        return [AttackElo(
            zone_id=r["zone_id"], attack_id=r["attack_id"],
            rating=r["rating"], comparisons=r["comparisons"],
            wins=r["wins"], losses=r["losses"], updated_at=r["updated_at"],
        ) for r in rows]

    def update_attack_elo(self, elo: AttackElo) -> None:
        with self.db.lock():
            self.db.execute(
                "INSERT INTO attack_elo"
                "(zone_id, attack_id, rating, comparisons, wins, losses, "
                "updated_at) VALUES(?,?,?,?,?,?, datetime('now')) "
                "ON CONFLICT(zone_id, attack_id) DO UPDATE SET "
                "rating=excluded.rating, comparisons=excluded.comparisons, "
                "wins=excluded.wins, losses=excluded.losses, "
                "updated_at=excluded.updated_at",
                (elo.zone_id, elo.attack_id, elo.rating, elo.comparisons,
                 elo.wins, elo.losses),
            )

    # ------------------------------------------------------------------
    # Policy corpus
    # ------------------------------------------------------------------
    def log_policy_corpus_result(self, result: PolicyCorpusResultInput) -> str:
        rid = _new_id("PCR")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO policy_corpus_results(result_id, run_id, case_id, "
                "observed_decision, expected_decision, passed, evidence, notes, "
                "created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (rid, result.run_id, result.case_id, result.observed_decision,
                 result.expected_decision, 1 if result.passed else 0,
                 result.evidence, result.notes, _now()),
            )
        return rid

    def get_policy_corpus_results(self, run_id: str) -> list[PolicyCorpusResult]:
        rows = self.db.fetchall(
            "SELECT * FROM policy_corpus_results WHERE run_id=? "
            "ORDER BY created_at, result_id",
            (run_id,),
        )
        return [PolicyCorpusResult(
            result_id=r["result_id"], run_id=r["run_id"], case_id=r["case_id"],
            observed_decision=r["observed_decision"],
            expected_decision=r["expected_decision"],
            passed=bool(r["passed"]), evidence=r["evidence"],
            notes=r["notes"], created_at=r["created_at"],
        ) for r in rows]

    # ------------------------------------------------------------------
    # Purple team — detection-as-pass scoring (purple-team spec §8)
    # ------------------------------------------------------------------
    def log_detection_result(self, verdict: DetectionVerdict) -> str:
        rid = _new_id("DET")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO detection_results(result_id, session_id, "
                "execution_id, zone_id, quadrant, prevention, observability, "
                "rule_id, evidence, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (rid, verdict.session_id, verdict.execution_id, verdict.zone_id,
                 verdict.quadrant, verdict.prevention, verdict.observability,
                 verdict.rule_id, verdict.evidence, _now()),
            )
        return rid

    def get_detection_results(
        self, zone_id: str | None = None
    ) -> list[DetectionVerdict]:
        if zone_id is None:
            rows = self.db.fetchall(
                "SELECT * FROM detection_results ORDER BY created_at")
        else:
            rows = self.db.fetchall(
                "SELECT * FROM detection_results WHERE zone_id=? "
                "ORDER BY created_at", (zone_id,))
        return [DetectionVerdict(
            execution_id=r["execution_id"], session_id=r["session_id"],
            zone_id=r["zone_id"], quadrant=r["quadrant"],
            prevention=r["prevention"], observability=r["observability"],
            rule_id=r["rule_id"], evidence=r["evidence"]) for r in rows]

    def log_detection_rule(self, rule: DetectionRuleInput) -> str:
        rid = _new_id("RULE")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO detection_rules(rule_id, zone_id, "
                "source_finding_id, logic, expected_telemetry_signature, "
                "response_action, status, created_at) VALUES(?,?,?,?,?,?,?,?)",
                (rid, rule.zone_id, rule.source_finding_id, rule.logic,
                 rule.expected_telemetry_signature, rule.response_action,
                 rule.status, _now()),
            )
        return rid

    def get_detection_rules(
        self, zone_id: str | None = None
    ) -> list[DetectionRule]:
        if zone_id is None:
            rows = self.db.fetchall(
                "SELECT * FROM detection_rules ORDER BY created_at")
        else:
            rows = self.db.fetchall(
                "SELECT * FROM detection_rules WHERE zone_id=? "
                "ORDER BY created_at", (zone_id,))
        return [DetectionRule(
            rule_id=r["rule_id"], zone_id=r["zone_id"],
            source_finding_id=r["source_finding_id"], logic=r["logic"],
            expected_telemetry_signature=r["expected_telemetry_signature"],
            response_action=r["response_action"], status=r["status"],
            created_at=r["created_at"]) for r in rows]

    def upsert_detection_coverage(self, coverage: DetectionCoverage) -> None:
        with self.db.lock():
            self.db.execute(
                "INSERT INTO detection_coverage(zone_id, coverage_score, "
                "sample_count, updated_at) VALUES(?,?,?,?) "
                "ON CONFLICT(zone_id) DO UPDATE SET "
                "coverage_score=excluded.coverage_score, "
                "sample_count=excluded.sample_count, "
                "updated_at=excluded.updated_at",
                (coverage.zone_id, coverage.coverage_score,
                 coverage.sample_count, coverage.updated_at or _now()),
            )

    def get_detection_coverage(self, zone_id: str) -> DetectionCoverage | None:
        row = self.db.fetchone(
            "SELECT * FROM detection_coverage WHERE zone_id=?", (zone_id,))
        if row is None:
            return None
        return DetectionCoverage(
            zone_id=row["zone_id"], coverage_score=row["coverage_score"],
            sample_count=row["sample_count"], updated_at=row["updated_at"])

    def log_control_validation_run(self, run: ControlValidationRun) -> str:
        rid = run.run_id or _new_id("CVR")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO control_validation_runs(run_id, kind, "
                "cases_total, cases_passed, regressions, victim_build_id, "
                "status, created_at) VALUES(?,?,?,?,?,?,?,?)",
                (rid, run.kind, run.cases_total, run.cases_passed,
                 json.dumps(run.regressions), run.victim_build_id,
                 run.status, run.created_at or _now()),
            )
        return rid

    def get_control_validation_runs(
        self, kind: str | None = None
    ) -> list[ControlValidationRun]:
        if kind is None:
            rows = self.db.fetchall(
                "SELECT * FROM control_validation_runs ORDER BY created_at DESC")
        else:
            rows = self.db.fetchall(
                "SELECT * FROM control_validation_runs WHERE kind=? "
                "ORDER BY created_at DESC", (kind,))
        return [ControlValidationRun(
            run_id=r["run_id"], kind=r["kind"], cases_total=r["cases_total"],
            cases_passed=r["cases_passed"],
            regressions=json.loads(r["regressions"]),
            victim_build_id=r["victim_build_id"], status=r["status"],
            created_at=r["created_at"]) for r in rows]

    def log_report_card(self, card: ReportCard) -> str:
        from dataclasses import asdict
        cid = card.card_id or _new_id("CARD")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO report_cards(card_id, generated_at, "
                "dimensions, summary) VALUES(?,?,?,?)",
                (cid, card.generated_at or _now(),
                 json.dumps([asdict(d) for d in card.dimensions]),
                 card.summary),
            )
        return cid

    def get_latest_report_card(self) -> ReportCard | None:
        from interfaces.types import ReportCardDimension
        row = self.db.fetchone(
            "SELECT * FROM report_cards ORDER BY generated_at DESC LIMIT 1")
        if row is None:
            return None
        dims = [ReportCardDimension(**d)
                for d in json.loads(row["dimensions"])]
        return ReportCard(
            card_id=row["card_id"], generated_at=row["generated_at"],
            dimensions=dims, summary=row["summary"])

    # ------------------------------------------------------------------
    # Queue / package / patch status transitions
    # ------------------------------------------------------------------
    def mark_repro_queue_status(
        self, finding_id: str, status: str, worker_id: str | None = None
    ) -> None:
        """Transition a repro_queue row through the FSM. Raises
        IllegalTransition on an illegal edge, KeyError on a missing row."""
        self.transitions.transition(
            entity="repro_queue", entity_id=finding_id, to_state=status,
            actor=worker_id or "mcp", reason="mark_repro_queue_status",
        )

    def mark_repro_package_status(
        self, package_id: str, blue_team_status: str
    ) -> None:
        """Transition a repro package through the REPRO_PKG_FSM."""
        self.transitions.transition(
            entity="repro_package", entity_id=package_id,
            to_state=blue_team_status, actor="blue_pipeline",
            reason="mark_repro_package_status",
        )

    def log_patch_candidate(self, patch: PatchCandidateInput) -> str:
        pid = _new_id("PATCH")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO patches(patch_id, vuln_ids, zone_id, approach, "
                "invasiveness, diff, explanation, side_effects, status, "
                "created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (pid, json.dumps(patch.vuln_ids), patch.zone_id, patch.approach,
                 patch.invasiveness, patch.diff, patch.explanation,
                 patch.side_effects, "proposed", _now()),
            )
        return pid

    def mark_patch_status(
        self, patch_id: str, status: str,
        verification_results: dict | None = None,
    ) -> None:
        """Transition a patch through the PATCH_FSM, optionally storing
        verification results."""
        self.transitions.transition(
            entity="patch", entity_id=patch_id, to_state=status,
            actor="patch_verifier", reason="mark_patch_status",
        )
        if verification_results is not None:
            with self.db.lock():
                self.db.execute(
                    "UPDATE patches SET verification_results = ? "
                    "WHERE patch_id = ?",
                    (json.dumps(verification_results), patch_id),
                )

    def mark_finding_patched(self, finding_id: str) -> None:
        """Advance a finding through patched then verified after its patch is
        approved. in_progress -> patched -> verified, both edges audited."""
        self.transitions.transition(
            entity="finding", entity_id=finding_id, to_state="patched",
            actor="blue_pipeline", reason="patch approved",
        )
        self.transitions.transition(
            entity="finding", entity_id=finding_id, to_state="verified",
            actor="blue_pipeline", reason="patch approved",
        )

    # ------------------------------------------------------------------
    # MAP-Elites archive
    # ------------------------------------------------------------------
    def update_archive_cell(self, update: ArchiveUpdateInput) -> ArchiveCell:
        self._emit_invoked("update_archive_cell")
        cell_id = f"{update.zone_id}|{update.interaction_style}|{update.response_movement}"
        now = _now()
        with self.db.lock():
            row = self.db.fetchone(
                "SELECT best_idea_id, best_score, occupancy, niche_descriptors "
                "FROM idea_archive_cells WHERE cell_id = ?",
                (cell_id,),
            )
            nd_json = json.dumps(update.niche_descriptors or {})
            if row is None:
                self.db.execute(
                    "INSERT INTO idea_archive_cells(cell_id, zone_id, "
                    "interaction_style, response_movement, best_idea_id, "
                    "best_score, occupancy, niche_descriptors, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
                    (cell_id, update.zone_id, update.interaction_style,
                     update.response_movement, update.idea_id, update.score,
                     nd_json, now),
                )
            else:
                promote = update.score > row["best_score"]
                self.db.execute(
                    "UPDATE idea_archive_cells SET best_idea_id = ?, "
                    "best_score = ?, occupancy = occupancy + 1, "
                    "niche_descriptors = ?, updated_at = ? "
                    "WHERE cell_id = ?",
                    (update.idea_id if promote else row["best_idea_id"],
                     update.score if promote else row["best_score"],
                     nd_json if promote else row["niche_descriptors"],
                     now, cell_id),
                )
            out = self.db.fetchone(
                "SELECT * FROM idea_archive_cells WHERE cell_id = ?", (cell_id,))
        return _archive_row_to_cell(out)

    def get_archive_cells(self, zone: str | None) -> list[ArchiveCell]:
        self._emit_invoked("get_archive_cells")
        if zone is None:
            rows = self.db.fetchall("SELECT * FROM idea_archive_cells")
        else:
            rows = self.db.fetchall(
                "SELECT * FROM idea_archive_cells WHERE zone_id = ?", (zone,))
        return [_archive_row_to_cell(r) for r in rows]

    def store_idea_components(
        self, idea_id: str, components: list[IdeaComponentInput]
    ) -> list[str]:
        self._emit_invoked("store_idea_components")
        now = _now()
        ids: list[str] = []
        params: list[tuple] = []
        for comp in components:
            cid = _new_id("CMP")
            ids.append(cid)
            params.append((cid, idea_id, comp.component_type, comp.content, now))
        with self.db.lock():
            self.db.executemany(
                "INSERT INTO idea_components(component_id, idea_id, "
                "component_type, content, created_at) VALUES (?, ?, ?, ?, ?)",
                params,
            )
        return ids

    def get_idea_components(self, idea_id: str) -> list[IdeaComponent]:
        self._emit_invoked("get_idea_components")
        rows = self.db.fetchall(
            "SELECT * FROM idea_components WHERE idea_id = ? ORDER BY created_at",
            (idea_id,),
        )
        return [
            IdeaComponent(
                component_id=r["component_id"], idea_id=r["idea_id"],
                component_type=r["component_type"], content=r["content"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Trajectory & near-miss scoring (trajectory spec §8)
    # ------------------------------------------------------------------
    def log_trajectory(self, trajectory: Trajectory) -> str:
        tid = _new_id("TRJ")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO trajectory_scores(trajectory_id, lane_id, "
                "idea_id, zone_id, max_stage, final_stage, erosion_slope, "
                "stalled_at_turn, monotonic, turn_scores, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (tid, trajectory.lane_id, trajectory.idea_id,
                 trajectory.zone_id, trajectory.max_stage,
                 trajectory.final_stage, trajectory.erosion_slope,
                 trajectory.stalled_at_turn, int(trajectory.monotonic),
                 json.dumps([asdict(t) for t in trajectory.turn_scores]),
                 _now()),
            )
        return tid

    def get_trajectories(
        self, zone_id: str | None = None
    ) -> list[Trajectory]:
        if zone_id is None:
            rows = self.db.fetchall(
                "SELECT * FROM trajectory_scores ORDER BY created_at DESC")
        else:
            rows = self.db.fetchall(
                "SELECT * FROM trajectory_scores WHERE zone_id=? "
                "ORDER BY created_at DESC", (zone_id,))
        return [
            Trajectory(
                lane_id=r["lane_id"], idea_id=r["idea_id"],
                zone_id=r["zone_id"], max_stage=r["max_stage"],
                final_stage=r["final_stage"],
                erosion_slope=r["erosion_slope"],
                stalled_at_turn=r["stalled_at_turn"],
                monotonic=bool(r["monotonic"]),
                turn_scores=[TurnScore(**ts)
                             for ts in json.loads(r["turn_scores"])],
            )
            for r in rows
        ]

    def log_near_miss(self, near_miss: NearMissInput) -> str:
        nid = _new_id("NMS")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO near_misses(near_miss_id, idea_id, lane_id, "
                "zone_id, max_stage, stalled_at_turn, erosion_excerpt, "
                "useful_components, mutation_seeds, consumed, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,0,?)",
                (nid, near_miss.idea_id, near_miss.lane_id,
                 near_miss.zone_id, near_miss.max_stage,
                 near_miss.stalled_at_turn, near_miss.erosion_excerpt,
                 json.dumps(near_miss.useful_components),
                 json.dumps(near_miss.mutation_seeds), _now()),
            )
        return nid

    def search_near_misses(
        self, zone: str | None, *, only_unconsumed: bool, top_k: int
    ) -> list[NearMiss]:
        clauses, params = [], []
        if zone is not None:
            clauses.append("zone_id=?")
            params.append(zone)
        if only_unconsumed:
            clauses.append("consumed=0")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.db.fetchall(
            f"SELECT * FROM near_misses{where} "
            f"ORDER BY created_at DESC LIMIT ?", (*params, max(0, top_k)))
        return [
            NearMiss(
                near_miss_id=r["near_miss_id"], idea_id=r["idea_id"],
                lane_id=r["lane_id"], zone_id=r["zone_id"],
                max_stage=r["max_stage"],
                stalled_at_turn=r["stalled_at_turn"],
                erosion_excerpt=r["erosion_excerpt"],
                useful_components=json.loads(r["useful_components"]),
                mutation_seeds=json.loads(r["mutation_seeds"]),
                consumed=bool(r["consumed"]), created_at=r["created_at"],
            )
            for r in rows
        ]

    def mark_near_miss_consumed(self, near_miss_id: str) -> None:
        with self.db.lock():
            self.db.execute(
                "UPDATE near_misses SET consumed=1 WHERE near_miss_id=?",
                (near_miss_id,))

    # ------------------------------------------------------------------
    # Corpus-driven ideation — technique tags + coverage axis
    # ------------------------------------------------------------------
    def log_idea_techniques(self, idea_id, refs):
        self._emit_invoked("log_idea_techniques")
        params = [
            (idea_id, r.kind, r.technique_id, r.corpus_version, r.resolved_by)
            for r in refs
        ]
        if not params:
            return
        with self.db.lock():
            self.db.executemany(
                "INSERT INTO idea_techniques (idea_id, technique_kind, "
                "technique_id, corpus_version, resolved_by) "
                "VALUES (?, ?, ?, ?, ?)",
                params,
            )

    def get_idea_techniques(self, idea_id):
        from interfaces.types import TechniqueRef
        rows = self.db.fetchall(
            "SELECT * FROM idea_techniques WHERE idea_id = ?", (idea_id,))
        return [TechniqueRef(
            kind=r["technique_kind"], technique_id=r["technique_id"],
            name="", corpus_version=r["corpus_version"],
            resolved_by=r["resolved_by"]) for r in rows]

    def log_finding_techniques(self, finding_id, refs):
        self._emit_invoked("log_finding_techniques")
        params = [
            (finding_id, r.kind, r.technique_id, r.corpus_version,
             r.resolved_by)
            for r in refs
        ]
        if not params:
            return
        with self.db.lock():
            self.db.executemany(
                "INSERT INTO finding_techniques (finding_id, technique_kind, "
                "technique_id, corpus_version, resolved_by) "
                "VALUES (?, ?, ?, ?, ?)",
                params,
            )

    def get_finding_techniques(self, finding_id):
        from interfaces.types import TechniqueRef
        rows = self.db.fetchall(
            "SELECT * FROM finding_techniques WHERE finding_id = ?",
            (finding_id,))
        return [TechniqueRef(
            kind=r["technique_kind"], technique_id=r["technique_id"],
            name="", corpus_version=r["corpus_version"],
            resolved_by=r["resolved_by"]) for r in rows]

    def bump_technique_coverage(self, zone_id, technique_kind, technique_id,
                                *, attempts=0, confirmations=0):
        self._emit_invoked("bump_technique_coverage")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO technique_coverage (zone_id, technique_kind, "
                "technique_id, attempts, confirmations, last_seen_at) "
                "VALUES (?, ?, ?, ?, ?, datetime('now')) "
                "ON CONFLICT(zone_id, technique_kind, technique_id) "
                "DO UPDATE SET "
                "attempts = attempts + ?, confirmations = confirmations + ?, "
                "last_seen_at = datetime('now')",
                (zone_id, technique_kind, technique_id, attempts,
                 confirmations, attempts, confirmations),
            )

    def get_technique_coverage_rows(self, zone_id=None):
        if zone_id is None:
            rows = self.db.fetchall("SELECT * FROM technique_coverage")
        else:
            rows = self.db.fetchall(
                "SELECT * FROM technique_coverage WHERE zone_id = ?",
                (zone_id,))
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------
    def send_alert(self, message: str, severity: str) -> None:
        self.db.execute(
            "INSERT INTO alerts(message, severity, channel, delivered) VALUES (?, ?, ?, ?)",
            (message, severity, "stdout" if self.alert_sink is None else "telegram", 0),
        )
        if self.alert_sink is not None:
            try:
                self.alert_sink(message, severity)
                # mark the most recent alert delivered
                self.db.execute(
                    "UPDATE alerts SET delivered = 1 WHERE alert_id = "
                    "(SELECT MAX(alert_id) FROM alerts)"
                )
            except Exception as e:
                LOG.exception("alert delivery failed: %s", e)
        else:
            sys.stderr.write(f"[ALERT {severity.upper()}] {message}\n")

    # ------------------------------------------------------------------
    # Mutation operator learning (mutation-operator-learning spec §8)
    # ------------------------------------------------------------------
    def get_mutation_operator_stats(
        self, zone_id: str | None = None
    ) -> list[MutationOperatorStat]:
        if zone_id is None:
            rows = self.db.fetchall(
                "SELECT operator, uses, successes, avg_score, "
                "squared_score, last_lift FROM mutation_operator_stats")
            return [MutationOperatorStat(
                operator=r["operator"], zone_id="", uses=r["uses"],
                successes=r["successes"], avg_score=r["avg_score"],
                squared_score=r["squared_score"], last_lift=r["last_lift"])
                for r in rows]
        rows = self.db.fetchall(
            "SELECT operator, uses, successes, avg_score, squared_score, "
            "last_lift FROM mutation_operator_stats_by_zone WHERE zone_id=?",
            (zone_id,))
        return [MutationOperatorStat(
            operator=r["operator"], zone_id=zone_id, uses=r["uses"],
            successes=r["successes"], avg_score=r["avg_score"],
            squared_score=r["squared_score"], last_lift=r["last_lift"])
            for r in rows]

    def update_mutation_operator_stats(
        self, stat: MutationOperatorStat
    ) -> None:
        with self.db.lock():
            if stat.zone_id:
                self.db.execute(
                    "INSERT INTO mutation_operator_stats_by_zone("
                    "operator, zone_id, uses, successes, avg_score, "
                    "squared_score, last_lift, updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(operator, zone_id) DO UPDATE SET "
                    "uses=excluded.uses, successes=excluded.successes, "
                    "avg_score=excluded.avg_score, "
                    "squared_score=excluded.squared_score, "
                    "last_lift=excluded.last_lift, "
                    "updated_at=excluded.updated_at",
                    (stat.operator, stat.zone_id, stat.uses, stat.successes,
                     stat.avg_score, stat.squared_score, stat.last_lift,
                     _now()))
            else:
                self.db.execute(
                    "INSERT INTO mutation_operator_stats("
                    "operator, uses, successes, avg_score, squared_score, "
                    "last_lift, updated_at) VALUES(?,?,?,?,?,?,?) "
                    "ON CONFLICT(operator) DO UPDATE SET "
                    "uses=excluded.uses, successes=excluded.successes, "
                    "avg_score=excluded.avg_score, "
                    "squared_score=excluded.squared_score, "
                    "last_lift=excluded.last_lift, "
                    "updated_at=excluded.updated_at",
                    (stat.operator, stat.uses, stat.successes,
                     stat.avg_score, stat.squared_score, stat.last_lift,
                     _now()))

    def log_mutation_attempt(self, attempt: MutationAttempt) -> str:
        aid = attempt.attempt_id or _new_id("MUT")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO mutation_attempts(attempt_id, cycle_id, "
                "zone_id, operator, parent_idea_id, child_idea_id, "
                "parent_score, child_score, lift, improved, child_verdict, "
                "created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (aid, attempt.cycle_id, attempt.zone_id, attempt.operator,
                 attempt.parent_idea_id, attempt.child_idea_id,
                 attempt.parent_score, attempt.child_score, attempt.lift,
                 1 if attempt.improved else 0, attempt.child_verdict,
                 attempt.created_at or _now()))
        return aid


# ---------------------------------------------------------------------------
# Row → dataclass helpers
# ---------------------------------------------------------------------------


def _archive_row_to_cell(r) -> ArchiveCell:
    return ArchiveCell(
        cell_id=r["cell_id"], zone_id=r["zone_id"],
        interaction_style=r["interaction_style"],
        response_movement=r["response_movement"],
        best_idea_id=r["best_idea_id"], best_score=r["best_score"],
        occupancy=r["occupancy"], updated_at=r["updated_at"],
        niche_descriptors=json.loads(r["niche_descriptors"] or "{}"),
    )


def _finding_row_to_record(r) -> FindingRecord:
    return FindingRecord(
        finding_id=r["finding_id"], cycle_id=r["cycle_id"], idea_id=r["idea_id"],
        zone_id=r["zone_id"], source_mode=r["source_mode"], idea_summary=r["idea_summary"],
        verdict=r["verdict"], tier_caught=r["tier_caught"], failure_class=r["failure_class"],
        severity=r["severity"], evidence=r["evidence"], repro_rate=r["repro_rate"],
        patch_status=r["patch_status"], reusability=r["reusability"], created_at=r["created_at"],
    )


def _repro_row_to_package(r) -> ReproPackage:
    from interfaces.types import FixSite, Message  # noqa: PLC0415
    affected = None
    if r["affected_paths"]:
        affected = [FixSite(**fs) for fs in json.loads(r["affected_paths"])]
    transcripts_raw = json.loads(r["transcripts"])
    transcripts = {
        k: [Message(**m) for m in v] for k, v in transcripts_raw.items()
    }
    return ReproPackage(
        package_id=r["package_id"], finding_id=r["finding_id"], vuln_id=r["vuln_id"],
        title=r["title"], severity=r["severity"], repro_rate=r["repro_rate"],
        minimal_steps=json.loads(r["minimal_steps"]),
        affected_zone=r["affected_zone"],
        affected_paths=affected, ideas_used=json.loads(r["ideas_used"]),
        transcripts=transcripts,
        suggested_mitigations=json.loads(r["suggested_mitigations"]),
        repro_document_md=r["repro_document_md"],
        cold_verified=bool(r["cold_verified"]),
        ready_for_blue=bool(r["ready_for_blue"]),
        blue_team_status=r["blue_team_status"],
        created_at=r["created_at"],
    )


def _regression_row_to_test(r) -> RegressionTest:
    return RegressionTest(
        test_id=r["test_id"], vuln_id=r["vuln_id"], zone_id=r["zone_id"],
        test_script=r["test_script"], expected_result=r["expected_result"],
        functionality_test_script=r["functionality_test_script"],
        created_at=r["created_at"], deprecated=bool(r["deprecated"]),
        last_run_at=r["last_run_at"], last_run_result=r["last_run_result"],
        consecutive_passes=r["consecutive_passes"],
    )


# ---------------------------------------------------------------------------
# HTTP front
# ---------------------------------------------------------------------------


def build_app(server: MCPServer):
    from fastapi import FastAPI, HTTPException

    app = FastAPI(title="MonkeyClaw MCP", version="0.1.0")

    @app.get("/health")
    def health():
        zones = server.get_coverage_gaps(top_n=3)
        return {"ok": True, "top_gaps": [asdict(z) for z in zones]}

    @app.post("/tool/{name}")
    def call(name: str, payload: dict):
        tool = getattr(server, name, None)
        if tool is None or name.startswith("_") or not callable(tool):
            raise HTTPException(status_code=404, detail=f"unknown tool {name}")
        try:
            result = tool(**payload)
        except TypeError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return _serialize(result)

    return app


def _serialize(obj):
    if obj is None:
        return None
    if isinstance(obj, list):
        return [_serialize(x) for x in obj]
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    return obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MonkeyClaw real MCP server")
    parser.add_argument("--db", default="data/monkeyclaw.db")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7322)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    db = Database(args.db)
    server = MCPServer(db)

    if args.smoke:
        return _smoke(server)

    import uvicorn
    uvicorn.run(build_app(server), host=args.host, port=args.port, log_level="info")
    return 0


def _smoke(server: MCPServer) -> int:
    """Lightweight smoke test against the real DB."""
    gaps = server.get_coverage_gaps(top_n=3)
    print("top 3 gaps:", [(g.zone_id, round(g.priority_score, 3)) for g in gaps])
    server.update_zone_coverage(gaps[0].zone_id, 0.05)
    # Ideation
    iid = server.log_idea(IdeaInput(
        cycle_id=1, zone_id=gaps[0].zone_id, source_mode="creative",
        title="Smoke test idea", approach="Try X then Y", success_criteria="Z occurs",
        estimated_turns=5, novelty_notes="-",
    ))
    print("logged idea:", iid)
    dup = server.check_duplicate(
        text="Smoke test idea\nTry X then Y",
        zone=gaps[0].zone_id, threshold=0.92,
    )
    print("dup (expect ~1.0):", dup)
    fid = server.log_finding(FindingInput(
        cycle_id=1, idea_id=iid, zone_id=gaps[0].zone_id, source_mode="creative",
        idea_summary="Smoke finding", verdict="confirmed", tier_caught="programmatic",
        failure_class="sandbox_escape", severity="high",
        evidence=json.dumps([]),
    ))
    print("logged finding:", fid)
    server.push_to_repro_queue(fid, "high")
    queue = server.get_repro_queue()
    print("repro_queue head:", [f.finding_id for f in queue])
    print("findings_search 'Smoke':", [f.finding_id for f in server.search_findings("Smoke", None, 3)])
    server.send_alert("smoke alert", "info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
