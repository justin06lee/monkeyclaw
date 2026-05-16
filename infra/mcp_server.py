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

from infra.database import Database, EmbeddingModel
from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import (
    CodeChunk,
    CoverageGap,
    CycleSummary,
    CycleSummaryInput,
    DupResult,
    FindingInput,
    FindingRecord,
    IdeaInput,
    JudgeVoteInput,
    ModelRunInput,
    PatchCandidateInput,
    PolicyCorpusResult,
    PolicyCorpusResultInput,
    RegressionTest,
    RegressionTestInput,
    ReproPackage,
    ReproPackageInput,
    TelemetryEvent,
    TelemetryEventInput,
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
        self.db.execute(
            "INSERT OR REPLACE INTO repro_queue(finding_id, priority, status, enqueued_at) "
            "VALUES (?, ?, 'queued', ?)",
            (finding_id, priority, _now()),
        )

    def get_repro_queue(self) -> list[FindingRecord]:
        """Atomically claim the next queued finding. Returns 0 or 1 record."""
        worker = os.environ.get("MC_WORKER_ID") or _new_id("WK")
        with self.db.lock():
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.fetchone(
                    "SELECT finding_id FROM repro_queue "
                    "WHERE status = 'queued' "
                    "ORDER BY CASE WHEN priority = 'high' THEN 0 ELSE 1 END, enqueued_at "
                    "LIMIT 1"
                )
                if row is None:
                    self.db.execute("COMMIT")
                    return []
                fid = row["finding_id"]
                self.db.execute(
                    "UPDATE repro_queue SET status = 'processing', dequeued_at = ?, worker_id = ? "
                    "WHERE finding_id = ?",
                    (_now(), worker, fid),
                )
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
        finding_row = self.db.fetchone("SELECT * FROM findings WHERE finding_id = ?", (fid,))
        if finding_row is None:
            return []
        return [_finding_row_to_record(finding_row)]

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
        with self.db.lock():
            self.db.execute(
                "INSERT INTO repro_packages(package_id, finding_id, vuln_id, title, severity, "
                "repro_rate, minimal_steps, affected_zone, affected_paths, ideas_used, "
                "transcripts, suggested_mitigations, repro_document_md, cold_verified, "
                "ready_for_blue, blue_team_status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (pid, package.finding_id, vuln_id, package.title, package.severity,
                 package.repro_rate, json.dumps(package.minimal_steps),
                 package.affected_zone, affected_paths,
                 json.dumps(package.ideas_used), transcripts,
                 json.dumps(package.suggested_mitigations), package.repro_document_md,
                 1 if package.cold_verified else 0,
                 1 if package.ready_for_blue else 0, "queued", _now()),
            )
            self.db.execute(
                "UPDATE findings SET repro_rate = ?, patch_status = 'in_progress' "
                "WHERE finding_id = ?",
                (package.repro_rate, package.finding_id),
            )
            self.db.execute(
                "UPDATE repro_queue SET status = 'completed' WHERE finding_id = ?",
                (package.finding_id,),
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

    # ------------------------------------------------------------------
    # Judge votes
    # ------------------------------------------------------------------
    def log_judge_vote(self, vote: JudgeVoteInput) -> str:
        vid = _new_id("VOTE")
        with self.db.lock():
            self.db.execute(
                "INSERT INTO judge_votes(vote_id, lane_id, judge_role, verdict, "
                "score, confidence, reasoning, evidence_turns, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (vid, vote.lane_id, vote.judge_role, vote.verdict, vote.score,
                 vote.confidence, vote.reasoning,
                 json.dumps(list(vote.evidence_turns)), _now()),
            )
        return vid

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
    # Queue / package / patch status transitions
    # ------------------------------------------------------------------
    def mark_repro_queue_status(
        self, finding_id: str, status: str, worker_id: str | None = None
    ) -> None:
        with self.db.lock():
            # Silent no-op if the row is absent — callers transition rows they already own.
            self.db.execute(
                "UPDATE repro_queue SET status=?, worker_id=COALESCE(?, worker_id) "
                "WHERE finding_id=?",
                (status, worker_id, finding_id),
            )

    def mark_repro_package_status(
        self, package_id: str, blue_team_status: str
    ) -> None:
        with self.db.lock():
            # Silent no-op if the row is absent — callers transition rows they already own.
            self.db.execute(
                "UPDATE repro_packages SET blue_team_status=? WHERE package_id=?",
                (blue_team_status, package_id),
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
        with self.db.lock():
            # Silent no-op if the row is absent — callers transition rows they already own.
            vr = json.dumps(verification_results) if verification_results is not None else None
            self.db.execute(
                "UPDATE patches SET status=?, verification_results=? "
                "WHERE patch_id=?",
                (status, vr, patch_id),
            )

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


# ---------------------------------------------------------------------------
# Row → dataclass helpers
# ---------------------------------------------------------------------------


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
