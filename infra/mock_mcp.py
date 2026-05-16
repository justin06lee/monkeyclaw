"""Mock MCP server.

Returns realistic-looking dummy data so Persons 2 and 3 can develop and test
their agents on Day 2 — before the real DB/MCP exists.

Design rules:
- Implements the full `MonkeyClawMCP` Protocol.
- In-memory only. Resets every process start (unless `--persist` is passed).
- Returns shape-correct data with sensible defaults, including edge cases:
  empty results, near-duplicate matches, queues with mixed priorities, etc.
- Writes are echoed to stdout in JSON for easy debugging.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import random
import sys
import uuid
from dataclasses import asdict
from datetime import UTC, datetime, timedelta

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import (
    ArchiveCell,
    ArchiveUpdateInput,
    CheckResult,
    CodeChunk,
    CoverageGap,
    CycleSummary,
    CycleSummaryInput,
    DupResult,
    FindingInput,
    FindingRecord,
    IdeaComponent,
    IdeaComponentInput,
    IdeaInput,
    JudgeVote,
    JudgeVoteInput,
    ModelRunInput,
    ModelRunRecord,
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

# Hard-coded zones mirror schema.sql seed. Keep these in sync.
SEED_ZONES = [
    ("SBX-FS", "Sandbox / Filesystem", 1.0),
    ("SBX-NET", "Sandbox / Network", 1.0),
    ("SBX-PROC", "Sandbox / Process", 1.0),
    ("SBX-IPC", "Sandbox / IPC", 0.8),
    ("PRV-ROUTE", "Privacy / Inference Routing", 1.0),
    ("PRV-LEAK", "Privacy / Data Leak", 1.0),
    ("PERM-MODEL", "Permission Model", 1.0),
    ("PERM-RUNTIME", "Permission Runtime", 0.8),
    ("SKILL-INSTALL", "Skill Installation", 1.0),
    ("SKILL-EXEC", "Skill Execution", 1.0),
    ("SKILL-SUPPLY", "Skill Supply Chain", 0.8),
    ("MEM-STATE", "Memory / Persistent State", 0.8),
    ("MEM-SHARED", "Memory / Shared State", 0.5),
    ("INF-ROUTE", "Inference Routing Integrity", 0.8),
    ("INF-LOCAL", "Local Inference", 0.5),
    ("AGENT-COMM", "Agent Communication", 0.5),
    ("PROMPT-INJ", "Prompt Injection", 1.0),
    ("SOCIAL-ENG", "Social Engineering", 0.8),
]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class MockMCP(MonkeyClawMCP):
    """In-memory MCP. Conforms to the MonkeyClawMCP Protocol."""

    def __init__(self, seed: int = 42, verbose: bool = True) -> None:
        self.rand = random.Random(seed)
        self.verbose = verbose
        # In-memory state
        self._zones: dict[str, dict] = {
            zid: {
                "zone_id": zid,
                "zone_name": name,
                # Start clean — no fabricated coverage. Real coverage
                # accrues only as zones are actually tested.
                "coverage_score": 0.0,
                "vulns_open": 0,
                "severity_weight": sev,
                "last_tested_at": None,
                "description": f"Mock zone: {name}",
            }
            for zid, name, sev in SEED_ZONES
        }
        self._findings: dict[str, FindingRecord] = {}
        self._ideas: dict[str, IdeaInput] = {}
        self._cycles: list[CycleSummary] = []
        self._repro_queue: list[tuple[str, str]] = []  # (finding_id, priority)
        self._repro_processing: set[str] = set()
        self._repro_packages: dict[str, ReproPackage] = {}
        self._regression_tests: dict[str, RegressionTest] = {}
        self._alerts: list[dict] = []
        # New stores for A5 / A2 / A4 deliverables
        self._telemetry: list[TelemetryEvent] = []
        self._model_runs: list[ModelRunRecord] = []
        self._judge_votes: list[JudgeVote] = []
        self._corpus_results: list[PolicyCorpusResult] = []
        self._patch_candidates: dict[str, PatchCandidateInput] = {}
        self._patch_statuses: dict[str, dict] = {}
        self._archive_cells: dict[str, ArchiveCell] = {}
        self._idea_components: dict[str, list[IdeaComponent]] = {}
        self._seed_history()

    def _seed_history(self) -> None:
        """Plant a handful of fake findings + an entry in the repro queue so callers
        get non-empty results during early testing."""
        examples = [
            ("PROMPT-INJ", "Tool-call exfil via doc paste", "prompt_injection", "high"),
            ("SBX-FS", "Symlink escape from /tmp", "sandbox_escape", "critical"),
            ("PRV-ROUTE", "Cloud-route PII bypass", "pii_leak", "high"),
            ("SOCIAL-ENG", "Multi-turn policy walk", "behavioral_manipulation", "medium"),
        ]
        for zone, summary, fail, sev in examples:
            fid = _new_id("FND")
            rec = FindingRecord(
                finding_id=fid,
                cycle_id=0,
                idea_id=_new_id("IDEA"),
                zone_id=zone,
                source_mode="creative",
                idea_summary=summary,
                verdict="confirmed",
                tier_caught="programmatic" if fail != "behavioral_manipulation" else "semantic",
                failure_class=fail,
                severity=sev,
                evidence=json.dumps([{"check_name": "filesystem_breach", "triggered": True}]),
                repro_rate=0.8,
                patch_status="open",
                reusability=0.6,
                created_at=(datetime.now(UTC) - timedelta(days=2)).isoformat(),
            )
            self._findings[fid] = rec
        # One item already queued for repro
        sample_id = next(iter(self._findings))
        self._repro_queue.append((sample_id, "high"))

    # ------------------------------------------------------------------
    def _log(self, op: str, payload: dict) -> None:
        if not self.verbose:
            return
        sys.stderr.write(
            json.dumps({"mock_mcp": op, "ts": _now(), **payload}, default=str) + "\n"
        )
        sys.stderr.flush()

    # ------------------------------------------------------------------
    # Coverage
    # ------------------------------------------------------------------
    def get_coverage_gaps(self, top_n: int) -> list[CoverageGap]:
        gaps: list[CoverageGap] = []
        for z in self._zones.values():
            coverage = z["coverage_score"]
            priority = z["severity_weight"] * (1 - coverage) * (1 + z["vulns_open"] * 0.2)
            gaps.append(
                CoverageGap(
                    zone_id=z["zone_id"],
                    zone_name=z["zone_name"],
                    coverage_score=coverage,
                    priority_score=priority,
                    vulns_open=z["vulns_open"],
                    last_tested_at=z["last_tested_at"],
                    description=z["description"],
                    severity_weight=z["severity_weight"],
                )
            )
        gaps.sort(key=lambda g: g.priority_score, reverse=True)
        return gaps[:top_n]

    def update_zone_coverage(self, zone_id: str, delta: float) -> None:
        if zone_id not in self._zones:
            raise KeyError(f"unknown zone {zone_id}")
        z = self._zones[zone_id]
        if delta > 0:
            z["coverage_score"] = min(1.0, z["coverage_score"] + delta * (1 - z["coverage_score"]))
        else:
            z["coverage_score"] = max(0.0, z["coverage_score"] + delta)
        z["last_tested_at"] = _now()
        self._log("update_zone_coverage", {"zone_id": zone_id, "delta": delta,
                                            "coverage": z["coverage_score"]})

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def log_finding(self, finding: FindingInput) -> str:
        fid = _new_id("FND")
        rec = FindingRecord(
            finding_id=fid,
            cycle_id=finding.cycle_id,
            idea_id=finding.idea_id,
            zone_id=finding.zone_id,
            source_mode=finding.source_mode,
            idea_summary=finding.idea_summary,
            verdict=finding.verdict,
            tier_caught=finding.tier_caught,
            failure_class=finding.failure_class,
            severity=finding.severity,
            evidence=finding.evidence,
            repro_rate=None,
            patch_status="open",
            reusability=finding.reusability,
            created_at=_now(),
        )
        self._findings[fid] = rec
        if finding.verdict == "confirmed":
            self._zones.setdefault(finding.zone_id, {"vulns_open": 0})
            self._zones[finding.zone_id]["vulns_open"] = (
                self._zones[finding.zone_id].get("vulns_open", 0) + 1
            )
        self._log("log_finding", {"finding_id": fid, "verdict": finding.verdict})
        return fid

    def search_findings(
        self, query: str, zone: str | None, top_k: int
    ) -> list[FindingRecord]:
        candidates = [
            f for f in self._findings.values()
            if zone is None or f.zone_id == zone
        ]
        # Fake semantic ranking: longer summary first, plus a noise tiebreak
        candidates.sort(key=lambda f: (-len(f.idea_summary), self.rand.random()))
        return candidates[:top_k]

    # ------------------------------------------------------------------
    # Cycle summaries
    # ------------------------------------------------------------------
    def get_recent_summaries(self, n: int) -> list[CycleSummary]:
        # Only real logged cycles — empty until cycles actually run.
        return list(reversed(self._cycles))[:n]

    def log_cycle_summary(self, summary: CycleSummaryInput) -> None:
        cs = CycleSummary(
            cycle_id=summary.cycle_id,
            summary=summary.summary,
            zones_targeted=summary.zones_targeted,
            vulns_confirmed=summary.vulns_confirmed,
            created_at=_now(),
        )
        self._cycles.append(cs)
        self._log("log_cycle_summary", {"cycle_id": cs.cycle_id})

    # ------------------------------------------------------------------
    # Ideation
    # ------------------------------------------------------------------
    def check_duplicate(
        self, text: str, zone: str, threshold: float
    ) -> DupResult:
        # The mock doesn't actually embed — we just need shape-correct output.
        # Vary the response to give Person 2 something interesting to handle:
        # ~80% novel, 15% near-dup (below threshold), 5% above-threshold dup.
        _ = text  # held so signature matches the real server
        roll = self.rand.random()
        if roll < 0.80:
            return DupResult(is_duplicate=False, max_similarity=self.rand.uniform(0.0, 0.6),
                             matching_idea_id=None)
        if roll < 0.95:
            return DupResult(is_duplicate=False, max_similarity=self.rand.uniform(0.6, threshold - 0.01),
                             matching_idea_id=None)
        # Pick a real idea_id if we have one, else fabricate
        existing = list(self._ideas.keys())
        matching = existing[0] if existing else _new_id("IDEA")
        return DupResult(is_duplicate=True, max_similarity=self.rand.uniform(threshold, 0.99),
                         matching_idea_id=matching)

    def log_idea(self, idea: IdeaInput) -> str:
        iid = _new_id("IDEA")
        self._ideas[iid] = idea
        self._log("log_idea", {"idea_id": iid, "zone": idea.zone_id,
                                "mode": idea.source_mode, "deduplicated": idea.deduplicated})
        return iid

    # ------------------------------------------------------------------
    # Repro queue
    # ------------------------------------------------------------------
    def push_to_repro_queue(self, finding_id: str, priority: str) -> None:
        if finding_id not in self._findings:
            raise KeyError(f"unknown finding_id {finding_id}")
        self._repro_queue.append((finding_id, priority))
        # high priority floats to the front
        self._repro_queue.sort(key=lambda p: 0 if p[1] == "high" else 1)
        self._log("push_to_repro_queue", {"finding_id": finding_id, "priority": priority})

    def get_repro_queue(self) -> list[FindingRecord]:
        # Atomic single-item dequeue
        for i, (fid, _prio) in enumerate(self._repro_queue):
            if fid not in self._repro_processing:
                self._repro_processing.add(fid)
                self._repro_queue.pop(i)
                rec = self._findings.get(fid)
                if rec is None:
                    continue
                self._log("get_repro_queue", {"finding_id": fid})
                return [rec]
        return []

    def sweep_stale_claims(self, older_than_seconds: int) -> int:
        """Requeue stranded processing claims; mock mode has no clock, no-op."""
        self._log("sweep_stale_claims",
                  {"older_than_seconds": older_than_seconds})
        return 0

    # ------------------------------------------------------------------
    # Repro packages
    # ------------------------------------------------------------------
    def push_repro_package(self, package: ReproPackageInput) -> str:
        pid = _new_id("PKG")
        full = ReproPackage(
            package_id=pid,
            finding_id=package.finding_id,
            vuln_id=package.vuln_id,
            title=package.title,
            severity=package.severity,
            repro_rate=package.repro_rate,
            minimal_steps=package.minimal_steps,
            affected_zone=package.affected_zone,
            affected_paths=package.affected_paths,
            ideas_used=package.ideas_used,
            transcripts=package.transcripts,
            suggested_mitigations=package.suggested_mitigations,
            repro_document_md=package.repro_document_md,
            cold_verified=package.cold_verified,
            ready_for_blue=package.ready_for_blue,
            blue_team_status="queued",
            created_at=_now(),
        )
        self._repro_packages[pid] = full
        # mark the original finding as repro'd
        if package.finding_id in self._findings:
            self._findings[package.finding_id].repro_rate = package.repro_rate
        self._log("push_repro_package", {"package_id": pid, "vuln_id": package.vuln_id})
        return pid

    def get_blue_team_queue(self) -> list[ReproPackage]:
        return [
            pkg for pkg in self._repro_packages.values()
            if pkg.ready_for_blue and pkg.blue_team_status == "queued"
        ]

    def findings_for_vuln(self, vuln_id: str) -> list[str]:
        """finding_ids of every repro package minted for this vuln_id."""
        return [
            pkg.finding_id for pkg in self._repro_packages.values()
            if getattr(pkg, "vuln_id", None) == vuln_id
        ]

    # ------------------------------------------------------------------
    # Regression
    # ------------------------------------------------------------------
    def get_regression_suite(self) -> list[RegressionTest]:
        return [t for t in self._regression_tests.values() if not t.deprecated]

    def add_regression_test(self, test: RegressionTestInput) -> str:
        tid = _new_id("RT")
        rec = RegressionTest(
            test_id=tid,
            vuln_id=test.vuln_id,
            zone_id=test.zone_id,
            test_script=test.test_script,
            expected_result=test.expected_result,
            functionality_test_script=test.functionality_test_script,
            created_at=_now(),
        )
        self._regression_tests[tid] = rec
        self._log("add_regression_test", {"test_id": tid, "vuln_id": test.vuln_id})
        return tid

    def record_regression_run(
        self, test_id: str, result: str, *, flaky: bool = False,
    ) -> str:
        """Persist a regression test run; mock mode never enforces the FSM."""
        target = "quarantined" if flaky else (
            "passing" if result == "pass" else "failing")
        self._log("record_regression_run",
                  {"test_id": test_id, "result": result, "flaky": flaky})
        return target

    def reopen_finding(self, finding_id: str, reason: str) -> None:
        """Reopen a verified finding (verified->open); mock mode records it."""
        self._log("reopen_finding", {"finding_id": finding_id, "reason": reason})

    # ------------------------------------------------------------------
    # Codebase
    # ------------------------------------------------------------------
    def search_codebase(self, query: str, top_k: int) -> list[CodeChunk]:
        # Return realistic-looking NemoClaw-flavored stubs
        samples = [
            CodeChunk(
                file_path="src/commands/sandbox/create.ts",
                function_name="createSandbox",
                line_range="L120-L168",
                content=(
                    "// Resolve policy paths before passing to OpenShell\n"
                    "function createSandbox(policy: Policy) {\n"
                    "  const resolved = resolvePolicyPaths(policy);\n"
                    "  return openshell.create({ resolved });\n"
                    "}"
                ),
                language="typescript",
                score=0.81,
            ),
            CodeChunk(
                file_path="src/lib/inference/router.ts",
                function_name="routeInference",
                line_range="L42-L98",
                content=(
                    "// Decide whether to route to local Nemotron or cloud\n"
                    "export function routeInference(req: InferenceRequest) {\n"
                    "  if (containsPII(req.body)) return 'local';\n"
                    "  return 'cloud';\n"
                    "}"
                ),
                language="typescript",
                score=0.74,
            ),
            CodeChunk(
                file_path="src/lib/skills/install.ts",
                function_name="installSkill",
                line_range="L88-L140",
                content=(
                    "export async function installSkill(manifest: SkillManifest) {\n"
                    "  await verifySignature(manifest);\n"
                    "  return registerSkill(manifest);\n"
                    "}"
                ),
                language="typescript",
                score=0.66,
            ),
        ]
        # Deterministic noise on score
        return samples[:top_k]

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------
    def send_alert(self, message: str, severity: str) -> None:
        entry = {"message": message, "severity": severity, "ts": _now()}
        self._alerts.append(entry)
        self._log("send_alert", entry)

    # ------------------------------------------------------------------
    # Telemetry & policy events
    # ------------------------------------------------------------------
    def log_telemetry_event(self, event: TelemetryEventInput) -> str:
        eid = _new_id("EVT")
        self._telemetry.append(TelemetryEvent(
            event_id=eid,
            session_id=event.session_id,
            event_type=event.event_type,
            timestamp=_now(),
            actor=event.actor,
            action_class=event.action_class,
            target=event.target,
            decision=event.decision,
            reason_code=event.reason_code,
            data_class=event.data_class,
            content_hash=event.content_hash,
            excerpt=event.excerpt,
            metadata=dict(event.metadata),
        ))
        self._log("log_telemetry_event", {"event_id": eid, "session_id": event.session_id})
        return eid

    def get_session_timeline(self, session_id: str) -> list[TelemetryEvent]:
        return [e for e in self._telemetry if e.session_id == session_id]

    # ------------------------------------------------------------------
    # Model run accounting
    # ------------------------------------------------------------------
    def log_model_run(self, run: ModelRunInput) -> str:
        rid = _new_id("RUN")
        self._model_runs.append(ModelRunRecord(
            run_id=rid,
            role=run.role,
            model=run.model,
            provider=run.provider,
            input_tokens=run.input_tokens,
            output_tokens=run.output_tokens,
            latency_ms=run.latency_ms,
            cost_usd=run.cost_usd,
            success=run.success,
            error=run.error,
            created_at=_now(),
        ))
        self._log("log_model_run", {"run_id": rid, "role": run.role})
        return rid

    def get_model_cost_rollup(self) -> list[dict]:
        """Per-role token & cost rollup over recorded model runs."""
        by_role: dict[str, dict] = {}
        for r in self._model_runs:
            agg = by_role.setdefault(r.role, {
                "role": r.role, "runs": 0, "input_tokens": 0,
                "output_tokens": 0, "cost_usd": 0.0, "failures": 0,
            })
            agg["runs"] += 1
            agg["input_tokens"] += r.input_tokens
            agg["output_tokens"] += r.output_tokens
            agg["cost_usd"] += r.cost_usd or 0.0
            if not r.success:
                agg["failures"] += 1
        return sorted(by_role.values(), key=lambda a: a["cost_usd"], reverse=True)

    # ------------------------------------------------------------------
    # Judge votes
    # ------------------------------------------------------------------
    def log_judge_vote(self, vote: JudgeVoteInput) -> str:
        vid = _new_id("VOTE")
        self._judge_votes.append(JudgeVote(
            vote_id=vid,
            lane_id=vote.lane_id,
            judge_role=vote.judge_role,
            verdict=vote.verdict,
            score=vote.score,
            confidence=vote.confidence,
            reasoning=vote.reasoning,
            evidence_turns=list(vote.evidence_turns),
        ))
        self._log("log_judge_vote", {"vote_id": vid, "lane_id": vote.lane_id})
        return vid

    # ------------------------------------------------------------------
    # Policy corpus
    # ------------------------------------------------------------------
    def log_policy_corpus_result(self, result: PolicyCorpusResultInput) -> str:
        rid = _new_id("PCR")
        self._corpus_results.append(PolicyCorpusResult(
            result_id=rid,
            run_id=result.run_id,
            case_id=result.case_id,
            observed_decision=result.observed_decision,
            expected_decision=result.expected_decision,
            passed=result.passed,
            evidence=result.evidence,
            notes=result.notes,
            created_at=_now(),
        ))
        self._log("log_policy_corpus_result", {"result_id": rid, "run_id": result.run_id})
        return rid

    def get_policy_corpus_results(self, run_id: str) -> list[PolicyCorpusResult]:
        return [r for r in self._corpus_results if r.run_id == run_id]

    # ------------------------------------------------------------------
    # Queue / package / patch status transitions
    # ------------------------------------------------------------------
    def mark_repro_queue_status(
        self, finding_id: str, status: str, worker_id: str | None = None
    ) -> None:
        """Transition a repro-queue item's effective status.

        _repro_queue holds (finding_id, priority) tuples for pending items;
        _repro_processing holds finding_ids currently being worked on.
        We update those collections to reflect the new status.
        """
        if status == "processing":
            # Remove from queue, add to processing set
            self._repro_queue = [(fid, p) for fid, p in self._repro_queue if fid != finding_id]
            self._repro_processing.add(finding_id)
        elif status in ("completed", "failed"):
            self._repro_processing.discard(finding_id)
        elif status == "queued":
            self._repro_processing.discard(finding_id)
            if not any(fid == finding_id for fid, _ in self._repro_queue):
                self._repro_queue.append((finding_id, "normal"))
        self._log("mark_repro_queue_status", {"finding_id": finding_id, "status": status,
                                               "worker_id": worker_id})

    def mark_repro_package_status(
        self, package_id: str, blue_team_status: str
    ) -> None:
        """Transition a repro package's blue_team_status."""
        if package_id in self._repro_packages:
            self._repro_packages[package_id].blue_team_status = blue_team_status
        self._log("mark_repro_package_status", {"package_id": package_id,
                                                 "blue_team_status": blue_team_status})

    def log_patch_candidate(self, patch: PatchCandidateInput) -> str:
        pid = _new_id("PATCH")
        self._patch_candidates[pid] = dataclasses.replace(patch, vuln_ids=list(patch.vuln_ids))
        self._patch_statuses[pid] = {"status": "proposed", "verification_results": None}
        self._log("log_patch_candidate", {"patch_id": pid, "zone_id": patch.zone_id})
        return pid

    def mark_patch_status(
        self, patch_id: str, status: str,
        verification_results: dict | None = None,
    ) -> None:
        if patch_id in self._patch_statuses:
            self._patch_statuses[patch_id]["status"] = status
            if verification_results is not None:
                self._patch_statuses[patch_id]["verification_results"] = verification_results
        self._log("mark_patch_status", {"patch_id": patch_id, "status": status})

    def mark_finding_patched(self, finding_id: str) -> None:
        """Advance a finding in_progress->patched->verified after approval.

        Mock mode never enforces the FSM — it records the call.
        """
        self._log("mark_finding_patched", {"finding_id": finding_id})

    # ------------------------------------------------------------------
    # MAP-Elites archive
    # ------------------------------------------------------------------
    def update_archive_cell(self, update: ArchiveUpdateInput) -> ArchiveCell:
        cell_id = f"{update.zone_id}|{update.interaction_style}|{update.response_movement}"
        existing = self._archive_cells.get(cell_id)
        if existing is None:
            cell = ArchiveCell(
                cell_id=cell_id, zone_id=update.zone_id,
                interaction_style=update.interaction_style,
                response_movement=update.response_movement,
                best_idea_id=update.idea_id, best_score=update.score,
                occupancy=1, updated_at=_now(),
            )
        else:
            promote = update.score > existing.best_score
            cell = ArchiveCell(
                cell_id=cell_id, zone_id=update.zone_id,
                interaction_style=update.interaction_style,
                response_movement=update.response_movement,
                best_idea_id=update.idea_id if promote else existing.best_idea_id,
                best_score=update.score if promote else existing.best_score,
                occupancy=existing.occupancy + 1, updated_at=_now(),
            )
        self._archive_cells[cell_id] = cell
        self._log("update_archive_cell", {"cell_id": cell_id,
                  "elite": cell.best_idea_id, "occupancy": cell.occupancy})
        return cell

    def get_archive_cells(self, zone: str | None) -> list[ArchiveCell]:
        cells = list(self._archive_cells.values())
        if zone is not None:
            cells = [c for c in cells if c.zone_id == zone]
        return cells

    def store_idea_components(
        self, idea_id: str, components: list[IdeaComponentInput]
    ) -> list[str]:
        ids: list[str] = []
        rows = self._idea_components.setdefault(idea_id, [])
        for comp in components:
            cid = _new_id("CMP")
            rows.append(IdeaComponent(
                component_id=cid, idea_id=idea_id,
                component_type=comp.component_type, content=comp.content,
                created_at=_now(),
            ))
            ids.append(cid)
        self._log("store_idea_components", {"idea_id": idea_id, "count": len(ids)})
        return ids

    def get_idea_components(self, idea_id: str) -> list[IdeaComponent]:
        return list(self._idea_components.get(idea_id, []))

    # ------------------------------------------------------------------
    # Inspection helpers (mock-only — not part of the Protocol)
    # ------------------------------------------------------------------
    def dump_state(self) -> dict:
        return {
            "zones": {k: dict(v) for k, v in self._zones.items()},
            "findings_count": len(self._findings),
            "ideas_count": len(self._ideas),
            "repro_queue_depth": len(self._repro_queue),
            "repro_packages": len(self._repro_packages),
            "regression_tests": len(self._regression_tests),
            "cycles": len(self._cycles),
            "alerts": len(self._alerts),
            "telemetry_events": len(self._telemetry),
            "model_runs": len(self._model_runs),
            "judge_votes": len(self._judge_votes),
            "policy_corpus_results": len(self._corpus_results),
            "patch_candidates": len(self._patch_candidates),
        }


# ---------------------------------------------------------------------------
# HTTP front — JSON-RPC-ish dispatch so Persons 2 & 3 can hit it from any
# language during early integration.
# ---------------------------------------------------------------------------


def build_app(mcp: MockMCP):
    """Build a FastAPI app that exposes every MCP tool as POST /<tool>."""
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel, ConfigDict

    app = FastAPI(title="MonkeyClaw Mock MCP", version="0.1.0")

    class Envelope(BaseModel):
        model_config = ConfigDict(extra="allow")

    @app.get("/health")
    def health():
        return {"ok": True, "state": mcp.dump_state()}

    @app.post("/tool/{name}")
    def call(name: str, payload: dict):
        tool = getattr(mcp, name, None)
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
    parser = argparse.ArgumentParser(description="MonkeyClaw mock MCP server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7321)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument(
        "--smoke", action="store_true",
        help="Exercise every tool once and print results; do not start HTTP server.",
    )
    args = parser.parse_args(argv)

    mcp = MockMCP(seed=args.seed, verbose=not args.quiet)

    if args.smoke:
        _smoke_test(mcp)
        return 0

    import uvicorn
    uvicorn.run(build_app(mcp), host=args.host, port=args.port, log_level="info")
    return 0


def _smoke_test(mcp: MockMCP) -> None:
    """One-shot exercise of every tool so we can verify shape in CI."""
    gaps = mcp.get_coverage_gaps(top_n=3)
    print("coverage_gaps:", [(g.zone_id, round(g.priority_score, 2)) for g in gaps])
    mcp.update_zone_coverage(gaps[0].zone_id, 0.05)
    print("dup:", mcp.check_duplicate("smoke idea text", gaps[0].zone_id, 0.92))
    iid = mcp.log_idea(IdeaInput(
        cycle_id=1, zone_id=gaps[0].zone_id, source_mode="creative",
        title="Test", approach="x", success_criteria="y", estimated_turns=5,
        novelty_notes="z",
    ))
    print("logged_idea:", iid)
    fid = mcp.log_finding(FindingInput(
        cycle_id=1, idea_id=iid, zone_id=gaps[0].zone_id, source_mode="creative",
        idea_summary="smoke", verdict="confirmed", tier_caught="programmatic",
        failure_class="sandbox_escape", severity="high",
        evidence=json.dumps([asdict(CheckResult("dummy", True, "high", {}))]),
    ))
    print("logged_finding:", fid)
    mcp.push_to_repro_queue(fid, "high")
    print("repro_queue_head:", mcp.get_repro_queue())
    print("findings_search:", [f.finding_id for f in mcp.search_findings("test", None, 3)])
    print("recent_summaries:", [c.cycle_id for c in mcp.get_recent_summaries(3)])
    print("codebase:", [c.file_path for c in mcp.search_codebase("router", 2)])
    mcp.send_alert("smoke", "info")
    # Exercise the 10 new methods
    eid = mcp.log_telemetry_event(TelemetryEventInput(
        session_id="smoke-session", event_type="agent.session.started",
        actor="orchestrator", action_class="session",
    ))
    print("log_telemetry_event:", eid)
    timeline = mcp.get_session_timeline("smoke-session")
    assert len(timeline) == 1 and timeline[0].event_id == eid
    print("get_session_timeline:", len(timeline), "events")
    rid = mcp.log_model_run(ModelRunInput(
        role="red_ideation", model="nemotron-70b", provider="nvidia",
        input_tokens=100, output_tokens=200, latency_ms=500,
    ))
    print("log_model_run:", rid)
    vid = mcp.log_judge_vote(JudgeVoteInput(
        lane_id="L1", judge_role="semantic", verdict="confirmed",
        score=0.9, confidence=0.8, reasoning="smoke", evidence_turns=[1, 2],
    ))
    print("log_judge_vote:", vid)
    pcr_id = mcp.log_policy_corpus_result(PolicyCorpusResultInput(
        run_id="R1", case_id="C1", observed_decision="allow",
        expected_decision="allow", passed=True,
    ))
    print("log_policy_corpus_result:", pcr_id)
    corpus = mcp.get_policy_corpus_results("R1")
    assert len(corpus) == 1 and corpus[0].result_id == pcr_id
    print("get_policy_corpus_results:", len(corpus), "results")
    pid = mcp.log_patch_candidate(PatchCandidateInput(
        vuln_ids=[fid], zone_id=gaps[0].zone_id, approach="restrict",
        invasiveness="low", diff="--- a\n+++ b", explanation="smoke patch",
    ))
    print("log_patch_candidate:", pid)
    mcp.mark_patch_status(pid, "verified", {"passed": True})
    print("mark_patch_status: ok")
    mcp.mark_repro_queue_status(fid, "queued")
    print("mark_repro_queue_status(queued): ok")
    mcp.mark_repro_package_status("nonexistent-pkg", "reviewed")
    print("mark_repro_package_status: ok")
    print("state:", mcp.dump_state())


if __name__ == "__main__":
    raise SystemExit(main())
