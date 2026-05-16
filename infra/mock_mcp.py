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
import json
import random
import sys
import uuid
from dataclasses import asdict
from datetime import UTC, datetime

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import (
    CheckResult,
    CodeChunk,
    CoverageGap,
    CycleSummary,
    CycleSummaryInput,
    DupResult,
    FindingInput,
    FindingRecord,
    IdeaInput,
    RegressionTest,
    RegressionTestInput,
    ReproPackage,
    ReproPackageInput,
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
        # No seeded history — the mock server starts empty. Findings,
        # cycles, and repro packages exist only once they are really logged.

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
            raise HTTPException(status_code=400, detail=str(e))
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
    print("state:", mcp.dump_state())


if __name__ == "__main__":
    raise SystemExit(main())
