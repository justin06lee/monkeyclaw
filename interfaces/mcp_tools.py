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
        self, embedding: list[float], zone: str, threshold: float
    ) -> DupResult:
        """Cosine similarity against all prior ideas for this zone.

        Returns max similarity + matching idea_id if above threshold.
        Embedding must be 384-dim float32.
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

    # ------------------------------------------------------------------
    # Repro packages
    # ------------------------------------------------------------------
    def push_repro_package(self, package: ReproPackageInput) -> str:
        """Publish a completed repro package. Returns package_id."""
        ...

    def get_blue_team_queue(self) -> list[ReproPackage]:
        """All repro packages with ready_for_blue=true and blue_team_status='queued'."""
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

    # ------------------------------------------------------------------
    # Codebase search
    # ------------------------------------------------------------------
    def search_codebase(self, query: str, top_k: int) -> list[CodeChunk]:
        """Vector search over NemoClaw source. Returns file path, line range, content."""
        ...

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------
    def send_alert(self, message: str, severity: str) -> None:
        """Telegram/webhook notification. severity in critical|high|medium|low|info."""
        ...


__all__ = ["MonkeyClawMCP"]
