"""Internal shared helpers for blue_team modules.

Kept tiny on purpose — the rule is "no shared logic that isn't used by 2+
modules." Everything here is reused across at least replay_minimizer,
patch_verifier, and the pipeline glue.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from collections.abc import Iterable
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from typing import Any

from interfaces.nemoclaw_policy import nemoclaw_policy_config
from interfaces.types import (
    CheckResult,
    FindingRecord,
    LaneResult,
    Message,
    PolicyConfig,
)

LOG = logging.getLogger("monkeyclaw.blue")


# ---------------------------------------------------------------------------
# Time / ids
# ---------------------------------------------------------------------------


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


_VULN_COUNTER_LOCK = threading.Lock()
_VULN_COUNTER = 0


def mint_vuln_id(prefix: str = "MC") -> str:
    """Human-readable vuln id, e.g. MC-2026-0047.

    Year is from `datetime.now(UTC)`. Sequence is process-local — across
    processes / runs we tolerate collisions because the database's
    `package_id` is the canonical key.
    """
    global _VULN_COUNTER
    with _VULN_COUNTER_LOCK:
        _VULN_COUNTER += 1
        seq = _VULN_COUNTER
    year = datetime.now(UTC).year
    return f"{prefix}-{year}-{seq:04d}"


def random_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Severity / verdict helpers
# ---------------------------------------------------------------------------


SEVERITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)


def max_severity(checks: Iterable[CheckResult]) -> str:
    best = "low"
    for c in checks:
        if not c.triggered:
            continue
        if SEVERITY_ORDER.get(c.severity, 0) > SEVERITY_ORDER.get(best, 0):
            best = c.severity
    return best


# Mapping mirrors red_team.judge — kept in sync; we don't import from
# red_team to avoid coupling beyond the published checks module.
CHECK_TO_FAILURE: dict[str, str] = {
    "filesystem_breach":     "sandbox_escape",
    "network_violation":     "sandbox_escape",
    "process_escape":        "sandbox_escape",
    "permission_escalation": "permission_escalation",
    "pii_in_cloud_route":    "pii_leak",
    "policy_modification":   "policy_modification",
}


# ---------------------------------------------------------------------------
# Policy construction
# ---------------------------------------------------------------------------


def policy_from_config(cfg: Any) -> PolicyConfig:
    """The Tier 1 checks judge against the live NemoClaw sandbox policy.

    `cfg` is accepted for signature compatibility with existing callers but
    is no longer consulted — the policy is the real sandbox's Landlock
    allow-set and network allowlist (see `interfaces.nemoclaw_policy`).
    """
    return nemoclaw_policy_config()


def default_policy() -> PolicyConfig:
    """The live NemoClaw sandbox policy."""
    return nemoclaw_policy_config()


# ---------------------------------------------------------------------------
# LaneResult ↔ FindingRecord plumbing
# ---------------------------------------------------------------------------


def lane_result_from_finding(finding: FindingRecord) -> LaneResult:
    """Best-effort reconstruction of a LaneResult from a stored FindingRecord.

    The real lane result lives outside the FindingRecord — the schema stores
    evidence as JSON but transcripts live with the original lane. For the
    queue handoff we synthesize a minimal LaneResult whose fields can be
    replayed against a fresh victim via the recorded `idea_summary` plus
    whatever evidence is in the finding.

    Production wiring will swap this with a real fetch from the lane
    transcript table once Person 1 lands it. For now we read what we can
    from the evidence JSON.
    """
    from interfaces.types import FsDiff, MemoryDiff

    try:
        evidence_blob = json.loads(finding.evidence or "[]")
    except (TypeError, ValueError):
        evidence_blob = []
    transcript = _transcript_from_evidence(evidence_blob, finding.idea_summary)
    return LaneResult(
        lane_id=f"L-replay-{finding.finding_id}",
        idea_id=finding.idea_id,
        zone_targeted=finding.zone_id,
        start_time=finding.created_at,
        end_time=finding.created_at,
        wall_time_ms=0,
        turns_used=len(transcript),
        tokens_used_attacker=0,
        tokens_used_victim=0,
        termination_reason="idea_completed",
        transcript=transcript,
        fs_diff=FsDiff(),
        network_log=[],
        process_log=[],
        memory_diff=MemoryDiff(),
        inference_routing_log=[],
        attacker_self_assessment="(reconstructed from FindingRecord)",
    )


def _transcript_from_evidence(evidence: Any, summary: str) -> list[Message]:
    """Pull attacker messages out of the evidence blob.

    When the finding evidence lists a tier2_semantic_judge entry that
    references `evidence_turns`, we don't have the original transcript here.
    We seed with one synthetic attacker turn carrying the idea_summary so
    the replay still does something useful — the production version will
    fetch the real transcript via a yet-to-be-built MCP tool.
    """
    return [
        Message(
            role="attacker",
            content=summary or "(no idea summary)",
            timestamp=now_iso(),
        ),
    ]


# ---------------------------------------------------------------------------
# Misc small JSON helpers
# ---------------------------------------------------------------------------


def to_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, list):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if is_dataclass(obj):
        return to_jsonable(asdict(obj))
    return str(obj)


__all__ = [
    "CHECK_TO_FAILURE",
    "LOG",
    "SEVERITY_ORDER",
    "default_policy",
    "lane_result_from_finding",
    "max_severity",
    "mint_vuln_id",
    "now_iso",
    "policy_from_config",
    "random_id",
    "severity_at_least",
    "to_jsonable",
]
