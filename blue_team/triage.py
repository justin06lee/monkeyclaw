"""Triage agent — Deliverable 5.

Consumes repro packages from the blue team queue and produces a prioritized
fix queue.

Scoring:
    score = severity_weight × blast_radius × (1 / fix_complexity)

- `severity_weight`: critical=1.0 / high=0.8 / medium=0.5 / low=0.3
- `blast_radius`: how many zones/features a vuln impacts. We derive this
  from the repro package — a permission-model issue is global (large), a
  specific prompt-injection is narrow (small).
- `fix_complexity`: estimated from the root-cause analysis if available;
  otherwise from the failure_class (a boundary check is cheap, redesign
  is expensive).

Grouping:
- Two repro packages are grouped if they target the same zone AND share a
  primary fix file (when both have root-cause data above the speculative
  threshold). Groups are fixed together — one patch resolves all members.

We don't actually update MCP state in this module directly; the pipeline
glue calls into us, then writes blue_team_status="triaged" via MCP per the
spec.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from interfaces.types import ReproPackage

from blue_team._common import SEVERITY_ORDER

LOG = logging.getLogger("monkeyclaw.blue.triage")


# ---------------------------------------------------------------------------
# Scoring tables
# ---------------------------------------------------------------------------


SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3,
}

# Failure classes → default fix complexity 1..10. Larger = more invasive.
# These are tuned from the spec's "how big is the fix?" intuitions —
# information disclosure is usually a logging-level fix, sandbox escape is
# usually a boundary-check or syscall-policy fix, prompt injection often
# needs system-prompt rework.
DEFAULT_COMPLEXITY: dict[str, float] = {
    "sandbox_escape": 4.0,
    "permission_escalation": 5.0,
    "policy_modification": 3.0,
    "pii_leak": 3.0,
    "prompt_injection": 6.0,
    "behavioral_manipulation": 7.0,
    "memory_corruption": 6.0,
    "skill_trust_bypass": 5.0,
    "information_disclosure": 3.0,
    "none": 5.0,
}


# Zones that affect cross-cutting concerns → bigger blast radius even if
# the specific finding looks narrow. Mirrors the surface-zone "category"
# split used by the seed in `interfaces/schema.sql`.
GLOBAL_ZONES: set[str] = {
    "PERM-MODEL", "PERM-RUNTIME", "INF-ROUTE", "INF-LOCAL",
    "AGENT-COMM",
}

# Zones whose blast radius is naturally narrow.
LOCAL_ZONES: set[str] = {
    "SKILL-EXEC", "SKILL-SUPPLY", "SKILL-INSTALL",
    "MEM-STATE", "MEM-SHARED",
}


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass
class FixTask:
    """One item on the prioritized fix queue. May represent a single repro
    package or a group of related ones that should be patched together."""

    task_id: str  # logical id (not MCP-issued)
    packages: list[ReproPackage]  # 1+ packages grouped together
    severity: str  # max severity across grouped packages
    score: float
    components: dict[str, float] = field(default_factory=dict)
    recommended_approach: str = ""
    rationale: str = ""

    @property
    def primary_package(self) -> ReproPackage:
        return self.packages[0]

    @property
    def vuln_ids(self) -> list[str]:
        return [p.vuln_id for p in self.packages]


@dataclass
class TriageConfig:
    # Cap on how many tasks we hand to the patch generator per cycle.
    # Patch generation is expensive — keep the queue focused on the top
    # items each cycle.
    max_tasks_per_cycle: int = 8
    # Grouping is only enabled when both packages have a root-cause site
    # whose confidence ≥ this threshold (read from RootCauseConfig in
    # production wiring).
    grouping_min_confidence: float = 0.5


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------


class TriageAgent:
    def __init__(self, cfg: TriageConfig | None = None) -> None:
        self.cfg = cfg or TriageConfig()

    # ------------------------------------------------------------------
    def triage(self, packages: list[ReproPackage]) -> list[FixTask]:
        if not packages:
            return []
        # Skip packages already advanced beyond "queued" — the queue
        # filter on the MCP side normally handles this, but be defensive.
        eligible = [p for p in packages if p.blue_team_status == "queued"]
        if not eligible:
            return []

        # 1. Group related packages
        groups = self._group_related(eligible)

        # 2. Score each group
        tasks: list[FixTask] = []
        for idx, group in enumerate(groups):
            severity = self._max_severity(group)
            sev_w = SEVERITY_WEIGHT.get(severity, 0.5)
            blast = self._blast_radius(group)
            complexity = self._fix_complexity(group)
            score = sev_w * blast * (1.0 / max(complexity, 1.0))
            recommended = self._recommend_approach(group)
            rationale = self._rationale(severity, blast, complexity, group)
            tasks.append(FixTask(
                task_id=f"FT-{idx:03d}",
                packages=list(group),
                severity=severity,
                score=score,
                components={
                    "severity_weight": sev_w,
                    "blast_radius": blast,
                    "fix_complexity": complexity,
                },
                recommended_approach=recommended,
                rationale=rationale,
            ))

        # 3. Sort by score, cap at max_tasks_per_cycle
        tasks.sort(key=lambda t: t.score, reverse=True)
        capped = tasks[: self.cfg.max_tasks_per_cycle]
        for t in capped:
            LOG.info(
                "triage task=%s severity=%s score=%.3f packages=%d "
                "approach=%r",
                t.task_id, t.severity, t.score, len(t.packages),
                t.recommended_approach,
            )
        return capped

    # ------------------------------------------------------------------
    # Grouping
    # ------------------------------------------------------------------
    def _group_related(
        self, packages: list[ReproPackage]
    ) -> list[list[ReproPackage]]:
        """Greedy grouping by (zone, primary fix file).

        Two packages are grouped if they share a zone AND each has at
        least one FixSite with confidence ≥ grouping_min_confidence
        pointing at the SAME file. This is intentionally conservative —
        we'd rather generate two patches than mis-group two unrelated
        vulns into one fix attempt.
        """
        by_key: dict[tuple[str, str], list[ReproPackage]] = {}
        ungrouped: list[ReproPackage] = []
        for pkg in packages:
            key = self._group_key(pkg)
            if key is None:
                ungrouped.append(pkg)
            else:
                by_key.setdefault(key, []).append(pkg)
        groups: list[list[ReproPackage]] = list(by_key.values())
        # Each ungrouped package becomes its own single-member group.
        for pkg in ungrouped:
            groups.append([pkg])
        return groups

    def _group_key(self, pkg: ReproPackage) -> tuple[str, str] | None:
        if not pkg.affected_paths:
            return None
        for site in pkg.affected_paths:
            if site.confidence >= self.cfg.grouping_min_confidence and site.file:
                return (pkg.affected_zone, site.file)
        return None

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------
    @staticmethod
    def _max_severity(group: list[ReproPackage]) -> str:
        best = "low"
        for p in group:
            if SEVERITY_ORDER.get(p.severity, 0) > SEVERITY_ORDER.get(best, 0):
                best = p.severity
        return best

    @staticmethod
    def _blast_radius(group: list[ReproPackage]) -> float:
        """Heuristic ∈ (0, 1.5]. 1.0 is "average single-feature impact".

        Bumps:
        - Group has >1 package → at least as many features as members.
        - Zone is in GLOBAL_ZONES → bump.
        - Repro rate near 1.0 → bump (high reproducibility = more reach).
        Penalties:
        - Zone in LOCAL_ZONES.
        """
        base = 1.0
        zones = {p.affected_zone for p in group}
        if any(z in GLOBAL_ZONES for z in zones):
            base += 0.4
        if all(z in LOCAL_ZONES for z in zones):
            base -= 0.3
        if len(group) > 1:
            base += min(0.4, 0.1 * (len(group) - 1))
        avg_rate = sum(p.repro_rate for p in group) / len(group)
        if avg_rate >= 0.9:
            base += 0.1
        return max(0.1, min(base, 1.5))

    @staticmethod
    def _fix_complexity(group: list[ReproPackage]) -> float:
        """Estimate 1..10. Higher = harder fix.

        Use root-cause data when available — a single high-confidence
        site is cheap; multiple speculative sites are expensive.
        Otherwise fall back to the failure_class table.
        """
        complexities: list[float] = []
        for pkg in group:
            # Default by class — we look at the *primary* failure class.
            # Repro packages don't carry failure_class directly; we use
            # the first triggered evidence in the doc as a proxy. Fall
            # back to "none" complexity.
            cls = _guess_failure_class(pkg)
            base = DEFAULT_COMPLEXITY.get(cls, DEFAULT_COMPLEXITY["none"])
            if pkg.affected_paths:
                strong = [s for s in pkg.affected_paths if s.confidence >= 0.7]
                if strong:
                    base *= 0.7  # high-confidence single site is easier
                speculative = [s for s in pkg.affected_paths if s.confidence < 0.5]
                if speculative and not strong:
                    base *= 1.3  # only speculative sites → expensive
            complexities.append(base)
        # When grouping multiple packages, complexity grows sublinearly.
        if not complexities:
            return DEFAULT_COMPLEXITY["none"]
        return max(complexities) + 0.2 * (len(complexities) - 1)

    # ------------------------------------------------------------------
    # Recommendation copy
    # ------------------------------------------------------------------
    @staticmethod
    def _recommend_approach(group: list[ReproPackage]) -> str:
        cls = _guess_failure_class(group[0])
        recs = {
            "sandbox_escape":
                "Add a boundary check at the sandbox entry point and "
                "pre-resolve symlinks / canonicalize paths before policy "
                "comparison.",
            "permission_escalation":
                "Re-check capabilities at call time rather than relying "
                "on cached grants; deny privileged binaries from inside "
                "the sandbox.",
            "policy_modification":
                "Make policy files read-only at the OS level for the "
                "agent uid; detect overlay files in the policy directory.",
            "pii_leak":
                "Tighten the cloud-route filter (regex + spaCy NER) and "
                "route any flagged content to local Nemotron.",
            "prompt_injection":
                "Strengthen the system-prompt refusal patterns; add a "
                "meta-instruction filter before the model receives "
                "user input.",
            "behavioral_manipulation":
                "Cap the number of consecutive on-policy-edge requests; "
                "re-assert the system prompt at fixed intervals.",
            "memory_corruption":
                "Treat persistent-memory writes as suggestions rather "
                "than authoritative; require a confirmation channel.",
            "skill_trust_bypass":
                "Re-verify skill signatures at each invocation, not just "
                "at install time.",
            "information_disclosure":
                "Audit log redaction; ensure response templates don't "
                "interpolate restricted fields.",
            "none":
                "Manual review required — failure class is ambiguous.",
        }
        return recs.get(cls, recs["none"])

    @staticmethod
    def _rationale(
        severity: str, blast: float, complexity: float,
        group: list[ReproPackage],
    ) -> str:
        return (
            f"severity={severity} (weight={SEVERITY_WEIGHT.get(severity, 0.5):.1f}), "
            f"blast={blast:.2f}, complexity={complexity:.1f}, "
            f"grouped={len(group)} package(s)"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _guess_failure_class(pkg: ReproPackage) -> str:
    """Repro packages don't carry the failure_class directly. Derive it
    from the title + the first suggested mitigation."""
    blob = (pkg.title + " " + " ".join(pkg.suggested_mitigations)).lower()
    if "sandbox" in blob or "filesystem" in blob or "symlink" in blob:
        return "sandbox_escape"
    if "permission" in blob or "privilege" in blob or "capability" in blob:
        return "permission_escalation"
    if "policy" in blob:
        return "policy_modification"
    if "pii" in blob or "ssn" in blob or "credit card" in blob:
        return "pii_leak"
    if "prompt" in blob or "injection" in blob or "system prompt" in blob:
        return "prompt_injection"
    if "behavioral" in blob or "multi-turn" in blob:
        return "behavioral_manipulation"
    if "memory" in blob:
        return "memory_corruption"
    if "skill" in blob:
        return "skill_trust_bypass"
    if "disclosure" in blob:
        return "information_disclosure"
    return "none"


__all__ = [
    "DEFAULT_COMPLEXITY",
    "FixTask",
    "GLOBAL_ZONES",
    "LOCAL_ZONES",
    "SEVERITY_WEIGHT",
    "TriageAgent",
    "TriageConfig",
]
