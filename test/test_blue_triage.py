"""Triage agent tests."""

from __future__ import annotations

from interfaces.types import FixSite, ReproPackage

from blue_team.triage import TriageAgent, TriageConfig


def _package(
    vuln_id: str,
    zone: str,
    severity: str = "high",
    repro_rate: float = 0.8,
    title: str = "Symlink escape",
    fix_sites: list[FixSite] | None = None,
    mitigations: list[str] | None = None,
) -> ReproPackage:
    return ReproPackage(
        package_id=f"PKG-{vuln_id}",
        finding_id=f"FND-{vuln_id}",
        vuln_id=vuln_id,
        title=title,
        severity=severity,
        repro_rate=repro_rate,
        minimal_steps=[],
        affected_zone=zone,
        affected_paths=fix_sites,
        ideas_used=["IDEA-1"],
        transcripts={},
        suggested_mitigations=mitigations or ["fix the boundary check"],
        repro_document_md="(doc)",
        cold_verified=True,
        ready_for_blue=True,
        blue_team_status="queued",
        created_at="2026-05-14T00:00:00Z",
    )


# ---------------------------------------------------------------------------
# Basic scoring
# ---------------------------------------------------------------------------


def test_triage_orders_by_score():
    a = _package("V1", "SBX-FS", severity="medium")
    b = _package("V2", "PERM-MODEL", severity="critical")  # bigger blast + sev
    c = _package("V3", "MEM-SHARED", severity="low",
                  title="Memory shared bleed")
    tasks = TriageAgent().triage([a, b, c])
    assert [t.primary_package.vuln_id for t in tasks][0] == "V2"
    # All tasks scored
    assert all(t.score > 0 for t in tasks)


def test_triage_drops_non_queued():
    p = _package("V1", "SBX-FS")
    p.blue_team_status = "patching"
    assert TriageAgent().triage([p]) == []


def test_triage_empty_input():
    assert TriageAgent().triage([]) == []


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------


def test_triage_groups_by_zone_and_fix_file():
    fix_site = FixSite(
        file="src/sandbox/create.ts", function="createSandbox",
        line_range="L100", explanation="boundary", confidence=0.85,
    )
    a = _package("V1", "SBX-FS", fix_sites=[fix_site])
    b = _package("V2", "SBX-FS", fix_sites=[fix_site])
    c = _package("V3", "SBX-FS")  # no fix site → not grouped
    tasks = TriageAgent().triage([a, b, c])
    # We expect 2 tasks: one grouped {V1,V2}, one solo {V3}
    grouped = [t for t in tasks if len(t.packages) == 2]
    assert len(grouped) == 1
    assert {p.vuln_id for p in grouped[0].packages} == {"V1", "V2"}
    assert grouped[0].vuln_ids == ["V1", "V2"]


def test_triage_does_not_group_different_zones_same_file():
    fix_site = FixSite(
        file="src/x.ts", function="f", line_range="L1",
        explanation="x", confidence=0.9,
    )
    a = _package("V1", "SBX-FS", fix_sites=[fix_site])
    b = _package("V2", "SBX-NET", fix_sites=[fix_site])
    tasks = TriageAgent().triage([a, b])
    # Two separate tasks despite same fix file — zones differ.
    assert len(tasks) == 2


def test_triage_no_grouping_below_confidence():
    low = FixSite(file="src/x.ts", function="f", line_range="L1",
                   explanation="speculative", confidence=0.3)
    a = _package("V1", "SBX-FS", fix_sites=[low])
    b = _package("V2", "SBX-FS", fix_sites=[low])
    tasks = TriageAgent().triage([a, b])
    # Both packages should remain as separate single-member groups.
    assert len(tasks) == 2


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


def test_triage_recommends_per_failure_class():
    pkg_pii = _package(
        "V1", "PRV-ROUTE", severity="high",
        title="PII cloud route bypass",
        mitigations=["tighten PII filter"],
    )
    [task] = TriageAgent().triage([pkg_pii])
    assert "cloud-route" in task.recommended_approach.lower() or "filter" in task.recommended_approach.lower()


def test_triage_caps_at_max_tasks_per_cycle():
    pkgs = [_package(f"V{i}", "SBX-FS") for i in range(20)]
    agent = TriageAgent(TriageConfig(max_tasks_per_cycle=3))
    tasks = agent.triage(pkgs)
    assert len(tasks) == 3
