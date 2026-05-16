"""C9 — dashboard smoke tests.

The dashboard must start and serve cleanly against a missing/empty DB and
against a populated one, and `/api/all` must expose every section the page
renders.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from infra.dashboard import build_dashboard_app

_SECTIONS = (
    "status", "zones", "findings", "cycles", "ideas", "repro", "packages",
    "patches", "regression", "models", "archive", "operators", "telemetry",
    "judges", "activity",
)


def test_dashboard_serves_with_missing_db(tmp_path: Path):
    client = TestClient(build_dashboard_app(str(tmp_path / "nope.db")))
    assert client.get("/").status_code == 200
    resp = client.get("/api/all")
    assert resp.status_code == 200
    data = resp.json()
    # Every section is present and empty-safe.
    for key in _SECTIONS:
        assert key in data, f"/api/all missing section {key!r}"
    assert data["status"]["cycles"] == 0
    assert data["zones"] == []


def test_dashboard_serves_with_seeded_db(tmp_path: Path, monkeypatch):
    """Run one mock orchestrator cycle, then point the dashboard at the DB."""
    monkeypatch.setenv("MC_STORAGE__DB_PATH", str(tmp_path / "mc.db"))
    monkeypatch.setenv("MC_LOGGING__FILE", str(tmp_path / "mc.log"))
    monkeypatch.setenv("MC_LANES__POOL_SIZE", "2")
    monkeypatch.setenv("MC_LANES__LANE_TIMEOUT_SECONDS", "5")
    from infra.orchestrator import main as orch_main
    assert orch_main(["--use-mock-provisioner", "--max-cycles", "1"]) == 0

    # Mock-provisioner runs write to the separate `-mock` database.
    client = TestClient(build_dashboard_app(str(tmp_path / "mc-mock.db")))
    assert client.get("/").status_code == 200
    data = client.get("/api/all").json()
    assert data["status"]["cycles"] >= 1
    assert len(data["zones"]) == 18          # all attack-surface zones seeded
    assert isinstance(data["status"]["coverage"], (int, float))


def test_dashboard_distinguishes_research_grounded_ideas(tmp_path: Path):
    """Mode D ideas carry source_mode='research_grounded' and are derived from
    the preloaded attack-skill corpus. The dashboard must give that mode a
    distinct color so attack-skill-derived ideas are visually identifiable,
    rather than collapsing into the generic var(--line) fallback shared with
    unrecognized modes."""
    client = TestClient(build_dashboard_app(str(tmp_path / "nope.db")))
    html = client.get("/").text
    # The JS color map keyed by idea.source_mode must recognize Mode D.
    assert "research_grounded:" in html, (
        "dashboard MODE color map has no research_grounded entry — "
        "attack-skill-derived ideas fall back to the generic var(--line)"
    )
    # ...and the CSS custom property that entry points at must be defined.
    assert "--research_grounded:" in html, (
        "--research_grounded CSS variable is undefined"
    )


def test_dashboard_exposes_research_grounded_skill_id(db):
    db.execute(
        "INSERT INTO ideas(idea_id, cycle_id, zone_id, source_mode, title, "
        "approach, success_criteria, estimated_turns, novelty_notes, "
        "priority_score, deduplicated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "IDEA-skill",
            7,
            "PROMPT-INJ",
            "research_grounded",
            "XML breakout probe",
            "Exploit XML parser boundary handling.",
            "policy_decision=deny",
            4,
            "[impact=high] parser edge case [skill=AS-XML-BREAKOUT]",
            0.91,
            0,
        ),
    )

    client = TestClient(build_dashboard_app(str(db.path)))
    idea = client.get("/api/ideas").json()[0]
    assert idea["derived_from_skill"] == "AS-XML-BREAKOUT"

    html = client.get("/").text
    assert "derived_from_skill" in html


def test_individual_endpoints_respond(tmp_path: Path):
    client = TestClient(build_dashboard_app(str(tmp_path / "nope.db")))
    for path in ("/api/status", "/api/zones", "/api/findings", "/api/telemetry",
                 "/api/judges", "/api/patches", "/api/packages"):
        assert client.get(path).status_code == 200, path
