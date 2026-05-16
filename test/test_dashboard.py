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


def test_individual_endpoints_respond(tmp_path: Path):
    client = TestClient(build_dashboard_app(str(tmp_path / "nope.db")))
    for path in ("/api/status", "/api/zones", "/api/findings", "/api/telemetry",
                 "/api/judges", "/api/patches", "/api/packages"):
        assert client.get(path).status_code == 200, path


def test_dashboard_snapshot_includes_purple_heatmap(tmp_path):
    from infra.dashboard import _all
    from infra.database import Database

    db = Database(tmp_path / "d.db")
    db.close()
    snap = _all(str(tmp_path / "d.db"))
    assert "purple_heatmap" in snap
    assert "purple_report_card" in snap
    assert "purple_timeline" in snap


def test_purple_heatmap_has_one_cell_per_zone(tmp_path):
    from infra.dashboard import _all
    from infra.database import Database

    db = Database(tmp_path / "d.db")
    db.close()
    snap = _all(str(tmp_path / "d.db"))
    # 18 registered zones.
    assert len(snap["purple_heatmap"]) == 18
    for cell in snap["purple_heatmap"]:
        assert {"zone_id", "attack_coverage", "detection_coverage"} \
            <= set(cell)


def test_niche_heatmap_view_renders(tmp_path: Path):
    """B5 — the niche-heatmap endpoint exposes the zone × style grid."""
    from infra.database import Database
    from infra.mcp_server import MCPServer
    from interfaces.types import ArchiveUpdateInput

    db_path = str(tmp_path / "mc.db")
    db = Database(db_path)
    try:
        server = MCPServer(db)
        server.update_archive_cell(ArchiveUpdateInput(
            zone_id="SBX-FS", interaction_style="direct",
            response_movement="refusal", idea_id="I1", score=6.0,
            niche_descriptors={"turn_bucket": "0-2"},
        ))
    finally:
        db.close()

    client = TestClient(build_dashboard_app(db_path))
    resp = client.get("/api/niche-heatmap")
    assert resp.status_code == 200
    data = resp.json()
    assert "direct" in data["styles"]
    assert any(row["zone_id"] == "SBX-FS" for row in data["rows"])
    fs_row = next(r for r in data["rows"] if r["zone_id"] == "SBX-FS")
    direct_idx = data["styles"].index("direct")
    assert fs_row["cells"][direct_idx]["best_score"] == 6.0


def test_dashboard_renders_trajectory_ribbon(server):
    from interfaces.types import Trajectory, TurnScore
    from infra.dashboard import render_trajectory_ribbon

    server.log_trajectory(Trajectory(
        lane_id="L1", idea_id="IDEA1", zone_id="PROMPT-INJ",
        turn_scores=[TurnScore(turn_index=0, stage=0, stage_delta=0),
                     TurnScore(turn_index=1, stage=3, stage_delta=3)],
        max_stage=3, final_stage=3, erosion_slope=1.5,
        stalled_at_turn=1, monotonic=True))
    html = render_trajectory_ribbon(server)
    assert "PROMPT-INJ" in html
    assert "stage" in html.lower()


def test_dashboard_renders_near_miss_queue(server):
    from interfaces.types import NearMissInput
    from infra.dashboard import render_near_miss_queue

    server.log_near_miss(NearMissInput(
        idea_id="IDEA1", lane_id="L1", zone_id="SBX-FS",
        max_stage=4, stalled_at_turn=3, erosion_excerpt="leaked path",
        useful_components=["partial_lead"],
        mutation_seeds=["concretize_final_request"]))
    html = render_near_miss_queue(server)
    assert "SBX-FS" in html
    assert "leaked path" in html
