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


def test_dashboard_exposes_mutation_operator_panel(tmp_path: Path):
    """The dashboard surfaces per-operator uses / success_rate / avg_lift,
    global rollup plus the per-zone breakdown."""
    from infra.database import Database
    from infra.mcp_server import MCPServer
    from interfaces.types import MutationOperatorStat

    db_path = tmp_path / "mut.db"
    db = Database(db_path)
    server = MCPServer(db)
    server.update_mutation_operator_stats(MutationOperatorStat(
        operator="paraphrase", zone_id="", uses=10, successes=7,
        avg_score=0.8, squared_score=6.4, last_lift=0.3))
    server.update_mutation_operator_stats(MutationOperatorStat(
        operator="paraphrase", zone_id="PROMPT-INJ", uses=4, successes=3,
        avg_score=0.9, squared_score=3.2, last_lift=0.5))
    db.close()

    client = TestClient(build_dashboard_app(str(db_path)))
    resp = client.get("/api/mutation-operators")
    assert resp.status_code == 200
    body = resp.json()
    glob = {r["operator"]: r for r in body["global"]}
    assert glob["paraphrase"]["uses"] == 10
    # success_rate 7/10 is computed and surfaced.
    assert glob["paraphrase"]["success_rate"] == 0.7
    assert glob["paraphrase"]["last_lift"] == 0.3
    # The per-zone breakdown carries its zone_id.
    by_zone = body["by_zone"]
    assert any(r["zone_id"] == "PROMPT-INJ" and r["operator"] == "paraphrase"
               for r in by_zone)
