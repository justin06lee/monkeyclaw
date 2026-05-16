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
    "patches", "regression", "models", "agents", "archive", "operators", "telemetry",
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
                 "/api/agents", "/api/judges", "/api/patches", "/api/packages"):
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


def test_dashboard_exposes_appeal_and_elo_panels(server):
    from infra.dashboard import _all
    from interfaces.types import AppealVerdict, AttackElo

    server.log_appeal_verdict(AppealVerdict(
        appeal_id="", lane_id="L1", ensemble_verdict="suspicious",
        appeal_verdict="confirmed", disagreement=0.7,
        ensemble_confidence=0.3, appeal_confidence=0.9))
    server.update_attack_elo(AttackElo(
        zone_id="SBX-FS", attack_id="F1", rating=1040.0,
        comparisons=2, wins=2, losses=0))
    state = _all(str(server.db.path))
    assert "judge_appeals" in state
    assert state["judge_appeals"]["appeal_count"] == 1
    assert state["judge_appeals"]["override_count"] == 1
    assert "attack_elo" in state
    assert state["attack_elo"][0]["attack_id"] == "F1"


def test_dashboard_page_renders_appeals_elo_and_sandbox_panels(tmp_path: Path):
    client = TestClient(build_dashboard_app(str(tmp_path / "nope.db")))
    html = client.get("/").text
    assert 'id="judgeAppeals"' in html
    assert 'id="attackElo"' in html
    assert 'id="sandboxRuns"' in html
    assert "function renderJudgeAppeals" in html
    assert "function renderAttackElo" in html
    assert "function renderSandboxRuns" in html
    assert "renderJudgeAppeals(d.judge_appeals)" in html
    assert "renderAttackElo(d.attack_elo)" in html
    assert "renderSandboxRuns(d.sandbox_runs)" in html


def test_technique_coverage_view_renders(server):
    from infra.dashboard import render_technique_coverage

    server.bump_technique_coverage(
        "PROMPT-INJ", "atlas", "AML.T0051", attempts=2, confirmations=1)
    html = render_technique_coverage(server)
    assert "Technique Coverage" in html
    assert "PROMPT-INJ" in html
    assert "AML.T0051" in html


def test_dashboard_exposes_model_winrate_panel(tmp_path: Path):
    """The dashboard surfaces per-zone model win-rate + recent rounds
    (model-ideation-tournament spec §9)."""
    from infra.dashboard import _all
    from infra.database import Database
    from infra.mcp_server import MCPServer
    from interfaces.types import ModelZoneWinrate, TournamentRound

    db_path = tmp_path / "tourney.db"
    db = Database(db_path)
    server = MCPServer(db)
    server.update_model_zone_winrate(ModelZoneWinrate(
        zone_id="SBX-FS", model_label="nemotron", role="red_ideation",
        h2h_wins=3, h2h_comparisons=4, confirmed=2, suspicious=1,
        ideas_executed=5, winrate=0.74))
    server.log_tournament_round(TournamentRound(
        round_id="", cycle_id=1, zone_id="SBX-FS",
        entrants=["nemotron", "frontier"],
        pairwise=[{"a": "nemotron", "b": "frontier",
                   "winner": "nemotron", "margin": 0.4}],
        winner_label="nemotron"))
    db.close()

    snap = _all(str(db_path))
    assert "model_tournament" in snap
    panel = snap["model_tournament"]
    assert panel["winrates"]
    assert panel["winrates"][0]["model_label"] == "nemotron"
    assert panel["recent_rounds"]
    assert panel["recent_rounds"][0]["winner"] == "nemotron"


def test_kill_chain_timeline_view_renders(tmp_path: Path):
    """The /kill-chains view lists composed chains and their step timeline."""
    from infra.database import Database
    from infra.mcp_server import MCPServer
    from interfaces.types import AttackChain, ChainStep, ChainStepResult

    db_path = str(tmp_path / "mc.db")
    db = Database(db_path)
    try:
        server = MCPServer(db)
        chain = AttackChain(
            chain_id="CHAIN-1", cycle_id=1, title="kill chain",
            zones=["PROMPT-INJ", "PRV-LEAK"], primary_zone="PRV-LEAK",
            steps=[
                ChainStep(0, "PROMPT-INJ", "foothold", "I0", "a0", [],
                          ["foothold.instruction_executed"], "s0"),
                ChainStep(1, "PRV-LEAK", "leak", "I1", "a1",
                          ["foothold.instruction_executed"],
                          ["secret.value_captured"], "s1"),
            ],
            builds_on=["I0", "I1"], estimated_turns=10)
        server.log_attack_chain(chain)
        server.log_chain_step_results([
            ChainStepResult("CHAIN-1", 0, "PROMPT-INJ", True,
                            ["foothold.instruction_executed"], (0, 3), 6.0),
            ChainStepResult("CHAIN-1", 1, "PRV-LEAK", False, [], (3, 6), 1.0),
        ])
    finally:
        db.close()

    client = TestClient(build_dashboard_app(db_path))
    resp = client.get("/kill-chains")
    assert resp.status_code == 200
    assert "CHAIN-1" in resp.text
    assert "PROMPT-INJ" in resp.text
    assert "PRV-LEAK" in resp.text


def test_patch_hardening_panel_renders(server):
    from infra.dashboard import render_patch_hardening
    from interfaces.types import VariantResult

    server.log_patch_variant_results("P1", "MC-2026-0001", [
        VariantResult(operator="paraphrase", variant_hash="h1",
                      blocked=True, judge_verdict="blocked"),
        VariantResult(operator="add_benign_framing", variant_hash="h2",
                      blocked=False, judge_verdict="confirmed"),
    ])
    server.log_patch_detection_result(
        patch_id="P1", vuln_id="MC-2026-0001", zone_id="SBX-FS",
        quadrant="PASS", observability="observed", prevention="blocked",
        passed=True, evidence="{}")
    html = render_patch_hardening(server, "P1")
    assert "paraphrase" in html
    assert "add_benign_framing" in html
    assert "PASS" in html

def test_dashboard_exposes_generalization_panel(tmp_path: Path):
    """The dashboard surfaces per-patch round count, operators tried,
    bypasses found and the final generalization status."""
    from infra.database import Database
    from infra.mcp_server import MCPServer
    from interfaces.types import GeneralizationRoundInput

    db_path = str(tmp_path / "gen.db")
    db = Database(db_path)
    try:
        server = MCPServer(db)
        server.log_generalization_round(GeneralizationRoundInput(
            patch_id="P1", finding_id="F1", vuln_id="MC-2026-0001",
            zone_id="PROMPT-INJ", round_index=0,
            operators_tried=["paraphrase", "insert_untrusted_document"],
            variants_total=2, variants_bypassed=1, variants_inconclusive=0,
            bypass_operators=["paraphrase"], outcome="generalized"))
    finally:
        db.close()

    client = TestClient(build_dashboard_app(db_path))
    resp = client.get("/generalization")
    assert resp.status_code == 200
    body = resp.text
    assert "P1" in body
    assert "paraphrase" in body
    assert "generalized" in body


def test_dashboard_renders_dataset_readiness(server):
    from infra.dashboard import render_dataset_readiness

    html = render_dataset_readiness(server)
    assert "dataset readiness" in html.lower()
    # An empty dataset is not ready — the volume criterion must show.
    assert "volume" in html.lower()
