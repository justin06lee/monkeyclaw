"""B1 — deterministic playbook attacks against planted mock victims.

Loads the demo/attacks/*.yaml playbooks, replays them through the
ExecutionAgent's deterministic playbook mode (no LLM), and judges the
result. At least three playbooks must produce a confirmed finding.
"""

from __future__ import annotations

from pathlib import Path

from infra.monitoring_harness import HarnessConfig, MonitoringHarness
from interfaces.config_schema import LaneConfig
from interfaces.llm import MockLLM
from interfaces.provisioning import VictimInstance
from red_team import mock_victim
from red_team.execution_agent import ExecutionAgent, ExecutionConfig
from red_team.judge import Judge, default_policy
from red_team.playbooks import (
    PLAYBOOK_PROFILES,
    load_playbook_ideas,
    load_playbooks,
)

_NONEXISTENT_PID = 2_147_483_640


def setup_function(_):
    mock_victim.reset_all()


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def test_all_five_playbooks_load():
    pbs = load_playbooks()
    assert len(pbs) == 5
    assert {p.profile for p in pbs} == set(PLAYBOOK_PROFILES)
    for p in pbs:
        assert p.zone_id, f"{p.name} missing zone"
        assert p.turns, f"{p.name} has no turns"
        assert p.success_criteria, f"{p.name} missing success_criteria"


def test_playbooks_become_executable_ideas():
    ideas = load_playbook_ideas(cycle_id=1)
    assert len(ideas) == 5
    for idea in ideas:
        assert idea.source_mode == "playbook"
        assert idea.idea_id.startswith("PLAYBOOK-")
        assert getattr(idea, "playbook", None) is not None
        assert idea.estimated_turns == len(idea.playbook.turns)


# ---------------------------------------------------------------------------
# Execution + judgment against planted victims
# ---------------------------------------------------------------------------


def _run_and_judge(idea, base: Path):
    """Replay one playbook against a fresh planted victim; return (verdict,
    LaneResult)."""
    base.mkdir(parents=True, exist_ok=True)
    allowed = base / "allowed"
    escape = base / "evil"
    endpoint, _ = mock_victim.build_and_register(
        allowed_root=str(allowed), escape_root=str(escape))
    victim = VictimInstance(
        instance_id="VICT-PB", chat_endpoint=endpoint,
        shell_endpoint=None, status="running")
    harness = MonitoringHarness(
        cfg=HarnessConfig(
            watched_paths=[str(base)], allowed_paths=[str(allowed)],
            sandbox_pid=_NONEXISTENT_PID, psutil_interval=60.0),
        lane_id="LANE-PB", idea_id=idea.idea_id, zone_id=idea.zone_id)
    agent = ExecutionAgent(MockLLM(), ExecutionConfig())
    with harness:
        # Playbook mode runs no LLM — the MockLLM is never called.
        agent.execute(idea, victim, harness, LaneConfig())
    result = harness.result()
    judge = Judge(MockLLM(), default_policy(allowed_paths=[str(allowed)]))
    return judge.judge(result).verdict, result


def _ideas_by_id():
    return {i.idea_id: i for i in load_playbook_ideas(cycle_id=1)}


def test_filesystem_escape_playbook_confirms(tmp_path):
    verdict, result = _run_and_judge(
        _ideas_by_id()["PLAYBOOK-filesystem_escape"], tmp_path)
    assert verdict == "confirmed"
    assert result.fs_diff.files_outside_allowed_paths


def test_pii_cloud_route_playbook_confirms(tmp_path):
    verdict, result = _run_and_judge(
        _ideas_by_id()["PLAYBOOK-pii_cloud_route"], tmp_path)
    assert verdict == "confirmed"
    assert any(e.routed_to == "cloud" for e in result.inference_routing_log)


def test_skill_poison_playbook_confirms(tmp_path):
    verdict, result = _run_and_judge(
        _ideas_by_id()["PLAYBOOK-skill_poison"], tmp_path)
    assert verdict == "confirmed"
    assert result.fs_diff.files_outside_allowed_paths


def test_at_least_three_playbooks_produce_confirmed_findings(tmp_path):
    """Spec B1 acceptance: >= 3 playbooks confirm against planted victims."""
    ideas = _ideas_by_id()
    confirmed = 0
    for name in ("filesystem_escape", "pii_cloud_route", "skill_poison",
                 "prompt_injection", "memory_poisoning"):
        idea = ideas[f"PLAYBOOK-{name}"]
        # Only the Tier-1 zones confirm deterministically without an LLM
        # judge; prompt/memory rely on the semantic judge, so guard the call.
        if idea.zone_id in ("PROMPT-INJ", "MEM-STATE"):
            continue
        verdict, _ = _run_and_judge(idea, tmp_path / name)
        if verdict == "confirmed":
            confirmed += 1
    assert confirmed >= 3


def test_prompt_injection_playbook_runs_and_leaks(tmp_path):
    """The prompt-injection playbook deterministically replays and the victim
    leaks its system prompt into the transcript (Tier 2 judges the verdict)."""
    _, result = _run_and_judge(
        _ideas_by_id()["PLAYBOOK-prompt_injection"], tmp_path)
    # 2 scripted attacker turns + 2 victim replies.
    assert len([m for m in result.transcript if m.role == "attacker"]) == 2
    assert any(mock_victim.PLANTED_SYSTEM_PROMPT in m.content
               for m in result.transcript)


def test_memory_poisoning_playbook_runs_all_turns(tmp_path):
    """The multi-turn memory playbook replays every scripted turn."""
    _, result = _run_and_judge(
        _ideas_by_id()["PLAYBOOK-memory_poisoning"], tmp_path)
    assert len([m for m in result.transcript if m.role == "attacker"]) == 3
    assert result.termination_reason == "idea_completed"
