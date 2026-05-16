"""Chain MCP persistence + routing."""

from __future__ import annotations

from infra.mock_mcp import MockMCP
from interfaces.types import (
    AttackChain,
    ChainFinding,
    ChainStep,
    ChainStepResult,
)


def _chain(chain_id="CHAIN-1"):
    return AttackChain(
        chain_id=chain_id, cycle_id=1, title="kill chain",
        zones=["PROMPT-INJ", "PRV-LEAK"], primary_zone="PRV-LEAK",
        steps=[
            ChainStep(0, "PROMPT-INJ", "foothold", "I0", "a0",
                      [], ["foothold.instruction_executed"], "s0"),
            ChainStep(1, "PRV-LEAK", "read secret", "I1", "a1",
                      ["foothold.instruction_executed"],
                      ["secret.value_captured"], "s1"),
        ],
        builds_on=["I0", "I1"], estimated_turns=12, rationale="why",
    )


def test_log_and_get_attack_chain_round_trip():
    mcp = MockMCP()
    mcp.log_attack_chain(_chain())
    chains = mcp.get_attack_chains(cycle_id=1)
    assert len(chains) == 1
    assert chains[0].chain_id == "CHAIN-1"
    assert chains[0].zones == ["PROMPT-INJ", "PRV-LEAK"]
    assert len(chains[0].steps) == 2


def test_log_chain_finding_and_step_results():
    mcp = MockMCP()
    mcp.log_attack_chain(_chain())
    cf = ChainFinding(
        chain_finding_id="CF-1", chain_id="CHAIN-1", cycle_id=1,
        zones_traversed=["PROMPT-INJ", "PRV-LEAK"], terminal_zone="PRV-LEAK",
        severity="high", verdict="confirmed", landed_steps=[0, 1],
    )
    cf_id = mcp.log_chain_finding(cf)
    assert cf_id == "CF-1"
    mcp.log_chain_step_results([
        ChainStepResult("CHAIN-1", 0, "PROMPT-INJ", True,
                        ["foothold.instruction_executed"], (0, 3), 6.0),
        ChainStepResult("CHAIN-1", 1, "PRV-LEAK", True,
                        ["secret.value_captured"], (3, 8), 8.5),
    ])


def test_route_chain_judgment_pushes_one_repro_and_archives_steps():
    from interfaces.types import ChainAttribution, FindingInput
    from red_team.archive import EliteArchive
    from red_team.routing import route_chain_judgment

    mcp = MockMCP()
    chain = _chain()
    mcp.log_attack_chain(chain)
    cf = ChainFinding(
        chain_finding_id="CF-1", chain_id="CHAIN-1", cycle_id=1,
        zones_traversed=["PROMPT-INJ", "PRV-LEAK"], terminal_zone="PRV-LEAK",
        severity="high", verdict="confirmed", landed_steps=[0, 1])
    per_zone = [
        FindingInput(cycle_id=1, idea_id="CHAIN-1", zone_id="PROMPT-INJ",
                     source_mode="chain", idea_summary="s0",
                     verdict="confirmed", tier_caught="programmatic",
                     failure_class="prompt_injection", severity="high",
                     evidence="{}", reusability=0.5, chain_id="CHAIN-1"),
        FindingInput(cycle_id=1, idea_id="CHAIN-1", zone_id="PRV-LEAK",
                     source_mode="chain", idea_summary="s1",
                     verdict="confirmed", tier_caught="programmatic",
                     failure_class="pii_leak", severity="high",
                     evidence="{}", reusability=0.5, chain_id="CHAIN-1"),
    ]
    step_results = [
        ChainStepResult("CHAIN-1", 0, "PROMPT-INJ", True,
                        ["foothold.instruction_executed"], (0, 3), 6.0),
        ChainStepResult("CHAIN-1", 1, "PRV-LEAK", True,
                        ["secret.value_captured"], (3, 8), 8.0),
    ]
    attr = ChainAttribution(
        chain_finding=cf, per_zone_findings=per_zone,
        coverage_deltas={"PROMPT-INJ": 0.03, "PRV-LEAK": 0.05},
        step_results=step_results)
    archive = EliteArchive()
    route_chain_judgment(attr, chain, mcp, archive=archive)

    assert len(mcp.get_repro_queue()) == 1          # one repro push
    assert archive.cell_count() == 2                # every landed step archived
    assert mcp.coverage_for("PRV-LEAK") > 0         # per-zone coverage applied
