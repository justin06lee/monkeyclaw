"""Phase 2 — ChainExecutionAgent: ordered, stateful chain execution."""

from __future__ import annotations

from interfaces.types import AttackChain, ChainStep, IdeaObject
from red_team.chain_executor import ChainExecutionAgent
from test.helpers import make_lane_config, make_mock_harness, make_mock_victim


def _chain():
    return AttackChain(
        chain_id="CHAIN-1", cycle_id=1, title="kill chain",
        zones=["PROMPT-INJ", "SBX-FS"], primary_zone="SBX-FS",
        steps=[
            ChainStep(0, "PROMPT-INJ", "foothold", "I0", "get a foothold",
                      [], ["foothold.instruction_executed"], "foothold set"),
            ChainStep(1, "SBX-FS", "read secret", "I1", "read /etc/secret",
                      ["foothold.instruction_executed"],
                      ["secret.credential_captured"], "secret read"),
        ],
        builds_on=["I0", "I1"], estimated_turns=10,
    )


def _idea_with_chain(chain):
    idea = IdeaObject(
        idea_id=chain.chain_id, cycle_id=1, zone_id=chain.primary_zone,
        source_mode="creative", title=chain.title, approach="",
        success_criteria="", estimated_turns=chain.estimated_turns,
        novelty_notes="",
    )
    idea.chain = chain
    return idea


def test_chain_runs_all_steps_when_each_lands():
    agent = ChainExecutionAgent()
    chain = _chain()
    harness = make_mock_harness()
    agent.execute(_idea_with_chain(chain), make_mock_victim(landing=True),
                  harness, make_lane_config())
    trace = harness.lane_result().chain_trace
    assert [r.step_index for r in trace] == [0, 1]
    assert all(r.landed for r in trace)
    assert harness.lane_result().termination == "completed"


def test_chain_carries_token_forward_between_steps():
    agent = ChainExecutionAgent()
    chain = _chain()
    harness = make_mock_harness()
    agent.execute(_idea_with_chain(chain), make_mock_victim(landing=True),
                  harness, make_lane_config())
    trace = harness.lane_result().chain_trace
    # Step 1 only runs because step 0 produced the token it requires.
    assert "foothold.instruction_executed" in trace[0].produced_tokens


def test_chain_stops_chain_broken_when_a_step_cannot_produce_its_token():
    agent = ChainExecutionAgent()
    chain = _chain()
    harness = make_mock_harness()
    # The mock victim refuses step 0, so the foothold token is never produced.
    agent.execute(_idea_with_chain(chain), make_mock_victim(landing=False),
                  harness, make_lane_config())
    result = harness.lane_result()
    assert result.termination == "chain_broken"
    trace = result.chain_trace
    assert trace[0].landed is False
    # Step 1 never ran — its precondition was unmet.
    assert len(trace) == 1


def test_execution_agent_delegates_to_chain_agent_when_idea_has_chain():
    from red_team.execution_agent import ExecutionAgent

    chain = _chain()
    idea = _idea_with_chain(chain)
    harness = make_mock_harness()
    # ExecutionAgent.execute must route a chain-carrying idea to the
    # ChainExecutionAgent — mirroring the idea.playbook sniff.
    ExecutionAgent().execute(idea, make_mock_victim(landing=True),
                             harness, make_lane_config())
    assert harness.lane_result().chain_trace  # the chain agent ran


def test_execution_agent_runs_plain_idea_unchanged():
    from interfaces.types import IdeaObject
    from red_team.execution_agent import ExecutionAgent

    plain = IdeaObject(
        idea_id="I-PLAIN", cycle_id=1, zone_id="SBX-FS",
        source_mode="creative", title="plain", approach="do it",
        success_criteria="sc", estimated_turns=4, novelty_notes="")
    harness = make_mock_harness()
    ExecutionAgent().execute(plain, make_mock_victim(landing=True),
                             harness, make_lane_config())
    assert harness.lane_result().chain_trace == []  # no chain ran
