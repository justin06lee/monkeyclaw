"""Cross-zone chaining: stateful, ordered execution of an AttackChain.

ChainExecutionAgent walks a chain's steps in order. Each step runs a bounded
deep-dive sub-conversation focused on that step's objective and zone, reusing
the execution_agent turn loop and the MonitoringHarness. After a step the
agent checks the step's success_signal against harness evidence: a landed
step's produced tokens enter the chain's live capability set and execution
advances; a step that fails to produce a token a later step requires stops
the chain early with termination=chain_broken. Captured outputs are carried
verbatim into the next step's context — this is what makes it a chain.
"""

from __future__ import annotations

import logging

from interfaces.types import AttackChain, ChainStep, ChainStepResult

from red_team.execution_agent import ExecutionAgent

LOG = logging.getLogger("monkeyclaw.red.chain_executor")


def _lane_result(harness):
    """Return the harness's assembled LaneResult, real or mock."""
    if hasattr(harness, "lane_result"):
        return harness.lane_result()
    return harness.result()


class ChainExecutionAgent:
    """Runs an AttackChain against one victim as an ordered, stateful unit."""

    def __init__(self, base_agent: ExecutionAgent | None = None) -> None:
        # Reuses the single-zone deep-dive turn loop for each step.
        self._base = base_agent or ExecutionAgent()

    def execute(self, idea, victim, harness, lane_cfg) -> None:
        """Execute idea.chain step-by-step. Same signature as
        ExecutionAgent.execute — selected by the chain attribute sniff."""
        chain: AttackChain = idea.chain
        available: set[str] = set()
        carried_context: list[str] = []
        trace: list[ChainStepResult] = []
        turn_cursor = 0
        termination = "completed"

        for step in chain.steps:
            if not set(step.requires) <= available:
                LOG.info("chain %s: step %d precondition unmet (%s) — broken",
                         chain.chain_id, step.step_index, step.requires)
                termination = "chain_broken"
                break
            landed, produced, span, progress = self._run_step(
                step, chain, victim, harness, lane_cfg,
                carried_context, turn_cursor)
            turn_cursor = span[1]
            trace.append(ChainStepResult(
                chain_id=chain.chain_id, step_index=step.step_index,
                zone_id=step.zone_id, landed=landed,
                produced_tokens=produced, turn_span=span,
                progress_score=progress))
            if landed:
                available |= set(produced)
                carried_context.append(
                    f"[step {step.step_index} / {step.zone_id}] "
                    f"produced: {', '.join(produced)}")
            else:
                LOG.info("chain %s: step %d did not land — broken",
                         chain.chain_id, step.step_index)
                termination = "chain_broken"
                break

        result = _lane_result(harness)
        result.chain_trace = trace
        result.termination_reason = termination
        # Free-text alias so chain consumers can read either name.
        try:
            result.termination = termination
        except (AttributeError, TypeError):
            pass
        LOG.info("chain %s finished: termination=%s landed=%d/%d",
                 chain.chain_id, termination,
                 sum(1 for r in trace if r.landed), len(chain.steps))

    # ------------------------------------------------------------------
    def _run_step(
        self, step: ChainStep, chain: AttackChain, victim, harness, lane_cfg,
        carried_context: list[str], turn_cursor: int,
    ) -> tuple[bool, list[str], tuple[int, int], float]:
        """Run one step's bounded sub-conversation; decide if it landed.

        A step lands when the harness records a side-effect matching the
        step's zone after the sub-conversation. Returns
        (landed, produced_tokens, turn_span, progress_score).
        """
        self._base.run_chain_step(
            step=step, victim=victim, harness=harness, lane_cfg=lane_cfg,
            carried_context="\n".join(carried_context))
        landed = harness.has_side_effect_for_zone(step.zone_id)
        turn_end = (harness.turn_count() if hasattr(harness, "turn_count")
                    else turn_cursor + step.step_index + 1)
        span = (turn_cursor, turn_end)
        progress = _step_progress(harness) if landed else 0.0
        produced = list(step.produces) if landed else []
        return (landed, produced, span, progress)


def _step_progress(harness) -> float:
    """A coarse progress score for a landed step, best-effort."""
    try:
        from red_team.progress import score_progress, search_score
        return float(search_score(score_progress(_lane_result(harness))))
    except Exception:  # noqa: BLE001
        return 5.0


__all__ = ["ChainExecutionAgent"]
