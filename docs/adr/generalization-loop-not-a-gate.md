# ADR: The patch generalization loop is a post-verification loop, not a seventh PatchVerifier gate

**Status:** Accepted
**Date:** 2026-05-16
**Spec:** `docs/superpowers/specs/2026-05-15-patch-generalization-loop-design.md` §5, §17

## Context

After blue verifies a patch, the patch is proven to block the *literal*
recorded attack and (via gate 1b) a fixed set of mutated variants. It is not
proven to block the *family* of attacks the finding represents: a verified
patch could still be bypassed by a paraphrase, a re-framing, or a multi-turn
re-split of the same attack.

Closing that gap requires mutating the original attack with the twelve
deterministic `red_team/mutations.py` operators, replaying every variant
against the patched victim, and — when a variant bypasses — bouncing the
bypass back to the patch generator and re-verifying, across a bounded number
of rounds.

The question this ADR settles: should that work be a seventh
`PatchVerifier` gate, or a separate post-verification loop?

## Decision

Patch generalization is implemented as `purple_team/generalization_loop.py`,
a post-verification loop that runs **after** `PatchVerifier.verify()` returns
an approved outcome — not as a gate inside `verify()`.

## Rationale

Three properties of a `PatchVerifier` gate make it the wrong shape for
generalization:

1. **Granularity.** A gate is a synchronous pass/fail predicate over one
   candidate patch inside a single `verify()` call. Generalization is an
   *iterative* process: each round may produce a new re-patch candidate,
   re-run the full verifier, and start another round. An iterative,
   multi-candidate, multi-round process cannot be expressed as one
   pass/fail predicate without smuggling a loop — and a re-entrant
   `PatchGenerator` call — inside a verifier gate.

2. **Ownership.** The six verifier gates are blue-team-owned and run
   synchronously inside `verify()`. The generalization loop is
   purple-owned: it composes red-team mutation, the blue `PatchGenerator`,
   and the blue `PatchVerifier` from the outside. Putting it inside
   `verify()` would invert that ownership and couple a purple concern into
   the blue verifier's internals.

3. **Reuse.** Because the loop sits outside the gate set, each round
   re-invokes the **unmodified** `PatchVerifier.verify()` and the
   `PatchedReplayFactory` on every re-patch candidate. The verifier's
   hardening fidelity — all six gates, including gate 1b mutation
   robustness and gate 7 detection — is inherited for free, with no risk of
   the loop weakening or diverging from the verifier's notion of "blocked."
   A gate-internal implementation would have to re-implement or bypass that
   path.

## Consequences

- The loop is additive. With `purple.generalization.enabled: false` the blue
  pipeline behaves exactly as it did before: the loop never runs and
  `_on_patch_approved` is the only finalization path.
- A verified patch now resolves to one of two terminal states —
  `GENERALIZED` (no variant bypassed within the round budget) or
  `UNCONVERGED` (a bypass survived budget exhaustion, or no re-patch passed
  the gates). "Unvalidated" is no longer a resting state.
- An `UNCONVERGED` patch is retained (it still blocks the literal finding)
  but the zone is **not** marked fixed: no coverage reset, and the patch is
  routed to the approval service for mandatory human review.
- Verifier hardening and generalization evolve independently: a new verifier
  gate is picked up by every generalization round automatically, and a new
  mutation operator is picked up by the loop without touching `verify()`.
- The boundary is fixed: generalization will not be re-litigated as a
  seventh gate.
