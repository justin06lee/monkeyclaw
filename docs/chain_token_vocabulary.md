# Capability-Token Vocabulary

Companion reference for the cross-zone attack chaining capability tokens.

A **capability token** is a short controlled string naming what a `ChainStep`
yields (`produces`) or needs (`requires`). The chain composer
(`red_team/chain_composer.py`) uses them to enforce the **chain invariant**:
every token a step requires must be produced by an earlier step. The
vocabulary is deliberately coarse — it expresses *dependency between steps*,
not a full attack ontology.

- Authoritative token list: `red_team/chain_tokens.py` → `CAPABILITY_TOKENS`.
- Per-zone produce/require defaults: `red_team/chain_composer.py` →
  `_ZONE_TOKEN_MAP`.

The "Produced by" / "Required by" columns below are the zones whose
`_ZONE_TOKEN_MAP` entry produces or requires the token. A zone not listed in
the map falls back to `_DEFAULT_TOKENS` (`recon.target_identified`, no
requirement).

| Token | Meaning | Produced by (zones) | Required by (zones) |
|---|---|---|---|
| `foothold.instruction_executed` | An attacker-controlled instruction is now running in the victim. | PROMPT-INJ, SOCIAL-ENG | PRV-LEAK, PRV-ROUTE, SBX-FS, SBX-PROC, SBX-IPC, PERM-MODEL, PERM-RUNTIME, SKILL-INSTALL, SKILL-EXEC, MEM-STATE, MEM-SHARED, INF-ROUTE, AGENT-COMM |
| `foothold.context_poisoned` | The victim's context has been seeded with attacker content. | PROMPT-INJ | — |
| `recon.target_identified` | The attacker has identified an exploitable target. | INF-LOCAL | — |
| `recon.path_discovered` | The attacker has discovered an exploitable path. | AGENT-COMM | — |
| `access.file_read` | The attacker reached and read a file resource. | SBX-FS | — |
| `access.tool_invoked` | The attacker caused a tool to be invoked. | SBX-PROC, SBX-IPC, SKILL-EXEC | — |
| `access.permission_escalated` | The attacker raised its permission level. | PERM-MODEL, PERM-RUNTIME | — |
| `secret.value_captured` | A sensitive value is in the attacker's hands. | PRV-LEAK | SBX-NET |
| `secret.credential_captured` | A credential is in the attacker's hands. | SBX-FS | — |
| `egress.channel_open` | A channel out of the sandbox is usable. | SBX-NET | — |
| `egress.data_exfiltrated` | Data has left the sandbox. | SBX-NET | — |
| `persistence.memory_written` | The attacker wrote durable state that survives a reset. | MEM-STATE, MEM-SHARED | — |
| `persistence.skill_installed` | The attacker installed a skill that survives a reset. | SKILL-INSTALL, SKILL-SUPPLY | — |
| `control.policy_modified` | A policy boundary has been moved. | PERM-MODEL | — |
| `control.routing_subverted` | A routing/permission boundary has been subverted. | PRV-ROUTE, INF-ROUTE | — |

## Notes

- The first step in a composed chain (in execution order) has its `requires`
  cleared — it has no earlier step to depend on.
- An unknown token raises `ValueError` from `chain_tokens.validate_tokens`;
  the composer treats that as a drop-with-logged-reason, never a crash.
- `requires` / `produces` are lists, so a future branching-chain extension
  needs no shape change.
