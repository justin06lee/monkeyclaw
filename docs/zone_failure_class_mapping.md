# Zone ↔ failure-class mapping

MonkeyClaw partitions the NemoClaw attack surface into **18 zones**. This
document maps each zone to the failure classes, controls, and detections
from the General Analysis whitepaper *"How to secure coding agents: a
comprehensive guide"* (the "Securing Coding Agents" reference).

Mapping each zone to a recognized failure class keeps MonkeyClaw's
coverage honest: a green zone means MonkeyClaw has exercised a class of
failure that the broader agent-security literature considers real.

## Reference vocabulary

**Failure classes** (whitepaper §3.2): secrets exposure, command
execution, MCP tool poisoning, approval fatigue, settings drift, browser
and desktop expansion, cloud execution drift, audit gaps.

**Control surfaces** (§1.2): filesystem sandbox & path scope,
sensitive-file exclusion, command approval, native tool hooks, MCP
governance, network egress, managed enterprise policy, audit & telemetry,
review & merge gates.

**Detection catalog** (§23.2): denied secret read, unexpected egress,
approval spike, MCP schema drift, control-plane edit, package-install
script egress, shell escape pattern, repeated denied tool, OAuth scope
expansion, browser profile access, unusual file volume, external
recipient write.

## Zone map

| Zone | MonkeyClaw scope | Whitepaper failure class | Primary controls | Detection signal |
|------|------------------|--------------------------|------------------|------------------|
| `SBX-FS` | Sandbox filesystem boundaries — escapes, symlink games, mounts | Secrets exposure; command execution | Filesystem sandbox & path scope; deny rules | Denied secret read; unusual file volume |
| `SBX-NET` | Outbound network policy — exfiltration, DNS smuggling | Command execution (exfiltration) | Network egress; proxy allowlist | Unexpected egress; shell escape pattern |
| `SBX-PROC` | Process boundary — child processes, syscalls, seccomp | Command execution | Sandboxed shell; command approval | Shell escape pattern; repeated denied tool |
| `SBX-IPC` | IPC channels — sockets, pipes, shared memory escapes | Command execution | Filesystem sandbox; process isolation | Unusual file volume |
| `PRV-ROUTE` | Privacy router — local vs. cloud routing of PII | Audit gaps; cloud execution drift | Network egress; managed enterprise policy | External recipient write |
| `PRV-LEAK` | Direct PII / secret leaks via responses, logs, tools | Secrets exposure | Sensitive-file exclusion; audit & telemetry | Denied secret read; external recipient write |
| `PERM-MODEL` | Policy-model integrity — capability grants, role boundaries | Settings drift | Managed enterprise policy; review & merge gates | Control-plane edit |
| `PERM-RUNTIME` | Runtime enforcement — TOCTOU, race conditions | Settings drift; audit gaps | Native tool hooks; command approval | Control-plane edit; approval spike |
| `SKILL-INSTALL` | Install pipeline — manifest validation, signatures | MCP tool poisoning (supply chain) | MCP governance; command approval | Package-install script egress |
| `SKILL-EXEC` | Skill runtime — sandboxing of skill code, capability binding | Command execution | Native tool hooks; sandboxed shell | Shell escape pattern |
| `SKILL-SUPPLY` | Marketplace / source integrity, malicious skills | MCP tool poisoning | MCP governance; schema scanning | MCP schema drift |
| `MEM-STATE` | Long-term agent memory — poisoning, false-fact injection | Settings drift (state) | Audit & telemetry; managed policy | Control-plane edit |
| `MEM-SHARED` | Cross-agent / cross-session memory bleed | Audit gaps | Managed enterprise policy | Unusual file volume |
| `INF-ROUTE` | Routing-decision integrity, MITM between agent and model | Cloud execution drift | Network egress; managed policy | Unexpected egress |
| `INF-LOCAL` | Local Nemotron inference — model swap, prompt leak | Secrets exposure (prompt) | Sensitive-file exclusion; audit & telemetry | Denied secret read |
| `AGENT-COMM` | Agent-to-agent messaging — spoofing, replay | Audit gaps | Audit & telemetry; review gates | Repeated denied tool |
| `PROMPT-INJ` | Prompt injection via inputs, documents, tools | MCP tool poisoning; command execution | Trusted/untrusted data separation; hooks | Shell escape pattern; unexpected egress |
| `SOCIAL-ENG` | Multi-turn manipulation to subvert policy | Approval fatigue | Command approval; deterministic policy | Approval spike |

## How MonkeyClaw uses this map

- **Red team** — ideation prompts for each zone are seeded with the
  matching failure class, so generated attacks resemble recognized
  classes rather than arbitrary noise.
- **Blue team** — the patch verifier's control-plane gate enforces the
  control surfaces above: a patch that loosens filesystem scope,
  suppresses telemetry, or edits MCP/CI config is rejected.
- **Dashboard** — the coverage heatmap is, in effect, a live view of
  which whitepaper failure classes have been exercised against NemoClaw.
- **Planted victims** — `demo/victims/` implements targets with flaws
  drawn from the whitepaper's adversarial corpus (Appendix E) and
  detection catalog (Appendix D), so the demo exercises real, named
  failure classes.
