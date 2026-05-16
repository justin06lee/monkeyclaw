# Zone ↔ MITRE ATLAS / OWASP LLM mapping

MonkeyClaw partitions the NemoClaw attack surface into **18 zones**. This
document maps each zone to the MITRE ATLAS techniques and OWASP LLM
Top 10 categories it exercises, so an outsider can map MonkeyClaw's
coverage onto a recognised adversarial-ML taxonomy.

> **The YAML is the authority.** `red_team/corpora/zone_atlas_mapping.yaml`
> is the human-authored, reviewed source of truth; this document is
> rendered from it together with `atlas_v5.4.0.yaml` and
> `owasp_llm_top10.yaml`. Corpus version: **`atlas-5.4.0+owasp-2025`**
> (see `red_team/corpora/corpus_meta.yaml`).

A green technique-coverage cell means MonkeyClaw has exercised a
technique the broader agent-security community recognises as real.

## Reference vocabulary

**MITRE ATLAS** (v5.4.0) — the Adversarial Threat Landscape for
Artificial-Intelligence Systems: a knowledge base of adversary tactics
and techniques against ML-enabled systems. Technique IDs are `AML.TNNNN`;
dotted IDs (`AML.T0051.001`) are sub-techniques.

**OWASP LLM Top 10** (2025 edition) — the ten most critical security
risks for LLM applications, `LLM01`–`LLM10`.

## Zone mapping

| Zone | ATLAS techniques | OWASP categories |
|------|------------------|------------------|
| PROMPT-INJ | AML.T0051 (LLM Prompt Injection), AML.T0051.000 (LLM Prompt Injection: Direct), AML.T0051.001 (LLM Prompt Injection: Indirect) | LLM01 (Prompt Injection) |
| SOCIAL-ENG | AML.T0077 (LLM Multi-Turn Manipulation) | LLM09 (Misinformation) |
| SBX-FS | AML.T0072 (Command and Scripting Interpreter) | LLM06 (Excessive Agency) |
| SBX-NET | AML.T0024 (Exfiltration via ML Inference API), AML.T0072 (Command and Scripting Interpreter) | LLM02 (Sensitive Information Disclosure) |
| SBX-PROC | AML.T0072 (Command and Scripting Interpreter) | LLM06 (Excessive Agency) |
| SBX-IPC | AML.T0072 (Command and Scripting Interpreter) | LLM06 (Excessive Agency) |
| PRV-ROUTE | AML.T0024 (Exfiltration via ML Inference API) | LLM02 (Sensitive Information Disclosure) |
| PRV-LEAK | AML.T0057 (LLM Data Leakage) | LLM02 (Sensitive Information Disclosure), LLM07 (System Prompt Leakage) |
| PERM-MODEL | AML.T0073 (Privilege Escalation), AML.T0074 (Defense Evasion) | LLM06 (Excessive Agency) |
| PERM-RUNTIME | AML.T0073 (Privilege Escalation), AML.T0074 (Defense Evasion) | LLM06 (Excessive Agency) |
| SKILL-INSTALL | AML.T0010 (ML Supply Chain Compromise), AML.T0053 (LLM Plugin Compromise) | LLM03 (Supply Chain) |
| SKILL-EXEC | AML.T0053 (LLM Plugin Compromise) | LLM06 (Excessive Agency) |
| SKILL-SUPPLY | AML.T0010 (ML Supply Chain Compromise) | LLM03 (Supply Chain) |
| MEM-STATE | AML.T0070 (Agent Memory Poisoning) | LLM08 (Vector and Embedding Weaknesses) |
| MEM-SHARED | AML.T0070 (Agent Memory Poisoning) | LLM08 (Vector and Embedding Weaknesses) |
| INF-ROUTE | AML.T0075 (Model Serving Interception) | LLM04 (Data and Model Poisoning) |
| INF-LOCAL | AML.T0075 (Model Serving Interception) | LLM04 (Data and Model Poisoning) |
| AGENT-COMM | AML.T0076 (Agent Impersonation) | LLM08 (Vector and Embedding Weaknesses) |

## Refreshing the corpus

The vendored corpus is regenerated only by the offline, human-run
`scripts/refresh_taxonomy_corpus.py`. A refresh never touches
`zone_atlas_mapping.yaml` automatically — a newly-vendored technique is
flagged *unmapped* so a human extends the mapping (and this document)
deliberately.
