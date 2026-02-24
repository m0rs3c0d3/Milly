# NIST AI RMF Alignment — Milly

This document maps Milly's design and implementation to the four functions of the
[NIST AI Risk Management Framework (AI RMF 1.0)](https://airc.nist.gov/Home).

Milly is a personal, single-user, local AI assistant. The scope and mitigations
are calibrated to that context — not to production APIs or multi-user deployments.

---

## GOVERN

*Policies, accountability, and organizational culture for responsible AI use.*

| Subcategory | Implementation |
|---|---|
| GOVERN 1.1 — Policies established | `config.yaml` defines all operating parameters. `THREAT_MODEL.md` documents scope, assumptions, and explicit non-goals. |
| GOVERN 1.2 — Accountability assigned | Single-user tool; the operator is the user. All decisions are local and auditable. |
| GOVERN 1.3 — Organizational risks identified | Threat model documents in-scope and out-of-scope risks explicitly. Pretending coverage that doesn't exist is a documented non-goal. |
| GOVERN 2.2 — Transparency of AI decisions | Guardian's flagging is surfaced to the user in real time. Audit log records all security events. No silent failures. |
| GOVERN 4.1 — Organizational teams informed | N/A (single user). Equivalent: session audit log available via `/audit`. |
| GOVERN 6.1 — Policies applied to third parties | Ollama is the only external dependency for inference. It runs locally; no data leaves the machine. |

---

## MAP

*Risk identification: what could go wrong and how.*

| Subcategory | Implementation |
|---|---|
| MAP 1.1 — Context established | Documented in `THREAT_MODEL.md`. Single-user, offline, personal assistant. |
| MAP 1.5 — Organizational risk tolerance defined | Injection attempts are flagged and logged but do not crash the session (continuity). Hard-blocking is reserved for length-based DoS only. |
| MAP 2.1 — Scientific findings reviewed | Guardian's pattern bank is based on OWASP LLM Top 10 and documented injection research. |
| MAP 2.2 — Scientific uncertainty acknowledged | Pattern-matching is not exhaustive. Novel injection techniques may not be caught. This is documented. |
| MAP 3.1 — AI risks identified | Input risks: prompt injection (direct and indirect), oversized inputs, encoding evasion. Output risks: ANSI injection, terminal escape sequences. |
| MAP 3.5 — Costs and benefits reviewed | TF-IDF chosen over embedding models: no model download required, no GPU needed, deterministic, auditable. Quality trade-off accepted for local use. |
| MAP 5.1 — Likelihood and magnitude evaluated | Indirect injection via documents is a realistic attack vector; mitigated by `[UNTRUSTED DOCUMENT CONTENT]` boundary and pre-ingestion scanning. |

---

## MEASURE

*Quantifying and monitoring risks.*

| Subcategory | Implementation |
|---|---|
| MEASURE 1.1 — Metrics established | Injection detection rate per session (via audit log). Input block rate. Inference error rate. |
| MEASURE 2.2 — Evaluation of AI system | `guardian.py` is independently testable. `GuardianResult` provides structured output for automated checks. |
| MEASURE 2.5 — AI system monitored | Every security event written to `logs/security.log` as structured JSON. Reviewable with `/audit`. |
| MEASURE 2.6 — Bias and fairness | Out of scope for personal local assistant. Documented as non-goal. |
| MEASURE 2.9 — Privacy risk evaluated | Content is never written to the audit log — only SHA-256 input hashes. History files are 0o600. HMAC key is 0o600. |
| MEASURE 3.1 — Metrics monitored over time | Audit log is append-only JSON. Session-scoped summaries available. Full log reviewable offline. |
| MEASURE 4.1 — Risk response metrics defined | Injection flagged → logged → user warned. Input blocked → logged → user notified with reason. |

---

## MANAGE

*Acting on identified risks.*

| Subcategory | Implementation |
|---|---|
| MANAGE 1.1 — Response plans established | Guardian mitigations run on every input. No manual intervention required. |
| MANAGE 1.3 — Responses prioritized | Hard block (length DoS) → silent truncation never used, input rejected. Soft flag (injection) → proceed with logging, surface warning. |
| MANAGE 2.2 — Mechanisms for AI risk response | Guardian is modular and independently importable. Pattern bank is documented and extensible. |
| MANAGE 2.4 — Risk response verified | HMAC verification on every session load. Tampered or corrupted history files are refused, not silently loaded. |
| MANAGE 3.1 — Residual risks documented | `THREAT_MODEL.md` — Out of scope section. Model weight integrity, supply chain, multi-user, network exposure are explicitly not covered. |
| MANAGE 3.2 — AI risks communicated | Flagged inputs surface a visible warning to the user after the model response. Blocked inputs surface the block reason immediately. |
| MANAGE 4.1 — Risk treatments applied | Symlink rejection (RAG path traversal). Character sanitization (terminal injection). Document injection scanning. Session isolation (namespaced history). |

---

## Summary Table

| Function | Coverage |
|---|---|
| GOVERN | Threat model, documented scope, explicit non-goals, config-driven policy |
| MAP | Input/output risk identification, RAG trust boundary, OWASP LLM Top 10 |
| MEASURE | Audit log, session summaries, input hashing (never content), anomaly detection |
| MANAGE | Guardian mitigations, memory integrity, session isolation, document sanitization |

---

*This document reflects Milly's design as a personal, single-user, local tool.
It is not a claim of enterprise or production compliance.*
