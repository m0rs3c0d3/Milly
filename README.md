# Milly

**Your local AI. Nobody else's.**

Milly is a local LLM chatbot with a security layer that actually means something. Runs entirely on your machine via Ollama. Remembers your conversations. Searches your documents. Doesn't phone home. Doesn't trust your input unconditionally.

Unlike basically every other local chatbot, Milly was designed from the ground up with a documented threat model and real mitigations — not a content filter bolted on at the end.

---

## Why This Exists

Most local LLM wrappers are the same project. Pull Ollama, wrap a chat loop, call it done. Some add RAG. A few add a UI. Almost none of them think seriously about prompt injection, document poisoning, history tampering, or what their "secure" label actually covers.

Milly is the answer to that question taken seriously.

---

## What It Does

- **Fully local inference** via [Ollama](https://ollama.com) — model agnostic, swap anything
- **Persistent memory** — HMAC-signed conversation history, tamper-evident
- **RAG** — drop files into `docs/`, Milly references them semantically at query time
- **Streaming** — token-by-token output, no waiting for full completions
- **Guardian layer** — prompt injection detection, input sanitization, output filtering
- **Audit log** — structured JSON security events, input hashes only, never content
- **Session isolation** — conversations are namespaced and independently reviewable
- **NIST AI RMF aligned** — documented in [COMPLIANCE.md](./COMPLIANCE.md)

---

## What It Doesn't Do

- Connect to the internet
- Send anything anywhere
- Let a file in `docs/` override your system prompt
- Trust user input unconditionally
- Pretend the above is hard to implement and nobody bothered

---

## The Guardian Layer

Every input passes through `guardian.py` before it reaches the model. Four checks, in order:

**1. Length enforcement**
Configurable max input length. Oversized inputs are rejected and logged — not silently truncated, not passed through.

**2. Prompt injection detection**
Pattern bank covering OWASP LLM Top 10 injection techniques: instruction override attempts, persona hijacking, role-play escape patterns, indirect injection markers. Flagged inputs are logged with the matching pattern. Milly keeps talking — it doesn't crash or go silent — but the attempt is on record.

**3. Character sanitization**
Null bytes, Unicode control characters, RTL override characters, and terminal escape sequences stripped before anything reaches the model or gets written to memory.

**4. Output filtering**
Model responses are sanitized before display. ANSI escape sequences stripped. Responses that structurally contradict the system prompt's stated constraints are flagged.

Guardian is a standalone module. You can use it independently of the rest of Milly.

---

## Memory Integrity

Conversation history is stored locally as HMAC-signed JSON. On every load, the signature is verified. If it fails — file was modified, corrupted, or tampered with — Milly refuses to load it and tells you why.

File permissions are set explicitly on creation (`0o600`). Your conversation history is not world-readable.

User messages are only written to history after the model responds successfully. No partial state from failed or interrupted requests.

---

## RAG Trust Boundaries

Documents in `docs/` are reference material. They are not instructions.

All retrieved context is injected into the model's context window under an explicit `[UNTRUSTED DOCUMENT CONTENT]` boundary, separate from the system prompt. The model is told explicitly what is instruction and what is reference.

Before ingestion, every document is:
- Checked for symlinks (rejected if they resolve outside `docs/`)
- Checked for size (configurable limit, default 10MB)
- Scanned for injection patterns by Guardian
- Assigned a collision-safe ID based on full path hash, not filename

---

## Audit Log

Every security event writes a structured JSON entry to `logs/security.log`:

```json
{
  "timestamp": "2026-02-23T14:32:01.442Z",
  "session_id": "a3f9c1",
  "event": "injection_attempt",
  "pattern": "persona_override",
  "input_hash": "sha256:e3b0c44...",
  "disposition": "flagged",
  "model": "llama3.2"
}
```

Content is never logged. Hashes are. You can audit what happened without the log itself becoming a liability.

---

## NIST AI RMF Alignment

See [COMPLIANCE.md](./COMPLIANCE.md) for the full mapping. Short version:

| Function | Coverage |
|---|---|
| GOVERN | Threat model, documented scope, explicit non-goals |
| MAP | Input/output risk identification, RAG trust boundary |
| MEASURE | Audit log, anomaly detection, session review |
| MANAGE | Guardian mitigations, memory integrity, session isolation |

---

## Threat Model

**In scope:**
- Prompt injection via user input
- Indirect prompt injection via ingested documents
- Conversation history tampering
- Terminal output manipulation via model responses
- Oversized input as denial-of-service vector

**Out of scope (explicitly):**
- Multi-user environments
- Network exposure
- Model weight integrity
- Supply chain attacks on dependencies

Milly is a personal, single-user, local tool. It is not a production API. The threat model reflects that honestly.

---

## Setup

### Requirements
- Python 3.11+
- [Ollama](https://ollama.com) running locally
- 8GB RAM minimum (16GB recommended for 13B+ models)

### Install

```bash
git clone https://github.com/m0rs3c0d3/milly
cd milly
pip install -r requirements.txt
```

### Pull a model

```bash
ollama pull llama3.2       # fast, good default
ollama pull mistral        # strong reasoning
ollama pull gemma3         # lightweight
```

### Run

```bash
python main.py
```

---

## Configuration

Everything lives in `config.yaml`. Key settings:

```yaml
model: "llama3.2"          # any Ollama model
temperature: 0.7

guardian:
  max_input_length: 4000
  injection_detection: true
  output_sanitization: true
  log_detections: true

memory:
  enabled: true
  max_history: 50

rag:
  enabled: true
  max_file_size_mb: 10
  scan_for_injection: true
```

---

## Commands

```
/help              Show commands
/clear             Clear session history
/ingest            Re-index docs/ folder
/status            Model, memory, RAG, Guardian stats
/audit             Print security event summary for this session
/session new       Start a new named session
/session list      List saved sessions
/session load NAME Load a previous session
/model NAME        Switch model live
/exit              Quit
```

---

## Project Structure

```
milly/
├── main.py            # CLI entry point
├── chat.py            # Conversation engine
├── guardian.py        # Security layer (standalone importable)
├── rag.py             # Document ingestion + retrieval
├── memory.py          # HMAC-signed persistent history
├── audit.py           # Structured security event logging
├── config.yaml        # All configuration
├── docs/              # Drop your documents here
├── memory/            # Auto-created: signed history + vector DB
├── logs/              # Auto-created: security audit log
├── COMPLIANCE.md      # NIST AI RMF mapping
└── THREAT_MODEL.md    # Full threat model documentation
```

---

## Using Guardian Standalone

Guardian is designed to be imported into any Ollama-based project:

```python
from guardian import Guardian

g = Guardian(config)

result = g.check(user_input)

if result.blocked:
    print(f"Blocked: {result.reason}")
elif result.flagged:
    print(f"Flagged ({result.pattern}): proceeding with log entry")
    sanitized = result.sanitized_input
```

---

## License

MIT. Use it, fork it, build on it.

---

## Contributing

Guardian's pattern bank is the highest-leverage place to contribute. If you find an injection technique it doesn't catch, open an issue with a reproduction case. No need to be polite about it — specificity is more useful than tact here.

---

*Milly doesn't promise to be unbreakable. It promises to be honest about what it covers and why.*
