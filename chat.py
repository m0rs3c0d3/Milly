"""
chat.py — Conversation engine for Milly.

Wires together Guardian → RAG → Ollama → Memory → AuditLog.

Usage:
    engine = ChatEngine(config, guardian, memory, audit, rag)

    # Stream a response
    try:
        for token in engine.chat("Hello"):
            print(token, end="", flush=True)
    except InputBlockedError as e:
        print(f"Blocked: {e}")

After each call, engine.last_guard_result holds the GuardianResult
(useful to surface flagged-but-not-blocked warnings to the user).
"""

import uuid
from typing import Generator, Optional

import ollama as _ollama

from audit import AuditLog
from guardian import Guardian, GuardianResult
from memory import Memory
from rag import RAG


class InputBlockedError(Exception):
    """Raised when Guardian hard-blocks an input."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class ChatEngine:
    def __init__(
        self,
        config: dict,
        guardian: Guardian,
        memory: Memory,
        audit: AuditLog,
        rag: RAG,
    ):
        self.config = config
        self.guardian = guardian
        self.memory = memory
        self.audit = audit
        self.rag = rag

        self.model: str = config.get("model", "llama3.2")
        self.temperature: float = float(config.get("temperature", 0.7))
        self.system_prompt: str = config.get("system_prompt", "You are Milly, a helpful local AI assistant.")
        self.rag_enabled: bool = config.get("rag", {}).get("enabled", True)

        host: str = config.get("ollama_host", "http://localhost:11434")
        self._client = _ollama.Client(host=host)

        self.session_id: str = self._new_session_id()
        self.history: list[dict] = []
        self.last_guard_result: Optional[GuardianResult] = None

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    @staticmethod
    def _new_session_id() -> str:
        return uuid.uuid4().hex[:6]

    def new_session(self, name: Optional[str] = None) -> str:
        self.session_id = name or self._new_session_id()
        self.history = []
        self.audit.log(self.session_id, "session_start", model=self.model)
        return self.session_id

    def load_session(self, session_id: str) -> None:
        """Load an existing session. Raises MemoryIntegrityError on tamper."""
        self.history = self.memory.load(session_id)
        self.session_id = session_id
        self.audit.log(self.session_id, "session_load", model=self.model)

    def clear_history(self) -> None:
        self.history = self.memory.clear(self.session_id)
        self.audit.log(self.session_id, "history_clear", model=self.model)

    def switch_model(self, model_name: str) -> None:
        old = self.model
        self.model = model_name
        self.audit.log(
            self.session_id, "model_switch", model=model_name, previous=old
        )

    # ------------------------------------------------------------------
    # Core chat
    # ------------------------------------------------------------------

    def chat(self, raw_input: str) -> Generator[str, None, None]:
        """
        Process raw_input through the security + inference pipeline.

        Yields streamed response tokens.
        Raises InputBlockedError if Guardian hard-blocks the input.
        Stores last_guard_result for the caller to inspect.
        """
        # --- Guardian check ---
        guard = self.guardian.check(raw_input)
        self.last_guard_result = guard

        if guard.blocked:
            self.audit.log(
                self.session_id,
                "input_blocked",
                model=self.model,
                reason=guard.reason,
                input_hash=guard.input_hash,
                disposition="blocked",
            )
            raise InputBlockedError(guard.reason)

        if guard.flagged and self.config.get("guardian", {}).get("log_detections", True):
            self.audit.log(
                self.session_id,
                "injection_attempt",
                model=self.model,
                pattern=guard.pattern,
                input_hash=guard.input_hash,
                disposition="flagged",
            )

        user_input = guard.sanitized_input

        # --- RAG retrieval ---
        rag_context = ""
        if self.rag_enabled and self.rag.doc_count > 0:
            docs = self.rag.query(user_input)
            if docs:
                rag_context = self.rag.format_context(docs)

        # --- Build message list ---
        messages = self._build_messages(user_input, rag_context)

        # --- Stream from Ollama ---
        full_response = ""
        try:
            stream = self._client.chat(
                model=self.model,
                messages=messages,
                stream=True,
                options={"temperature": self.temperature},
            )
            for chunk in stream:
                # ollama SDK >= 0.2 returns ChatResponse objects
                try:
                    token: str = chunk.message.content or ""
                except AttributeError:
                    token = chunk.get("message", {}).get("content", "")  # type: ignore[union-attr]

                if token:
                    token = self.guardian.filter_output(token)
                    full_response += token
                    yield token

        except Exception as e:
            self.audit.log(
                self.session_id, "inference_error", model=self.model, error=str(e)
            )
            raise

        # --- Persist only after successful response ---
        if full_response:
            self.history = self.memory.append(
                self.session_id, self.history, "user", user_input
            )
            self.history = self.memory.append(
                self.session_id, self.history, "assistant", full_response
            )
            self.memory.save(self.session_id, self.history)

        self.audit.log(
            self.session_id, "chat_turn", model=self.model, disposition="ok"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_messages(self, user_input: str, rag_context: str) -> list[dict]:
        messages: list[dict] = [{"role": "system", "content": self.system_prompt}]
        messages.extend(self.history)

        content = user_input
        if rag_context:
            content = f"{rag_context}\n\nUser: {user_input}"

        messages.append({"role": "user", "content": content})
        return messages

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict:
        s = {
            "model": self.model,
            "session_id": self.session_id,
            "history_turns": len(self.history) // 2,
            "rag_docs": self.rag.doc_count,
            "rag_enabled": self.rag_enabled,
            "guardian_injection_detection": self.guardian.injection_detection,
            "guardian_output_sanitization": self.guardian.output_sanitization,
            "temperature": self.temperature,
        }
        s.update({"guardian_" + k: v for k, v in self.guardian.stats().items()})
        return s
