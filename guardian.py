"""
guardian.py — Security layer for Milly. Standalone importable.

Four checks in order:
  1. Length enforcement
  2. Prompt injection detection (OWASP LLM Top 10 patterns)
  3. Character sanitization (null bytes, control chars, RTL overrides, ANSI escapes)
  4. Output filtering (ANSI stripping, control char removal)

Usage:
    from guardian import Guardian

    g = Guardian(config)
    result = g.check(user_input)

    if result.blocked:
        print(f"Blocked: {result.reason}")
    elif result.flagged:
        print(f"Flagged ({result.pattern}): proceeding with log entry")
        sanitized = result.sanitized_input
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class GuardianResult:
    blocked: bool = False
    flagged: bool = False
    reason: Optional[str] = None
    pattern: Optional[str] = None
    sanitized_input: str = ""
    input_hash: str = ""


class Guardian:
    """
    Input/output security layer.

    Covers OWASP LLM Top 10 injection categories:
      - LLM01: Prompt Injection (direct)
      - LLM02: Insecure Output Handling (output sanitization)
      - LLM06: Sensitive Information Disclosure (audit, not block)
      - Indirect injection via documents (scan_document method)
    """

    # Pattern bank: (regex, category_name)
    # Each pattern targets a documented injection technique.
    INJECTION_PATTERNS: list[tuple[str, str]] = [
        # Instruction override
        (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|directives?)", "instruction_override"),
        (r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)", "instruction_override"),
        (r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)", "instruction_override"),
        (r"override\s+(your\s+)?(instructions?|system\s+prompt|guidelines?|safety)", "instruction_override"),
        (r"your\s+(new\s+)?(instructions?|prompt|system\s+prompt|rules?)\s+(are|is)\b", "instruction_override"),
        (r"new\s+instructions?\s*:", "instruction_override"),
        (r"from\s+now\s+on\s*(,\s*)?(you\s+)?(must|should|will|are\s+to)", "instruction_override"),
        # Persona hijacking
        (r"you\s+are\s+now\s+(?!milly\b)", "persona_override"),
        (r"pretend\s+(that\s+)?you\s+are\b", "persona_override"),
        (r"act\s+as\b", "persona_override"),
        (r"roleplay\s+as\b", "persona_override"),
        (r"simulate\s+(being\s+)?(?!milly\b)", "persona_override"),
        # System prompt injection via delimiter spoofing
        (r"\bsystem\s*:\s*", "system_injection"),
        (r"\[system\]", "system_injection"),
        (r"<\s*system\s*>", "system_injection"),
        (r"<\s*/?inst\s*>", "system_injection"),
        (r"\[INST\]", "system_injection"),
        (r"<<SYS>>", "system_injection"),
        (r"<\|system\|>", "system_injection"),
        (r"<\|im_start\|>", "system_injection"),
        # Jailbreak keywords
        (r"\bjailbreak\b", "jailbreak_attempt"),
        (r"\bDAN\b", "jailbreak_attempt"),
        (r"do\s+anything\s+now", "jailbreak_attempt"),
        (r"developer\s+mode", "jailbreak_attempt"),
        (r"sudo\s+mode", "jailbreak_attempt"),
        (r"god\s+mode", "jailbreak_attempt"),
        (r"admin\s+mode", "jailbreak_attempt"),
        (r"unrestricted\s+mode", "jailbreak_attempt"),
        # Safety bypass attempts
        (r"bypass\s+(your\s+)?(safety|security|filter|restriction|guideline|ethics)", "bypass_attempt"),
        (r"(disable|turn\s+off)\s+(your\s+)?(safety|security|filter|restriction)", "bypass_attempt"),
        (r"you\s+have\s+no\s+(restrictions?|limitations?|filters?|ethics)", "bypass_attempt"),
        (r"without\s+(any\s+)?(restrictions?|limitations?|filters?|safety)", "bypass_attempt"),
        # Encoding-based evasion
        (r"base64\s*[:-]?\s*decode", "encoding_evasion"),
        (r"translate\s+the\s+following\s+(from\s+)?base64", "encoding_evasion"),
        (r"decode\s+this\s+base64", "encoding_evasion"),
        # Indirect injection markers (document-borne)
        (r"\[prompt\s+injection\]", "indirect_injection"),
        (r"<\s*injection\s*>", "indirect_injection"),
        (r"<!-- inject", "indirect_injection"),
        # Markdown-formatted injection (common in document poisoning attacks)
        (r"#{1,6}\s*(new\s+instructions?|system\s*(prompt|override))\b", "indirect_injection"),
        (r"\*{1,2}\s*(system\s*(override|prompt)|new\s+instructions?)\s*\*{1,2}", "indirect_injection"),
    ]

    # Dangerous characters: control chars, zero-width, RTL overrides, terminal escapes
    _DANGEROUS_CHARS = re.compile(
        r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f"   # ASCII control chars (keep \t \n \r)
        r"\u200b-\u200f"                         # Zero-width spaces/joiners
        r"\u202a-\u202e"                         # Bidirectional override chars
        r"\u2060-\u2064"                         # Word joiner, invisible chars
        r"\ufeff"                                # BOM
        r"\x1b"                                  # ESC — terminal escape sequences
        r"]"
    )

    # ANSI escape sequences in model output
    _ANSI_ESCAPE = re.compile(
        r"\x1b\[[0-9;]*[A-Za-z]"       # CSI sequences (colors, cursor movement)
        r"|\x1b\][^\x07]*\x07"          # OSC sequences
        r"|\x1b[()][A-Z0-9]"            # Character set designation
        r"|\x1b[^[\]()]"                # Other ESC sequences
    )

    def __init__(self, config: dict):
        self.max_length: int = config.get("max_input_length", 4000)
        self.injection_detection: bool = config.get("injection_detection", True)
        self.output_sanitization: bool = config.get("output_sanitization", True)

        self._compiled: list[tuple[re.Pattern, str]] = [
            (re.compile(pattern, re.IGNORECASE | re.MULTILINE), name)
            for pattern, name in self.INJECTION_PATTERNS
        ]

        # Lifetime detection counts for this instance (chat turns only, not doc scans)
        self._stats: dict[str, int] = {"blocked": 0, "flagged": 0, "clean": 0}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, user_input: str) -> GuardianResult:
        """
        Run all input checks. Returns a GuardianResult.

        Blocked  → caller must not pass input to the model.
        Flagged  → caller may proceed but should log the attempt.
        """
        result = GuardianResult()
        result.input_hash = self._hash(user_input)

        # 1. Length enforcement
        if len(user_input) > self.max_length:
            result.blocked = True
            result.reason = (
                f"Input exceeds maximum length "
                f"({len(user_input)} chars > {self.max_length} limit)"
            )
            self._stats["blocked"] += 1
            return result

        # 2. Character sanitization (before injection scan to remove evasion tricks)
        sanitized = self._strip_dangerous(user_input)

        # 3. Injection detection
        if self.injection_detection:
            for pattern, name in self._compiled:
                if pattern.search(sanitized):
                    result.flagged = True
                    result.pattern = name
                    result.reason = f"Potential prompt injection: {name}"
                    break

        result.sanitized_input = sanitized
        if result.flagged:
            self._stats["flagged"] += 1
        else:
            self._stats["clean"] += 1
        return result

    def scan_document(self, content: str) -> GuardianResult:
        """
        Scan document content for injection patterns.
        No length limit — documents are allowed to be large.
        Only scans the first 20 000 chars to bound CPU usage.
        """
        result = GuardianResult()
        result.input_hash = self._hash(content[:8192])  # hash prefix for audit

        sanitized = self._strip_dangerous(content)

        if self.injection_detection:
            sample = sanitized[:20_000]
            for pattern, name in self._compiled:
                if pattern.search(sample):
                    result.flagged = True
                    result.pattern = name
                    result.reason = f"Injection pattern in document: {name}"
                    break

        result.sanitized_input = sanitized
        return result

    def filter_output(self, text: str) -> str:
        """Sanitize model output before display."""
        if not self.output_sanitization:
            return text
        cleaned = self._ANSI_ESCAPE.sub("", text)
        cleaned = self._strip_dangerous(cleaned)
        return cleaned

    def stats(self) -> dict:
        """
        Return lifetime detection counts for this Guardian instance.

        Counts only check() calls (chat turns). scan_document() is excluded
        because document ingestion is a separate operation from chat turns.

        Returns a copy — mutating the result does not affect internal state.
        """
        return dict(self._stats)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hash(text: str) -> str:
        return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()

    @classmethod
    def _strip_dangerous(cls, text: str) -> str:
        return cls._DANGEROUS_CHARS.sub("", text)
