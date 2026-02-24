"""
audit.py — Structured security event logging for Milly.

Writes JSON entries to logs/security.log.
Content is never logged; only input hashes and metadata.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, log_dir: str = "logs"):
        self.log_path = Path(log_dir) / "security.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, session_id: str, event: str, model: str = "", **kwargs: Any) -> None:
        """Write a structured security event entry."""
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "event": event,
        }
        if model:
            entry["model"] = model
        entry.update(kwargs)

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def get_session_events(self, session_id: str) -> list[dict]:
        """Return all log entries for a given session."""
        events: list[dict] = []
        if not self.log_path.exists():
            return events

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("session_id") == session_id:
                        events.append(entry)
                except json.JSONDecodeError:
                    continue
        return events

    def get_session_summary(self, session_id: str) -> dict:
        """Return a count summary of events by type for a session."""
        events = self.get_session_events(session_id)
        counts: dict[str, int] = {}
        for e in events:
            etype = e.get("event", "unknown")
            counts[etype] = counts.get(etype, 0) + 1
        return {"session_id": session_id, "total": len(events), "by_type": counts}
