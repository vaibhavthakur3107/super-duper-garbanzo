"""
Cyber-Sentry AI – Notes / Loot Manager
Saves findings, credentials, and vulnerabilities discovered during assessments.
Inspired by PentestAgent's loot/notes system.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional


# Where notes/loot are persisted
_DEFAULT_LOOT_DIR = Path(os.environ.get("LOOT_DIR", "./loot"))


class NotesManager:
    """
    Persists agent findings to a JSON file in the loot directory.

    Note categories (same as PentestAgent):
    - ``credential``    – discovered usernames/passwords
    - ``vulnerability`` – confirmed vulnerabilities
    - ``finding``       – general findings / observations
    - ``artifact``      – files, hashes, screenshots, etc.
    """

    CATEGORIES = {"credential", "vulnerability", "finding", "artifact"}

    def __init__(self, loot_dir: Optional[Path] = None):
        self.loot_dir = Path(loot_dir or _DEFAULT_LOOT_DIR)
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        self._notes_path = self.loot_dir / "notes.json"
        self._notes: list[dict] = self._load()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self) -> list[dict]:
        if self._notes_path.exists():
            try:
                return json.loads(self._notes_path.read_text())
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def _save(self):
        self._notes_path.write_text(json.dumps(self._notes, indent=2))

    # ── Public API ───────────────────────────────────────────────────────────

    def add_note(
        self,
        content: str,
        category: str = "finding",
        target: str = "",
        source: str = "",
    ) -> dict:
        """Add a note and persist it to disk."""
        if category not in self.CATEGORIES:
            category = "finding"
        note = {
            "id": (max(n["id"] for n in self._notes) + 1) if self._notes else 1,
            "timestamp": datetime.now().isoformat(),
            "category": category,
            "target": target,
            "source": source,
            "content": content,
        }
        self._notes.append(note)
        self._save()
        return note

    def get_notes(
        self,
        category: Optional[str] = None,
        target: Optional[str] = None,
    ) -> list[dict]:
        """Return all notes, optionally filtered."""
        notes = self._notes
        if category:
            notes = [n for n in notes if n.get("category") == category]
        if target:
            notes = [n for n in notes if n.get("target") == target]
        return notes

    def clear_session(self):
        """Clear in-memory notes for the current session (does not delete persisted file)."""
        self._notes = self._load()  # reload from disk – keeps previously saved notes

    def generate_report(self, session_results: list[dict], target: str = "") -> Path:
        """
        Compile a Markdown report from session results and saved notes.
        Returns the path to the saved report file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.loot_dir / f"report_{timestamp}.md"

        lines = [
            "# Cyber-Sentry AI – Penetration Test Report",
            "",
            f"**Target:** {target or 'N/A'}",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "---",
            "",
        ]

        # ── Notes / Findings ─────────────────────────────────────────────────
        notes = self.get_notes(target=target) if target else self._notes
        if notes:
            lines += ["## 📌 Saved Notes", ""]
            for n in notes:
                lines.append(f"### [{n['category'].upper()}] {n.get('source', '')}")
                lines.append(f"*{n['timestamp']}*")
                lines.append("")
                lines.append(n["content"])
                lines.append("")

        # ── Thought Trace ────────────────────────────────────────────────────
        for idx, result in enumerate(session_results, 1):
            thoughts = result.get("thought_trace", [])
            if not thoughts:
                continue
            lines += [f"## Session {idx} – Thought Trace", ""]
            for t in thoughts:
                node = t.get("node", "").upper()
                action = t.get("action", "")
                lines.append(f"### [{node}] `{action}`")
                if t.get("thought"):
                    lines.append(f"**Thought:** {t['thought']}")
                if t.get("reasoning"):
                    lines.append(f"**Reasoning:** {t['reasoning']}")
                if t.get("observation"):
                    lines.append(f"**Observation:**\n```\n{t['observation']}\n```")
                lines.append("")

        report_path.write_text("\n".join(lines))
        return report_path
