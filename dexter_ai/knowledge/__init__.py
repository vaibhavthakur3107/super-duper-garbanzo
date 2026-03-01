"""
Dexter AI Pentest – Knowledge Base
Provides context injection from local knowledge sources.

Inspired by PentestAgent's RAG/knowledge system.
Place methodology notes, CVE references, or wordlists under:
    dexter_ai/knowledge/sources/

Files are loaded at runtime and injected into the agent context.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

# Default sources directory
_DEFAULT_SOURCES_DIR = Path(__file__).parent / "sources"


class KnowledgeBase:
    """
    Loads and serves knowledge documents for RAG-style context injection.

    Documents in ``sources/`` are plain-text or Markdown files.
    They are made available to agents via ``get_context()``.
    """

    def __init__(self, sources_dir: Optional[Path] = None):
        self.sources_dir = Path(sources_dir or _DEFAULT_SOURCES_DIR)
        self._docs: dict[str, str] = {}
        self._load()

    def _load(self):
        """Load all .txt and .md files from the sources directory."""
        if not self.sources_dir.exists():
            return
        for path in sorted(self.sources_dir.glob("**/*")):
            if path.is_file() and path.suffix in {".txt", ".md"}:
                try:
                    self._docs[path.stem] = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    pass

    def list_sources(self) -> list[str]:
        """Return names of loaded knowledge sources."""
        return list(self._docs.keys())

    def get(self, name: str) -> Optional[str]:
        """Get a knowledge document by name (without extension)."""
        return self._docs.get(name)

    def get_context(self, query: str = "", max_chars: int = 4000) -> str:
        """
        Return relevant knowledge context for injection into agent prompts.

        If ``query`` is provided, returns documents whose names or content
        contain query keywords (simple keyword match).  Otherwise returns
        all documents up to ``max_chars``.
        """
        if not self._docs:
            return ""

        if query:
            keywords = query.lower().split()
            selected = {
                name: content
                for name, content in self._docs.items()
                if any(kw in name.lower() or kw in content.lower() for kw in keywords)
            }
        else:
            selected = self._docs

        combined = "\n\n---\n\n".join(
            f"### {name}\n{content}"
            for name, content in selected.items()
        )
        if len(combined) > max_chars:
            combined = combined[:max_chars] + "\n... [knowledge truncated]"
        return combined

    def reload(self):
        """Reload all sources from disk."""
        self._docs.clear()
        self._load()


# Module-level singleton
knowledge_base = KnowledgeBase()
