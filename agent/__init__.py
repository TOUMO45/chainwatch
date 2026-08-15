"""Chainwatch capability 12 — the reporting agent layer.

Reads a finished scan report and drafts human-readable documents from it. It
never analyses, never decides a verdict, and never reaches the chain or a
repository's source. See AGENT-DESIGN.md for the tool design and RULES.md for
the amended rule governing which verdicts it may see.
"""

from .store import FindingStore, finding_id
from .templates import assemble, header_for, skeleton
from .verify import verify

__all__ = ["FindingStore", "finding_id", "assemble", "header_for", "skeleton", "verify"]
