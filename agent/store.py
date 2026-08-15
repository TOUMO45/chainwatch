"""Finding store — the agent layer's ONLY window onto the engine.

ARCHITECTURAL BOUNDARY (AGENT-DESIGN.md §2, property 1). Nothing in `agent/`
imports from `src.rules`. This module reads a FINISHED report dict — the same
JSON `chainwatch.py --json` writes — and hands out immutable views of it. There
is no code path here that can analyse a contract, re-run a rule, or alter a
verdict, because there is no code path here that can reach one.

Finding ids are assigned HERE rather than by the engine, deliberately: the
engine's report format is ground truth and should not grow a field just because
a downstream consumer wants a handle. The id is a deterministic hash of the
facts that identify a finding, so the same report always yields the same ids.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Optional


def finding_id(f: dict) -> str:
    """Stable handle for one finding: hash of what identifies it."""
    key = "|".join(str(f.get(k, "")) for k in
                   ("rule_id", "file", "contract", "function", "commit", "line"))
    return hashlib.sha256(key.encode()).hexdigest()[:12]


class FindingStore:
    """One scan report, indexed by finding id."""

    def __init__(self, report: dict, repo: Optional[Path] = None):
        self._report = report
        self._repo = Path(repo or report.get("repo", "")).resolve()
        self._by_id: dict[str, dict] = {}
        for f in report.get("findings", []):
            self._by_id[finding_id(f)] = f

    @classmethod
    def from_path(cls, path) -> "FindingStore":
        report = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(report)

    # ---------------------------------------------------------------- access

    @property
    def report(self) -> dict:
        return self._report

    @property
    def repo(self) -> Path:
        return self._repo

    def ids(self) -> list[str]:
        return list(self._by_id)

    def get(self, fid: str) -> Optional[dict]:
        return self._by_id.get(fid)

    def index(self) -> list[dict]:
        """Identity fields only — deliberately no prose, so a listing cannot be
        mistaken for evidence."""
        out = []
        for fid, f in self._by_id.items():
            out.append({
                "finding_id": fid,
                "rule_id": f.get("rule_id"),
                "owasp": f.get("owasp"),
                "verdict": f.get("verdict"),
                "contract": f.get("contract"),
                "function": f.get("function"),
                "file": f.get("file"),
                "line": f.get("line"),
                "commit": (f.get("commit") or "")[:12],
            })
        return out

    # ------------------------------------------------------------------ diff

    def diff(self, fid: str, context: int = 6) -> tuple[bool, str]:
        """`git diff parent..commit -- file` for one finding. Read-only."""
        f = self.get(fid)
        if not f:
            return False, f"no finding with id {fid}"
        if not f.get("commit") or not f.get("parent"):
            return False, "finding carries no commit pair"
        if not (self._repo / ".git").exists():
            return False, f"repository not available at {self._repo}"
        try:
            proc = subprocess.run(
                ["git", "diff", f"-U{max(0, min(context, 40))}",
                 f["parent"], f["commit"], "--", f["file"]],
                cwd=str(self._repo), capture_output=True, text=True, timeout=120,
            )
        except Exception as exc:  # noqa: BLE001
            return False, f"{type(exc).__name__}: {exc}"
        if proc.returncode != 0:
            return False, proc.stderr[:300]
        return True, proc.stdout

    # ------------------------------------------------------------ fact sheet

    def facts(self, fid: str) -> dict[str, Any]:
        """Every fact a report about this finding is ALLOWED to state.

        This is the closed set `verify_report` checks a draft against. If a
        detail is not derivable from here, it did not come from Chainwatch and
        has no business in a Chainwatch report.
        """
        f = self.get(fid) or {}
        ev = f.get("evidence") or {}
        return {
            "finding_id": fid,
            "verdict": f.get("verdict"),
            "rule_id": f.get("rule_id"),
            "owasp": f.get("owasp"),
            "contract": f.get("contract"),
            "function": f.get("function"),
            "signature": f.get("signature"),
            "file": f.get("file"),
            "line": f.get("line"),
            "detail": f.get("detail"),
            "commit": f.get("commit"),
            "parent": f.get("parent"),
            "author": f.get("author"),
            "date": f.get("date"),
            "line_range": f.get("line_range"),
            "survives_to_head": f.get("survives_to_head"),
            "fixed_at": f.get("fixed_at"),
            "liveness": f.get("liveness"),
            "liveness_reason": f.get("liveness_reason"),
            "evidence": ev,
            "missing_evidence": [k for k, v in ev.items() if v in (None, "", [], {})],
            "downgrade_reasons": f.get("downgrade_reasons") or [],
            "rule_evidence": f.get("raw_evidence") or {},
            "repo": self._report.get("repo"),
            "head": self._report.get("head"),
            "live_caveat": self._report.get("live_caveat", ""),
        }
