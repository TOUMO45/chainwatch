"""The SmartBugs-curated harness (goal pass 3, precision half).

`github.com/smartbugs/smartbugs-curated` is 143 Solidity contracts with
LINE-LEVEL ground truth in `vulnerabilities.json`:

    {"name": "FibonacciBalance.sol", "path": "dataset/access_control/...",
     "vulnerabilities": [{"lines": [31, 38], "category": "access_control"}]}

Ten categories, of which only some are things Chainwatch's model can express an
opinion about. That mapping is declared here rather than assumed, because the
honest denominator for a recall number is "bugs of a kind this tool claims to
find", not "every bug in the corpus".

WHY THIS CORPUS IS AWKWARD, STATED UP FRONT
-------------------------------------------
Almost every contract here is pragma 0.4.x, written 2016-2018. Chainwatch's
deep oracles reason about vaults, shares, oracles and signatures - concepts
that mostly postdate this corpus. So a low recall here is not the same kind of
result as a low recall on DeFiHackLabs, and the two must not be averaged.

What the corpus IS good for is the direction the goal actually cares about:
these files are DELIBERATELY vulnerable, so a finding is cheap to adjudicate,
and the categories Chainwatch does claim (access control) can be scored
honestly against exact line numbers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import findings as F

# SmartBugs category -> the Deep Hunt finding types that would count as
# "found the same thing". A category absent from this map is OUT OF SCOPE:
# Chainwatch does not claim to detect it, so it is excluded from the recall
# denominator rather than counted as a miss.
CATEGORY_TO_TYPES: dict[str, frozenset] = {
    "access_control": frozenset({F.ACCESS_CONTROL, F.STATE_MACHINE}),
    "reentrancy": frozenset({F.STATE_MACHINE, F.ACCOUNTING, F.LIVE_LOGIC}),
    "arithmetic": frozenset({F.ACCOUNTING}),
    "unchecked_low_level_calls": frozenset({F.LIVE_LOGIC, F.PROTOCOL_INVARIANT}),
    "denial_of_service": frozenset({F.LIVE_LOGIC, F.STATE_MACHINE}),
    "front_running": frozenset({F.ECONOMIC, F.LIVE_LOGIC}),
    "time_manipulation": frozenset({F.ORACLE, F.LIVE_LOGIC}),
}
# Deliberately unmapped (Chainwatch makes no claim): bad_randomness,
# short_addresses, other.
OUT_OF_SCOPE_CATEGORIES = frozenset({"bad_randomness", "short_addresses", "other"})


@dataclass
class SBCase:
    name: str
    path: str
    pragma: str = ""
    categories: list = field(default_factory=list)
    lines: list = field(default_factory=list)

    @property
    def in_scope(self) -> bool:
        return any(c in CATEGORY_TO_TYPES for c in self.categories)


def load_cases(repo_root: str) -> list[SBCase]:
    root = Path(repo_root)
    data = json.loads((root / "vulnerabilities.json").read_text(encoding="utf-8"))
    out: list[SBCase] = []
    for e in data:
        cats, lines = [], []
        for v in e.get("vulnerabilities") or []:
            cats.append(v.get("category", ""))
            lines.extend(v.get("lines") or [])
        out.append(SBCase(name=e.get("name", ""), path=e.get("path", ""),
                          pragma=e.get("pragma", ""),
                          categories=sorted(set(c for c in cats if c)),
                          lines=sorted(set(lines))))
    return out


@dataclass
class SBResult:
    name: str
    categories: list = field(default_factory=list)
    in_scope: bool = False
    compiled: bool = False
    n_findings: int = 0
    finding_types: list = field(default_factory=list)
    matched_category: bool = False
    confirmed: int = 0
    seconds: float = 0.0
    error: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "categories": self.categories,
                "in_scope": self.in_scope, "compiled": self.compiled,
                "n_findings": self.n_findings,
                "finding_types": self.finding_types,
                "matched_category": self.matched_category,
                "confirmed": self.confirmed, "seconds": self.seconds,
                "error": self.error or None}


def run_case(case: SBCase, repo_root: str, *, budget_findings: int = 8) -> SBResult:
    import time

    from .hunt import HuntInputs, run as run_hunt

    res = SBResult(name=case.name, categories=case.categories,
                   in_scope=case.in_scope)
    src = Path(repo_root) / case.path
    try:
        text = src.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        res.error = f"unreadable: {exc}"
        return res
    t0 = time.time()
    try:
        hr = run_hunt(HuntInputs(source=text, budget_findings=budget_findings))
    except Exception as exc:  # noqa: BLE001
        res.error = f"{type(exc).__name__}: {exc}"[:180]
        res.seconds = round(time.time() - t0, 1)
        return res
    res.seconds = round(time.time() - t0, 1)
    res.compiled = bool(hr.model and hr.model.compiled)
    live = [f for f in hr.findings if f.confidence != F.REJECTED]
    res.n_findings = len(live)
    types = {f.finding_type for f in live}
    res.finding_types = sorted(types)
    res.confirmed = sum(1 for f in live if f.confidence == F.CONFIRMED)
    want: set = set()
    for c in case.categories:
        want |= set(CATEGORY_TO_TYPES.get(c, frozenset()))
    res.matched_category = bool(types & want)
    return res


@dataclass
class SBReport:
    total: int = 0
    in_scope: int = 0
    out_of_scope: int = 0
    attempted: int = 0
    compiled: int = 0
    with_findings: int = 0
    matched: int = 0
    confirmed: int = 0
    errors: int = 0
    results: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"total": self.total, "in_scope": self.in_scope,
                "out_of_scope": self.out_of_scope, "attempted": self.attempted,
                "compiled": self.compiled, "with_findings": self.with_findings,
                "matched": self.matched, "confirmed": self.confirmed,
                "errors": self.errors,
                "results": [r.as_dict() for r in self.results]}

    def render(self) -> str:
        def pct(a, b):
            return f"{100.0 * a / b:.1f}%" if b else "n/a"
        return "\n".join([
            "CHAINWATCH vs SmartBugs-curated", "=" * 31, "",
            f"  contracts in corpus     {self.total}",
            f"  category out of scope   {self.out_of_scope}   "
            f"(bad_randomness / short_addresses / other - no claim made)",
            f"  IN SCOPE                {self.in_scope}", "",
            f"  attempted               {self.attempted}",
            f"  modelled (compiled)     {self.compiled}   "
            f"({pct(self.compiled, self.attempted)})",
            f"  produced >=1 finding    {self.with_findings}   "
            f"({pct(self.with_findings, self.compiled)} of modelled)",
            f"  finding of the RIGHT    {self.matched}   "
            f"({pct(self.matched, self.compiled)} of modelled)",
            f"  category",
            f"  reached CONFIRMED       {self.confirmed}   "
            f"(source-only: expected 0)",
            f"  errors                  {self.errors}",
        ])


def run_smartbugs(repo_root: str, *, limit: Optional[int] = None,
                  in_scope_only: bool = True, budget_findings: int = 8,
                  on_result=None) -> SBReport:
    cases = load_cases(repo_root)
    rep = SBReport(total=len(cases))
    for c in cases:
        if c.in_scope:
            rep.in_scope += 1
        else:
            rep.out_of_scope += 1
    todo = [c for c in cases if (c.in_scope or not in_scope_only)]
    if limit:
        todo = todo[:limit]
    for c in todo:
        r = run_case(c, repo_root, budget_findings=budget_findings)
        rep.attempted += 1
        rep.compiled += int(r.compiled)
        rep.with_findings += int(r.n_findings > 0)
        rep.matched += int(r.matched_category)
        rep.confirmed += int(r.confirmed > 0)
        rep.errors += int(bool(r.error))
        rep.results.append(r)
        if on_result:
            on_result(r)
    return rep
