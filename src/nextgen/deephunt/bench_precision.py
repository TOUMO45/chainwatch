"""The precision pass (goal pass 3) - false positives at scale.

Detection numbers are only meaningful next to a false-positive number, and the
honest way to get one is to run over code that is NOT a known incident and
count what the tool says anyway.

CORPUS. `smart-contract-sanctuary-ethereum` is a scrape of Etherscan-verified
mainnet contracts - ordinary deployed code, not a vulnerability dataset. It is
not "known-clean": some of it is certainly buggy, and a few entries are
outright malicious. So a finding here is not automatically wrong, and this
module never calls one "a false positive" on its own authority.

What it measures instead, and what each number is worth:

  CONFIRMED rate        The strict claim. Chainwatch's whole thesis is
                        "when it says CONFIRMED, it means it". On a
                        source-only run the evidence chain CANNOT close (no
                        deployment proof, no reproducer), so the correct
                        result is exactly zero, and any non-zero value is a
                        real defect in the gate. This is a genuine falsifier.

  high-confidence rate  Findings at LIKELY or above - the ones a human would
                        be asked to read. A tool that emits these on most
                        ordinary contracts is noise regardless of its recall.

  sig-scope fire rate   The narrow oracle added this arc, which claims high
                        precision. Every fire is recorded with its contract,
                        function and party so it can be adjudicated by hand
                        rather than assumed correct.

UNITS. The goal asked for "false positives per 1,000 commit pairs". Sanctuary
contracts have no git history, so that unit does not exist here; this module
reports per 1,000 CONTRACTS SCANNED and says so. The commit-pair figure is a
different measurement over repositories with history and is not conflated with
this one.
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import findings as F

# Confidence levels that would put a finding in front of a human.
_HIGH = frozenset({F.CONFIRMED, F.LIKELY})


@dataclass
class PrecResult:
    path: str
    compiled: bool = False
    n_findings: int = 0
    n_high: int = 0
    confirmed: int = 0
    sigscope: list = field(default_factory=list)
    finding_types: list = field(default_factory=list)
    seconds: float = 0.0
    error: str = ""

    def as_dict(self) -> dict:
        return {"path": self.path, "compiled": self.compiled,
                "n_findings": self.n_findings, "n_high": self.n_high,
                "confirmed": self.confirmed, "sigscope": self.sigscope,
                "finding_types": self.finding_types, "seconds": self.seconds,
                "error": self.error or None}


def sample_contracts(root: str, *, n: int, seed: int = 20260830,
                     min_bytes: int = 1200) -> list[Path]:
    """A deterministic random sample of `.sol` files under `root`.

    Deterministic so the number is reproducible; `min_bytes` drops the stub
    files (bare interfaces, one-line proxies) that would inflate a "no findings"
    rate without testing anything.
    """
    files = [p for p in Path(root).rglob("*.sol")
             if p.is_file() and p.stat().st_size >= min_bytes]
    files.sort()                                   # stable before sampling
    rng = random.Random(seed)
    rng.shuffle(files)
    return files[:n]


def run_one(path: Path, *, budget_findings: int = 6) -> PrecResult:
    from . import invariants as INV
    from . import protocolmodel as PM
    from .hunt import HuntInputs, run as run_hunt

    res = PrecResult(path=str(path))
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        res.error = f"unreadable: {exc}"
        return res

    t0 = time.time()
    try:
        hr = run_hunt(HuntInputs(source=text, budget_findings=budget_findings))
    except Exception as exc:  # noqa: BLE001
        res.error = f"{type(exc).__name__}: {exc}"[:160]
        res.seconds = round(time.time() - t0, 1)
        return res
    res.seconds = round(time.time() - t0, 1)
    res.compiled = bool(hr.model and hr.model.compiled)
    if not res.compiled:
        return res

    live = [f for f in hr.findings if f.confidence != F.REJECTED]
    res.n_findings = len(live)
    res.n_high = sum(1 for f in live if f.confidence in _HIGH)
    res.confirmed = sum(1 for f in live if f.confidence == F.CONFIRMED)
    res.finding_types = sorted({f.finding_type for f in live})

    # the narrow oracle, recorded per fire so each can be adjudicated by hand
    try:
        for i in INV.cat_signature_scope(hr.model):
            t = i.predicate["test_recipe"]
            res.sigscope.append(
                {"fn": f"{i.contract}.{i.functions[0]}",
                 "party": t.get("party_param", ""),
                 "nonce": t.get("nonce_var", "")})
    except Exception:  # noqa: BLE001
        pass
    return res


@dataclass
class PrecReport:
    scanned: int = 0
    compiled: int = 0
    errors: int = 0
    with_findings: int = 0
    with_high: int = 0
    confirmed: int = 0
    sigscope_fires: int = 0
    sigscope_contracts: int = 0
    results: list = field(default_factory=list)

    def per_1k(self, count: int) -> float:
        return round(1000.0 * count / self.compiled, 2) if self.compiled else 0.0

    def as_dict(self) -> dict:
        return {"scanned": self.scanned, "compiled": self.compiled,
                "errors": self.errors, "with_findings": self.with_findings,
                "with_high": self.with_high, "confirmed": self.confirmed,
                "sigscope_fires": self.sigscope_fires,
                "sigscope_contracts": self.sigscope_contracts,
                "confirmed_per_1k_contracts": self.per_1k(self.confirmed),
                "high_conf_per_1k_contracts": self.per_1k(self.with_high),
                "sigscope_per_1k_contracts": self.per_1k(self.sigscope_contracts),
                "results": [r.as_dict() for r in self.results]}

    def render(self) -> str:
        def pct(a, b):
            return f"{100.0 * a / b:.1f}%" if b else "n/a"
        return "\n".join([
            "CHAINWATCH precision pass - ordinary verified mainnet contracts",
            "=" * 62, "",
            f"  contracts sampled       {self.scanned}",
            f"  modelled (compiled)     {self.compiled}   "
            f"({pct(self.compiled, self.scanned)})",
            f"  errors                  {self.errors}", "",
            "  per 1,000 CONTRACTS SCANNED (not commit pairs - see module doc):",
            f"    CONFIRMED             {self.per_1k(self.confirmed):>8}   "
            f"({self.confirmed} absolute)",
            f"    high-confidence       {self.per_1k(self.with_high):>8}   "
            f"({self.with_high} absolute)",
            f"    signature-scope fires {self.per_1k(self.sigscope_contracts):>8}   "
            f"({self.sigscope_contracts} contracts, {self.sigscope_fires} fires)",
            "",
            f"  any finding at all      {self.with_findings}   "
            f"({pct(self.with_findings, self.compiled)} of modelled)",
            "",
            "  CONFIRMED must be 0: a source-only run has no deployment proof",
            "  and no reproducer, so the evidence chain cannot close.",
        ])


def run_precision(root: str, *, n: int = 300, seed: int = 20260830,
                  budget_findings: int = 6, on_result=None) -> PrecReport:
    rep = PrecReport()
    for p in sample_contracts(root, n=n, seed=seed):
        r = run_one(p, budget_findings=budget_findings)
        rep.scanned += 1
        rep.compiled += int(r.compiled)
        rep.errors += int(bool(r.error))
        rep.with_findings += int(r.n_findings > 0)
        rep.with_high += int(r.n_high > 0)
        rep.confirmed += int(r.confirmed > 0)
        if r.sigscope:
            rep.sigscope_contracts += 1
            rep.sigscope_fires += len(r.sigscope)
        rep.results.append(r)
        if on_result:
            on_result(r)
    return rep


def write_report(rep: PrecReport, path: str) -> None:
    Path(path).write_text(json.dumps(rep.as_dict(), indent=1, default=str),
                          encoding="utf-8")
