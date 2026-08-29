"""The DeFiHackLabs detection harness (goal pass 1).

`github.com/SunWeb3Sec/DeFiHackLabs` carries ~876 reproduced real-world DeFi
incidents, each as a Foundry PoC whose header records the vulnerable contract,
the chain, and the fork block:

    // @KeyInfo - Total Lost : 34.88 BNB (~$20K USD)
    // Vulnerable Contract : https://bscscan.com/address/0xbe779d42...
    // Attack Tx : https://bscscan.com/tx/0x5e694707...
    ...
    vm.createSelectFork("bsc", 42_846_998 - 1);

That is everything a scan needs: WHAT to look at, on WHICH chain, at WHICH
block - the state immediately before the attack.

WHAT THIS HARNESS DOES NOT PRETEND
----------------------------------
A large fraction of these incidents are NOT in scope for a source-level
analyser, and saying so is part of the result rather than an excuse:

  * compromised private keys / rogue admin  - nothing in the Solidity is wrong
  * off-chain oracle or bridge-relayer failure
  * frontend / DNS / social engineering
  * pure economic design (a working contract used as designed)

`classify_scope` separates those out mechanically from the incident's own
labels, and the harness reports the split. A detection rate quoted over
incidents a source analyser structurally cannot see would be dishonest in both
directions - it understates the tool and overstates the corpus.

Source comes from Sourcify (keyless), exactly as `bench_dvbench` does. An
incident whose contract has no verified source is recorded as such and excluded
from the denominator, never silently counted as a miss.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------- #
# parsing an incident PoC
# --------------------------------------------------------------------------- #

_CHAIN_IDS = {
    "mainnet": 1, "ethereum": 1, "eth": 1,
    "bsc": 56, "bnb": 56, "binance": 56,
    "base": 8453, "arbitrum": 42161, "arb": 42161,
    "polygon": 137, "matic": 137, "optimism": 10, "op": 10,
    "avalanche": 43114, "avax": 43114, "fantom": 250, "ftm": 250,
    "gnosis": 100, "xdai": 100, "celo": 42220, "moonriver": 1285,
    "moonbeam": 1284, "cronos": 25, "harmony": 1666600000,
    "linea": 59144, "scroll": 534352, "blast": 81457, "mantle": 5000,
    "zksync": 324, "opbnb": 204, "sonic": 146, "berachain": 80094,
}

_EXPLORER_CHAIN = {
    "etherscan.io": 1, "bscscan.com": 56, "basescan.org": 8453,
    "arbiscan.io": 42161, "polygonscan.com": 137,
    "optimistic.etherscan.io": 10, "snowtrace.io": 43114,
    "ftmscan.com": 250, "gnosisscan.io": 100, "celoscan.io": 42220,
    "lineascan.build": 59144, "scrollscan.com": 534352,
    "blastscan.io": 81457, "mantlescan.xyz": 5000, "era.zksync.network": 324,
    "opbnbscan.com": 204, "sonicscan.org": 146, "berascan.com": 80094,
}

_RE_VULN = re.compile(
    r"//\s*Vulnerable\s*Contract\s*:?\s*(?:https?://([^/\s]+)/address/)?"
    r"(0x[a-fA-F0-9]{40})", re.I)
# Older PoCs (2017-2021) predate the "Vulnerable Contract :" convention and
# instead link the verified source directly, e.g.
#   // https://etherscan.io/address/0xc5d105e6...#code  Line261
_RE_ADDR_LINK = re.compile(
    r"//[^\n]*?https?://([A-Za-z0-9.\-]*scan[A-Za-z0-9.\-]*|[A-Za-z0-9.\-]*"
    r"etherscan\.io)/address/(0x[a-fA-F0-9]{40})", re.I)
_RE_FORK = re.compile(
    r"""createSelectFork\(\s*["']([A-Za-z0-9_]+)["']\s*,\s*([0-9_]+)""")
_RE_LOST = re.compile(r"//\s*@KeyInfo\s*-\s*Total\s*Lost\s*:?\s*(.+)")
_RE_USD = re.compile(r"\$\s*([0-9][0-9,._]*)\s*([KMB])?", re.I)


def _num(s: str) -> Optional[int]:
    try:
        return int(str(s).replace("_", ""))
    except (TypeError, ValueError):
        return None


def _usd(text: str) -> Optional[float]:
    m = _RE_USD.search(text or "")
    if not m:
        return None
    try:
        base = float(m.group(1).replace(",", "").rstrip("."))
    except ValueError:
        return None
    return base * {"k": 1e3, "m": 1e6, "b": 1e9}.get(
        (m.group(2) or "").lower(), 1.0)


@dataclass
class Incident:
    id: str                       # e.g. "2024-10/AIZPTToken_exp"
    name: str
    path: str
    address: str = ""
    chain_id: int = 0
    chain_name: str = ""
    block_number: Optional[int] = None
    lost_usd: Optional[float] = None
    lost_raw: str = ""
    label: str = ""               # README root-cause title, when present
    vuln_class: str = ""          # one of the VC_* classes
    scope: str = ""               # IN_SCOPE / OUT_OF_SCOPE / UNKNOWN_SCOPE
    scope_reason: str = ""

    def as_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "address": self.address,
                "chain_id": self.chain_id, "block_number": self.block_number,
                "lost_usd": self.lost_usd, "label": self.label,
                "vuln_class": self.vuln_class,
                "scope": self.scope, "scope_reason": self.scope_reason}


def parse_incident(path: Path, repo_root: Path) -> Optional[Incident]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    head = text[:4000]                       # the metadata block, not the PoC
    rid = path.relative_to(repo_root / "src" / "test").as_posix().rsplit(".", 1)[0]
    inc = Incident(id=rid, name=path.stem.replace("_exp", ""),
                   path=str(path))

    m = _RE_VULN.search(head) or _RE_ADDR_LINK.search(head)
    if m:
        host, addr = m.group(1), m.group(2)
        inc.address = addr
        if host:
            inc.chain_id = _EXPLORER_CHAIN.get(host.lower(), 0)

    f = _RE_FORK.search(text)
    if f:
        inc.chain_name = f.group(1).lower()
        inc.block_number = _num(f.group(2))
        if not inc.chain_id:
            inc.chain_id = _CHAIN_IDS.get(inc.chain_name, 0)
        # the PoC forks one block BEFORE the attack ("block - 1"); the header
        # number is already that pre-attack block in most files.

    k = _RE_LOST.search(head)
    if k:
        inc.lost_raw = k.group(1).strip()[:120]
        inc.lost_usd = _usd(inc.lost_raw)

    inc.scope, inc.scope_reason = classify_scope(inc.name, head)
    return inc


# A README entry looks like
#
#   ### 20260827 MoonwellMAMO - Chainlink oracle-source price manipulation ...
#   ### Lost: ~71.36 cbBTC ...
#   ```sh
#   forge test --contracts src/test/2026-08/MoonwellMAMO_exp.sol ...
#   ```
#   #### Contract
#   [MoonwellMAMO_exp.sol](src/test/2026-08/MoonwellMAMO_exp.sol)
#
# The `###` title is the only place the ROOT CAUSE is stated in words, so it is
# the authoritative label - far better than anything the PoC source implies.
_RE_MD_TITLE = re.compile(r"^###\s+(?:\d{8}\s+)?(.+?)\s*$", re.M)
_RE_MD_LINK = re.compile(r"src/test/(\d{4}-\d{2}/[A-Za-z0-9_]+)\.sol")


def load_readme_labels(repo_root: str) -> dict[str, str]:
    """`{incident_id: root-cause title}` mined from every README in the repo
    (the live one plus `past/<year>/README.md`)."""
    root = Path(repo_root)
    files = [root / "README.md", *sorted(root.glob("past/*/README.md"))]
    labels: dict[str, str] = {}
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # walk the file once, remembering the most recent non-"Lost:" title
        title = ""
        for line in text.splitlines():
            m = _RE_MD_TITLE.match(line)
            if m:
                t = m.group(1).strip()
                if not t.lower().startswith("lost"):
                    title = t
                continue
            for lm in _RE_MD_LINK.finditer(line):
                if title:
                    labels.setdefault(lm.group(1), title)
    return labels


def load_incidents(repo_root: str) -> list[Incident]:
    root = Path(repo_root)
    labels = load_readme_labels(repo_root)
    out: list[Incident] = []
    for p in sorted((root / "src" / "test").rglob("*_exp.sol")):
        inc = parse_incident(p, root)
        if inc is None:
            continue
        title = labels.get(inc.id, "")
        if title:
            inc.label = title
            # the README title states the root cause; re-classify from it,
            # which is strictly better evidence than the PoC body.
            inc.scope, inc.scope_reason = classify_scope(title, "")
        inc.vuln_class = classify_vuln(inc.label)
        out.append(inc)
    return out


# --------------------------------------------------------------------------- #
# scope classification - which incidents a SOURCE analyser could ever see
# --------------------------------------------------------------------------- #

# An incident whose root cause is off-chain, or is a key compromise, has no
# defect in the Solidity to find. Counting those as misses would understate any
# source-level tool; counting them as in-scope would overstate the corpus. They
# are separated and reported, per the goal's "that filtering itself is a useful
# stat".
_OUT_OF_SCOPE = (
    ("private key", "compromised key", "key leak", "keyleak", "leaked key",
     "compromised private", "privatekey"),
    ("rug", "rugpull", "rug pull", "exit scam", "honeypot"),
    # NB: "twitter" / "discord" are deliberately NOT needles. DeFiHackLabs'
    # PoC template contains the boilerplate lines `// @POC Author : ...` and
    # `// twitter guy :`, which say who wrote the write-up, not what went
    # wrong - matching them mislabelled 324 incidents as social engineering.
    ("phishing", "social engineering", "dns hijack", "frontend attack",
     "front-end attack", "website compromise"),
    ("compromised owner", "malicious owner", "owner compromise",
     "admin key", "compromised admin", "multisig compromise"),
    ("off-chain", "offchain", "centralized oracle", "oracle service",
     "chainlink outage", "relayer"),
)
_OUT_LABELS = {
    "PRIVATE_KEY_COMPROMISE": _OUT_OF_SCOPE[0],
    "RUGPULL_OR_SCAM": _OUT_OF_SCOPE[1],
    "SOCIAL_OR_FRONTEND": _OUT_OF_SCOPE[2],
    "COMPROMISED_PRIVILEGED_ACCOUNT": _OUT_OF_SCOPE[3],
    "OFF_CHAIN_DEPENDENCY": _OUT_OF_SCOPE[4],
}

IN_SCOPE = "IN_SCOPE"
OUT_OF_SCOPE = "OUT_OF_SCOPE"
UNKNOWN_SCOPE = "UNKNOWN_SCOPE"


# Every PoC credits its author as `// @POC Author : [name](https://twitter.com/x)`,
# and most link the attacker's explorer page. Neither says anything about the
# ROOT CAUSE, and matching them cost 536 incidents to a bogus "social
# engineering" label on the first run. Strip the noise before classifying.
_RE_AUTHOR_LINE = re.compile(r"//\s*@POC\s*Author.*", re.I)
_RE_SOCIAL_URL = re.compile(
    r"https?://(?:www\.)?(?:twitter\.com|x\.com|t\.me|discord\.\S+|"
    r"medium\.com|mirror\.xyz|github\.com)/\S*", re.I)
_RE_ANY_URL = re.compile(r"https?://\S+")


def classify_scope(name: str, header: str) -> tuple[str, str]:
    """`(scope, reason)` from the incident's own text.

    Conservative by construction: only an explicit off-chain / key-compromise
    marker moves an incident OUT of scope, so the in-scope set is never
    inflated by a guess. Author credits and bare explorer/social URLs are
    stripped first - they describe who wrote the PoC, not what went wrong.
    """
    hay = f"{name} {header}"
    hay = _RE_AUTHOR_LINE.sub(" ", hay)
    hay = _RE_SOCIAL_URL.sub(" ", hay)
    hay = _RE_ANY_URL.sub(" ", hay)
    hay = hay.lower()
    for label, needles in _OUT_LABELS.items():
        for n in needles:
            # word-boundary match: "rug" must not fire inside "rugged"/"drug"
            if re.search(rf"(?<![a-z]){re.escape(n)}(?![a-z])", hay):
                return OUT_OF_SCOPE, f"{label}: matched {n!r}"
    return IN_SCOPE, "no off-chain / key-compromise marker in the incident text"


# --------------------------------------------------------------------------- #
# root-cause taxonomy, mined from the corpus's own vocabulary
# --------------------------------------------------------------------------- #
#
# Derived by counting terms over all 848 README root-cause titles rather than
# invented up front, so the classes reflect what actually happens in the wild.
# Order matters: the first match wins, and the more specific classes come
# first, because "price manipulation via flashloan" is a PRICE_MANIPULATION
# incident, not a FLASHLOAN one.

VC_ACCESS_CONTROL = "ACCESS_CONTROL"
VC_PRICE_MANIPULATION = "PRICE_MANIPULATION"
VC_REENTRANCY = "REENTRANCY"
VC_ARBITRARY_CALL = "ARBITRARY_EXTERNAL_CALL"
VC_SIGNATURE = "SIGNATURE_REPLAY"
VC_ACCOUNTING = "ACCOUNTING_MATH"
VC_INIT = "UNPROTECTED_INIT_UPGRADE"
VC_VALIDATION = "INPUT_VALIDATION"
VC_BUSINESS_LOGIC = "BUSINESS_LOGIC"
VC_OTHER = "OTHER"

_VULN_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (VC_INIT, ("uninitialized", "reinitializ", "unprotected init", "initializ",
               "upgrade", "delegatecall to unprotected", "selfdestruct")),
    (VC_SIGNATURE, ("signature", "ecrecover", "permit", "replay", "nonce")),
    (VC_REENTRANCY, ("reentran", "erc777", "erc721 callback", "cross-function")),
    (VC_PRICE_MANIPULATION, ("price manipulation", "oracle", "spot price",
                             "reserve manipulation", "twap", "price",
                             "manipulation of", "skim", "sync(")),
    (VC_ARBITRARY_CALL, ("arbitrary call", "arbitrary external",
                         "unchecked call", "arbitrary token", "arbitrary")),
    (VC_ACCESS_CONTROL, ("access control", "missing permission", "unprotected",
                         "permission check", "onlyowner", "authorization",
                         "unauthorized", "missing modifier", "public function")),
    (VC_ACCOUNTING, ("overflow", "underflow", "rounding", "precision",
                     "inflation", "share", "accounting", "calculation",
                     "incorrect math", "division", "decimal")),
    (VC_VALIDATION, ("validation", "input", "missing check", "lack of check",
                     "slippage", "deadline", "unchecked")),
    (VC_BUSINESS_LOGIC, ("business logic", "logic flaw", "logic error",
                         "flawed logic", "logic")),
)


def classify_vuln(label: str) -> str:
    """The root-cause class of an incident, from its README title."""
    hay = (label or "").lower()
    for cls, needles in _VULN_PATTERNS:
        if any(n in hay for n in needles):
            return cls
    return VC_OTHER


# Which classes a SOURCE-level analyser can even express an opinion about.
# PRICE_MANIPULATION is included: the defect is in the contract (it trusts a
# spot reserve), even though triggering it needs market state.
ANALYSABLE_CLASSES = frozenset({
    VC_ACCESS_CONTROL, VC_PRICE_MANIPULATION, VC_REENTRANCY, VC_ARBITRARY_CALL,
    VC_SIGNATURE, VC_ACCOUNTING, VC_INIT, VC_VALIDATION, VC_BUSINESS_LOGIC,
})


# --------------------------------------------------------------------------- #
# the detection pass
# --------------------------------------------------------------------------- #

@dataclass
class DetectionResult:
    incident: str
    name: str = ""
    chain_id: int = 0
    address: str = ""
    source_available: bool = False
    compiled: bool = False
    n_findings: int = 0
    finding_types: list = field(default_factory=list)
    top_functions: list = field(default_factory=list)
    verdict: str = ""
    confirmed: int = 0
    seconds: float = 0.0
    error: str = ""

    def as_dict(self) -> dict:
        return {"incident": self.incident, "name": self.name,
                "chain_id": self.chain_id, "address": self.address,
                "source_available": self.source_available,
                "compiled": self.compiled, "n_findings": self.n_findings,
                "finding_types": self.finding_types,
                "top_functions": self.top_functions, "verdict": self.verdict,
                "confirmed": self.confirmed, "seconds": self.seconds,
                "error": self.error or None}


def run_incident(inc: Incident, *, cache_dir: str, allow_fetch: bool = True,
                 budget_findings: int = 8) -> DetectionResult:
    """Fetch the pre-attack verified source and run Deep Hunt over it."""
    from . import bench_dvbench as BD
    from . import findings as F
    from .hunt import HuntInputs, run as run_hunt

    res = DetectionResult(incident=inc.id, name=inc.name,
                          chain_id=inc.chain_id, address=inc.address)
    if not (inc.address and inc.chain_id):
        res.error = "no vulnerable address / chain in the PoC header"
        return res

    case = {"chain_id": inc.chain_id, "target_contract": inc.address}
    src = BD.load_source(case, "", cache_dir=cache_dir, allow_fetch=allow_fetch)
    if src is None:
        res.error = "no verified source (Sourcify)"
        return res
    res.source_available = True

    t0 = time.time()
    try:
        hr = run_hunt(HuntInputs(
            source=src["source_files"], target_contract=src.get("name", ""),
            chain_id=inc.chain_id, block_number=inc.block_number,
            address=inc.address, budget_findings=budget_findings,
            compiler_version=src.get("compiler_version", "")))
    except Exception as exc:  # noqa: BLE001
        res.error = f"{type(exc).__name__}: {exc}"[:200]
        res.seconds = round(time.time() - t0, 1)
        return res

    res.seconds = round(time.time() - t0, 1)
    res.compiled = bool(hr.model and hr.model.compiled)
    res.verdict = hr.verdict
    live = [f for f in hr.findings if f.confidence != F.REJECTED]
    res.n_findings = len(live)
    res.finding_types = sorted({f.finding_type for f in live})
    res.top_functions = [f"{f.contract}.{f.function}" for f in live[:5]]
    res.confirmed = sum(1 for f in live if f.confidence == F.CONFIRMED)
    return res


@dataclass
class DetectionReport:
    total_incidents: int = 0
    in_scope: int = 0
    out_of_scope: int = 0
    out_of_scope_by_label: dict = field(default_factory=dict)
    attempted: int = 0
    source_available: int = 0
    compiled: int = 0
    with_findings: int = 0
    confirmed: int = 0
    errors: int = 0
    results: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"total_incidents": self.total_incidents,
                "in_scope": self.in_scope, "out_of_scope": self.out_of_scope,
                "out_of_scope_by_label": self.out_of_scope_by_label,
                "attempted": self.attempted,
                "source_available": self.source_available,
                "compiled": self.compiled, "with_findings": self.with_findings,
                "confirmed": self.confirmed, "errors": self.errors,
                "results": [r.as_dict() for r in self.results]}

    def render(self) -> str:
        def pct(a, b):
            return f"{100.0 * a / b:.1f}%" if b else "n/a"
        return "\n".join([
            "CHAINWATCH vs DeFiHackLabs - detection pass", "=" * 43, "",
            f"  incidents in corpus     {self.total_incidents}",
            f"  out of scope            {self.out_of_scope}   "
            f"(key compromise / rug / social / off-chain)",
            *[f"      {k:<34} {v}"
              for k, v in sorted(self.out_of_scope_by_label.items())],
            f"  IN SCOPE (source-level) {self.in_scope}", "",
            f"  attempted               {self.attempted}",
            f"  verified source found   {self.source_available}   "
            f"({pct(self.source_available, self.attempted)} of attempted)",
            f"  modelled (compiled)     {self.compiled}   "
            f"({pct(self.compiled, self.source_available)} of source-available)",
            f"  produced >=1 finding    {self.with_findings}   "
            f"({pct(self.with_findings, self.compiled)} of modelled)",
            f"  reached CONFIRMED       {self.confirmed}   "
            f"(source-only: expected 0 - no deployment proof, no reproducer)",
            f"  errors                  {self.errors}",
        ])


def run_detection(repo_root: str, *, cache_dir: str,
                  limit: Optional[int] = None, scope: str = IN_SCOPE,
                  allow_fetch: bool = True, budget_findings: int = 8,
                  on_result=None) -> DetectionReport:
    incidents = load_incidents(repo_root)
    rep = DetectionReport(total_incidents=len(incidents))
    for i in incidents:
        if i.scope == OUT_OF_SCOPE:
            rep.out_of_scope += 1
            label = i.scope_reason.split(":", 1)[0]
            rep.out_of_scope_by_label[label] = \
                rep.out_of_scope_by_label.get(label, 0) + 1
        else:
            rep.in_scope += 1

    todo = [i for i in incidents if scope in ("", i.scope)]
    if limit:
        todo = todo[:limit]
    for inc in todo:
        r = run_incident(inc, cache_dir=cache_dir, allow_fetch=allow_fetch,
                         budget_findings=budget_findings)
        rep.attempted += 1
        rep.source_available += int(r.source_available)
        rep.compiled += int(r.compiled)
        rep.with_findings += int(r.n_findings > 0)
        rep.confirmed += int(r.confirmed > 0)
        rep.errors += int(bool(r.error) and r.source_available)
        rep.results.append(r)
        if on_result:
            on_result(r)
    return rep


def write_report(rep: DetectionReport, path: str) -> None:
    Path(path).write_text(json.dumps(rep.as_dict(), indent=1, default=str),
                          encoding="utf-8")
