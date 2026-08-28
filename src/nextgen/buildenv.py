"""Compiler / build-environment security (spec §19).

The build environment is part of the security model. A historical commit must be
compiled with the environment appropriate to THAT commit - not silently rebuilt
with a modern compiler and then treated as authoritative. And a finding's
bytecode-provenance claim (spec §9) is only as good as the match between the
settings under analysis and the settings the chain actually executed.

This module encodes the five representative compiler-version-risk patterns as
pure predicates over a `BuildContext`:

  1. RANGE_PRAGMA        the pragma is not exact (`^`, `>=`, `<`, `-`), so the
                         tested build and the deployed build need not be the
                         same compiler at all.
  2. HISTORICAL_MISMATCH the version used for analysis (or deployment) differs
                         from what the commit pins, across a solc boundary
                         where semantics changed (0.5.0 visibility, 0.6.0
                         `abstract`/`virtual`/`override`, 0.7.0 arithmetic &
                         `now`, 0.8.0 checked arithmetic, 0.8.20 default EVM).
  3. KNOWN_BUGGY_COMPILER the resolved compiler matches a documented Solidity
                         advisory, optionally gated on a trigger (`--via-ir`,
                         ABIEncoderV2).
  4. EVM_VERSION_DRIFT   `evmVersion` differs between analysis and deployment,
                         or the default changed across the solc range in play
                         (Shanghai / PUSH0 at 0.8.20+), so the target chain's
                         support is uncertain.
  5. OPTIMIZER_DRIFT     optimizer enabled / runs / `viaIR` differ between the
                         build under analysis and the deployed/verified build,
                         which alone makes the bytecode differ.

`analyze()` returns a report whose `gate` is PASS / FAIL / UNKNOWN for the
`build_environment` gate in `state.py`. It is deliberately conservative: it
returns FAIL only for a drift it can prove against known deployment settings,
PASS only for an exact, matching build, and UNKNOWN otherwise.

The advisory list is NON-EXHAUSTIVE by design - the authoritative source is the
Solidity team's own bug list. This module checks the *mechanism* (build env vs
advisories vs deployment), not every historical bug.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from . import state as S

# --------------------------------------------------------------------------- #
# risk-pattern ids
# --------------------------------------------------------------------------- #

RANGE_PRAGMA = "RANGE_PRAGMA"
HISTORICAL_MISMATCH = "HISTORICAL_MISMATCH"
KNOWN_BUGGY_COMPILER = "KNOWN_BUGGY_COMPILER"
EVM_VERSION_DRIFT = "EVM_VERSION_DRIFT"
OPTIMIZER_DRIFT = "OPTIMIZER_DRIFT"

RISK_PATTERNS: tuple[str, ...] = (
    RANGE_PRAGMA, HISTORICAL_MISMATCH, KNOWN_BUGGY_COMPILER,
    EVM_VERSION_DRIFT, OPTIMIZER_DRIFT,
)

# solc semantic boundaries: crossing one of these between "pinned" and "used"
# changes what the same source MEANS.
SEMANTIC_BOUNDARIES: tuple[tuple[tuple[int, int, int], str], ...] = (
    ((0, 5, 0), "explicit function visibility became mandatory; `constructor` "
                "keyword; byte[] -> bytes"),
    ((0, 6, 0), "`abstract` / `virtual` / `override`; array `.length` no "
                "longer assignable; `try/catch`"),
    ((0, 7, 0), "`now` removed; exponentiation right-associative; stricter "
                "conversions; `wei`/`gwei` only"),
    ((0, 8, 0), "checked arithmetic by default (over/underflow reverts); "
                "explicit `unchecked{}` required for wraparound"),
    ((0, 8, 20), "default target EVM became Shanghai - emits PUSH0, which "
                 "pre-Shanghai chains reject"),
)

# Documented Solidity advisories. `trigger`: None = always; a string = only when
# that build feature is on. Conservative subset; see module docstring.
@dataclass(frozen=True)
class Advisory:
    id: str
    lo: tuple[int, int, int]        # inclusive
    hi: tuple[int, int, int]        # inclusive
    trigger: Optional[str]          # None | "via_ir" | "abiencoderv2"
    summary: str
    fixed_in: str


ADVISORIES: tuple[Advisory, ...] = (
    Advisory("via-ir-inline-asm-memory-2022", (0, 8, 13), (0, 8, 14), "via_ir",
             "optimizer dropped memory side effects of inline assembly under "
             "--via-ir", "0.8.15"),
    Advisory("abiencoderv2-calldata-head-overflow", (0, 5, 8), (0, 8, 15), "abiencoderv2",
             "ABI ABIEncoderV2 calldata tuple head-overflow read", "0.8.16"),
    Advisory("nested-calldata-array-abiencoderv2", (0, 6, 0), (0, 8, 15), "abiencoderv2",
             "wrong data read for nested calldata arrays with ABIEncoderV2",
             "0.8.16"),
    Advisory("storage-write-removal-0.8.13", (0, 8, 13), (0, 8, 16), "via_ir",
             "conditional storage writes wrongly removed by the via-IR "
             "optimizer", "0.8.17"),
)

_VER = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_PRAGMA_RANGE_TOKENS = ("^", "~", ">", "<", " - ", "||", "x", "*")


def parse_version(v: Optional[str]) -> Optional[tuple[int, int, int]]:
    if not v:
        return None
    m = _VER.search(str(v))
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def is_range_pragma(pragma_expr: Optional[str]) -> bool:
    """True if the pragma admits more than one compiler version."""
    if not pragma_expr:
        return False
    e = pragma_expr.strip()
    e = e.replace("pragma solidity", "").replace(";", "").strip()
    if any(tok in e for tok in _PRAGMA_RANGE_TOKENS):
        return True
    # a bare, fully-qualified "0.8.20" is exact; "0.8" is not
    return parse_version(e) is None


def crossed_boundaries(a: Optional[tuple[int, int, int]],
                       b: Optional[tuple[int, int, int]]
                       ) -> list[tuple[tuple[int, int, int], str]]:
    """Semantic boundaries strictly between versions a and b (order-independent)."""
    if not a or not b:
        return []
    lo, hi = sorted((a, b))
    return [(bnd, desc) for bnd, desc in SEMANTIC_BOUNDARIES if lo < bnd <= hi]


def matching_advisories(ver: Optional[tuple[int, int, int]], *,
                        via_ir: bool = False,
                        abiencoderv2: bool = False) -> list[Advisory]:
    if not ver:
        return []
    active = {"via_ir": via_ir, "abiencoderv2": abiencoderv2}
    out = []
    for adv in ADVISORIES:
        if not (adv.lo <= ver <= adv.hi):
            continue
        if adv.trigger and not active.get(adv.trigger, False):
            continue
        out.append(adv)
    return out


@dataclass
class BuildContext:
    """Everything known about how a commit's code is/was built. All optional;
    partial information degrades to UNKNOWN, never to a false PASS."""

    pragma_expr: Optional[str] = None
    pinned_solc: Optional[str] = None          # what the commit pins (lockfile / exact pragma)
    analysis_solc: Optional[str] = None        # what Chainwatch compiled with
    deployed_solc: Optional[str] = None        # from Sourcify / verified.py

    analysis_evm: Optional[str] = None
    deployed_evm: Optional[str] = None

    analysis_optimizer: Optional[bool] = None
    analysis_runs: Optional[int] = None
    analysis_via_ir: Optional[bool] = None

    deployed_optimizer: Optional[bool] = None
    deployed_runs: Optional[int] = None
    deployed_via_ir: Optional[bool] = None

    uses_abiencoderv2: bool = False


@dataclass
class RiskHit:
    pattern: str
    severity: str                    # "blocking" | "advisory"
    summary: str
    detail: str = ""

    def as_dict(self) -> dict:
        return {"pattern": self.pattern, "severity": self.severity,
                "summary": self.summary, "detail": self.detail}


@dataclass
class BuildEnvReport:
    hits: list[RiskHit] = field(default_factory=list)
    gate: str = S.GATE_UNKNOWN
    rationale: str = ""

    @property
    def blocking(self) -> list[RiskHit]:
        return [h for h in self.hits if h.severity == "blocking"]

    def as_dict(self) -> dict:
        return {"gate": self.gate, "rationale": self.rationale,
                "hits": [h.as_dict() for h in self.hits]}

    def render_text(self) -> str:
        lines = ["BUILD-ENVIRONMENT SECURITY (spec §19)", "=" * 37, "",
                 f"  gate: {self.gate}  -  {self.rationale}", ""]
        if not self.hits:
            lines.append("  no compiler-version-risk pattern matched")
        for h in self.hits:
            lines.append(f"  [{h.severity.upper()}] {h.pattern}")
            lines.append(f"      {h.summary}")
            if h.detail:
                lines.append(f"      {h.detail}")
        return "\n".join(lines)


def analyze(ctx: BuildContext) -> BuildEnvReport:
    """Evaluate the five risk patterns and pick a gate result."""
    hits: list[RiskHit] = []

    pinned = parse_version(ctx.pinned_solc) or _from_pragma(ctx.pragma_expr)
    used = parse_version(ctx.analysis_solc)
    deployed = parse_version(ctx.deployed_solc)

    # 1. RANGE_PRAGMA - advisory: it means a mismatch is *possible*.
    if is_range_pragma(ctx.pragma_expr):
        hits.append(RiskHit(
            RANGE_PRAGMA, "advisory",
            f"pragma {ctx.pragma_expr!r} is not exact",
            "the build under analysis and the deployed build may be different "
            "compilers; provenance cannot be assumed from source alone"))

    # 2. HISTORICAL_MISMATCH - blocking when a semantic boundary was crossed.
    for other, label in ((used, "analysis"), (deployed, "deployment")):
        crossed = crossed_boundaries(pinned, other)
        if crossed:
            descs = "; ".join(d for _, d in crossed)
            hits.append(RiskHit(
                HISTORICAL_MISMATCH, "blocking",
                f"{label} compiler {_fmt(other)} is across a semantic boundary "
                f"from the pinned {_fmt(pinned)}",
                descs))

    # 3. KNOWN_BUGGY_COMPILER - blocking if the compiler ACTUALLY used matches.
    for adv in matching_advisories(used, via_ir=bool(ctx.analysis_via_ir),
                                   abiencoderv2=ctx.uses_abiencoderv2):
        hits.append(RiskHit(
            KNOWN_BUGGY_COMPILER, "blocking",
            f"analysis compiler {_fmt(used)} matches advisory {adv.id}",
            f"{adv.summary}; fixed in {adv.fixed_in}"))
    for adv in matching_advisories(deployed, via_ir=bool(ctx.deployed_via_ir),
                                   abiencoderv2=ctx.uses_abiencoderv2):
        hits.append(RiskHit(
            KNOWN_BUGGY_COMPILER, "advisory",
            f"deployed compiler {_fmt(deployed)} matches advisory {adv.id}",
            f"{adv.summary}; fixed in {adv.fixed_in}"))

    # 4. EVM_VERSION_DRIFT
    if ctx.analysis_evm and ctx.deployed_evm and \
            ctx.analysis_evm.lower() != ctx.deployed_evm.lower():
        hits.append(RiskHit(
            EVM_VERSION_DRIFT, "blocking",
            f"evmVersion differs: analysis={ctx.analysis_evm}, "
            f"deployed={ctx.deployed_evm}",
            "same source + different target EVM = different bytecode / opcodes"))
    elif (used and deployed and
          (used >= (0, 8, 20)) != (deployed >= (0, 8, 20)) and
          not (ctx.analysis_evm and ctx.deployed_evm)):
        hits.append(RiskHit(
            EVM_VERSION_DRIFT, "advisory",
            "one side is solc >= 0.8.20 (default target Shanghai / PUSH0) and "
            "the other is not",
            "confirm the target chain supports PUSH0, or pin evmVersion"))

    # 5. OPTIMIZER_DRIFT - blocking: bytecode cannot match if these differ.
    drift = _optimizer_drift(ctx)
    if drift:
        hits.append(RiskHit(OPTIMIZER_DRIFT, "blocking",
                            "optimizer settings differ between analysis and "
                            "deployment", drift))

    return _gate(ctx, hits, pinned, used, deployed)


def _gate(ctx: BuildContext, hits: list[RiskHit],
          pinned, used, deployed) -> BuildEnvReport:
    blocking = [h for h in hits if h.severity == "blocking"]
    if blocking:
        return BuildEnvReport(
            hits, S.FAIL,
            "a blocking build-environment risk was found: "
            + ", ".join(sorted({h.pattern for h in blocking})))

    # PASS only for an exact pragma, a compiler that matches what is pinned,
    # and - when deployment settings are known - a full match to them.
    exact = not is_range_pragma(ctx.pragma_expr)
    pin_ok = bool(pinned and used and pinned == used)
    if deployed is not None:
        # A PASS here claims the analysis build is PROVEN identical to the
        # deployed one, so every setting must be KNOWN and equal on both sides -
        # an absent optimizer record is "unproven", never "assumed matching".
        dep_ok = (used == deployed and
                  _known_eq(ctx.analysis_optimizer, ctx.deployed_optimizer) and
                  _known_eq(ctx.analysis_runs, ctx.deployed_runs) and
                  bool(ctx.analysis_via_ir) == bool(ctx.deployed_via_ir))
        if exact and pin_ok and dep_ok:
            return BuildEnvReport(hits, S.PASS,
                                  "exact pragma; analysis compiler and settings "
                                  "match both the pinned version and the "
                                  "deployed build")
        return BuildEnvReport(hits, S.GATE_UNKNOWN,
                              "no blocking risk, but the analysis build is not "
                              "proven identical to the deployed build")
    if exact and pin_ok:
        return BuildEnvReport(hits, S.PASS,
                              "exact pragma; analysis compiler matches the "
                              "pinned version (no deployment to compare)")
    return BuildEnvReport(hits, S.GATE_UNKNOWN,
                          "insufficient information to establish the build "
                          "environment")


def _optimizer_drift(ctx: BuildContext) -> str:
    bits = []
    if _differs(ctx.analysis_optimizer, ctx.deployed_optimizer):
        bits.append(f"enabled: analysis={ctx.analysis_optimizer}, "
                    f"deployed={ctx.deployed_optimizer}")
    if _differs(ctx.analysis_runs, ctx.deployed_runs):
        bits.append(f"runs: analysis={ctx.analysis_runs}, "
                    f"deployed={ctx.deployed_runs}")
    if _differs(ctx.analysis_via_ir, ctx.deployed_via_ir):
        bits.append(f"viaIR: analysis={ctx.analysis_via_ir}, "
                    f"deployed={ctx.deployed_via_ir}")
    return "; ".join(bits)


def _differs(a, b) -> bool:
    return a is not None and b is not None and a != b


def _same(a, b) -> bool:
    """True unless both are known and unequal (used for 'not contradictory')."""
    return a is None or b is None or a == b


def _known_eq(a, b) -> bool:
    """True only when both are known and equal (used for 'proven identical')."""
    return a is not None and b is not None and a == b


def _from_pragma(expr: Optional[str]) -> Optional[tuple[int, int, int]]:
    """The lower bound a pragma implies, when it is fully qualified."""
    if not expr:
        return None
    return parse_version(expr)


def _fmt(v: Optional[tuple[int, int, int]]) -> str:
    return "?" if not v else ".".join(str(x) for x in v)
