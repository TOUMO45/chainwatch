"""Deployment-aware security (spec §10).

A vulnerability in an old implementation is not automatically relevant. Given a
proxy / clone / plain address, decide whether the VULNERABLE implementation is
what is served RIGHT NOW:

    is this a proxy?  what does it point to?  is that the vulnerable impl?
    can it still be upgraded?  is the vulnerable function exposed?

`src/liveness.resolve_implementation` already does the on-chain resolution
(EIP-1967 / beacon / EIP-1167 clone / legacy). This module turns its output
into a `target_live` gate result, and the pure `assess` core is testable
without a network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import state as S

_ZERO40 = "0" * 40


@dataclass
class DeploymentFacts:
    address: str
    proxy_kind: str = "unknown"
    current_impl: Optional[str] = None
    admin: Optional[str] = None
    upgradeable: Optional[bool] = None
    vulnerable_impl: Optional[str] = None
    serves_vulnerable: Optional[bool] = None
    gate: str = S.GATE_UNKNOWN
    rationale: str = ""

    def as_dict(self) -> dict:
        return {"address": self.address, "proxy_kind": self.proxy_kind,
                "current_impl": self.current_impl, "admin": self.admin,
                "upgradeable": self.upgradeable,
                "vulnerable_impl": self.vulnerable_impl,
                "serves_vulnerable": self.serves_vulnerable,
                "gate": self.gate, "rationale": self.rationale}

    def render_text(self) -> str:
        return "\n".join([
            "DEPLOYMENT-AWARE SECURITY (spec §10)", "=" * 35, "",
            f"  address        : {self.address}",
            f"  proxy kind     : {self.proxy_kind}",
            f"  current impl   : {self.current_impl}",
            f"  upgradeable    : {self.upgradeable}",
            f"  vulnerable impl: {self.vulnerable_impl}",
            f"  serves vuln    : {self.serves_vulnerable}",
            "",
            f"  gate: {self.gate}  -  {self.rationale}",
        ])


def _norm(a: Optional[str]) -> Optional[str]:
    if not a:
        return None
    a = str(a).lower()
    if a.startswith("0x"):
        a = a[2:]
    return a[-40:] if len(a) >= 40 else a


def assess(resolution: dict, *, vulnerable_impl: Optional[str] = None,
           liveness_verdict: Optional[str] = None) -> DeploymentFacts:
    """`resolution` is `src.liveness.resolve_implementation` output (a dict with
    `proxy_kind`, `target`, `slots`, ...)."""
    addr = resolution.get("address", "")
    kind = resolution.get("proxy_kind", "unknown")
    target = resolution.get("target")
    facts = DeploymentFacts(address=addr, proxy_kind=kind, current_impl=target,
                            vulnerable_impl=vulnerable_impl)

    slots = resolution.get("slots") or {}
    admin_raw = slots.get("eip1967.admin")
    if admin_raw:
        admin = "0x" + str(admin_raw)[-40:]
        facts.admin = admin
        facts.upgradeable = _norm(admin) not in (None, _ZERO40)
    elif kind in ("eip1967", "eip1967-beacon", "zeppelinos-legacy"):
        facts.upgradeable = True
    elif kind in ("eip1167-clone", "none"):
        facts.upgradeable = False

    if kind == "not-a-contract":
        facts.serves_vulnerable = False
        facts.gate = S.FAIL
        facts.rationale = "no code at the address - nothing is deployed here"
        return facts

    if target is None:
        facts.gate = S.GATE_UNKNOWN
        facts.rationale = "the implementation behind this address could not be " \
                          "resolved"
        return facts

    if vulnerable_impl is not None:
        same = _norm(target) == _norm(vulnerable_impl)
        facts.serves_vulnerable = same
        if same:
            facts.gate = S.PASS
            facts.rationale = ("the address currently serves the vulnerable "
                               "implementation")
        else:
            facts.gate = S.FAIL
            facts.rationale = (f"the address now serves {target}, not the "
                               f"vulnerable {vulnerable_impl} - the regression "
                               f"is not live here")
        return facts

    # No explicit vulnerable-impl address: fall back to the liveness verdict,
    # which compared the *artifact* bytecode.
    lv = (liveness_verdict or "").upper()
    if lv == "LIVE":
        facts.serves_vulnerable = True
        facts.gate = S.PASS
        facts.rationale = ("liveness proved the vulnerable build's bytecode is "
                           "what executes here"
                           + ("; an EIP-1167 clone's implementation is immutable"
                              if kind == "eip1167-clone" else ""))
    elif lv == "PATCHED":
        facts.serves_vulnerable = False
        facts.gate = S.FAIL
        facts.rationale = "liveness shows different code executes here now"
    else:
        facts.gate = S.GATE_UNKNOWN
        facts.rationale = ("cannot establish whether the vulnerable code is "
                           "what is served (no impl address, no LIVE/PATCHED)")
    return facts


def run(address: str, *, vulnerable_impl: Optional[str] = None,
        artifact_runtime_hex: Optional[str] = None,
        rpc_url: Optional[str] = None, block: str = "latest") -> DeploymentFacts:
    """Live path. Any failure -> UNKNOWN gate, never a wrong verdict."""
    try:
        from src import liveness as L
        w3 = L._w3(rpc_url)
        resolution = L.resolve_implementation(w3, address, block)
    except Exception as exc:  # noqa: BLE001
        f = DeploymentFacts(address=address)
        f.gate = S.GATE_UNKNOWN
        f.rationale = f"on-chain resolution unavailable: {type(exc).__name__}"
        return f

    liveness_verdict = None
    if artifact_runtime_hex and vulnerable_impl is None:
        try:
            from src import liveness as L
            res = L.check_against_artifact(address, artifact_runtime_hex,
                                          rpc_url=rpc_url)
            liveness_verdict = getattr(res, "verdict", None)
        except Exception:  # noqa: BLE001
            liveness_verdict = None

    return assess(resolution, vulnerable_impl=vulnerable_impl,
                  liveness_verdict=liveness_verdict)
