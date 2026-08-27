"""Capability 13 - live one-shot-exposure probe.

Answers a DIFFERENT question from capability 11's liveness gate, and never
feeds the CONFIRMED/CANDIDATE verdict model (RULES.md's six required evidence
fields are untouched by this module - this is a separate, clearly labelled
signal, not a seventh field and not a shortcut into CONFIRMED):

    Is there a one-shot initializer / critical-config function, identified the
    same way Rule 3b identifies one, that is STILL CALLABLE on a live deployed
    contract right now - i.e. the one-shot window was never consumed?

This is a real, currently-active 2026 attack class this project had ZERO
coverage for before this module existed. Attackers scan continuously for
freshly-deployed-but-not-yet-initialized proxies (and EIP-2535 Diamond facets,
which carry the same shape) and race the legitimate deployer to call the
initializer first, planting a dormant backdoor that activates months later.
Kinto Protocol ($1.55M, 2025, still the named case in 2026 write-ups) and a
broader "Uninitialized Proxy Campaign" ($10M+ across protocols) are both this
exact mechanism.

Rule 3b already asks "was the guard ever REMOVED" - a HISTORICAL, source-diff
question, answered by walking commit history. This module asks "has anyone
actually CLAIMED the one-shot window yet" - a LIVE, present-tense, deployed-
state question, answered by asking the chain directly. The two are
independent: a contract can be exposed here while Rule 3b has nothing to
report, because the guard was never removed - it simply was never consumed.
Conversely a contract Rule 3b already flagged historically may show CLOSED
here if someone (attacker or legitimate deployer) has since called it.

METHOD: the exact technique this project used, by hand, to verify the real
88mph `NFT.init()` regression is still live on real mainnet contracts
(2026-08-26) - a real, read-only `eth_call` simulating the call, never a
guess and never a real transaction. Generalised here so any contract gets the
same check automatically, not just one hand-investigated case.

READ-ONLY, ALWAYS (CHARTER.md rule 5). This module issues exactly one JSON-RPC
method, eth_call - a pure simulation against the current chain state. It never
constructs, signs, or sends a transaction, and never loads a private key.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Optional

from web3 import Web3

OPEN = "OPEN"
CLOSED = "CLOSED"
UNKNOWN = "UNKNOWN"

_SIG_RE = re.compile(r"^[^(]+\(([^)]*)\)$")
_UINT_RE = re.compile(r"^u?int(\d*)$")

# A fixed, distinguishable, deliberately NON-ZERO 20-byte value. Non-zero
# matters: a probe that filled `address` arguments with the zero address could
# trip an unrelated `require(x != address(0))` guard and be misread as the
# one-shot guard itself closing the window - exactly the failure mode a naive
# all-zero-argument probe hits. Matches the dummy address used in this
# project's own manual 88mph verification, for continuity with that evidence.
_ADDR_DUMMY = "0x" + "ab" * 19 + "cd"
_SENDER_DUMMY = "0x" + "11" * 20


def dummy_abi_value(type_str: str):
    """A safe, non-zero dummy value for one Solidity ABI type - or `None` if
    this module does not know how to encode it.

    Deliberately narrow. An unsupported type must make `build_probe_calldata`
    refuse to build calldata at all, never guess at an encoding: the same
    "UNKNOWN beats a guess" discipline `liveness.py` already applies to
    liveness verdicts applies here to exposure verdicts. Arrays, tuples/structs
    and dynamic-length `bytes` are the common real-world cases left
    unsupported; a real-init-function signature carrying one is rare enough
    that reporting UNKNOWN rather than a wrong OPEN/CLOSED is the right trade.
    """
    t = type_str.strip()
    if t == "address":
        return Web3.to_checksum_address(_ADDR_DUMMY)
    if t == "bool":
        return True
    if t == "string":
        return "chainwatch-probe"
    if t == "bytes":
        return None
    if t.startswith("bytes") and t[5:].isdigit():
        n = int(t[5:])
        if 1 <= n <= 32:
            return (b"\xab" * n)
        return None
    m = _UINT_RE.match(t)
    if m:
        return 1
    return None


def build_probe_calldata(signature: str) -> Optional[bytes]:
    """4-byte selector + ABI-encoded dummy arguments for a
    `name(type1,type2,...)` signature string (the same format this project
    already carries as `Finding.signature` / Slither's `Function.full_name`).

    Returns `None` - never a best-effort guess - if the signature can't be
    parsed or any argument type isn't in `dummy_abi_value`'s supported set.
    """
    m = _SIG_RE.match(signature.strip())
    if not m:
        return None
    arg_str = m.group(1).strip()
    types = [t.strip() for t in arg_str.split(",")] if arg_str else []
    values = []
    for t in types:
        v = dummy_abi_value(t)
        if v is None:
            return None
        values.append(v)
    selector = Web3.keccak(text=signature)[:4]
    if not types:
        return selector
    from eth_abi import encode as abi_encode
    return selector + abi_encode(types, values)


@dataclass
class ExposureResult:
    status: str
    contract: str
    function: str
    signature: str
    address: str
    reason: str = ""
    evidence: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def probe(w3: Web3, address: str, contract: str, function: str, signature: str,
          sender: Optional[str] = None) -> ExposureResult:
    """Read-only `eth_call` simulating a call to `signature` on `address`.

    OPEN    the simulated call did NOT revert: the one-shot window is
            exploitable right now, by anyone, verified rather than inferred.
    CLOSED  the simulated call reverted: consistent with the guard having
            already fired (already initialized). Not proof of safety in the
            fully general case - an unrelated `require` could also revert -
            but a revert on a real one-shot-guard candidate, identified the
            same way Rule 3b identifies one, is the expected shape of
            "already consumed".
    UNKNOWN calldata could not be built (unsupported argument type) or the
            call itself could not be attempted (RPC error). Never silently
            reported as CLOSED - an unreachable check is not a safe one.
    """
    calldata = build_probe_calldata(signature)
    if calldata is None:
        return ExposureResult(UNKNOWN, contract, function, signature, address,
                              reason="could not build calldata for this "
                                     "signature (unsupported argument type) - "
                                     "not checked, not assumed safe")
    try:
        addr = Web3.to_checksum_address(address)
        frm = Web3.to_checksum_address(sender) if sender else Web3.to_checksum_address(
            _SENDER_DUMMY)
    except Exception as exc:  # noqa: BLE001
        return ExposureResult(UNKNOWN, contract, function, signature, address,
                              reason=f"bad address: {exc}"[:200])
    try:
        w3.eth.call({"to": addr, "from": frm, "data": calldata})
        return ExposureResult(OPEN, contract, function, signature, address,
                              reason="simulated call did not revert - the "
                                     "one-shot window is still open",
                              evidence={"calldata_len": len(calldata)})
    except Exception as exc:  # noqa: BLE001 - a revert IS the expected "closed" signal
        msg = str(exc)
        return ExposureResult(CLOSED, contract, function, signature, address,
                              reason=f"simulated call reverted: {msg}"[:300])


def find_candidates(slither_obj, source_path: Optional[str] = None) -> list:
    """Every (contract, function) this project would already call, via Rule
    3b's own `_contract_initializer`, the contract's critical-config
    initializer - reused here for a live check instead of a historical diff.
    Same identification criteria RULES.md documents for Rule 3b Trigger 1:
    `has_init_guard(fn) and _sets_critical_config(fn, contract)`. Test/mock
    paths and library code (node_modules) excluded, matching every other
    rule's convention.

    `source_path`: the REPO-RELATIVE path the caller already knows (`rel` in
    scan.py's pair loop), passed through to `is_test_path_segments` exactly
    the way seven of the ten shipped rules already do. Falls back to the
    absolute filesystem path only when the caller has none to give - and that
    fallback is a real, measured hazard (3x-L1), not a neutral default: this
    project's OWN real-world-testing convention checks every target out under
    a directory literally named `realworld-test/`, so an absolute-path
    fallback silently discards every candidate found there. Reproduced
    directly on a real 2026 target (Kinto's `BridgedToken.initialize`) before
    this parameter existed - `find_candidates` returned empty on a function
    manually confirmed, moments earlier, to satisfy every one of Rule 3b's
    own criteria.
    """
    from .rules._shared import declared_in_repo, is_test_path_segments
    from .rules.rule3b import _contract_initializer

    out = []
    seen = set()
    for contract in slither_obj.contracts_derived:
        if getattr(contract, "is_interface", False) or not contract.functions:
            continue
        fn = _contract_initializer(contract)
        if fn is None or not declared_in_repo(fn):
            continue
        path = source_path or str(
            fn.contract_declarer.source_mapping.filename.absolute).replace("\\", "/")
        if is_test_path_segments(path):
            continue
        key = (contract.name, fn.full_name)
        if key in seen:
            continue
        seen.add(key)
        out.append((contract, fn))
    return out
