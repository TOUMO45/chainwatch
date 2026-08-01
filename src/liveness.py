"""Capability 11 - on-chain liveness. THE DECISIVE GATE (CHARTER.md).

Answers one question: is the code deployed at this address the code that a
given commit (or a given reference deployment) produces?

READ-ONLY, ALWAYS (CHARTER.md rule 5). This module issues exactly these
JSON-RPC methods: eth_chainId, eth_blockNumber, eth_getCode, eth_getStorageAt,
and eth_call for beacon resolution. It never constructs, signs, or sends a
transaction, and never loads a private key. There is no code path here that can
write to a chain.

--------------------------------------------------------------------------
COMPARISON METHOD: normalized runtime-bytecode identity
--------------------------------------------------------------------------
Naive byte-equality of eth_getCode against a compiled artifact fails for
several independent reasons. Each is handled explicitly rather than papered
over:

1. RUNTIME vs CREATION bytecode. eth_getCode returns *runtime* code; solc
   --bin emits *creation* code (constructor logic plus the runtime it returns).
   These are different artifacts and will never be equal. We compare against
   --bin-runtime, which is the matching one. Choosing runtime also makes
   problem 4 disappear entirely.

2. CBOR METADATA TRAILER. Solidity appends a CBOR blob (compiler version, and
   an ipfs/bzzr hash covering the *sources including comments*) plus a 2-byte
   big-endian length. It changes with compiler version, settings, and even a
   touched comment, so byte-equality essentially never holds across build
   environments. We split it off before comparing, and parse it for evidence -
   the deployed compiler version is recoverable from it.

3. IMMUTABLES are written into the runtime code at construction time. A
   compiled artifact carries zero-filled placeholders exactly where a deployed
   contract carries real values. solc reports these positions as
   immutableReferences; we zero those ranges on both sides before hashing.

4. CONSTRUCTOR ARGUMENTS are appended to *creation* bytecode. Because we
   compare runtime code, they are structurally absent. No handling needed.

5. PROXIES. For a proxy address, eth_getCode returns the PROXY's code, not the
   implementation's - so a naive check compares the wrong contract entirely and
   would be blind to every Rule 3 finding. We resolve the implementation first
   (EIP-1967 slot, beacon, EIP-1167 clone, legacy zeppelinos slot) and check
   THAT address.

--------------------------------------------------------------------------
VERDICT DISCIPLINE: UNKNOWN beats a guess
--------------------------------------------------------------------------
Confidence depends entirely on where the reference came from.

  * Reference is another DEPLOYED address (bytecode vs bytecode). Both sides
    were produced by whatever compiler actually built them; no recompilation is
    involved, so no build-settings ambiguity exists. LIVE and PATCHED are both
    trustworthy here.

  * Reference is COMPILED FROM SOURCE. A match still proves LIVE (identical
    normalized code cannot arise by accident). A MISMATCH is ambiguous: it is
    indistinguishable from a compiler-settings difference (optimizer runs,
    viaIR, evmVersion, library linking), none of which are recoverable from
    deployed bytecode. Reporting PATCHED there would be guessing, so this
    module returns UNKNOWN with the reason attached, unless the deployed
    metadata source hash proves an exact settings-and-sources match.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from typing import Optional

from dotenv import load_dotenv
from web3 import Web3

LIVE = "LIVE"
PATCHED = "PATCHED"
UNKNOWN = "UNKNOWN"

# EIP-1967 standardised slots.
EIP1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
EIP1967_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
# Pre-EIP-1967 OpenZeppelin/zeppelinos slot. Not academic: USDC still uses it.
ZEPPELINOS_IMPL = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"

ZERO_ADDR = "0x" + "0" * 40


@dataclass
class LivenessResult:
    verdict: str
    address: str
    target_address: Optional[str] = None
    proxy_kind: str = "none"
    reason: str = ""
    evidence: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _w3(rpc_url: Optional[str] = None) -> Web3:
    if rpc_url is None:
        load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))
        rpc_url = os.environ.get("RPC_URL")
    if not rpc_url:
        raise RuntimeError("RPC_URL not set (.env)")
    return Web3(Web3.HTTPProvider(rpc_url))


# ---------------------------------------------------------------- bytecode


def split_metadata(code: bytes) -> tuple[bytes, bytes]:
    """Split the trailing CBOR metadata off runtime bytecode.

    Layout: [...code...][cbor blob][2-byte big-endian length of blob].
    Returns (code_without_metadata, metadata_blob). If the trailer does not
    look like CBOR, the code is returned untouched.
    """
    if len(code) < 4:
        return code, b""
    length = int.from_bytes(code[-2:], "big")
    if length == 0 or length + 2 > len(code):
        return code, b""
    blob = code[-(length + 2):-2]
    # A CBOR map header is 0xa0..0xbf. Guards against a coincidental length.
    if not blob or not (0xA0 <= blob[0] <= 0xBF):
        return code, b""
    return code[: -(length + 2)], blob


def parse_metadata(blob: bytes) -> dict:
    """Best-effort extraction of evidence from the CBOR metadata blob.

    Deliberately a targeted scan rather than a full CBOR decoder: we only need
    the compiler version and the source hash, and a partial parse must never be
    able to change a verdict. This feeds the evidence record only.
    """
    out: dict = {}
    if not blob:
        return out
    idx = blob.find(b"solc")
    if idx != -1 and idx + 4 < len(blob):
        if blob[idx + 4] == 0x43 and idx + 8 <= len(blob):  # bytes(3) => x.y.z
            major, minor, patch = blob[idx + 5: idx + 8]
            out["solc_version"] = f"{major}.{minor}.{patch}"
    for key in (b"ipfs", b"bzzr0", b"bzzr1"):
        i = blob.find(key)
        if i != -1:
            j = i + len(key)
            if j < len(blob) and 0x58 <= blob[j] <= 0x5B:
                ln = blob[j + 1] if blob[j] == 0x58 else 32
                out["source_hash_kind"] = key.decode()
                out["source_hash"] = blob[j + 2: j + 2 + ln].hex()
            break
    return out


def mask_immutables(code: bytes, immutable_refs: Optional[dict]) -> bytes:
    """Zero every byte range solc reports as an immutable placeholder."""
    if not immutable_refs:
        return code
    buf = bytearray(code)
    for refs in immutable_refs.values():
        for ref in refs:
            start, length = int(ref["start"]), int(ref["length"])
            if start >= 0 and start + length <= len(buf):
                buf[start: start + length] = b"\x00" * length
    return bytes(buf)


def normalize(code: bytes, immutable_refs: Optional[dict] = None) -> dict:
    """Strip metadata, mask immutables, hash. Returns the whole picture so
    callers can show their work rather than a bare boolean."""
    stripped, blob = split_metadata(code)
    masked = mask_immutables(stripped, immutable_refs)
    return {
        "raw_len": len(code),
        "stripped_len": len(stripped),
        "metadata_len": len(blob),
        "metadata": parse_metadata(blob),
        "raw_keccak": Web3.keccak(code).hex(),
        "normalized_keccak": Web3.keccak(masked).hex(),
    }


# ------------------------------------------------------------------- proxy


def _eip1167_target(code: bytes) -> Optional[str]:
    """EIP-1167 minimal proxies carry the implementation inline, not in a slot."""
    h = code.hex()
    pre, post = "363d3d373d3d3d363d73", "5af43d82803e903d91602b57fd5bf3"
    i = h.find(pre)
    if i == -1:
        return None
    j = i + len(pre)
    if h[j + 40: j + 40 + len(post)] != post:
        return None
    return "0x" + h[j: j + 40]


def resolve_implementation(w3: Web3, address: str, block: str | int = "latest") -> dict:
    """Find what actually executes at `address`.

    Order matters: EIP-1967 first (the standard), then beacon, then EIP-1167
    clone (implementation embedded in code, no slot at all), then the legacy
    zeppelinos slot.
    """
    addr = Web3.to_checksum_address(address)
    out: dict = {"address": addr, "proxy_kind": "none", "target": addr, "slots": {}}

    code = w3.eth.get_code(addr, block_identifier=block)
    out["code_len"] = len(code)
    if len(code) == 0:
        out["proxy_kind"] = "not-a-contract"
        out["target"] = None
        return out

    for label, slot in (
        ("eip1967.implementation", EIP1967_IMPL),
        ("eip1967.beacon", EIP1967_BEACON),
        ("eip1967.admin", EIP1967_ADMIN),
        ("zeppelinos.implementation", ZEPPELINOS_IMPL),
    ):
        raw = w3.eth.get_storage_at(addr, slot, block_identifier=block)
        out["slots"][label] = "0x" + raw.hex()

    impl = "0x" + out["slots"]["eip1967.implementation"][-40:]
    if impl != ZERO_ADDR:
        out["proxy_kind"] = "eip1967"
        out["target"] = Web3.to_checksum_address(impl)
        return out

    beacon = "0x" + out["slots"]["eip1967.beacon"][-40:]
    if beacon != ZERO_ADDR:
        out["proxy_kind"] = "eip1967-beacon"
        out["beacon"] = Web3.to_checksum_address(beacon)
        try:  # implementation() - a read-only eth_call
            res = w3.eth.call(
                {"to": out["beacon"], "data": Web3.keccak(text="implementation()")[:4]},
                block_identifier=block,
            )
            out["target"] = Web3.to_checksum_address("0x" + res.hex()[-40:])
        except Exception as exc:
            out["target"] = None
            out["beacon_error"] = f"{type(exc).__name__}: {exc}"
        return out

    clone = _eip1167_target(code)
    if clone:
        out["proxy_kind"] = "eip1167-clone"
        out["target"] = Web3.to_checksum_address(clone)
        return out

    legacy = "0x" + out["slots"]["zeppelinos.implementation"][-40:]
    if legacy != ZERO_ADDR:
        out["proxy_kind"] = "zeppelinos-legacy"
        out["target"] = Web3.to_checksum_address(legacy)
        return out

    return out


# ---------------------------------------------------------------- verdicts


def _compare(deployed: dict, reference: dict, trusted: bool, source: str) -> tuple[str, str]:
    if deployed["normalized_keccak"] == reference["normalized_keccak"]:
        return LIVE, f"normalized runtime bytecode is identical to {source}"
    if trusted:
        return PATCHED, (
            f"normalized runtime bytecode differs from {source}; both sides are "
            "deployed artifacts, so the difference is real code, not a build artifact"
        )
    return UNKNOWN, (
        f"normalized runtime bytecode differs from {source}, but the reference was "
        "compiled locally. A mismatch cannot be distinguished from a compiler "
        "settings difference (optimizer runs, viaIR, evmVersion, library linking), "
        "so PATCHED would be a guess"
    )


def check_against_deployed(
    address: str,
    reference_address: str,
    rpc_url: Optional[str] = None,
    block: str | int = "latest",
) -> LivenessResult:
    """Is the code running at `address` the same as the code at
    `reference_address`? Both sides are real deployed artifacts, so both LIVE
    and PATCHED are trustworthy."""
    w3 = _w3(rpc_url)
    res = resolve_implementation(w3, address, block)
    ev: dict = {
        "chain_id": w3.eth.chain_id,
        "block": w3.eth.block_number if block == "latest" else block,
        "resolution": res,
    }
    if res["target"] is None:
        return LivenessResult(UNKNOWN, address, None, res["proxy_kind"],
                              "no implementation could be resolved", ev)

    dep_code = w3.eth.get_code(res["target"], block_identifier=block)
    ref_addr = Web3.to_checksum_address(reference_address)
    ref_code = w3.eth.get_code(ref_addr, block_identifier=block)
    if len(dep_code) == 0 or len(ref_code) == 0:
        return LivenessResult(UNKNOWN, address, res["target"], res["proxy_kind"],
                              "no code at implementation or reference address", ev)

    dep, ref = normalize(dep_code), normalize(ref_code)
    ev["deployed"] = dep
    ev["reference"] = ref
    ev["reference_address"] = ref_addr
    verdict, reason = _compare(dep, ref, trusted=True,
                               source=f"reference deployment {ref_addr}")
    return LivenessResult(verdict, address, res["target"], res["proxy_kind"], reason, ev)


def check_against_artifact(
    address: str,
    runtime_hex: str,
    immutable_refs: Optional[dict] = None,
    rpc_url: Optional[str] = None,
    block: str | int = "latest",
) -> LivenessResult:
    """Is the code running at `address` what this commit's source compiles to?

    `runtime_hex` must be RUNTIME bytecode (solc --bin-runtime). A mismatch
    yields UNKNOWN, not PATCHED - see the module docstring.
    """
    w3 = _w3(rpc_url)
    res = resolve_implementation(w3, address, block)
    ev: dict = {
        "chain_id": w3.eth.chain_id,
        "block": w3.eth.block_number if block == "latest" else block,
        "resolution": res,
    }
    if res["target"] is None:
        return LivenessResult(UNKNOWN, address, None, res["proxy_kind"],
                              "no implementation could be resolved", ev)

    dep_code = w3.eth.get_code(res["target"], block_identifier=block)
    if len(dep_code) == 0:
        return LivenessResult(UNKNOWN, address, res["target"], res["proxy_kind"],
                              "no code at implementation address", ev)

    raw = runtime_hex[2:] if runtime_hex.startswith("0x") else runtime_hex
    ref_code = bytes.fromhex(raw)
    dep = normalize(dep_code, immutable_refs)
    ref = normalize(ref_code, immutable_refs)
    ev["deployed"] = dep
    ev["reference"] = ref
    ev["immutables_masked"] = bool(immutable_refs)
    ev["solc_deployed"] = dep["metadata"].get("solc_version")
    ev["solc_reference"] = ref["metadata"].get("solc_version")

    dep_hash = dep["metadata"].get("source_hash")
    if dep_hash and dep_hash == ref["metadata"].get("source_hash"):
        # Exact metadata match: identical sources AND identical settings.
        return LivenessResult(LIVE, address, res["target"], res["proxy_kind"],
                              "metadata source hash matches exactly (full match: "
                              "same sources, same compiler settings)", ev)

    verdict, reason = _compare(dep, ref, trusted=False, source="the compiled artifact")
    d, r = ev["solc_deployed"], ev["solc_reference"]
    if verdict == UNKNOWN and d and r and d != r:
        reason += f"; deployed solc {d} != reference solc {r}"
    return LivenessResult(verdict, address, res["target"], res["proxy_kind"], reason, ev)
