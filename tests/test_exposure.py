"""Unit tests for `src/exposure.py` — capability 13, the live one-shot-
exposure probe.

Fast where possible (pure calldata-building logic, no compile, no network); a
handful of tests compile a real, existing, frozen fixture
(`fixtures/positive/P3b-01/before.sol`, read-only, not modified) to prove
`find_candidates` identifies a real one-shot initializer the same way Rule 3b
already does, and `probe` is exercised against a stub Web3 object so the
OPEN/CLOSED/UNKNOWN branches are locked without needing a live RPC endpoint.

Run:  python -m pytest tests/test_exposure.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import exposure as E  # noqa: E402
from src.rules import _shared  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
P3B_01_BEFORE = ROOT / "fixtures" / "positive" / "P3b-01" / "before.sol"

# `scan._apply_build_config` REASSIGNS the module-level `_shared.REMAPS`
# default to whatever the last-scanned commit's dependency tree was (not
# merely `register_root`'s per-checkout override) - so any earlier
# scan-driving test in the same pytest process can leave the "default" REMAPS
# pointing at a since-deleted worktree, and a fixture parsed after that point
# fails with a bare "File not found" that has nothing to do with the fixture
# itself. Captured here, at collection time - before any test function body
# has run and had the chance to mutate it - which is the one point in the
# process this module can be sure still holds the real default.
_ORIGINAL_REMAPS = list(_shared.REMAPS)


# --------------------------------------------------------------- calldata


def test_dummy_abi_value_supported_types():
    assert E.dummy_abi_value("address").startswith("0x")
    assert E.dummy_abi_value("bool") is True
    assert E.dummy_abi_value("string") == "chainwatch-probe"
    assert E.dummy_abi_value("uint256") == 1
    assert E.dummy_abi_value("uint8") == 1
    assert E.dummy_abi_value("bytes32") == b"\xab" * 32


def test_dummy_abi_value_unsupported_types_return_none():
    """Never guess: an array, a struct/tuple, or dynamic bytes must refuse,
    not silently encode something wrong."""
    assert E.dummy_abi_value("uint256[]") is None
    assert E.dummy_abi_value("address[3]") is None
    assert E.dummy_abi_value("bytes") is None
    assert E.dummy_abi_value("tuple(address,uint256)") is None


def test_build_probe_calldata_matches_real_88mph_signature():
    """The exact signature this project hand-verified live on real mainnet
    contracts, 2026-08-26 (`0xF0b7DE...`): `init(address,string,string)`.
    Locks that this module can reconstruct the same calldata shape used in
    that manual investigation, not just plausible-looking bytes."""
    calldata = E.build_probe_calldata("init(address,string,string)")
    assert calldata is not None
    assert len(calldata) % 32 == 4        # selector + whole 32-byte ABI words, always
    assert len(calldata) > 4              # real args were actually encoded, not skipped
    from web3 import Web3
    assert calldata[:4] == Web3.keccak(text="init(address,string,string)")[:4]


def test_build_probe_calldata_no_args():
    calldata = E.build_probe_calldata("initialize()")
    assert calldata is not None
    assert len(calldata) == 4


def test_build_probe_calldata_unsupported_arg_returns_none():
    assert E.build_probe_calldata("initialize(uint256[])") is None


def test_build_probe_calldata_malformed_signature_returns_none():
    assert E.build_probe_calldata("not a signature") is None


# --------------------------------------------------------------- probe()


class _FakeEth:
    def __init__(self, should_revert: bool):
        self.should_revert = should_revert
        self.last_call = None

    def call(self, tx):
        self.last_call = tx
        if self.should_revert:
            raise Exception("execution reverted: Initializable: contract is already initialized")
        return b""


class _FakeW3:
    def __init__(self, should_revert: bool):
        self.eth = _FakeEth(should_revert)


def test_probe_open_when_call_does_not_revert():
    w3 = _FakeW3(should_revert=False)
    res = E.probe(w3, "0xF0b7DE03134857391d8D43Ed48e20EDF21461097", "NFT", "init",
                  "init(address,string,string)")
    assert res.status == E.OPEN
    assert "still open" in res.reason


def test_probe_closed_when_call_reverts():
    w3 = _FakeW3(should_revert=True)
    res = E.probe(w3, "0xF0b7DE03134857391d8D43Ed48e20EDF21461097", "Vault", "initialize",
                  "initialize(address,address)")
    assert res.status == E.CLOSED
    assert "reverted" in res.reason


def test_probe_unknown_when_calldata_cannot_be_built():
    """Must never fall through to a real eth_call attempt with wrong/guessed
    calldata for an unsupported type - UNKNOWN, and the fake RPC must not even
    be touched."""
    w3 = _FakeW3(should_revert=False)
    res = E.probe(w3, "0xF0b7DE03134857391d8D43Ed48e20EDF21461097", "X", "initialize",
                  "initialize(uint256[])")
    assert res.status == E.UNKNOWN
    assert w3.eth.last_call is None


def test_probe_sends_nonzero_address_argument():
    """Regression guard for the exact failure mode this module exists to
    avoid: a naive all-zero-argument probe could trip an unrelated
    `require(x != address(0))` and be misread as the guard itself firing."""
    w3 = _FakeW3(should_revert=False)
    E.probe(w3, "0xF0b7DE03134857391d8D43Ed48e20EDF21461097", "Vault", "initialize",
           "initialize(address,address)")
    calldata = w3.eth.last_call["data"]
    assert calldata[4:36] != b"\x00" * 32   # first address argument is not the zero address


# --------------------------------------------------------------- find_candidates()


@pytest.mark.skipif(not P3B_01_BEFORE.is_file(), reason="frozen fixture not present")
def test_find_candidates_identifies_the_real_p3b01_initializer():
    """`fixtures/positive/P3b-01/before.sol` (frozen, read-only, unmodified by
    this test) declares `Vault.initialize(address,address) external
    initializer`, which sets `_owner` via `_transferOwnership` - exactly Rule
    3b's own `has_init_guard` + critical-config-write criteria. This is the
    same fixture Rule 3b's own suite already trusts; reusing it here proves
    `find_candidates` calls the SAME identification Rule 3b does, not a
    reimplementation that happens to agree on this one case."""
    _shared.reset_caches()
    _shared.clear_roots()
    _shared.REMAPS = list(_ORIGINAL_REMAPS)
    slither_obj = _shared.parse(P3B_01_BEFORE)
    candidates = E.find_candidates(slither_obj)
    names = {(c.name, fn.name) for c, fn in candidates}
    assert ("Vault", "initialize") in names


@pytest.mark.skipif(not P3B_01_BEFORE.is_file(), reason="frozen fixture not present")
def test_find_candidates_signature_is_probe_buildable():
    """The signature `find_candidates` reports for the real fixture must
    itself survive `build_probe_calldata` - the whole point of reusing Rule
    3b's own function object is that its `full_name` is exactly what a real
    probe would be built from."""
    _shared.reset_caches()
    _shared.clear_roots()
    _shared.REMAPS = list(_ORIGINAL_REMAPS)
    slither_obj = _shared.parse(P3B_01_BEFORE)
    candidates = E.find_candidates(slither_obj)
    vault_fn = next(fn for c, fn in candidates if c.name == "Vault")
    calldata = E.build_probe_calldata(vault_fn.full_name)
    assert calldata is not None
