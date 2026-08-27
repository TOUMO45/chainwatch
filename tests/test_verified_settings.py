"""Capability 17 - build the rebuild with the settings the deployment used.

11-R3 refuses to call a bytecode mismatch PATCHED, because a mismatch cannot be
distinguished from a compiler-settings difference. That is correct, and it is
also why liveness so often answers UNKNOWN: the settings were never knowable
locally, so they were guessed.

    optimizer runs    hardcoded 200
    optimizer on/off  assumed ALWAYS ON whenever runs were passed
    evmVersion        never set at all

MEASURED, on 88mph's real NFT source, that each guess changes the output:

    optimize ON  runs=200   sha a6dad442...  17,000 chars
    optimize OFF            sha bb601b93...  26,650 chars   <- 56% larger
    optimize ON  runs=999   sha 73cca44d...  17,500 chars
    evm=byzantium           does not compile at all

And on real mainnet contracts, that the guesses are sometimes simply wrong:

    88mph NFT  0.5.17  optimizer {runs 200, enabled True}   evm istanbul
    WETH9      0.4.19  optimizer {runs 200, enabled FALSE}  evm None

WETH is the proof: the old path would pass `--optimize`, rebuild bytecode the
deployment never had, and liveness could only ever answer UNKNOWN.

THIS CANNOT COST PRECISION. `check_against_artifact` still demands an exact
normalized match; supplying real settings only lets a rebuild that SHOULD match
actually match. Unknown fields fall back to the previous behaviour exactly, so
an unverified contract is no worse off than before.

No network: Sourcify is stubbed. Hitting a live third-party service from the
suite would make it flaky and slow for every future contributor.

Run:  python -m pytest tests/test_verified_settings.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import verified as VER  # noqa: E402


class _Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


_88MPH = {"compilation": {
    "compilerVersion": "0.5.17+commit.d19bba13", "name": "NFT",
    "compilerSettings": {"optimizer": {"runs": 200, "enabled": True},
                         "evmVersion": "istanbul"}}, "match": "exact_match"}

_WETH = {"compilation": {
    "compilerVersion": "0.4.19+commit.c4cbbb05", "name": "WETH9",
    "compilerSettings": {"optimizer": {"runs": 200, "enabled": False}}},
    "match": "match"}


@pytest.fixture(autouse=True)
def _clear():
    VER.clear_cache()
    yield
    VER.clear_cache()


def _stub(monkeypatch, resp):
    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: resp)


# ------------------------------------------------------------ parsing


def test_real_verified_settings_are_extracted(monkeypatch):
    _stub(monkeypatch, _Resp(200, _88MPH))
    r = VER.settings_for("0x" + "de" * 20)
    assert r["found"] is True
    assert r["compiler_version"] == "0.5.17"     # commit hash stripped
    assert r["optimize"] is True
    assert r["optimize_runs"] == 200
    assert r["evm_version"] == "istanbul"
    assert r["contract_name"] == "NFT"


def test_optimizer_disabled_is_preserved_as_false_not_none(monkeypatch):
    """THE CASE THAT MATTERS. `False` (verified: optimizer off) and `None`
    (unknown) must stay distinct - collapsing them reinstates the
    always-optimize assumption, which on WETH rebuilds bytecode 56% larger
    than what is deployed."""
    _stub(monkeypatch, _Resp(200, _WETH))
    r = VER.settings_for("0x" + "c0" * 20)
    assert r["optimize"] is False
    assert r["optimize"] is not None


def test_absent_evm_version_is_none_not_a_guess(monkeypatch):
    _stub(monkeypatch, _Resp(200, _WETH))
    assert VER.settings_for("0x" + "c0" * 20)["evm_version"] is None


# ------------------------------------------------- degradation (never blocks)


def test_unverified_contract_yields_all_none(monkeypatch):
    """A 404 must leave every field None so the caller's own defaults apply -
    the whole fallback contract."""
    _stub(monkeypatch, _Resp(404))
    r = VER.settings_for("0x" + "01" * 20)
    assert r["found"] is False
    assert all(r[k] is None for k in
               ("compiler_version", "optimize", "optimize_runs", "evm_version"))
    assert "not verified" in r["reason"]


def test_network_failure_is_contained(monkeypatch):
    """Sourcify being unreachable is an ordinary condition for an engine that
    must work offline - never an exception that ends a scan."""
    import requests

    def boom(*a, **k):
        raise requests.exceptions.ConnectTimeout("no route")

    monkeypatch.setattr(requests, "get", boom)
    r = VER.settings_for("0x" + "de" * 20)
    assert r["found"] is False
    assert "ConnectTimeout" in r["reason"]


def test_a_transient_failure_is_not_cached(monkeypatch):
    """A network blip must not poison the rest of the run: the next call has to
    be able to succeed."""
    import requests

    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise requests.exceptions.ConnectTimeout("blip")
        return _Resp(200, _88MPH)

    monkeypatch.setattr(requests, "get", flaky)
    addr = "0x" + "de" * 20
    assert VER.settings_for(addr)["found"] is False
    assert VER.settings_for(addr)["found"] is True, "a blip was cached forever"


def test_a_404_IS_cached(monkeypatch):
    """Unverified is a stable fact, unlike a network blip - re-asking every
    finding would spend a request per finding to learn the same thing."""
    calls = {"n": 0}

    def counting(*a, **k):
        calls["n"] += 1
        return _Resp(404)

    import requests
    monkeypatch.setattr(requests, "get", counting)
    addr = "0x" + "01" * 20
    VER.settings_for(addr)
    VER.settings_for(addr)
    assert calls["n"] == 1


def test_garbage_response_does_not_raise(monkeypatch):
    class Bad(_Resp):
        def json(self):
            raise ValueError("not json")

    _stub(monkeypatch, Bad(200))
    assert VER.settings_for("0x" + "de" * 20)["found"] is False


def test_bad_address_is_rejected_without_a_request(monkeypatch):
    def must_not_call(*a, **k):
        raise AssertionError("made a request for an invalid address")

    import requests
    monkeypatch.setattr(requests, "get", must_not_call)
    assert VER.settings_for("0xdead", chain_id="not-a-chain")["found"] is False


# ------------------------------------------------------------ describe


def test_describe_is_readable_for_each_shape(monkeypatch):
    _stub(monkeypatch, _Resp(200, _88MPH))
    line = VER.describe(VER.settings_for("0x" + "de" * 20))
    assert "0.5.17" in line and "optimizer on" in line and "istanbul" in line

    VER.clear_cache()
    _stub(monkeypatch, _Resp(200, _WETH))
    line = VER.describe(VER.settings_for("0x" + "c0" * 20))
    assert "optimizer off" in line
    assert "runs" not in line, "runs are meaningless when the optimizer is off"

    assert "no verified build settings" in VER.describe(VER._empty("nope"))


# --------------------------------------------- wiring into the rebuild


def test_runtime_bytecode_accepts_the_verified_fields():
    """The signature is the contract between this module and the liveness
    path; a rename there would silently drop back to guessing."""
    import inspect

    from src.scan import _runtime_bytecode

    params = inspect.signature(_runtime_bytecode).parameters
    for name in ("optimize_runs", "optimize", "evm_version", "compiler_version"):
        assert name in params, f"_runtime_bytecode lost its {name} parameter"
