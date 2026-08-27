"""ANCHOR-1 - which commit built the code that is live right now?

The normal pipeline runs forwards (walk history, then ask if it is live) and
needs a deployed address per finding, which a user rarely has. This inverts it:
one address, searched backwards through history, anchors an entire trajectory.

VERIFIED AGAINST A KNOWN ANSWER, which is the only way a search like this can be
trusted. Run live against 88mph's deployed implementation
(`0xDe71B24FE56358cC0ADfd6f2e0f6D8ed9e2CF634`), the search returned
`a4c48d61661ae3d8ce5aadfda6e4de27c4f07a9e` - the exact commit this project had
already, independently, established as byte-identical to that deployment. It
also REJECTED `29be743a9c7f`, the April-2021 fix commit, which is the more
informative half: the comparison discriminates, it does not merely match.

THE HONESTY PROPERTY THESE TESTS PIN. An early version of `find_anchor` counted
compile ATTEMPTS and reported `NO_MATCH` over a window where nothing had
compiled at all - announcing a negative result about code it never examined.
That is the same "a miss over uncompiled code is unmeasured, not a negative"
error this project documents elsewhere, committed inside the module meant to
answer a question of record. `examined` now counts SUCCESSFUL builds, and a
window that produced none reports `UNRUNNABLE`.

The compiler is injected (`compile_at`), so these run without solc.

Run:  python -m pytest tests/test_anchor.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import anchor as A  # noqa: E402

_SHA_A = "a" * 40
_SHA_B = "b" * 40
_SHA_C = "c" * 40


@pytest.fixture()
def stubbed(monkeypatch, tmp_path):
    """Replace everything that touches the network, git or a compiler."""
    state = {"commits": [_SHA_A, _SHA_B, _SHA_C], "builds": {}, "target_hash": ""}

    def fake_fingerprint(address, rpc_url=None, block="latest"):
        return {"ok": True, "resolved": {"proxy_kind": "none"},
                "target": address, "normalized_keccak": state["target_hash"],
                "code_len": 100}

    class _WT:
        path = tmp_path / "wt"

        def checkout(self, sha):
            state["at"] = sha

    monkeypatch.setattr(A, "deployed_fingerprint", fake_fingerprint)
    monkeypatch.setattr(A, "commits_touching", lambda *a, **k: state["commits"])
    monkeypatch.setattr(A.H, "mirror_clone", lambda src, dest: dest)
    monkeypatch.setattr(A.H, "Worktree", lambda origin, path: _WT())
    monkeypatch.setattr(A.H, "detect_env", lambda root: object())
    monkeypatch.setattr(A.H, "install", lambda spec, cache: (True, "", "cached"))
    monkeypatch.setattr(A, "_bind_build_config", lambda spec: None)

    def fake_normalize(code, immutable_refs=None):
        # The stub encodes each commit's "bytecode" as its own bytes, so the
        # hash is just that content - real normalization is covered by
        # liveness' own tests.
        return {"normalized_keccak": code.hex()}

    monkeypatch.setattr(A.L, "normalize", fake_normalize)
    return state


def _run(state, **kw):
    def compile_at(root, rel, contract, runs):
        return state["builds"].get(state["at"])
    return A.find_anchor(Path("repo"), "0x" + "11" * 20, "contracts/X.sol", "X",
                         compile_at=compile_at, **kw)


def test_anchors_the_commit_whose_build_matches(stubbed):
    stubbed["builds"] = {_SHA_A: "dead", _SHA_B: "beef", _SHA_C: "f00d"}
    stubbed["target_hash"] = "beef"
    res = _run(stubbed)
    assert res["status"] == A.ANCHORED
    assert res["commit"] == _SHA_B


def test_a_non_matching_window_is_no_match_not_a_false_anchor(stubbed):
    """The discriminating half: a search that matches nothing must say so
    rather than return its closest candidate."""
    stubbed["builds"] = {_SHA_A: "dead", _SHA_B: "beef", _SHA_C: "f00d"}
    stubbed["target_hash"] = "9999"
    res = _run(stubbed)
    assert res["status"] == A.NO_MATCH
    assert res["commit"] is None
    assert res["examined"] == 3


def test_nothing_compiled_is_unrunnable_never_no_match(stubbed):
    """THE REGRESSION GUARD for the bug this module actually had. Zero
    successful builds means zero comparisons, which is not a negative result."""
    stubbed["builds"] = {}          # every compile returns None
    stubbed["target_hash"] = "beef"
    res = _run(stubbed)
    assert res["status"] == A.UNRUNNABLE
    assert res["examined"] == 0
    assert "says nothing about where" in res["reason"]


def test_examined_counts_successful_builds_not_attempts(stubbed):
    """The counter whose meaning caused the bug."""
    stubbed["builds"] = {_SHA_B: "beef"}     # only one of three compiles
    stubbed["target_hash"] = "9999"
    res = _run(stubbed)
    assert res["status"] == A.NO_MATCH
    assert res["examined"] == 1, "attempts were counted as examinations"
    assert res["candidates"] == 3


def test_no_match_reason_refuses_to_overclaim(stubbed):
    """Wording matters here: a reader must not take NO_MATCH as proof the
    contract came from a different repository."""
    stubbed["builds"] = {_SHA_A: "dead"}
    stubbed["target_hash"] = "9999"
    res = _run(stubbed)
    assert "does NOT establish" in res["reason"]
    assert "compiler settings" in res["reason"]


def test_an_empty_history_window_is_unrunnable(stubbed):
    stubbed["commits"] = []
    res = _run(stubbed, limit=5)
    assert res["status"] == A.UNRUNNABLE
    assert "no commit" in res["reason"]


def test_a_dead_address_never_starts_a_search(monkeypatch):
    """No code at the address means there is nothing to anchor; the search must
    not spend a single compile discovering that."""
    monkeypatch.setattr(A, "deployed_fingerprint",
                        lambda *a, **k: {"ok": False, "reason": "no code at X",
                                         "resolved": {"proxy_kind": "not-a-contract"}})
    called = []
    res = A.find_anchor(Path("repo"), "0x" + "11" * 20, "x.sol", "X",
                        compile_at=lambda *a: called.append(1))
    assert res["status"] == A.UNRUNNABLE
    assert not called, "compiled despite there being no deployed code"


def test_statuses_are_distinct():
    assert len({A.ANCHORED, A.NO_MATCH, A.UNRUNNABLE}) == 3
