"""LIVE-L1 (LIMITATIONS.md) - the immutable-code liveness fallback, widened
from "is an EIP-1167 clone" to "is code that cannot ever be repointed".

The real, publicly-disclosed 88mph `NFT.init()` case is CANDIDATE-not-
CONFIRMED for two independent reasons: the finding's file moved at HEAD (so
the HEAD-based compile finds nothing), and the fallback that recompiles the
REGRESSION COMMIT's own source was gated on `proxy_kind == "eip1167-clone"`
while `0xDe71B24F...` resolves `proxy_kind: none` - it is the shared logic
three real clones delegate to, not a clone address itself. The underlying
byte comparison (`liveness.check_against_artifact`) was never the problem: it
already re-resolves fresh on every call and handles `proxy_kind: none`
correctly by comparing straight against the address's own code. The gate that
decided WHEN to attempt the fallback was the only thing too narrow.

These tests exercise `src.scan._attach_liveness` directly, mocking every
external boundary (RPC, git checkout, dependency install, solc compile) so
the DECISION LOGIC is proven without a real chain, a real clone, or a real
compiler. The real, unmocked, live-mainnet reproduction of the 88mph case
itself is `README.md`'s "Try it yourself" section and is re-verified by hand
each time this fallback changes; this file is what pins the logic between
those manual runs.

Run:  python -m pytest tests/test_attach_liveness_immutable_fallback.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import liveness as LIVENESS  # noqa: E402
from src import scan as SC  # noqa: E402
from src import verdict as V  # noqa: E402
from src.liveness import LivenessResult  # noqa: E402

# `_attach_liveness` does `from . import liveness as L` LOCALLY, inside the
# function body, not at module scope - so there is no `SC.L` to patch. Python
# resolves that import from `sys.modules` every call, returning the SAME
# `src.liveness` module object each time, so patching attributes directly on
# `LIVENESS` (imported here exactly the same way) is what actually reaches
# the function under test. A fabricated `SC.L` attribute would sit unused:
# the function would still see the real, unmocked module.


def _finding(file="contracts/NFT.sol", contract="NFT", commit="a" * 40) -> V.Finding:
    f = V.Finding(rule_id="10", file=file, contract=contract, commit=commit,
                  evidence=V.Evidence())
    f.liveness = None
    return f


class _Worktree:
    """Stand-in for `history.Worktree` - `_attach_liveness` only ever reads
    `.path` off it and passes it whole to `_checkout` (mocked here)."""

    def __init__(self, path="/fake/wt"):
        self.path = Path(path)


def _opts(address="0xDe71B24FE56358cC0ADfd6f2e0f6D8ed9e2CF634") -> SimpleNamespace:
    return SimpleNamespace(address=address, rpc_url=None)


@pytest.fixture
def wired(monkeypatch):
    """Mock every boundary `_attach_liveness` crosses, recording what it was
    asked to do so a test can assert on call counts as well as outcomes."""
    calls = {"checkout": [], "runtime_bytecode": [], "check_against_artifact": []}

    monkeypatch.setattr(SC, "_checkout", lambda wt, sha, emit: calls["checkout"].append(sha))
    monkeypatch.setattr(SC.H, "detect_env", lambda path: SimpleNamespace())
    monkeypatch.setattr(SC.H, "install", lambda spec, cache: (True, "", ""))
    monkeypatch.setattr(SC.VER, "settings_for", lambda address: {
        "found": False, "optimize_runs": None, "optimize": None,
        "evm_version": None, "compiler_version": None})

    monkeypatch.setattr(LIVENESS, "_w3", lambda rpc_url: object())
    monkeypatch.setattr(LIVENESS, "resolve_implementation",
                        lambda w3, address: {"proxy_kind": PROXY_KIND["value"]})

    def fake_check(address, runtime, rpc_url=None):
        calls["check_against_artifact"].append((address, runtime))
        return CHECK_RESULT["value"]

    monkeypatch.setattr(LIVENESS, "check_against_artifact", fake_check)
    return calls


# Mutable boxes the fixture's FakeL closes over, set per-test before the call.
PROXY_KIND = {"value": "none"}
CHECK_RESULT = {"value": LivenessResult(V.UNKNOWN, "0xabc", reason="not checked")}


def _set_head_runtime(monkeypatch, runtime_by_path: dict):
    """`_runtime_bytecode(root, rel, contract, **kw)` -> a stand-in that
    answers based on which worktree PATH it was compiled from, so the HEAD
    compile and the regression-commit compile can be given different (or
    identical) outcomes in one test."""
    def fake(root, rel, contract, **kw):
        return runtime_by_path.get(str(root))
    monkeypatch.setattr(SC, "_runtime_bytecode", fake)


# --------------------------------------------------------------------------- #
# 1. The exact 88mph shape: HEAD compile fails (file moved), proxy_kind=none.
#    Before the widening this stayed CANDIDATE forever. After, it reaches LIVE.
# --------------------------------------------------------------------------- #

def test_none_proxy_kind_now_reaches_live_when_head_compile_fails(monkeypatch, wired):
    PROXY_KIND["value"] = "none"
    CHECK_RESULT["value"] = LivenessResult(
        V.LIVE, "0xDe71B24FE56358cC0ADfd6f2e0f6D8ed9e2CF634",
        reason="normalized runtime bytecode is identical to the compiled artifact")

    head_wt = _Worktree("/fake/head")
    cur_wt = _Worktree("/fake/cur")
    _set_head_runtime(monkeypatch, {
        str(head_wt.path): None,            # HEAD: file moved, nothing compiles
        str(cur_wt.path): "0x600160026003",  # regression commit: compiles fine
    })

    f = _finding()
    SC._attach_liveness(_opts(), [f], head_wt, lambda *a, **kw: None,
                        cur_wt=cur_wt, cache=object())

    assert f.liveness == V.LIVE
    assert "non-proxy contract" in f.liveness_reason
    assert "REGRESSION COMMIT" in f.liveness_reason
    assert f.survives_to_head is True
    assert f.evidence.liveness == V.LIVE
    assert wired["checkout"] == [f.commit]
    assert len(wired["check_against_artifact"]) == 1


def test_a_confirmed_finding_reaches_confirmed_end_to_end_through_verdict(monkeypatch, wired):
    """Not just `f.liveness` in isolation - the same classify() call every
    other finding goes through, with every other evidence field present.

    `survives_to_head` starts False on purpose: `_attach_liveness`'s own
    `V.update_survival(f, True)` call is what is supposed to flip it, and
    `update_survival` RECOMPUTES `evidence.reachability` fresh from
    `raw_evidence` when it does - so `raw_evidence` (the shape a rule's own
    `emit()` produces), not `evidence.reachability` directly, is what has to
    be populated for this path. (First draft of this test set
    `evidence.reachability` directly and failed with "missing evidence:
    reachability" - `update_survival` had silently overwritten it with the
    None `raw_evidence` alone produces. Fixed here, not worked around.)
    """
    PROXY_KIND["value"] = "none"
    CHECK_RESULT["value"] = LivenessResult(V.LIVE, "0xabc...", reason="byte-exact")

    head_wt, cur_wt = _Worktree("/fake/head"), _Worktree("/fake/cur")
    _set_head_runtime(monkeypatch, {str(head_wt.path): None,
                                    str(cur_wt.path): "0x60"})

    f = V.Finding(
        rule_id="10", contract="NFT", function="init",
        file="contracts/NFT.sol", commit="a" * 40, parent="b" * 40,
        survives_to_head=False,        # about to be flipped True by the fallback
        raw_evidence={"oneshot_writers_before": ["constructor"],
                     "unguarded_writer_after": "init",
                     "visibility_after": "public", "writes_state_after": True},
        evidence=V.Evidence(
            regression_commit={"hash": "a" * 40, "line_range": "36-49"},
            pre_state="oneshot_writers_before=['constructor']",
            post_state="unguarded_writer_after='init'",
            no_compensating_control="rule 10 exclusion set evaluated"))
    f.liveness = None

    SC._attach_liveness(_opts(), [f], head_wt, lambda *a, **kw: None,
                        cur_wt=cur_wt, cache=object())
    f.evidence.liveness = f.liveness
    V.classify(f)

    assert f.verdict == V.CONFIRMED, f.downgrade_reasons
    assert f.downgrade_reasons == []
    assert f.evidence.reachability is not None


# --------------------------------------------------------------------------- #
# 2. Regression protection: the ORIGINAL eip1167-clone path is untouched.
# --------------------------------------------------------------------------- #

def test_eip1167_clone_path_still_works_exactly_as_before(monkeypatch, wired):
    PROXY_KIND["value"] = "eip1167-clone"
    CHECK_RESULT["value"] = LivenessResult(V.LIVE, "0xclone", reason="byte-exact")

    head_wt, cur_wt = _Worktree("/fake/head"), _Worktree("/fake/cur")
    _set_head_runtime(monkeypatch, {str(head_wt.path): None,
                                    str(cur_wt.path): "0x60"})

    f = _finding()
    SC._attach_liveness(_opts(), [f], head_wt, lambda *a, **kw: None,
                        cur_wt=cur_wt, cache=object())

    assert f.liveness == V.LIVE
    assert "immutable EIP-1167 clone" in f.liveness_reason
    assert "non-proxy" not in f.liveness_reason


# --------------------------------------------------------------------------- #
# 3. Deliberately NOT widened: upgradeable proxy kinds must stay disarmed.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("kind", ["eip1967", "eip1967-beacon", "zeppelinos-legacy",
                                  "not-a-contract"])
def test_upgradeable_and_nonexistent_kinds_never_engage_the_fallback(
        kind, monkeypatch, wired):
    PROXY_KIND["value"] = kind
    CHECK_RESULT["value"] = LivenessResult(V.LIVE, "0xwhatever", reason="would match")

    head_wt, cur_wt = _Worktree("/fake/head"), _Worktree("/fake/cur")
    _set_head_runtime(monkeypatch, {str(head_wt.path): None,
                                    str(cur_wt.path): "0x60"})  # would succeed if tried

    f = _finding()
    SC._attach_liveness(_opts(), [f], head_wt, lambda *a, **kw: None,
                        cur_wt=cur_wt, cache=object())

    assert f.liveness == V.UNKNOWN
    assert wired["checkout"] == [], "the fallback must not even attempt a checkout"


def test_rpc_failure_during_proxy_kind_resolution_disarms_the_fallback(monkeypatch, wired):
    """`proxy_kind` stays Python `None` (not the string "none") on an RPC
    failure - `None not in _IMMUTABLE_PROXY_KINDS` must hold, or a transient
    RPC hiccup would silently start recompiling regression commits.

    `wired` already stubs `_w3`/`resolve_implementation` to succeed; this test
    overrides just `_w3` to raise, which is exactly what
    `_attach_liveness`'s own try/except around proxy-kind resolution wraps."""
    def raising_w3(rpc_url):
        raise RuntimeError("rate limited")

    monkeypatch.setattr(LIVENESS, "_w3", raising_w3)

    head_wt, cur_wt = _Worktree("/fake/head"), _Worktree("/fake/cur")
    monkeypatch.setattr(SC, "_runtime_bytecode",
                        lambda root, rel, contract, **kw: None)
    warnings = []

    f = _finding()
    SC._attach_liveness(_opts(), [f], head_wt,
                        lambda kind, **kw: warnings.append((kind, kw)),
                        cur_wt=cur_wt, cache=object())

    assert f.liveness == V.UNKNOWN
    assert wired["checkout"] == []
    assert any(k == "warn" and "disarmed" in kw.get("message", "")
              for k, kw in warnings)


# --------------------------------------------------------------------------- #
# 4. The fallback must still require everything it always required.
# --------------------------------------------------------------------------- #

def test_no_fallback_without_a_regression_commit_checkout_or_cache(monkeypatch, wired):
    PROXY_KIND["value"] = "none"
    CHECK_RESULT["value"] = LivenessResult(V.LIVE, "0xabc", reason="would match")
    head_wt = _Worktree("/fake/head")
    _set_head_runtime(monkeypatch, {str(head_wt.path): None})

    f = _finding()
    # cur_wt=None, cache=None - the two preconditions the ORIGINAL code also
    # required and this widening must not relax.
    SC._attach_liveness(_opts(), [f], head_wt, lambda *a, **kw: None,
                        cur_wt=None, cache=None)

    assert f.liveness == V.UNKNOWN
    assert wired["checkout"] == []


def test_already_live_from_head_never_triggers_the_fallback(monkeypatch, wired):
    """The fallback is a LAST RESORT - if the ordinary HEAD-based check
    already proved LIVE, recompiling the regression commit is wasted work
    (and, for a large repo, an expensive one)."""
    PROXY_KIND["value"] = "none"
    head_wt, cur_wt = _Worktree("/fake/head"), _Worktree("/fake/cur")
    _set_head_runtime(monkeypatch, {str(head_wt.path): "0x60"})

    call_count = {"n": 0}

    def check(address, runtime, rpc_url=None):
        call_count["n"] += 1
        return LivenessResult(V.LIVE, address, reason="matched at HEAD")

    monkeypatch.setattr(LIVENESS, "check_against_artifact", check)

    f = _finding()
    SC._attach_liveness(_opts(), [f], head_wt, lambda *a, **kw: None,
                        cur_wt=cur_wt, cache=object())

    assert f.liveness == V.LIVE
    assert "REGRESSION COMMIT" not in f.liveness_reason
    assert call_count["n"] == 1          # only the HEAD-side check ran
    assert wired["checkout"] == []


# --------------------------------------------------------------------------- #
# 5. The constant itself, pinned against the real function it must track.
# --------------------------------------------------------------------------- #

def test_immutable_proxy_kinds_is_a_subset_of_what_resolve_implementation_returns():
    """Read directly from liveness.py's source rather than re-typing the
    literals, so this fails loudly if resolve_implementation ever adds or
    renames a proxy_kind value without updating the set here."""
    import re

    src = Path(SC.__file__).parent.joinpath("liveness.py").read_text(encoding="utf-8")
    real_values = set(re.findall(r'proxy_kind"\]\s*=\s*"([^"]+)"', src))
    real_values.add("none")  # the dict-literal default, not a `[...] = ` assignment
    assert SC._IMMUTABLE_PROXY_KINDS <= real_values
    # And the exclusion is deliberate, not accidental - every upgradeable kind
    # this function knows about must still be excluded.
    upgradeable = real_values - {"none", "eip1167-clone", "not-a-contract"}
    assert upgradeable, "liveness.py should still define at least one upgradeable kind"
    assert SC._IMMUTABLE_PROXY_KINDS.isdisjoint(upgradeable)
