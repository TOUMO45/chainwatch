"""Unit tests for the verdict classifier (src/verdict.py).

Fast - no compilation, no git. These pin the rules that decide whether a
finding is allowed to be called CONFIRMED, because that decision is the entire
false-positive defence and it must not drift silently.

Run:  python -m pytest tests/test_verdict.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import verdict as V  # noqa: E402

FULL_COMMIT = {"hash": "abc123def456", "author": "dev", "date": "2026-01-01T00:00:00Z",
               "line_range": "40-52", "parent": "0000aaaa"}

RECORD = {
    "rule_id": "1",
    "severity": V.CONFIRMED,
    "contract": "Vault",
    "function": "withdraw",
    "signature": "withdraw(uint256)",
    "file": "contracts/Vault.sol",
    "line": 44,
    "detail": "Vault.withdraw(uint256) lost its msg.sender constraint",
    "evidence": {
        "owasp": "SC01",
        "constrained_before": True,
        "constrained_after": False,
        "visibility_after": "external",
        "writes_state_after": True,
    },
}


def _build(**kw):
    args = {"commit": FULL_COMMIT, "survives_to_head": True, "liveness": V.LIVE}
    args.update(kw)
    return V.build(dict(RECORD), **args)


def test_all_six_present_and_live_is_confirmed():
    f = _build()
    assert f.verdict == V.CONFIRMED, f.downgrade_reasons
    assert not f.evidence.missing()


def test_no_address_means_no_confirmed():
    """The consequence people are surprised by: liveness is one of the six, so
    a repo-only scan cannot produce a CONFIRMED finding."""
    f = _build(liveness=None)
    assert f.verdict == V.CANDIDATE
    assert any("liveness" in r for r in f.downgrade_reasons)


def test_patched_on_chain_is_not_confirmed():
    f = _build(liveness=V.PATCHED)
    assert f.verdict == V.CANDIDATE
    assert any("PATCHED" in r for r in f.downgrade_reasons)


def test_regression_repaired_before_head_is_not_confirmed():
    """RULES.md: reachable at HEAD, not just at commit N. History is worth
    reporting; it is not a live exposure."""
    f = _build(survives_to_head=False)
    assert f.verdict == V.CANDIDATE
    assert any("HEAD" in r for r in f.downgrade_reasons)
    assert f.evidence.reachability is None


def test_undetermined_head_survival_is_not_proof():
    f = _build(survives_to_head=None)
    assert f.verdict == V.CANDIDATE


def test_internal_function_is_not_reachability_proof():
    rec = dict(RECORD)
    rec["evidence"] = {**RECORD["evidence"], "visibility_after": "internal"}
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CANDIDATE
    assert f.evidence.reachability is None


def test_read_only_function_is_not_reachability_proof():
    rec = dict(RECORD)
    rec["evidence"] = {**RECORD["evidence"], "writes_state_after": False}
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CANDIDATE


def test_rule_candidate_ceiling_is_never_raised():
    """RULES.md caps read-only reentrancy (2.10) and best-effort notification
    hooks (5.3) at CANDIDATE. Complete evidence must not promote them."""
    rec = dict(RECORD)
    rec["severity"] = V.CANDIDATE
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CANDIDATE
    assert any("caps this trigger class" in r for r in f.downgrade_reasons)


def test_missing_line_range_breaks_evidence_field_one():
    f = _build(commit={k: v for k, v in FULL_COMMIT.items() if k != "line_range"})
    assert f.verdict == V.CANDIDATE
    assert f.evidence.regression_commit is None


def test_unknown_rule_id_cannot_reach_confirmed():
    """A rule with no registered pre/post keys or exclusion set has not proved
    what the model requires, so it caps at CANDIDATE by construction."""
    rec = dict(RECORD)
    rec["rule_id"] = "99"
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CANDIDATE
    assert f.evidence.pre_state is None
    assert f.evidence.no_compensating_control is None


def test_every_shipped_rule_has_pre_post_and_exclusions():
    """Guards against adding a rule to the engine and forgetting the model.

    A rule id may register its pre/post mapping either directly (PRE_POST) or,
    if it fires from more than one structurally distinct trigger (Rule 4 -
    see PRE_POST_BY_TRIGGER), per-trigger. Either satisfies this invariant;
    neither existing is what test_rule4_every_trigger_shape_reaches_confirmed
    below exists to catch.
    """
    from src.scan import RULE_ORDER

    for rid in RULE_ORDER:
        assert rid in V.PRE_POST or rid in V.PRE_POST_BY_TRIGGER, \
            f"rule {rid} has no pre/post evidence mapping"
        assert rid in V.EXCLUSIONS_EVALUATED, f"rule {rid} has no exclusion record"


def test_rule4_every_trigger_shape_reaches_confirmed():
    """RC-VERDICT1. `PRE_POST["4"]` used to be a single (pragma_before,
    pragma_after) pair, which only rule4.py's pragma-lowered trigger ever
    populates. Its OTHER two triggers - safemath-removed and
    unchecked-block-added, both real and both fixture-verified-firing
    (fixtures-r4 P4-02 / P4-01) - emit neither key, so a finding from either
    one carried pre_state=None / post_state=None and could NEVER reach
    CONFIRMED, regardless of liveness. The rule-id-level check above did not
    catch this because rule "4" WAS registered in PRE_POST; only one of its
    three live firing shapes actually matched what was registered - the same
    defect class as PRE_POST's "10" entry, one level deeper.

    One record per trigger, each shaped exactly like that trigger's real
    `emit()` call in rule4.py, with full liveness and HEAD survival - the
    strongest evidence otherwise available. All three must reach CONFIRMED.
    """
    base_evidence = {"owasp": "SC09", "visibility_after": "external",
                      "writes_state_after": True}
    shapes = {
        "pragma-lowered": {**base_evidence, "trigger": "pragma-lowered",
                            "pragma_before": "0.8.0", "pragma_after": "0.7.6"},
        "safemath-removed": {**base_evidence, "trigger": "safemath-removed",
                              "wrapper_calls_before": 1, "wrapper_calls_after": 0,
                              "compiler_checked": False},
        "unchecked-block-added": {**base_evidence, "trigger": "unchecked-block-added",
                                   "operation": "ADDITION", "compiler_checked": True,
                                   "checked_before": True, "checked_after": False},
    }
    for trigger, evidence in shapes.items():
        rec = dict(RECORD)
        rec["rule_id"] = "4"
        rec["evidence"] = evidence
        f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
        assert f.verdict == V.CONFIRMED, \
            f"trigger {trigger!r} capped at {f.verdict}: {f.downgrade_reasons}"
        assert not f.evidence.missing()


def test_rule3c_erc7201_trigger_reaches_confirmed():
    """Same audit, same defect class, found in the OZ 5 ERC-7201 namespaced-
    storage path (the 3x-L3 unlock): its emit() reported only a boolean
    collision fact with no pre/post keys at all, registered nowhere. Fixed via
    PRE_POST_BY_TRIGGER["3c"]["erc7201-namespaced"] = (collision_before,
    collision_after) - coarser than the OZ 4 path's exact slot numbers, by
    necessity (`_namespaced_collision` returns a bare bool), not oversight.
    Rule 3c is CONTRACT_LEVEL, so `proxy_deployed` alone satisfies
    reachability - unlike rule 3b's disableInitializers-removed trigger,
    below.
    """
    rec = dict(RECORD)
    rec["rule_id"] = "3c"
    rec["function"] = None
    rec["evidence"] = {
        "owasp": "SC10", "mode": "erc7201-namespaced", "proxy_deployed": True,
        "collision_before": False, "collision_after": True,
    }
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CONFIRMED, f.downgrade_reasons
    assert not f.evidence.missing()


def test_rule3b_disableinitializers_trigger_reaches_confirmed_via_resolved_initializer():
    """Third instance of the same audit: rule 3b's SECOND trigger
    (`_disableInitializers()` removed from a constructor) ALSO emitted no
    pre/post keys, fixed the same way (`disables_init_before/after`).

    A second, separate gap was found on top of that: this trigger fires on
    `decl=contract_a` (a contract, not a function), rule 3b is not in
    CONTRACT_LEVEL_RULES, and `_reachability()`'s function-level path needs
    `visibility_after`/`writes_state_after`, which the constructor itself has
    no meaningful values for - nothing calls a constructor twice. Fixed via
    `_contract_initializer()`: the regression's real exposed surface is the
    contract's OWN critical-config initializer (still guarded, but now
    reachable on the raw implementation contract instead of only through the
    proxy), so `rule3b.py` resolves that function and reports ITS
    visibility/state-write facts as reachability evidence, while attribution
    (file/line) stays on `contract_a`.
    """
    rec = dict(RECORD)
    rec["rule_id"] = "3b"
    rec["function"] = None
    rec["evidence"] = {
        "owasp": "SC10", "trigger": "disableInitializers-removed",
        "proxy_deployed": True,
        "disables_init_before": True, "disables_init_after": False,
        "visibility_after": "external", "writes_state_after": True,
        "exposed_initializer": "initialize(address)",
    }
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.evidence.pre_state == "disables_init_before=True"
    assert f.evidence.post_state == "disables_init_after=False"
    assert f.verdict == V.CONFIRMED, f.downgrade_reasons
    assert not f.evidence.missing()


def test_rule3b_disableinitializers_trigger_caps_when_no_initializer_identifiable():
    """The fail-safe direction of the same fix: if `_contract_initializer()`
    cannot identify the contract's own critical-config initializer (an edge
    case - a proxy-deployed contract whose init machinery this module cannot
    otherwise characterise), `rule3b.py` leaves `visibility_after`/
    `writes_state_after` UNSET rather than guessing, and the finding correctly
    caps at CANDIDATE. Precision-first: an unidentifiable reachability surface
    is reported as unproven, not assumed reachable.
    """
    rec = dict(RECORD)
    rec["rule_id"] = "3b"
    rec["function"] = None
    rec["evidence"] = {
        "owasp": "SC10", "trigger": "disableInitializers-removed",
        "proxy_deployed": True,
        "disables_init_before": True, "disables_init_after": False,
    }
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CANDIDATE
    assert f.evidence.missing() == ["reachability"]


def test_rule10_writes_state_after_was_never_set_RC_VERDICT2():
    """RC-VERDICT2. Found LIVE (2026-08-26) scanning the actual, real,
    publicly-disclosed 88mph NFT.init() regression this rule exists to catch
    (`5f52a2ead702..a4c48d61661a`, Immunefi-reported, $6.5M at risk, funds
    returned) with a real mainnet `--address` supplied: the finding capped at
    CANDIDATE with `missing evidence: reachability` even though `init()`
    manifestly writes `_owner` - it is LITERALLY the unguarded writer rule 10's
    own trigger identified. `rule10.py`'s single `emit()` call set
    `visibility_after` but never `writes_state_after` at all, so
    `_reachability()` read the key as ABSENT (not False) and capped every
    rule 10 finding at CANDIDATE forever, regardless of liveness - the same
    defect SHAPE as RC-VERDICT1 (missing/mismatched evidence keys silently
    capping a verdict), found on a rule with only ONE emit site this time, so
    the earlier multi-emit-site audit could not have caught it.

    Fixed: `"writes_state_after": bool(fn_a.all_state_variables_written())` -
    true by construction, since `fn_a` IS T3's identified unguarded writer.
    This record is the REAL evidence shape from that live run (captured in
    `88mph_nft_live.json` before the fix), reproduced exactly, with the key
    added back the way the fix now does it.
    """
    real_commit = {"hash": "a4c48d61661ae3d8ce5aadfda6e4de27c4f07a9e",
                   "author": "Zefram Lou", "date": "2021-02-16T17:03:32-08:00",
                   "line_range": "36-49", "parent": "5f52a2ead702"}
    rec = dict(RECORD)
    rec["rule_id"] = "10"
    rec["contract"] = "NFT"
    rec["function"] = "init"
    rec["signature"] = "init(address,string,string)"
    rec["file"] = "contracts/NFT.sol"
    rec["line"] = 39
    rec["evidence"] = {
        "owasp": "SC01", "trigger": "control-migrated-to-unguarded-entry-point",
        "gate_variable": "Ownable._owner", "variable_class": "gate",
        "oneshot_writers_before": ["Ownable.constructor()"],
        "unguarded_writers_before": [],
        "unguarded_writer_after": "NFT.init(address,string,string)",
        "visibility_after": "external",
        "writes_state_after": True,
    }
    f = V.build(rec, commit=real_commit, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CONFIRMED, f.downgrade_reasons
    assert not f.evidence.missing()


def test_rule10_without_writes_state_after_would_have_capped():
    """Regression guard proving the ABOVE test is real: the pre-fix shape
    (identical evidence, `writes_state_after` key absent) must still cap at
    CANDIDATE - so a future refactor that accidentally drops the key again
    fails this test, not silently ships the live bug back."""
    real_commit = {"hash": "a4c48d61661ae3d8ce5aadfda6e4de27c4f07a9e",
                   "author": "Zefram Lou", "date": "2021-02-16T17:03:32-08:00",
                   "line_range": "36-49", "parent": "5f52a2ead702"}
    rec = dict(RECORD)
    rec["rule_id"] = "10"
    rec["evidence"] = {
        "owasp": "SC01", "trigger": "control-migrated-to-unguarded-entry-point",
        "gate_variable": "Ownable._owner", "variable_class": "gate",
        "oneshot_writers_before": ["Ownable.constructor()"],
        "unguarded_writers_before": [],
        "unguarded_writer_after": "NFT.init(address,string,string)",
        "visibility_after": "external",
    }
    f = V.build(rec, commit=real_commit, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CANDIDATE
    assert f.evidence.missing() == ["reachability"]


def test_update_survival_unlocks_confirmed_for_immutable_clone():
    """The real 88mph liveness fallback (scan.py `_attach_liveness`,
    2026-08-26). At real repo HEAD (`f4886f3`), `contracts/NFT.sol` no longer
    exists at that path - it was fixed six weeks after the regression and later
    moved and rewritten - so `_head_survival` cannot find anything to compare
    and returns `(None, None)`: UNDETERMINED, not proof either way. Built with
    that honest starting state, the finding caps at CANDIDATE missing BOTH
    reachability and liveness, exactly like a normal unmeasured case.

    But the address supplied is a real, structurally-confirmed EIP-1167 clone
    (`resolve_implementation` reads this from the proxy's own bytecode, never
    assumed), and its deployed implementation is - verified against real
    mainnet RPC, 2026-08-26 - still byte-for-byte the `a4c48d6` build: for
    immutable code, "this exact bytecode is still running" and "the regression
    still exists" are the same fact, more direct than the source-diff
    `_head_survival` ran. `update_survival` is what scan.py's clone fallback
    calls once its own liveness recheck (against the regression commit's own
    source, not HEAD) independently proves LIVE.
    """
    real_commit = {"hash": "a4c48d61661ae3d8ce5aadfda6e4de27c4f07a9e",
                   "author": "Zefram Lou", "date": "2021-02-16T17:03:32-08:00",
                   "line_range": "36-49", "parent": "5f52a2ead702"}
    rec = dict(RECORD)
    rec["rule_id"] = "10"
    rec["contract"] = "NFT"
    rec["function"] = "init"
    rec["signature"] = "init(address,string,string)"
    rec["file"] = "contracts/NFT.sol"
    rec["line"] = 39
    rec["evidence"] = {
        "owasp": "SC01", "trigger": "control-migrated-to-unguarded-entry-point",
        "gate_variable": "Ownable._owner", "variable_class": "gate",
        "oneshot_writers_before": ["Ownable.constructor()"],
        "unguarded_writers_before": [],
        "unguarded_writer_after": "NFT.init(address,string,string)",
        "visibility_after": "external",
        "writes_state_after": True,
    }

    # Starting state: source-diff survival is undetermined (file gone at real
    # HEAD), liveness not yet checked.
    f = V.build(rec, commit=real_commit, survives_to_head=None, liveness=None)
    assert f.verdict == V.CANDIDATE
    assert set(f.evidence.missing()) == {"reachability", "liveness"}

    # scan.py's clone fallback: its own regression-commit liveness recheck
    # came back LIVE, so it calls update_survival(f, True) and sets liveness.
    V.update_survival(f, True)
    f.liveness = V.LIVE
    f.evidence.liveness = V.LIVE
    assert V.classify(f) == V.CONFIRMED, f.downgrade_reasons
    assert not f.evidence.missing()


def test_update_survival_does_not_confirm_without_liveness():
    """Regression guard: update_survival alone (proving reachability) must
    never be sufficient by itself - CONFIRMED still requires liveness=LIVE to
    be set separately, exactly as RULES.md's six-field model requires. A
    future refactor that let survival imply liveness would silently drop the
    decisive gate."""
    real_commit = {"hash": "a4c48d61661ae3d8ce5aadfda6e4de27c4f07a9e",
                   "author": "Zefram Lou", "date": "2021-02-16T17:03:32-08:00",
                   "line_range": "36-49", "parent": "5f52a2ead702"}
    rec = dict(RECORD)
    rec["rule_id"] = "10"
    rec["evidence"] = {
        "owasp": "SC01", "trigger": "control-migrated-to-unguarded-entry-point",
        "gate_variable": "Ownable._owner", "variable_class": "gate",
        "oneshot_writers_before": ["Ownable.constructor()"],
        "unguarded_writers_before": [],
        "unguarded_writer_after": "NFT.init(address,string,string)",
        "visibility_after": "external",
        "writes_state_after": True,
    }
    f = V.build(rec, commit=real_commit, survives_to_head=None, liveness=None)
    V.update_survival(f, True)
    assert V.classify(f) == V.CANDIDATE
    assert f.evidence.missing() == ["liveness"]


def test_rule3a_caller_set_widened_trigger_reaches_confirmed():
    """3a-L2, closed 2026-08-26. Real evidence shape captured from an actual
    `rule3a.run()` call against `fixtures-r3a-widen/positive/P3a-widen-02`:
    `changeAdmin` keeps `require(msg.sender == pendingController)` - a real
    msg.sender check survives, so the ORIGINAL "constraint-removed" trigger
    correctly never fires - but `pendingController` has an unguarded setter,
    so the SECOND trigger shape fires. `changeAdmin` is a genuinely external,
    state-changing target function (unlike UUPS's always-internal
    `_authorizeUpgrade` - see the sibling fixture P3a-widen-01 and the
    dedicated internal-visibility test below), so reachability is satisfied
    and this must reach CONFIRMED. Registered under its own key in
    PRE_POST_BY_TRIGGER["3a"] from the day it shipped (unlike rule 4/3b/3c's
    history, where a second trigger shipped once and silently could never
    reach CONFIRMED because its evidence keys weren't registered yet)."""
    rec = dict(RECORD)
    rec["rule_id"] = "3a"
    rec["contract"] = "ProxyAdmin"
    rec["function"] = "changeAdmin"
    rec["evidence"] = {
        "owasp": "SC10", "trigger": "caller-set-widened",
        "upgrade_function": "changeAdmin",
        "illusory_targets": ["ProxyAdmin.pendingController"],
        "target_protected_before": True, "target_protected_after": False,
        "visibility_after": "external",
        "writes_state_after": True,
    }
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CONFIRMED, f.downgrade_reasons
    assert not f.evidence.missing()


def test_rule3a_caller_set_widened_without_registration_would_have_capped():
    """Regression guard: the shape RC-VERDICT1/RC-VERDICT2 already taught this
    project to fear - a real trigger shape whose evidence keys are not
    registered - reproduced deliberately (evidence dict emptied of the new
    keys) to prove the test above is actually exercising the registration and
    not passing by accident."""
    rec = dict(RECORD)
    rec["rule_id"] = "3a"
    rec["evidence"] = {"owasp": "SC10", "trigger": "caller-set-widened"}
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CANDIDATE
    assert "pre_state" in f.evidence.missing()
    assert "post_state" in f.evidence.missing()


def test_rule3a_caller_set_widened_on_internal_authorizeupgrade_caps_at_candidate():
    """Real evidence shape captured from `fixtures-r3a-widen/positive/
    P3a-widen-01` (UUPS's `_authorizeUpgrade`, always `internal` by design).
    NOT a defect introduced by 3a-L2's fix: the ORIGINAL "constraint-removed"
    trigger, run against the pre-existing `fixtures/positive/P3a-01`, produces
    the identical `visibility_after: "internal"` and caps the same way - this
    is a pre-existing characteristic of Rule 3a's reachability model (it never
    accounted for a function being externally reachable THROUGH an inherited
    entry point, e.g. UUPS's public `upgradeToAndCall` calling internal
    `_authorizeUpgrade`), not something new. Recorded here so a future fix to
    that model has a test proving what changes."""
    rec = dict(RECORD)
    rec["rule_id"] = "3a"
    rec["contract"] = "Vault"
    rec["function"] = "_authorizeUpgrade"
    rec["evidence"] = {
        "owasp": "SC10", "trigger": "caller-set-widened",
        "upgrade_function": "_authorizeUpgrade",
        "illusory_targets": ["Vault.admin"],
        "target_protected_before": True, "target_protected_after": False,
        "visibility_after": "internal",
        "writes_state_after": False,
    }
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CANDIDATE
    assert f.evidence.missing() == ["reachability"]
