"""Phase 3b - deployment-aware security (src/nextgen/deployment.py, spec §10).

Pure: `assess` from a `resolve_implementation`-shaped dict, no network. Pins
that a proxy now pointing elsewhere REJECTS the finding (PATCHED), and that an
immutable clone proven LIVE PASSES.

Run:  python -m pytest tests/test_nextgen_deployment.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen import deployment as DEP  # noqa: E402
from src.nextgen import gates as G  # noqa: E402
from src.nextgen import state as S  # noqa: E402

VULN = "0x" + "a" * 40
OTHER = "0x" + "b" * 40


def _res(kind, target, admin=None):
    slots = {}
    if admin is not None:
        slots["eip1967.admin"] = admin
    return {"address": "0x" + "1" * 40, "proxy_kind": kind, "target": target,
            "slots": slots}


def test_proxy_serving_the_vulnerable_impl_passes():
    facts = DEP.assess(_res("eip1967", VULN, admin="0x" + "9" * 40),
                       vulnerable_impl=VULN)
    assert facts.serves_vulnerable is True
    assert facts.gate == S.PASS
    assert facts.upgradeable is True


def test_proxy_pointing_elsewhere_now_is_patched_and_rejects():
    facts = DEP.assess(_res("eip1967", OTHER), vulnerable_impl=VULN)
    assert facts.serves_vulnerable is False
    assert facts.gate == S.FAIL
    fs = S.FindingState("f")
    G.apply_deployment(fs, facts)
    fine, verdict, _ = S.classify(fs.gates)
    assert fine == S.PATCHED
    assert verdict == S.VERDICT_REJECTED


def test_not_a_contract_fails():
    facts = DEP.assess(_res("not-a-contract", None), vulnerable_impl=VULN)
    assert facts.gate == S.FAIL
    assert facts.serves_vulnerable is False


def test_unresolved_target_is_unknown():
    facts = DEP.assess({"address": "0x" + "1" * 40, "proxy_kind": "eip1967",
                        "target": None, "slots": {}}, vulnerable_impl=VULN)
    assert facts.gate == S.GATE_UNKNOWN


def test_immutable_clone_proven_live_passes_without_an_impl_address():
    facts = DEP.assess(_res("eip1167-clone", VULN), vulnerable_impl=None,
                       liveness_verdict="LIVE")
    assert facts.gate == S.PASS
    assert facts.serves_vulnerable is True
    assert facts.upgradeable is False
    assert "immutable" in facts.rationale


def test_plain_address_patched_liveness_fails():
    facts = DEP.assess(_res("none", VULN), vulnerable_impl=None,
                       liveness_verdict="PATCHED")
    assert facts.gate == S.FAIL


def test_no_impl_address_and_no_liveness_is_unknown():
    facts = DEP.assess(_res("eip1967", OTHER), vulnerable_impl=None,
                       liveness_verdict=None)
    assert facts.gate == S.GATE_UNKNOWN


def test_render_text():
    facts = DEP.assess(_res("eip1967", VULN, admin="0x" + "9" * 40),
                       vulnerable_impl=VULN)
    assert "DEPLOYMENT-AWARE SECURITY" in facts.render_text()
