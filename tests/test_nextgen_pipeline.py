"""Phase 6 - the end-to-end pipeline (src/nextgen/pipeline.py, spec §26).

Drives the whole chain over synthetic inputs. Needs slither; the reproducer
steps additionally need a Foundry toolchain (they degrade to PENDING otherwise,
so the pipeline still returns a result).

Run:  python -m pytest tests/test_nextgen_pipeline.py -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen import _solc  # noqa: E402
from src.nextgen import pipeline as PL  # noqa: E402
from src.nextgen import proofscore as PS  # noqa: E402
from src.nextgen import state as S  # noqa: E402
from src.nextgen.execground import foundry as F  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P{function f() external pure returns(uint){return 1;}}\n")
try:
    _solc.slither_for_source(_TRIVIAL)
    _OK = True
except Exception:  # noqa: BLE001
    _OK = False
pytestmark = pytest.mark.skipif(not _OK, reason="slither/solc unavailable")

_HAVE_FORGE = F.resolve() is not None

GUARDED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setOwner(address o) external onlyOwner { owner = o; }
}
"""
UNGUARDED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    constructor() { owner = msg.sender; }
    function setOwner(address o) external { owner = o; }
}
"""
RENAMED = GUARDED.replace("onlyOwner", "authFn")


def _inputs(**kw):
    base = dict(candidate_id="c1", contract="Vault", function="setOwner",
                signature="setOwner(address)", call_args="address(0xBEEF)",
                type_label="Authorization Security Regression",
                invariant_kind="ACCESS_CONTROL_INVARIANT")
    base.update(kw)
    return PL.PipelineInputs(**base)


def test_genuine_removal_offline_is_unknown_but_key_gates_pass():
    res = PL.run(_inputs(before_source=GUARDED, after_source=UNGUARDED,
                         source_bundle=UNGUARDED, run_reproducer=_HAVE_FORGE))
    assert res.verdict == S.VERDICT_UNKNOWN          # no deployment / dedup offline
    g = res.finding_state.gates
    assert g["regression_commit"] == S.PASS
    assert g["security_invariant"] == S.PASS
    assert g["reachable_path"] == S.PASS
    assert g["no_compensating_control"] == S.PASS
    if _HAVE_FORGE:
        assert g["reproducer"] == S.PASS
        assert g["invariant_violated"] == S.PASS
    assert "CHAINWATCH" in res.report_text
    assert isinstance(res.proof_score, PS.ProofScore)


def test_renamed_modifier_is_rejected():
    res = PL.run(_inputs(before_source=GUARDED, after_source=RENAMED,
                         source_bundle=RENAMED, run_reproducer=False))
    assert res.verdict == S.VERDICT_REJECTED
    assert "NOT A FINDING" in res.report_text


def test_still_present_is_rejected_on_regression_gate():
    res = PL.run(_inputs(before_source=GUARDED, after_source=GUARDED,
                         source_bundle=GUARDED, run_reproducer=False))
    assert res.verdict == S.VERDICT_REJECTED
    assert res.finding_state.gates["regression_commit"] == S.FAIL


def test_result_is_json_safe():
    res = PL.run(_inputs(before_source=GUARDED, after_source=UNGUARDED,
                         source_bundle=UNGUARDED, run_reproducer=False))
    json.dumps(res.as_dict())


def test_pipeline_is_resilient_to_a_bad_source():
    res = PL.run(_inputs(before_source="not solidity", after_source="also not",
                         source_bundle="nope", run_reproducer=False))
    # it must still return a classified result, not raise
    assert res.verdict in (S.VERDICT_UNKNOWN, S.VERDICT_REJECTED)
    assert any(k.endswith("_error") for k in res.sub_reports)


@pytest.mark.skipif(not _HAVE_FORGE, reason="no Foundry toolchain")
def test_offline_hard_negative_view_function_is_rejected():
    before = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault { address public owner; uint256 public r;
 constructor(){owner=msg.sender;}
 modifier onlyOwner(){require(msg.sender==owner);_;}
 function setR(uint256 v) external onlyOwner { r = v; } }"""
    after = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault { address public owner; uint256 public r;
 constructor(){owner=msg.sender;}
 function setR() external view returns (uint256) { return r; } }"""
    res = PL.run(_inputs(function="setR", signature="setR()", call_args="",
                         before_source=before, after_source=after,
                         source_bundle=after, run_reproducer=True))
    assert res.verdict == S.VERDICT_REJECTED
    assert res.finding_state.gates["reachable_path"] == S.FAIL
