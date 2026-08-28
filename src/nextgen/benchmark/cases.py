"""The starter OFFLINE benchmark suite (spec §20).

Synthetic, self-contained sources. HEAVY ON HARD NEGATIVES - benign changes
that look suspicious and must NOT confirm. This suite measures rejection
discipline (false-positive rate); recall needs deployment + a reproducer and
is measured by the online suite in a later phase.
"""

from __future__ import annotations

from . import model as M


def _c(**kw) -> M.BenchmarkCase:
    return M.BenchmarkCase(**kw)


_HN_RENAMED_MODIFIER_BEFORE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public keeper;
    uint256 public x;
    constructor() { keeper = msg.sender; }
    modifier onlyKeeper() { require(msg.sender == keeper, "no"); _; }
    function poke(uint256 v) external onlyKeeper { x = v; }
}
"""
_HN_RENAMED_MODIFIER_AFTER = _HN_RENAMED_MODIFIER_BEFORE.replace(
    "onlyKeeper", "gateFn")

_HN_MODIFIER_TO_INLINE_BEFORE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public keeper;
    bool public paused;
    constructor() { keeper = msg.sender; }
    modifier onlyKeeper() { require(msg.sender == keeper); _; }
    function pause() external onlyKeeper { paused = true; }
}
"""
_HN_MODIFIER_TO_INLINE_AFTER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public keeper;
    bool public paused;
    constructor() { keeper = msg.sender; }
    function pause() external { require(msg.sender == keeper); paused = true; }
}
"""

_HN_BECAME_VIEW_BEFORE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Config {
    address public owner;
    uint256 public rate;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setRate(uint256 r) external onlyOwner { rate = r; }
}
"""
_HN_BECAME_VIEW_AFTER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Config {
    address public owner;
    uint256 public rate;
    constructor() { owner = msg.sender; }
    function setRate() external view returns (uint256) { return rate; }
}
"""

_HN_STILL_PRESENT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setOwner(address o) external onlyOwner { owner = o; }
}
"""

_POS_GENUINE_REMOVAL_BEFORE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setOwner(address o) external onlyOwner { owner = o; }
}
"""
_POS_GENUINE_REMOVAL_AFTER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    constructor() { owner = msg.sender; }
    function setOwner(address o) external { owner = o; }
}
"""


OFFLINE_CASES: list[M.BenchmarkCase] = [
    _c(id="HN-renamed-modifier", nature=M.HARD_NEGATIVE, expected=M.EXP_REJECTED,
       vuln_class="SC01", contract="Vault", function="poke",
       invariant="only the keeper may call poke()",
       reason="the modifier was renamed but still checks msg.sender == keeper; "
              "not a regression",
       before_source=_HN_RENAMED_MODIFIER_BEFORE,
       after_source=_HN_RENAMED_MODIFIER_AFTER),

    _c(id="HN-modifier-to-inline", nature=M.HARD_NEGATIVE, expected=M.EXP_REJECTED,
       vuln_class="SC01", contract="Vault", function="pause",
       invariant="only the keeper may pause",
       reason="the onlyKeeper modifier was replaced by an inline "
              "require(msg.sender == keeper); protection intact",
       before_source=_HN_MODIFIER_TO_INLINE_BEFORE,
       after_source=_HN_MODIFIER_TO_INLINE_AFTER),

    _c(id="HN-became-view", nature=M.HARD_NEGATIVE, expected=M.EXP_REJECTED,
       vuln_class="SC01", contract="Config", function="setRate",
       invariant="only the owner may set the rate",
       reason="setRate no longer writes state (became a view); there is nothing "
              "for an access guard to protect",
       before_source=_HN_BECAME_VIEW_BEFORE, after_source=_HN_BECAME_VIEW_AFTER,
       expect_gates={"reachable_path": "FAIL"}),

    _c(id="HN-still-present", nature=M.HARD_NEGATIVE, expected=M.EXP_REJECTED,
       vuln_class="SC01", contract="Vault", function="setOwner",
       invariant="only the owner may set the owner",
       reason="the guard is in force in both versions - no regression",
       before_source=_HN_STILL_PRESENT, after_source=_HN_STILL_PRESENT,
       expect_gates={"regression_commit": "FAIL"}),

    _c(id="POS-genuine-removal", nature=M.POSITIVE, expected=M.EXP_UNKNOWN,
       vuln_class="SC01", contract="Vault", function="setOwner",
       invariant="only the owner may set the owner",
       reason="onlyOwner was genuinely removed and nothing compensates; still "
              "UNKNOWN offline because deployment + a reproducer are required "
              "to CONFIRM",
       before_source=_POS_GENUINE_REMOVAL_BEFORE,
       after_source=_POS_GENUINE_REMOVAL_AFTER,
       expect_gates={"regression_commit": "PASS", "security_invariant": "PASS",
                     "reachable_path": "PASS", "no_compensating_control": "PASS"}),
]
