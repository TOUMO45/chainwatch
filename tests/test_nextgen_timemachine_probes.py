"""Phase 1 - the concrete Time Machine probes (src/nextgen/timemachine_probes.py).

Integration: needs `slither` + a working `solc`. Builds a synthetic git repo
with a SELF-CONTAINED Vault.sol (no imports, so it compiles in isolation) whose
history introduces, removes, and restores a msg.sender guard on withdraw(), and
checks the real `AccessControlProbe` walk produces the right events.

Skips - visibly, not vacuously - when the toolchain cannot compile a trivial
contract on this machine.

Run:  python -m pytest tests/test_nextgen_timemachine_probes.py -q
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen import timemachine as TM  # noqa: E402
from src.nextgen import timemachine_probes as P  # noqa: E402

_TRIVIAL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Ping { function p() external pure returns (uint) { return 1; } }
"""

try:
    P._slither_for(_TRIVIAL)
    _TOOLCHAIN_OK = True
except Exception as _exc:  # noqa: BLE001
    _TOOLCHAIN_OK = False
    _WHY = f"{type(_exc).__name__}: {_exc}"

pytestmark = pytest.mark.skipif(
    not _TOOLCHAIN_OK,
    reason="slither/solc cannot compile a trivial contract here"
           + (f" ({_WHY})" if not _TOOLCHAIN_OK else ""))


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True,
                   capture_output=True, text=True)


V1_INLINE_GUARD = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    mapping(address => uint256) public bal;
    constructor() { owner = msg.sender; }
    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "not owner");
        bal[msg.sender] -= amount;
    }
}
"""

V2_NO_GUARD = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    mapping(address => uint256) public bal;
    constructor() { owner = msg.sender; }
    function withdraw(uint256 amount) external {
        bal[msg.sender] -= amount;
    }
}
"""

V3_MODIFIER_GUARD = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    mapping(address => uint256) public bal;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function withdraw(uint256 amount) external onlyOwner {
        bal[msg.sender] -= amount;
    }
}
"""


@pytest.fixture
def vault_history(tmp_path):
    repo = tmp_path / "repo"
    (repo / "contracts").mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t.t")
    _git(repo, "config", "user.name", "t")
    f = repo / "contracts" / "Vault.sol"

    def commit(body, msg):
        f.write_text(body, encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", msg)

    commit(V1_INLINE_GUARD, "vault with inline owner check")
    commit(V2_NO_GUARD, "drop the owner check")
    commit(V3_MODIFIER_GUARD, "restore protection via onlyOwner modifier")
    return repo


def test_access_control_probe_tracks_introduce_remove_restore(vault_history):
    probe = P.AccessControlProbe("contracts/Vault.sol", "Vault", "withdraw")
    tl = TM.walk_property(vault_history, probe, limit=50)

    assert [s.measurable for s in tl.snapshots] == [True, True, True]
    assert [s.present for s in tl.snapshots] == [True, False, True]

    kinds = [e.kind for e in tl.events]
    assert kinds == [TM.INTRODUCED, TM.REMOVED, TM.RESTORED]
    assert tl.current_state == TM.PRESENT
    assert tl.regression_commit is None          # restored -> no live regression
    assert tl.restored_after_regression is True


def test_probe_marks_a_live_regression_when_guard_stays_off(vault_history):
    # add a 4th commit that removes the guard again
    f = vault_history / "contracts" / "Vault.sol"
    f.write_text(V2_NO_GUARD, encoding="utf-8")
    _git(vault_history, "add", "-A")
    _git(vault_history, "commit", "-q", "-m", "remove protection again")

    probe = P.AccessControlProbe("contracts/Vault.sol", "Vault", "withdraw")
    tl = TM.walk_property(vault_history, probe, limit=50)

    assert tl.current_state == TM.ABSENT
    reg = tl.regression_commit
    assert reg is not None
    assert reg.subject == "remove protection again"
    assert [e.kind for e in tl.events] == [
        TM.INTRODUCED, TM.REMOVED, TM.RESTORED, TM.REMOVED]


def test_probe_reports_unmeasurable_when_file_absent(vault_history):
    probe = P.AccessControlProbe("contracts/DoesNotExist.sol", "Nope", "x")
    tl = TM.walk_property(vault_history, probe, limit=50)
    # no commit touched that path -> empty walk
    assert tl.snapshots == []
    assert tl.current_state == TM.UNKNOWN
