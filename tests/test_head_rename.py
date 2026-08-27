"""Regression test for a real gap found this session (2026-08-26), while
investigating why the real, publicly-disclosed 88mph `NFT.init()` regression
reports `reachability = not established` instead of a real answer:
`scan._head_survival` treated "file missing at HEAD's old path" as
UNDETERMINED unconditionally, discarding the real, checkable difference
between a file that was DELETED and one that simply MOVED.

Measured on the real repository, not assumed: `git diff --name-status -M
a4c48d61661a <88mph's real v3 HEAD>` shows `contracts/NFT.sol` as `D` and
`contracts/tokens/NFT.sol` as a SEPARATE `A` - not paired as a rename -
because git's own similarity-based rename detection (~50% threshold) does
not survive the file's rewrite (solc 0.5.17 constructor-style init ->
0.8.4 OZ `Initializable`) bundled with the move. This is exactly the shape
`_renamed_path_at_head`'s same-basename fallback exists for.

Run:  python -m pytest tests/test_head_rename.py -q
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import history as H  # noqa: E402
from src.scan import _head_survival, _renamed_path_at_head  # noqa: E402

BEFORE = """\
pragma solidity 0.8.20;
contract Vault {
    address owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function withdraw(uint256 amount) external onlyOwner {
        payable(msg.sender).transfer(amount);
    }
}
"""

# Same shape a real regression commit would produce: the guard is gone.
STILL_VULNERABLE = """\
pragma solidity 0.8.20;
contract Vault {
    address owner;
    constructor() { owner = msg.sender; }
    function withdraw(uint256 amount) external {
        payable(msg.sender).transfer(amount);
    }
}
"""

# A heavy rewrite bundled with the move (mirrors the real 88mph case: a
# different inheritance shape, extra state, a restored guard, an added
# event) - deliberately dissimilar enough that git's own -M detection will
# NOT pair this with the original path, so the same-basename fallback is
# what has to find it, not git's rename detector. Self-contained (no
# import) so the fixture's only variable is the rewrite itself.
FIXED_AND_REWRITTEN = """\
pragma solidity 0.8.20;
abstract contract Ownable {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
}
contract Vault is Ownable {
    event Withdrawn(address indexed to, uint256 amount);
    mapping(address => bool) public allowlist;
    function setAllowlist(address who, bool ok) external onlyOwner {
        allowlist[who] = ok;
    }
    function withdraw(uint256 amount) external onlyOwner {
        payable(msg.sender).transfer(amount);
        emit Withdrawn(msg.sender, amount);
    }
}
"""


def _run(cwd, *args):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True)


def _commit_all(repo, msg):
    _run(repo, "add", "-A")
    _run(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", msg)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo),
                          capture_output=True, text=True, encoding="utf-8").stdout.strip()


def _build_repo(tmp_path, head_content: str):
    """N-1 (guarded) -> N (guard removed, regression) -> HEAD (moved to
    contracts/tokens/Vault.sol, content = `head_content`)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _run(repo, "init", "-q")
    _run(repo, "config", "user.email", "test@example.com")
    _run(repo, "config", "user.name", "Test")

    contracts = repo / "contracts"
    contracts.mkdir()
    (contracts / "Vault.sol").write_text(BEFORE, encoding="utf-8")
    prev = _commit_all(repo, "guarded")

    (contracts / "Vault.sol").write_text(STILL_VULNERABLE, encoding="utf-8")
    cur = _commit_all(repo, "regression: remove onlyOwner")

    (contracts / "Vault.sol").unlink()
    tokens = contracts / "tokens"
    tokens.mkdir()
    (tokens / "Vault.sol").write_text(head_content, encoding="utf-8")
    head = _commit_all(repo, "v2: move Vault into tokens/ and rewrite")

    return repo, prev, cur, head


@pytest.fixture()
def still_vulnerable_repo(tmp_path):
    return _build_repo(tmp_path, STILL_VULNERABLE.replace(
        "contract Vault {", "contract Vault {  // moved, unchanged shape\n"))


@pytest.fixture()
def fixed_repo(tmp_path):
    return _build_repo(tmp_path, FIXED_AND_REWRITTEN)


# ------------------------------------------------- _renamed_path_at_head()


def test_git_rename_detection_does_not_pair_the_heavy_rewrite(fixed_repo):
    """Confirms the premise, on THIS fixture, the same way it was confirmed
    on the real 88mph repo: git's own -M rename detection must NOT catch
    this move, or the fallback this test locks would never be exercised."""
    repo, prev, cur, head = fixed_repo
    out = H._git(repo, "diff", "--name-status", "-M", cur, head)
    lines = out.splitlines()
    assert any(l.startswith("D") and "contracts/Vault.sol" in l for l in lines)
    assert any(l.startswith("A") and "contracts/tokens/Vault.sol" in l for l in lines)
    assert not any(l.startswith("R") for l in lines)


def test_renamed_path_found_via_basename_fallback(fixed_repo):
    repo, prev, cur, head = fixed_repo
    found = _renamed_path_at_head(repo, cur, head, "contracts/Vault.sol")
    assert found == "contracts/tokens/Vault.sol"


def test_renamed_path_confirms_against_contract_name(fixed_repo):
    repo, prev, cur, head = fixed_repo
    found = _renamed_path_at_head(repo, cur, head, "contracts/Vault.sol", contract="Vault")
    assert found == "contracts/tokens/Vault.sol"


def test_renamed_path_refuses_when_contract_name_does_not_match(fixed_repo):
    """A same-basename file that does NOT declare the expected contract must
    not be trusted - refusing here is the 0-FP discipline, not a bug."""
    repo, prev, cur, head = fixed_repo
    found = _renamed_path_at_head(repo, cur, head, "contracts/Vault.sol", contract="NotVault")
    assert found is None


def test_renamed_path_none_when_file_genuinely_deleted(tmp_path):
    """A file that was actually removed (no same-basename replacement
    anywhere) must return None, never invent a location."""
    repo = tmp_path / "repo2"
    repo.mkdir()
    _run(repo, "init", "-q")
    _run(repo, "config", "user.email", "t@e.com")
    _run(repo, "config", "user.name", "T")
    c = repo / "contracts"
    c.mkdir()
    (c / "Vault.sol").write_text(BEFORE, encoding="utf-8")
    cur = _commit_all(repo, "add")
    (c / "Vault.sol").unlink()
    (c / "Other.sol").write_text("pragma solidity 0.8.20;\ncontract Other {}\n",
                                 encoding="utf-8")
    head = _commit_all(repo, "delete Vault, add unrelated Other")
    found = _renamed_path_at_head(repo, cur, head, "contracts/Vault.sol")
    assert found is None


# ---------------------------------------------------------- _head_survival()


def test_head_survival_follows_rename_and_finds_regression_still_present(
        still_vulnerable_repo):
    repo, prev, cur, head = still_vulnerable_repo
    origin = H.mirror_clone(repo, repo.parent / "origin.git")
    head_wt = H.Worktree(origin, repo.parent / "wt" / "head")
    head_wt.checkout(head)
    before_p = repo / "contracts" / "Vault.sol"  # N-1 content, still on disk
    before_p.write_text(BEFORE, encoding="utf-8")

    survives, fixed_at = _head_survival(
        "1", before_p, "contracts/Vault.sol", ["contracts/Vault.sol"],
        head_wt, head, origin=origin, commit=cur)

    assert survives is True
    assert fixed_at is None


def test_head_survival_follows_rename_and_finds_regression_fixed(fixed_repo):
    repo, prev, cur, head = fixed_repo
    origin = H.mirror_clone(repo, repo.parent / "origin.git")
    head_wt = H.Worktree(origin, repo.parent / "wt" / "head")
    head_wt.checkout(head)
    before_p = repo / "contracts" / "Vault.sol"
    before_p.write_text(BEFORE, encoding="utf-8")

    survives, fixed_at = _head_survival(
        "1", before_p, "contracts/Vault.sol", ["contracts/Vault.sol"],
        head_wt, head, origin=origin, commit=cur)

    assert survives is False
    assert fixed_at == head[:12]


def test_head_survival_without_origin_or_commit_falls_back_to_undetermined(
        still_vulnerable_repo):
    """The OLD behaviour (undetermined, not a crash) when the new optional
    parameters are not supplied - callers that have not been updated must
    keep working exactly as before."""
    repo, prev, cur, head = still_vulnerable_repo
    origin = H.mirror_clone(repo, repo.parent / "origin.git")
    head_wt = H.Worktree(origin, repo.parent / "wt" / "head")
    head_wt.checkout(head)
    before_p = repo / "contracts" / "Vault.sol"
    before_p.write_text(BEFORE, encoding="utf-8")

    survives, fixed_at = _head_survival(
        "1", before_p, "contracts/Vault.sol", ["contracts/Vault.sol"], head_wt, head)

    assert survives is None
    assert fixed_at is None
