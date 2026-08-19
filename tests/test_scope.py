"""What a scan actually LOOKS AT, and whether it admits when that was nothing.

SCAN-L1. The web app shipped `root_dir` pre-filled with `contracts`. Pasting
morpho-blue - whose Solidity lives in `src/` - therefore diffed a directory
that does not exist, found no modified files in any pair, and still counted
every pair as analysed. Measured: 6 pairs "analysed", `files_total = 0`, zero
findings, and no warning anywhere that not one Solidity file had been compared.

Two things are tested here and they are different:

  1. SCOPE DETECTION picks the directories holding a repo's own Solidity,
     without being told. The hard case is morpho-blue, where `test/` holds MORE
     .sol files (29) than `src/` (22) - so any rule that counts before
     excluding picks the tests.

  2. THE ZERO-COMPARISON INVARIANT. Whatever scope is chosen, a scan that
     compared no files must say so. This is HIST-L1's rule applied one level
     down: "0 findings over 0 comparisons" and "0 findings over 400
     comparisons" are different claims.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import history as H  # noqa: E402


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 0, "git %s: %s" % (" ".join(args), proc.stderr)
    return proc.stdout


def _repo(tmp_path: Path, name: str, files: dict) -> Path:
    """A git repo containing exactly `files` (path -> contents), one commit."""
    src = tmp_path / name
    src.mkdir(parents=True)
    for rel, body in files.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(src)], capture_output=True,
                   text=True, timeout=120, check=True)
    _git(src, "config", "user.email", "t@example.com")
    _git(src, "config", "user.name", "t")
    _git(src, "add", "-A")
    _git(src, "commit", "--quiet", "-m", "one")
    return src


SOL = "pragma solidity ^0.8.0;\ncontract C {}\n"


# ------------------------------------------------------------------ detection


def test_conventional_contracts_layout(tmp_path):
    r = _repo(tmp_path, "conv", {
        "contracts/Token.sol": SOL,
        "contracts/Vault.sol": SOL,
        "test/TokenTest.sol": SOL,
    })
    scope = H.detect_source_scope(r)
    assert scope["roots"] == ["contracts"]
    assert scope["source_files"] == 2
    assert scope["excluded_files"] == 1


def test_src_layout_wins_even_when_tests_are_more_numerous(tmp_path):
    """The morpho-blue shape, which is the whole reason this exists: counting
    before excluding picks `test/`."""
    files = {"src/Morpho.sol": SOL, "src/libraries/Math.sol": SOL}
    for i in range(9):
        files["test/Case%d.t.sol" % i] = SOL
    r = _repo(tmp_path, "morphoish", files)
    scope = H.detect_source_scope(r)
    assert scope["roots"] == ["src"], scope
    assert scope["source_files"] == 2
    assert scope["excluded_files"] == 9


def test_mocks_nested_under_the_source_root_are_excluded(tmp_path):
    r = _repo(tmp_path, "nested", {
        "src/Morpho.sol": SOL,
        "src/mocks/ERC20Mock.sol": SOL,
        "src/libraries/test/Helper.sol": SOL,
    })
    scope = H.detect_source_scope(r)
    assert scope["roots"] == ["src"]
    assert scope["excluded_files"] == 2
    assert any("mocks" in e or "test" in e for e in scope["exclude_segments"])


def test_a_filename_is_never_evidence_only_a_directory_is(tmp_path):
    """reserve-protocol ships `contracts/facade/FacadeTest.sol` - a DEPLOYED
    facade, not a test. Excluding on filename would silently drop real
    contracts, so exclusion matches path SEGMENTS only."""
    r = _repo(tmp_path, "facade", {
        "contracts/facade/FacadeTest.sol": SOL,
        "contracts/Main.sol": SOL,
    })
    scope = H.detect_source_scope(r)
    assert scope["source_files"] == 2, "a file called *Test.sol was dropped"
    assert scope["excluded_files"] == 0


def test_monorepo_descends_through_the_container_directory(tmp_path):
    r = _repo(tmp_path, "mono", {
        "packages/core/contracts/A.sol": SOL,
        "packages/core/test/A.t.sol": SOL,
        "packages/ui/src/B.sol": SOL,
    })
    scope = H.detect_source_scope(r)
    assert all(x.startswith("packages/") for x in scope["roots"]), scope
    assert "packages/core" in scope["roots"] or \
           "packages/core/contracts" in scope["roots"], scope


def test_solidity_at_the_repository_root(tmp_path):
    r = _repo(tmp_path, "flat", {"Token.sol": SOL, "test/T.sol": SOL})
    scope = H.detect_source_scope(r)
    assert scope["roots"] == [""], scope
    assert scope["source_files"] == 1


def test_a_repo_whose_solidity_is_all_tests_reports_that_honestly(tmp_path):
    """Degenerate but real (a fixture or example repository). It must NOT
    silently fall back to scanning the tests and calling that a source scan,
    and it must NOT claim a scope it does not have."""
    r = _repo(tmp_path, "alltests", {"test/A.sol": SOL, "test/B.sol": SOL})
    scope = H.detect_source_scope(r)
    assert scope["source_files"] == 0
    assert scope["roots"] == []
    assert scope["reason"], "no explanation given for an empty scope"


def test_a_repo_with_no_solidity_at_all(tmp_path):
    r = _repo(tmp_path, "nosol", {"README.md": "hi\n", "src/app.ts": "x\n"})
    scope = H.detect_source_scope(r)
    assert scope["total_files"] == 0
    assert scope["roots"] == []
    assert "no solidity" in scope["reason"].lower()


# --------------------------------------------------------- applying the scope


def test_changed_sol_honours_detected_roots_and_exclusions(tmp_path):
    r = _repo(tmp_path, "diffed", {
        "src/A.sol": SOL,
        "src/mocks/M.sol": SOL,
        "test/T.sol": SOL,
        "docs/readme.md": "x\n",
    })
    first = _git(r, "rev-parse", "HEAD").strip()
    for rel in ("src/A.sol", "src/mocks/M.sol", "test/T.sol"):
        (r / rel).write_text(SOL + "// touched\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "--quiet", "-m", "two")
    second = _git(r, "rev-parse", "HEAD").strip()

    scope = H.detect_source_scope(r)
    changed = H.changed_sol(r, first, second, roots=scope["roots"],
                            exclude_segments=scope["exclude_segments"])
    assert changed["modified"] == ["src/A.sol"], changed


def test_an_explicit_root_is_honoured_exactly_with_no_extra_filtering(tmp_path):
    """An explicit `root_dir` is the user's instruction, not a hint. Applying
    the auto-mode exclusions on top of it would silently change what every
    existing pinned scan sees - tests/test_realworld_reserve.py pins
    root_dir="contracts", and reserve keeps mocks under it."""
    r = _repo(tmp_path, "explicit", {
        "contracts/A.sol": SOL,
        "contracts/mocks/M.sol": SOL,
    })
    first = _git(r, "rev-parse", "HEAD").strip()
    for rel in ("contracts/A.sol", "contracts/mocks/M.sol"):
        (r / rel).write_text(SOL + "// touched\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "--quiet", "-m", "two")
    second = _git(r, "rev-parse", "HEAD").strip()

    changed = H.changed_sol(r, first, second, root="contracts")
    assert sorted(changed["modified"]) == ["contracts/A.sol",
                                           "contracts/mocks/M.sol"], changed


# ------------------------------------------------- the zero-comparison invariant


def _cov(files_total=0):
    from src.scan import Coverage
    c = Coverage()
    c.files_total = files_total
    return c


def test_a_scan_that_compared_nothing_says_so():
    """The exact shape of the morpho-blue run: every pair 'analysed', not one
    file compared, zero findings. Without this the report reads as clean."""
    from src.scan import _nothing_compared
    msg = _nothing_compared(_cov(0), {"mode": "explicit", "roots": ["contracts"]})
    assert msg and "No Solidity file was compared" in msg
    assert "UNMEASURED" in msg or "unmeasured" in msg


def test_a_scan_that_compared_something_stays_quiet():
    from src.scan import _nothing_compared
    assert _nothing_compared(_cov(12), {"mode": "auto", "roots": ["src"]}) is None


def test_an_empty_auto_scope_explains_itself():
    from src.scan import _nothing_compared
    msg = _nothing_compared(_cov(0), {"mode": "auto", "roots": [],
                                      "reason": "all 4 tracked Solidity files sit under test"})
    assert msg and "test" in msg
    assert "evidence" in msg.lower()


def test_the_report_carries_scope_and_the_invariant():
    """Both must be IN THE REPORT, not left for each front end to recompute -
    that is how the CLI and the web app start disagreeing."""
    from src.scan import ScanOptions, _report
    rep = _report(ScanOptions(repo=Path(".")), _cov(0), [], 0.0, head=None,
                  scope={"mode": "auto", "roots": ["src"], "reason": "x"})
    assert rep["scope"]["roots"] == ["src"]
    assert rep["nothing_compared"], "the report does not flag a zero-comparison scan"
