"""DEP-3 - Soldeer dependency resolution, without executing forge or soldeer.

MEASURED against the real Soldeer registry API and a real target repository
(term-structure/termmax-contract-v2). Two shapes exist in `foundry.toml`'s
`[dependencies]`:

    forge-std = "1.9.6"                                    registry-hosted
    pendle-core-v2 = { version = "1.0.0",                  git-pinned
                       git = "...", rev = "d3dafee2..." }

Neither needs forge or the soldeer binary (CHARTER rule 3 forbids installing
forge - WALK-L9). Registry packages are a plain HTTPS GET of a public S3 zip;
git-pinned ones are a shallow `git fetch --depth 1` of the exact commit,
through the project's own trusted `history._git`.

THE SHALLOW-FETCH FIX IS THE PART WORTH LOCKING. An early version used a full
`git clone`. termmax-v2 pins `@chainlink-contracts` at
smartcontractkit/chainlink - a large monorepo - and a full clone of it hung
past any reasonable per-dependency budget. Measured directly: a shallow fetch
of the exact pinned commit took 33.5s and 54MB. `_resolve_git` must never
regress to a full clone.

Network-touching tests are gated on an environment variable, the same
`skipif`-on-a-condition style already used elsewhere in this suite (e.g.
`test_foundry_fallback.py`'s `needs_no_forge`) rather than a new pytest CLI
option.

Run:  python -m pytest tests/test_soldeer.py -q
Run (incl. real registry/git):
    CHAINWATCH_TEST_NETWORK=1 python -m pytest tests/test_soldeer.py -q
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import soldeer as S  # noqa: E402

needs_network = pytest.mark.skipif(
    not os.environ.get("CHAINWATCH_TEST_NETWORK"),
    reason="set CHAINWATCH_TEST_NETWORK=1 to run tests against the real "
           "Soldeer registry and a real git host")


# ------------------------------------------------------- parsing, no network


_TOML = """
[dependencies]
forge-std = "1.9.6"
"@openzeppelin-contracts" = "5.2.0"
"@chainlink-contracts" = { version = "v1.12.0", git = "https://github.com/smartcontractkit/chainlink.git", rev = "b57617ed2249ac711db75e5bef5a0a78bf10b2aa" }
"""


def test_detects_a_real_dependencies_table(tmp_path):
    (tmp_path / "foundry.toml").write_text(_TOML, encoding="utf-8")
    assert S.has_soldeer_dependencies(tmp_path)
    deps = S._read_dependencies(tmp_path)
    assert set(deps) == {"forge-std", "@openzeppelin-contracts", "@chainlink-contracts"}


def test_no_foundry_toml_is_false_not_an_error(tmp_path):
    assert not S.has_soldeer_dependencies(tmp_path)


def test_foundry_toml_without_dependencies_is_false(tmp_path):
    (tmp_path / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n",
                                            encoding="utf-8")
    assert not S.has_soldeer_dependencies(tmp_path)


def test_malformed_toml_does_not_raise(tmp_path):
    (tmp_path / "foundry.toml").write_text("[[[not valid toml", encoding="utf-8")
    assert not S.has_soldeer_dependencies(tmp_path)


# ------------------------------------------------------ directory naming


def test_registry_dependency_dir_name_matches_soldeers_own_convention():
    """Confirmed against a REAL project's own committed remappings.txt
    (termmax-v2): dependencies/@openzeppelin-contracts-5.2.0/."""
    assert S.dependency_dir_name("@openzeppelin-contracts", "5.2.0") == \
        "@openzeppelin-contracts-5.2.0"


def test_git_pinned_dir_name_uses_the_declared_version_not_the_rev():
    """The directory is named after `version` (the human-facing tag), not
    `rev` (the resolved commit) - confirmed against termmax-v2's real
    dependencies/@chainlink-contracts-v1.12.0/, not a sha-named directory."""
    entry = {"version": "v1.12.0", "git": "https://x/y.git", "rev": "deadbeef" * 5}
    assert S.dependency_dir_name("@chainlink-contracts", entry) == \
        "@chainlink-contracts-v1.12.0"


def test_missing_version_is_refused_not_guessed():
    assert S.dependency_dir_name("x", {"git": "https://x/y.git"}) is None
    assert S.dependency_dir_name("x", {}) is None


# ------------------------------------------------------- zip-slip guard


def test_extract_zip_refuses_a_path_traversal_entry(tmp_path):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.sol", "malicious")
    target = tmp_path / "safe_target"
    ok, why = S._extract_zip(buf.getvalue(), target)
    assert not ok
    assert "unsafe" in why.lower()


def test_extract_zip_accepts_a_normal_archive(tmp_path):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/Token.sol", "contract Token {}")
        zf.writestr("README.md", "hi")
    target = tmp_path / "pkg-1.0.0"
    ok, why = S._extract_zip(buf.getvalue(), target)
    assert ok, why
    assert (target / "src" / "Token.sol").is_file()


def test_a_corrupt_download_does_not_raise(tmp_path):
    ok, why = S._extract_zip(b"not a zip file at all", tmp_path / "x")
    assert not ok
    assert "zip" in why.lower()


# ------------------------------------------------ install_soldeer_dependencies


def test_no_dependencies_table_is_reported_not_silently_ok(tmp_path):
    ok, detail = S.install_soldeer_dependencies(tmp_path)
    assert not ok
    assert "no [dependencies]" in detail


def test_already_resolved_package_is_not_refetched(tmp_path, monkeypatch):
    """A worktree slot reused across commits in a walk must not re-fetch a
    dependency it already has - this is the amortisation the whole cache
    model depends on, applied without a second parallel cache system."""
    (tmp_path / "foundry.toml").write_text(_TOML, encoding="utf-8")
    existing = tmp_path / "dependencies" / "forge-std-1.9.6"
    existing.mkdir(parents=True)
    (existing / "src").mkdir()
    (existing / "src" / "Test.sol").write_text("x", encoding="utf-8")

    calls = []
    monkeypatch.setattr(S, "_resolve_registry",
                        lambda *a, **k: (calls.append(a) or (True, "fetched")))
    monkeypatch.setattr(S, "_resolve_git",
                        lambda *a, **k: (calls.append(a) or (True, "fetched")))
    S.install_soldeer_dependencies(tmp_path)
    assert not any(c[0] == "forge-std" for c in calls if c), \
        "re-fetched a dependency that was already present"


def test_one_failed_dependency_does_not_hide_the_others(tmp_path, monkeypatch):
    """The same 'one broken thing must not hide the rest' principle _run_rule
    already applies to individual rules."""
    (tmp_path / "foundry.toml").write_text(_TOML, encoding="utf-8")

    def fake_registry(name, version, target, timeout):
        if name == "forge-std":
            return False, "simulated registry outage"
        target.mkdir(parents=True, exist_ok=True)
        (target / "marker").write_text("ok", encoding="utf-8")
        return True, "ok"

    monkeypatch.setattr(S, "_resolve_registry", fake_registry)
    monkeypatch.setattr(S, "_resolve_git", lambda *a, **k: (True, "ok"))
    ok, detail = S.install_soldeer_dependencies(tmp_path)
    assert not ok
    assert "forge-std" in detail and "simulated registry outage" in detail
    # the OTHER two packages still resolved despite forge-std failing
    assert (tmp_path / "dependencies" / "@openzeppelin-contracts-5.2.0" / "marker").is_file()


# ------------------------------------- dependencies/ excluded from scanning


def test_a_transitive_import_inside_dependencies_is_not_the_targets_own(tmp_path):
    """THE REAL BUG, found end-to-end against termmax-v2 - not hypothetical.
    After every real Soldeer dependency resolved correctly, every pair STILL
    reported dep-missing. Root cause: `imported_packages` (which
    `_missing_imported_packages` calls) excludes `node_modules` and `lib`
    from its scan, but had never been taught about Soldeer's `dependencies/`
    directory - so a vendored package's OWN transitive imports (chainlink's
    full monorepo, pulled in as one git-pinned dependency, imports
    @eth-optimism/contracts, erc4626-tests and base64-sol for code termmax-v2
    never uses) were counted as the TARGET repo's missing imports.

    This reproduces that exact shape without needing the real 2554-file
    chainlink checkout.
    """
    from src.history import imported_packages

    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "Vault.sol").write_text(
        'import "@openzeppelin/contracts/token/ERC20/IERC20.sol";\n'
        "contract Vault {}\n", encoding="utf-8")

    vendored = tmp_path / "dependencies" / "@chainlink-contracts-v1.12.0"
    vendored.mkdir(parents=True)
    (vendored / "Bridge.sol").write_text(
        'import "@eth-optimism/contracts/Foo.sol";\n'
        "contract Bridge {}\n", encoding="utf-8")

    pkgs = imported_packages(tmp_path, exclude_deps=True)
    assert "@openzeppelin/contracts" in pkgs, "the repo's own real import was lost"
    assert "@eth-optimism/contracts" not in pkgs, \
        "a vendored dependency's OWN transitive import leaked into the target's set"


def test_dependencies_dir_is_excluded_even_without_exclude_deps(tmp_path):
    """Unconditional, matching node_modules - not gated behind exclude_deps
    the way `lib` is. `derive_remaps` calls this with the default
    (exclude_deps=False) and must not try to remap a vendored package's own
    transitive imports either."""
    from src.history import imported_packages

    (tmp_path / "dependencies" / "pkg").mkdir(parents=True)
    (tmp_path / "dependencies" / "pkg" / "X.sol").write_text(
        'import "some-transitive-thing/Y.sol";\ncontract X {}\n', encoding="utf-8")
    assert "some-transitive-thing" not in imported_packages(tmp_path)


# --------------------------------------------------- real network (opt-in)


@needs_network
def test_real_registry_lookup_matches_the_measured_shape():
    ok, why = S._resolve_registry("forge-std", "1.9.6",
                                  Path("/tmp/chainwatch-soldeer-test-fs"), 30)
    assert ok, why


@needs_network
def test_real_shallow_git_fetch_does_not_pull_full_history(tmp_path):
    """THE REGRESSION GUARD for the actual bug this module had: a full clone
    of a large monorepo (chainlink) hung past any reasonable timeout. A
    shallow fetch of one commit must complete in well under a minute and use
    a small fraction of the repository's real size."""
    import time

    target = tmp_path / "chainlink-pin"
    t0 = time.monotonic()
    ok, why = S._resolve_git(
        "https://github.com/smartcontractkit/chainlink.git",
        "b57617ed2249ac711db75e5bef5a0a78bf10b2aa", target, timeout=30)
    elapsed = time.monotonic() - t0
    assert ok, why
    assert elapsed < 90, f"shallow fetch took {elapsed:.0f}s - regressed toward a full clone"
    size = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
    assert size < 200_000_000, f"{size} bytes - looks like a full clone, not one commit"
