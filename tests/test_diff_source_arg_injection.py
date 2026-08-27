"""SEC-L3 - `prev`/`cur`/`rev` on the diff/source endpoints must not be
usable as injected git options.

THE REAL RISK, MEASURED. `GET /api/scan/{job_id}/diff?file=&prev=&cur=`
built `["git", ..., "diff", f"-U{n}", prev, cur, "--", file]` and
`GET /api/scan/{job_id}/source?file=&rev=` built `git show f"{rev}:{file}"`
- in both cases `prev`/`cur`/`rev` reach `subprocess.run` as bare argv
content, with `--` (in the diff case) placed AFTER them rather than before,
so a caller-supplied value starting with `-` is parsed by git as an OPTION,
not a revision. `--output=<path>` alone is enough to make either endpoint
write to an arbitrary path the process can reach - an unauthenticated,
public HTTP GET turning into a file-write primitive, no valid job or
repository required to reach the vulnerable code (the fix in
`webapp/server.py` validates before ever looking up the job).

Run:  python -m pytest tests/test_diff_source_arg_injection.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from webapp.server import _require_git_rev, app  # noqa: E402

client = TestClient(app)


@pytest.mark.parametrize("value", [
    "--output=/tmp/pwned",
    "-O/etc/passwd",
    "--ext-diff",
    "-c",
    "; rm -rf /",
    "",
    "not-hex-zzz",
    "a" * 41,          # one longer than a full sha
])
def test_a_non_sha_value_is_rejected(value):
    with pytest.raises(Exception):  # HTTPException
        _require_git_rev(value, "prev")


@pytest.mark.parametrize("value", [
    "a" * 40,          # full sha, lowercase
    "A" * 40,          # full sha, uppercase (git accepts either case)
    "deadbeef",        # abbreviated sha
    "0123",            # minimum accepted length
])
def test_a_real_sha_shaped_value_is_accepted(value):
    assert _require_git_rev(value, "prev") == value


def test_diff_endpoint_refuses_an_option_shaped_prev_before_touching_any_job():
    """No job named 'nope' exists; a 400 (not a 404) proves the injected
    value was refused BEFORE the job lookup ever ran - so this check
    guards the endpoint even for a caller that never had a valid scan."""
    r = client.get("/api/scan/nope/diff", params={
        "file": "Foo.sol", "prev": "--output=/tmp/pwned", "cur": "deadbeef",
    })
    assert r.status_code == 400
    assert "prev" in r.text


def test_source_endpoint_refuses_an_option_shaped_rev_before_touching_any_job():
    r = client.get("/api/scan/nope/source", params={
        "file": "Foo.sol", "rev": "--output=/tmp/pwned",
    })
    assert r.status_code == 400
    assert "rev" in r.text


def test_diff_endpoint_with_a_well_shaped_rev_reaches_the_normal_404():
    """A legitimately-shaped sha for a job that does not exist must reach
    the EXISTING 'no such scan' 404, proving the new check does not shadow
    the endpoint's real behaviour for a genuine request."""
    r = client.get("/api/scan/nope/diff", params={
        "file": "Foo.sol", "prev": "a" * 40, "cur": "b" * 40,
    })
    assert r.status_code == 404
