"""CORPUS-1 / capability 16 - the findings corpus on Firestore.

TWO PROPERTIES MATTER MORE THAN THE STORAGE ITSELF, and they are what these
tests pin:

  1. IT DEGRADES, NEVER BLOCKS. Chainwatch is an analysis engine that must keep
     working on a laptop with no cloud project. Every entry point returns a
     status instead of raising when Firestore is absent, misconfigured, or
     unreachable - a scan whose persistence failed is still a valid scan, it
     just was not recorded. Verified here by running with NO credentials, which
     is also the state a fresh clone starts in.

  2. IT DECIDES NOTHING. The corpus stores verdicts `verdict.classify` already
     produced. If a cached read could differ from what the engine returns, the
     cache would be a second, divergent opinion about what CONFIRMED means -
     the same "two things that can disagree" failure this project refuses
     everywhere else.

These run WITHOUT credentials on purpose. Round-tripping real documents is a
deployment check, not a unit test, and a suite that needed a cloud project
would stop being runnable by anyone who clones the repo.

Run:  python -m pytest tests/test_corpus.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import corpus as C  # noqa: E402


# ------------------------------------------------------- degradation


def _force_unavailable(monkeypatch):
    monkeypatch.setattr(C, "_client", None)
    monkeypatch.setattr(C, "_probe_error", "no credentials (test)")


def test_available_reports_why_it_is_not(monkeypatch):
    """The front ends must be able to SAY 'not recorded' rather than fail
    obscurely - the same contract `agent.runner.api_key_present` has."""
    _force_unavailable(monkeypatch)
    st = C.available()
    assert st["available"] is False
    assert st["reason"]
    assert st["project"] and st["database"]


def test_record_scan_returns_a_status_instead_of_raising(monkeypatch):
    _force_unavailable(monkeypatch)
    res = C.record_scan({"repo": "x/y", "findings": [{"rule_id": "10"}],
                         "coverage": {}, "summary": {}})
    assert res["ok"] is False
    assert res["written"] == 0
    assert res["reason"]


def test_reads_return_empty_not_an_exception(monkeypatch):
    _force_unavailable(monkeypatch)
    assert C.seen_pair("x/y", "a" * 40, "b" * 40) is None
    assert C.query_findings(rule_id="10") == []
    assert C.get_job("nope") is None
    assert C.put_job("nope", {"a": 1}) is False


def test_a_broken_client_does_not_escape(monkeypatch):
    """Not just 'absent' - a client that raises mid-call (network drop, quota,
    revoked token) must also be contained. This is the case that would
    otherwise kill a scan that had already done all its real work."""
    class Boom:
        def collection(self, *a, **k):
            raise RuntimeError("connection reset")

        def batch(self):
            raise RuntimeError("connection reset")

    monkeypatch.setattr(C, "_client", Boom())
    monkeypatch.setattr(C, "_probe_error", "")
    assert C.seen_pair("x", "a" * 40, "b" * 40) is None
    assert C.query_findings() == []
    assert C.get_job("j") is None
    assert C.put_job("j", {}) is False
    res = C.record_scan({"repo": "x", "findings": [], "coverage": {}})
    assert res["ok"] is False


# ------------------------------------------------------- key derivation


def test_the_same_pair_keys_identically_across_url_forms():
    """A repo analysed from a clone URL and from a local checkout of the same
    project must hit the SAME cache entry, or the corpus never dedupes."""
    a = C.pair_key("https://github.com/Org/Repo.git", "a" * 40, "b" * 40)
    b = C.pair_key("github.com/org/repo", "a" * 40, "b" * 40)
    c = C.pair_key("git@github.com:Org/Repo", "a" * 40, "b" * 40)
    assert a == b == c


def test_different_pairs_key_differently():
    base = C.pair_key("r", "a" * 40, "b" * 40)
    assert base != C.pair_key("r", "b" * 40, "a" * 40), "direction must matter"
    assert base != C.pair_key("other", "a" * 40, "b" * 40)


def test_document_ids_are_firestore_legal():
    """A Firestore document id may not contain '/' and is length-capped; a raw
    repo URL violates both, which is why the key is hashed."""
    key = C.pair_key("https://github.com/a/very/deeply/nested/repo.git",
                     "a" * 40, "b" * 40)
    assert "/" not in key
    assert 0 < len(key) <= 64
    assert key.isalnum()


def test_repo_id_normalisation_is_case_and_suffix_insensitive():
    assert C._repo_id("HTTPS://GitHub.com/Org/Repo.git") == "github.com/org/repo"
    assert C._repo_id("github.com/org/repo/") == "github.com/org/repo"
    assert C._repo_id(r"C:\checkouts\repo") == "c/checkouts/repo"


# ------------------------------------------------------- batching


def test_a_large_scan_is_chunked_under_the_firestore_batch_cap(monkeypatch):
    """Firestore rejects a batch over 500 operations. A 300-finding walk must
    be chunked, not silently truncated - losing the tail of a long scan would
    be a data-loss bug that nothing else would surface."""
    commits = []

    class FakeBatch:
        def __init__(self):
            self.n = 0

        def set(self, ref, payload):
            self.n += 1

        def commit(self):
            commits.append(self.n)

    class FakeClient:
        def collection(self, name):
            return self

        def document(self, key):
            return ("ref", key)

        def batch(self):
            return FakeBatch()

    monkeypatch.setattr(C, "_client", FakeClient())
    monkeypatch.setattr(C, "_probe_error", "")

    report = {
        "repo": "org/repo", "head": "h", "summary": {}, "coverage": {
            "pair_records": [{"pair": f"{i:040x}..{i+1:040x}", "comparisons": 1,
                              "comparisons_ok": 1, "seconds": 1.0}
                             for i in range(300)]},
        "findings": [{"rule_id": "10", "commit": f"{i:040x}", "file": "a.sol",
                      "contract": "C", "function": "f"} for i in range(300)],
    }
    res = C.record_scan(report)
    assert res["ok"] is True
    assert len(commits) > 1, "everything went into one over-sized batch"
    assert all(n <= 500 for n in commits), f"a batch exceeded the cap: {commits}"
    assert sum(commits) == res["written"] == 601   # 1 scan + 300 pairs + 300 findings
