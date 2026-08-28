"""The Security Time Machine (spec §1) - a temporal security-property graph.

The classic pipeline compares exactly two commits: `parent -> commit`. That is
enough to attribute a regression, but it cannot answer "when did this control
first exist, was it ever removed before, has it come back". This module walks
the WHOLE history of the file(s) that define one security property and records
its life:

    commit 1  property introduced
    commit 2  property modified
    commit 3  property removed          <- regression
    commit 4  property still absent
    ...
    HEAD      current state

It is deliberately probe-agnostic. A `PropertyProbe` knows how to measure ONE
property's value from source at ONE commit; this module knows how to walk git,
call the probe at every relevant commit, collapse equal measurements, and
classify each change as INTRODUCED / MODIFIED / REMOVED / RESTORED.

WHAT THIS MODULE DOES NOT DO: decide a verdict. A timeline is evidence for the
`regression_commit` and `security_invariant` gates in `state.py`; it is not a
finding. The concrete probes live in `timemachine_probes.py` and are built on
the SAME Slither primitives the classic rules use, so the Time Machine and the
rules cannot disagree about what "the property" is.

Read-only on the target: every git call goes through `history._git`, which runs
against Chainwatch's own mirror clone (CHARTER rule 5).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Callable, Hashable, Optional

from .. import history as H
from . import evidence_graph as EG

# --------------------------------------------------------------------------- #
# Invariant classes (spec §2). A probe declares which one it measures.
# --------------------------------------------------------------------------- #

CODE = "CODE_INVARIANT"
PROTOCOL = "PROTOCOL_INVARIANT"
ACCESS_CONTROL = "ACCESS_CONTROL_INVARIANT"
ACCOUNTING = "ACCOUNTING_INVARIANT"
ECONOMIC = "ECONOMIC_INVARIANT"
STATE_MACHINE = "STATE_MACHINE_INVARIANT"
DEPLOYMENT = "DEPLOYMENT_INVARIANT"
CROSS_CONTRACT = "CROSS_CONTRACT_INVARIANT"

INVARIANT_KINDS: frozenset[str] = frozenset({
    CODE, PROTOCOL, ACCESS_CONTROL, ACCOUNTING, ECONOMIC, STATE_MACHINE,
    DEPLOYMENT, CROSS_CONTRACT,
})

# --------------------------------------------------------------------------- #
# Event kinds and current-state values.
# --------------------------------------------------------------------------- #

INTRODUCED = "INTRODUCED"
MODIFIED = "MODIFIED"
REMOVED = "REMOVED"
RESTORED = "RESTORED"

PRESENT = "PRESENT"
ABSENT = "ABSENT"
UNKNOWN = "UNKNOWN"


@dataclass
class Measurement:
    """One probe's reading at one commit.

    `present`     is the security property in force at this commit?
    `value`       finer detail (which guard, which modifier, the exact
                  require expression...). A change here while `present` stays
                  True is a MODIFIED event. Must be hashable/comparable.
    `measurable`  False means "could not tell" - file absent, would not
                  compile, declaration not found. Never guessed either way.
    """

    present: bool
    value: Hashable = None
    measurable: bool = True
    note: str = ""


class PropertyProbe(abc.ABC):
    """Measure one security property's value from source at one commit.

    Subclasses set `id`, `title`, `kind` (an INVARIANT_KINDS member) and
    `paths` (repo-relative files that define the property), and implement
    `measure`.
    """

    id: str = ""
    title: str = ""
    kind: str = CODE
    paths: tuple[str, ...] = ()

    @abc.abstractmethod
    def measure(self, get_file: Callable[[str], Optional[str]]) -> Measurement:
        """`get_file(repo_relative_path)` returns that file's text at the commit
        under examination, or None if it does not exist there."""
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Timeline data
# --------------------------------------------------------------------------- #

@dataclass
class Snapshot:
    commit: str
    short: str
    author: str
    date: str
    subject: str
    present: bool
    value: Hashable
    measurable: bool
    note: str = ""

    def as_dict(self) -> dict:
        return {"commit": self.commit, "short": self.short,
                "author": self.author, "date": self.date,
                "subject": self.subject, "present": self.present,
                "value": _jsonable(self.value), "measurable": self.measurable,
                "note": self.note}


@dataclass
class PropertyEvent:
    kind: str                       # INTRODUCED / MODIFIED / REMOVED / RESTORED
    at_commit: str
    at_short: str
    author: str
    date: str
    subject: str
    from_value: Hashable
    to_value: Hashable
    prev_commit: Optional[str]
    at_window_start: bool = False   # INTRODUCED that may actually predate the walk

    def as_dict(self) -> dict:
        return {"kind": self.kind, "at_commit": self.at_commit,
                "at_short": self.at_short, "author": self.author,
                "date": self.date, "subject": self.subject,
                "from_value": _jsonable(self.from_value),
                "to_value": _jsonable(self.to_value),
                "prev_commit": self.prev_commit,
                "at_window_start": self.at_window_start}


def _jsonable(v: Hashable):
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    if isinstance(v, (tuple, frozenset, set, list)):
        return sorted(_jsonable(x) for x in v)
    return str(v)


@dataclass
class PropertyTimeline:
    probe_id: str
    title: str
    kind: str
    paths: tuple[str, ...]
    snapshots: list[Snapshot] = field(default_factory=list)
    events: list[PropertyEvent] = field(default_factory=list)

    # -- derived views ------------------------------------------------------- #

    @property
    def first_introduced(self) -> Optional[PropertyEvent]:
        for e in self.events:
            if e.kind == INTRODUCED:
                return e
        return None

    @property
    def regression_commit(self) -> Optional[PropertyEvent]:
        """The REMOVED event that explains why the property is absent NOW - the
        last REMOVED not followed by a RESTORED. None if the property is
        currently present (or was never present, or is unmeasurable)."""
        reg: Optional[PropertyEvent] = None
        for e in self.events:
            if e.kind == REMOVED:
                reg = e
            elif e.kind == RESTORED:
                reg = None
        return reg if self.current_state == ABSENT else None

    @property
    def restored_after_regression(self) -> bool:
        seen_removed = False
        for e in self.events:
            if e.kind == REMOVED:
                seen_removed = True
            elif e.kind == RESTORED and seen_removed:
                return True
        return False

    @property
    def current_state(self) -> str:
        for s in reversed(self.snapshots):
            if s.measurable:
                return PRESENT if s.present else ABSENT
        return UNKNOWN

    @property
    def modifications(self) -> list[PropertyEvent]:
        return [e for e in self.events if e.kind == MODIFIED]

    # -- serialisation / rendering ---------------------------------------- #

    def as_dict(self) -> dict:
        reg = self.regression_commit
        return {
            "probe_id": self.probe_id, "title": self.title, "kind": self.kind,
            "paths": list(self.paths),
            "current_state": self.current_state,
            "first_introduced": (self.first_introduced.as_dict()
                                 if self.first_introduced else None),
            "regression_commit": reg.as_dict() if reg else None,
            "restored_after_regression": self.restored_after_regression,
            "events": [e.as_dict() for e in self.events],
            "snapshots": [s.as_dict() for s in self.snapshots],
        }

    def render_text(self) -> str:
        lines = ["SECURITY PROPERTY TIMELINE", "=" * 26, ""]
        lines.append("Property:")
        lines.append(f"  {self.title}   [{self.kind}]")
        lines.append("")
        lines.append("Defining files:")
        for p in self.paths:
            lines.append(f"  {p}")
        lines.append("")
        fi = self.first_introduced
        if fi:
            tail = ("   (present as of the earliest commit examined - may be older)"
                    if fi.at_window_start else "")
            lines.append("First seen:")
            lines.append(f"  {fi.at_short}  {fi.date}  {fi.author}  "
                         f"\"{fi.subject}\"{tail}")
            lines.append("")
        lines.append("Timeline:")
        reg = self.regression_commit
        for e in self.events:
            mark = "   <-- regression" if (reg and e.at_commit == reg.at_commit) else ""
            lines.append(f"  {e.at_short}  {e.kind:<10}  {e.date}  "
                         f"{e.author}  \"{e.subject}\"{mark}")
        if not self.events:
            lines.append("  (no change in this property across the examined history)")
        lines.append("")
        lines.append("Current status:")
        if self.current_state == ABSENT and reg:
            lines.append(f"  ABSENT - not restored since {reg.at_short} "
                         f"({reg.date}, {reg.author})")
        elif self.current_state == ABSENT:
            lines.append("  ABSENT - the property is not in force at HEAD")
        elif self.current_state == PRESENT:
            lines.append("  PRESENT - the property is in force at HEAD")
        else:
            lines.append("  UNKNOWN - could not measure the property at any "
                         "examined commit")
        return "\n".join(lines)

    def to_evidence_graph(self, g: EG.EvidenceGraph) -> str:
        """Add this timeline to `g` and return the SECURITY_PROPERTY node id.

        The property node is established by this module; each event's commit
        node is established by `history.py` (git IS the source for a commit).
        """
        pid = g.add_node(
            EG.SECURITY_PROPERTY, self.title, established_by="nextgen.timemachine",
            data={"probe_id": self.probe_id, "kind": self.kind,
                  "current_state": self.current_state,
                  "paths": list(self.paths)})
        reg = self.regression_commit
        for e in self.events:
            cid = g.add_node(
                EG.COMMIT, f"{e.at_short} {e.kind}: {e.subject}"[:120],
                established_by="history.py",
                data={"hash": e.at_commit, "event": e.kind,
                      "author": e.author, "date": e.date})
            g.add_edge(pid, EG.DERIVED_FROM, cid)
            if reg and e.at_commit == reg.at_commit:
                g.add_edge(cid, EG.REFUTES, pid)   # this commit is why it's gone
        return pid


# --------------------------------------------------------------------------- #
# The walk
# --------------------------------------------------------------------------- #

def _commits_touching(repo, paths: tuple[str, ...], limit: Optional[int],
                      head: str) -> list[tuple[str, str, str, str]]:
    """(sha, author, iso-date, subject) for every commit that touched any of
    `paths`, oldest first. Capped to the most recent `limit`."""
    if not paths:
        return []
    out = H._git(repo, "log", "--reverse", "--date-order",
                 "--format=%H%x1f%an%x1f%aI%x1f%s", head, "--", *paths)
    rows: list[tuple[str, str, str, str]] = []
    for line in out.splitlines():
        parts = line.split("\x1f")
        if len(parts) == 4:
            rows.append((parts[0], parts[1], parts[2], parts[3]))
    if limit and len(rows) > limit:
        rows = rows[-limit:]
    return rows


def _reader(repo, sha: str) -> Callable[[str], Optional[str]]:
    def get(path: str) -> Optional[str]:
        return H.file_at(repo, sha, path)
    return get


def walk_property(repo, probe: PropertyProbe, *, limit: Optional[int] = 300,
                  head: str = "HEAD") -> PropertyTimeline:
    """Measure `probe` at every commit that touched its defining files, oldest
    first, and derive the introduce/modify/remove/restore events."""
    if probe.kind not in INVARIANT_KINDS:
        raise ValueError(f"probe.kind {probe.kind!r} is not an invariant class")
    rows = _commits_touching(repo, tuple(probe.paths), limit, head)
    snaps: list[Snapshot] = []
    for sha, author, date, subject in rows:
        m = probe.measure(_reader(repo, sha))
        snaps.append(Snapshot(sha, sha[:12], author, date, subject,
                              bool(m.present), m.value, bool(m.measurable),
                              m.note))
    return PropertyTimeline(probe.id, probe.title, probe.kind,
                            tuple(probe.paths), snaps, _derive_events(snaps))


def build_timeline(snapshots: list[Snapshot], *, probe_id: str = "",
                   title: str = "", kind: str = CODE,
                   paths: tuple[str, ...] = ()) -> PropertyTimeline:
    """Construct a timeline from pre-measured snapshots (for callers that walk
    git themselves, and for tests)."""
    return PropertyTimeline(probe_id, title, kind, tuple(paths),
                            list(snapshots), _derive_events(snapshots))


def _derive_events(snaps: list[Snapshot]) -> list[PropertyEvent]:
    """Collapse equal measurements; classify each change.

    Unmeasurable snapshots are skipped entirely - they neither create nor
    break an event. The first measurable snapshot, if `present`, yields an
    INTRODUCED flagged `at_window_start` (it may predate the walk).
    """
    events: list[PropertyEvent] = []
    prev: Optional[Snapshot] = None
    removed_outstanding = False

    for s in snaps:
        if not s.measurable:
            continue
        if prev is None:
            if s.present:
                events.append(_ev(INTRODUCED, s, None, None, s.value,
                                  at_window_start=True))
            prev = s
            continue

        if s.present and not prev.present:
            kind = RESTORED if removed_outstanding else INTRODUCED
            events.append(_ev(kind, s, prev.commit, prev.value, s.value))
            removed_outstanding = False
        elif s.present and prev.present and s.value != prev.value:
            events.append(_ev(MODIFIED, s, prev.commit, prev.value, s.value))
        elif not s.present and prev.present:
            events.append(_ev(REMOVED, s, prev.commit, prev.value, s.value))
            removed_outstanding = True
        # (absent -> absent, present -> present same value): no event
        prev = s

    return events


def _ev(kind: str, s: Snapshot, prev_commit: Optional[str],
        from_value: Hashable, to_value: Hashable,
        at_window_start: bool = False) -> PropertyEvent:
    return PropertyEvent(kind, s.commit, s.short, s.author, s.date, s.subject,
                         from_value, to_value, prev_commit, at_window_start)
