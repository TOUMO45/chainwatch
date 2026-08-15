"""The hallucination gate. MECHANICAL — no model is involved in checking a model.

A security disclosure that invents one commit hash is worse than no disclosure,
so this is treated exactly like a false positive: zero tolerance, and the check
is deterministic code rather than a second LLM pass. Asking a model to grade a
model gives you two things that can be wrong instead of one.

WHAT IT CHECKS

  1. Every commit-hash-shaped token in the draft appears in the finding record.
  2. Every 0x-address appears in the finding record.
  3. Every *.sol path appears in the finding record.
  4. Every "line N" / "lines N-M" reference matches the recorded line or range.
  5. Every Contract.function reference matches the recorded declaration.
  6. CANDIDATE only: the fixed header is present and unmodified, no severity or
     impact section was invented, and no assertive vulnerability language is
     used (RULES.md amended hard rule).
  7. Any verdict: no exploit code / proof-of-concept (CHARTER anti-goal).

WHAT IT DELIBERATELY DOES NOT CHECK: whether the prose is *good*. That is a
human's job. This answers one question only - does every checkable fact in this
document come from the finding record.
"""

from __future__ import annotations

import re
from typing import Any

# A hex run long enough to be a commit hash, not a number in prose.
_HASH = re.compile(r"\b[0-9a-fA-F]{7,64}\b")
_ADDR = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
_SOL = re.compile(r"\b[\w./-]+\.sol\b")
_LINE = re.compile(r"\blines?\s+(\d+)(?:\s*[-–]\s*(\d+))?", re.I)
_QUALIFIED = re.compile(r"\b([A-Z]\w*)\.(\w+)\b")

# Language a CANDIDATE document may not use about its own subject.
_ASSERTIVE = re.compile(
    r"\b(is (?:a )?(?:confirmed|exploitable|vulnerable|critical)"
    r"|can be exploited|is exploitable|attacker can|allows an attacker"
    r"|confirmed vulnerability|proof of concept|proof-of-concept)\b", re.I)

# NOTE: no trailing \b. Several of these alternatives end in punctuation - a
# word boundary after "(" or ")" can never match, which silently disabled them.
# Caught by tests/test_agent_tools.py::test_exploit_material_is_caught.
_EXPLOIT = re.compile(
    r"(?:\bfunction\s+attack|\bexploit\(\)|\bcalldata payload"
    r"|\babi\.encode(?:WithSelector|WithSignature|Packed)?\("
    r"|\bcast send\b|\bforge script\b.*attack)", re.I)

_BANNED_SECTIONS_FOR_CANDIDATE = ("severity", "impact", "risk rating", "cvss")


def _fact_strings(facts: dict) -> set[str]:
    """Flatten the finding record into a set of lowercase strings a draft may cite."""
    out: set[str] = set()

    def walk(v: Any):
        if v is None:
            return
        if isinstance(v, dict):
            for k, vv in v.items():
                out.add(str(k).lower())
                walk(vv)
        elif isinstance(v, (list, tuple, set)):
            for vv in v:
                walk(vv)
        else:
            out.add(str(v).lower())

    walk(facts)
    return out


def verify(markdown: str, facts: dict) -> dict:
    """Returns {status, ok, violations:[{kind, span, reason}]}."""
    text = markdown or ""
    haystack = _fact_strings(facts)
    blob = " ".join(haystack)
    violations: list[dict] = []

    def cite(kind: str, span: str, reason: str):
        violations.append({"kind": kind, "span": span, "reason": reason})

    # 1. commit hashes
    for m in _HASH.finditer(text):
        tok = m.group(0).lower()
        if len(tok) < 7:
            continue
        if not any(tok in h or h.startswith(tok) for h in haystack):
            cite("hash", m.group(0), "commit-hash-shaped token not present in the finding record")

    # 2. addresses
    for m in _ADDR.finditer(text):
        if m.group(0).lower() not in blob:
            cite("address", m.group(0), "address not present in the finding record")

    # 3. source paths
    for m in _SOL.finditer(text):
        tok = m.group(0).lower()
        if not any(tok in h or h.endswith(tok) for h in haystack):
            cite("path", m.group(0), "source path not present in the finding record")

    # 4. line references
    allowed_lines = set()
    if facts.get("line"):
        allowed_lines.add(int(facts["line"]))
    for part in str(facts.get("line_range") or "").replace(" ", "").split(","):
        m = re.match(r"^(\d+)-(\d+)$", part)
        if m:
            allowed_lines.update(range(int(m.group(1)), int(m.group(2)) + 1))
        elif part.isdigit():
            allowed_lines.add(int(part))
    if allowed_lines:
        for m in _LINE.finditer(text):
            nums = [int(g) for g in m.groups() if g]
            for n in nums:
                if n not in allowed_lines:
                    cite("line", m.group(0),
                         f"line {n} is outside the recorded location/range")

    # 5. qualified names
    contract = (facts.get("contract") or "").lower()
    fn = (facts.get("function") or "").lower()
    for m in _QUALIFIED.finditer(text):
        c, f = m.group(1).lower(), m.group(2).lower()
        if c in ("chainwatch", "rules", "charter", "limitations", "readme"):
            continue
        if c.endswith(".sol") or f == "sol":
            continue
        if c == contract and (not fn or f == fn or f in blob):
            continue
        if f"{c}.{f}" in blob:
            continue
        cite("name", m.group(0), "qualified name not present in the finding record")

    # 7. exploit material, any verdict
    for m in _EXPLOIT.finditer(text):
        cite("exploit", m.group(0), "exploit / proof-of-concept material is out of scope (CHARTER)")

    # 6. CANDIDATE-only structural constraints (RULES.md amended hard rule)
    if (facts.get("verdict") or "").upper() == "CANDIDATE":
        from .templates import header_for
        expected = header_for(facts)
        if expected not in text:
            cite("header", expected[:60],
                 "the fixed NOT CONFIRMED header is missing or was altered")
        for heading in re.findall(r"^#{1,6}\s*(.+)$", text, re.M):
            h = heading.strip().lower()
            if any(h.startswith(b) for b in _BANNED_SECTIONS_FOR_CANDIDATE):
                cite("section", heading.strip(),
                     "a CANDIDATE report has no severity/impact section to fill")
        for m in _ASSERTIVE.finditer(text):
            cite("overclaim", m.group(0),
                 "assertive vulnerability language is not permitted for a CANDIDATE")

    return {
        "status": "success",
        "ok": not violations,
        "violation_count": len(violations),
        "violations": violations[:50],
    }
