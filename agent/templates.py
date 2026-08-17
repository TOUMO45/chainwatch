"""Report skeletons — where RULES.md's amended hard rule is ENFORCED.

RULES.md (amended 2026-08-15) permits the model to see a CANDIDATE finding only
through "a template that is structurally incapable of asserting a
vulnerability". This module is that structure. Two properties do the work, and
neither is a prompt:

1. **THE MODEL NEVER AUTHORS THE FRAMING.** `assemble()` emits the header from
   the finding's own verdict and ignores anything the model may have written in
   its place. For a CANDIDATE the header is the fixed string
   `NOT CONFIRMED - missing evidence: {...}`. A model that tries to write its
   own header simply has that text dropped, because header text is not one of
   the slots it can fill.

2. **THERE IS NO SLOT FOR THE CLAIM.** The CANDIDATE skeleton has no severity
   section and no impact section. Overclaiming is not forbidden by instruction;
   there is nowhere to put it.

Facts are rendered by code from the finding object. The model contributes prose
into named slots and nothing else - so it never types a commit hash, an
address, or a line number, and therefore cannot get one wrong.
"""

from __future__ import annotations

from typing import Optional

CONFIRMED = "CONFIRMED"
CANDIDATE = "CANDIDATE"

# The one string a CANDIDATE document always opens with. Not overridable.
CANDIDATE_HEADER = "NOT CONFIRMED - missing evidence: {missing}"
CONFIRMED_HEADER = "CONFIRMED regression - {contract}.{function}"

# Slots the model may fill, per verdict. A slot absent from this table cannot be
# written to; `assemble` drops unknown keys rather than trusting them.
SLOTS: dict[str, list[dict]] = {
    CONFIRMED: [
        {"key": "summary", "title": "Summary",
         "guidance": "Two or three sentences: which control existed, which commit removed it, "
                     "and what the code now permits that it did not before. State facts only."},
        {"key": "mechanism", "title": "Mechanism",
         "guidance": "Explain the change as shown in the diff. Refer to the code you were given; "
                     "do not speculate about code you have not seen."},
        {"key": "impact", "title": "Impact",
         "guidance": "Describe conceptually what an unprotected version permits. Do NOT provide "
                     "exploit steps, calldata, or a proof of concept."},
        {"key": "remediation", "title": "Remediation",
         "guidance": "The smallest change that restores the control that commit N-1 had."},
    ],
    CANDIDATE: [
        {"key": "summary", "title": "What the rule found",
         "guidance": "Two or three sentences describing the change the rule detected. "
                     "Do not characterise it as a vulnerability - it has not met that bar."},
        {"key": "mechanism", "title": "The change itself",
         "guidance": "Explain what the diff shows. Facts only."},
        {"key": "why_not_confirmed", "title": "Why this is not confirmed",
         "guidance": "Walk through the missing evidence fields listed above and explain, in plain "
                     "language, what each one would have required. This is the point of the "
                     "document."},
        {"key": "what_would_settle_it", "title": "What would settle it",
         "guidance": "State what a human would have to establish to move this to CONFIRMED, "
                     "or to discard it."},
    ],
}


# Impact narration slots (capability: explain_impact). A SECOND slot set over
# the SAME finding record, header, fact block and verification gate - not a
# second document type with its own rules. The engine's verdict is never an
# input the model can touch: `header_for` still writes the framing, `assemble`
# still drops unknown keys, and `verify` still applies every CANDIDATE
# structural constraint. This tool narrates ONE existing finding; it cannot
# create one, promote one, or reclassify one.
IMPACT_SLOTS: dict[str, list[dict]] = {
    CONFIRMED: [
        {"key": "what_changes", "title": "What changes for the contract",
         "guidance": "In plain language, what the code permits after this commit that it did "
                     "not permit before. Facts from the record only."},
        {"key": "who_is_exposed", "title": "Who is exposed",
         "guidance": "Which participants depend on the control that was removed. Describe "
                     "roles conceptually; do not name real people, protocols, or addresses "
                     "that are not in the record."},
        {"key": "preconditions", "title": "Preconditions for it to matter",
         "guidance": "What must be true of the deployment for this to have consequences - "
                     "e.g. that the affected version is the live one. State them as "
                     "conditions, not as established facts. No exploit steps."},
    ],
    CANDIDATE: [
        {"key": "what_changes", "title": "What the change would mean if it were confirmed",
         "guidance": "Conditional language only. This finding has NOT met the bar, so describe "
                     "what WOULD follow if it did, never what does follow."},
        {"key": "what_is_unknown", "title": "What is still unknown",
         "guidance": "Walk the missing evidence fields in the record and say what each absence "
                     "prevents anyone from concluding. This is the point of the document."},
        {"key": "preconditions", "title": "Preconditions that were not established",
         "guidance": "State the conditions that would have to hold, and note that the record "
                     "does not establish them. No severity, no impact rating, no exploit "
                     "material."},
    ],
}

def header_for(facts: dict) -> str:
    """The hardcoded framing line for this verdict. Code writes this, never the model."""
    if facts.get("verdict") == CONFIRMED:
        return CONFIRMED_HEADER.format(
            contract=facts.get("contract") or "?",
            function=facts.get("function") or "(contract-level)")
    missing = facts.get("missing_evidence") or []
    return CANDIDATE_HEADER.format(missing=", ".join(missing) if missing else "none recorded")


def _slot_set(kind: str) -> dict:
    return IMPACT_SLOTS if kind == "impact" else SLOTS


def skeleton(facts: dict, kind: str = "report") -> dict:
    """What the model is asked to fill: the header it CANNOT change, the facts
    already rendered, and the empty prose slots.

    `kind` selects WHICH slot set, never anything else. The header, the fact
    block, the unknown-key dropping in `assemble` and the whole verification
    gate are shared, so a second narration type cannot acquire weaker rules
    than the first by construction."""
    verdict = facts.get("verdict") or CANDIDATE
    return {
        "status": "success",
        "finding_id": facts.get("finding_id"),
        "verdict": verdict,
        "header": header_for(facts),
        "header_is_fixed": True,
        "facts_rendered_by_code": _fact_block(facts),
        "kind": kind,
        "slots": [dict(s, content="")
                  for s in _slot_set(kind).get(verdict, _slot_set(kind)[CANDIDATE])],
        "rules": [
            "Fill only the 'content' of each slot. Everything else is rendered by code.",
            "Do not restate commit hashes, addresses, line numbers or file paths - they are "
            "already rendered above and will be re-rendered from the finding object.",
            "Never assert that a CANDIDATE finding is confirmed, exploitable, or a vulnerability.",
            "No exploit code, calldata, or proof-of-concept transactions, under any verdict.",
        ],
    }


def _fact_block(facts: dict) -> str:
    """Every fact, rendered from the finding object by code."""
    lines = [
        f"- rule            : {facts.get('rule_id')}  ({facts.get('owasp') or 'n/a'})",
        f"- location        : {facts.get('file')}:{facts.get('line')}",
        f"- declaration     : {facts.get('contract')}"
        f"{('.' + facts['function']) if facts.get('function') else ''}",
        f"- engine detail   : {facts.get('detail')}",
        f"- regression commit: {facts.get('commit')}",
        f"- parent commit   : {facts.get('parent')}",
        f"- author / date   : {facts.get('author')} / {facts.get('date')}",
        f"- changed lines   : {facts.get('line_range')}",
        f"- still at HEAD   : {facts.get('survives_to_head')}",
    ]
    if facts.get("liveness"):
        lines.append(f"- on-chain        : {facts.get('liveness')} - {facts.get('liveness_reason')}")
        if facts.get("liveness") == "LIVE" and facts.get("live_caveat"):
            lines.append(f"- IMPORTANT       : {facts['live_caveat']}")
    ev = facts.get("evidence") or {}
    lines.append("- required evidence:")
    for k, v in ev.items():
        lines.append(f"    [{'x' if v not in (None, '', [], {}) else ' '}] {k}: "
                     f"{v if v not in (None, '', [], {}) else 'NOT ESTABLISHED'}")
    if facts.get("downgrade_reasons"):
        lines.append("- why not CONFIRMED:")
        for r in facts["downgrade_reasons"]:
            lines.append(f"    - {r}")
    return "\n".join(lines)


def assemble(facts: dict, slot_content: Optional[dict] = None,
             kind: str = "report") -> str:
    """Render the final markdown.

    The header and the fact block come from `facts`. `slot_content` supplies
    prose for KNOWN slot keys only; unknown keys are dropped rather than
    trusted, so a model cannot smuggle in a section of its own design.
    """
    verdict = facts.get("verdict") or CANDIDATE
    slot_content = slot_content or {}
    table = _slot_set(kind)
    known = {s["key"]: s for s in table.get(verdict, table[CANDIDATE])}

    out = [f"# {header_for(facts)}", ""]
    if verdict == CANDIDATE:
        out += [
            "> This document describes a finding that **did not meet Chainwatch's "
            "CONFIRMED bar**. It is not a vulnerability report and must not be read "
            "as one.", ""]
    out += ["## Facts (rendered from the finding record)", "",
            _fact_block(facts), ""]
    for key, spec in known.items():
        body = (slot_content.get(key) or "").strip()
        out += [f"## {spec['title']}", "", body or "_(not written)_", ""]
    out += ["---",
            f"Generated by Chainwatch from finding `{facts.get('finding_id')}`. "
            f"Verdict `{verdict}` was decided by the deterministic engine, not by a "
            f"language model."]
    return "\n".join(out)
