# Capability 12 — the reporting agent: tool design

**Status: BUILT AND WIRED.** Tools, templates and the mechanical gate are
implemented (`agent/`); both front ends call one runner (`agent/runner.py`);
the whole product is **containerized and locally verified**. **Cloud Run
deployment is pending** — it needs a Google Cloud project and credentials that
were not available, and is deferred rather than cancelled (TODO.md, 2026-08-16).

Track: "The Taskmaster". Judging weights this design targets: 40% *autonomous,
high-value action over simple chat*, 30% *architectural discipline*.

---

## 1. Stack — confirmed, not assumed (2a)

Checked against PyPI and the current ADK docs on 2026-08-15, because ADK moves
fast and training-data recall is not evidence.

| Fact | Value |
|---|---|
| `google-adk` latest | **2.7.0** |
| `google-genai` latest | **2.18.1** |
| ADK requires | Python **>= 3.10**; `google-genai >=2.12.1,<3`; `pydantic >=2.12,<3`; `fastapi >=0.133,<1`; `google-auth[pyopenssl] >=2.47` |
| ADK 2.x vs 1.x | **Breaking**: agent API, event model, session schema. Sessions written by 2.0+ are readable by 1.28+, not by older 1.x. Pin `>=2.7,<3`. |
| Tool definition | A **plain Python function** placed in an agent's `tools` list is auto-wrapped as a `FunctionTool`. |
| Schema derivation | From the function **name**, **docstring**, and **type hints**. A parameter with a type hint and no default is required. |
| Return convention | **A dict.** Non-dict returns get wrapped as `{"result": ...}`. Include a `"status"` key. |
| Error convention | **Return** `{"status": "error", "error_message": "..."}` — do not raise. |
| Import path | `from google.adk.tools import ToolContext, LongRunningFunctionTool` |

**Local compatibility, already checked:** `fastapi 0.139.0` ✓, `pydantic 2.13.4` ✓.
**Risk flagged:** this box runs **Python 3.14.4**. ADK declares `>=3.10` but is
unlikely to be *tested* on 3.14. This is the single most likely early blocker
and must be settled by an install-and-import smoke test before any agent code,
not after.

**Rate limits are a config change, not an architecture change.** The Gemini
free tier allows 15 `generate_content` requests per minute per model, and one
finding costs roughly five to eight of them. `agent/runner.py` paces at the
individual MODEL REQUEST via ADK's `before_model_callback`, and honours the
server's own `retryDelay` on a 429. Moving to a paid tier means raising
`RateLimiter(max_requests=...)` (or passing `--rpm`) — no code path, tool, or
boundary moves.

**Do we need ADK at all?** `google-genai` alone supports automatic function
calling and would be lighter. ADK is still the recommendation: it supplies the
session/state model and the Cloud Run deployment path (2e), and the track is
explicitly agentic. Underneath, ADK uses `google-genai` anyway.

---

## 2. The architectural boundary (this is the 30% criterion)

```
   deterministic engine                    |   agent layer
   ------------------------------------    |   ---------------------------
   rules/  -> attribution -> verdict.py    |   tools read a FINISHED report
   scan.py -> report JSON  ---------------->   agent drafts prose
                                           |   agent NEVER imports a rule
                                           |   agent NEVER re-runs analysis
                                           |   agent CANNOT change a verdict
```

Five properties, each enforced structurally rather than by prompt:

1. **One-way dependency.** `agent/` may import nothing from `src/rules/`. Its
   only input is a completed report dict. Enforceable by a test that asserts
   the import graph.
2. **The agent cannot analyse.** No tool reads a `.sol` file, invokes Slither,
   or touches an RPC. Every fact it can state already exists as a field in the
   finding object.
3. **The agent cannot decide.** `verdict`, `downgrade_reasons`, and the six
   evidence fields are inputs. There is no tool that writes them.
4. **Credential isolation.** The agent reads `GEMINI_API_KEY` only. It never
   sees `RPC_URL`. Keys are never placed in a report, a tool return, or a log.
5. **No outward-facing action, by charter.** There is deliberately no
   `post_to_github`, `send_email`, or `open_issue` tool. CHARTER: *"Auto-publish
   or auto-disclose anything… Never automated."* The agent's terminal action is
   writing a file to local disk. **Stating this as a design decision is itself
   the Architectural Discipline point** — an agent that could disclose would be
   a worse product, not a more impressive one.

### RESOLVED — amendment approved 2026-08-15

The conflict recorded below was settled: the amendment was approved **with a
structural requirement**, and the amended rule now lives verbatim in
**RULES.md** (the authoritative file), which cites this document as the
implementing spec. The requirement, restated because it constrains tool 4:

> The CANDIDATE framing is a **template wrapper the model's prose is injected
> into**, never an instruction the model is asked to follow. The renderer emits
> a hardcoded `NOT CONFIRMED — missing evidence: {missing_fields}` header; the
> model contributes only named prose slots inside it. The CANDIDATE skeleton has
> **no severity and no impact section**, so there is no slot in which
> "confirmed" or "exploitable" language could land.

`verify_report` (tool 5) gains a corresponding mechanical check: for a CANDIDATE
draft, assert the hardcoded header is present and unmodified, and assert no
severity/impact section was invented. A draft failing either is rejected the
same way a hallucinated commit hash is.

### ⚠ The conflict as originally raised (retained for provenance)

RULES.md states a **hard rule**: *"the LLM never sees CANDIDATE or DISCARDED.
If it never sees a non-finding, it can never write a convincing report about
one. This is the entire false-positive defence — architectural, not
probabilistic."*

Our only real-world demonstration material is a **CANDIDATE**
(`ActFacet.revenueOverview`, see SUBMISSION-NOTES.md). Under the rule as
written, the agent may not see it, and there is nothing to demo.

**Proposed amendment, for the human to accept or reject — I have not applied
it:**

> The LLM never sees a **DISCARDED** verdict, and never sees raw rule output.
> It may see a CANDIDATE **only** through a template that is structurally
> incapable of asserting a vulnerability: for a CANDIDATE the document's thesis
> is *"this did not meet the bar, and here is precisely which evidence is
> missing."*

Rationale: the rule's stated purpose is to stop the model writing a *convincing
vulnerability report about a non-finding*. A verdict-dispatched template that
can only produce a "not confirmed" dossier preserves that purpose while making
the honest case demonstrable. If rejected, capability 12 demos on a synthetic
CONFIRMED finding clearly labelled as synthetic — which is weaker, but honest.

---

## 3. The tools

Six MUST-HAVE. All are thin readers over an existing report dict; none performs
analysis. All return dicts with `status`, per ADK convention.

| # | Tool | Purpose | Why it exists |
|---|---|---|---|
| 1 | `list_findings(scan_id)` | Index: `finding_id`, rule, verdict, contract, function, file, line, commit. **No prose.** | The agent must *choose* what to work on — this is the triage step that makes it autonomous rather than a formatter |
| 2 | `get_finding(finding_id)` | Full bundle: six evidence fields with established/not, `downgrade_reasons`, trajectory (parent → commit → HEAD), liveness + `LIVE_CAVEAT`, raw rule evidence | The single source of every fact the report may contain |
| 3 | `get_diff(finding_id)` | The actual `git diff` for that file at that commit | Ground truth. Lets the agent check the engine's claim against the change, and quote real code |
| 4 | `draft_report(finding_id, audience)` | Returns a **skeleton with every fact pre-filled by code** and named prose slots left empty | Facts come from code; narrative comes from the model. The model cannot get a hash wrong because it never types one |
| 5 | `verify_report(finding_id, markdown)` | **Mechanical, non-LLM.** Extracts every commit hash, address, line number, function name and file path from the draft and asserts each appears in the finding object. Returns offending spans | The zero-tolerance hallucination gate, callable by the agent so it can self-correct |
| 6 | `save_report(finding_id, markdown)` | Writes to `reports/<scan>/<finding>.md`, returns the path | The terminal artifact — the "did something" for the 40% criterion |

**The loop that makes it autonomous (40%):** given a finished scan, the agent
*decides* which findings merit a write-up, pulls evidence, reads the real diff,
drafts, **runs the verifier on its own output, and revises until it passes**,
then saves. Multi-step, tool-driven, self-correcting, ending in an artifact —
not a chat turn.

### Verdict-dispatched output (tool 4)

| verdict | document produced |
|---|---|
| CONFIRMED | Responsible-disclosure dossier: what broke, which commit, reachability, liveness (with `LIVE_CAVEAT` verbatim), remediation |
| CANDIDATE | **"Not confirmed" dossier**: what the rule found, and a field-by-field account of which of the six is missing and why that is the correct call |
| DISCARDED | Not exposed at all |

The CANDIDATE template has no "impact" or "severity" section to fill. It cannot
overclaim because the shape does not allow it.

### Stretch, explicitly not in the 15-day plan

| Tool | Verdict |
|---|---|
| `check_similar_cve(query)` | **Stretch.** Adds an external dependency and a hallucination surface (the model paraphrasing someone else's CVE). Only with `verify_report` extended to cite-check it |
| `rescan_at_head()` | **Rejected.** Lets the agent influence analysis; breaks property 2 and 3 |
| `post_to_github` / `send_email` | **Rejected by charter**, permanently |

---

## 4. Plan for the remaining window (~15 days to Aug 31)

| | Work | Est. |
|---|---|---|
| Gate 0 | `pip install google-adk` + import smoke test on **Python 3.14** | 0.5 d — **do this first, it is the blocker** |
| 2c | Tools 1–3 + 5 (`verify_report` first — the gate before the generator) | 1 d |
| 2c | Hallucination test on the ActFacet finding, graded against the checklist | 0.5 d |
| 2d | Tools 4 + 6, wire "Generate report" into the existing web UI and CLI | 1 d |
| 2e | Cloud Run deploy + evidence capture | 1 d |
| 2f | Devpost | 0.5 d |

Building `verify_report` **before** `draft_report` is deliberate: the gate must
exist before the thing it gates, or the first draft that looks good gets
trusted.

**Not in scope:** HIST-L2 auto-install, the 1b re-run, 1c profiling, and the
RC-RENAME1 rule. All documented, all deferred.
