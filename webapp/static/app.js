/* Chainwatch UI.
 *
 * Renders whatever the engine reports and nothing more. Two rules this file
 * follows deliberately:
 *   1. Coverage is drawn before findings, always, even when there are none -
 *      "0 findings" and "0 findings out of 3 analysable commits" are different
 *      claims and the UI must not blur them.
 *   2. No verdict is computed here. `verdict`, `downgrade_reasons` and the six
 *      evidence fields come from src/verdict.py; the browser only formats them.
 */

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/* Motion helpers. Every animation here communicates a STATE CHANGE and every
 * one degrades to an instant set when the OS asks for reduced motion — the
 * essential value (the number, the colour, the badge) is never motion-gated. */
const prefersReduced = () =>
  window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/* Tween one element's number toward data-count-to. A count that ticks upward
 * says "coverage advanced" far better than a value that snaps into place. */
function countUp(el) {
  const to = parseFloat(el.dataset.countTo);
  const dec = parseInt(el.dataset.decimals || "0", 10);
  if (!isFinite(to)) return;
  if (prefersReduced()) { el.textContent = to.toFixed(dec); return; }
  const dur = 520, t0 = performance.now();
  const step = (t) => {
    const p = Math.min((t - t0) / dur, 1);
    const eased = 1 - Math.pow(1 - p, 3);              // ease-out cubic
    el.textContent = (to * eased).toFixed(dec);
    if (p < 1) requestAnimationFrame(step);
    else el.textContent = to.toFixed(dec);
  };
  requestAnimationFrame(step);
}
function animateCounts(root) {
  root.querySelectorAll("[data-count-to]").forEach(countUp);
}
/* Progress bar: born at width 0, driven to its target on the next frame so the
 * CSS width-transition actually fires (a width set at creation would not). */
function animateBar(root, pct) {
  const i = root.querySelector(".bar > i");
  if (!i) return;
  if (prefersReduced()) { i.style.width = pct + "%"; return; }
  requestAnimationFrame(() => { i.style.width = pct + "%"; });
}
/* One-shot attention pulse: add the class, strip it when the animation ends so
 * it can be re-triggered on the next arrival and never loops. */
function pulseOnce(el) {
  if (!el || prefersReduced()) return;
  el.classList.remove("pulse");
  void el.offsetWidth;                                  // restart the animation
  el.classList.add("pulse");
  el.addEventListener("animationend", () => el.classList.remove("pulse"), { once: true });
}

let JOB = null;
let SOURCE = null;
let REPORT = null;
let RULE_TITLES = {};

/* A scan that could not run must say so at the same weight as a result.
 * "0 findings" and "the clone failed" are different claims and the UI must
 * never let one be mistaken for the other - the same rule the coverage block
 * already follows. */
function showAlert(head, body, note, kind) {
  const el = $("alert");
  el.className = "alert" + (kind === "warn" ? " warn" : "");
  el.innerHTML = `<div class="alert-head">${esc(head)}</div>
    <div class="alert-body">${esc(body)}</div>` +
    (note ? `<div class="alert-note">${esc(note)}</div>` : "");
}

function clearAlert() { $("alert").className = "alert hidden"; $("alert").innerHTML = ""; }

/* Time measured, and what it supports. The refusal is rendered at ALERT weight,
 * the same standard the SCAN-L1 banner set: a withheld range reads as a bug
 * unless the report itself says the withholding is deliberate and why. The
 * `refusal` string already carries the age->bias->13x argument (SIZE-L1); this
 * function only has to make sure it reaches the screen and not just the JSON. */
function renderSizing(sz) {
  const el = $("sizing");
  const obs = sz.observed;
  if (!obs) { el.className = "sizing hidden"; el.innerHTML = ""; return; }

  const sp = sz.per_comparison_seconds, cvg = sz.coverage_pct;
  const rows = `
    <div class="cov-metric"><b>${obs.pairs}</b><span>pair(s) measured</span></div>
    <div class="cov-metric"><b>${obs.comparisons}</b>
      <span>comparison(s), ${obs.comparisons_ok} ok</span></div>
    <div class="cov-metric"><b>${obs.seconds}s</b><span>elapsed, measured</span></div>
    ${sp ? `<div class="cov-metric"><b>${sp.low}-${sp.high}s</b>
      <span>per comparison (${sp.basis_n} pairs)</span></div>` : ""}
    ${cvg ? `<div class="cov-metric"><b>${cvg.low}-${cvg.high}%</b>
      <span>coverage spread (${cvg.basis_n} pairs)</span></div>` : ""}`;

  let tail;
  if (sz.projection) {
    const p = sz.projection;
    tail = `<p class="cov-note"><b>Remaining:</b> ${p.low}-${p.high}s
      <span class="muted">— a range of what this run has done, not a prediction.</span></p>
      <p class="cov-note muted">${esc(sz.caveat || "")}</p>`;
  } else if (sz.refusal) {
    /* Banner weight: a deliberate refusal, not a missing number. */
    tail = `<div class="sizing-refusal">
      <div class="alert-head">No time estimate — and this is why</div>
      <div class="alert-body">${esc(sz.refusal)}</div></div>`;
  } else {
    tail = "";
  }

  el.className = "sizing" + (sz.refusal ? " refused" : "");
  el.innerHTML = `<div class="cov-head">Sizing — measured, not predicted</div>
    <div class="cov-grid">${rows}</div>${tail}`;
}

/* Capability 13 - live one-shot-exposure probe. NEVER a finding, NEVER part
 * of the verdict model - drawn as its own instrument card, same weight class
 * as sizing, for exactly that reason. */
function renderExposure(rows) {
  const el = $("exposure");
  if (!rows || !rows.length) { el.className = "exposure hidden"; el.innerHTML = ""; return; }
  el.className = "exposure";
  el.innerHTML = `<div class="cov-head">Exposure probe — capability 13
      <span class="muted">(live, present-tense, not a finding)</span></div>` +
    rows.map((r) => `<div class="exp-row exp-${esc(r.status)}">
        <span class="exp-status">${esc(r.status)}</span>
        <span class="exp-who">${esc(r.contract)}.${esc(r.function)}</span>
        <span class="exp-reason">${esc(r.reason || "")}</span>
      </div>`).join("");
}

/* Capability 19 - the funnel and the resolution queue.
 *
 * Renders a DERIVED view and nothing else. `distance_to_confirmed` is a count
 * of gates that have not been able to run - not a likelihood, not a score, and
 * emphatically not a ranking of how real a finding is. The engine computed
 * every value here and `funnel.verify` already re-derived each verdict from
 * its own recorded gate states before the report left the server; the browser
 * only formats what it is handed, exactly as it does for verdicts.
 */
function renderFunnel(fun) {
  const el = $("funnel");
  const traces = (fun && fun.traces) || [];
  if (!traces.length) {
    el.className = "funnel hidden";
    el.innerHTML = "";
    return;
  }
  const s = fun.summary || {};
  const med = s.median_distance_to_confirmed;

  const verdictChips = Object.entries(s.verdicts || {})
    .map(([v, n]) => `<div class="cov-metric"><b>${n}</b><span>${esc(v)}</span></div>`)
    .join("");

  const gateBars = (obj, cls) => Object.entries(obj || {})
    .map(([g, n]) => `<div class="gate-row ${cls}">
        <span class="gate-n">${n}</span>
        <span class="gate-name">${esc(g)}</span></div>`).join("");

  /* Sorted server-side (funnel.resolution_queue); the browser must not
   * reorder it, or two surfaces would disagree about what to work on next. */
  const queue = (fun.resolution_queue || [])
    .map((id) => traces.find((t) => t.finding_id === id))
    .filter(Boolean);

  const queueRows = queue.map((t, i) => `
    <div class="q-row">
      <div class="q-rank">${i + 1}</div>
      <div class="q-main">
        <div class="q-head">
          <span class="q-dist" title="Gates that have not been able to run. NOT a likelihood.">distance ${t.distance_to_confirmed}</span>
          <span class="q-id">${esc(t.finding_id)}</span>
          <span class="q-rule">${esc(t.rule_class || "")}</span>
        </div>
        ${(t.required_inputs || []).length ? `<div class="q-supply">
          <b>supply:</b> ${(t.required_inputs || []).map((r) => `<code>${esc(r)}</code>`).join(" ")}
        </div>` : ""}
        ${(t.evidence_requests || []).map((r) => `
          <div class="q-req">
            <span class="q-gate">${esc(r.gate)}</span>
            <span class="q-status">${esc(r.status)}</span>
            <span class="q-how">${esc(r.how)}</span>
          </div>`).join("")}
      </div>
    </div>`).join("");

  el.className = "funnel";
  el.innerHTML = `
    <div class="cov-head">Funnel — capability 19
      <span class="muted">(derived from the engine's own gate states; decides nothing)</span></div>
    ${fun.divergence ? `<div class="sizing-refusal">
      <div class="alert-head">Trace divergence</div>
      <div class="alert-body">${esc(fun.divergence)}</div></div>` : ""}
    <div class="cov-grid">
      ${verdictChips}
      <div class="cov-metric"><b>${s.resolvable ?? 0}</b><span>resolvable by evidence</span></div>
      <div class="cov-metric"><b>${s.killed ?? 0}</b><span>killed at a gate</span></div>
      ${med !== null && med !== undefined
        ? `<div class="cov-metric"><b>${med}</b><span>median distance to CONFIRMED</span></div>` : ""}
    </div>
    ${Object.keys(s.kill_gates || {}).length ? `<div class="gate-block">
      <div class="gate-title">Killed at</div>${gateBars(s.kill_gates, "kill")}</div>` : ""}
    ${Object.keys(s.blocking_gates || {}).length ? `<div class="gate-block">
      <div class="gate-title">Blocked on — a gate that could not run</div>
      ${gateBars(s.blocking_gates, "block")}</div>` : ""}
    ${queueRows ? `<div class="q-block">
      <div class="gate-title">Resolution queue — closest to a decidable answer first</div>
      <p class="cov-note">Distance counts mechanical checks that have not run.
        It is not a likelihood and it never promotes anything: supplying the
        named input lets the gate run, and the same verdict function decides
        the outcome.</p>
      ${queueRows}</div>`
      : `<p class="cov-note">Nothing here is resolvable by supplying evidence.</p>`}`;
}

/* Capability 21 - sweep history.
 *
 * Draws unattended runs, and draws FAILED targets at the same weight as
 * successful ones. A sweep page that quietly hides the repos that would not
 * clone is the same mistake as a scan report that hides coverage: the reader
 * cannot tell "nothing was found" from "nothing was looked at".
 */
async function loadSweeps() {
  const el = $("sweeps");
  if (!el) return;
  let data;
  try {
    data = await (await fetch("/api/sweeps?limit=10")).json();
  } catch (e) {
    el.className = "sweeps hidden";
    return;
  }

  if (!data.available) {
    el.className = "sweeps";
    el.innerHTML = `<div class="cov-head">Sweeps — capability 21
        <span class="muted">(unattended, scheduled runs)</span></div>
      <p class="cov-note">Sweep history is <b>not recorded</b>: ${esc(data.reason
        || "no corpus configured")}. Scans still run; they are just not
        persisted, so this list cannot say whether any sweep has ever run.</p>`;
    return;
  }
  if (!data.sweeps || !data.sweeps.length) {
    el.className = "sweeps";
    el.innerHTML = `<div class="cov-head">Sweeps — capability 21
        <span class="muted">(unattended, scheduled runs)</span></div>
      <p class="cov-note">No sweep has been recorded yet.</p>`;
    return;
  }

  const when = (t) => {
    const d = new Date((t || 0) * 1000);
    return isFinite(d.getTime()) ? d.toISOString().replace("T", " ").slice(0, 16) : "—";
  };

  el.className = "sweeps";
  el.innerHTML = `<div class="cov-head">Sweeps — capability 21
      <span class="muted">(unattended, scheduled runs)</span></div>` +
    data.sweeps.map((s) => {
      const t = s.totals || {};
      const rows = (s.results || []).map((r) => `
        <div class="sw-row ${r.ok ? "sw-ok" : "sw-fail"}">
          <span class="sw-mark">${r.ok ? "ok" : "FAIL"}</span>
          <span class="sw-repo">${esc(r.repo)}</span>
          <span class="sw-meta">${r.ok
            ? `${(r.summary || {}).findings ?? 0} finding(s) · ${r.seconds}s`
            : esc(r.error || "failed")}</span>
        </div>`).join("");
      return `<div class="sw-block">
        <div class="sw-head">
          <span class="sw-id">${esc(s.sweep_id || "")}</span>
          <span class="sw-when">${when(s.started_at)}</span>
          <span class="sw-tot">${t.ok ?? 0} ok · ${t.failed ?? 0} failed ·
            ${t.findings ?? 0} finding(s) · ${t.confirmed ?? 0} CONFIRMED</span>
        </div>${rows}</div>`;
    }).join("");
}

// -------------------------------------------------------------- bootstrap

/* Decorative only — the moving grid/orbs are pure CSS; this just seeds a
 * handful of rising dots so the atmosphere isn't perfectly static. Reuses
 * the existing non-verdict accent tokens via CSS, no colour choice here. */
(function seedParticles() {
  const bg = document.querySelector(".bg");
  if (!bg || prefersReduced()) return;
  for (let i = 0; i < 22; i++) {
    const p = document.createElement("div");
    p.className = "particle";
    p.style.left = Math.random() * 100 + "%";
    p.style.animationDuration = (14 + Math.random() * 18) + "s";
    p.style.animationDelay = -(Math.random() * 20) + "s";
    bg.appendChild(p);
  }
})();

/* Real capability status, not decoration: the same /api/agent and /api/corpus
 * endpoints the rest of the app already trusts to say "available" honestly
 * rather than fail obscurely (see webapp/server.py's own docstrings on both). */
(async function loadCapabilityPills() {
  try {
    const agent = await (await fetch("/api/agent")).json();
    const on = !!agent.available;
    $("agent-pill").className = "pill " + (on ? "on" : "off");
    $("agent-pill-state").textContent = on ? agent.model || "available" : "no API key";
    $("cap-agent-badge").textContent = on ? (agent.model || "available") : "no API key";
  } catch (e) {
    $("agent-pill-state").textContent = "unreachable";
    $("cap-agent-badge").textContent = "unreachable";
  }
  try {
    const corpus = await (await fetch("/api/corpus")).json();
    const on = !!corpus.available;
    $("corpus-pill").className = "pill " + (on ? "on" : "off");
    $("corpus-pill-state").textContent = on ? corpus.database || "recording" : "not connected";
  } catch (e) {
    $("corpus-pill-state").textContent = "unreachable";
  }
})();

loadSweeps();

fetch("/api/rules").then((r) => r.json()).then((d) => {
  RULE_TITLES = d.titles;
  $("rule-boxes").innerHTML = d.order.map((r) =>
    `<label title="${esc(d.titles[r])}"><input type="checkbox" value="${r}" checked> ${r}</label>`
  ).join("");
  restoreLast();
});

/* Re-attach to the most recent scan on load: a reload during a long walk should
 * not lose the run, and a finished report should still be readable (including
 * its diffs, which need the job's repo path server-side). */
async function restoreLast() {
  try {
    const { scans } = await (await fetch("/api/scans")).json();
    if (!scans || !scans.length) return;
    const last = scans[0];
    JOB = last.id;
    if (["queued", "cloning", "running"].includes(last.status)) {
      $("go").disabled = true;
      $("cancel").disabled = false;
      setStatus(last.status, "running");
      listen(JOB);
      return;
    }
    const data = await (await fetch(`/api/scan/${JOB}`)).json();
    if (data.report) {
      REPORT = data.report;
      render(REPORT);
      setStatus(`${last.status} (previous scan)`, last.status === "done" ? "done" : "");
      log("info", `restored scan ${JOB} of ${last.repo}`);
      return;
    }
    /* No report means the scan never produced one - it failed before or during
     * the walk. Previously this branch did nothing at all, so a reload after a
     * failed scan showed an idle page with an empty log: the user was left with
     * no trace that anything had gone wrong, or why. */
    if (last.status === "error" || last.status === "cancelled") {
      setStatus(`${last.status} (previous scan)`, last.status === "error" ? "error" : "");
      showAlert(
        last.status === "error" ? "This scan could not run" : "Scan cancelled",
        last.error || "no reason was recorded",
        `${last.repo} — nothing was analysed, so this is not a result about the code.`,
        last.status === "error" ? "" : "warn");
      $("findings-body").innerHTML =
        `<div class="placeholder">Not analysed — see the message above.</div>`;
    }
  } catch (e) { /* nothing to restore */ }
}

$("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const rules = [...document.querySelectorAll("#rule-boxes input:checked")].map((i) => i.value);
  if (!rules.length) { alert("Select at least one rule."); return; }

  const body = {
    repo: $("repo").value.trim(),
    limit: parseInt($("limit").value, 10) || 15,
    root_dir: $("root_dir").value.trim(),
    address: $("address").value.trim() || null,
    rules,
    check_head_survival: $("head_check").checked,
    check_exposure: $("exposure_check").checked,
    check_exploit_proof: $("exploit_check").checked,
  };

  setStatus("starting…", "running");
  clearAlert();
  $("log").innerHTML = "";
  $("findings-body").innerHTML = `<div class="placeholder">Scanning…</div>`;
  $("rank-wrap").className = "rank-wrap hidden";
  $("rank-box").innerHTML = "";
  $("exposure").className = "exposure hidden";
  REPORT = null;

  const res = await fetch("/api/scan", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  if (!res.ok) {
    const t = await res.text();
    setStatus("error", "error");
    log("error", t);
    return;
  }
  JOB = (await res.json()).id;
  $("go").disabled = true;
  $("cancel").disabled = false;
  listen(JOB);
});

$("cancel").addEventListener("click", () => {
  if (JOB) fetch(`/api/scan/${JOB}/cancel`, { method: "POST" });
  log("info", "cancellation requested — the current commit pair finishes first");
});

$("drawer-close").addEventListener("click", () => $("drawer").classList.add("hidden"));
$("drawer").addEventListener("click", (e) => {
  if (e.target === $("drawer")) $("drawer").classList.add("hidden");
});

// -------------------------------------------------------------------- stream

function listen(id) {
  if (SOURCE) SOURCE.close();
  SOURCE = new EventSource(`/api/scan/${id}/events`);
  SOURCE.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    handle(ev);
    if (ev.kind === "closed") { SOURCE.close(); finish(id, ev.status); }
  };
  SOURCE.onerror = () => { /* server closes the stream when the scan ends */ };
}

function handle(ev) {
  switch (ev.kind) {
    case "start":
      log("info", `scanning ${ev.repo}`); break;
    case "scope":
      log("info", `scope: ${(ev.roots || []).map((r) => r || "(repo root)").join(", ")
        || "(nothing)"} — ${ev.reason || ""}`);
      break;
    case "pairs":
      log("info", `${ev.total} commit pair(s) to analyse`); break;
    case "pair":
      setStatus(`pair ${ev.index}/${ev.total}`, "running");
      log("pair", `[${ev.index}/${ev.total}] ${ev.prev}..${ev.cur}  ${ev.subject || ""}`);
      break;
    case "skip":
      log("skip", `    SKIPPED ${ev.prev}..${ev.cur} — ${ev.reason}`); break;
    case "finding": {
      /* Class the log line by VERDICT so red stays reserved for CONFIRMED and
       * amber for CANDIDATE — the same controlled-vocabulary rule the table
       * follows. A skip (below) is infra, not a verdict, and takes its own tone. */
      const cls = ev.verdict === "CONFIRMED" ? "find-confirmed"
                : ev.verdict === "CANDIDATE" ? "find-candidate" : "find";
      const where = ev.function ? `${ev.contract}.${ev.function}` : `${ev.contract}`;
      log(cls, `    ${ev.verdict} rule ${ev.rule}  ${ev.file}::${where}`);
      break;
    }
    case "liveness":
      log("info", `checking on-chain liveness for ${ev.address}`); break;
    case "exposure":
      log("info", `    exposure probe: ${ev.status} ${ev.contract}.${ev.function}`); break;
    case "exploit-proof":
      log(ev.status === "OPEN" ? "find-confirmed" : "info",
        `    exploitability proof: ${ev.status} ${ev.contract}.${ev.function}`);
      break;
    case "env":
      /* The longest silent phase of a scan: a large monorepo dependency
       * install runs for minutes with nothing else to show. Without this the
       * live log simply stops and the scan looks hung. */
      log("info", `... ${ev.message}`); break;
    case "warn": case "info":
      log("info", ev.message); break;
    case "error":
      log("skip", ev.message); break;
    case "done":
      log("done", `finished: ${ev.findings} finding(s), ` +
        `${ev.pairs_analyzed}/${ev.pairs_total} pairs analysed, ${ev.seconds}s`);
      break;
  }
}

async function finish(id, status) {
  $("go").disabled = false;
  $("cancel").disabled = true;
  setStatus(status, status === "done" ? "done" : (status === "error" ? "error" : ""));
  const data = await (await fetch(`/api/scan/${id}`)).json();
  if (data.report) { REPORT = data.report; render(REPORT); return; }
  if (status === "error") {
    showAlert("This scan could not run", data.error || "no reason was recorded",
      "Nothing was analysed. This is an environment or input failure, not a "
      + "result about the repository's code.");
    $("findings-body").innerHTML =
      `<div class="placeholder">Not analysed — see the message above.</div>`;
  }
}

function log(cls, msg) {
  const el = document.createElement("div");
  el.className = "l-" + cls;
  el.textContent = msg;
  $("log").appendChild(el);
  $("log").scrollTop = $("log").scrollHeight;
}

function setStatus(text, cls) {
  $("status").textContent = text;
  $("status").className = "status " + (cls || "");
}

// -------------------------------------------------------------------- render

function render(rep) {
  const cov = rep.coverage, s = rep.summary;

  /* A scan that compared no Solidity at all is not a result about the code,
   * and the engine now says so in `nothing_compared`. Shown at the top, at the
   * same weight as a failure, because "0 findings over 0 comparisons" reads
   * exactly like "0 findings over 400" unless something stops it. */
  if (rep.nothing_compared) {
    showAlert("Not a result about this code", rep.nothing_compared,
      "Chainwatch compiled nothing, so no rule ever ran.", "warn");
  } else {
    clearAlert();
  }
  const partial = cov.pairs_analyzed < cov.pairs_total || cov.files_error > 0
                  || (cov.files_skipped || 0) > 0 || (cov.files_partial || 0) > 0;

  const skipCounts = {};
  (cov.skips || []).forEach((k) => { skipCounts[k.reason] = (skipCounts[k.reason] || 0) + 1; });
  (cov.file_skips || []).forEach((k) => { skipCounts[k.reason] = (skipCounts[k.reason] || 0) + 1; });
  const skipLines = Object.entries(skipCounts)
    .map(([r, n]) => `<div class="cov-note">· ${n} × ${esc(r)}</div>`).join("");

  const sc = rep.scope || {};
  const scopeLine = sc.roots
    ? `<div class="scope-line"><b>Scope</b>
         <span class="scope-roots">${esc((sc.roots.length
            ? sc.roots.map((r) => (r ? r + "/" : "(repository root)")).join(", ")
            : "nothing"))}</span>
         <span class="muted">${esc(sc.mode === "explicit"
            ? "as requested" : "detected automatically")}</span>
         <div class="cov-note">${esc(sc.reason || "")}</div></div>`
    : "";

  $("coverage").className = "coverage" + (partial ? " partial" : "");
  $("coverage").innerHTML = scopeLine + `
    <div class="cov-head">Coverage — read this before the findings</div>
    <div class="cov-grid">
      <div class="cov-metric"><b><span data-count-to="${cov.pairs_analyzed}">0</span>/${cov.pairs_total}</b>
        <span>commit pairs analysed (${cov.pairs_analyzed_pct}%)</span></div>
      <div class="cov-metric"><b><span data-count-to="${cov.files_ok}">0</span>/${cov.files_total}</b>
        <span>file comparisons completed (${cov.files_ok_pct}%)</span></div>
      <div class="cov-metric"><b><span data-count-to="${cov.files_error}">0</span></b>
        <span>comparisons lost to errors</span></div>
      <div class="cov-metric"><b><span data-count-to="${cov.files_skipped || 0}">0</span></b>
        <span>never attempted (toolchain missing)</span></div>
      ${cov.rule_invocations_total ? `
      <div class="cov-metric"><b><span data-count-to="${cov.rule_invocations_ok}">0</span>/${cov.rule_invocations_answerable}</b>
        <span>rule checks completed (${cov.rule_coverage_pct}% of answerable)</span></div>` : ""}
      ${cov.files_partial ? `
      <div class="cov-metric"><b><span data-count-to="${cov.files_partial}">0</span></b>
        <span>partially analysed (some rules ran)</span></div>` : ""}
      ${cov.rule_invocations_unsupported ? `
      <div class="cov-metric"><b><span data-count-to="${cov.rule_invocations_unsupported}">0</span></b>
        <span>not applicable on this compiler</span></div>` : ""}
    </div>
    <div class="bar"><i></i></div>
    ${skipLines}
    ${partial ? `<p class="cov-note cov-warn">This scan did not see the whole
       history. Over the unanalysed commits a quiet result means
       <strong>unmeasured</strong>, not safe.</p>` : ""}`;
  animateCounts($("coverage"));
  animateBar($("coverage"), cov.pairs_analyzed_pct);

  $("summary").innerHTML = `
    <div class="chip"><b><span data-count-to="${s.findings}">0</span></b><span>findings</span></div>
    <div class="chip confirmed"><b><span data-count-to="${s.confirmed}">0</span></b><span>CONFIRMED</span></div>
    <div class="chip candidate"><b><span data-count-to="${s.candidates}">0</span></b><span>CANDIDATE</span></div>
    <div class="chip"><b>${s.seconds}s</b><span>elapsed</span></div>
    ${!rep.address ? `<div class="chip"><b>—</b><span>no address: liveness UNKNOWN,
       so nothing can reach CONFIRMED</span></div>` : ""}`;
  animateCounts($("summary"));
  /* Draw the eye to what actually landed: any finding pulses its chip; a
   * CONFIRMED finding pulses harder (a stronger, redder ring). */
  if (s.findings > 0) pulseOnce($("summary").children[0]);
  if (s.confirmed > 0) pulseOnce($("summary").querySelector(".chip.confirmed"));
  else if (s.candidates > 0) pulseOnce($("summary").querySelector(".chip.candidate"));

  renderSizing(rep.sizing || {});
  renderExposure(rep.exposure || []);
  renderFunnel(rep.funnel || {});

  const body = $("findings-body");
  if (!rep.findings.length) {
    body.innerHTML = `<div class="placeholder">
      No regression matched any selected rule over the analysed pairs.</div>`;
    $("rank-wrap").className = "rank-wrap hidden";
    return;
  }
  const order = { CONFIRMED: 0, CANDIDATE: 1, DISCARDED: 2 };
  const rows = [...rep.findings].sort(
    (a, b) => (order[a.verdict] - order[b.verdict]) || a.rule_id.localeCompare(b.rule_id));

  body.innerHTML = rows.map((f, i) => `
    <div data-i="${i}" class="frow row-${esc(f.verdict)}">
      <div>${verdictPill(f.verdict)}</div>
      <div><span class="rule-tag">${esc(f.rule_id)}</span>${f.owasp
          ? `<br><span class="owasp-tag">${esc(f.owasp)}</span>` : ""}</div>
      <div class="where">${esc(f.contract)}${f.function ? "." + esc(f.function) : ""}
          <small>${esc(f.file)}:${f.line ?? "?"}</small></div>
      <div><span class="sha">${esc((f.commit || "").slice(0, 10))}</span>
          <span class="meta">${esc((f.date || "").slice(0, 10))} ${esc(f.author || "")}</span></div>
      <div>${headCell(f)}</div>
      <div>${onChainCell(f)}</div>
    </div>`).join("");

  [...body.querySelectorAll("[data-i]")].forEach((el) =>
    el.addEventListener("click", () => openDrawer(rows[+el.dataset.i])));

  wireRankButton(rows.filter((f) => f.verdict === "CONFIRMED"));
}

function headCell(f) {
  if (f.survives_to_head === true) return `<span class="head-live">still present</span>`;
  if (f.survives_to_head === false) return `<span class="head-ok">repaired later</span>`;
  return `<span class="muted">undetermined</span>`;
}

/* Verdict badge with a redundant ICON channel: a SOLID shield for CONFIRMED, a
 * HOLLOW warning-triangle for CANDIDATE. The icon means the badge survives a
 * grayscale print or a colour-blind reader even before the fill/weight do. */
const VERDICT_ICON = {
  CONFIRMED: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>',
  CANDIDATE: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l9 16H3z"/><path d="M12 10v4"/><path d="M12 17h.01"/></svg>',
  DISCARDED: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M5 12h14"/></svg>',
};
function verdictPill(verdict) {
  const v = esc(verdict);
  return `<span class="v ${v}">${VERDICT_ICON[verdict] || ""}${v}</span>`;
}

/* On-chain cell. LIVE is an ESCALATION, not reassurance (locked decision:
 * escalated red): the vulnerable code is what is deployed. It renders as a
 * glowing filled red pill with a broadcast dot, and the caveat that LIVE
 * compares code, not exploitability. */
function onChainCell(f) {
  if (!f.liveness) return `<span class="muted">not checked</span>`;
  const caveat = esc((REPORT && REPORT.live_caveat) || "");
  const xp = f.exploit_proof;
  const xpBadge = (xp && xp.status === "OPEN")
    ? `<span class="xp-pill" title="${esc(xp.reason || "")}">callable now</span>` : "";
  if (f.liveness === "LIVE") {
    return `<span class="live-pill" title="${caveat}"><span class="dot"></span>LIVE</span>
            <span class="live-note">code, not risk</span>${xpBadge}`;
  }
  return `<span class="muted" title="${caveat}">${esc(f.liveness)}</span>${xpBadge}`;
}

// -------------------------------------------------------------------- drawer

const EV_LABELS = {
  regression_commit: "1. regression commit",
  pre_state: "2. pre-state (N-1)",
  post_state: "3. post-state (N)",
  reachability: "4. reachability",
  no_compensating_control: "5. no compensating control",
  liveness: "6. on-chain liveness",
};

function openDrawer(f) {
  const ev = f.evidence || {};
  const evRows = Object.keys(EV_LABELS).map((k) => {
    const v = ev[k];
    const has = v !== null && v !== undefined && v !== "";
    const text = has
      ? (typeof v === "object" ? JSON.stringify(v) : String(v))
      : "not established";
    return `<li class="${has ? "yes" : "no"}">
      <span class="mark">${has ? "✓" : "✕"}</span>
      <span class="k">${EV_LABELS[k]}</span>
      <span class="val">${esc(text)}</span></li>`;
  }).join("");

  $("drawer-body").innerHTML = `
    <h2 class="d-title">${esc(f.contract)}${f.function ? "." + esc(f.function) : ""}
      ${verdictPill(f.verdict)}</h2>
    <div class="d-sub">rule ${esc(f.rule_id)} — ${esc(RULE_TITLES[f.rule_id] || "")}
      · ${esc(f.file)}:${f.line ?? "?"}</div>
    <div class="d-detail">${esc(f.detail)}</div>

    <h3 class="d-h">Trajectory</h3>
    <div class="traj">
      <div class="tnode">
        <div class="tlabel">control present</div>
        <div class="tsha">${esc((f.parent || "").slice(0, 10) || "—")}</div>
        <div class="tmeta">parent commit (N−1)</div>
      </div>
      <div class="tarrow">→</div>
      <div class="tnode hit">
        <div class="tlabel">control removed here</div>
        <div class="tsha">${esc((f.commit || "").slice(0, 10))}</div>
        <div class="tmeta">${esc((f.date || "").slice(0, 10))} · ${esc(f.author || "")}<br>
          lines ${esc(f.line_range || "?")}</div>
      </div>
      <div class="tarrow">→</div>
      <div class="tnode head ${f.survives_to_head === false ? "ok" : ""}">
        <div class="tlabel">at HEAD</div>
        <div class="tsha">${f.survives_to_head === true ? "still missing"
          : f.survives_to_head === false ? "restored" : "undetermined"}</div>
        <div class="tmeta">${f.survives_to_head === true
          ? "the same rule still fires against HEAD"
          : f.survives_to_head === false
            ? "a later commit restored the control"
            : "no HEAD comparison was possible"}</div>
      </div>
    </div>

    ${f.liveness ? `<h3 class="d-h">On-chain</h3>
      <div class="d-detail">${esc(f.liveness)} — ${esc(f.liveness_reason)}</div>
      ${f.liveness === "LIVE" ? `<div class="caveat">${esc(
        (REPORT && REPORT.live_caveat) || "")}</div>` : ""}` : ""}

    ${f.exploit_proof && f.exploit_proof.status !== "NOT_APPLICABLE" ? `
      <h3 class="d-h">Exploitability proof <span class="muted">(capability 14 —
        read-only eth_call, never a transaction)</span></h3>
      <div class="d-detail xp-${esc(f.exploit_proof.status)}">
        <b>${esc(f.exploit_proof.status)}</b> — ${esc(f.exploit_proof.reason || "")}
      </div>` : ""}

    <h3 class="d-h">Required evidence (all six, or it is not CONFIRMED)</h3>
    <ul class="ev">${evRows}</ul>

    ${f.downgrade_reasons && f.downgrade_reasons.length ? `
      <h3 class="d-h">Why this is not CONFIRMED</h3>
      <div class="why"><ul>${f.downgrade_reasons.map((r) =>
        `<li>${esc(r)}</li>`).join("")}</ul></div>` : ""}

    <h3 class="d-h">Rule evidence</h3>
    <ul class="ev">${Object.entries(f.raw_evidence || {}).map(([k, v]) =>
      `<li><span class="mark"></span><span class="k">${esc(k)}</span>
        <span class="val">${esc(typeof v === "object" ? JSON.stringify(v) : v)}</span></li>`
    ).join("")}</ul>

    <h3 class="d-h">Dossier <span class="muted">(capability 12 — the agent explains,
      it never decides)</span></h3>
    <div id="report-box">
      <button id="gen-report" class="genbtn">Generate report</button>
      <span id="gen-note" class="muted"></span>
    </div>

    <h3 class="d-h">The change itself</h3>
    <div id="diff" class="diff"><div class="loading">loading diff…</div></div>`;

  $("drawer").classList.remove("hidden");
  wireReport(f);
  loadDiff(f);
}

/* ---- capability 12: request a dossier and poll for it ------------------- */

async function wireReport(f) {
  const btn = $("gen-report"), note = $("gen-note");
  if (!f.finding_id) { btn.disabled = true; note.textContent = "re-run the scan to enable"; return; }

  let agent = { available: false };
  try { agent = await (await fetch("/api/agent")).json(); } catch (e) { /* offline */ }
  if (!agent.available) {
    btn.disabled = true;
    note.textContent = "GEMINI_API_KEY not configured — the engine above needs no key, only this step does";
    return;
  }
  note.textContent = `${agent.model}, ${agent.rpm_budget} model-requests/min budget`;

  // Already generated (or generating) in this session? Show it.
  const existing = await (await fetch(`/api/scan/${JOB}/report/${f.finding_id}`)).json();
  if (existing.status && existing.status !== "none") return showReport(f, existing);

  btn.onclick = async () => {
    btn.disabled = true;
    await fetch(`/api/scan/${JOB}/report/${f.finding_id}`, { method: "POST" });
    pollReport(f);
  };
}

async function pollReport(f) {
  const box = $("report-box");
  for (;;) {
    const r = await (await fetch(`/api/scan/${JOB}/report/${f.finding_id}`)).json();
    if (r.status !== "running") return showReport(f, r);
    box.innerHTML = `<div class="genlog"><b>drafting…</b>${
      (r.log || []).map((l) => `<div>${esc(l)}</div>`).join("")}</div>`;
    await new Promise((res) => setTimeout(res, 1200));
  }
}

function showReport(f, r) {
  const box = $("report-box");
  if (r.status === "error") {
    box.innerHTML = `<div class="why"><b>Report refused.</b> ${esc(r.error_message || "")}
      ${(r.violations || []).map((v) =>
        `<div>rejected [${esc(v.kind)}] ${esc(v.span)}</div>`).join("")}</div>`;
    return;
  }
  if (r.status !== "success") { box.innerHTML = `<div class="loading">no report yet</div>`; return; }
  box.innerHTML =
    `<div class="genok">✓ verified against the finding record — every hash, address,
       path and line in this document came from the engine, not the model</div>
     <div class="report">${mdToHtml(r.markdown || "")}</div>`;
}

/* ---- capability 12's ranking tool: order CONFIRMED findings by priority - */

function wireRankButton(confirmed) {
  const wrap = $("rank-wrap"), btn = $("rank-btn");
  if (confirmed.length < 2) { wrap.className = "rank-wrap hidden"; return; }
  wrap.className = "rank-wrap";
  $("rank-box").innerHTML = "";
  btn.disabled = false;
  btn.textContent = `Rank ${confirmed.length} CONFIRMED findings — Gemini`;
  btn.onclick = async () => {
    btn.disabled = true;
    const ids = confirmed.map((f) => f.finding_id).filter(Boolean);
    const res = await fetch(`/api/scan/${JOB}/rank`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding_ids: ids }),
    });
    if (!res.ok) {
      $("rank-box").innerHTML = `<div class="why">${esc(await res.text())}</div>`;
      btn.disabled = false;
      return;
    }
    pollRanking(confirmed);
  };
}

async function pollRanking(confirmed) {
  const box = $("rank-box");
  for (;;) {
    const r = await (await fetch(`/api/scan/${JOB}/rank`)).json();
    if (r.status !== "running") return showRanking(confirmed, r);
    box.innerHTML = `<div class="genlog"><b>ranking…</b>${
      (r.log || []).map((l) => `<div>${esc(l)}</div>`).join("")}</div>`;
    await new Promise((res) => setTimeout(res, 1200));
  }
}

function showRanking(confirmed, r) {
  const box = $("rank-box"), btn = $("rank-btn");
  btn.disabled = false;
  if (r.status === "error") {
    box.innerHTML = `<div class="why"><b>Ranking refused.</b> ${esc(r.error_message || "")}
      ${(r.violations || []).map((v) =>
        `<div>rejected [${esc(v.kind)}] ${esc(v.span)}</div>`).join("")}</div>`;
    return;
  }
  const byId = Object.fromEntries(confirmed.map((f) => [f.finding_id, f]));
  const ordered = [...(r.ranking || [])].sort((a, b) => a.rank - b.rank);
  box.innerHTML =
    `<div class="genok">✓ verified against the finding record — every fact this
       ordering cites came from the engine, not the model</div>
     <ol class="rank-list">${ordered.map((item) => {
        const f = byId[item.finding_id];
        const who = f ? `${esc(f.contract)}${f.function ? "." + esc(f.function) : ""}`
                      : esc(item.finding_id);
        return `<li><div class="rank-who">${who}
              <span class="rule-tag">${f ? esc(f.rule_id) : ""}</span></div>
            <div class="rank-why">${esc(item.rationale || "")}</div></li>`;
      }).join("")}</ol>`;
}

/* Minimal markdown renderer: headings, blockquote, bold, code, lists. Kept
   inline because a published page must be self-contained. */
function mdToHtml(md) {
  const lines = md.split("\n");
  const out = [];
  let inList = false;
  for (const raw of lines) {
    const l = raw.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
      .replace(/`(.+?)`/g, "<code>$1</code>");
    const h = l.match(/^(#{1,6})\s+(.*)$/);
    if (h) { if (inList) { out.push("</ul>"); inList = false; }
             out.push(`<h${h[1].length + 2}>${h[2]}</h${h[1].length + 2}>`); continue; }
    if (/^&gt;\s?/.test(l)) { out.push(`<blockquote>${l.replace(/^&gt;\s?/, "")}</blockquote>`); continue; }
    if (/^\s*[-*]\s+/.test(l)) {
      if (!inList) { out.push("<ul>"); inList = true; }
      out.push(`<li>${l.replace(/^\s*[-*]\s+/, "")}</li>`); continue;
    }
    if (inList) { out.push("</ul>"); inList = false; }
    if (/^---+$/.test(l.trim())) { out.push("<hr>"); continue; }
    out.push(l.trim() ? `<p>${l}</p>` : "");
  }
  if (inList) out.push("</ul>");
  return out.join("");
}

async function loadDiff(f) {
  if (!f.commit || !f.parent) {
    $("diff").innerHTML = `<div class="loading">no commit pair recorded for this finding</div>`;
    return;
  }
  if (!JOB) {
    $("diff").innerHTML = `<div class="loading">no active scan session — re-run the scan to load diffs</div>`;
    return;
  }
  const url = `/api/scan/${JOB}/diff?file=${encodeURIComponent(f.file)}` +
    `&prev=${encodeURIComponent(f.parent)}&cur=${encodeURIComponent(f.commit)}`;
  try {
    const r = await fetch(url);
    if (!r.ok) throw new Error(await r.text());
    const { diff } = await r.json();
    if (!diff.trim()) { $("diff").innerHTML = `<div class="loading">empty diff</div>`; return; }
    $("diff").innerHTML = diff.split("\n").map((line) => {
      let cls = "";
      if (line.startsWith("+++") || line.startsWith("---")) cls = "meta";
      else if (line.startsWith("@@")) cls = "hunk";
      else if (line.startsWith("+")) cls = "add";
      else if (line.startsWith("-")) cls = "del";
      else if (line.startsWith("diff ") || line.startsWith("index ")) cls = "meta";
      return `<div class="${cls}">${esc(line) || "&nbsp;"}</div>`;
    }).join("");
  } catch (e) {
    $("diff").innerHTML = `<div class="loading">could not load diff: ${esc(e.message)}</div>`;
  }
}
