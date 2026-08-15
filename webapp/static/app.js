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

let JOB = null;
let SOURCE = null;
let REPORT = null;
let RULE_TITLES = {};

// ---------------------------------------------------------------- bootstrap

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
  };

  setStatus("starting…", "running");
  $("log").innerHTML = "";
  $("findings-body").innerHTML = `<tr class="placeholder"><td colspan="6">Scanning…</td></tr>`;
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
    case "pairs":
      log("info", `${ev.total} commit pair(s) to analyse`); break;
    case "pair":
      setStatus(`pair ${ev.index}/${ev.total}`, "running");
      log("pair", `[${ev.index}/${ev.total}] ${ev.prev}..${ev.cur}  ${ev.subject || ""}`);
      break;
    case "skip":
      log("skip", `    SKIPPED ${ev.prev}..${ev.cur} — ${ev.reason}`); break;
    case "finding":
      log("find", `    ${ev.verdict} rule ${ev.rule}  ${ev.file}::${ev.contract}.${ev.function}`);
      break;
    case "liveness":
      log("info", `checking on-chain liveness for ${ev.address}`); break;
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
  if (data.report) { REPORT = data.report; render(REPORT); }
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
  const partial = cov.pairs_analyzed < cov.pairs_total || cov.files_error > 0
                  || (cov.files_skipped || 0) > 0;

  const skipCounts = {};
  (cov.skips || []).forEach((k) => { skipCounts[k.reason] = (skipCounts[k.reason] || 0) + 1; });
  (cov.file_skips || []).forEach((k) => { skipCounts[k.reason] = (skipCounts[k.reason] || 0) + 1; });
  const skipLines = Object.entries(skipCounts)
    .map(([r, n]) => `<div class="cov-note">· ${n} × ${esc(r)}</div>`).join("");

  $("coverage").className = "coverage" + (partial ? " partial" : "");
  $("coverage").innerHTML = `
    <div class="cov-head">Coverage — read this before the findings</div>
    <div class="cov-grid">
      <div class="cov-metric"><b>${cov.pairs_analyzed}/${cov.pairs_total}</b>
        <span>commit pairs analysed (${cov.pairs_analyzed_pct}%)</span></div>
      <div class="cov-metric"><b>${cov.files_ok}/${cov.files_total}</b>
        <span>file comparisons completed (${cov.files_ok_pct}%)</span></div>
      <div class="cov-metric"><b>${cov.files_error}</b>
        <span>comparisons lost to errors</span></div>
      <div class="cov-metric"><b>${cov.files_skipped || 0}</b>
        <span>never attempted (toolchain missing)</span></div>
    </div>
    <div class="bar"><i style="width:${cov.pairs_analyzed_pct}%"></i></div>
    ${skipLines}
    ${partial ? `<p class="cov-note cov-warn">This scan did not see the whole
       history. Over the unanalysed commits a quiet result means
       <strong>unmeasured</strong>, not safe.</p>` : ""}`;

  $("summary").innerHTML = `
    <div class="chip"><b>${s.findings}</b><span>findings</span></div>
    <div class="chip confirmed"><b>${s.confirmed}</b><span>CONFIRMED</span></div>
    <div class="chip candidate"><b>${s.candidates}</b><span>CANDIDATE</span></div>
    <div class="chip"><b>${s.seconds}s</b><span>elapsed</span></div>
    ${!rep.address ? `<div class="chip"><b>—</b><span>no address: liveness UNKNOWN,
       so nothing can reach CONFIRMED</span></div>` : ""}`;

  const body = $("findings-body");
  if (!rep.findings.length) {
    body.innerHTML = `<tr class="placeholder"><td colspan="6">
      No regression matched any selected rule over the analysed pairs.</td></tr>`;
    return;
  }
  const order = { CONFIRMED: 0, CANDIDATE: 1, DISCARDED: 2 };
  const rows = [...rep.findings].sort(
    (a, b) => (order[a.verdict] - order[b.verdict]) || a.rule_id.localeCompare(b.rule_id));

  body.innerHTML = rows.map((f, i) => `
    <tr data-i="${i}">
      <td><span class="v ${f.verdict}">${f.verdict}</span></td>
      <td><span class="rule-tag">${esc(f.rule_id)}</span><br>
          <small class="muted">${esc(f.owasp || "")}</small></td>
      <td class="where">${esc(f.contract)}${f.function ? "." + esc(f.function) : ""}
          <small>${esc(f.file)}:${f.line ?? "?"}</small></td>
      <td><span class="sha">${esc((f.commit || "").slice(0, 10))}</span><br>
          <small class="muted">${esc((f.date || "").slice(0, 10))} ${esc(f.author || "")}</small></td>
      <td>${headCell(f)}</td>
      <td>${f.liveness
            ? `<span title="${esc((REPORT && REPORT.live_caveat) || "")}">${esc(f.liveness)}${
                f.liveness === "LIVE" ? ' <span class="muted">(code, not risk)</span>' : ""}</span>`
            : '<span class="muted">not checked</span>'}</td>
    </tr>`).join("");

  [...body.querySelectorAll("tr[data-i]")].forEach((tr) =>
    tr.addEventListener("click", () => openDrawer(rows[+tr.dataset.i])));
}

function headCell(f) {
  if (f.survives_to_head === true) return `<span style="color:var(--confirmed)">still present</span>`;
  if (f.survives_to_head === false) return `<span style="color:var(--ok)">repaired later</span>`;
  return `<span class="muted">undetermined</span>`;
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
      <span class="v ${f.verdict}">${f.verdict}</span></h2>
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

    <h3 class="d-h">The change itself</h3>
    <div id="diff" class="diff"><div class="loading">loading diff…</div></div>`;

  $("drawer").classList.remove("hidden");
  loadDiff(f);
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
