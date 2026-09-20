// EVE Operations Console — vanilla JS, no build step.
"use strict";
const $ = (id) => document.getElementById(id);
let TOKEN = localStorage.getItem("eve_token") || "operator-token";
let activeOp = null;
let poller = null;
let evtSource = null;

document.getElementById("year").textContent = new Date().getFullYear();
$("token").value = TOKEN;

function headers() { return { "Authorization": "Bearer " + TOKEN, "Content-Type": "application/json" }; }

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { ...headers(), ...(opts.headers || {}) } });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (e) {}
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

async function whoami() {
  try {
    const s = await api("/api/status");
    $("whoami").textContent = `Connected. Sentinel ${s.sentinel_available ? "available" : "UNAVAILABLE"}, ${s.tools} tools registered.`;
    $("estop").setAttribute("aria-pressed", String(s.emergency_stop));
  } catch (e) { $("whoami").textContent = "Auth failed: " + e.message; }
}

$("save-token").onclick = () => {
  TOKEN = $("token").value.trim();
  localStorage.setItem("eve_token", TOKEN);
  whoami(); refreshOps();
};

$("create").onclick = async () => {
  const goal = $("goal").value.trim();
  const targets = $("targets").value.split(",").map(t => t.trim()).filter(Boolean);
  const require_approval = $("require-approval").checked;
  $("create").disabled = true;
  try {
    const op = await api("/api/operations", { method: "POST",
      body: JSON.stringify({ goal, targets, require_approval }) });
    await refreshOps();
    selectOp(op.id);
  } catch (e) { alert("Create failed: " + e.message); }
  finally { $("create").disabled = false; }
};

$("estop").onclick = async () => {
  const engaged = $("estop").getAttribute("aria-pressed") === "true";
  if (engaged) {
    if (!confirm("Reset the emergency stop?")) return;
    await api("/api/emergency-stop/reset", { method: "POST" });
  } else {
    const reason = prompt("Reason for emergency stop:", "operator initiated halt");
    if (reason === null) return;
    await api("/api/emergency-stop", { method: "POST", body: JSON.stringify({ reason }) });
  }
  whoami(); if (activeOp) loadOp(activeOp);
};

async function refreshOps() {
  try {
    const data = await api("/api/operations");
    const list = $("op-list");
    if (!data.operations.length) { list.innerHTML = '<li class="empty">No operations yet.</li>'; return; }
    list.innerHTML = "";
    for (const op of data.operations) {
      const li = document.createElement("li");
      li.className = "op-item" + (op.id === activeOp ? " active" : "");
      li.tabIndex = 0;
      li.innerHTML = `<div class="goal">${escapeHtml(op.goal)}</div>
        <div class="meta"><span class="badge ${op.state}">${op.state}</span>
        ${op.targets.map(escapeHtml).join(", ")}</div>`;
      li.onclick = () => selectOp(op.id);
      li.onkeydown = (e) => { if (e.key === "Enter") selectOp(op.id); };
      list.appendChild(li);
    }
  } catch (e) { /* not connected */ }
}

function selectOp(id) {
  activeOp = id;
  refreshOps();
  loadOp(id);
  if (poller) clearInterval(poller);
  poller = setInterval(() => loadOp(id), 1200);
  startStream(id);
}

async function loadOp(id) {
  let op;
  try { op = await api("/api/operations/" + id); } catch (e) { return; }
  $("detail").hidden = false;
  $("d-goal").textContent = op.goal;
  $("d-sub").textContent = `${op.id} · actor ${op.actor}`;
  const badge = $("d-state"); badge.textContent = op.state; badge.className = "badge " + op.state;
  const done = op.plan.steps.filter(s => ["SUCCEEDED","FAILED","SKIPPED"].includes(s.state)).length;
  $("d-progress").textContent = `${done}/${op.plan.steps.length}`;
  $("d-adapt").textContent = op.adaptations;
  $("d-findings").textContent = op.findings.length;
  $("d-authz").innerHTML = statusDot(op.authorization_ok);
  $("d-sentinel").innerHTML = statusDot(op.sentinel_ok);
  $("d-step").textContent = op.current_step || "—";
  $("scope-card").hidden = false;
  $("d-scope").textContent = "Authorized: " + op.targets.join(", ");
  $("btn-approve").hidden = op.state !== "AWAITING_APPROVAL";
  $("findings-card").hidden = false;
  const fl = $("d-finding-list");
  if (!op.findings.length) { fl.innerHTML = '<li class="empty">None yet.</li>'; }
  else {
    fl.innerHTML = "";
    for (const f of op.findings) {
      const li = document.createElement("li");
      li.className = "finding " + f.confidence;
      li.innerHTML = `<div class="ftitle">${escapeHtml(f.title)}
        <span class="sev ${f.severity}">${f.severity}</span></div>
        <div class="fmeta">${escapeHtml(f.target)} · ${f.confidence}${f.remediation ? " · " + escapeHtml(f.remediation) : ""}</div>`;
      fl.appendChild(li);
    }
  }
  $("steps-card").hidden = false;
  const sl = $("d-steps"); sl.innerHTML = "";
  for (const s of op.plan.steps) {
    const li = document.createElement("li");
    li.innerHTML = `<span>${s.phase.toLowerCase()} · ${escapeHtml(s.tool_id)}.${escapeHtml(s.action)} → ${escapeHtml(s.target)}</span>
      <span class="st">${s.state}</span>`;
    sl.appendChild(li);
  }
  if (op.report) {
    $("report-card").hidden = false;
    const r = op.report;
    $("d-report").innerHTML = `<p style="margin:0 0 8px">${escapeHtml(r.summary)}</p>
      <div style="color:var(--muted);font-size:12px">Outcome: <strong>${escapeHtml(r.outcome)}</strong> · steps ${r.steps_succeeded}/${r.steps_total} ok · ${r.findings.length} reportable finding(s)</div>`;
  } else { $("report-card").hidden = true; }
  if (["SUCCEEDED","FAILED","CANCELLED","STOPPED"].includes(op.state) && poller) {
    clearInterval(poller); poller = null;
  }
}

$("btn-approve").onclick = () => act("approve");
$("btn-pause").onclick = () => act("pause");
$("btn-resume").onclick = () => act("resume");
$("btn-cancel").onclick = () => { if (confirm("Cancel this operation?")) act("cancel"); };
async function act(verb) {
  if (!activeOp) return;
  try { await api(`/api/operations/${activeOp}/${verb}`, { method: "POST", body: "{}" }); }
  catch (e) { alert(verb + " failed: " + e.message); }
  loadOp(activeOp);
  if (verb === "resume" || verb === "approve") selectOp(activeOp);
}

function startStream(id) {
  if (evtSource) evtSource.close();
  const el = $("d-events"); el.innerHTML = ""; $("events-card").hidden = false;
  evtSource = new EventSource(`/api/operations/${id}/events/stream?token=${encodeURIComponent(TOKEN)}`);
  evtSource.onmessage = (m) => {
    try {
      const e = JSON.parse(m.data);
      if (e.type === "HEARTBEAT") return;
      const li = document.createElement("li");
      li.innerHTML = `<span class="etype">${escapeHtml(e.type)}</span> ${escapeHtml(e.message || "")}`;
      el.insertBefore(li, el.firstChild);
    } catch (err) {}
  };
  evtSource.onerror = () => { /* auto-reconnects */ };
}

function statusDot(ok) { return `<span class="dot ${ok ? "ok" : "bad"}"></span>${ok ? "OK" : "—"}`; }
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

whoami(); refreshOps();
setInterval(refreshOps, 4000);
