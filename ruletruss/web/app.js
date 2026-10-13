"use strict";
// RuleTruss front end. No frameworks, no inline script, no innerHTML for anything that came from an upload:
// every string is placed with textContent so hostile names in a capture or configuration cannot become markup.

const TABS = [
  ["start", "Import"], ["inventory", "Inventory"], ["comms", "Communications"], ["graph", "Graph"], ["config", "Configuration"],
  ["compare", "Compare"], ["groups", "Groups & labels"], ["migrate", "Migrate"], ["export", "Export & AI"], ["privacy", "Data & privacy"],
];
const state = { verbose: false, token: "", projects: [], pid: "", tab: "start", overview: null, status: null, plan: null, translation: null, zoneMap: {} };

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const svgNS = "http://www.w3.org/2000/svg";
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  for (const kid of kids.flat()) if (kid) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
const chip = (label, cls) => h("span", { class: `chip ${cls || label}` , text: label });
const kindChip = (k) => chip(k, k.toLowerCase().split(" ")[0]);

function toast(message, bad) {
  const t = document.getElementById("toast");
  t.textContent = message; t.className = "show" + (bad ? " bad" : "");
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { t.className = ""; }, bad ? 9000 : 4000);
}

async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: { Authorization: `Bearer ${state.token}` } };
  if (opts.json !== undefined) { init.body = JSON.stringify(opts.json); init.headers["Content-Type"] = "application/json"; }
  if (opts.file) { init.body = opts.file; init.headers["Content-Type"] = "application/octet-stream"; }
  const res = await fetch(path, init);
  if (opts.raw) {
    if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.error || res.statusText); }
    return res;
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
  return data;
}
async function guarded(fn) { try { return await fn(); } catch (e) { toast(e.message, true); return null; } }

const fmtTime = (ts) => (ts ? new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC" : "-");
const fmtBytes = (n) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n > 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);
const proj = () => state.projects.find((p) => p.id === state.pid);

// ------------------------------------------------------------------ shell
function renderTabs() {
  const nav = document.getElementById("tabs");
  nav.replaceChildren(...TABS.map(([id, label]) => h("button", { type: "button", role: "tab", "aria-selected": id === state.tab, onclick: () => { state.tab = id; render(); } }, label)));
}
function renderProjects() {
  const sel = document.getElementById("projectSelect");
  sel.replaceChildren(...state.projects.map((p) => h("option", { value: p.id, selected: p.id === state.pid }, `${p.name} (${p.sources} files)`)));
  if (!state.projects.length) sel.replaceChildren(h("option", { value: "" }, "no projects yet"));
}
async function loadProjects(select) {
  const data = await api("/api/projects");
  state.projects = data.projects;
  if (select) state.pid = select;
  if (!state.projects.find((p) => p.id === state.pid)) state.pid = state.projects.length ? state.projects[0].id : "";
  renderProjects();
}
let renderTicket = 0;
async function render() {
  const ticket = ++renderTicket;       // a slow render must never overwrite a newer one
  renderTabs();
  const view = document.getElementById("view");
  view.replaceChildren(h("p", { class: "muted", text: "Loading..." }));
  const fn = VIEWS[state.tab];
  if (state.tab !== "start" && state.tab !== "privacy" && !state.pid) {
    view.replaceChildren(h("section", { class: "card" }, h("h2", { text: "Start a project" }), h("p", { text: "Create a project and import a capture or a device export on the Import tab first." })));
    return;
  }
  const out = await guarded(() => fn());
  if (out && ticket === renderTicket) view.replaceChildren(...[].concat(out));
}
function table(headers, rows, opts = {}) {
  const t = h("table", {}, h("thead", {}, h("tr", {}, headers.map((x) => h("th", { scope: "col", text: x })))),
    h("tbody", {}, rows.map((r) => (opts.detail ? expandable(r, headers.length, opts.detail) : h("tr", {}, r.cells.map((c) => h("td", {}, c)))))));
  return h("div", { class: "tablewrap" }, t);
}
function expandable(row, cols, detailFn) {
  const tr = h("tr", { class: "expandable", tabindex: 0, role: "button", "aria-expanded": "false" }, row.cells.map((c) => h("td", {}, c)));
  let open = null;
  const toggle = () => {
    if (open) { open.remove(); open = null; tr.setAttribute("aria-expanded", "false"); return; }
    open = h("tr", {}, h("td", { class: "detail", colspan: cols }, detailFn(row)));
    tr.after(open); tr.setAttribute("aria-expanded", "true");
  };
  tr.addEventListener("click", toggle);
  tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
  return tr;
}
function evidenceList(ev) {
  if (!ev || !ev.length) return h("p", { class: "muted small", text: "No evidence reference." });
  return h("ul", { class: "plain small" }, ev.map((e) => h("li", {}, h("b", { text: `${e.kind} ${e.ref}` }), e.text ? `: ${e.text}` : "")));
}
function notice(text, cls) { return h("div", { class: `notice ${cls || ""}`, text }); }
// Long explanations stay one click away. "Show explanations" (top right) opens all of them.
function more(label, ...kids) {
  const opts = typeof kids[0] === "object" && kids[0] && kids[0].__open !== undefined ? kids.shift() : {};
  return h("details", { class: "more", open: state.verbose || opts.__open }, h("summary", { text: label }), h("div", { class: "morebody" }, kids));
}
function splitSentence(text) {
  const m = text.match(/^(.{20,170}?[.;])\s+(.*)$/s);
  if (m) return [m[1], m[2]];
  if (text.length > 170) { const cut = text.lastIndexOf(" ", 150); return [text.slice(0, cut) + "\u2026", text]; }
  return [text, ""];
}
function brief(text) {
  const [head, tail] = splitSentence(String(text));
  return tail ? h("details", { class: "inline", open: state.verbose }, h("summary", { text: head }), h("span", { class: "morebody", text: tail })) : h("span", { text: head });
}
function stat(label, value) { return h("div", { class: "stat" }, h("b", { text: String(value) }), h("span", { class: "muted", text: label })); }
function sectionTitle(title, kind) { return h("h2", {}, title, " ", kind ? kindChip(kind) : null); }

// ------------------------------------------------------------------ views
const VIEWS = {};

VIEWS.start = async () => {
  const out = [];
  const project = proj() ? await api(`/api/projects/${state.pid}`) : null;
  out.push(h("section", { class: "card" }, h("h2", { text: "Import" }),
    h("p", { class: "small", text: "Drop in captures (PCAP, PCAPNG), Zeek logs and device exports. The type is detected from the content; files stay on this computer." }),
    project ? importForm(project) : notice("Create a project first (New project, top right), or load an example below.", "info"),
    h("div", { class: "row" }, h("button", { type: "button", class: "primary", onclick: () => loadSample("riverbend") }, "Load the Riverbend example"),
      h("span", { class: "muted small", text: "Fictional plant: 3 captures, a flow log, 5 device exports. Guide: samples/riverbend/GUIDE.md" })),
    h("div", { class: "row" }, h("button", { type: "button", onclick: () => loadSample("small") }, "Load the small example"),
      h("span", { class: "muted small", text: "One capture, one firewall." }))));
  if (project) out.push(sourcesCard(project));
  out.push(supportCard());
  return out;
};
function importForm(project) {
  const input = h("input", { type: "file", id: "fileInput", multiple: true, "aria-label": "Files to import" });
  const point = h("input", { type: "text", id: "obsPoint", placeholder: "e.g. SPAN on distribution switch 1", size: 40 });
  const drop = h("div", { class: "dropzone" }, h("p", { text: "Drop files here or choose files" }), input);
  const go = async (files) => {
    for (const f of files) {
      toast(`Importing ${f.name}...`);
      const q = new URLSearchParams({ name: f.name, observation_point: point.value });
      const res = await guarded(() => api(`/api/projects/${project.id}/sources?${q}`, { method: "POST", file: f }));
      if (res) toast(`Imported ${f.name} as ${res.kind}.`);
    }
    await loadProjects(); state.overview = null; render();
  };
  input.addEventListener("change", () => go([...input.files]));
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); go([...e.dataTransfer.files]); });
  return h("div", {}, h("label", { class: "field", for: "obsPoint" }, "Capture point (optional; never guessed)", point), h("p"), drop);
}
function sourcesCard(project) {
  const rows = project.sources.map((src) => ({ cells: [
    kindChip(src.kind === "policy" ? "CONFIGURED" : "OBSERVED"), src.filename, src.format || "",
    src.kind === "policy" ? `${src.vendor}${src.hostname ? " / " + src.hostname : ""}: ${src.rules} rules` : `${src.flows} flows`,
    src.observation_point || "-", h("button", { type: "button", class: "danger", onclick: async () => { if (confirm(`Delete ${src.filename} and its analysis from this computer?`)) { await guarded(() => api(`/api/projects/${project.id}/sources/${src.id}`, { method: "DELETE" })); await loadProjects(); render(); } } }, "Delete")] }));
  return h("section", { class: "card" }, h("h2", { text: "Files" }),
    rows.length ? table(["Type", "File", "Format", "Contents", "Capture point", ""], rows) : h("p", { class: "muted", text: "No files yet." }));
}
function supportCard() {
  const st = state.status;
  if (!st) return h("span");
  return h("section", { class: "card" }, h("h2", { text: "What can be read" }),
    h("p", { class: "small", text: ["PCAP, PCAPNG, Zeek conn.log", ...Object.values(st.formats)].join(" \u00b7 ") }),
    more("Limits and caveats", h("p", { class: "small", text: `Captures up to ${fmtBytes(st.limits.max_capture_bytes)}, exports up to ${fmtBytes(st.limits.max_config_bytes)}; parsing stops after ${st.limits.parse_seconds} s. A format is listed because an adapter exists and is tested on synthetic exports, not on every product version.` })));
}
async function loadSample(which) {
  const res = await guarded(() => api("/api/sample", { method: "POST", json: { name: which } }));
  if (res) { await loadProjects(res.id); state.overview = null; state.tab = "inventory"; toast("Sample project created."); render(); }
}

async function getOverview() {
  state.overview = await api(`/api/projects/${state.pid}/overview`);
  return state.overview;
}
VIEWS.inventory = async () => {
  const o = await getOverview();
  const out = [h("section", { class: "card" }, sectionTitle("What was captured", "OBSERVED"),
    h("div", { class: "grid" }, stat("flows", o.flows), stat("communications", o.communications), stat("devices", o.inventory.devices.length), stat("files", o.sources.length)),
    h("p", { class: "small muted", text: "Seen only from the capture points below. Absence from a capture is not evidence of absence." }),
    more(`Capture points and limits (${o.captures.length})`, o.captures.map((c) => h("p", { class: "small", text: `${c.filename}: ${c.format}, ${fmtTime(c.first_ts)} to ${fmtTime(c.last_ts)}, ${c.packets_read} records. Point: ${c.observation_point || "not supplied"}` })),
      h("ul", { class: "plain small" }, o.coverage.map((n) => h("li", { text: n })))))];
  const conf = Object.entries(o.direction_confidence);
  out.push(h("section", { class: "card" }, h("h2", { text: "Direction confidence" }),
    h("div", { class: "row" }, conf.length ? conf.map(([k, v]) => h("span", {}, chip(k), ` ${v}  `)) : "-"),
    more("What do high, medium and low mean?", h("p", { class: "small", text: "high: a handshake (SYN) or echo request was seen. medium: indirect evidence, such as a payload that is clearly a request. low or unknown: mid-conversation capture, one-way UDP, or no evidence. Low and unknown are never turned into policy unless you choose to." })),
    h("h3", { text: "Applications" }),
    h("p", { class: "small", text: Object.entries(o.applications).map(([k, v]) => `${k} ${v}`).join(" \u00b7 ") })));
  out.push(matrixCard(o.matrix));
  out.push(h("section", { class: "card" }, h("h2", { text: "Devices" }),
    h("p", { class: "small muted", text: "Counts only. A device's role is never inferred; labels are yours." }),
    table(["Address", "Label", "Subnet", "Initiated", "Received", "Peers out/in", "Uncertain"],
      o.inventory.devices.slice(0, 1000).map((d) => ({ cells: [d.ip, d.label || "-", d.subnet_label || d.subnet || "-", d.initiated_flows, d.received_flows, `${d.peers_initiated_to} / ${d.peers_received_from}`, d.uncertain_direction_flows] }))),
    h("h3", { text: "Subnets" }), table(["Subnet", "Label", "Devices"], o.inventory.subnets.map((x) => ({ cells: [x.subnet, x.label || "-", x.devices] })))));
  return out;
};
function matrixCard(cells) {
  const names = [...new Set(cells.flatMap((c) => [c.from, c.to]))].sort();
  const cell = (a, b) => cells.find((c) => c.from === a && c.to === b);
  const body = names.map((a) => h("tr", {}, h("th", { scope: "row", text: a }), names.map((b) => {
    const c = cell(a, b);
    return h("td", { title: c ? `${c.communications} communications, ${c.flows} flows, ${c.low_confidence} with uncertain direction` : "nothing observed" },
      c ? `${c.communications} / ${c.flows}${c.low_confidence ? " \u26A0" : ""}` : "");
  })));
  return h("section", { class: "card" }, sectionTitle("Who initiated to whom, by subnet", "OBSERVED"),
    h("p", { class: "small muted", text: "Row initiated to column. Cell = communications / flows; \u26A0 = some initiators uncertain; empty = nothing seen." }),
    cells.length ? h("div", { class: "tablewrap" }, h("table", { id: "matrix" }, h("thead", {}, h("tr", {}, h("th", { text: "initiator \u2192 responder" }), names.map((n) => h("th", { scope: "col", text: n })))), h("tbody", {}, body))) : h("p", { class: "muted", text: "No flows yet." }));
}

const confOptions = ["", "high", "medium", "low", "unknown"];
VIEWS.comms = async () => {
  const f = state.commFilter || (state.commFilter = { q: "", proto: "", port: "", app: "", min_confidence: "" });
  const holder = h("div");
  const load = async () => {
    const q = new URLSearchParams(Object.entries(f).filter(([, v]) => v)); q.set("limit", "300");
    const data = await guarded(() => api(`/api/projects/${state.pid}/communications?${q}`));
    if (!data) return;
    holder.replaceChildren(h("p", { class: "muted small", text: `${data.total} match${data.total > 300 ? " (first 300 shown)" : ""}. Click a row for details.` }),
      table(["Initiator", "Responder", "Service", "Application", "Direction", "Flows"], data.rows.map((r) => ({ r, cells: [
        h("span", {}, r.initiator, r.initiator_label ? ` (${r.initiator_label})` : ""), h("span", {}, r.responder, r.responder_label ? ` (${r.responder_label})` : ""),
        r.port !== null ? `${r.proto}/${r.port}` : (r.icmp_type !== null ? `${r.proto} type ${r.icmp_type}` : r.proto),
        r.apps.length ? h("span", {}, r.apps[0].name, " ", chip(r.apps[0].confidence)) : "-", chip(r.direction_confidence), r.flows] })), { detail: commDetail }));
  };
  const field = (key, label, el) => h("label", { class: "field" }, label, el);
  const mk = (key, ph) => { const i = h("input", { type: "search", value: f[key], placeholder: ph, size: 14 }); i.addEventListener("input", () => { f[key] = i.value.trim(); clearTimeout(mk.t); mk.t = setTimeout(load, 250); }); return i; };
  const sel = h("select", {}, confOptions.map((o) => h("option", { value: o, selected: f.min_confidence === o }, o || "any")));
  sel.addEventListener("change", () => { f.min_confidence = sel.value; load(); });
  const protoSel = h("select", {}, ["", "tcp", "udp", "icmp", "icmp6", "sctp"].map((o) => h("option", { value: o, selected: f.proto === o }, o || "any")));
  protoSel.addEventListener("change", () => { f.proto = protoSel.value; load(); });
  load();
  return h("section", { class: "card" }, sectionTitle("Communications", "OBSERVED"),
    h("div", { class: "row" }, field("q", "Address or label", mk("q", "10.20.")), field("proto", "Protocol", protoSel), field("port", "Port", mk("port", "502")), field("app", "Application", mk("app", "modbus")), field("min", "Direction confidence at least", sel)), holder);
};
function commDetail(row) {
  const r = row.r;
  return h("div", {}, h("p", { text: r.explanation_short }),
    h("p", { class: "small" }, "Direction: ", chip(r.direction_confidence), " ", r.direction_basis[0] || ""),
    more("Full explanation, applications and evidence", h("p", { text: r.explanation }),
      r.apps.length ? h("ul", { class: "plain small" }, r.apps.map((a) => h("li", {}, h("b", { text: a.name }), " ", chip(a.confidence), `: ${a.basis}`))) : null,
      r.notes.length ? h("ul", { class: "plain small" }, r.notes.map((n) => h("li", { text: n }))) : null,
      evidenceList(r.evidence), h("p", { class: "small muted", text: `${r.packets_fwd} packets initiator to responder, ${r.packets_rev} back. ${fmtTime(r.first_ts)} to ${fmtTime(r.last_ts)}.` })));
}

VIEWS.graph = async () => {
  const level = state.graphLevel || "subnet";
  const data = await api(`/api/projects/${state.pid}/graph?level=${level}`);
  const sel = h("select", {}, [["subnet", "Subnets"], ["device", "Devices (busiest 120)"]].map(([v, l]) => h("option", { value: v, selected: v === level }, l)));
  sel.addEventListener("change", () => { state.graphLevel = sel.value; render(); });
  return h("section", { class: "card" }, sectionTitle("Directional relationship graph", "OBSERVED"),
    h("div", { class: "row" }, h("label", { class: "field" }, "Show", sel)),
    h("p", { class: "small muted", text: "Arrows point from initiator to responder. Dashed red = some initiators uncertain." }),
    drawGraph(data), data.truncated ? notice("Only the busiest devices are drawn.", "info") : null);
};
function drawGraph(data) {
  const W = 1000, H = 520, svg = s("svg", { class: "graph", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Directional communication graph" });
  svg.append(s("defs", {}, s("marker", { id: "arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" }, s("path", { d: "M0 0 L10 5 L0 10 z" }))));
  if (!data.nodes.length) { svg.append(s("text", { x: 20, y: 30 }, "Nothing to draw yet.")); return svg; }
  const groups = [...new Set(data.nodes.map((n) => n.group))];
  const pos = {};
  const cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 70;
  data.nodes.forEach((n, i) => { const a = (2 * Math.PI * i) / data.nodes.length - Math.PI / 2; pos[n.id] = { x: cx + R * 1.5 * Math.cos(a), y: cy + R * Math.sin(a), n }; });
  const maxCount = Math.max(...data.edges.map((e) => e.count), 1);
  for (const e of data.edges) {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) continue;
    const width = 1 + 3 * Math.log(1 + e.count) / Math.log(1 + maxCount);
    let d;
    if (a === b) d = `M${a.x} ${a.y - 14} c -40 -50 40 -50 0 0`;
    else {
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2, dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1, off = 28;
      d = `M${a.x} ${a.y} Q${mx - (dy / len) * off} ${my + (dx / len) * off} ${b.x} ${b.y}`;
    }
    const path = s("path", { class: `edge${e.low ? " low" : ""}`, d, "stroke-width": width, "marker-end": "url(#arrow)" });
    path.append(s("title", {}, `${e.from} to ${e.to}: ${e.count} flows${e.services.length ? " (" + e.services.join(", ") + ")" : ""}${e.low ? "; some initiators uncertain" : ""}`));
    svg.append(path);
  }
  for (const id of Object.keys(pos)) {
    const { x, y, n } = pos[id];
    const g = s("g", {}, s("circle", { class: "node", cx: x, cy: y, r: 12 }), s("text", { x: x + 16, y: y + 4 }, n.label.length > 26 ? n.label.slice(0, 25) + "..." : n.label));
    g.append(s("title", {}, `${n.label} (${n.group})`));
    svg.append(g);
  }
  return svg;
}

VIEWS.config = async () => {
  const project = await api(`/api/projects/${state.pid}`);
  const policies = project.sources.filter((x) => x.kind === "policy");
  if (!policies.length) return h("section", { class: "card" }, sectionTitle("Configuration", "CONFIGURED"), h("p", { text: "Import a firewall, router or switch export first." }));
  const id = state.policyId && policies.find((p) => p.id === state.policyId) ? state.policyId : policies[0].id; state.policyId = id;
  const v = await api(`/api/projects/${state.pid}/policies/${id}`);
  const bad = v.issues.filter((i) => i.severity !== "info");
  return [h("section", { class: "card" }, sectionTitle("Configured policy", "CONFIGURED"), policyPicker(policies, id),
    h("div", { class: "grid" }, stat("platform", v.summary.platform), stat("host", v.summary.hostname || "-"), stat("rules", v.summary.rules), stat("stateful", v.summary.stateful ? "yes" : "no")),
    h("p", { class: "small muted", text: `Default: ${v.summary.default}. Rule addresses: ${v.summary.address_context}.` }),
    v.issues.length ? more(`Notes (${v.issues.length}${bad.length ? `, ${bad.length} to read` : ""})`, warnList(v.issues)) : null),
  h("section", { class: "card" }, h("h2", { text: "Rules, in evaluation order" }), v.truncated ? notice("Only the first 3000 rules are shown.", "info") : null,
    table(["Pos", "Rule", "Action", "From", "To", "Source", "Destination", "Service", "Not evaluated"], v.rules.map((r) => ({ r, cells: [r.position, r.id, h("span", {}, chip(r.action), r.enabled ? "" : " disabled"), r.src_zones.join(", ") || "any", r.dst_zones.join(", ") || "any", r.src, r.dst, r.service, r.unsupported.concat(r.applications.length ? ["application: " + r.applications.join(", ")] : [], r.users.length ? ["identity: " + r.users.join(", ")] : [], r.schedule ? ["schedule " + r.schedule] : []).join("; ") || "-"] })),
      { detail: (row) => h("div", {}, h("p", { text: row.r.explanation }), row.r.notes.map((n) => h("p", { class: "small", text: n })), more("Evidence", evidenceList(row.r.evidence))) })),
  h("section", { class: "card" }, h("h2", { text: `Rule analysis (${v.findings.length})` }), v.findings.length ? h("ul", { class: "plain" }, v.findings.map((f) => h("li", {}, chip(f.kind, f.severity === "warning" ? "medium" : "high"), " ", brief(f.message)))) : h("p", { class: "small", text: "No shadowed, conflicting or overly broad rules found." })),
  v.nat.length ? h("section", { class: "card" }, h("h2", { text: `NAT (${v.nat.length}; recorded, not applied)` }), table(["Id", "Kind", "Original source", "Original destination", "Translated source", "Translated destination", "Zones"], v.nat.map((n) => ({ cells: [n.id, n.kind, n.original_src, n.original_dst, n.translated_src, n.translated_dst, n.zones] })))) : null];
};
function policyPicker(policies, id) {
  const sel = h("select", {}, policies.map((p) => h("option", { value: p.id, selected: p.id === id }, `${p.filename} (${p.vendor})`)));
  sel.addEventListener("change", () => { state.policyId = sel.value; render(); });
  return h("div", { class: "row" }, h("label", { class: "field" }, "Configuration", sel));
}

VIEWS.compare = async () => {
  const project = await api(`/api/projects/${state.pid}`);
  const policies = project.sources.filter((x) => x.kind === "policy");
  if (!policies.length) return h("section", { class: "card" }, sectionTitle("Compare"), h("p", { text: "Import a configuration and a capture to compare them." }));
  const id = state.policyId && policies.find((p) => p.id === state.policyId) ? state.policyId : policies[0].id; state.policyId = id;
  const c = await api(`/api/projects/${state.pid}/policies/${id}/compare`);
  const showAll = !!state.showAllCompare;
  const shown = c.rows.filter((r) => showAll || r.crosses_device);
  const toggle = h("input", { type: "checkbox", id: "showAll", checked: showAll }); toggle.addEventListener("change", () => { state.showAllCompare = toggle.checked; render(); });
  return [h("section", { class: "card" }, h("h2", {}, "Observed against configured ", kindChip("OBSERVED"), " ", kindChip("CONFIGURED")), policyPicker(policies, id),
    h("div", { class: "row" }, Object.entries(showAll ? c.counts : c.crossing_counts).map(([k, v]) => h("span", {}, chip(k), ` ${v}  `)),
      h("span", { class: "small muted", text: `${c.crossing} of ${c.rows.length} cross this device` }),
      h("label", { class: "small" }, toggle, " show the rest")),
    more("How to read this", h("p", { class: "small", text: c.note + " Traffic that does not cross the device (an end is in no zone this configuration knows) cannot be judged by it, so it is hidden by default." })),
    table(["Initiator", "Responder", "Service", "Outcome", "Rule", "Reading"], shown.map((r) => ({ r, cells: [r.observed.initiator, r.observed.responder, r.observed.port !== null ? `${r.observed.proto}/${r.observed.port}` : r.observed.proto, chip(r.outcome), r.rule || "-", r.reading_short] })),
      { detail: (row) => h("div", {}, h("p", { text: row.r.reading }), h("p", { class: "small", text: row.r.basis }), row.r.uncertain.length ? h("p", { class: "small", text: "Uncertain: " + row.r.uncertain.join("; ") }) : null, row.r.return_path ? h("p", { class: "small", text: `Reply direction (stateless): ${row.r.return_path.outcome}. ${row.r.return_path.basis}` }) : null, h("p", { class: "small muted", text: `Zones used: ${row.r.zones.map((z) => z || "unknown").join(" to ")}.` }), more("Evidence", evidenceList(row.r.decision_evidence), h("p", { text: row.r.observed.explanation }), evidenceList(row.r.observed.evidence))) })),
  h("section", { class: "card" }, h("h2", { text: `Allow rules no observed traffic matched (${c.unobserved_rules.length})` }), h("p", { class: "small muted", text: "Not a list of unused rules: a capture covers only its own window and place." }),
    c.unobserved_rules.length ? table(["Rule", "Source", "Destination", "Service"], c.unobserved_rules.map((r) => ({ cells: [r.rule, r.src, r.dst, r.svc] }))) : h("p", { class: "small", text: "Every enabled allow rule matched some observed traffic first." }))];
};

// ------------------------------------------------------------------ groups & labels
VIEWS.groups = async () => {
  const project = await api(`/api/projects/${state.pid}`);
  const subnets = project.subnets.map((x) => ({ ...x })), groups = project.groups.map((g) => ({ ...g, members: [...g.members] })), labels = Object.entries(project.labels);
  const subBody = h("tbody"), grpBody = h("tbody"), lblBody = h("tbody");
  const input = (v, ph, w) => h("input", { type: "text", value: v || "", placeholder: ph, size: w || 18 });
  const addSub = (x = { cidr: "", label: "", zone: "", external: false }) => { const c = input(x.cidr, "10.20.0.0/16"), l = input(x.label, "Engineering"), z = input(x.zone, "zone or interface name", 22);
    const ex = h("input", { type: "checkbox", checked: x.external, "aria-label": "outside your control" });
    const tr = h("tr", { "data-kind": "sub" }, h("td", {}, c), h("td", {}, l), h("td", {}, z), h("td", {}, ex), h("td", {}, h("button", { type: "button", onclick: () => tr.remove() }, "Remove"))); tr._get = () => ({ cidr: c.value.trim(), label: l.value.trim(), zone: z.value.trim(), external: ex.checked }); subBody.append(tr); };
  const addLbl = (ip = "", label = "") => { const a = input(ip, "10.20.1.15"), l = input(label, "Engineering workstation", 30);
    const tr = h("tr", {}, h("td", {}, a), h("td", {}, l), h("td", {}, h("button", { type: "button", onclick: () => tr.remove() }, "Remove"))); tr._get = () => [a.value.trim(), l.value.trim()]; lblBody.append(tr); };
  const addGrp = (g = { name: "", members: [], gateway_isolated: false }) => { const n = input(g.name, "Controllers"), m = h("textarea", { rows: 2, cols: 34, placeholder: "10.30.0.0/16 10.30.9.5" }, g.members.join(" ")); const gw = h("input", { type: "checkbox", checked: g.gateway_isolated });
    const tr = h("tr", {}, h("td", {}, n), h("td", {}, m), h("td", {}, gw), h("td", {}, h("button", { type: "button", onclick: () => tr.remove() }, "Remove"))); tr._get = () => ({ name: n.value.trim(), members: m.value.split(/[\s,]+/).filter(Boolean), gateway_isolated: gw.checked }); grpBody.append(tr); };
  subnets.forEach(addSub); groups.forEach(addGrp); labels.forEach(([ip, l]) => addLbl(ip, l));
  const save = async () => {
    const body = { subnets: [...subBody.children].map((t) => t._get()).filter((x) => x.cidr), groups: [...grpBody.children].map((t) => t._get()).filter((x) => x.name),
      labels: Object.fromEntries([...lblBody.children].map((t) => t._get()).filter((x) => x[0])) };
    if (await guarded(() => api(`/api/projects/${state.pid}/context`, { method: "PUT", json: body }))) { toast("Saved."); state.overview = null; }
  };
  const suggest = async () => {
    const res = await guarded(() => api(`/api/projects/${state.pid}/suggest-groups`, { method: "POST", json: {} }));
    if (!res) return;
    res.groups.forEach((g) => { if (![...grpBody.children].some((t) => t._get().name === g.name)) addGrp(g); });
    toast(res.unassigned.length ? `${res.unassigned.length} address(es) are in no subnet and were not grouped.` : "Suggested one group per subnet. Edit them before use.");
  };
  const loadJson = (file) => { const reader = new FileReader(); reader.onload = () => { try {
      const data = JSON.parse(reader.result); if (typeof data !== "object" || data === null) throw new Error("not an object");
      subBody.replaceChildren(); grpBody.replaceChildren(); lblBody.replaceChildren();
      (data.subnets || []).forEach((x) => addSub({ cidr: x.cidr || "", label: x.label || "", zone: x.zone || "", external: !!x.external }));
      (data.groups || []).forEach((g) => addGrp({ name: g.name || "", members: g.members || [], gateway_isolated: !!g.gateway_isolated }));
      Object.entries(data.labels || {}).forEach(([ip, l]) => addLbl(ip, String(l)));
      toast("Loaded into the editor. Press Save to keep it.");
    } catch (e) { toast(`That file could not be read as subnets, labels and groups: ${e.message}`, true); } }; reader.readAsText(file); };
  const fileIn = h("input", { type: "file", accept: ".json,application/json", "aria-label": "Load subnets, labels and groups from a JSON file" }); fileIn.addEventListener("change", () => fileIn.files[0] && loadJson(fileIn.files[0]));
  const exportJson = () => { const data = { subnets: [...subBody.children].map((t) => t._get()), groups: [...grpBody.children].map((t) => t._get()), labels: Object.fromEntries([...lblBody.children].map((t) => t._get()).filter((x) => x[0])) };
    const a = h("a", { href: URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" })), download: "ruletruss-context.json" }); document.body.append(a); a.click(); a.remove(); };
  return [h("section", { class: "card" }, h("h2", { text: "Load or save this page" }), h("p", { class: "small muted", text: "A JSON file of subnets, labels and groups (Riverbend ships one)." }),
    h("div", { class: "row" }, h("label", { class: "field" }, "Load from a JSON file", fileIn), h("button", { type: "button", onclick: exportJson }, "Download as JSON"))),
  h("section", { class: "card" }, h("h2", { text: "Subnets" }), h("p", { class: "small muted", text: "Your networks. Zone = the name a firewall rule uses for it." }), more("Zone aliases and outside networks", h("p", { class: "small", text: "Products name one segment differently, so list aliases with | (for example outside|wan); each configuration uses the alias it has. Tick 'outside my control' for the Internet, a vendor or a partner: destinations there are what external egress policies are for." })),
    h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Network (CIDR)", "Label", "Zone / interface", "Outside my control", ""].map((x) => h("th", { text: x })))), subBody)), h("div", { class: "row" }, h("button", { type: "button", onclick: () => addSub() }, "Add subnet"))),
  h("section", { class: "card" }, h("h2", { text: "Device labels" }), h("p", { class: "small muted", text: "Your names for devices. The tool never guesses what a device is." }),
    h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Address", "Label", ""].map((x) => h("th", { text: x })))), lblBody)), h("div", { class: "row" }, h("button", { type: "button", onclick: () => addLbl() }, "Add label"))),
  h("section", { class: "card" }, h("h2", {}, "Groups for directional policies ", kindChip("PROPOSED")), h("p", { class: "small muted", text: "An endpoint can be in several groups. Members: addresses or CIDRs." }), more("Isolated behind a gateway", h("p", { class: "small", text: "Tick this for groups whose members reach the outside only through an external egress policy." })),
    h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Group", "Members", "Isolated behind a gateway", ""].map((x) => h("th", { text: x })))), grpBody)),
    h("div", { class: "row" }, h("button", { type: "button", onclick: () => addGrp() }, "Add group"), h("button", { type: "button", onclick: suggest }, "Suggest one group per subnet"))),
  h("div", { class: "row" }, h("button", { type: "button", class: "primary", onclick: save }, "Save subnets, labels and groups"))];
};

// ------------------------------------------------------------------ migrate
function warnList(items) {
  return h("ul", { class: "plain small" }, items.map((w) => h("li", {}, chip(w.severity, w.severity === "info" ? "medium" : w.severity), " ", brief(w.message),
    w.evidence && w.evidence.length ? h("span", { class: "muted" }, " [", w.evidence.map((e) => `${e.kind} ${e.ref}`).join("; "), "]") : null)));
}
VIEWS.migrate = async () => {
  const project = await api(`/api/projects/${state.pid}`);
  const policies = project.sources.filter((x) => x.kind === "policy");
  const mig = state.mig || (state.mig = { workflow: "preserve", policy: "", low: false, ack: false, target: "cisco-asa" });
  if (!policies.find((p) => p.id === mig.policy) && policies.length) mig.policy = policies[0].id;
  const out = [h("section", { class: "card" }, h("h2", {}, "Workflow ", kindChip("PROPOSED")),
    h("div", { class: "row" }, h("label", {}, h("input", { type: "radio", name: "wf", value: "preserve", checked: mig.workflow === "preserve", onchange: () => { mig.workflow = "preserve"; render(); } }), " Preserve what is configured"),
      h("label", {}, h("input", { type: "radio", name: "wf", value: "narrow", checked: mig.workflow === "narrow", onchange: () => { mig.workflow = "narrow"; render(); } }), " Propose narrower from observation")),
    mig.workflow === "preserve" ? h("p", { class: "small muted", text: "Translates the configured rules one by one. Every place it widens or narrows is reported." })
      : [h("p", { class: "small muted", text: "Built only from what was seen. Not proof of need; every proposal needs review." }),
        h("label", { class: "small" }, h("input", { type: "checkbox", checked: mig.low, onchange: (e) => { mig.low = e.target.checked; } }), " Include flows with uncertain direction (not recommended)")],
    mig.workflow === "preserve" ? (policies.length ? h("div", { class: "row" }, h("label", { class: "field" }, "Source configuration", (() => { const sel = h("select", {}, policies.map((p) => h("option", { value: p.id, selected: p.id === mig.policy }, `${p.filename} (${p.vendor})`))); sel.addEventListener("change", () => { mig.policy = sel.value; }); return sel; })())) : notice("Import a configuration first.", "bad")) : null)];
  out.push(directionalCard(mig));
  out.push(firewallCard(mig, project, policies));
  return out;
};
function body(mig, extra) { return { workflow: mig.workflow, policy: mig.policy, include_low_confidence: mig.low, ...extra }; }
function directionalCard(mig) {
  const holder = h("div");
  const run = async () => {
    const plan = await guarded(() => api(`/api/projects/${state.pid}/plan`, { method: "POST", json: body(mig) }));
    if (!plan) return;
    state.plan = plan; holder.replaceChildren(...showPlan(plan, mig));
  };
  if (state.plan && state.plan.workflow === mig.workflow) holder.replaceChildren(...showPlan(state.plan, mig));
  return h("section", { class: "card" }, h("h2", {}, "Directional group policies ", kindChip("PROPOSED")),
    h("p", { class: "small", text: "From groups may start connections to To groups. The reverse needs its own policy; replies need none." }),
    more("About the model", h("p", { class: "small", text: "A policy connects From groups to To groups and says who may initiate. Allowing both directions takes two policies. External egress policies are a separate type for endpoints isolated behind a gateway. Ports, protocols, deny rules, ordering, applications and schedules are not part of the model: they are kept as information, and any loss is reported." })),
    h("div", { class: "row" }, h("button", { type: "button", class: "primary", onclick: run }, "Build directional policies")), holder);
}
function showPlan(plan, mig) {
  const out = [];
  const bad = plan.summary.policies_that_broaden_access || plan.summary.policies_that_lose_restrictions || plan.summary.deny_rules_not_translated;
  out.push(notice(plan.summary.verdict, bad ? "bad" : "info"));
  out.push(h("div", { class: "grid" }, Object.entries(plan.summary).filter(([k]) => k !== "verdict").map(([k, v]) => stat(k.replace(/_/g, " "), v))));
  const reviews = plan.review_items;
  if (plan.workflow === "narrow") {
    const o = plan.observation, first = reviews.find((i) => i.code === "observation-limits");
    out.push(h("p", { class: "small" }, h("b", { text: "Observation window: " }), `${fmtTime(o.first_ts)} to ${fmtTime(o.last_ts)} (${((o.duration_seconds || 0) / 3600).toFixed(2)} h). `, (o.captures || []).map((c) => c.observation_point).filter((v, i, a) => a.indexOf(v) === i).join("; ")));
    out.push(notice("Review required: anything that did not happen in this window is invisible here (scheduled jobs, failover, maintenance, vendor access).", ""));
    if (first) out.push(more("Observation limits", h("p", { class: "small", text: first.message }), h("ul", { class: "plain small" }, (o.caveats || []).map((c) => h("li", { text: c })))));
  }
  const live = plan.policies.filter((p) => p.status !== "blocked"), blocked = plan.policies.filter((p) => p.status === "blocked");
  out.push(h("h3", { text: `Group policies (${live.length})` }));
  for (const p of live) {
    out.push(h("div", { class: "card tight" }, h("div", { class: "row" }, h("b", { text: p.name }), chip(p.status), chip(p.origin, "proposed")),
      h("p", { class: "small" }, `${p.from_groups.join(", ")} may initiate to ${p.to_groups.join(", ")}`, p.granted_pairs ? h("span", { class: "muted", text: ` \u00b7 ${p.granted_pairs.toLocaleString()} address pairs granted${p.observed_pairs ? `, ${p.observed_pairs} ${plan.workflow === "narrow" ? "observed" : "source-permitted"}` : ""}` }) : null),
      p.services_informational.length ? h("p", { class: "small muted", text: `Services (information only): ${p.services_informational.slice(0, 3).join("; ")}${p.services_informational.length > 3 ? `; +${p.services_informational.length - 3} more` : ""}` }) : null,
      p.warnings.length ? more(`${p.warnings.length} warning${p.warnings.length === 1 ? "" : "s"}`, warnList(p.warnings)) : null,
      more("Basis and evidence", h("p", { class: "small", text: p.basis }), evidenceList(p.evidence.slice(0, 4)))));
  }
  if (blocked.length) out.push(more(`Not translated (${blocked.length})`, table(["Source rule", "Why"], blocked.map((p) => ({ cells: [p.source_rules.join(", "), brief(p.warnings.map((w) => w.message).join(" "))] })))));
  if (plan.egress_policies.length) {
    out.push(h("h3", { text: `External egress policies (${plan.egress_policies.length})` }));
    for (const e of plan.egress_policies) out.push(h("div", { class: "card tight" }, h("div", { class: "row" }, h("b", { text: e.name }), chip(e.status)),
      h("p", { class: "small", text: `${e.endpoint_groups.join(", ")} may reach: prefixes ${e.allowed_prefixes.join(" ") || "-"}; DNS names ${e.allowed_dns_names.join(" ") || "-"}; all DNS queries ${e.allow_all_dns ? "allowed" : "not allowed"}` }),
      e.services.length ? h("p", { class: "small muted", text: `Services (information only): ${e.services.join("; ")}` }) : null,
      e.warnings.length ? more(`${e.warnings.length} warning${e.warnings.length === 1 ? "" : "s"}`, warnList(e.warnings)) : null));
  }
  if (plan.gaps.length) out.push(more(`Gaps: not translated or translated with a loss (${plan.gaps.length})`, warnList(plan.gaps)));
  const rest = reviews.filter((i) => i.code !== "observation-limits");
  if (rest.length) out.push(more(`Review items (${rest.length})`, warnList(rest)));
  if (plan.workflow === "narrow") out.push(h("label", { class: "small" }, h("input", { type: "checkbox", checked: mig.ack, onchange: (e) => { mig.ack = e.target.checked; } }), " I have read the observation limits and will confirm each proposal with the people who run these systems."));
  out.push(h("p", { class: "small muted", text: "Directional rules alone are not a complete zero trust architecture. Export on the Export tab." }));
  return out;
}
function firewallCard(mig, project, policies) {
  const holder = h("div");
  const targets = state.status ? Object.entries(state.status.targets) : [];
  const targetSel = h("select", {}, targets.map(([k, l]) => h("option", { value: k, selected: k === mig.target }, l)));
  targetSel.addEventListener("change", () => { mig.target = targetSel.value; });
  const zoneInput = h("textarea", { class: "wide", rows: 3, placeholder: "source zone = destination interface, one per line\not = Vlan30\ncorp = Vlan10" }, Object.entries(state.zoneMap).map(([k, v]) => `${k} = ${v}`).join("\n"));
  const run = async () => {
    state.zoneMap = Object.fromEntries(zoneInput.value.split("\n").map((l) => l.split("=").map((x) => x.trim())).filter((p) => p.length === 2 && p[0] && p[1]));
    const t = await guarded(() => api(`/api/projects/${state.pid}/translate`, { method: "POST", json: body(mig, { target: mig.target, zone_map: state.zoneMap }) }));
    if (!t) return;
    state.translation = t; holder.replaceChildren(...showTranslation(t));
  };
  if (state.translation && state.translation.workflow === mig.workflow) holder.replaceChildren(...showTranslation(state.translation));
  return h("section", { class: "card" }, h("h2", {}, "Translate to another firewall ", kindChip("PROPOSED")),
    h("p", { class: "small", text: "Order and statefulness are kept or called out. A rule the destination cannot express is blocked, never turned into 'any'." }),
    h("div", { class: "row" }, h("label", { class: "field" }, "Destination", targetSel)),
    h("label", { class: "field" }, "Interface mapping (never guessed; unmapped zones show as <TARGET-IF:...>)", zoneInput),
    h("div", { class: "row" }, h("button", { type: "button", class: "primary", onclick: run }, "Translate and validate")), holder);
}
function showTranslation(t) {
  const out = [];
  const s_ = t.summary;
  out.push(notice(s_.verdict, s_.blocked || s_.blocked_deny_rules || s_.rules_known_broader ? "bad" : "info"));
  out.push(h("div", { class: "grid" }, Object.entries(s_).filter(([k]) => k !== "verdict").map(([k, v]) => stat(k.replace(/_/g, " "), v))));
  const interesting = t.report.filter((e) => e.status !== "translated");
  out.push(more(`Per-rule report (${t.report.length} rules, ${interesting.length} not translated or skipped)`, { __open: interesting.length > 0 }, table(["Source", "Status", "Reason"], t.report.map((e) => ({ cells: [e.source_rule, chip(e.status, e.status === "translated" ? "allow" : e.status === "blocked" ? "blocked" : "medium"), e.reason ? brief(e.reason) : "-"] })))));
  if (t.issues.length) out.push(more(`Issues (${t.issues.length})`, warnList(t.issues)));
  const v = t.validation, rows = (v.mismatches || v.problems || []);
  out.push(h("h3", { text: "Validation on sampled connections" }), h("div", { class: "row" }, chip(rows.length ? "differences found" : "no difference", rows.length ? "medium" : "allow"), h("span", { class: "small", text: v.summary.result })),
    h("div", { class: "grid" }, Object.entries(v.summary).filter(([k]) => k !== "result").map(([k, x]) => stat(k.replace(/_/g, " "), x))));
  if (rows.length) out.push(more(`Differences (${rows.length})`, table(["Kind", "Connection", "Detail"], rows.map((m) => ({ cells: [m.kind + (m.explained_by_known_broader_rule ? " (known broader return rule)" : "") + (m.explained_by_blocked_rule ? ` (rule ${m.explained_by_blocked_rule} not translated)` : "") + (m.explained_by_source_default ? " (source default not translated)" : "") + (m.explained_by_reply_entry ? " (reply-only source entry not translated)" : "") + (m.explained_by_source_return_path ? " (stateless source drops the replies)" : ""), m.connection, brief(m.detail || `source: ${m.source} / destination: ${m.destination}`)] })))));
  out.push(more("Limits of this comparison", h("p", { class: "small", text: v.limits.join(" ") })));
  if (t.placeholders.length) out.push(notice(`Replace before use: ${t.placeholders.join(" ")}`, "bad"));
  out.push(more("Generated configuration (review only)", { __open: true }, h("pre", { class: "code", text: t.text })));
  return out;
}

async function download(kind, extra) {
  const res = await guarded(() => api(`/api/projects/${state.pid}/export`, { method: "POST", json: { kind, ...extra }, raw: true }));
  if (!res) return;
  const blob = await res.blob();
  const name = (res.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
  const a = h("a", { href: URL.createObjectURL(blob), download: name ? name[1] : "export.txt" });
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
VIEWS.export = async () => {
  const project = await api(`/api/projects/${state.pid}`);
  const mig = state.mig || (state.mig = { workflow: "preserve", policy: "", low: false, ack: false, target: "cisco-asa" });
  const policies = project.sources.filter((x) => x.kind === "policy");
  if (!policies.find((p) => p.id === mig.policy) && policies.length) mig.policy = policies[0].id;
  const b = (extra) => body(mig, { ...extra, acknowledge_observation_limits: mig.ack, target: mig.target, zone_map: state.zoneMap });
  const btn = (label, kind, extra) => h("button", { type: "button", onclick: () => download(kind, b(extra)) }, label);
  const out = [h("section", { class: "card" }, h("h2", { text: "Export" }),
    h("p", { class: "small muted", text: `Workflow: ${mig.workflow === "preserve" ? "preserve what is configured" : "narrower from observation"} (change it on Migrate).` }),
    mig.workflow === "narrow" ? h("label", { class: "small" }, h("input", { type: "checkbox", checked: mig.ack, onchange: (e) => { mig.ack = e.target.checked; } }), " I have read the observation limits (required to export observation-based proposals)") : null,
    h("h3", { text: "Directional group policy worksheet" }), h("div", { class: "row" }, btn("Markdown", "plan-markdown"), btn("JSON", "plan-json"), btn("Policies CSV", "plan-csv-group-policies"), btn("Groups CSV", "plan-csv-groups"), btn("Egress CSV", "plan-csv-egress-policies"), btn("Gaps CSV", "plan-csv-gaps"), btn("Review CSV", "plan-csv-review")),
    h("h3", { text: "Firewall translation" }), h("div", { class: "row" }, btn("Configuration text", "firewall-text"), btn("Report with validation", "firewall-markdown")),
    h("h3", { text: "Observed communications" }), h("div", { class: "row" }, btn("Explanations (Markdown)", "communications-markdown"), btn("Table (CSV)", "communications-csv")),
    more("About the exports", h("p", { class: "small", text: "The worksheet is applied by hand and is not an import file for any product. CSV cells that a spreadsheet could run as formulas are neutralised, and text from captures and exports is escaped in Markdown." })))];
  out.push(await aiCard());
  return out;
};
async function aiCard() {
  const holder = h("div");
  const pkg = async () => { const r = await guarded(() => api(`/api/projects/${state.pid}/ai`, { method: "POST", json: {} })); if (r) holder.replaceChildren(h("p", { class: "small muted", text: `Sends to: ${r.sends_to}` }), h("textarea", { class: "wide", readonly: true, rows: 10 }, r.prompt)); };
  const ask = async () => { const r = await guarded(() => api(`/api/projects/${state.pid}/ai`, { method: "POST", json: { send: true } })); if (r) holder.replaceChildren(notice(r.label, "info"), h("pre", { class: "code", text: r.text })); };
  const on = state.status && state.status.ai_enabled;
  return h("section", { class: "card" }, h("h2", { text: "Optional AI assistance" }),
    h("p", { class: "small", text: `Nothing is sent to any AI service by default. ${on ? "An endpoint was configured at start-up." : "Sending is off (start with --ai-endpoint to enable it)."}` }),
    more("What the prompt contains", h("p", { class: "small", text: "Only this tool's parsed statements, with uploaded text marked as untrusted data inside it. Copy it into any assistant you choose." })),
    h("div", { class: "row" }, h("button", { type: "button", onclick: pkg }, "Show grounded prompt"), on ? h("button", { type: "button", onclick: ask }, "Send to the configured endpoint") : null), holder);
}

// ------------------------------------------------------------------ privacy
VIEWS.privacy = async () => {
  const st = await api("/api/status"); state.status = st;
  return [h("section", { class: "card" }, h("h2", { text: "About RuleTruss" }),
    h("div", { class: "about" }, h("img", { class: "only-light", src: "/brand/okieotsec-lockup.svg", alt: "OkieOTSec" }), h("img", { class: "only-dark", src: "/brand/okieotsec-lockup-dark.svg", alt: "OkieOTSec" }),
      h("p", { class: "small", text: `RuleTruss ${st.version} by OkieOTSec. MIT licensed code; the OkieOTSec name and logo are not part of that licence.` }))),
  h("section", { class: "card" }, h("h2", { text: "Your data" }),
    h("p", { text: `Stored in ${st.usage.data_dir} (${st.usage.files} files, ${fmtBytes(st.usage.bytes)}), readable only by your user account. ${st.network}` }),
    more("How uploads are handled", h("ul", { class: "plain small" }, h("li", { text: "Parsed in a separate process with memory, CPU and time limits; never executed." }), h("li", { text: "Passwords, keys and community strings are redacted from evidence, exports and anything shown." }),
      h("li", { text: "Nothing is deleted automatically unless the server was started with --retention-days." }),
      h("li", { text: "Deletion overwrites file contents first, as a best effort; that cannot be guaranteed on SSDs, copy-on-write file systems or backups." }))),
    h("div", { class: "row" }, state.pid ? h("button", { type: "button", class: "danger", onclick: async () => { if (confirm("Delete this project and every file in it?")) { await guarded(() => api(`/api/projects/${state.pid}`, { method: "DELETE" })); await loadProjects(); state.overview = null; render(); } } }, "Delete this project") : null,
      h("button", { type: "button", class: "danger", onclick: async () => { if (confirm("Delete ALL projects and files from this computer?")) { await guarded(() => api("/api/data", { method: "DELETE" })); await loadProjects(); render(); } } }, "Delete all data"))),
  h("section", { class: "card" }, h("h2", { text: "What this tool does not claim" }), more("Four things to keep in mind", h("ul", { class: "plain" },
    h("li", { text: "Observed traffic is not proof of business need, and traffic missing from a capture is not proof that it never happens." }),
    h("li", { text: "A device's role is never inferred from its traffic." }),
    h("li", { text: "A translation is not proven equivalent to its source; the validation uses this tool's own evaluator on both sides." }),
    h("li", { text: "Directional policies are one control, not a complete zero trust architecture." }))))];
};

// ------------------------------------------------------------------ start
async function main() {
  const wanted = location.hash.match(/tab=([a-z]+)/);
  if (wanted && TABS.some(([id]) => id === wanted[1])) state.tab = wanted[1];
  const m = location.hash.match(/token=([A-Za-z0-9_-]+)/);
  if (m) { try { sessionStorage.setItem("rt-token", m[1]); } catch (e) { /* storage may be unavailable */ } history.replaceState(null, "", location.pathname); }
  try { state.token = sessionStorage.getItem("rt-token") || ""; } catch (e) { state.token = ""; }
  if (!state.token) { document.getElementById("view").replaceChildren(notice("Open the address printed in the terminal when the server started; it includes the access token.", "bad")); return; }
  try { state.verbose = localStorage.getItem("rt-verbose") === "1"; } catch (e) { state.verbose = false; }
  const verbose = document.getElementById("verbose"); verbose.checked = state.verbose;
  verbose.addEventListener("change", () => { state.verbose = verbose.checked; try { localStorage.setItem("rt-verbose", state.verbose ? "1" : "0"); } catch (e) { /* optional preference */ } render(); });
  document.getElementById("projectSelect").addEventListener("change", (e) => { state.pid = e.target.value; state.overview = null; state.plan = null; state.translation = null; render(); });
  document.getElementById("newProject").addEventListener("click", async () => {
    const name = prompt("Name for the new project:"); if (!name) return;
    const p = await guarded(() => api("/api/projects", { method: "POST", json: { name } })); if (p) { await loadProjects(p.id); state.tab = "start"; render(); }
  });
  await guarded(async () => { state.status = await api("/api/status"); await loadProjects(); });
  render();
}
main();
