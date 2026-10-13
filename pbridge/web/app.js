"use strict";
// Policy Bridge front end. No frameworks, no inline script, no innerHTML for anything that came from an upload:
// every string is placed with textContent so hostile names in a capture or configuration cannot become markup.

const TABS = [
  ["start", "Import"], ["inventory", "Inventory"], ["comms", "Communications"], ["graph", "Graph"], ["config", "Configuration"],
  ["compare", "Compare"], ["groups", "Groups & labels"], ["migrate", "Migrate"], ["export", "Export & AI"], ["privacy", "Data & privacy"],
];
const state = { token: "", projects: [], pid: "", tab: "start", overview: null, status: null, plan: null, translation: null, zoneMap: {} };

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
  for (const kid of kids.flat()) {
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
async function render() {
  renderTabs();
  const view = document.getElementById("view");
  view.replaceChildren(h("p", { class: "muted", text: "Loading..." }));
  const fn = VIEWS[state.tab];
  if (state.tab !== "start" && state.tab !== "privacy" && !state.pid) {
    view.replaceChildren(h("section", { class: "card" }, h("h2", { text: "Start a project" }), h("p", { text: "Create a project and import a capture or a device export on the Import tab first." })));
    return;
  }
  const out = await guarded(() => fn());
  if (out) view.replaceChildren(...[].concat(out));
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
function stat(label, value) { return h("div", { class: "stat" }, h("b", { text: String(value) }), h("span", { class: "muted", text: label })); }
function sectionTitle(title, kind) { return h("h2", {}, title, " ", kind ? kindChip(kind) : null); }

// ------------------------------------------------------------------ views
const VIEWS = {};

VIEWS.start = async () => {
  const proj_ = proj();
  const out = [];
  const project = proj_ ? await api(`/api/projects/${state.pid}`) : null;
  out.push(h("section", { class: "card" }, h("h2", { text: "1. Import" }),
    h("p", { text: "Add packet captures (PCAP, PCAPNG), Zeek conn.log files, and firewall or router/switch exports. The file type is recognised from its content, not its name. Files are stored only on this computer." }),
    project ? importForm(project) : notice("Create a project first (New project, top right), or load the sample project.", "info"),
    h("div", { class: "row" }, h("button", { type: "button", class: "primary", onclick: loadSample }, "Create a sample project (synthetic data)"),
      h("span", { class: "muted small", text: "A fictional plant: one capture, one firewall export, subnets, labels and groups." }))));
  if (project) out.push(sourcesCard(project));
  out.push(supportCard());
  return out;
};
function importForm(project) {
  const input = h("input", { type: "file", id: "fileInput", multiple: true, "aria-label": "Files to import" });
  const point = h("input", { type: "text", id: "obsPoint", placeholder: "e.g. SPAN port on distribution switch 1", size: 44 });
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
  return h("div", {}, h("label", { class: "field", for: "obsPoint" }, "Where was the capture taken? (stored with the capture; never guessed)", point), h("p"), drop);
}
function sourcesCard(project) {
  const rows = project.sources.map((src) => ({ cells: [
    kindChip(src.kind === "policy" ? "CONFIGURED" : "OBSERVED"), src.filename, src.format || "",
    src.kind === "policy" ? `${src.vendor}${src.hostname ? " / " + src.hostname : ""}: ${src.rules} rules, ${src.issues} notes` : `${src.flows} flows, ${src.packets} records`,
    src.observation_point || "-", h("button", { type: "button", class: "danger", onclick: async () => { if (confirm(`Delete ${src.filename} and its analysis from this computer?`)) { await guarded(() => api(`/api/projects/${project.id}/sources/${src.id}`, { method: "DELETE" })); await loadProjects(); render(); } } }, "Delete")] }));
  return h("section", { class: "card" }, h("h2", { text: "Files in this project" }),
    rows.length ? table(["Type", "File", "Format", "Contents", "Observation point", ""], rows) : h("p", { class: "muted", text: "No files yet." }));
}
function supportCard() {
  const st = state.status;
  if (!st) return h("span");
  return h("section", { class: "card" }, h("h2", { text: "What can be read" }),
    h("ul", { class: "plain" }, Object.values(st.formats).map((f) => h("li", { text: f })), h("li", { text: "PCAP and PCAPNG captures (Ethernet, raw IP, Linux cooked, loopback)" }), h("li", { text: "Zeek conn.log (TSV or JSON lines)" })),
    h("p", { class: "muted small", text: "A format is listed only because an adapter exists and has tests against synthetic exports. It has not been validated on every version of every product. See the support matrix in the documentation." }),
    h("p", { class: "small", text: `Limits: captures up to ${fmtBytes(st.limits.max_capture_bytes)}, exports up to ${fmtBytes(st.limits.max_config_bytes)}, parsing stops after ${st.limits.parse_seconds} s.` }));
}
async function loadSample() {
  const res = await guarded(() => api("/api/sample", { method: "POST", json: {} }));
  if (res) { await loadProjects(res.id); state.overview = null; state.tab = "inventory"; toast("Sample project created."); render(); }
}

async function getOverview() {
  state.overview = await api(`/api/projects/${state.pid}/overview`);
  return state.overview;
}
VIEWS.inventory = async () => {
  const o = await getOverview();
  const out = [h("section", { class: "card" }, sectionTitle("What was captured", "OBSERVED"),
    h("div", { class: "grid" }, stat("flows", o.flows), stat("communications (initiator, responder, service)", o.communications), stat("devices seen", o.inventory.devices.length), stat("files", o.sources.length)),
    h("h3", { text: "Coverage and limits" }), h("ul", { class: "plain" }, o.coverage.length ? o.coverage.map((n) => h("li", { text: n })) : h("li", { text: "No capture imported yet." })),
    o.captures.map((c) => h("p", { class: "small muted", text: `${c.filename}: ${c.format}, ${fmtTime(c.first_ts)} to ${fmtTime(c.last_ts)}, ${c.packets_read} records, observation point: ${c.observation_point || "not supplied"}` })))];
  const conf = Object.entries(o.direction_confidence);
  out.push(h("section", { class: "card" }, h("h2", { text: "How sure is the direction of each flow?" }),
    conf.length ? h("div", { class: "row" }, conf.map(([k, v]) => h("span", {}, chip(k), ` ${v}  `))) : h("p", { class: "muted", text: "-" }),
    h("p", { class: "small muted", text: "high: a handshake (SYN) or echo request was seen. medium: indirect evidence such as a payload that is clearly a request. low or unknown: a capture that starts mid-conversation, one-way UDP, or no evidence. Low and unknown are never turned into policy proposals unless you choose to." }),
    h("h3", { text: "Applications" }), h("ul", { class: "plain" }, Object.entries(o.applications).map(([k, v]) => h("li", { text: `${k}: ${v} flows` })))));
  out.push(h("section", { class: "card" }, h("h2", { text: "Devices" }),
    h("p", { class: "small muted", text: "Counts of what this capture saw. A device's function is never inferred from its traffic; labels are yours." }),
    table(["Address", "Your label", "Subnet", "Initiated", "Received", "Peers (out/in)", "Uncertain direction"],
      o.inventory.devices.slice(0, 1000).map((d) => ({ cells: [d.ip, d.label || "-", d.subnet_label || d.subnet || "(not in a defined subnet)", d.initiated_flows, d.received_flows, `${d.peers_initiated_to} / ${d.peers_received_from}`, d.uncertain_direction_flows] }))),
    h("h3", { text: "Subnets" }), table(["Subnet", "Label", "Devices seen"], o.inventory.subnets.map((x) => ({ cells: [x.subnet, x.label || "-", x.devices] })))));
  return out;
};

const confOptions = ["", "high", "medium", "low", "unknown"];
VIEWS.comms = async () => {
  const f = state.commFilter || (state.commFilter = { q: "", proto: "", port: "", app: "", min_confidence: "" });
  const holder = h("div");
  const load = async () => {
    const q = new URLSearchParams(Object.entries(f).filter(([, v]) => v)); q.set("limit", "300");
    const data = await guarded(() => api(`/api/projects/${state.pid}/communications?${q}`));
    if (!data) return;
    holder.replaceChildren(h("p", { class: "muted small", text: `${data.total} communications match${data.total > 300 ? " (showing the first 300; narrow the filter)" : ""}. Click a row for the explanation and evidence.` }),
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
  return h("div", {}, h("p", { text: r.explanation }), h("h3", { text: "Why this direction" }), h("ul", { class: "plain small" }, r.direction_basis.map((b) => h("li", { text: b }))),
    h("h3", { text: "Applications" }), r.apps.length ? h("ul", { class: "plain small" }, r.apps.map((a) => h("li", {}, h("b", { text: a.name }), " ", chip(a.confidence), `: ${a.basis}`))) : h("p", { class: "small muted", text: "None identified." }),
    r.notes.length ? [h("h3", { text: "Notes" }), h("ul", { class: "plain small" }, r.notes.map((n) => h("li", { text: n })))] : null,
    h("h3", { text: "Evidence" }), evidenceList(r.evidence), h("p", { class: "small muted", text: `${r.packets_fwd} packets initiator to responder, ${r.packets_rev} back. First ${fmtTime(r.first_ts)}, last ${fmtTime(r.last_ts)}.` }));
}

VIEWS.graph = async () => {
  const level = state.graphLevel || "subnet";
  const data = await api(`/api/projects/${state.pid}/graph?level=${level}`);
  const sel = h("select", {}, [["subnet", "Subnets"], ["device", "Devices (busiest 120)"]].map(([v, l]) => h("option", { value: v, selected: v === level }, l)));
  sel.addEventListener("change", () => { state.graphLevel = sel.value; render(); });
  return h("section", { class: "card" }, sectionTitle("Directional relationship graph", "OBSERVED"),
    h("div", { class: "row" }, h("label", { class: "field" }, "Show", sel)),
    h("p", { class: "small muted", text: "An arrow points from the side that initiated to the side that answered. Two arrows between the same pair mean each side initiated something. Dashed red edges include flows whose initiator is uncertain." }),
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
  if (!policies.length) return h("section", { class: "card" }, sectionTitle("Configuration", "CONFIGURED"), h("p", { text: "Import a firewall, router or switch export on the Import tab." }));
  const id = state.policyId && policies.find((p) => p.id === state.policyId) ? state.policyId : policies[0].id; state.policyId = id;
  const v = await api(`/api/projects/${state.pid}/policies/${id}`);
  return [h("section", { class: "card" }, sectionTitle("Configured policy", "CONFIGURED"), policyPicker(policies, id),
    h("div", { class: "grid" }, stat("platform", v.summary.platform), stat("host name", v.summary.hostname || "-"), stat("rules", v.summary.rules), stat("stateful", v.summary.stateful ? "yes" : "no (replies need their own rules)")),
    h("p", { class: "small muted", text: `Default when nothing matches: ${v.summary.default}. Rule addresses are written as: ${v.summary.address_context}.` }),
    v.issues.map((i) => notice(`${i.message}`, i.severity === "blocker" ? "bad" : i.severity === "warning" ? "" : "info"))),
  h("section", { class: "card" }, h("h2", { text: "Rules in evaluation order" }), v.truncated ? notice("Only the first 3000 rules are shown.", "info") : null,
    table(["Pos", "Rule", "Action", "From zone", "To zone", "Source", "Destination", "Service", "Conditions not evaluated"], v.rules.map((r) => ({ r, cells: [r.position, r.id, h("span", {}, chip(r.action), r.enabled ? "" : " disabled"), r.src_zones.join(", ") || "any", r.dst_zones.join(", ") || "any", r.src, r.dst, r.service, r.unsupported.concat(r.applications.length ? ["application: " + r.applications.join(", ")] : [], r.users.length ? ["identity: " + r.users.join(", ")] : [], r.schedule ? ["schedule " + r.schedule] : []).join("; ") || "-"] })),
      { detail: (row) => h("div", {}, h("p", { text: row.r.explanation }), row.r.notes.map((n) => h("p", { class: "small", text: n })), h("h3", { text: "Evidence" }), evidenceList(row.r.evidence)) })),
  h("section", { class: "card" }, h("h2", { text: "Rule analysis" }), v.findings.length ? h("ul", { class: "plain" }, v.findings.map((f) => h("li", {}, chip(f.kind, f.severity === "warning" ? "medium" : "high"), " ", f.message))) : h("p", { text: "No shadowed, conflicting or overly broad rules were found by this tool's checks." })),
  v.nat.length ? h("section", { class: "card" }, h("h2", { text: "NAT (recorded, not applied to decisions)" }), table(["Id", "Kind", "Original source", "Original destination", "Translated source", "Translated destination", "Zones", "Notes"], v.nat.map((n) => ({ cells: [n.id, n.kind, n.original_src, n.original_dst, n.translated_src, n.translated_dst, n.zones, n.notes.join(" ")] })))) : null];
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
  return [h("section", { class: "card" }, h("h2", {}, "Observed traffic against configured permissions ", kindChip("OBSERVED"), " ", kindChip("CONFIGURED")), policyPicker(policies, id),
    h("div", { class: "row" }, Object.entries(c.counts).map(([k, v]) => h("span", {}, chip(k), ` ${v}  `))), notice(c.note, "info"),
    table(["Initiator", "Responder", "Service", "Outcome", "Matched rule", "Reading"], c.rows.map((r) => ({ r, cells: [r.observed.initiator, r.observed.responder, r.observed.port !== null ? `${r.observed.proto}/${r.observed.port}` : r.observed.proto, chip(r.outcome), r.rule || "-", r.reading] })),
      { detail: (row) => h("div", {}, h("p", { text: row.r.basis }), row.r.uncertain.length ? h("p", { class: "small", text: "Uncertain because: " + row.r.uncertain.join("; ") }) : null, row.r.return_path ? h("p", { class: "small", text: `Reply direction (stateless): ${row.r.return_path.outcome}: ${row.r.return_path.basis}` }) : null, h("p", { class: "small muted", text: `Zones used: ${row.r.zones.map((z) => z || "unknown").join(" to ")}. Set zones on the Groups & labels tab.` }), h("h3", { text: "Rule evidence" }), evidenceList(row.r.decision_evidence), h("h3", { text: "Observed" }), h("p", { text: row.r.observed.explanation }), evidenceList(row.r.observed.evidence)) })),
  h("section", { class: "card" }, h("h2", { text: "Allow rules no observed traffic matched" }), h("p", { class: "small muted", text: "This is not a list of unused rules: a capture only covers its own time window and location." }),
    c.unobserved_rules.length ? table(["Rule", "Source", "Destination", "Service"], c.unobserved_rules.map((r) => ({ cells: [r.rule, r.src, r.dst, r.svc] }))) : h("p", { text: "Every enabled allow rule matched some observed traffic first." }))];
};

// ------------------------------------------------------------------ groups & labels
VIEWS.groups = async () => {
  const project = await api(`/api/projects/${state.pid}`);
  const subnets = project.subnets.map((x) => ({ ...x })), groups = project.groups.map((g) => ({ ...g, members: [...g.members] })), labels = Object.entries(project.labels);
  const subBody = h("tbody"), grpBody = h("tbody"), lblBody = h("tbody");
  const input = (v, ph, w) => h("input", { type: "text", value: v || "", placeholder: ph, size: w || 18 });
  const addSub = (x = { cidr: "", label: "", zone: "" }) => { const c = input(x.cidr, "10.20.0.0/16"), l = input(x.label, "Engineering"), z = input(x.zone, "zone or interface name", 22);
    const tr = h("tr", { "data-kind": "sub" }, h("td", {}, c), h("td", {}, l), h("td", {}, z), h("td", {}, h("button", { type: "button", onclick: () => tr.remove() }, "Remove"))); tr._get = () => ({ cidr: c.value.trim(), label: l.value.trim(), zone: z.value.trim() }); subBody.append(tr); };
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
  return [h("section", { class: "card" }, h("h2", { text: "Subnets" }), h("p", { class: "small muted", text: "Define the networks you know. The optional zone is the zone or interface name a firewall rule would use for that network; it is how observed traffic is matched against zone-based rules." }),
    h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Network (CIDR)", "Label", "Zone / interface", ""].map((x) => h("th", { text: x })))), subBody)), h("div", { class: "row" }, h("button", { type: "button", onclick: () => addSub() }, "Add subnet"))),
  h("section", { class: "card" }, h("h2", { text: "Device labels" }), h("p", { class: "small muted", text: "Labels are yours. They appear in explanations as 'labelled ...'. The tool does not guess what a device is." }),
    h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Address", "Label", ""].map((x) => h("th", { text: x })))), lblBody)), h("div", { class: "row" }, h("button", { type: "button", onclick: () => addLbl() }, "Add label"))),
  h("section", { class: "card" }, h("h2", {}, "Groups for directional policies ", kindChip("PROPOSED")), h("p", { class: "small muted", text: "An endpoint can be in several groups. Members are addresses or CIDR networks. Tick 'isolated behind a gateway' for groups whose members reach the outside only through an external egress policy." }),
    h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Group", "Members", "Isolated behind a gateway", ""].map((x) => h("th", { text: x })))), grpBody)),
    h("div", { class: "row" }, h("button", { type: "button", onclick: () => addGrp() }, "Add group"), h("button", { type: "button", onclick: suggest }, "Suggest one group per subnet"))),
  h("div", { class: "row" }, h("button", { type: "button", class: "primary", onclick: save }, "Save subnets, labels and groups"))];
};

// ------------------------------------------------------------------ migrate
function warnList(items) {
  return h("ul", { class: "plain small" }, items.map((w) => h("li", {}, chip(w.severity, w.severity === "info" ? "medium" : w.severity), " ", w.message, w.evidence && w.evidence.length ? h("span", { class: "muted" }, " [", w.evidence.map((e) => `${e.kind} ${e.ref}`).join("; "), "]") : null)));
}
VIEWS.migrate = async () => {
  const project = await api(`/api/projects/${state.pid}`);
  const policies = project.sources.filter((x) => x.kind === "policy");
  const mig = state.mig || (state.mig = { workflow: "preserve", policy: "", low: false, ack: false, target: "cisco-asa" });
  if (!policies.find((p) => p.id === mig.policy) && policies.length) mig.policy = policies[0].id;
  const out = [h("section", { class: "card" }, h("h2", {}, "Choose a workflow ", kindChip("PROPOSED")),
    h("div", { class: "row" }, h("label", {}, h("input", { type: "radio", name: "wf", value: "preserve", checked: mig.workflow === "preserve", onchange: () => { mig.workflow = "preserve"; render(); } }), " Preserve existing configured permissions"),
      h("label", {}, h("input", { type: "radio", name: "wf", value: "narrow", checked: mig.workflow === "narrow", onchange: () => { mig.workflow = "narrow"; render(); } }), " Propose narrower permissions from observed communications")),
    mig.workflow === "preserve" ? h("p", { class: "small muted", text: "Translates what the source device is configured to allow, rule by rule. Nothing is narrowed or widened on purpose; every place it does either is reported." })
      : [h("p", { class: "small muted", text: "Builds proposals only from what the imported capture(s) show. Observed traffic is not proof of business need, and a capture is only a time window. Every proposal needs review." }),
        h("label", {}, h("input", { type: "checkbox", checked: mig.low, onchange: (e) => { mig.low = e.target.checked; } }), " Include flows whose initiator is low or unknown confidence (not recommended)")],
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
    h("p", { class: "small", text: "A policy connects From groups to To groups. From may initiate connections to To; To may not initiate to From. Allowing both directions takes two policies. External egress policies are separate. Replies to a permitted connection are not a separate permission." }),
    h("div", { class: "row" }, h("button", { type: "button", class: "primary", onclick: run }, "Build directional policies")), holder);
}
function showPlan(plan, mig) {
  const out = [];
  const bad = plan.summary.policies_that_broaden_access || plan.summary.policies_that_lose_restrictions || plan.summary.deny_rules_not_translated;
  out.push(notice(plan.summary.verdict, bad ? "bad" : "info"));
  out.push(h("div", { class: "grid" }, Object.entries(plan.summary).filter(([k]) => k !== "verdict").map(([k, v]) => stat(k.replace(/_/g, " "), v))));
  if (plan.workflow === "narrow") {
    const o = plan.observation;
    out.push(h("h3", { text: "Observation period (read before using any proposal)" }), h("ul", { class: "plain small" }, (o.captures || []).map((c) => h("li", { text: `${c.filename}: ${fmtTime(c.first_ts)} to ${fmtTime(c.last_ts)}; observation point: ${c.observation_point}` })), (o.caveats || []).map((c) => h("li", { text: c }))));
  }
  out.push(h("h3", { text: "Group policies" }));
  for (const p of plan.policies) {
    out.push(h("div", { class: "card" }, h("b", { text: p.name }), " ", chip(p.status), " ", chip(p.origin, "proposed"),
      p.status === "blocked" ? null : h("p", { class: "small" }, h("b", { text: "From " }), p.from_groups.join(", "), " ", h("b", { text: "may initiate to " }), p.to_groups.join(", "), ". ", p.direction_note.split(". ")[1] || ""),
      h("p", { class: "small muted", text: p.basis }), p.services_informational.length ? h("p", { class: "small", text: "Services (information only; the model does not enforce them): " + p.services_informational.join("; ") }) : null,
      p.granted_pairs ? h("p", { class: "small", text: `Group membership grants ${p.granted_pairs.toLocaleString()} address pair(s); ${p.observed_pairs} ${plan.workflow === "narrow" ? "initiating pair(s) observed" : "pair(s) covered by source rules"}.` }) : null,
      p.warnings.length ? warnList(p.warnings) : null, evidenceList(p.evidence.slice(0, 4))));
  }
  if (plan.egress_policies.length) {
    out.push(h("h3", { text: "External egress policies" }));
    for (const e of plan.egress_policies) out.push(h("div", { class: "card" }, h("b", { text: e.name }), " ", chip(e.status), h("p", { class: "small", text: `Endpoint groups: ${e.endpoint_groups.join(", ")}. Enabled: ${e.enabled ? "yes" : "no"}. Allow all DNS queries: ${e.allow_all_dns ? "yes" : "no"}.` }),
      h("p", { class: "small", text: `Allowed prefixes: ${e.allowed_prefixes.join(" ") || "-"}` }), h("p", { class: "small", text: `Allowed DNS names: ${e.allowed_dns_names.join(" ") || "-"}` }), e.services.length ? h("p", { class: "small", text: "Services (information only): " + e.services.join("; ") }) : null, warnList(e.warnings)));
  }
  out.push(h("h3", { text: "Gaps: what did not translate, or translated with a loss" }), plan.gaps.length ? warnList(plan.gaps) : h("p", { class: "small", text: "None recorded." }));
  out.push(h("h3", { text: "Review items" }), plan.review_items.length ? warnList(plan.review_items) : h("p", { class: "small", text: "None." }));
  if (plan.workflow === "narrow") out.push(h("label", {}, h("input", { type: "checkbox", checked: mig.ack, onchange: (e) => { mig.ack = e.target.checked; } }), " I have read the observation limits and will confirm each proposal with the people who run these systems before enforcing it."));
  out.push(h("p", { class: "small muted", text: "Directional rules alone are not a complete zero trust architecture: identity, device posture, encryption and monitoring are outside this worksheet. Export it on the Export tab." }));
  return out;
}
function firewallCard(mig, project, policies) {
  const holder = h("div");
  const targets = state.status ? Object.entries(state.status.targets) : [];
  const zoneRow = h("div", { class: "row" });
  const targetSel = h("select", {}, targets.map(([k, l]) => h("option", { value: k, selected: k === mig.target }, l)));
  targetSel.addEventListener("change", () => { mig.target = targetSel.value; });
  const zoneInput = h("textarea", { class: "wide", rows: 3, placeholder: "One per line: source zone = destination interface, for example\not = Vlan30\ncorp = Vlan10" }, Object.entries(state.zoneMap).map(([k, v]) => `${k} = ${v}`).join("\n"));
  const run = async () => {
    state.zoneMap = Object.fromEntries(zoneInput.value.split("\n").map((l) => l.split("=").map((x) => x.trim())).filter((p) => p.length === 2 && p[0] && p[1]));
    const t = await guarded(() => api(`/api/projects/${state.pid}/translate`, { method: "POST", json: body(mig, { target: mig.target, zone_map: state.zoneMap }) }));
    if (!t) return;
    state.translation = t; holder.replaceChildren(...showTranslation(t));
  };
  if (state.translation && state.translation.workflow === mig.workflow) holder.replaceChildren(...showTranslation(state.translation));
  return h("section", { class: "card" }, h("h2", {}, "Translate to another firewall ", kindChip("PROPOSED")),
    h("p", { class: "small", text: "Rule order and stateful or stateless behaviour are preserved or called out. A rule the destination cannot express is blocked and left as a comment; it is never replaced by 'any'. Output is for review and is not deployed anywhere." }),
    h("div", { class: "row" }, h("label", { class: "field" }, "Destination", targetSel)),
    h("label", { class: "field" }, "Interface mapping (destination interface names are never guessed; unmapped zones show as <TARGET-IF:...> placeholders)", zoneInput), zoneRow,
    h("div", { class: "row" }, h("button", { type: "button", class: "primary", onclick: run }, "Translate and validate")), holder);
}
function showTranslation(t) {
  const out = [];
  const s_ = t.summary;
  out.push(notice(s_.verdict, s_.blocked || s_.blocked_deny_rules || s_.rules_known_broader ? "bad" : "info"));
  out.push(h("div", { class: "grid" }, Object.entries(s_).filter(([k]) => k !== "verdict").map(([k, v]) => stat(k.replace(/_/g, " "), v))));
  out.push(h("h3", { text: "Per-rule report" }), table(["Source", "Status", "Reason"], t.report.map((e) => ({ cells: [e.source_rule, chip(e.status, e.status === "translated" ? "allow" : e.status === "blocked" ? "blocked" : "medium"), e.reason || "-"] }))));
  out.push(h("h3", { text: "Issues" }), warnList(t.issues));
  const v = t.validation;
  out.push(h("h3", { text: "Validation: source and destination decisions on sampled connections" }), notice(v.summary.result, (v.summary.target_broader || v.summary.problems) ? "bad" : "info"),
    h("div", { class: "grid" }, Object.entries(v.summary).filter(([k]) => k !== "result").map(([k, x]) => stat(k.replace(/_/g, " "), x))));
  const rows = (v.mismatches || v.problems || []);
  if (rows.length) out.push(table(["Kind", "Connection", "Detail"], rows.map((m) => ({ cells: [m.kind + (m.explained_by_known_broader_rule ? " (known broader return rule)" : "") + (m.explained_by_blocked_rule ? ` (rule ${m.explained_by_blocked_rule} was not translated)` : "") + (m.explained_by_source_default ? " (source default not translated)" : ""), m.connection, m.detail || `source: ${m.source} / destination: ${m.destination}`] }))));
  out.push(h("p", { class: "small muted" }, h("b", { text: "Limits of this comparison: " }), v.limits.join(" ")));
  if (t.placeholders.length) out.push(notice(`Replace these placeholders before use: ${t.placeholders.join(" ")}`, "bad"));
  out.push(h("h3", { text: "Generated configuration (review only)" }), h("pre", { class: "code", text: t.text }));
  return out;
}

// ------------------------------------------------------------------ export & AI
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
  const out = [h("section", { class: "card" }, h("h2", { text: "Exports" }), h("p", { class: "small", text: `Current workflow: ${mig.workflow === "preserve" ? "preserve configured permissions" : "narrower permissions from observation"}. Change it on the Migrate tab.` }),
    mig.workflow === "narrow" ? h("label", {}, h("input", { type: "checkbox", checked: mig.ack, onchange: (e) => { mig.ack = e.target.checked; } }), " I have read the observation limits (required to export proposals built from a capture)") : null,
    h("h3", { text: "Directional group policy worksheet" }), h("div", { class: "row" }, btn("Worksheet (Markdown)", "plan-markdown"), btn("Worksheet (JSON)", "plan-json"), btn("Group policies (CSV)", "plan-csv-group-policies"), btn("Groups (CSV)", "plan-csv-groups"), btn("Egress policies (CSV)", "plan-csv-egress-policies"), btn("Gaps (CSV)", "plan-csv-gaps"), btn("Review items (CSV)", "plan-csv-review")),
    h("p", { class: "small muted", text: "This is a worksheet to apply by hand. It is not an import file for any product." }),
    h("h3", { text: "Firewall translation" }), h("div", { class: "row" }, btn("Configuration text", "firewall-text"), btn("Report with validation (Markdown)", "firewall-markdown")),
    h("h3", { text: "Observed communications" }), h("div", { class: "row" }, btn("Explanations (Markdown)", "communications-markdown"), btn("Table (CSV)", "communications-csv")),
    h("p", { class: "small muted", text: "CSV cells that a spreadsheet could run as formulas are neutralised. Text from captures and exports is escaped in Markdown." }))];
  out.push(await aiCard());
  return out;
};
async function aiCard() {
  const holder = h("div");
  const pkg = async () => { const r = await guarded(() => api(`/api/projects/${state.pid}/ai`, { method: "POST", json: {} })); if (r) holder.replaceChildren(h("p", { class: "small muted", text: `Sends to: ${r.sends_to}` }), h("textarea", { class: "wide", readonly: true, rows: 10 }, r.prompt)); };
  const ask = async () => { const r = await guarded(() => api(`/api/projects/${state.pid}/ai`, { method: "POST", json: { send: true } })); if (r) holder.replaceChildren(notice(r.label, "info"), h("pre", { class: "code", text: r.text })); };
  return h("section", { class: "card" }, h("h2", { text: "Optional AI assistance (off unless you set it up)" }),
    h("p", { class: "small", text: "Nothing is sent to any AI service by default. You can copy a prompt made only from the parsed statements above (uploaded text is marked as untrusted data inside it) and use it anywhere you choose." + (state.status && state.status.ai_enabled ? " An endpoint was configured when this server started." : " Sending from this page is disabled; start the server with --ai-endpoint to enable it.") }),
    h("div", { class: "row" }, h("button", { type: "button", onclick: pkg }, "Show grounded prompt"), state.status && state.status.ai_enabled ? h("button", { type: "button", onclick: ask }, "Send to the configured endpoint") : null), holder);
}

// ------------------------------------------------------------------ privacy
VIEWS.privacy = async () => {
  const st = await api("/api/status"); state.status = st;
  return [h("section", { class: "card" }, h("h2", { text: "Where your data is" }),
    h("p", { text: `Everything is stored in ${st.usage.data_dir} (${st.usage.files} files, ${fmtBytes(st.usage.bytes)}), readable only by your user account.` }),
    h("p", { text: st.network }),
    h("ul", { class: "plain" }, h("li", { text: "Uploaded files are parsed in a separate process with memory, CPU and time limits, and are never executed." }), h("li", { text: "Passwords, keys and community strings found in configuration exports are redacted from anything stored as evidence or shown." }),
      h("li", { text: "Nothing is deleted automatically unless the server was started with --retention-days." }),
      h("li", { text: "Deleting overwrites file contents before removing them, as a best effort. It cannot be guaranteed on SSDs, copy-on-write file systems, or in backups you made.", })),
    h("div", { class: "row" }, state.pid ? h("button", { type: "button", class: "danger", onclick: async () => { if (confirm("Delete this project and every file in it?")) { await guarded(() => api(`/api/projects/${state.pid}`, { method: "DELETE" })); await loadProjects(); state.overview = null; render(); } } }, "Delete this project") : null,
      h("button", { type: "button", class: "danger", onclick: async () => { if (confirm("Delete ALL projects and files from this computer?")) { await guarded(() => api("/api/data", { method: "DELETE" })); await loadProjects(); render(); } } }, "Delete all data"))),
  h("section", { class: "card" }, h("h2", { text: "What this tool does not claim" }), h("ul", { class: "plain" },
    h("li", { text: "Observed traffic is not proof of business need, and traffic missing from a capture is not proof that it never happens." }),
    h("li", { text: "A device's role is never inferred from its traffic." }),
    h("li", { text: "A translation is not proven equivalent to its source. The validation compares sampled connections using this tool's own evaluator." }),
    h("li", { text: "Directional policies are one control, not a complete zero trust architecture." })))];
};

// ------------------------------------------------------------------ start
async function main() {
  const wanted = location.hash.match(/tab=([a-z]+)/);
  if (wanted && TABS.some(([id]) => id === wanted[1])) state.tab = wanted[1];
  const m = location.hash.match(/token=([A-Za-z0-9_-]+)/);
  if (m) { try { sessionStorage.setItem("pb-token", m[1]); } catch (e) { /* storage may be unavailable */ } history.replaceState(null, "", location.pathname); }
  try { state.token = sessionStorage.getItem("pb-token") || ""; } catch (e) { state.token = ""; }
  if (!state.token) { document.getElementById("view").replaceChildren(notice("Open the address printed in the terminal when the server started; it includes the access token.", "bad")); return; }
  document.getElementById("projectSelect").addEventListener("change", (e) => { state.pid = e.target.value; state.overview = null; state.plan = null; state.translation = null; render(); });
  document.getElementById("newProject").addEventListener("click", async () => {
    const name = prompt("Name for the new project:"); if (!name) return;
    const p = await guarded(() => api("/api/projects", { method: "POST", json: { name } })); if (p) { await loadProjects(p.id); state.tab = "start"; render(); }
  });
  await guarded(async () => { state.status = await api("/api/status"); await loadProjects(); });
  render();
}
main();
