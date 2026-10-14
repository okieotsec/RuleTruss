"use strict";
// The relationship graph: a force layout you can drag, pan, zoom and resize, with a side panel that drills into a device, a subnet or one
// direction between two of them. Every string from a capture or an upload is placed with textContent, never as markup.
// Uses the helpers of app.js (h, s, api, guarded, chip, table, more, notice, fmtTime, fmtBytes, state, render).

const GRAPH_SIZES = [["Compact", 380], ["Standard", 560], ["Tall", 820]];
const GRAPH_COLORS = 8;
const graphMemory = new Map();      // dragged positions, kept while this page is open

function seededRandom(text) {
  let a = 2166136261;
  for (let i = 0; i < text.length; i++) { a ^= text.charCodeAt(i); a = Math.imul(a, 16777619); }
  return () => { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

// Fruchterman-Reingold with a pull towards each node's subnet, so subnets form visible clusters. Deterministic for the same data.
function layoutGraph(nodes, edges, W, H) {
  const n = nodes.length, groups = [...new Set(nodes.map((x) => x.group))].sort();
  const centers = {};
  groups.forEach((g, i) => {
    const a = (2 * Math.PI * i) / groups.length - Math.PI / 2, r = groups.length > 1 ? Math.min(W, H) * 0.3 : 0;
    centers[g] = { x: W / 2 + r * 1.35 * Math.cos(a), y: H / 2 + r * Math.sin(a) };
  });
  const rnd = seededRandom(nodes.map((x) => x.id).join("|"));
  const pos = nodes.map((nd) => { const c = centers[nd.group]; return { x: c.x + (rnd() - 0.5) * 120, y: c.y + (rnd() - 0.5) * 120, dx: 0, dy: 0 }; });
  const index = new Map(nodes.map((nd, i) => [nd.id, i]));
  const links = edges.map((e) => [index.get(e.from), index.get(e.to)]).filter(([a, b]) => a !== undefined && b !== undefined && a !== b);
  const k = Math.sqrt((W * H) / Math.max(n, 1)) * 0.55, iterations = n > 90 ? 160 : 260;
  for (let step = 0; step < iterations; step++) {
    const t = (W / 9) * (1 - step / iterations) + 0.5;
    for (const p of pos) { p.dx = 0; p.dy = 0; }
    for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
      let dx = pos[i].x - pos[j].x, dy = pos[i].y - pos[j].y, d = Math.hypot(dx, dy);
      if (d < 0.01) { dx = rnd() - 0.5; dy = rnd() - 0.5; d = 0.5; }
      const f = (k * k) / d;
      pos[i].dx += (dx / d) * f; pos[i].dy += (dy / d) * f; pos[j].dx -= (dx / d) * f; pos[j].dy -= (dy / d) * f;
    }
    for (const [a, b] of links) {
      const dx = pos[a].x - pos[b].x, dy = pos[a].y - pos[b].y, d = Math.hypot(dx, dy) || 0.01, f = (d * d) / k * 0.6;
      pos[a].dx -= (dx / d) * f; pos[a].dy -= (dy / d) * f; pos[b].dx += (dx / d) * f; pos[b].dy += (dy / d) * f;
    }
    nodes.forEach((nd, i) => {
      const c = centers[nd.group];
      pos[i].dx += (c.x - pos[i].x) * 0.35; pos[i].dy += (c.y - pos[i].y) * 0.35;
      pos[i].dx += (W / 2 - pos[i].x) * 0.02; pos[i].dy += (H / 2 - pos[i].y) * 0.02;
      const d = Math.hypot(pos[i].dx, pos[i].dy) || 0.01, m = Math.min(d, t);
      pos[i].x += (pos[i].dx / d) * m; pos[i].y += (pos[i].dy / d) * m;
    });
  }
  return pos.map((p) => ({ x: p.x, y: p.y }));
}

VIEWS.graph = async () => {
  const level = state.graphLevel || "subnet", focus = level === "device" ? (state.graphFocus || "") : "";
  const data = await api(`/api/projects/${state.pid}/graph?level=${level}${focus ? `&focus=${encodeURIComponent(focus)}` : ""}`);
  const size = state.graphSize || 560;
  const holder = h("div", { class: "gwrap" });
  const panel = h("aside", { class: "gdetail", "aria-live": "polite" }, h("p", { class: "muted small", text: "Click a circle to see what it is, who it talks to and a sample of its traffic. Click an arrow for one direction. Double-click a subnet to open its devices." }));
  const box = h("div", { class: "graphbox" });
  box.style.height = size > 0 ? `${size}px` : `${Math.max(380, window.innerHeight - 190)}px`;      // set through the CSSOM: the page's policy forbids style attributes
  const view = drawGraph(data, box, panel, level);
  box.append(view.svg);
  const modeSel = h("select", { "aria-label": "Show" }, [["subnet", "Subnets"], ["device", "Devices (busiest 120)"]].map(([v, l]) => h("option", { value: v, selected: v === level }, l)));
  modeSel.addEventListener("change", () => { state.graphLevel = modeSel.value; state.graphFocus = ""; render(); });
  const sizeSel = h("select", { "aria-label": "Size" }, [...GRAPH_SIZES, ["Window", 0]].map(([l, v]) => h("option", { value: v, selected: v === size || (v === 0 && size === -1) }, l)));
  sizeSel.addEventListener("change", () => {
    const v = Number(sizeSel.value);
    state.graphSize = v || -1;
    box.style.height = v ? `${v}px` : `${Math.max(380, window.innerHeight - 190)}px`;
    view.fit();
  });
  const labelSel = h("select", { "aria-label": "Labels" }, [["auto", "Labels: busiest"], ["all", "Labels: all"], ["none", "Labels: hover only"]].map(([v, l]) => h("option", { value: v, selected: v === (state.graphLabels || "auto") }, l)));
  labelSel.addEventListener("change", () => { state.graphLabels = labelSel.value; view.setLabels(labelSel.value); });
  const btn = (label, title, fn) => h("button", { type: "button", title, "aria-label": title, onclick: fn }, label);
  const back = focus ? h("button", { type: "button", onclick: () => { state.graphLevel = "subnet"; state.graphFocus = ""; render(); } }, "Back to subnets") : null;
  const legend = h("div", { class: "glegend", "aria-label": "Colours are subnets" }, view.groups.slice(0, 16).map(([g, i, label]) => h("span", { class: "glegitem" }, h("i", { class: `gdot gc${i}` }), label)),
    view.groups.length > 16 ? h("span", { class: "muted small", text: `+${view.groups.length - 16} more` }) : null);
  holder.append(box, panel);
  return h("section", { class: "card" }, sectionTitle("Who talks to whom", "OBSERVED"),
    h("div", { class: "row gtools" }, h("label", { class: "field" }, "Show", modeSel), back, h("label", { class: "field" }, "Size", sizeSel), h("label", { class: "field" }, "Labels", labelSel),
      h("span", { class: "btngroup" }, btn("+", "Zoom in", () => view.zoom(1 / 1.3)), btn("\u2212", "Zoom out", () => view.zoom(1.3)), btn("Fit", "Fit everything in the box", () => view.fit()))),
    h("p", { class: "small muted", text: focus ? `Devices in ${focus} and the devices they talk to. Arrows point from the side that started the conversation; dashed red means some starters are uncertain. Drag circles, scroll to zoom, drag the corner to resize.` : "Arrows point from the side that started the conversation; dashed red means some starters are uncertain. Drag circles, scroll to zoom, drag the corner of the box to resize it." }),
    legend, holder, data.truncated ? notice("Only the busiest devices are drawn. Open a subnet to see its devices.", "info") : null);
};

function drawGraph(data, box, panel, level) {
  const svg = s("svg", { class: "graph", role: "group", "aria-label": "Directional communication graph", preserveAspectRatio: "xMidYMid meet" });
  svg.append(s("defs", {}, s("marker", { id: "arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 11, markerHeight: 11, markerUnits: "userSpaceOnUse", orient: "auto" }, s("path", { d: "M0 0 L10 5 L0 10 z" })),
    s("marker", { id: "arrowlow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 11, markerHeight: 11, markerUnits: "userSpaceOnUse", orient: "auto" }, s("path", { d: "M0 0 L10 5 L0 10 z" }))));
  const nodes = data.nodes, groupNames = [...new Set(nodes.map((n) => n.group))].sort();
  const groupIndex = new Map(groupNames.map((g, i) => [g, i % GRAPH_COLORS]));
  const groups = groupNames.map((g) => [g, groupIndex.get(g), (nodes.find((n) => n.group === g) || {}).label && level === "subnet" ? nodes.find((n) => n.group === g).label : g]);
  const api_ = { svg, groups, zoom() {}, fit() {}, setLabels() {} };
  if (!nodes.length) { svg.setAttribute("viewBox", "0 0 400 120"); svg.append(s("text", { x: 20, y: 60 }, "Nothing to draw yet. Import a capture first.")); return api_; }

  const W = 1000, H = 640, key = (id) => `${level}|${data.focus || ""}|${id}`;
  const laid = layoutGraph(nodes, data.edges, W, H);
  const maxWeight = Math.max(...nodes.map((n) => n.weight || 1), 1);
  const items = nodes.map((n, i) => {
    const saved = graphMemory.get(key(n.id));
    return { n, x: saved ? saved.x : laid[i].x, y: saved ? saved.y : laid[i].y, r: 7 + 16 * Math.sqrt((n.weight || 1) / maxWeight), color: groupIndex.get(n.group) };
  });
  const byId = new Map(items.map((it) => [it.n.id, it]));
  const maxCount = Math.max(...data.edges.map((e) => e.count), 1);
  const busiest = new Set([...items].sort((a, b) => (b.n.weight || 0) - (a.n.weight || 0)).slice(0, items.length <= 24 ? items.length : 14).map((it) => it.n.id));
  let labelMode = state.graphLabels || "auto", selected = null;

  const edgeEls = data.edges.map((e) => {
    const a = byId.get(e.from), b = byId.get(e.to);
    if (!a || !b) return null;
    const width = 1.2 + 3.2 * Math.log(1 + e.count) / Math.log(1 + maxCount);
    const g = s("g", { class: `edgeg${e.low ? " low" : ""}`, tabindex: 0, role: "button", "aria-label": `${a.n.label} to ${b.n.label}, ${e.count} flows` });
    const hit = s("path", { class: "edgehit" }), path = s("path", { class: `edge${e.low ? " low" : ""}`, "stroke-width": width, "marker-end": e.low ? "url(#arrowlow)" : "url(#arrow)" });
    g.append(hit, path, s("title", {}, `${a.n.label} to ${b.n.label}: ${e.count} flows${e.services.length ? " (" + e.services.join(", ") + ")" : ""}${e.low ? "; some starters uncertain" : ""}`));
    const pick = () => select({ kind: "edge", from: e.from, to: e.to, el: g });
    g.addEventListener("click", (ev) => { ev.stopPropagation(); pick(); });
    g.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); pick(); } });
    const el = { e, a, b, g, hit, path };
    return el;
  }).filter(Boolean);
  const edgeLayer = s("g", { class: "edges" }, edgeEls.map((x) => x.g)), nodeLayer = s("g", { class: "nodes" });
  const nodeEls = items.map((it) => {
    const circle = s("circle", { class: `node gc${it.color}`, r: it.r });
    const text = s("text", { class: "nodelabel" }, it.n.label.length > 26 ? it.n.label.slice(0, 25) + "\u2026" : it.n.label);
    const g = s("g", { class: "nodeg", tabindex: 0, role: "button", "aria-label": `${it.n.label}${it.n.address && it.n.address !== it.n.label ? " (" + it.n.address + ")" : ""}` }, circle, text, s("title", {}, `${it.n.label}${it.n.address && it.n.address !== it.n.label ? " (" + it.n.address + ")" : ""}${it.n.devices ? `, ${it.n.devices} devices` : ""}`));
    it.g = g; it.text = text; it.circle = circle;
    return g;
  });
  nodeLayer.append(...nodeEls);
  svg.append(edgeLayer, nodeLayer);

  function place() {
    for (const x of edgeEls) {
      const { a, b, e } = x;
      let d;
      if (a === b) d = `M${a.x - 4} ${a.y - a.r} c -28 -42 40 -42 8 0`;
      else {
        const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1, ux = dx / len, uy = dy / len;
        const sx = a.x + ux * (a.r + 1), sy = a.y + uy * (a.r + 1), ex = b.x - ux * (b.r + 3), ey = b.y - uy * (b.r + 3);
        const off = Math.min(26, len * 0.12) * (e.from < e.to ? 1 : -1), mx = (sx + ex) / 2 - uy * off, my = (sy + ey) / 2 + ux * off;
        d = `M${sx} ${sy} Q${mx} ${my} ${ex} ${ey}`;
      }
      x.path.setAttribute("d", d); x.hit.setAttribute("d", d);
    }
    for (const it of items) { it.g.setAttribute("transform", `translate(${it.x} ${it.y})`); it.text.setAttribute("x", it.r + 5); it.text.setAttribute("y", 4); }
  }
  function showLabels() {
    for (const it of items) it.g.classList.toggle("nolabel", !(labelMode === "all" || (labelMode === "auto" && busiest.has(it.n.id)) || (selected && selected.id === it.n.id)));
  }

  // ---- view box: fit, zoom, pan
  let vb = { x: 0, y: 0, w: W, h: H };
  const apply = () => svg.setAttribute("viewBox", `${vb.x} ${vb.y} ${vb.w} ${vb.h}`);
  function fit() {
    const xs = items.flatMap((it) => [it.x - it.r, it.x + it.r + (labelMode === "none" ? 0 : 150)]), ys = items.flatMap((it) => [it.y - it.r - 8, it.y + it.r + 8]);
    const x0 = Math.min(...xs) - 30, x1 = Math.max(...xs) + 30, y0 = Math.min(...ys) - 30, y1 = Math.max(...ys) + 30;
    const rect = box.getBoundingClientRect(), aspect = (rect.width || 1000) / (rect.height || 560);
    let w = Math.max(x1 - x0, 620), hgt = Math.max(y1 - y0, 620 / aspect);          // do not zoom a small graph up until it looks cartoonish
    if (w / hgt < aspect) w = hgt * aspect; else hgt = w / aspect;
    vb = { x: (x0 + x1) / 2 - w / 2, y: (y0 + y1) / 2 - hgt / 2, w, h: hgt };
    apply();
  }
  function zoom(factor, cx, cy) {
    const px = cx === undefined ? vb.x + vb.w / 2 : cx, py = cy === undefined ? vb.y + vb.h / 2 : cy;
    const w = Math.min(Math.max(vb.w * factor, 120), 6000), k = w / vb.w;
    vb = { x: px - (px - vb.x) * k, y: py - (py - vb.y) * k, w, h: vb.h * k };
    apply();
  }
  const toSvg = (ev) => { const p = svg.createSVGPoint(); p.x = ev.clientX; p.y = ev.clientY; const m = svg.getScreenCTM(); return m ? p.matrixTransform(m.inverse()) : { x: 0, y: 0 }; };
  svg.addEventListener("wheel", (ev) => { ev.preventDefault(); const p = toSvg(ev); zoom(ev.deltaY > 0 ? 1.15 : 1 / 1.15, p.x, p.y); }, { passive: false });

  // ---- dragging a circle, panning the background
  let drag = null, lastTap = null;
  svg.addEventListener("pointerdown", (ev) => {
    if (ev.button !== 0) return;
    const target = ev.target.closest ? ev.target.closest(".nodeg") : null;
    const it = target ? items.find((x) => x.g === target) : null;
    const edge = ev.target.closest ? ev.target.closest(".edgeg") : null;
    if (edge) return;
    drag = { it, start: toSvg(ev), moved: false, lastX: ev.clientX, lastY: ev.clientY };
    try { svg.setPointerCapture(ev.pointerId); } catch (e) { /* a synthetic pointer has nothing to capture */ }
  });
  svg.addEventListener("pointermove", (ev) => {
    if (!drag) return;
    if (Math.hypot(ev.clientX - drag.lastX, ev.clientY - drag.lastY) > 3) drag.moved = true;
    if (!drag.moved) return;
    const p = toSvg(ev);
    if (drag.it) { drag.it.x += p.x - drag.start.x; drag.it.y += p.y - drag.start.y; drag.start = p; place(); }
    else { vb.x -= p.x - drag.start.x; vb.y -= p.y - drag.start.y; apply(); drag.start = toSvg(ev); }
    svg.classList.add("dragging");
  });
  const finish = (ev) => {
    if (!drag) return;
    const d = drag; drag = null; svg.classList.remove("dragging");
    try { svg.releasePointerCapture(ev.pointerId); } catch (e) { /* the pointer may already be released */ }
    if (d.it) {
      graphMemory.set(key(d.it.n.id), { x: d.it.x, y: d.it.y });
      if (d.moved) return;
      // A double-click is detected here: the pointer was captured by the svg, so the browser's own dblclick no longer names the circle.
      const now = performance.now(), again = lastTap && lastTap.id === d.it.n.id && now - lastTap.t < 450;
      lastTap = { id: d.it.n.id, t: now };
      if (again && level === "subnet" && d.it.n.id !== "(undefined)") { state.graphLevel = "device"; state.graphFocus = d.it.n.id; render(); return; }
      select({ kind: level === "subnet" ? "subnet" : "device", id: d.it.n.id, el: d.it.g });
    } else if (!d.moved) select(null);
  };
  svg.addEventListener("pointerup", finish); svg.addEventListener("pointercancel", finish);
  nodeEls.forEach((g, i) => g.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); select({ kind: level === "subnet" ? "subnet" : "device", id: items[i].n.id, el: g }); }
    if (ev.key === "Enter" && ev.shiftKey && level === "subnet" && items[i].n.id !== "(undefined)") { state.graphLevel = "device"; state.graphFocus = items[i].n.id; render(); }
  }));
  box.addEventListener("keydown", (ev) => { if (ev.key === "Escape") select(null); });

  // ---- hover highlights the neighbourhood of a circle
  const hover = (id) => {
    svg.classList.toggle("hovering", !!id);
    const near = new Set(id ? [id] : []);
    edgeEls.forEach((x) => { const on = id && (x.e.from === id || x.e.to === id); x.g.classList.toggle("hot", !!on); if (on) { near.add(x.e.from); near.add(x.e.to); } });
    items.forEach((it) => it.g.classList.toggle("near", near.has(it.n.id)));
  };
  nodeEls.forEach((g, i) => { g.addEventListener("pointerenter", () => hover(items[i].n.id)); g.addEventListener("pointerleave", () => hover(null)); g.addEventListener("focus", () => hover(items[i].n.id)); g.addEventListener("blur", () => hover(null)); });

  // ---- the panel
  async function select(sel) {
    nodeEls.forEach((g) => g.classList.remove("selected")); edgeEls.forEach((x) => x.g.classList.remove("selected"));
    selected = sel && sel.kind !== "edge" ? { id: sel.id } : null;
    showLabels();
    if (!sel) { panel.replaceChildren(h("p", { class: "muted small", text: "Click a circle or an arrow to see what is behind it." })); return; }
    sel.el.classList.add("selected");
    panel.replaceChildren(h("p", { class: "muted small", text: "Loading\u2026" }));
    const q = new URLSearchParams(sel.kind === "edge" ? { kind: "edge", level, from: sel.from, to: sel.to } : { kind: sel.kind, id: sel.id });
    const detail = await guarded(() => api(`/api/projects/${state.pid}/graph/detail?${q}`));
    if (!detail) { panel.replaceChildren(h("p", { class: "muted small", text: "Nothing more is known about this one." })); return; }
    panel.replaceChildren(detailPanel(detail, level, (id) => { const it = byId.get(id); if (it) select({ kind: level === "subnet" ? "subnet" : "device", id, el: it.g }); }));
  }

  place(); showLabels(); apply();
  requestAnimationFrame(fit);
  if (typeof ResizeObserver === "function") { let first = true; new ResizeObserver(() => { if (first) { first = false; return; } fit(); }).observe(box); }
  Object.assign(api_, { zoom: (f) => zoom(f), fit, setLabels: (m) => { labelMode = m; showLabels(); } });
  return api_;
}

function flowsText(n) { return `${n.toLocaleString()} flow${n === 1 ? "" : "s"}`; }
function topList(title, rows, labels, pick) {
  if (!rows || !rows.length) return null;
  return h("div", { class: "gsec" }, h("h4", { text: title }), h("ul", { class: "glist" }, rows.map((r) => h("li", {},
    pick ? h("button", { type: "button", class: "linkbtn", onclick: () => pick(r.name), text: r.name }) : h("span", { text: r.name }),
    labels && labels[r.name] ? h("span", { class: "muted small", text: ` ${labels[r.name]}` }) : null, h("span", { class: "gcount", text: flowsText(r.flows) })))));
}
function serviceChips(title, rows) {
  if (!rows || !rows.length) return null;
  return h("div", { class: "gsec" }, h("h4", { text: title }), h("div", { class: "chips" }, rows.map((r) => h("span", { class: "svc", text: `${r.name} \u00d7${r.flows.toLocaleString()}` }))));
}
function sampleBlock(detail) {
  const comms = detail.sample_communications || [], flows = detail.sample_flows || [];
  return [comms.length ? h("div", { class: "gsec" }, h("h4", { text: "Sample of the traffic" }), h("ul", { class: "glist samples" }, comms.map((c) => h("li", {}, h("span", { text: c.text }), " ", chip(c.direction_confidence)))),
    h("p", { class: "small muted", text: "The most recent communications first. Each line says who started it and how sure that is." })) : null,
  flows.length ? more(`Recent connections (${flows.length})`, table(["Last seen", "Protocol", "From", "To", "Application", "Packets", "Bytes", "Evidence"], flows.map((f) => ({ cells: [fmtTime(f.last_ts), f.proto + (f.ports ? ` ${f.ports}` : ""), f.from, f.to, f.application || "-", f.packets.toLocaleString(), fmtBytes(f.bytes), f.evidence || "-"] })))) : null];
}
function goComms(filter) { state.commFilter = { q: "", proto: "", port: "", app: "", min_confidence: "", ...filter }; state.tab = "comms"; render(); }
function detailPanel(d, level, pick) {
  if (d.kind === "device") {
    const labels = d.labels || {};
    return h("div", {}, h("h3", { text: d.label || d.address }), h("p", { class: "small" }, h("code", { text: d.address }), d.subnet ? ` \u00b7 ${d.subnet_label || d.subnet}` : ""),
      d.mac || d.identity || d.nic_vendor ? h("p", { class: "small" }, d.mac ? [h("code", { text: d.mac }), " ", chip(d.mac_confidence || "possible"), " "] : null, d.nic_vendor ? `card by ${d.nic_vendor}. ` : "", d.identity ? `Says it is: ${d.identity}` : "") : null,
      h("div", { class: "gstats" }, stat("started", flowsText(d.started_flows)), stat("answered", flowsText(d.answered_flows)), stat("talks to", `${d.peers_out} device${d.peers_out === 1 ? "" : "s"}`), stat("reached by", `${d.peers_in} device${d.peers_in === 1 ? "" : "s"}`)),
      d.uncertain ? h("p", { class: "small muted", text: `${d.uncertain} communication${d.uncertain === 1 ? "" : "s"} where who started it is uncertain.` }) : null,
      topList("Talks to", d.talks_to, labels, level === "device" ? pick : null), topList("Reached by", d.reached_by, labels, level === "device" ? pick : null),
      serviceChips("Offers (answers on)", d.offers), serviceChips("Uses (connects to)", d.uses), sampleBlock(d),
      h("div", { class: "row" }, h("button", { type: "button", class: "primary", onclick: () => goComms({ q: d.address }) }, "See all its communications")));
  }
  if (d.kind === "subnet") {
    return h("div", {}, h("h3", { text: d.label || d.id }), h("p", { class: "small" }, h("code", { text: d.id }), d.zone ? ` \u00b7 zone ${d.zone}` : ""),
      h("div", { class: "gstats" }, stat("devices seen", d.devices), stat("started", flowsText(d.started_flows)), stat("answered", flowsText(d.answered_flows)), stat("inside itself", flowsText(d.inside_flows))),
      topList("Busiest devices", d.busiest_devices.map((x) => ({ name: x.name, flows: x.flows })), Object.fromEntries(d.busiest_devices.filter((x) => x.label).map((x) => [x.name, x.label])), null),
      topList("Talks to (other subnets)", d.talks_to, null, level === "subnet" ? pick : null), topList("Reached by (other subnets)", d.reached_by, null, level === "subnet" ? pick : null),
      serviceChips("Offers (answers on)", d.offers), serviceChips("Uses (connects to)", d.uses), sampleBlock(d),
      h("div", { class: "row" }, d.id !== "(undefined)" ? h("button", { type: "button", class: "primary", onclick: () => { state.graphLevel = "device"; state.graphFocus = d.id; render(); } }, "Open its devices") : null,
        h("button", { type: "button", onclick: () => goComms({ from_subnet: d.filter_key }) }, "Traffic it starts")));
  }
  const names = level === "device" ? [d.initiator_label || d.from, d.responder_label || d.to] : [d.from, d.to];
  return h("div", {}, h("h3", { text: `${names[0]} \u2192 ${names[1]}` }), h("p", { class: "small" }, h("code", { text: d.from }), " started, ", h("code", { text: d.to }), " answered"),
    h("div", { class: "gstats" }, stat("flows", d.flows.toLocaleString()), stat("communications", d.communications), stat("uncertain who started", d.uncertain)),
    serviceChips("Services", d.services), sampleBlock(d),
    h("div", { class: "row" }, h("button", { type: "button", class: "primary", onclick: () => goComms(d.level === "device" ? { initiator: d.from, responder: d.to } : { from_subnet: d.from, to_subnet: d.to }) }, "See these communications")));
}
