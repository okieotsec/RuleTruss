// End-to-end check of the web interface in headless Chromium, using only Node's built-ins (no packages, no window).
// Usage: node tools/ui_check.mjs "<url with #token=...>" [screenshot-directory]
// Prints one JSON object: {ok, failures, console_errors, checks}. Exits 0 when every check passes.
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const url = process.argv[2];
const shots = process.argv[3];
const chromium = process.env.CHROMIUM || "chromium";
const profile = mkdtempSync(join(tmpdir(), "rt-ui-"));
const env = { ...process.env }; delete env.DISPLAY; delete env.WAYLAND_DISPLAY;   // nothing may appear on a real desktop
const proc = spawn(chromium, ["--headless=new", "--disable-gpu", "--no-sandbox", `--user-data-dir=${profile}`, "--remote-debugging-port=0",
  "--window-size=1300,1000", "about:blank"], { env, stdio: ["ignore", "ignore", "pipe"] });

const wsUrl = await new Promise((resolve, reject) => {
  let buf = ""; const t = setTimeout(() => reject(new Error("browser did not start")), 90000);   // a shared build machine can be slow to start a browser
  proc.stderr.on("data", (d) => { buf += d; const m = buf.match(/DevTools listening on (ws:\/\/\S+)/); if (m) { clearTimeout(t); resolve(m[1]); } });
});
const port = new URL(wsUrl).port;
const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r));
let id = 0; const pending = new Map(); const consoleErrors = [];
ws.addEventListener("message", (e) => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  if (m.method === "Runtime.exceptionThrown") consoleErrors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
  if (m.method === "Runtime.consoleAPICalled" && m.params.type === "error") consoleErrors.push(m.params.args.map((a) => a.value || a.description).join(" "));
  if (m.method === "Log.entryAdded" && m.params.entry.level === "error" && !/favicon/.test(m.params.entry.url || "")) consoleErrors.push(m.params.entry.text);
});
const send = (method, params = {}) => new Promise((resolve) => { const i = ++id; pending.set(i, resolve); ws.send(JSON.stringify({ id: i, method, params })); });
const evaluate = async (expression) => {
  const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (r.result.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || "evaluation failed");
  return r.result.result.value;
};
await send("Runtime.enable"); await send("Page.enable"); await send("Log.enable");
const checks = []; const failures = [];
const check = (name, ok, detail = "") => { checks.push({ name, ok: !!ok, detail }); if (!ok) failures.push(`${name} ${detail}`); };
const waitFor = (cond, ms = 30000) => evaluate(`(async()=>{const end=Date.now()+${ms};while(Date.now()<end){try{if(${cond})return true}catch(e){}await new Promise(r=>setTimeout(r,100))}return false})()`);
const tab = async (label) => { await evaluate(`[...document.querySelectorAll('#tabs button')].find(b=>b.textContent==='${label}').click()`); await new Promise((r) => setTimeout(r, 300)); };
const shot = async (name) => { if (!shots) return; mkdirSync(shots, { recursive: true }); const r = await send("Page.captureScreenshot", { format: "png" }); writeFileSync(join(shots, `${name}.png`), Buffer.from(r.result.data, "base64")); };
const mouse = async (x, y, clicks = 1) => {           // a real mouse click through the browser, so pointer capture and double-click behave as for a person
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
  for (let n = 1; n <= clicks; n++) {
    await send("Input.dispatchMouseEvent", { type: "mousePressed", x, y, button: "left", clickCount: n });
    await send("Input.dispatchMouseEvent", { type: "mouseReleased", x, y, button: "left", clickCount: n });
  }
};
const centerOf = (selector, index = 0) => evaluate(`(() => { const r = document.querySelectorAll(${JSON.stringify(selector)})[${index}].getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
const click = (text) => evaluate(`[...document.querySelectorAll('button')].find(b=>b.textContent.includes(${JSON.stringify(text)})).click()`);

try {
  await send("Page.navigate", { url });
  await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });
  check("the page loads and lists the sample project", await waitFor("document.querySelector('#projectSelect').textContent.includes('Sample plant')"));
  await tab("Import");
  check("the import tab shows a getting-started checklist or the import form", await waitFor("document.querySelector('.dropzone') && document.querySelector('#tabs svg')"));
  check("every tab has an icon and a name", await evaluate("[...document.querySelectorAll('#tabs button')].every(b => b.querySelector('svg') && b.textContent.trim().length > 3)"));
  await shot("import");
  await tab("Inventory");
  check("inventory shows flow counts and coverage limits", await waitFor("document.body.textContent.includes('not evidence of absence')"));
  check("the subnet matrix keeps direction (rows initiate, columns respond)", await waitFor("document.querySelectorAll('#matrix tbody tr').length >= 3 && document.querySelector('#matrix thead').textContent.includes('initiator')"));
  check("no device role is shown", await evaluate("![...document.querySelectorAll('#view th')].some(th => /role|function|type/i.test(th.textContent))"));
  check("devices show MAC and card-maker columns", await evaluate("(() => { const th = [...document.querySelectorAll('#view th')].map(x => x.textContent); return th.includes('MAC') && th.includes('Card maker') && th.includes('Says it is'); })()"));
  check("a MAC is labelled with how sure we are", await evaluate("[...document.querySelectorAll('#view td .chip')].some(c => ['confirmed', 'probable', 'randomised?'].includes(c.textContent))"));
  await evaluate("[...document.querySelectorAll('#view tr.expandable')].find(r => r.querySelector('code')).click()");
  check("a device row opens to what it said about itself, or says nothing was said", await waitFor("document.querySelector('#view td.detail') && /self-reported|weak hint|Nothing identifying/.test(document.querySelector('#view td.detail').textContent)"));
  check("MACs shared by several addresses are listed apart", await evaluate("document.body.textContent.includes('MACs shared by several addresses') && /not attributed/i.test(document.body.textContent)"));
  await tab("Communications");
  check("explanations are short by default (closed expanders)", await waitFor("document.querySelectorAll('details.more:not([open])').length >= 0"));
  check("communications table has rows", await waitFor("document.querySelectorAll('#view tbody tr').length >= 10"));
  await evaluate("document.querySelector('#view tbody tr.expandable').click()");
  check("a row expands to its explanation and evidence", await waitFor("document.querySelector('#view td.detail') && /evidence/i.test(document.querySelector('#view td.detail').textContent)"));
  check("a row opens with a one-line statement first", await evaluate("document.querySelector('#view td.detail p').textContent.length < 260"));
  await shot("communications");
  await tab("Graph");
  check("the graph draws nodes and arrows", await waitFor("document.querySelectorAll('svg.graph circle').length >= 3 && document.querySelectorAll('svg.graph path.edge').length >= 3"));
  await shot("graph");
  check("the graph box can be resized by dragging its corner", await evaluate("getComputedStyle(document.querySelector('.graphbox')).resize === 'both'"));
  check("every subnet has a legend colour", await evaluate("document.querySelectorAll('.glegitem .gdot').length >= 2"));
  const viewBefore = await evaluate("document.querySelector('svg.graph').getAttribute('viewBox')");
  await click("+");
  check("zoom changes what the graph shows", await waitFor(`document.querySelector('svg.graph').getAttribute('viewBox') !== ${JSON.stringify(viewBefore)}`));
  await click("Fit");
  const at = await centerOf("svg.graph .nodeg circle", 0);
  await mouse(at.x, at.y);
  check("clicking a circle opens its details with a sample of the traffic", await waitFor("document.querySelector('.gdetail h3') && /Sample of the traffic/.test(document.querySelector('.gdetail').textContent) && /started/.test(document.querySelector('.gdetail').textContent)"));
  check("the details offer a way to see the communications", await evaluate("[...document.querySelectorAll('.gdetail button')].some(b => /communications|devices|Traffic it starts/.test(b.textContent))"));
  await shot("graph-detail");
  const dragFrom = await centerOf("svg.graph .nodeg circle", 1);
  const beforeT = await evaluate("document.querySelectorAll('svg.graph .nodeg')[1].getAttribute('transform')");
  await send("Input.dispatchMouseEvent", { type: "mousePressed", x: dragFrom.x, y: dragFrom.y, button: "left", clickCount: 1 });
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x: dragFrom.x + 60, y: dragFrom.y + 40, button: "left" });
  await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: dragFrom.x + 60, y: dragFrom.y + 40, button: "left", clickCount: 1 });
  check("a circle can be dragged to a new place", await evaluate(`document.querySelectorAll('svg.graph .nodeg')[1].getAttribute('transform') !== ${JSON.stringify(beforeT)}`));
  const arrow = await centerOf("svg.graph .edgehit", 0);
  await evaluate("document.querySelector('svg.graph .edgeg').dispatchEvent(new MouseEvent('click', { bubbles: true }))");
  check("clicking an arrow shows that direction's traffic", await waitFor("/started, .* answered|flows/.test(document.querySelector('.gdetail').textContent) && /Services/.test(document.querySelector('.gdetail').textContent)"));
  const real = await evaluate("[...document.querySelectorAll('svg.graph .nodeg')].findIndex(g => !g.getAttribute('aria-label').startsWith('('))");   // not the '(undefined)' group
  const sub = await centerOf("svg.graph .nodeg circle", real);
  await mouse(sub.x, sub.y, 2);
  check("double-clicking a subnet opens its devices, with a way back", await waitFor("[...document.querySelectorAll('#view button')].some(b => b.textContent === 'Back to subnets') && document.querySelectorAll('svg.graph .nodeg').length >= 2"));
  await shot("graph-devices");
  await click("Back to subnets");
  await waitFor("document.querySelectorAll('svg.graph .nodeg').length >= 3");
  await tab("Configuration");
  check("rules are listed with analysis findings", await waitFor("document.querySelectorAll('#view tbody tr').length >= 10 && document.body.textContent.includes('Rule analysis')"));
  await tab("Compare");
  check("compare says how many communications cross the device", await waitFor("document.body.textContent.includes('cross this device')"));
  check("compare shows outcomes and the not-a-finding note", await waitFor("document.body.textContent.includes('not a finding about the device') && document.querySelectorAll('.chip.deny').length >= 1"));
  await tab("Migrate");
  await click("Build directional policies");
  check("preserve plan shows its verdict and gaps", await waitFor("document.body.textContent.includes('Gaps: not translated')"));
  check("the preserve plan says a policy goes From to To and the reverse needs its own", await evaluate("document.body.textContent.includes('may initiate to') || document.body.textContent.includes('Not translated')"));
  await evaluate("document.querySelector('input[name=wf][value=narrow]').click()");
  await new Promise((r) => setTimeout(r, 600));
  await click("Build directional policies");
  check("narrow plan shows the observation period and the review requirement", await waitFor("document.body.textContent.includes('Observation window') && document.body.textContent.includes('scheduled jobs, failover')"));
  check("an egress policy is proposed for the isolated group", await evaluate("document.body.textContent.includes('Egress Controllers') && document.body.textContent.includes('updates.vendor.example')"));
  await shot("narrow-plan");
  await evaluate("document.querySelector('input[name=wf][value=preserve]').click()");
  await new Promise((r) => setTimeout(r, 600));
  await evaluate("(()=>{const t=document.querySelector('textarea.wide'); t.value='eng = port2\\nplc = port3\\nhist = port4\\ncorp = port5'})()");
  await evaluate("(()=>{const s=[...document.querySelectorAll('select')].find(x=>[...x.options].some(o=>o.value==='fortios')); s.value='fortios'; s.dispatchEvent(new Event('change'))})()");
  await click("Translate and validate");
  check("translation shows validation, limits and generated text", await waitFor("document.body.textContent.includes('Limits of this comparison') && document.querySelector('pre.code')"));
  check("the generated text is for review, with blocked rules left as comments", await evaluate("document.querySelector('pre.code').textContent.includes('REVIEW BEFORE USE')"));
  await shot("translation");
  await tab("Groups & labels");
  check("the context can be loaded from and saved to a JSON file", await evaluate("document.body.textContent.includes('Load from a JSON file') && document.body.textContent.includes('Download as JSON')"));
  check("groups editor shows the sample groups", await waitFor("document.body.textContent.includes('Isolated behind a gateway') && document.querySelectorAll('#view tbody tr').length >= 8"));
  // hostile text must never become markup
  await evaluate(`(async()=>{const p=document.getElementById('projectSelect').value; await fetch('/api/projects/'+p+'/context',{method:'PUT',headers:{'Authorization':'Bearer '+sessionStorage.getItem('rt-token'),'Content-Type':'application/json'},body:JSON.stringify({labels:{'10.20.1.15':'<img src=x onerror=window.__xss=1>'}})})})()`);
  await tab("Communications");
  await waitFor("document.body.textContent.includes('<img src=x')");
  check("a hostile device label is shown as text, not run", await evaluate("window.__xss === undefined && !document.querySelector('#view img') && document.body.textContent.includes('<img src=x')"));
  await tab("Export & AI");
  check("exports and the off-by-default AI notice are present", await waitFor("document.body.textContent.includes('Nothing is sent to any AI service by default')"));
  await evaluate("document.getElementById('verbose').click()");
  check("'Show explanations' opens every expander", await waitFor("document.querySelectorAll('details.more').length === document.querySelectorAll('details.more[open]').length"));
  await evaluate("document.getElementById('verbose').click()");
  await tab("Data & privacy");
  check("privacy tab states where data is kept and the network behaviour", await waitFor("document.body.textContent.includes('readable only by your user account') && document.body.textContent.includes('no outbound connections')"));
  await shot("privacy");
  check("vendor names are optional and downloaded only when asked", await evaluate("document.body.textContent.includes('Vendor names (optional)') && document.body.textContent.includes('Download from the IEEE') && document.body.textContent.includes('Not loaded')"));
  const lightBg = await evaluate("getComputedStyle(document.body).backgroundColor");
  await evaluate("document.getElementById('themeToggle').click()");      // system -> light
  await evaluate("document.getElementById('themeToggle').click()");      // light -> dark
  check("the theme switch forces the dark theme", await waitFor(`document.documentElement.getAttribute('data-theme') === 'dark' && getComputedStyle(document.body).backgroundColor !== ${JSON.stringify(lightBg)}`));
  await shot("privacy-dark");
  await evaluate("document.getElementById('themeToggle').click()");      // dark -> system
  check("the theme switch returns to following the system", await waitFor("!document.documentElement.hasAttribute('data-theme')"));
  check("with files loaded no tab is marked as not ready", await evaluate("document.querySelectorAll('#tabs button.locked').length === 0"));
  await evaluate("(async () => { const p = await api('/api/projects', { method: 'POST', json: { name: 'Empty project' } }); await loadProjects(p.id); state.tab = 'inventory'; render(); })()");
  check("a project with no files marks the tabs that need files", await waitFor("document.querySelectorAll('#tabs button.locked').length >= 6"));
  check("opening a tab that is not ready says what it needs and offers a button", await waitFor("/not ready yet/.test(document.querySelector('#view').textContent) && /Import traffic/.test(document.querySelector('#view').textContent) && [...document.querySelectorAll('#view button')].some(b => b.textContent === 'Go to Import')"));
  check("tabs that need nothing are never marked", await evaluate("[...document.querySelectorAll('#tabs button')].filter(b => /^(Import|Groups & labels|Data & privacy)$/.test(b.textContent.trim())).every(b => !b.classList.contains('locked'))"));
  check("a locked tab says why when hovered", await evaluate("[...document.querySelectorAll('#tabs button.locked')].every(b => /Needs:/.test(b.title))"));
  await shot("not-ready");
  await evaluate("(async () => { await loadProjects(); const first = state.projects.find(p => p.sources > 0); state.pid = first.id; state.tab = 'privacy'; render(); })()");
  check("the page makes no request to another origin", await evaluate("performance.getEntriesByType('resource').every(r => new URL(r.name).origin === location.origin)"));
  if (process.env.UNIFI_EXPORT) {      // the UniFi zone matrix, from a file chosen through the real file input
    await tab("Import");
    await waitFor("document.getElementById('fileInput')");
    const doc = (await send("DOM.getDocument", {})).result.root.nodeId;
    const field = (await send("DOM.querySelector", { nodeId: doc, selector: "#fileInput" })).result.nodeId;
    await send("DOM.setFileInputFiles", { files: [process.env.UNIFI_EXPORT], nodeId: field });
    check("a UniFi export is imported and listed", await waitFor("document.getElementById('toast').textContent.includes('as policy') && document.body.textContent.includes('unifi-export.json')"));
    await tab("Configuration");
    await evaluate("(() => { const s = document.querySelector('#view select'); const o = [...s.options].find(x => x.textContent.includes('unifi')); s.value = o.value; s.dispatchEvent(new Event('change')); })()");
    check("the zone matrix shows every zone pair as a button", await waitFor("document.querySelectorAll('.zm button').length >= 36"));
    check("cells say what the pair ends in", await evaluate("/Allow/.test(document.querySelector('.zm').textContent) && /Block/.test(document.querySelector('.zm').textContent)"));
    await evaluate("[...document.querySelectorAll('.zm button')].find(b => b.getAttribute('aria-label').startsWith('Internal to External')).click()");
    check("a cell lists its policies in order with the final default last", await waitFor("(() => { const rows = [...document.querySelectorAll('.zmdetail tbody tr')]; return rows.length >= 3 && rows[rows.length - 1].textContent.includes('final default'); })()"));
    check("the page never shows the word null", await evaluate("!document.querySelector('#view').textContent.includes('null')"));
    await shot("zone-matrix");
  }
  if (process.env.BIG_CAPTURE) {       // a capture over the background-import size, chosen through the real file input
    await tab("Import");
    await waitFor("document.getElementById('fileInput')");
    const root = (await send("DOM.getDocument", {})).result.root.nodeId;
    const input = (await send("DOM.querySelector", { nodeId: root, selector: "#fileInput" })).result.nodeId;
    await send("DOM.setFileInputFiles", { files: [process.env.BIG_CAPTURE], nodeId: input });
    check("a large capture is imported in the background and its source is listed", await waitFor("document.getElementById('toast').textContent.includes('as capture') && document.body.textContent.includes('big-test.pcap')", 120000));
  }
} catch (error) {
  failures.push(`script error: ${error.message}`);
} finally {
  check("no console errors", consoleErrors.length === 0, consoleErrors.join(" | "));
  let finalView = "";
  if (failures.length) { try { finalView = await evaluate("document.querySelector('#view').textContent.slice(0, 600)"); } catch (e) { finalView = String(e); } }
  console.log(JSON.stringify({ ok: failures.length === 0, failures, console_errors: consoleErrors, checks, final_view: finalView }, null, 1));
  ws.close(); proc.kill();
  process.exit(failures.length === 0 ? 0 : 1);
}
