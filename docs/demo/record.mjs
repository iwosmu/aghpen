// Records the Czujka demo video from the real product: Playwright drives the UI, Chromium's screencast captures
// every frame, ffmpeg cuts the shots, overlays the captions and writes the film.
//
//   cd docs/demo && npm install && node record.mjs          (docs/demo/record.sh does the whole thing, one command)
//
// Output (docs/demo): czujka-demo.mp4 (1920x1080, 30 fps, no audio), czujka-demo.pl.srt (captions), lektor.txt (voice-over per
// shot with its time code). Nothing is faked: every frame is the real UI against the stack at CZ_URL. A shot that compresses
// a long wait (the live scan) carries a visible "×8" mark for exactly the compressed part.
//
// Environment (all optional except the password):
//   CZ_URL            product URL (default http://127.0.0.1:18640)
//   CZ_EMAIL          login (default admin@czujka.local)
//   CZ_PASSWORD       password (required)
//   CZ_WIZARD_URL     a FRESH stack for the install-and-wizard shot (its first-run password in CZ_WIZARD_PASSWORD);
//                     without it shot 1 shows the login on CZ_URL
//   CZ_PROFILE        profile to start live in shot 2 (default "Laboratorium /16: pełny przegląd"); CZ_START_SCAN=0 shows the
//                     latest completed run of that profile instead (for a read-only account)
//   CZ_SCAN_SECONDS   real seconds of the live scan to record (default 96; shown at ×8, so 12 s in the film)
//   CZ_SCAN_WARM_CHUNKS  the film cuts in once this many address groups are done and a host is up (default 8; the
//                     discovery phase before it is cut out); CZ_SCAN_WARM_MAX caps that wait in seconds (default 900)
//   CZ_SCAN_FINISH    1 (default) waits off-camera for the live run to finish and ends the shot on its counts; 0 ends on
//                     the last finished run of the profile; CZ_SCAN_FINISH_MAX caps the wait in seconds (default 1800)
//   CZ_HOST           unstable host for shot 4 (default 10.66.70.20)
//   CZ_RULE           rule for shot 6 (default "Panel administracyjny poza siecią zarządzania")
//   CZ_SERVICE        service for the signature from an example, "ip:port" (default 10.66.1.10:80)
//   CZ_STOP           1 (default) records the emergency stop and releases it afterwards; 0 skips the shot
//   CZ_HEADED=1       show the browser while recording
//   CZ_ONLY           comma list of shot ids to record (testing), e.g. CZ_ONLY=time,rules
import { chromium } from "playwright";
import { mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const env = process.env;
const URL0 = (env.CZ_URL || "http://127.0.0.1:18640").replace(/\/$/, "");
const EMAIL = env.CZ_EMAIL || "admin@czujka.local";
const PASSWORD = env.CZ_PASSWORD;
if (!PASSWORD) { console.error("set CZ_PASSWORD"); process.exit(2); }
const PROFILE = env.CZ_PROFILE || "Laboratorium /16: pełny przegląd";
const SCAN_WARM_CHUNKS = Number(env.CZ_SCAN_WARM_CHUNKS || 8);
const SCAN_WARM_MAX = Number(env.CZ_SCAN_WARM_MAX || 900);
const SCAN_FINISH = env.CZ_SCAN_FINISH !== "0";
const SCAN_FINISH_MAX = Number(env.CZ_SCAN_FINISH_MAX || 1800);
const START_SCAN = env.CZ_START_SCAN !== "0";
const SCAN_SECONDS = Number(env.CZ_SCAN_SECONDS || 96);
const HOST = env.CZ_HOST || "10.66.70.20";
const RULE = env.CZ_RULE || "Panel administracyjny poza siecią zarządzania";
const SERVICE = env.CZ_SERVICE || "10.66.1.10:80";
const STOP = env.CZ_STOP !== "0";
const FAST = 8;
const ONLY = env.CZ_ONLY ? env.CZ_ONLY.split(",") : null; // for testing: record only these shots
const want = (id) => !ONLY || ONLY.includes(id);

const WORK = join(here, "out", "work");
rmSync(WORK, { recursive: true, force: true });
mkdirSync(join(WORK, "frames"), { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => Date.now() / 1000;

// ---------- shots: caption (at most 6 words, burned in) and voice-over (lektor.txt) ----------
const SHOTS = [
  { id: "install", caption: "Jedno polecenie, potem kreator",
    vo: "Czujka staje jednym poleceniem. Kreator prowadzi od pierwszego logowania do skanu: hasło, zakresy i limity od właściciela sieci." },
  { id: "scan", caption: "Skan całej sieci /16",
    vo: "Skan całej sieci /16. Mapa pokazuje każdy blok dwustu pięćdziesięciu sześciu adresów. Tempo nigdy nie przekracza limitu z polityki." },
  { id: "changes", caption: "Co się zmieniło między skanami",
    vo: "Drugi skan porównuje się z pierwszym: nowe hosty, zniknięte usługi, zmienione wersje i tytuły." },
  { id: "unstable", caption: "Rytm hosta i ponowne sprawdzenia",
    vo: "Ten host odpowiada nieregularnie. Czujka zna jego rytm tygodnia, więc cisza w zwykłej porze nie jest alarmem. Gdy milknie poza rytmem, sprawdza ponownie tylko ten adres." },
  { id: "time", caption: "Oś czasu",
    vo: "Oś czasu pokazuje sieć taką, jaka była po dowolnym skanie, i to, co od tamtej pory zniknęło albo się zmieniło." },
  { id: "rules", caption: "Reguła i sygnatura z przykładu",
    vo: "Reguła mówi, czego w sieci być nie może, i sprawdza się po każdym skanie bez pakietów. Z jednej usługi Czujka proponuje sygnaturę i testuje ją na historii." },
  { id: "stop", caption: "Stop awaryjny",
    vo: "Stop awaryjny zatrzymuje wszystkie skany w ułamku sekundy." },
  { id: "end", caption: "",
    vo: "Czujka. Działa na czujka.dev." },
];
const marks = {}; // id -> {start, end, fast: [[t0, t1]]}
let cur = null;
function begin(id) { cur = { start: now(), end: 0, fast: [], skip: [] }; marks[id] = cur; }
function end() { cur.end = now(); cur = null; }
function fastOn() { cur.fast.push([now(), 0]); }
function fastOff() { cur.fast[cur.fast.length - 1][1] = now(); }
// A cut inside a shot: the frames between skipOn and skipOff are left out of the film (a hard cut, no ×8 mark).
function skipOn() { cur.skip.push([now(), 0]); }
function skipOff() { cur.skip[cur.skip.length - 1][1] = now(); }
// Waits until check(run) is true or the timeout passes; returns the last run state.
async function waitRun(id, check, timeoutS) {
  const t0 = now();
  let st = null;
  while (now() - t0 < timeoutS) {
    st = await api("/runs/" + id);
    if (st && (check(st) || ["completed", "failed", "cancelled"].includes(st.status))) break;
    await sleep(3000);
  }
  return st;
}

// ---------- browser ----------
const browser = await chromium.launch({ headless: env.CZ_HEADED !== "1" });
const ctx = await browser.newContext({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1, locale: "pl-PL", timezoneId: "Europe/Warsaw", colorScheme: "dark" });
await ctx.addInitScript(() => {
  try { localStorage.setItem("czujka.lang", "pl"); } catch {}
  // A visible cursor: an overlay that follows the real mouse events, with a ring on every click.
  const install = () => {
    if (document.getElementById("__cz_cursor")) return;
    const c = document.createElement("div");
    c.id = "__cz_cursor";
    c.innerHTML = '<svg width="30" height="30" viewBox="0 0 30 30"><path d="M4 2 L4 24 L9.8 18.6 L14 27.6 L17.8 26 L13.6 17 L21.6 17 Z" fill="#ffffff" stroke="#0e131b" stroke-width="1.6" stroke-linejoin="round"/></svg>';
    const z = parseFloat(getComputedStyle(document.documentElement).zoom || "1") || 1;
    Object.assign(c.style, { position: "fixed", left: "0", top: "0", width: "30px", height: "30px", zIndex: "2147483647", pointerEvents: "none", zoom: String(1 / z) });
    const p = JSON.parse(sessionStorage.getItem("__cz_pos") || "[-100,-100]");
    c.style.transform = "translate(" + p[0] + "px," + p[1] + "px)";
    document.documentElement.appendChild(c);
  };
  const pos = (e) => {
    const c = document.getElementById("__cz_cursor"); if (!c) return;
    const z = parseFloat(getComputedStyle(document.documentElement).zoom || "1") || 1;
    c.style.zoom = String(1 / z);
    // clientX is in screen pixels; the cursor is counter-zoomed so the page zoom does not scale its position or size.
    const x = e.clientX, y = e.clientY;
    c.style.transform = "translate(" + x + "px," + y + "px)";
    sessionStorage.setItem("__cz_pos", JSON.stringify([x, y]));
  };
  document.addEventListener("mousemove", pos, true);
  document.addEventListener("mousedown", (e) => {
    pos(e);
    const z = parseFloat(getComputedStyle(document.documentElement).zoom || "1") || 1;
    const r = document.createElement("div");
    Object.assign(r.style, { position: "fixed", left: (e.clientX - 18) + "px", top: (e.clientY - 18) + "px", width: "36px", height: "36px", borderRadius: "50%", border: "3px solid #6ea3f2", zIndex: "2147483646", pointerEvents: "none", zoom: String(1 / z), transition: "transform 450ms ease-out, opacity 450ms ease-out" });
    document.documentElement.appendChild(r);
    requestAnimationFrame(() => { r.style.transform = "scale(1.8)"; r.style.opacity = "0"; });
    setTimeout(() => r.remove(), 600);
  }, true);
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", install); else install();
  new MutationObserver(install).observe(document, { childList: true, subtree: true });
});
const page = await ctx.newPage();

// Frames: Chromium's screencast sends a frame each time the screen changes, with its time stamp.
const frames = [];
const cdp = await ctx.newCDPSession(page);
let fn = 0;
cdp.on("Page.screencastFrame", async ({ data, metadata, sessionId }) => {
  const file = join(WORK, "frames", "f" + String(fn++).padStart(6, "0") + ".jpg");
  writeFileSync(file, Buffer.from(data, "base64"));
  frames.push({ ts: metadata.timestamp, file });
  try { await cdp.send("Page.screencastFrameAck", { sessionId }); } catch {}
});
await cdp.send("Page.startScreencast", { format: "jpeg", quality: 92, maxWidth: 1920, maxHeight: 1080, everyNthFrame: 1 });

// ---------- human input ----------
let mx = 960, my = 600;
async function moveTo(x, y, ms = 650) {
  const n = Math.max(10, Math.round(ms / 16)), x0 = mx, y0 = my;
  for (let i = 1; i <= n; i++) {
    const t = i / n, e = t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
    await page.mouse.move(x0 + (x - x0) * e, y0 + (y - y0) * e);
    await sleep(16);
  }
  mx = x; my = y;
}
async function point(loc, ms) {
  await loc.scrollIntoViewIfNeeded();
  const b = await loc.boundingBox();
  await moveTo(b.x + b.width / 2, b.y + b.height / 2, ms);
}
async function click(loc, ms) { await point(loc, ms); await sleep(220); await page.mouse.down(); await sleep(90); await page.mouse.up(); }
async function type(loc, text, delay = 70) { await click(loc); await sleep(150); await page.keyboard.type(text, { delay }); }
async function smoothScroll(dy, ms = 900) {
  const n = Math.max(10, Math.round(ms / 16));
  let done = 0;
  for (let i = 1; i <= n; i++) {
    const t = i / n, e = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
    const step = Math.round(dy * e) - done; done += step;
    await page.mouse.wheel(0, step);
    await sleep(16);
  }
}
async function scrollIntoMiddle(loc, ms = 900) {
  const b = await loc.boundingBox();
  if (!b) return;
  const target = 1080 * 0.38;
  await smoothScroll(Math.round(b.y - target), ms);
  await sleep(300);
}
async function api(path, method = "GET", body) {
  return page.evaluate(async ([path, method, body]) => {
    let csrf = "";
    if (method !== "GET") { const me = await (await fetch("/api/v1/me", { credentials: "same-origin" })).json().catch(() => ({})); csrf = me.csrf_token || ""; }
    const r = await fetch("/api/v1" + path, { method, credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: body ? JSON.stringify(body) : undefined });
    const t = await r.text();
    try { return JSON.parse(t); } catch { return t; }
  }, [path, method, body]);
}
async function login(url, email, password, visible) {
  await page.goto(url + "/login");
  const e = page.getByLabel(/e-mail|email/i).first();
  const p = page.getByLabel(/^Hasło$/).first();
  await e.waitFor();
  if (visible) { await type(e, email, 35); await type(p, password, 30); await sleep(400); await click(page.getByRole("button", { name: "Zaloguj się" })); }
  else { await e.fill(email); await p.fill(password); await page.getByRole("button", { name: "Zaloguj się" }).click(); }
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
}
async function present(path) { await page.goto(URL0 + path + (path.includes("?") ? "&" : "?") + "present=1"); await page.waitForLoadState("networkidle").catch(() => {}); await sleep(600); }
const settle = (ms = 1200) => sleep(ms);

// ---------- 1. install and wizard ----------
if (!want("install")) {} else if (env.CZ_WIZARD_URL) {
  const W = env.CZ_WIZARD_URL.replace(/\/$/, "");
  await page.goto(W + "/login?present=1");
  await page.getByLabel(/^Hasło$/).first().waitFor();
  begin("install");
  await settle(900);
  await login(W, EMAIL, env.CZ_WIZARD_PASSWORD, true);
  await page.goto(W + "/setup?present=1"); await settle(1200);
  const pw1 = page.getByTestId("setup-pw");
  await pw1.waitFor({ timeout: 15000 }).catch(() => {});
  if (await pw1.isVisible().catch(() => false)) {
    await type(pw1, "Kampus-AGH-2026!", 30);
    await type(page.getByTestId("setup-pw2"), "Kampus-AGH-2026!", 30);
    await click(page.getByRole("button", { name: "Zapisz hasło i dalej" }));
    await settle(900);
  }
  await type(page.getByTestId("setup-net-name"), "Kampus AGH", 70);
  await type(page.getByTestId("setup-ranges"), "10.66.0.0/16", 70);
  await settle(1500);
  await click(page.getByRole("button", { name: "Zapisz zakres i dalej" }));
  await settle(1800);
  end();
} else {
  await page.goto(URL0 + "/login");
  await page.getByLabel(/^Hasło$/).first().waitFor();
  begin("install");
  await settle(800);
  await login(URL0, EMAIL, PASSWORD, true);
  await present("/"); await settle(2500);
  end();
}

// ---------- the main stack ----------
await login(URL0, EMAIL, PASSWORD, false);

const profiles = (await api("/profiles?limit=100")).items || [];
const prof = profiles.find((p) => p.name === PROFILE);
if (!prof) throw new Error("no profile named " + PROFILE);
const done = ((await api("/runs?limit=50&status=completed&profile_id=" + prof.id)).items || []).filter((r) => !r.ad_hoc);

// ---------- 2. live /16 scan ----------
let liveRun = null, liveDone = false, stopExtra = null;
const TIME_STEPS_BACK = Number(env.CZ_TIME_STEPS || 4);
if (!want("scan")) {} else if (START_SCAN) {
  await present("/runs");
  begin("scan");
  await settle(600);
  await click(page.getByRole("button", { name: "Uruchom skan" }).first());
  await settle(700);
  const sel = page.getByRole("dialog").locator("select").first();
  await point(sel); await sel.selectOption({ label: PROFILE }); await settle(1200);
  await click(page.getByRole("dialog").getByRole("button", { name: "Uruchom", exact: true }));
  await page.waitForURL(/\/runs\/\d+/);
  liveRun = Number(page.url().match(/\/runs\/(\d+)/)[1]);
  await settle(1800);
  // Discovery (one ARP sweep on-link, then the host sweep) shows 0 % and no hosts for minutes: cut it out and come back
  // when the first address groups have finished and hosts are on the map.
  skipOn();
  await waitRun(liveRun, (st) => (st.stats?.chunks_done || 0) >= SCAN_WARM_CHUNKS && (st.stats?.hosts_up || 0) > 0, SCAN_WARM_MAX);
  // The run page has tabs; the address-space map is in tab "Mapa" (a running run opens on "Przebieg").
  await present("/runs/" + liveRun + "?tab=map"); await settle(1500);
  skipOff();
  const map = page.getByText("Mapa przestrzeni adresowej").first();
  await point(map, 900);
  await settle(1200);
  fastOn();
  const t0 = now();
  while (now() - t0 < SCAN_SECONDS) {
    await moveTo(mx + (Math.random() - 0.5) * 40, my + (Math.random() - 0.5) * 30, 2000);
    const st = await api("/runs/" + liveRun);
    if (st && ["completed", "failed", "cancelled"].includes(st.status)) break;
  }
  fastOff();
  // End on a finished run with its counts: wait (cut) for this run to finish, else show the last finished run.
  skipOn();
  const fin = SCAN_FINISH ? await waitRun(liveRun, () => false, SCAN_FINISH_MAX) : null;
  // End on the counts: tab "Przebieg" holds the stats (a finished run opens on "Usługi").
  if (fin && fin.status === "completed") { await present("/runs/" + liveRun + "?tab=progress"); liveDone = true; }
  else if (done[0]) await present("/runs/" + done[0].id + "?tab=progress");
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.evaluate(() => window.scrollTo(0, 0)); await settle(1200);
  skipOff();
  await settle(3500);
  end();
} else {
  const last = done[0];
  await present("/runs/" + last.id + "?tab=map");
  begin("scan"); await settle(6000); end();
}

// ---------- 3. changes between the two last completed scans ----------
if (want("changes")) {
  const [to, from] = done;
  await present(to && from ? "/changes/compare?from=" + from.id + "&to=" + to.id : "/changes");
  begin("changes");
  await settle(2500);
  const gone = page.getByText(/Zniknęły|Nowe|Zmienione/).first();
  if (await gone.count()) await point(gone, 900);
  await settle(1500);
  await smoothScroll(380, 1400);
  await settle(3500);
  end();
}

// ---------- 4. unstable host: rhythm and re-probe plan ----------
if (want("unstable")) {
  const hosts = await api("/hosts?q=" + encodeURIComponent(HOST) + "&limit=5");
  const h = (hosts.items || []).find((x) => x.ip === HOST) || (hosts.items || [])[0];
  // The heatmap and the re-probe plan are in the host page tab "Dostępność".
  await present("/hosts/" + h.id + "?tab=availability");
  begin("unstable");
  await settle(2200);
  const heat = page.getByText("Dostępność w tygodniu").first();
  await scrollIntoMiddle(heat, 1100);
  await point(heat, 900);
  const cells = page.locator("rect, [data-hour]").first();
  await settle(3500);
  const plan = page.getByText("Plan ponownych sprawdzeń").first();
  if (await plan.count()) { await scrollIntoMiddle(plan, 1100); await point(plan, 900); }
  await settle(4500);
  end();
}

// ---------- 5. time machine ----------
if (want("time")) {
  // Pick where to scrub from the data: the step between two analysed runs where the counts change most, then start
  // a few runs before it so the scrub crosses it (no fixed run id).
  // Every analysed run, as on the scrubber (the arrow keys step through the same list).
  const pts = (await api("/timeline")).runs || [];
  const score = (a, b) => Math.abs(a.hosts_up - b.hosts_up) * 3 + Math.abs(a.services_open - b.services_open) * 2 + Math.abs(a.hosts_missing - b.hosts_missing) + Math.abs(a.hosts_down - b.hosts_down) + Math.abs(a.findings_open - b.findings_open);
  let best = -1, bi = 0;
  for (let i = 1; i < pts.length; i++) { const s = score(pts[i - 1], pts[i]); if (s >= best) { best = s; bi = i; } }
  const startIdx = Math.min(pts.length - 1, bi + TIME_STEPS_BACK - 1);
  const after = pts.length ? pts[startIdx] : null;
  console.log("time machine: biggest change between runs", pts[bi - 1]?.run_id, "and", pts[bi]?.run_id, "(score " + best + ")");
  await present(after ? "/time?run=" + after.run_id : "/time");
  begin("time");
  await settle(2200);
  // Point at the scrubber (the step hint text was removed from the UI); the arrow keys below step through the runs.
  const strip = page.getByTestId("tm-scrubber").first();
  if (await strip.count()) { await point(strip, 900); await strip.focus().catch(() => {}); }
  await settle(800);
  // Step back across the change, then forward over it again, slow enough to read the numbers and the map.
  for (let i = 0; i < TIME_STEPS_BACK; i++) { await page.keyboard.press("ArrowLeft"); await settle(1500); }
  await settle(800);
  for (let i = 0; i < 2; i++) { await page.keyboard.press("ArrowRight"); await settle(1700); }
  await settle(2500);
  end();
}

// ---------- 6. exposure rule and a signature from an example ----------
if (want("rules")) {
  await present("/rules");
  begin("rules");
  await settle(1500);
  await click(page.getByTestId("rule-list").getByText(RULE).first(), 900);
  await settle(1500);
  const dry = page.getByTestId("rule-dryrun");
  if (await dry.count()) await point(dry, 900);
  await settle(2200);
  const [ip, port] = SERVICE.split(":");
  const svcs = await api("/services?q=" + encodeURIComponent(ip) + "&limit=50");
  const s = (svcs.items || []).find((x) => (x.ip === ip || x.host_ip === ip) && String(x.port) === port) || (svcs.items || [])[0];
  await present("/services/" + s.id);
  await settle(1200);
  await click(page.getByRole("button", { name: "Zaproponuj sygnaturę" }), 900);
  await page.getByTestId("suggest-result").waitFor({ timeout: 30000 }).catch(() => {});
  await settle(1200);
  const res = page.getByTestId("suggest-result");
  if (await res.count()) await point(res.locator("svg, p, div").first(), 900);
  await settle(3800);
  end();
}

// ---------- 7. emergency stop ----------
if (STOP && want("stop")) {
  // The stop needs a running scan to show its effect: reuse the live run, or start the profile (cancelled afterwards).
  let stopRun = liveRun && !liveDone ? liveRun : null;
  if (!stopRun) {
    const r = await api("/runs", "POST", { profile_id: prof.id });
    stopRun = (r && r.id) || (r && r.details && r.details.run_id) || null;
    if (stopRun && !liveRun) liveRun = stopRun;
    if (stopRun && stopRun !== liveRun) stopExtra = stopRun;
    if (stopRun) await waitRun(stopRun, (st) => st.status === "running" && (st.stats?.packets_sent || st.stats?.addresses_done || 0) > 0, 120);
  }
  if (stopRun) await present("/runs/" + stopRun); else await present("/");
  begin("stop");
  await settle(1500);
  await click(page.getByTestId("emergency-stop"), 900);
  await settle(900);
  const confirm = page.getByRole("dialog").getByRole("button", { name: /Stop awaryjny|Zatrzymaj|Potwierdź/ }).last();
  await click(confirm, 700);
  // The state after the stop: the run paused by the emergency stop, the top strip in its stopped state, 0 pps.
  await settle(2500);
  const state = page.getByText(/wstrzymany|zatrzyman/i).first();
  if (await state.count()) await point(state, 900);
  await settle(1500);
  await moveTo(1500, 60, 900);
  await settle(2500);
  end();
}

// ---------- end card ----------
if (want("end")) {
  const logo = readFileSync(resolve(here, "../../web/public/favicon.svg"), "utf8");
  const fd = (pkg) => resolve(here, "node_modules/@fontsource", pkg, "files");
  const fc = (fam, pkg, w) => ["latin", "latin-ext"].map((s) => "@font-face{font-family:'" + fam + "';font-weight:" + w + ";src:url(data:font/woff2;base64," + readFileSync(join(fd(pkg), pkg + "-" + s + "-" + w + "-normal.woff2")).toString("base64") + ") format('woff2');}").join("");
  const ENDFONTS = "<style>" + fc("IBM Plex Sans", "ibm-plex-sans", 600) + fc("IBM Plex Mono", "ibm-plex-mono", 500) + "</style>";
  await page.setContent('<html><head>' + ENDFONTS + '</head><body style="margin:0;background:#0e131b;color:#e9e5da;font-family:IBM Plex Sans,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;gap:28px"><div style="display:flex;align-items:center;gap:32px"><div style="width:120px;height:120px">' + logo.replace(/width="[^"]*"|height="[^"]*"/g, "").replace("<svg", '<svg width="120" height="120"') + '</div><div style="font-size:120px;font-weight:600;letter-spacing:-0.03em">Czujka</div></div><div style="font-family:IBM Plex Mono,monospace;font-size:56px;color:#6ea3f2">czujka.dev</div></body></html>');
  await page.evaluate(() => { const c = document.getElementById("__cz_cursor"); if (c) c.remove(); return document.fonts.ready; });
  await page.addStyleTag({ content: "#__cz_cursor{display:none!important}" });
  begin("end"); await settle(5000); end();
}

// ---------- clean up what the recording changed (the emergency stop is released, the live scan cancelled) ----------
if (marks.stop) {
  await api("/emergency-stop/release", "POST");
  // Runs that the stop paused (scheduled ones too) would block their profile's schedule: resume them, cancel our own live scan.
  const paused = ((await api("/runs?status=paused&limit=100")).items || []).filter((r) => r.pause_reason === "emergency_stop");
  for (const r of paused) await api("/runs/" + r.id + (r.id === liveRun ? "/cancel" : "/resume"), "POST");
}
if (liveRun && !liveDone) await api("/runs/" + liveRun + "/cancel", "POST");
if (stopExtra) await api("/runs/" + stopExtra + "/cancel", "POST");
await cdp.send("Page.stopScreencast");
await sleep(300);

// ---------- captions as images (this ffmpeg has no text filters) ----------
const cp = await ctx.newPage();
const fontDir = (pkg) => resolve(here, "node_modules/@fontsource", pkg, "files");
const face = (fam, pkg, w) => ["latin", "latin-ext"].map((s) => "@font-face{font-family:'" + fam + "';font-weight:" + w + ";src:url(data:font/woff2;base64," + readFileSync(join(fontDir(pkg), pkg + "-" + s + "-" + w + "-normal.woff2")).toString("base64") + ") format('woff2');}").join("");
const FONTS = "<style>" + face("IBM Plex Sans", "ibm-plex-sans", 500) + face("IBM Plex Sans", "ibm-plex-sans", 600) + face("IBM Plex Mono", "ibm-plex-mono", 500) + "</style>";
async function png(html, file, w, h) {
  await cp.setViewportSize({ width: w, height: h });
  await cp.setContent('<html><head>' + FONTS + '</head><body style="margin:0;background:transparent">' + html + "</body></html>");
  await cp.evaluate(() => document.fonts.ready);
  await cp.screenshot({ path: file, omitBackground: true });
}
for (const s of SHOTS) {
  if (!s.caption) continue;
  await png('<div style="height:120px;display:flex;align-items:center;justify-content:center"><span style="font-family:IBM Plex Sans,sans-serif;font-size:40px;font-weight:500;color:#fff;background:rgba(10,14,21,0.86);padding:12px 32px;border-radius:2px">' + s.caption + "</span></div>", join(WORK, "cap-" + s.id + ".png"), 1920, 120);
}
await png('<div style="width:200px;height:96px;display:flex;align-items:center;justify-content:center"><span style="font-family:IBM Plex Mono,monospace;font-size:48px;font-weight:500;color:#0e131b;background:#c98500;padding:6px 22px;border-radius:2px">×' + FAST + "</span></div>", join(WORK, "fast.png"), 200, 96);
await browser.close();

// ---------- cut ----------
const ff = (args) => execFileSync("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", ...args], { stdio: "inherit" });
const clips = [];
let tl = 0;
const srt = [], lektor = [];
const fmt = (t) => { const ms = Math.round(t * 1000), h = Math.floor(ms / 3600000), m = Math.floor(ms / 60000) % 60, s = Math.floor(ms / 1000) % 60; return String(h).padStart(2, "0") + ":" + String(m).padStart(2, "0") + ":" + String(s).padStart(2, "0") + "," + String(ms % 1000).padStart(3, "0"); };
const mmss = (t) => Math.floor(t / 60) + ":" + String(Math.round(t % 60)).padStart(2, "0");
for (const s of SHOTS) {
  const m = marks[s.id];
  if (!m) continue;
  // Frames inside the shot, plus the last frame before it (the screen as it was at the start).
  const before = frames.filter((f) => f.ts <= m.start).pop();
  const inside = frames.filter((f) => f.ts > m.start && f.ts < m.end);
  const seq = (before ? [{ ...before, ts: m.start }] : []).concat(inside);
  if (!seq.length) continue;
  const speed = (t) => (m.skip.some(([a, b]) => t >= a && t < b) ? Infinity : m.fast.some(([a, b]) => t >= a && t < b) ? FAST : 1);
  let list = "", out = 0, fastFrom = -1, fastTo = -1;
  for (let i = 0; i < seq.length; i++) {
    const t = seq[i].ts, next = i + 1 < seq.length ? seq[i + 1].ts : m.end;
    // Split a frame's hold at the edges of a fast segment so each part gets its own speed.
    const cuts = [t, ...m.fast.flat().concat(m.skip.flat()).filter((x) => x > t && x < next), next];
    for (let k = 0; k + 1 < cuts.length; k++) {
      const sp = speed(cuts[k]);
      const d = (cuts[k + 1] - cuts[k]) / sp;
      if (d <= 0) continue;
      if (sp > 1) { if (fastFrom < 0) fastFrom = out; fastTo = out + d; }
      list += "file '" + seq[i].file + "'\nduration " + d.toFixed(4) + "\n";
      out += d;
    }
  }
  list += "file '" + seq[seq.length - 1].file + "'\n";
  const lf = join(WORK, "list-" + s.id + ".txt");
  writeFileSync(lf, list);
  const clip = join(WORK, "clip-" + s.id + ".mp4");
  const inputs = ["-f", "concat", "-safe", "0", "-i", lf];
  let filter = "[0:v]fps=30,scale=1920:1080:flags=lanczos,format=yuv420p[v0]";
  let last = "v0";
  if (s.caption) { inputs.push("-loop", "1", "-i", join(WORK, "cap-" + s.id + ".png")); filter += ";[" + last + "][1:v]overlay=0:H-h-20:shortest=1[v1]"; last = "v1"; }
  if (fastFrom >= 0) { inputs.push("-loop", "1", "-i", join(WORK, "fast.png")); const idx = s.caption ? 2 : 1; filter += ";[" + last + "][" + idx + ":v]overlay=W-w-40:H-h-32:shortest=1:enable='between(t," + fastFrom.toFixed(2) + "," + fastTo.toFixed(2) + ")'[v2]"; last = "v2"; }
  ff([...inputs, "-filter_complex", filter, "-map", "[" + last + "]", "-t", out.toFixed(3), "-r", "30", "-c:v", "libx264", "-preset", "medium", "-crf", "18", "-pix_fmt", "yuv420p", clip]);
  clips.push(clip);
  if (s.caption) srt.push(srt.length + 1 + "\n" + fmt(tl) + " --> " + fmt(tl + out) + "\n" + s.caption + "\n");
  const words = s.vo.split(/\s+/).filter(Boolean).length;
  lektor.push("[" + mmss(tl) + "–" + mmss(tl + out) + "] " + s.id + " (" + out.toFixed(1) + " s; " + words + " słów ≈ " + (words / 2.3).toFixed(1) + " s przy 2,3 słowa/s)\n" + s.vo + "\n");
  console.log(s.id.padEnd(9), out.toFixed(1).padStart(5) + " s", fastFrom >= 0 ? "(×" + FAST + " from " + fastFrom.toFixed(1) + " s to " + fastTo.toFixed(1) + " s)" : "");
  tl += out;
}
writeFileSync(join(WORK, "clips.txt"), clips.map((c) => "file '" + c + "'").join("\n") + "\n");
const mp4 = resolve(here, "czujka-demo.mp4");
ff(["-f", "concat", "-safe", "0", "-i", join(WORK, "clips.txt"), "-c", "copy", "-movflags", "+faststart", mp4]);
writeFileSync(resolve(here, "czujka-demo.pl.srt"), srt.join("\n"));
const totalWords = SHOTS.reduce((n, s) => n + (marks[s.id] ? s.vo.split(/\s+/).filter(Boolean).length : 0), 0);
writeFileSync(resolve(here, "lektor.txt"), "Lektor do filmu czujka-demo.mp4 (czas filmu " + mmss(tl) + ", " + totalWords + " słów ≈ " + (totalWords / 2.3).toFixed(0) + " s przy 2,3 słowa/s).\nNagraj głos na film; kody czasu to początek i koniec ujęcia. Wygenerowane przez record.mjs.\n\n" + lektor.join("\n"));
console.log("film", mmss(tl), "(" + tl.toFixed(1) + " s),", frames.length, "frames ->", mp4);
