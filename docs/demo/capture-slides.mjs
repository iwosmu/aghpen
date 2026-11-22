// Takes the deck's product screenshots from a running stack, sharp (device scale 2), in presentation mode, Polish, dark.
//   cd docs/demo && CZ_URL=https://... CZ_EMAIL=... CZ_PASS=... node capture-slides.mjs
// Credentials come from the environment only; nothing prints or stores them. The account block is blurred.
// Writes into docs/slides/img (CZ_SLIDES_OUT changes it), one file per slide:
//   scale-run.png       slide 3: the address map of a full run (CZ_SCALE_RUN, default: the latest completed run with a map)
//   service-detail.png  slide 4: a service and the reasons for its interest (CZ_SERVICE "ip:port", default 10.66.1.10:80)
//   reprobe-host.png    slide 5: an unstable host's week rhythm and re-probe plan (CZ_HOST, default 10.66.70.20)
//   time-machine.png    slide 6: the time machine at a run (CZ_TIME_RUN, default the latest), 960 px wide so the panels stack
//   rule-dry-run.png    slide 7: an exposure rule and its current violations (CZ_RULE, default the starter admin-panel rule)
// CZ_ONLY=scale,time takes only some of them. Read-only: GET requests and the sign-in only.
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const here = dirname(fileURLToPath(import.meta.url));
const env = process.env;
const URL0 = (env.CZ_URL || "http://127.0.0.1:18640").replace(/\/$/, "");
const EMAIL = env.CZ_EMAIL || "admin@czujka.local";
const PASSWORD = env.CZ_PASS || env.CZ_PASSWORD;
if (!PASSWORD) { console.error("set CZ_PASS"); process.exit(2); }
const SERVICE = env.CZ_SERVICE || "10.66.1.10:80";
const HOST = env.CZ_HOST || "10.66.70.20";
const RULE = env.CZ_RULE || "Panel administracyjny poza siecią zarządzania";
const ONLY = env.CZ_ONLY ? env.CZ_ONLY.split(",") : null;
const want = (id) => !ONLY || ONLY.includes(id);
const out = resolve(env.CZ_SLIDES_OUT || resolve(here, "../slides/img"));
mkdirSync(out, { recursive: true });

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, locale: "pl-PL", timezoneId: "Europe/Warsaw", colorScheme: "dark" });
await ctx.addInitScript(() => {
  localStorage.setItem("czujka.lang", "pl");
  const st = document.createElement("style"); st.textContent = "[data-testid=whoami]{filter:blur(9px)!important}";
  (document.head || document.documentElement).appendChild(st);
});
const page = await ctx.newPage();
await page.goto(URL0 + "/login");
await page.getByLabel(/e-mail|email/i).first().fill(EMAIL);
await page.getByLabel(/^Hasło$/).first().fill(PASSWORD);
await page.getByRole("button", { name: "Zaloguj się" }).click();
await page.waitForURL((u) => !u.pathname.startsWith("/login"));
const api = (path) => page.evaluate(async (p) => (await fetch("/api/v1" + p, { credentials: "same-origin" })).json(), path);
async function shot(path, file, width = 1440, height = 900) {
  await page.setViewportSize({ width, height });
  await page.goto(URL0 + path + (path.includes("?") ? "&" : "?") + "present=1");
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(2500);
  await page.screenshot({ path: resolve(out, file) });
  console.log("wrote", file, "from", path);
}

if (want("scale")) {
  let run = env.CZ_SCALE_RUN;
  if (!run) { const runs = (await api("/runs?limit=50&status=completed")).items || []; const scans = runs.filter((r) => r.profile_id && !r.ad_hoc); const big = scans.find((r) => (r.stats?.addresses_total || 0) > 256) || scans[0]; run = big && big.id; }
  if (run) await shot("/runs/" + run + "?tab=map", "scale-run.png"); else console.log("skip scale-run.png: no completed run");
}
if (want("service")) {
  const [ip, port] = SERVICE.split(":");
  const s = ((await api("/services?q=" + encodeURIComponent(ip) + "&limit=100")).items || []).find((x) => (x.ip === ip || x.host_ip === ip) && String(x.port) === port);
  if (s) await shot("/services/" + s.id, "service-detail.png"); else console.log("skip service-detail.png: no service " + SERVICE);
}
if (want("reprobe")) {
  const h = ((await api("/hosts?q=" + encodeURIComponent(HOST) + "&limit=10")).items || []).find((x) => x.ip === HOST);
  if (h) await shot("/hosts/" + h.id + "?tab=availability", "reprobe-host.png", 1440, 1300); else console.log("skip reprobe-host.png: no host " + HOST);
}
if (want("time")) await shot("/time" + (env.CZ_TIME_RUN ? "?run=" + env.CZ_TIME_RUN : ""), "time-machine.png", Number(env.CZ_TIME_W || 960), 1300);
if (want("rule")) {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(URL0 + "/rules?present=1"); await page.waitForLoadState("networkidle").catch(() => {});
  const item = page.getByTestId("rule-list").getByText(RULE).first();
  if (await item.count()) { await item.click(); await page.waitForLoadState("networkidle").catch(() => {}); await page.waitForTimeout(2500); await page.screenshot({ path: resolve(out, "rule-dry-run.png") }); console.log("wrote rule-dry-run.png from /rules (" + RULE + ")"); }
  else console.log("skip rule-dry-run.png: no rule " + RULE);
}
await browser.close();
console.log("written to", out);
