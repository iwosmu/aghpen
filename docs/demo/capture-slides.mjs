// Takes the deck's product screenshots from a running stack, sharp (device scale 2), in presentation mode.
//   cd docs/demo && CZ_PASSWORD=... CZ_TIME_RUN=<run id> node capture-slides.mjs
// Writes docs/slides/img/time-machine.png: the time machine at that run, 960 px wide so the panels stack (slide 6).
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const here = dirname(fileURLToPath(import.meta.url));
const env = process.env;
const URL0 = (env.CZ_URL || "http://127.0.0.1:18640").replace(/\/$/, "");
const out = resolve(here, "../slides/img");
mkdirSync(out, { recursive: true });
const browser = await chromium.launch();
async function shot(path, file, vw, vh) {
  const ctx = await browser.newContext({ viewport: { width: vw, height: vh }, deviceScaleFactor: 2, locale: "pl-PL", timezoneId: "Europe/Warsaw", colorScheme: "dark" });
  await ctx.addInitScript(() => localStorage.setItem("czujka.lang", "pl"));
  const page = await ctx.newPage();
  await page.goto(URL0 + "/login");
  await page.getByLabel(/e-mail|email/i).first().fill(env.CZ_EMAIL || "admin@czujka.local");
  await page.getByLabel(/^Hasło$/).first().fill(env.CZ_PASSWORD);
  await page.getByRole("button", { name: "Zaloguj się" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  await page.goto(URL0 + path + (path.includes("?") ? "&" : "?") + "present=1");
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(2500);
  await page.screenshot({ path: resolve(out, file) });
  await ctx.close();
}
await shot("/time" + (env.CZ_TIME_RUN ? "?run=" + env.CZ_TIME_RUN : ""), "time-machine.png", Number(env.CZ_TIME_W || 960), 1300);
await browser.close();
console.log("written to", out);
