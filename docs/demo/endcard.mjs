// Records the closing shot: the product's own sign-in background with the wordmark and the address.
// Read-only: one GET of the public sign-in page. Writes frames and a concat list into out/end60.
// END_SPEED=3.2 captures 3.2 times longer and plays it back that much faster, so the moving background reaches 60 fps;
// ffmpeg then encodes out/end60/list-end.txt like the other shots and replaces the last clip of the film.
import { chromium } from "playwright";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
const here = dirname(fileURLToPath(import.meta.url));
const W = join(here, "out", "end60"); rmSync(W, { recursive: true, force: true }); mkdirSync(join(W, "frames"), { recursive: true });
const SECS = Number(process.env.END_SECS || 6.2);
const SPEED = Number(process.env.END_SPEED || 1); // capture SECS*SPEED of real time, play it SPEED times faster
const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1, locale: "pl-PL", colorScheme: "dark" });
await ctx.addInitScript(() => { localStorage.setItem("czujka.lang", "pl"); });
const page = await ctx.newPage();
await page.goto("https://czujka.dev/login", { waitUntil: "networkidle" });
await page.addStyleTag({ content: `
  .lgn-main,.lgn-pill{display:none!important}
  #cz-end{position:fixed;right:5vw;bottom:9.5vh;font-family:'IBM Plex Mono',ui-monospace,monospace;font-size:64px;font-weight:500;letter-spacing:-0.01em;color:#f3efe6;opacity:0;animation:czin ${(0.7 * SPEED).toFixed(2)}s ease-out ${(0.5 * SPEED).toFixed(2)}s forwards;z-index:50;text-shadow:0 2px 24px rgba(0,0,0,.35)}
  @keyframes czin{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
  *{cursor:none!important}
` });
await page.evaluate(() => { (document.activeElement)?.blur?.(); return document.fonts.ready; });
await page.waitForTimeout(600);
const frames = []; let fn = 0;
const cdp = await ctx.newCDPSession(page);
cdp.on("Page.screencastFrame", async ({ data, metadata, sessionId }) => {
  const file = join(W, "frames", "e" + String(fn++).padStart(5, "0") + ".jpg");
  writeFileSync(file, Buffer.from(data, "base64")); frames.push({ ts: metadata.timestamp, file });
  try { await cdp.send("Page.screencastFrameAck", { sessionId }); } catch {}
});
await cdp.send("Page.startScreencast", { format: "jpeg", quality: 92, maxWidth: 1920, maxHeight: 1080, everyNthFrame: 1 });
await page.evaluate(() => { const d = document.createElement("div"); d.id = "cz-end"; d.textContent = "czujka.dev"; document.body.appendChild(d); });
const t0 = Date.now(); while (Date.now() - t0 < SECS * SPEED * 1000 + 300) await page.waitForTimeout(100);
await cdp.send("Page.stopScreencast"); await page.waitForTimeout(200);
const start = frames[0].ts, end = start + SECS * SPEED;
const seq = frames.filter((f) => f.ts < end);
let list = "";
for (let i = 0; i < seq.length; i++) { const d = (i + 1 < seq.length ? seq[i + 1].ts : end) - seq[i].ts; if (d > 0) list += "file '" + seq[i].file + "'\nduration " + (d / SPEED).toFixed(4) + "\n"; }
list += "file '" + seq[seq.length - 1].file + "'\n";
writeFileSync(join(W, "list-end.txt"), list);
console.log("end card:", seq.length, "frames over", SECS, "s of film ->", (seq.length / SECS).toFixed(1), "fps (capture " + (seq.length / SECS / SPEED).toFixed(1) + " fps, speed x" + SPEED + ")");
await browser.close();
