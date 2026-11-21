// Builds the Czujka deck.
//   czujka.src.html  -> czujka.html (fonts and images inlined: one self-contained file)
//                    -> czujka.pdf  (headless Chromium, 1920 x 1080 pages)
// Then checks every slide: text below 24 px, elements that leave the slide or overlap the footer, the word budget
// (title at most 8 words, at most 12 more words on the slide; numbers count as words; the slide number is not counted)
// and the banned structures (lists, tables, code blocks of more than one line). Prints the word count per slide.
// Usage: cd docs/slides && npm install && npm run build
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, resolve, extname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { chromium } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(resolve(here, "czujka.src.html"), "utf8");

const mime = { ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml", ".webp": "image/webp" };
let html = src.replace(/src="((?:\.\.\/|img\/)[^"]+)"/g, (m, rel) => {
  const p = resolve(here, rel);
  if (!existsSync(p)) throw new Error("missing image " + rel);
  return 'src="data:' + mime[extname(p)] + ";base64," + readFileSync(p).toString("base64") + '"';
});

const fs = (pkg) => resolve(here, "node_modules/@fontsource", pkg, "files");
const faces = [];
for (const [family, pkg, weights] of [["IBM Plex Sans", "ibm-plex-sans", [400, 500, 600]], ["IBM Plex Mono", "ibm-plex-mono", [400, 500]]]) {
  for (const w of weights) {
    for (const subset of ["latin", "latin-ext"]) {
      const f = resolve(fs(pkg), pkg + "-" + subset + "-" + w + "-normal.woff2");
      faces.push("@font-face{font-family:\"" + family + "\";font-weight:" + w + ";font-style:normal;src:url(data:font/woff2;base64," + readFileSync(f).toString("base64") + ") format(\"woff2\");}");
    }
  }
}
html = html.replace("/*FONTS*/", faces.join("\n"));
writeFileSync(resolve(here, "czujka.html"), html);

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
await page.emulateMedia({ media: "print" });
await page.goto(pathToFileURL(resolve(here, "czujka.html")).href, { waitUntil: "load" });
await page.evaluate(() => { document.documentElement.style.setProperty("--s", 1); return document.fonts.ready; });

const report = await page.evaluate(() => {
  const out = [];
  document.querySelectorAll("section.slide").forEach((s, i) => {
    const sr = s.getBoundingClientRect();
    const foot = s.querySelector(".foot").getBoundingClientRect();
    s.querySelectorAll("*").forEach((e) => {
      if (e.closest("defs") || e.closest(".foot") || e.parentElement.classList.contains("shot")) return; // a cropped screenshot is clipped by its frame
      const r = e.getBoundingClientRect();
      if (!r.width || !r.height) return;
      const hasText = [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
      const fsz = parseFloat(getComputedStyle(e).fontSize);
      const label = e.tagName.toLowerCase() + (e.className && typeof e.className === "string" ? "." + e.className : "") + " " + (e.textContent || "").trim().slice(0, 40);
      if (hasText && fsz < 24) out.push("slide " + (i + 1) + ": small text " + fsz + "px: " + label);
      if (r.right > sr.right + 0.5 || r.bottom > sr.bottom + 0.5 || r.left < sr.left - 0.5) out.push("slide " + (i + 1) + ": leaves the slide: " + label);
      else if (hasText && r.bottom > foot.top + 0.5 && e.tagName !== "SECTION") out.push("slide " + (i + 1) + ": overlaps the footer: " + label);
      if (hasText && e.scrollWidth > e.clientWidth + 1 && getComputedStyle(e).overflow !== "visible") out.push("slide " + (i + 1) + ": clipped: " + label);
    });
  });
  // Word budget. A number written with a non-breaking space between digit groups ("65 535") is one word.
  const words = (t) => t.replace(/(\d)[\u00a0\u202f](?=\d)/g, "$1").split(/\s+/).filter((w) => /[\p{L}\p{N}]/u.test(w));
  const counts = [];
  document.querySelectorAll("section.slide").forEach((s, i) => {
    const title = words(s.querySelector("h1")?.textContent || "").length;
    let rest = 0;
    const tw = document.createTreeWalker(s, NodeFilter.SHOW_TEXT);
    for (let n = tw.nextNode(); n; n = tw.nextNode()) {
      const p = n.parentElement;
      if (p.closest("h1, .foot, defs, script, style")) continue;
      rest += words(n.textContent).length;
    }
    counts.push({ slide: i + 1, title, other: rest });
    if (title > 8) out.push("slide " + (i + 1) + ": title has " + title + " words (max 8)");
    if (rest > 12) out.push("slide " + (i + 1) + ": " + rest + " words besides the title (max 12)");
    if (s.querySelector("ul, ol, table")) out.push("slide " + (i + 1) + ": list or table");
    s.querySelectorAll("pre, code").forEach((c) => { if (c.textContent.trim().includes("\n")) out.push("slide " + (i + 1) + ": code block longer than one line"); });
  });
  return { slides: document.querySelectorAll("section.slide").length, words: counts, issues: out };
});

await page.pdf({ path: resolve(here, "czujka.pdf"), width: "1920px", height: "1080px", printBackground: true, preferCSSPageSize: true });
await browser.close();
for (const c of report.words) console.log("slide " + String(c.slide).padStart(2) + ": title " + c.title + "/8 words, other " + c.other + "/12 words");
console.log(JSON.stringify({ slides: report.slides, issues: report.issues }, null, 2));
if (report.issues.length) process.exitCode = 1;
