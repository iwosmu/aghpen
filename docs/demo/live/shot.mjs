// Screenshots of the live jury machine for docs/demo/LIVE.md proofs.
//   node docs/demo/live/shot.mjs <out.png> <ui-path> [<out.png> <ui-path> ...]
// Env: CZ_URL (http://127.0.0.1:18730), CZ_EMAIL (admin@czujka.local), CZ_PASSWORD, WIDTH (1440), LANG_UI (pl).
import { chromium } from 'playwright';
const base = process.env.CZ_URL || 'http://127.0.0.1:18730';
const width = Number(process.env.WIDTH || 1440);
const args = process.argv.slice(2);
const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width, height: 900 }, deviceScaleFactor: 1, locale: 'pl-PL' });
const page = await ctx.newPage();
await page.goto(base + '/login');
await page.fill('input[type=email], input[name=email]', process.env.CZ_EMAIL || 'admin@czujka.local');
await page.fill('input[type=password]', process.env.CZ_PASSWORD || '');
await page.keyboard.press('Enter');
await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 15000 });
for (let i = 0; i + 1 < args.length; i += 2) {
  await page.goto(base + args[i + 1]);
  await page.waitForLoadState('networkidle').catch(() => {});
  await page.waitForTimeout(Number(process.env.WAIT_MS || 1200));
  await page.screenshot({ path: args[i], fullPage: process.env.FULL === '1' });
  console.log('saved', args[i], args[i + 1]);
}
await browser.close();
