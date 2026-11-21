// Juror walk-through of the UI, one role at a time (docs/demo/live). Not part of the product.
// It submits forms with test input, so it changes data: run it on the jury machine only, then live.sh reset.
//   WALK_ROLES='[{"role":"viewer","email":"...","pw":"..."}]' WALK_OUT=dir node docs/demo/live/walk.mjs
import { chromium } from 'playwright';
import fs from 'node:fs';
const base = process.env.CZ_URL || 'http://127.0.0.1:18730';
const out = process.env.WALK_OUT || 'walk-out';
const roles = JSON.parse(process.env.WALK_ROLES || '[]');
const MAXBTN = Number(process.env.WALK_MAXBTN || 30);
fs.mkdirSync(out, { recursive: true });
const issues = [];
const note = (o) => { issues.push(o); fs.appendFileSync(out + '/issues.jsonl', JSON.stringify(o) + '\n'); };
// Skips controls that delete, stop or lock out: account switches too (a first run disabled four accounts with one click each).
const SKIP = /konto aktywne|account active|usuń|delete|remove|stop awaryjny|emergency|wyloguj|log ?out|zwolnij stop|release|resetuj|reset|wyczyść|clear all|odbierz|revoke/i;
const slug = (s) => s.replace(/^https?:\/\/[^/]+/, '').replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '') || 'root';

async function login(page, r) {
  await page.goto(base + '/login');
  await page.fill('input[type=email], input[name=email]', r.email);
  await page.fill('input[type=password]', r.pw);
  await page.keyboard.press('Enter');
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 20000 });
}

function fillValue(el, wrong) {
  const t = (el.type || '').toLowerCase(), k = ((el.name || '') + ' ' + (el.placeholder || '') + ' ' + (el.label || '')).toLowerCase();
  if (t === 'email' || /e-?mail/.test(k)) return wrong ? 'nie-email' : 'juror.test@agh.edu.pl';
  if (t === 'password' || /hasło|password/.test(k)) return wrong ? 'a' : 'Haslo-Testowe-2026!';
  if (/yaml|sygnatur|regu/.test(k) && el.tag === 'textarea') return wrong ? '::: to nie jest yaml [' : null;
  if (/cidr|adres|address|\bip\b|cel|target|host/.test(k)) return wrong ? '999.300.1.1' : '172.18.0.1';
  if (/port/.test(k)) return wrong ? '99999' : '8080';
  if (t === 'number') return wrong ? '-5' : '10';
  if (t === 'url' || /url/.test(k)) return wrong ? 'ht!tp:/x' : 'http://127.0.0.1:18090';
  if (/cron/.test(k)) return wrong ? 'co pięć minut' : '0 2 * * *';
  if (t === 'date' || t === 'datetime-local' || t === 'time' || t === 'checkbox' || t === 'radio' || t === 'file' || t === 'hidden' || t === 'range' || t === 'color') return null;
  return wrong ? '' : 'Test jury';
}

async function formTest(page, root, ctx, which) {
  // root: a locator of a form or dialog. Fills every visible input/textarea, then presses the submit button.
  const fields = await root.locator('input, textarea').evaluateAll((els) => els.filter((e) => e.offsetParent !== null && !e.disabled && !e.readOnly).map((e, i) => {
    const lab = e.labels && e.labels[0] ? e.labels[0].innerText : (e.getAttribute('aria-label') || '');
    e.setAttribute('data-walk', String(i));
    return { i, tag: e.tagName.toLowerCase(), type: e.type, name: e.name, placeholder: e.placeholder, label: lab };
  }));
  if (!fields.length) return null;
  for (const f of fields) {
    const v = fillValue(f, which === 'wrong');
    if (v === null) continue;
    await root.locator('[data-walk="' + f.i + '"]').fill(v).catch(() => {});
  }
  const resp = [];
  const h = (r) => { if (r.url().includes('/api/') && r.request().method() !== 'GET') resp.push(r.request().method() + ' ' + r.url().replace(base, '') + ' ' + r.status()); };
  page.on('response', h);
  let btn = root.locator('button[type=submit]').first();
  if (!(await btn.count())) btn = root.getByRole('button', { name: /zapisz|dodaj|utwórz|importuj|zaloguj|sprawdź|save|add|create|import|validate|test/i }).first();
  let clicked = false, disabled = false;
  if (await btn.count()) {
    disabled = await btn.isDisabled().catch(() => false);
    if (!disabled) { await btn.click({ timeout: 3000 }).then(() => (clicked = true)).catch(() => {}); }
  }
  await page.waitForTimeout(1500);
  page.off('response', h);
  const msgs = await page.locator('[role=alert], .error, .err, [data-error], .toast, [role=status]').allInnerTexts().catch(() => []);
  const r = { ...ctx, step: 'form-' + which, fields: fields.map((f) => f.label || f.name || f.placeholder || f.type).slice(0, 12), clicked, disabled, responses: resp, messages: msgs.map((m) => m.slice(0, 200)).slice(0, 5) };
  await page.screenshot({ path: out + '/' + ctx.shot + '-form-' + which + '.png' }).catch(() => {});
  return r;
}

async function walkRole(browser, r, mode) {
  const width = mode.width, tag = r.role + '-' + mode.lang + '-' + width;
  const ctx = await browser.newContext({ viewport: { width, height: width < 500 ? 844 : 900 }, locale: mode.lang === 'en' ? 'en-US' : 'pl-PL' });
  await ctx.addInitScript((l) => { try { localStorage.setItem('czujka.lang', l); } catch {} }, mode.lang);
  const page = await ctx.newPage();
  let where = 'login', step = 'load';
  page.on('dialog', (d) => { note({ role: r.role, mode: tag, page: where, kind: 'native-dialog', text: d.message().slice(0, 200), step }); d.dismiss().catch(() => {}); });
  page.on('console', (m) => { if (m.type() === 'error') note({ role: r.role, mode: tag, page: where, kind: 'console-error', text: m.text().slice(0, 300), step }); });
  page.on('pageerror', (e) => note({ role: r.role, mode: tag, page: where, kind: 'page-error', text: String(e).slice(0, 300), step }));
  page.on('response', (resp) => { const s = resp.status(); if (s >= 400 && resp.url().includes('/api/')) note({ role: r.role, mode: tag, page: where, kind: 'http-' + s, text: resp.request().method() + ' ' + resp.url().replace(base, ''), step }); });
  await login(page, r);
  const links = await page.locator('nav a[href], aside a[href]').evaluateAll((as) => [...new Set(as.map((a) => a.getAttribute('href')).filter((h) => h && h.startsWith('/')))]);
  const pages = [];
  for (const href of links) {
    where = href; step = 'open';
    await page.goto(base + href); await page.waitForLoadState('networkidle').catch(() => {}); await page.waitForTimeout(800);
    const shot = tag + '-' + slug(href);
    await page.screenshot({ path: out + '/' + shot + '.png', fullPage: true }).catch(() => {});
    const info = await page.evaluate((lang) => {
      const vis = (e) => e.offsetParent !== null && getComputedStyle(e).visibility !== 'hidden';
      const trunc = [...document.querySelectorAll('main *, [role=main] *')].filter((e) => vis(e) && e.children.length === 0 && e.innerText && e.scrollWidth > e.clientWidth + 1 && ['hidden', 'clip'].includes(getComputedStyle(e).overflowX)).map((e) => e.innerText.trim().slice(0, 80)).slice(0, 12);
      const overflow = document.documentElement.scrollWidth > window.innerWidth + 1 ? document.documentElement.scrollWidth : 0;
      let untranslated = [];
      if (lang === 'en') untranslated = [...new Set([...document.querySelectorAll('button, label, th, h1, h2, h3, h4, nav a, [placeholder], option, .badge, .chip, p, span')].filter(vis).map((e) => (e.getAttribute('placeholder') || e.innerText || '').trim()).filter((s) => s && s.length < 120 && /[ąćęłńśźżĄĆĘŁŃŚŹŻ]|\b(nie|oraz|brak|wszystkie|skan|usługa|zmiany)\b/i.test(s)))].slice(0, 25);
      const en = lang === 'pl' ? [...new Set([...document.querySelectorAll('button, label, th, h1, h2, h3, [placeholder], option')].filter(vis).map((e) => (e.getAttribute('placeholder') || e.innerText || '').trim()).filter((s) => /\b(Loading|Cancel|Save|Error|Submit|Delete|Search|Close|Settings|Unknown|None)\b/.test(s)))].slice(0, 15) : [];
      const empty = [...document.querySelectorAll('main *')].filter((e) => vis(e) && e.children.length === 0 && /^(brak|nic|pusto|no |nothing|empty)/i.test((e.innerText || '').trim())).map((e) => e.parentElement.innerText.trim().slice(0, 160)).slice(0, 6);
      const h1 = (document.querySelector('h1') || {}).innerText || '';
      return { trunc, overflow, untranslated, en, empty, h1 };
    }, mode.lang);
    pages.push({ href, shot, ...info });
    if (info.overflow) note({ role: r.role, mode: tag, page: href, kind: 'horizontal-overflow', text: 'document ' + info.overflow + ' px wide at ' + width, shot });
    if (info.trunc.length) note({ role: r.role, mode: tag, page: href, kind: 'truncated', text: info.trunc.join(' | '), shot });
    if (info.untranslated.length) note({ role: r.role, mode: tag, page: href, kind: 'untranslated-en', text: info.untranslated.join(' | '), shot });
    if (info.en.length) note({ role: r.role, mode: tag, page: href, kind: 'english-in-pl', text: info.en.join(' | '), shot });
    if (!mode.interact) continue;
    // forms on the page
    const forms = page.locator('main form');
    for (let i = 0; i < Math.min(await forms.count(), 3); i++) {
      for (const which of ['good', 'wrong']) {
        await page.goto(base + href); await page.waitForLoadState('networkidle').catch(() => {});
        step = 'form ' + i + ' ' + which;
        const res = await formTest(page, page.locator('main form').nth(i), { role: r.role, mode: tag, page: href, shot: shot + '-f' + i }, which).catch((e) => ({ error: String(e).slice(0, 200) }));
        if (res) note({ kind: 'form', ...res });
      }
    }
    // buttons and links in the main area
    await page.goto(base + href); await page.waitForLoadState('networkidle').catch(() => {});
    const labels = await page.locator('main button:visible, main a[href]:visible, main [role=button]:visible, main [role=tab]:visible').evaluateAll((els) => els.map((e) => (e.innerText || e.getAttribute('aria-label') || e.getAttribute('title') || '').trim().replace(/\s+/g, ' ').slice(0, 60)));
    const seen = new Set();
    let n = 0;
    for (let idx = 0; idx < labels.length && n < MAXBTN; idx++) {
      const label = labels[idx];
      if (!label || seen.has(label)) continue; seen.add(label);
      if (SKIP.test(label)) { note({ role: r.role, mode: tag, page: href, kind: 'skipped-destructive-visible', text: label }); continue; }
      n++;
      await page.goto(base + href); await page.waitForLoadState('networkidle').catch(() => {}); await page.waitForTimeout(300);
      const el = page.locator('main button:visible, main a[href]:visible, main [role=button]:visible, main [role=tab]:visible').nth(idx);
      if (!(await el.count())) continue;
      step = 'click "' + label + '"';
      const disabled = await el.isDisabled().catch(() => false);
      const title = await el.getAttribute('title').catch(() => null);
      if (disabled) { note({ role: r.role, mode: tag, page: href, kind: 'disabled', text: label + (title ? ' (title: ' + title + ')' : ' (no reason shown)') }); continue; }
      const beforeUrl = page.url(); const beforeText = await page.locator('body').innerText().catch(() => '');
      const reqs = [];
      const h = (rq) => { if (rq.url().includes('/api/')) reqs.push(rq.method() + ' ' + rq.url().replace(base, '')); };
      const hr = (resp) => { if (resp.url().includes('/api/') && resp.status() === 403) note({ role: r.role, mode: tag, page: href, kind: 'visible-control-403', text: label + ' -> ' + resp.request().method() + ' ' + resp.url().replace(base, ''), shot: tag + '-' + slug(href) + '-403-' + n }); };
      page.on('request', h); page.on('response', hr);
      const target = await el.getAttribute('target').catch(() => null);
      if (target === '_blank') { page.off('request', h); page.off('response', hr); continue; }
      await el.click({ timeout: 3000 }).catch((e) => note({ role: r.role, mode: tag, page: href, kind: 'click-failed', text: label + ': ' + String(e).split('\n')[0].slice(0, 120) }));
      await page.waitForTimeout(1200);
      const dialog = page.locator('[role=dialog]:visible, dialog[open]');
      if (await dialog.count()) {
        await page.screenshot({ path: out + '/' + tag + '-' + slug(href) + '-dlg-' + n + '.png' }).catch(() => {});
        const hasInputs = await dialog.first().locator('input:visible, textarea:visible').count();
        if (hasInputs) {
          for (const which of ['wrong', 'good']) {
            if (which === 'good') { await page.goto(base + href); await page.waitForLoadState('networkidle').catch(() => {}); const e2 = page.locator('main button:visible, main a[href]:visible, main [role=button]:visible, main [role=tab]:visible').nth(idx); await e2.click({ timeout: 3000 }).catch(() => {}); await page.waitForTimeout(800); }
            step = 'dialog of "' + label + '" ' + which;
            const res = await formTest(page, page.locator('[role=dialog]:visible, dialog[open]').first(), { role: r.role, mode: tag, page: href, shot: tag + '-' + slug(href) + '-dlg-' + n, opener: label }, which).catch((e) => ({ error: String(e).slice(0, 200) }));
            if (res) note({ kind: 'form', ...res });
          }
        }
        await page.keyboard.press('Escape').catch(() => {});
      }
      page.off('request', h); page.off('response', hr);
      const afterUrl = page.url(); const afterText = await page.locator('body').innerText().catch(() => '');
      if (!reqs.length && afterUrl === beforeUrl && afterText === beforeText && !(await dialog.count())) note({ role: r.role, mode: tag, page: href, kind: 'no-effect', text: label });
    }
  }
  await ctx.close();
  return pages;
}

const browser = await chromium.launch();
const modes = (process.env.WALK_MODES || 'pl-1440-i,en-1440,pl-390').split(',').map((m) => { const [lang, w, i] = m.split('-'); return { lang, width: Number(w), interact: i === 'i' }; });
const all = {};
// One role and one browser context at a time: the walk shares the laptop with the jury machine.
for (const r of roles) { all[r.role] = {}; for (const m of modes) { try { all[r.role][m.lang + '-' + m.width] = await walkRole(browser, r, m); } catch (e) { note({ role: r.role, mode: m.lang + '-' + m.width, kind: 'walker-error', text: String(e).slice(0, 300) }); } } }
fs.writeFileSync(out + '/pages.json', JSON.stringify(all, null, 1));
await browser.close();
console.log('issues', issues.length);
