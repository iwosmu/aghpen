// Dev-only fixture backend. It answers the same REST paths as docs/API.md from
// in-memory data and simulates one live run over the event streams.
// install() is called from main.tsx only when VITE_FIXTURES=1 in a dev server.
import { setTransport } from '../api/client';
import { setStreamFactory, type EventHandlers } from '../api/events';
import type {
  Change, Chunk, Finding, Host, InvalidLine, MapBlock, NameCount, Permission, RetroHit, ScanEstimate, ScanProfile, ScanRun, Service,
  ServiceGroup, Session, Signature, SignatureIssue, Target, TargetKind, TargetPreview, User, Dashboard, Evidence, ServiceResult,
} from '../api/types';
import * as db from './data';

class HttpError extends Error {
  status: number; code: string;
  constructor(status: number, code: string, message: string) { super(message); this.status = status; this.code = code; }
}
const iso = (ms = Date.now()) => new Date(ms).toISOString();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------- session ----------
const SKEY = 'czujka.fx.user';
function currentUser(): User | null {
  const id = Number(sessionStorage.getItem(SKEY) ?? 0);
  return db.users.find((u) => u.id === id && !u.disabled) ?? null;
}
function sessionOf(u: User): Session {
  const role = db.roles.find((r) => r.id === u.role_id)!;
  return { user: { ...u, role_slug: role.slug, role_name: role.name }, permissions: [...role.permissions], csrf_token: 'fx-' + u.id + '-csrf' };
}

// ---------- list helpers ----------
function page<T>(items: T[], q: URLSearchParams, defSort?: string) {
  const sort = q.get('sort') || defSort || '';
  let list = items;
  if (sort) {
    const desc = sort.startsWith('-');
    const f = desc ? sort.slice(1) : sort;
    const val = (x: any) => {
      const v = x[f];
      if (f === 'ip' && typeof v === 'string') return v.split('.').reduce((a: number, p: string) => a * 256 + Number(p), 0);
      if (Array.isArray(v)) return v.length;
      return v ?? '';
    };
    list = [...items].sort((a, b) => { const x = val(a), y = val(b); return (x < y ? -1 : x > y ? 1 : 0) * (desc ? -1 : 1); });
  }
  const limit = Math.min(1000, Math.max(1, Number(q.get('limit') ?? 50)));
  const offset = Math.max(0, Number(q.get('offset') ?? 0));
  return { items: list.slice(offset, offset + limit), total: list.length, limit, offset };
}
const has = (s: string | null | undefined, needle: string) => (s ?? '').toLowerCase().includes(needle);
const ipNum = (ip: string) => ip.split('.').reduce((a, p) => a * 256 + Number(p), 0);
function inCidr(ip: string, cidr: string): boolean {
  const [base, bitsS] = cidr.split('/');
  const bits = bitsS === undefined ? 32 : Number(bitsS);
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(base) || Number.isNaN(bits)) return has(ip, cidr.toLowerCase());
  const size = Math.pow(2, 32 - bits);
  const lo = Math.floor(ipNum(base) / size) * size;
  const n = ipNum(ip);
  return n >= lo && n < lo + size;
}

function filterHosts(q: URLSearchParams): Host[] {
  const text = (q.get('q') ?? '').toLowerCase();
  const status = q.get('status'), tag = q.get('tag'), scope = q.get('scope_id'), cidr = q.get('cidr'), tech = (q.get('tech') ?? '').toLowerCase();
  const port = q.get('port'), minI = Number(q.get('min_interest') ?? 0), unstable = q.get('unstable');
  return db.hosts.filter((h) =>
    (!text || has(h.ip, text) || h.hostnames?.some((n) => has(n, text)) || has(h.label, text) || has(h.owner, text) || has(h.os_guess, text) || has(h.note, text)) &&
    (!status || status.split(',').includes(h.status)) && (!tag || h.tags?.includes(tag)) && (!scope || h.scope_ids?.includes(Number(scope))) &&
    (!cidr || inCidr(h.ip, cidr)) && (!tech || h.technologies?.some((x) => x.toLowerCase().includes(tech))) && (!port || h.open_ports?.includes(Number(port))) &&
    h.interest >= minI && (!unstable || unstable === 'false' || h.status === 'unstable'));
}
function filterServices(q: URLSearchParams): Service[] {
  const text = (q.get('q') ?? '').toLowerCase();
  const host = q.get('host_id'), port = q.get('port'), state = q.get('state'), name = q.get('name'), tech = (q.get('tech') ?? '').toLowerCase();
  const cls = q.get('class'), tag = q.get('tag'), gk = q.get('group_key'), minI = Number(q.get('min_interest') ?? 0), tls = q.get('tls');
  return db.services.filter((s) =>
    (!text || has(s.ip, text) || has(s.hostname, text) || has(s.title, text) || has(s.product, text) || has(s.name, text) || s.technologies?.some((x) => has(x.name, text))) &&
    (!host || s.host_id === Number(host)) && (!port || s.port === Number(port)) && (!state || s.state === state) && (!name || s.name === name) &&
    (!tech || s.technologies?.some((x) => x.name.toLowerCase().includes(tech))) && (!cls || s.classes?.includes(cls)) && (!tag || s.tags?.includes(tag)) &&
    (!gk || s.group_key === gk) && s.interest >= minI && (!tls || String(s.tls) === tls));
}
function filterChanges(q: URLSearchParams): Change[] {
  const text = (q.get('q') ?? '').toLowerCase();
  const run = q.get('run_id'), kind = q.get('kind'), sev = q.get('severity'), host = q.get('host_id'), acked = q.get('acked'), expected = q.get('expected'), from = q.get('from'), to = q.get('to');
  return db.changes.filter((c) =>
    (!text || has(c.ip, text) || has(c.summary, text)) && (!run || c.run_id === Number(run)) && (!kind || kind.split(',').includes(c.kind)) && (!sev || sev.split(',').includes(c.severity)) &&
    (!host || c.host_id === Number(host)) && (!acked || String(Boolean(c.acked_at)) === acked) && (!expected || String(c.expected) === expected) && (!from || c.at >= from) && (!to || c.at <= to));
}
function filterFindings(q: URLSearchParams): Finding[] {
  const text = (q.get('q') ?? '').toLowerCase();
  const status = q.get('status'), sev = q.get('severity'), type = q.get('type'), host = q.get('host_id'), tag = q.get('tag'), minI = Number(q.get('min_interest') ?? 0), exported = q.get('exported'), assignee = q.get('assignee');
  return db.findings.filter((f) =>
    (!text || has(f.title, text) || has(f.ip, text) || has(f.description, text) || has(f.url, text)) && (!status || status.split(',').includes(f.status)) && (!sev || sev.split(',').includes(f.severity)) &&
    (!type || f.type === type) && (!host || f.host_id === Number(host)) && (!tag || f.tags?.includes(tag)) && f.interest >= minI && (!exported || String(f.dojo_id !== null) === exported) &&
    (!assignee || f.assignee === assignee));
}
function filterSignatures(q: URLSearchParams): Signature[] {
  const text = (q.get('q') ?? '').toLowerCase();
  const cat = q.get('category'), enabled = q.get('enabled'), builtin = q.get('builtin'), tag = q.get('tag');
  return db.signatures.filter((s) => (!text || has(s.name, text) || has(s.slug, text) || has(s.description, text)) && (!cat || s.category === cat) && (!enabled || String(s.enabled) === enabled) && (!builtin || String(s.builtin) === builtin) && (!tag || s.tags?.includes(tag)));
}

// ---------- targets ----------
function parseTargetLine(v: string): { kind: TargetKind; addresses: number } | string {
  const ipRe = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const okIp = (s: string) => { const m = ipRe.exec(s); return Boolean(m && m.slice(1).every((p) => Number(p) <= 255)); };
  if (v.includes('/')) {
    const [a, b] = v.split('/');
    if (!okIp(a)) return 'nieprawidłowy adres sieci';
    const bits = Number(b);
    if (!/^\d+$/.test(b) || bits > 32) return 'nieprawidłowa długość prefiksu';
    if (bits < 12) return 'zakres większy niż /12: podziel go na mniejsze';
    return { kind: 'cidr', addresses: Math.pow(2, 32 - bits) };
  }
  if (v.includes('-') && /^\d/.test(v) && v.split('-').length === 2) {
    const [a, b] = v.split('-').map((x) => x.trim());
    if (!okIp(a) || !okIp(b)) return 'nieprawidłowy adres w zakresie';
    if (ipNum(b) < ipNum(a)) return 'koniec zakresu przed początkiem';
    return { kind: 'range', addresses: ipNum(b) - ipNum(a) + 1 };
  }
  if (/^\d+(\.\d+)*$/.test(v) || ipRe.test(v)) return okIp(v) ? { kind: 'ip', addresses: 1 } : 'nieprawidłowy adres IPv4';
  if (/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(v)) return { kind: 'domain', addresses: 1 };
  return 'nie jest adresem IP, zakresem CIDR, zakresem ani domeną';
}
function previewTargets(lines: string[], scopeId: number, source: string): TargetPreview {
  const valid: Target[] = [];
  const invalid: InvalidLine[] = [];
  let duplicates = 0, excluded = 0;
  const seen = new Set(db.targets.map((x) => x.value));
  lines.forEach((raw0, i) => {
    const v = raw0.split('#')[0].trim();
    if (!v) return;
    const r = parseTargetLine(v);
    if (typeof r === 'string') { invalid.push({ line: i + 1, value: v, reason: r }); return; }
    if (seen.has(v)) { duplicates++; return; }
    seen.add(v);
    for (const ex of db.safety.exclusions) {
      if (ex === v) excluded += r.addresses;
      else if (r.kind === 'cidr' && ex.includes('/') && inCidr(ex.split('/')[0], v)) excluded += Math.pow(2, 32 - Number(ex.split('/')[1]));
      else if (r.kind === 'cidr' && /^\d+\.\d+\.\d+\.\d+$/.test(ex) && inCidr(ex, v)) excluded += 1;
    }
    valid.push({ id: 0, scope_id: scopeId, kind: r.kind, value: v, note: '', tags: [], enabled: true, source, addresses: r.addresses, created_at: iso(), created_by: currentUser()?.id ?? null });
  });
  return { valid, invalid, duplicates, excluded, address_count: valid.reduce((a, x) => a + x.addresses, 0) - excluded };
}
function saveTargets(p: TargetPreview) {
  let id = Math.max(0, ...db.targets.map((x) => x.id));
  for (const v of p.valid) { v.id = ++id; db.targets.push(v); }
  recountScopes();
}
function recountScopes() {
  for (const s of db.scopes) {
    const list = db.targets.filter((x) => x.scope_id === s.id);
    s.target_count = list.length;
    s.address_count = list.filter((x) => x.enabled).reduce((a, x) => a + x.addresses, 0);
  }
}
function linesFromFile(name: string, text: string): string[] {
  if (name.toLowerCase().endsWith('.json') || text.trim().startsWith('[') || text.trim().startsWith('{')) {
    const j = JSON.parse(text);
    const arr = Array.isArray(j) ? j : j.targets ?? [];
    return arr.map((x: any) => (typeof x === 'string' ? x : x.value ?? x.target ?? x.ip ?? ''));
  }
  const rows = text.split(/\r?\n/).map((l) => l.split(/[;,]/)[0].trim().replace(/^"|"$/g, ''));
  if (rows.length && /^(target|value|cel|adres|ip|host)$/i.test(rows[0])) rows[0] = '';
  return rows;
}

// ---------- signatures ----------
function validateYaml(yaml: string) {
  const issues: SignatureIssue[] = [];
  const paths: string[] = [];
  const lines = yaml.split('\n');
  const top = new Set<string>();
  let matcher = -1;
  let group = 'any';
  let inMatch = false;
  lines.forEach((line) => {
    if (line.includes('\t')) issues.push({ level: 'error', path: '', message: 'YAML nie dopuszcza tabulatorów we wcięciach', safety: false });
    const m = /^(\s*)(- )?([A-Za-z_]+):\s*(.*)$/.exec(line);
    if (!m) return;
    const indent = m[1].length, key = m[3], value = m[4].trim().replace(/^['"]|['"]$/g, '');
    if (indent === 0 && !m[2]) { top.add(key); inMatch = key === 'match'; if (key === 'paths') for (const p of value.replace(/[[\]]/g, '').split(',')) if (p.trim()) paths.push(p.trim()); return; }
    if (inMatch && (key === 'any' || key === 'all') && !m[2]) { group = key; return; }
    if (inMatch && m[2]) matcher++;
    const path = inMatch ? 'match.' + group + '[' + Math.max(0, matcher) + '].' + key : key;
    if (key === 'method' && !/^(GET|HEAD)$/i.test(value)) issues.push({ level: 'error', path, message: 'Metoda ' + value.toUpperCase() + ' jest niedozwolona. Sygnatury używają wyłącznie GET i HEAD.', safety: true });
    if (/^(payload|data|post_data|username|password|login|credentials|form)$/.test(key)) issues.push({ level: 'error', path, message: 'Pole „' + key + '” wysyła dane do usługi. Sygnatura może tylko odczytywać odpowiedź.', safety: true });
    if (key === 'path') {
      if (/(\.\.\/|%2e%2e|<script|union\s+select|['"]\s*or\s|\$\{|;\s*(cat|id|ls)\b)/i.test(value)) issues.push({ level: 'error', path, message: 'Ścieżka wygląda na próbę wykorzystania podatności, a nie na wykrycie obecności.', safety: true });
      else if (!value.startsWith('/')) issues.push({ level: 'error', path, message: 'Ścieżka musi zaczynać się od „/”', safety: false });
      else if (!paths.includes(value)) paths.push(value);
    }
    if (key === 'regex' || key === 'name_regex') {
      try { new RegExp(value.replace(/^\(\?i\)/, ''), value.startsWith('(?i)') ? 'i' : ''); } catch (e) { issues.push({ level: 'error', path, message: 'Nieprawidłowe wyrażenie regularne: ' + (e as Error).message, safety: false }); }
      if (value.length > 0 && value.length < 3) issues.push({ level: 'warning', path, message: 'Bardzo krótkie wyrażenie da wiele fałszywych trafień', safety: false });
    }
    if (key === 'weight') { const w = Number(value); if (Number.isNaN(w) || w <= 0 || w > 1) issues.push({ level: 'error', path, message: 'Waga musi być liczbą z przedziału (0, 1]', safety: false }); }
    if (key === 'type' && inMatch && !/^(header|header_absent|cookie|body|title|favicon|path|banner|tls|meta|status|host)$/.test(value)) issues.push({ level: 'error', path, message: 'Nieznany typ dopasowania „' + value + '”', safety: false });
    if (key === 'safe' && value === 'false') issues.push({ level: 'error', path: 'safe', message: 'Sygnatura musi działać w trybie bezpiecznym (safe: true)', safety: true });
  });
  for (const k of ['id', 'name', 'match']) if (!top.has(k)) issues.push({ level: 'error', path: k, message: 'Brak wymaganego pola „' + k + '”', safety: false });
  if (!top.has('category')) issues.push({ level: 'warning', path: 'category', message: 'Brak kategorii: sygnatura trafi do „inne”', safety: false });
  if (top.has('match') && matcher < 0) issues.push({ level: 'error', path: 'match', message: 'Sekcja match nie zawiera żadnego dopasowania', safety: false });
  if (paths.length > db.safety.max_paths_per_host) issues.push({ level: 'warning', path: 'paths', message: 'Sygnatura prosi o ' + paths.length + ' ścieżek, polityka pozwala na ' + db.safety.max_paths_per_host + ' na usługę', safety: false });
  return { ok: !issues.some((i) => i.level === 'error'), issues, paths };
}
interface Matcher { [k: string]: string }
function parseMatchers(yaml: string): { name: string; matchers: Matcher[] } {
  const out: Matcher[] = [];
  let name = '', inMatch = false;
  for (const line of yaml.split('\n')) {
    const m = /^(\s*)(- )?([A-Za-z_]+):\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[3], value = m[4].trim().replace(/^['"]|['"]$/g, '');
    if (m[1].length === 0 && !m[2]) { inMatch = key === 'match'; if (key === 'name') name = value; continue; }
    if (!inMatch) continue;
    if (m[2]) out.push({});
    if (out.length) out[out.length - 1][key] = value;
  }
  return { name, matchers: out };
}
function rx(s: string): RegExp | null {
  try { return new RegExp(s.replace(/^\(\?i\)/, ''), s.startsWith('(?i)') ? 'i' : ''); } catch { return null; }
}
function matchOne(m: Matcher, s: Service, r: ServiceResult): Evidence | null {
  const h = r.http;
  const re = m.regex ? rx(m.regex) : null;
  switch (m.type) {
    case 'header': {
      const vals = h?.headers?.[m.name] ?? Object.entries(h?.headers ?? {}).find(([k]) => k.toLowerCase() === (m.name ?? '').toLowerCase())?.[1];
      if (!vals) return null;
      const v = vals.join(', ');
      return !re || re.test(v) ? { matcher: 'header', where: 'header:' + m.name, snippet: v.slice(0, 80) } : null;
    }
    case 'header_absent': return h && s.tls && !Object.keys(h.headers ?? {}).some((k) => k.toLowerCase() === (m.name ?? '').toLowerCase()) ? { matcher: 'header', where: 'header:' + m.name, snippet: 'brak nagłówka' } : null;
    case 'cookie': {
      const nre = m.name_regex ? rx(m.name_regex) : null;
      const c = h?.cookies?.find((x) => (m.name ? x.name === m.name : nre ? nre.test(x.name) : false) && (m.flag_absent !== 'secure' || !x.secure));
      return c ? { matcher: 'cookie', where: 'cookie:' + c.name, snippet: c.name + (c.secure ? '; Secure' : '') + (c.http_only ? '; HttpOnly' : '') } : null;
    }
    case 'title': return h && h.title && re && re.test(h.title) ? { matcher: 'title', where: 'title', snippet: h.title.slice(0, 80) } : null;
    case 'body': { const mm = h && re ? re.exec(h.body_excerpt) : null; return mm ? { matcher: 'body', where: 'body', snippet: mm[0].slice(0, 80) } : null; }
    case 'meta': return h && h.meta_generator && re && re.test(h.meta_generator) ? { matcher: 'meta', where: 'meta:' + (m.name ?? 'generator'), snippet: h.meta_generator } : null;
    case 'favicon': return h && h.favicon_mmh3 !== null && String(h.favicon_mmh3) === m.mmh3 ? { matcher: 'favicon', where: 'favicon:mmh3', snippet: m.mmh3 } : null;
    case 'path': { const p = h?.paths?.find((x) => x.path === m.path && (!m.status || String(x.status) === m.status)); return p ? { matcher: 'path', where: 'path:' + p.path, snippet: String(p.status) + (p.title ? ', ' + p.title : '') } : null; }
    case 'banner': return r.banner && re && re.test(r.banner) ? { matcher: 'banner', where: 'banner', snippet: r.banner.slice(0, 80) } : null;
    case 'host': return s.hostname && re && re.test(s.hostname) ? { matcher: 'host', where: 'host', snippet: s.hostname } : null;
    default: return null;
  }
}
function retroHunt(yaml: string) {
  const t0 = performance.now();
  const { name, matchers } = parseMatchers(yaml);
  const hits: RetroHit[] = [];
  let scanned = 0;
  for (const s of db.services) {
    const r = db.latest.get(s.id);
    if (!r) continue;
    scanned += 3;
    const evidence = matchers.map((m) => ({ m, e: matchOne(m, s, r) })).filter((x) => x.e);
    if (evidence.length === 0) continue;
    const conf = 1 - evidence.reduce((a, x) => a * (1 - Math.min(1, Math.max(0, Number(x.m.weight ?? 0.5)))), 1);
    hits.push({ service_id: s.id, ip: s.ip, port: s.port, url: s.url, run_id: 41, at: s.last_seen, match: { signature: 'draft', name: name || 'draft', category: '', version: '', confidence: conf, interest: 0, classes: null, tags: null, evidence: evidence.map((x) => x.e!) } });
  }
  hits.sort((a, b) => b.match.confidence - a.match.confidence);
  return { scanned, hits: hits.slice(0, 200), took_ms: Math.max(1, Math.round(performance.now() - t0)), packets_sent: 0 };
}

// ---------- dashboard ----------
function dashboard(): Dashboard {
  const last = db.runs.filter((r) => r.status === 'completed' && r.profile_id === 1).sort((a, b) => b.id - a.id)[0] ?? null;
  const active = db.runs.find((r) => r.status === 'running' || r.status === 'analyzing') ?? null;
  const open = db.findings.filter((f) => f.status === 'new' || f.status === 'triaged');
  const lastChanges = db.changes.filter((c) => c.run_id === last?.id);
  const news = lastChanges.filter((c) => !c.expected && (c.kind === 'host_new' || c.kind === 'service_new')).length;
  const gone = lastChanges.filter((c) => !c.expected && (c.kind === 'host_gone' || c.kind === 'service_gone')).length;
  const count = (list: string[]): NameCount[] => {
    const m = new Map<string, number>();
    for (const x of list) m.set(x, (m.get(x) ?? 0) + 1);
    return [...m.entries()].map(([name, c]) => ({ name, count: c })).sort((a, b) => b.count - a.count);
  };
  const openSvc = db.services.filter((s) => s.state === 'open');
  const trend = db.runs.filter((r) => r.status === 'completed' && r.profile_id === 1).sort((a, b) => a.id - b.id).map((r) => ({
    at: r.finished_at!, run_id: r.id, hosts: r.stats.hosts_up, services: r.stats.services_open,
    changes: r.summary ? r.summary.hosts_new + r.summary.hosts_gone + r.summary.services_new + r.summary.services_gone + r.summary.services_changed : 0, findings: 30 + Math.round((r.id - 20) * 0.8),
  }));
  const certs = openSvc.filter((s) => s.tls && (db.latest.get(s.id)?.tls?.days_left ?? 999) <= 30).sort((a, b) => (db.latest.get(a.id)!.tls!.days_left) - (db.latest.get(b.id)!.tls!.days_left)).slice(0, 8)
    .map((s) => ({ ...s, latest: { id: s.id * 100, service_id: s.id, run_id: 41, at: s.last_seen, result: db.latest.get(s.id)! } }));
  return {
    generated_at: iso(),
    headline: {
      addresses_in_scope: db.scopes.reduce((a, s) => a + s.address_count, 0), hosts_up: db.hosts.filter((h) => h.status === 'up').length, hosts_unstable: db.hosts.filter((h) => h.status === 'unstable').length,
      hosts_down: db.hosts.filter((h) => h.status === 'down').length, services_open: openSvc.length, web_services: openSvc.filter((s) => s.name === 'http').length, findings_open: open.length,
      findings_high: open.filter((f) => f.severity === 'high').length, changes_unacked: db.changes.filter((c) => !c.acked_at && !c.expected).length, new_since_last_run: news, gone_since_last_run: gone,
      admin_panels: openSvc.filter((s) => s.classes?.includes('admin-panel')).length, staging_envs: openSvc.filter((s) => s.classes?.includes('staging')).length,
    },
    last_run: last, active_run: active, next_run_at: db.profiles[0].next_run_at,
    top_findings: [...open].sort((a, b) => ({ high: 3, medium: 2, low: 1, info: 0 }[b.severity] - { high: 3, medium: 2, low: 1, info: 0 }[a.severity]) || b.interest - a.interest).slice(0, 8),
    recent_changes: db.changes.filter((c) => c.run_id === last?.id).sort((a, b) => Number(a.expected) - Number(b.expected) || ({ high: 3, medium: 2, low: 1, info: 0 }[b.severity] - { high: 3, medium: 2, low: 1, info: 0 }[a.severity])).slice(0, 40),
    top_services: [...openSvc].sort((a, b) => b.interest - a.interest).slice(0, 8),
    technologies: db.services.flatMap((s) => (s.technologies ?? []).map((x) => x.name)).reduce<NameCount[]>((acc, name) => { const f = acc.find((x) => x.name === name); if (f) f.count++; else acc.push({ name, count: 1, extra: db.services.find((s) => s.technologies?.some((x) => x.name === name))?.technologies?.find((x) => x.name === name)?.category }); return acc; }, []).sort((a, b) => b.count - a.count).slice(0, 12),
    ports: count(openSvc.map((s) => String(s.port))).slice(0, 12).map((p) => ({ ...p, extra: openSvc.find((s) => String(s.port) === p.name)?.name })),
    classes: count(openSvc.flatMap((s) => s.classes ?? [])),
    trend,
    unstable_hosts: db.hosts.filter((h) => h.status === 'unstable').sort((a, b) => b.interest - a.interest).slice(0, 8),
    certs_expiring: certs, safety: db.safety,
  };
}

function estimate(p: ScanProfile): ScanEstimate {
  const addresses = db.scopes.filter((s) => p.scope_ids.includes(s.id)).reduce((a, s) => a + s.address_count, 0);
  const ports = p.ports.startsWith('top-') ? Number(p.ports.slice(4)) : p.ports.split(',').reduce((a, part) => { const [x, y] = part.split('-').map(Number); return a + (y ? y - x + 1 : 1); }, 0);
  const live = 0.034;
  const packets = Math.round(addresses * 6 + addresses * live * ports * 2.2 + (p.service_detection ? addresses * live * 40 * (1 + p.version_intensity / 3) : 0));
  const pps = Math.max(1, Math.min(p.rate.max_pps, db.safety.max_pps));
  const prev = db.runs.filter((r) => r.profile_id === p.id && r.stats.addresses_done > 0 && r.stats.elapsed_sec > 0).sort((a, b) => b.id - a.id)[0];
  const dur = prev ? Math.round((addresses * prev.stats.elapsed_sec) / prev.stats.addresses_done) : Math.round(packets / pps + addresses * live * 9);
  const w = p.schedule.windows[0];
  let windowSec = 0;
  if (w) { const [sh, sm] = w.start.split(':').map(Number); const [eh, em] = w.end.split(':').map(Number); let mins = eh * 60 + em - (sh * 60 + sm); if (mins <= 0) mins += 24 * 60; windowSec = mins * 60; }
  const size = p.chunking.adaptive ? Math.round((p.chunking.initial_size + p.chunking.max_size) / 2.6) : p.chunking.initial_size;
  return { addresses, chunks: Math.max(1, Math.ceil(addresses / Math.max(1, size))), est_packets: prev ? Math.round(prev.stats.avg_pps * dur) || packets : packets, est_duration_sec: dur, effective_pps: pps, fits_window: windowSec === 0 || dur <= windowSec, window_sec: windowSec, based_on_history: Boolean(prev), expected_live_rate: live };
}

// ---------- event streams and the live run ----------
const subs = new Map<string, Set<EventHandlers>>();
function emit(path: string, event: string, data: unknown) {
  subs.get(path)?.forEach((h) => { try { h[event]?.(JSON.parse(JSON.stringify(data))); } catch (e) { console.error(e); } });
}
const remain = new Map<number, number>();
let analyzing = 0;
let tickN = 0;
function tick() {
  tickN++;
  for (const run of db.runs) {
    const cs = db.chunksByRun.get(run.id);
    if (run.status === 'analyzing') {
      if (--analyzing <= 0) {
        run.status = 'completed'; run.finished_at = iso(); run.stats.current_pps = 0; run.stats.eta_sec = 0;
        run.summary = { prev_run_id: 41, hosts_new: 2, hosts_gone: 1, hosts_back: 3, hosts_unstable: 1, services_new: 3, services_gone: 1, services_changed: 7, by_kind: null, findings_new: 1 };
        emit('/runs/' + run.id + '/events', 'progress', run); emit('/runs/' + run.id + '/events', 'done', {}); emit('/events', 'run', run);
      }
      continue;
    }
    if (run.status !== 'running' || !cs) continue;
    const s = run.stats;
    const profile = db.profiles.find((p) => p.id === run.profile_id);
    const par = profile?.rate.max_parallel_chunks ?? 2;
    const cap = Math.min(profile?.rate.max_pps ?? 800, db.safety.max_pps);
    let running = cs.filter((c) => c.status === 'running');
    for (const c of running) {
      if (!remain.has(c.id)) remain.set(c.id, Math.round((c.size / 256) * 6 * (0.5 + Math.random() * 0.5)));
      const left = remain.get(c.id)! - 1;
      remain.set(c.id, left);
      if (left <= 0) {
        c.status = 'done'; c.finished_at = iso(); c.duration_ms = Date.now() - new Date(c.started_at!).getTime();
        c.hosts_up = c.spec.reduce((a, cidr) => a + (db.blocks.find((b) => b.cidr === cidr)?.hosts ?? 0), 0);
        c.pps = Math.round(cap / par * (0.9 + Math.random() * 0.1));
        emit('/runs/' + run.id + '/events', 'chunk', c);
        const found = db.hosts.filter((h) => c.spec.some((cidr) => inCidr(h.ip, cidr)) && (h.status === 'up' || h.status === 'unstable')).slice(0, 5);
        for (const h of found) emit('/runs/' + run.id + '/events', 'host', { ip: h.ip, up: true, services: h.service_count });
      }
    }
    running = cs.filter((c) => c.status === 'running');
    const nextSize = adaptiveNext(cs);
    while (running.length < par) {
      const next = cs.find((c) => c.status === 'pending');
      if (!next) break;
      next.status = 'running'; next.started_at = iso();
      void nextSize;
      running.push(next);
      emit('/runs/' + run.id + '/events', 'chunk', next);
    }
    const done = cs.filter((c) => c.status === 'done');
    const partial = running.reduce((a, c) => { const total = (c.size / 256) * 6; const left = remain.get(c.id) ?? total; return a + c.size * Math.max(0, Math.min(0.95, 1 - left / total)); }, 0);
    s.chunks_total = cs.length; s.chunks_done = done.length;
    s.addresses_done = Math.round(done.reduce((a, c) => a + c.size, 0) + partial);
    s.hosts_up = done.reduce((a, c) => a + c.hosts_up, 0);
    const doneHosts = db.hosts.filter((h) => done.some((c) => c.spec.some((cidr) => inCidr(h.ip, cidr))) && (h.status === 'up' || h.status === 'unstable'));
    s.services_open = doneHosts.reduce((a, h) => a + h.service_count, 0);
    s.http_services = Math.round(s.services_open * 0.42);
    s.current_pps = running.length ? Math.round(cap * (0.86 + Math.random() * 0.1)) : 0;
    s.packets_sent += s.current_pps; s.http_requests = Math.round(s.http_services * 5.1);
    s.elapsed_sec += 1; s.avg_pps = Math.round(s.packets_sent / Math.max(1, s.elapsed_sec));
    const rate = s.addresses_done / Math.max(1, s.elapsed_sec);
    s.eta_sec = Math.round((s.addresses_total - s.addresses_done) / Math.max(0.5, rate));
    if (running.length === 0 && !cs.some((c) => c.status === 'pending')) { run.status = 'analyzing'; analyzing = 6; s.addresses_done = s.addresses_total; s.eta_sec = 0; s.current_pps = 0; }
    emit('/runs/' + run.id + '/events', 'progress', run);
    if (tickN % 2 === 0 || run.status !== 'running') emit('/events', 'run', run);
  }
}
function adaptiveNext(cs: Chunk[]): number { return cs.length; }
function seedLiveStats() {
  const run = db.liveRun, cs = db.chunksByRun.get(42)!;
  const done = cs.filter((c) => c.status === 'done');
  const s = run.stats;
  s.chunks_done = done.length; s.addresses_done = done.reduce((a, c) => a + c.size, 0); s.hosts_up = done.reduce((a, c) => a + c.hosts_up, 0);
  s.elapsed_sec = Math.round((Date.now() - new Date(run.started_at!).getTime()) / 1000); s.avg_pps = 742; s.current_pps = 768; s.packets_sent = s.avg_pps * s.elapsed_sec;
  s.services_open = Math.round(s.hosts_up * 2.1); s.http_services = Math.round(s.services_open * 0.42); s.http_requests = s.http_services * 5; s.retried = 7;
  s.eta_sec = Math.round((s.addresses_total - s.addresses_done) / Math.max(1, s.addresses_done / s.elapsed_sec));
}

// ---------- CSV ----------
function toCsv(rows: any[]): string {
  if (rows.length === 0) return '';
  const cols = Object.keys(rows[0]).filter((k) => !k.startsWith('_') && typeof rows[0][k] !== 'object' || Array.isArray(rows[0][k]));
  const cell = (v: unknown) => { const s = Array.isArray(v) ? v.join(' ') : v === null || v === undefined ? '' : String(v); return /[",\n;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  return [cols.join(','), ...rows.map((r) => cols.map((c) => cell(r[c])).join(','))].join('\n') + '\n';
}

// ---------- routes ----------
interface Ctx { q: URLSearchParams; body: any; form: FormData | null; user: User }
type Handler = (m: string[], c: Ctx) => unknown | Promise<unknown>;
const routes: [string, RegExp, Permission | null, Handler][] = [];
const on = (method: string, pattern: string, perm: Permission | null, h: Handler) => {
  routes.push([method, new RegExp('^' + pattern.replace(/:id/g, '([^/]+)') + '$'), perm, h]);
};
const find = <T extends { id: number }>(list: T[], id: string, what: string): T => {
  const x = list.find((i) => i.id === Number(id));
  if (!x) throw new HttpError(404, 'not_found', 'Nie znaleziono: ' + what + ' ' + id);
  return x;
};
const strip = (h: Host) => { const { _avail, _block, ...rest } = h as db.FxHost; void _avail; void _block; return rest; };
function applyOverrides<T extends { overrides: Record<string, any> | null }>(entity: T, body: Record<string, unknown>, observedFields: string[], user: User) {
  const e = entity as any;
  entity.overrides = entity.overrides ?? {};
  for (const [k, v] of Object.entries(body)) {
    if (observedFields.includes(k)) {
      if (v === null) { const o = entity.overrides[k]; if (o) { e[k] = o.observed; delete entity.overrides[k]; } }
      else { const observed = entity.overrides[k]?.observed ?? e[k]; entity.overrides[k] = { value: v, observed, by: user.email, at: iso() }; e[k] = v; }
    } else if (v !== undefined) e[k] = v;
  }
}

on('GET', '/healthz', null, () => ({ status: 'ok', version: 'dev-fixtures', db: 'fixtures', tde: 'n/a' }));
on('GET', '/me', null, (_m, c) => sessionOf(c.user));
on('GET', '/permissions', null, () => db.permissions);
on('GET', '/users', 'users:manage', (_m, c) => page(db.users, c.q, 'id'));
on('POST', '/users', 'users:manage', (_m, c) => {
  if (!/^\S+@\S+\.\S+$/.test(c.body.email ?? '')) throw new HttpError(422, 'validation', 'Nieprawidłowy adres e-mail');
  if ((c.body.password ?? '').length < 10) throw new HttpError(422, 'validation', 'Hasło musi mieć co najmniej 10 znaków');
  if (db.users.some((u) => u.email === c.body.email)) throw new HttpError(409, 'conflict', 'Użytkownik o tym adresie już istnieje');
  const role = find(db.roles, String(c.body.role_id), 'rola');
  const u: User = { id: Math.max(...db.users.map((x) => x.id)) + 1, email: c.body.email, name: c.body.name ?? '', role_id: role.id, role_slug: role.slug, role_name: role.name, disabled: false, created_at: iso(), last_login_at: null };
  db.users.push(u); role.user_count++; db.addAudit(c.user, 'user.create', 'user', u.id, { email: u.email, role: role.slug });
  return u;
});
on('PATCH', '/users/:id', 'users:manage', (m, c) => {
  const u = find(db.users, m[1], 'użytkownik');
  if (c.body.role_id !== undefined) { const role = find(db.roles, String(c.body.role_id), 'rola'); u.role_id = role.id; u.role_slug = role.slug; u.role_name = role.name; }
  if (c.body.name !== undefined) u.name = c.body.name;
  if (c.body.disabled !== undefined) { if (u.id === c.user.id) throw new HttpError(409, 'conflict', 'Nie można wyłączyć własnego konta'); u.disabled = c.body.disabled; }
  for (const r of db.roles) r.user_count = db.users.filter((x) => x.role_id === r.id).length;
  db.addAudit(c.user, 'user.update', 'user', u.id, c.body);
  return u;
});
on('DELETE', '/users/:id', 'users:manage', (m, c) => {
  const u = find(db.users, m[1], 'użytkownik');
  if (u.id === c.user.id) throw new HttpError(409, 'conflict', 'Nie można usunąć własnego konta');
  db.users.splice(db.users.indexOf(u), 1); db.addAudit(c.user, 'user.delete', 'user', u.id, { email: u.email });
});
on('GET', '/roles', null, () => db.roles);
on('POST', '/roles', 'roles:manage', (_m, c) => {
  if (!c.body.name) throw new HttpError(422, 'validation', 'Rola musi mieć nazwę');
  const r = { id: Math.max(...db.roles.map((x) => x.id)) + 1, slug: String(c.body.name).toLowerCase().replace(/[^a-z0-9]+/g, '-'), name: c.body.name, description: c.body.description ?? '', builtin: false, permissions: c.body.permissions ?? [], user_count: 0 };
  db.roles.push(r); db.addAudit(c.user, 'role.create', 'role', r.id, { name: r.name });
  return r;
});
on('PATCH', '/roles/:id', 'roles:manage', (m, c) => {
  const r = find(db.roles, m[1], 'rola');
  if (r.builtin) throw new HttpError(409, 'conflict', 'Wbudowanych ról nie można zmieniać');
  Object.assign(r, { name: c.body.name ?? r.name, description: c.body.description ?? r.description, permissions: c.body.permissions ?? r.permissions });
  db.addAudit(c.user, 'role.update', 'role', r.id, { permissions: r.permissions.length });
  return r;
});
on('DELETE', '/roles/:id', 'roles:manage', (m, c) => {
  const r = find(db.roles, m[1], 'rola');
  if (r.builtin) throw new HttpError(409, 'conflict', 'Wbudowanych ról nie można usuwać');
  if (r.user_count > 0) throw new HttpError(409, 'conflict', 'Rola ma przypisanych użytkowników');
  db.roles.splice(db.roles.indexOf(r), 1); db.addAudit(c.user, 'role.delete', 'role', r.id, {});
});
on('GET', '/audit', 'audit:read', (_m, c) => {
  const text = (c.q.get('q') ?? '').toLowerCase(), uid = c.q.get('user_id'), action = c.q.get('action'), entity = c.q.get('entity');
  return page(db.audit.filter((a) => (!text || has(a.action, text) || has(a.user_email, text) || has(a.entity_id, text)) && (!uid || a.user_id === Number(uid)) && (!action || a.action.startsWith(action)) && (!entity || a.entity === entity)), c.q);
});

on('GET', '/scopes', 'targets:read', (_m, c) => page(db.scopes, c.q, 'id'));
on('GET', '/scopes/:id', 'targets:read', (m) => find(db.scopes, m[1], 'zakres'));
on('POST', '/scopes', 'targets:create', (_m, c) => {
  if (!c.body.name) throw new HttpError(422, 'validation', 'Zakres musi mieć nazwę');
  const s = { id: Math.max(...db.scopes.map((x) => x.id)) + 1, name: c.body.name, description: c.body.description ?? '', owner: c.body.owner ?? '', criticality: c.body.criticality ?? 3, tags: c.body.tags ?? [], target_count: 0, address_count: 0, created_at: iso(), updated_at: iso() };
  db.scopes.push(s); db.addAudit(c.user, 'scope.create', 'scope', s.id, { name: s.name });
  return s;
});
on('PATCH', '/scopes/:id', 'targets:update', (m, c) => { const s = find(db.scopes, m[1], 'zakres'); Object.assign(s, c.body, { id: s.id, updated_at: iso() }); db.addAudit(c.user, 'scope.update', 'scope', s.id, c.body); return s; });
on('DELETE', '/scopes/:id', 'targets:delete', (m, c) => {
  const s = find(db.scopes, m[1], 'zakres');
  db.scopes.splice(db.scopes.indexOf(s), 1);
  for (let i = db.targets.length - 1; i >= 0; i--) if (db.targets[i].scope_id === s.id) db.targets.splice(i, 1);
  db.addAudit(c.user, 'scope.delete', 'scope', s.id, { name: s.name });
});
on('GET', '/scopes/:id/targets', 'targets:read', (m, c) => page(db.targets.filter((x) => x.scope_id === Number(m[1])), c.q, 'id'));
on('POST', '/scopes/:id/targets', 'targets:create', (m, c) => {
  find(db.scopes, m[1], 'zakres');
  const p = previewTargets(String(c.body.text ?? '').split(/\r?\n/), Number(m[1]), 'manual');
  saveTargets(p); db.addAudit(c.user, 'target.create', 'scope', m[1], { added: p.valid.length, source: 'manual' });
  return p;
});
on('POST', '/scopes/:id/targets/import', 'targets:create', async (m, c) => {
  find(db.scopes, m[1], 'zakres');
  const file = c.form?.get('file') as File | null;
  if (!file) throw new HttpError(400, 'bad_request', 'Brak pliku');
  let lines: string[];
  try { lines = linesFromFile(file.name, await file.text()); } catch (e) { throw new HttpError(422, 'validation', 'Nie udało się odczytać pliku: ' + (e as Error).message); }
  const dry = String(c.form?.get('dry_run') ?? 'false') === 'true';
  const p = previewTargets(lines, Number(m[1]), file.name.toLowerCase().endsWith('.json') ? 'json' : 'csv');
  if (!dry) { saveTargets(p); db.addAudit(c.user, 'target.create', 'scope', m[1], { added: p.valid.length, source: file.name }); }
  return p;
});
on('POST', '/targets/preview', 'targets:read', (_m, c) => previewTargets(String(c.body.text ?? '').split(/\r?\n/), 0, 'manual'));
on('PATCH', '/targets/:id', 'targets:update', (m, c) => { const x = find(db.targets, m[1], 'cel'); Object.assign(x, c.body, { id: x.id }); recountScopes(); db.addAudit(c.user, 'target.update', 'target', x.id, c.body); return x; });
on('DELETE', '/targets/:id', 'targets:delete', (m, c) => { const x = find(db.targets, m[1], 'cel'); db.targets.splice(db.targets.indexOf(x), 1); recountScopes(); db.addAudit(c.user, 'target.delete', 'target', x.id, { value: x.value }); });

on('GET', '/profiles', 'scans:read', (_m, c) => page(db.profiles, c.q, 'id'));
on('GET', '/profiles/:id', 'scans:read', (m) => find(db.profiles, m[1], 'profil'));
on('POST', '/profiles', 'scans:configure', (_m, c) => {
  if (!c.body.name) throw new HttpError(422, 'validation', 'Profil musi mieć nazwę');
  const p: ScanProfile = { ...c.body, id: Math.max(...db.profiles.map((x) => x.id)) + 1, created_at: iso(), updated_at: iso(), next_run_at: null, last_run_id: null };
  db.profiles.push(p); db.addAudit(c.user, 'profile.create', 'profile', p.id, { name: p.name });
  return p;
});
on('PATCH', '/profiles/:id', 'scans:configure', (m, c) => { const p = find(db.profiles, m[1], 'profil'); Object.assign(p, c.body, { id: p.id, updated_at: iso() }); db.addAudit(c.user, 'profile.update', 'profile', p.id, {}); return p; });
on('DELETE', '/profiles/:id', 'scans:configure', (m, c) => { const p = find(db.profiles, m[1], 'profil'); db.profiles.splice(db.profiles.indexOf(p), 1); db.addAudit(c.user, 'profile.delete', 'profile', p.id, { name: p.name }); });
on('POST', '/profiles/:id/estimate', 'scans:read', (m, c) => {
  const p = m[1] === '0' ? (c.body as ScanProfile) : { ...find(db.profiles, m[1], 'profil'), ...(c.body && c.body.rate ? c.body : {}) };
  return estimate(p);
});

on('GET', '/runs', 'scans:read', (_m, c) => {
  const pid = c.q.get('profile_id'), status = c.q.get('status');
  return page(db.runs.filter((r) => (!pid || r.profile_id === Number(pid)) && (!status || status.split(',').includes(r.status))), c.q, '-id');
});
on('GET', '/runs/:id', 'scans:read', (m) => (m[1] === '9001' ? db.scaleRun : find(db.runs, m[1], 'przebieg')));
on('POST', '/runs', 'scans:run', (_m, c) => {
  if (db.safety.emergency_stop) throw new HttpError(409, 'emergency_stop', 'Stop awaryjny jest aktywny. Nowe skany są zablokowane.');
  const p = find(db.profiles, String(c.body.profile_id), 'profil');
  if (db.runs.some((r) => r.profile_id === p.id && (r.status === 'running' || r.status === 'analyzing'))) throw new HttpError(409, 'conflict', 'Ten profil ma już trwający przebieg');
  const id = Math.max(...db.runs.map((r) => r.id)) + 1;
  const list = db.blocks.filter((b) => (p.scope_ids.includes(1) && b.idx < 32) || (p.scope_ids.includes(2) && b.idx >= 32 && b.idx < 48) || (p.scope_ids.includes(3) && b.idx >= 100));
  const sorted = [...list].sort((a, b) => b.hosts - a.hosts);
  const cs: Chunk[] = [];
  for (let i = 0, seq = 0; i < sorted.length;) { const n = Math.min(4, 1 + Math.floor(seq / 3)); const part = sorted.slice(i, i + n); i += n; cs.push({ id: id * 1000 + seq, run_id: id, seq: ++seq, spec: part.map((b) => b.cidr), size: part.length * 256, priority: 100 - seq, status: 'pending', started_at: null, finished_at: null, duration_ms: 0, hosts_up: 0, pps: 0, error: '' }); }
  db.chunksByRun.set(id, cs);
  const run: ScanRun = { ...db.liveRun, id, profile_id: p.id, profile_name: p.name, status: 'running', trigger: 'manual', created_by: c.user.id, created_at: iso(), started_at: iso(), finished_at: null, summary: null,
    stats: { ...db.scaleRun.stats, addresses_total: list.length * 256, addresses_done: 0, chunks_total: cs.length, chunks_done: 0, hosts_up: 0, avg_pps: 0, elapsed_sec: 0, eta_sec: 0, packets_sent: 0, services_open: 0, http_services: 0, http_requests: 0 } };
  db.runs.push(run); p.last_run_id = id; db.addAudit(c.user, 'run.start', 'run', id, { profile_id: p.id });
  emit('/events', 'run', run);
  return run;
});
const runAction = (action: 'pause' | 'resume' | 'cancel') => (m: string[], c: Ctx) => {
  const run = find(db.runs, m[1], 'przebieg');
  const cs = db.chunksByRun.get(run.id) ?? [];
  if (action === 'pause') {
    if (run.status !== 'running') throw new HttpError(409, 'conflict', 'Przebieg nie jest w toku');
    run.status = 'paused'; run.pause_reason = 'manual'; run.stats.current_pps = 0;
    for (const ch of cs) if (ch.status === 'running') { ch.status = 'deferred'; remain.delete(ch.id); }
  } else if (action === 'resume') {
    if (db.safety.emergency_stop) throw new HttpError(409, 'emergency_stop', 'Stop awaryjny jest aktywny. Zwolnij blokadę przed wznowieniem.');
    if (run.status !== 'paused') throw new HttpError(409, 'conflict', 'Przebieg nie jest wstrzymany');
    run.status = 'running'; run.pause_reason = ''; run.resume_at = null;
    for (const ch of cs) if (ch.status === 'deferred') ch.status = 'pending';
  } else {
    if (!['running', 'paused', 'queued'].includes(run.status)) throw new HttpError(409, 'conflict', 'Przebieg jest już zakończony');
    run.status = 'cancelled'; run.finished_at = iso(); run.stats.current_pps = 0;
    for (const ch of cs) if (ch.status === 'running') ch.status = 'deferred';
  }
  db.addAudit(c.user, 'run.' + action, 'run', run.id, {});
  emit('/runs/' + run.id + '/events', 'progress', run); emit('/events', 'run', run);
  return run;
};
on('POST', '/runs/:id/pause', 'scans:run', runAction('pause'));
on('POST', '/runs/:id/resume', 'scans:run', runAction('resume'));
on('POST', '/runs/:id/cancel', 'scans:run', runAction('cancel'));
on('GET', '/runs/:id/chunks', 'scans:read', (m) => db.chunksByRun.get(Number(m[1])) ?? []);
on('GET', '/runs/:id/map', 'scans:read', (m): { blocks: MapBlock[] } => ({ blocks: db.mapFor(Number(m[1])) }));

on('GET', '/hosts', 'results:read', (_m, c) => { const p = page(filterHosts(c.q), c.q, '-interest'); return { ...p, items: p.items.map(strip) }; });
on('GET', '/hosts/:id', 'results:read', (m) => strip(find(db.hosts, m[1], 'host')));
on('PATCH', '/hosts/:id', 'results:update', (m, c) => { const h = find(db.hosts, m[1], 'host'); applyOverrides(h, c.body, ['hostnames', 'os_guess'], c.user); db.addAudit(c.user, 'host.update', 'host', h.id, c.body); return strip(h); });
on('DELETE', '/hosts/:id', 'results:delete', (m, c) => { const h = find(db.hosts, m[1], 'host'); db.hosts.splice(db.hosts.indexOf(h), 1); db.addAudit(c.user, 'host.delete', 'host', h.id, { ip: h.ip }); });
on('GET', '/hosts/:id/services', 'results:read', (m) => db.services.filter((s) => s.host_id === Number(m[1])).sort((a, b) => a.port - b.port));
on('GET', '/hosts/:id/availability', 'results:read', (m) => db.availability(find(db.hosts, m[1], 'host')));
on('GET', '/hosts/:id/changes', 'results:read', (m, c) => page(db.changes.filter((x) => x.host_id === Number(m[1])), c.q));
on('GET', '/services', 'results:read', (_m, c) => page(filterServices(c.q), c.q, '-interest'));
on('GET', '/services/:id', 'results:read', (m, c) => {
  const s = find(db.services, m[1], 'usługa');
  const r = JSON.parse(JSON.stringify(db.latest.get(s.id))) as ServiceResult;
  if (!sessionOf(c.user).permissions.includes('results:update')) for (const ck of r.http?.cookies ?? []) delete ck.value;
  return { ...s, latest: { id: s.id * 100, service_id: s.id, run_id: 41, at: s.last_seen, result: r } };
});
on('PATCH', '/services/:id', 'results:update', (m, c) => { const s = find(db.services, m[1], 'usługa'); applyOverrides(s, c.body, ['name', 'product', 'version', 'classes'], c.user); db.addAudit(c.user, 'service.update', 'service', s.id, c.body); return s; });
on('DELETE', '/services/:id', 'results:delete', (m, c) => { const s = find(db.services, m[1], 'usługa'); db.services.splice(db.services.indexOf(s), 1); db.addAudit(c.user, 'service.delete', 'service', s.id, {}); });
on('GET', '/services/:id/observations', 'results:read', (m, c) => page(db.observations(find(db.services, m[1], 'usługa')), c.q));
on('GET', '/service-groups', 'results:read', (_m, c) => {
  const groups = new Map<string, ServiceGroup>();
  for (const s of filterServices(c.q)) {
    if (s.name !== 'http' && !c.q.get('all')) continue;
    let g = groups.get(s.group_key);
    if (!g) { g = { key: s.group_key, label: s.technologies?.[0]?.name || s.product || s.name, count: 0, technologies: (s.technologies ?? []).map((x) => x.name), title: s.title, sample_ids: [], interest: 0 }; groups.set(s.group_key, g); }
    g.count++; g.interest = Math.max(g.interest, s.interest); if (g.sample_ids!.length < 4) g.sample_ids!.push(s.id);
  }
  return page([...groups.values()], c.q, '-count');
});
on('GET', '/technologies', 'results:read', () => dashboardTech());
on('GET', '/tags', 'results:read', () => {
  const m = new Map<string, number>();
  for (const x of [...db.hosts, ...db.services, ...db.findings]) for (const tag of x.tags ?? []) m.set(tag, (m.get(tag) ?? 0) + 1);
  return [...m.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
});
function dashboardTech(): NameCount[] {
  const m = new Map<string, NameCount>();
  for (const s of db.services) for (const x of s.technologies ?? []) { const e = m.get(x.name) ?? { name: x.name, count: 0, extra: x.category }; e.count++; m.set(x.name, e); }
  return [...m.values()].sort((a, b) => b.count - a.count);
}

on('GET', '/changes', 'results:read', (_m, c) => page(filterChanges(c.q), c.q));
const ack = (ids: number[], user: User) => { let n = 0; for (const ch of db.changes) if (ids.includes(ch.id) && !ch.acked_at) { ch.acked_at = iso(); ch.acked_by = user.email; n++; } db.addAudit(user, 'change.ack', 'change', ids.length === 1 ? ids[0] : 'bulk', { count: n }); return { acked: n }; };
on('POST', '/changes/ack', 'results:update', (_m, c) => ack((c.body.ids ?? []).map(Number), c.user));
on('POST', '/changes/:id/ack', 'results:update', (m, c) => ack([Number(m[1])], c.user));
on('GET', '/diff', 'results:read', (_m, c) => {
  const from = find(db.runs, c.q.get('from') ?? '', 'przebieg'), to = find(db.runs, c.q.get('to') ?? '', 'przebieg');
  if (from.id === to.id) throw new HttpError(400, 'bad_request', 'Wybierz dwa różne przebiegi');
  const lo = Math.min(from.id, to.id), hi = Math.max(from.id, to.id);
  const list = db.changes.filter((x) => x.run_id > lo && x.run_id <= hi);
  const n = (k: string, exp = false) => list.filter((x) => x.kind === k && x.expected === exp).length;
  const by: Record<string, number> = {};
  for (const x of list) by[x.kind] = (by[x.kind] ?? 0) + 1;
  return { from, to, changes: list, summary: { prev_run_id: from.id, hosts_new: n('host_new'), hosts_gone: n('host_gone'), hosts_back: n('host_back'), hosts_unstable: n('host_unstable'), services_new: n('service_new'), services_gone: n('service_gone'),
    services_changed: list.filter((x) => !['host_new', 'host_gone', 'host_back', 'host_unstable', 'service_new', 'service_gone'].includes(x.kind)).length, by_kind: by, findings_new: db.findings.filter((f) => f.first_run_id > lo && f.first_run_id <= hi).length } };
});

on('GET', '/findings', 'results:read', (_m, c) => page(filterFindings(c.q), c.q));
on('GET', '/findings/:id', 'results:read', (m) => find(db.findings, m[1], 'znalezisko'));
on('POST', '/findings', 'results:create', (_m, c) => {
  if (!c.body.title) throw new HttpError(422, 'validation', 'Znalezisko musi mieć tytuł');
  const host = db.hosts.find((h) => h.ip === c.body.ip);
  const f: Finding = { id: Math.max(...db.findings.map((x) => x.id)) + 1, key: 'manual:' + (c.body.ip ?? '') + ':' + Date.now(), type: 'manual', title: c.body.title, description: c.body.description ?? '', severity: c.body.severity ?? 'info', status: 'new', interest: c.body.interest ?? 50,
    host_id: host?.id ?? 0, ip: c.body.ip ?? '', service_id: null, port: Number(c.body.port ?? 0), url: c.body.url ?? '', signature: '', evidence: [], note: c.body.note ?? '', tags: c.body.tags ?? [], assignee: c.body.assignee ?? '', first_seen: iso(), last_seen: iso(),
    first_run_id: 0, last_run_id: 0, overrides: {}, dojo_id: null, dojo_url: '', manual: true };
  db.findings.unshift(f); db.addAudit(c.user, 'finding.create', 'finding', f.id, { title: f.title });
  emit('/events', 'finding', f);
  return f;
});
on('PATCH', '/findings/:id', 'results:update', (m, c) => { const f = find(db.findings, m[1], 'znalezisko'); applyOverrides(f, c.body, ['title', 'description', 'severity'], c.user); db.addAudit(c.user, 'finding.update', 'finding', f.id, c.body); return f; });
on('DELETE', '/findings/:id', 'results:delete', (m, c) => { const f = find(db.findings, m[1], 'znalezisko'); db.findings.splice(db.findings.indexOf(f), 1); db.addAudit(c.user, 'finding.delete', 'finding', f.id, {}); });
on('POST', '/findings/export/defectdojo', 'export:run', async (_m, c) => {
  if (!db.dojo.enabled || !db.dojo.url) throw new HttpError(409, 'conflict', 'Integracja z DefectDojo jest wyłączona. Skonfiguruj ją w Administracji.');
  await sleep(700);
  const ids: number[] = (c.body.ids ?? []).map(Number);
  const list = db.findings.filter((f) => ids.includes(f.id));
  let exported = 0, updated = 0;
  for (const f of list) { if (f.dojo_id) updated++; else { exported++; f.dojo_id = 1200 + f.id; f.dojo_url = db.dojo.url + '/finding/' + f.dojo_id; } }
  db.addAudit(c.user, 'finding.export', 'defectdojo', '77', { exported, updated });
  return { exported, updated, failed: 0, test_id: 77, test_url: db.dojo.url + '/test/77', errors: [] };
});

on('GET', '/signatures', 'signatures:read', (_m, c) => page(filterSignatures(c.q), c.q));
on('GET', '/signatures/:id', 'signatures:read', (m) => find(db.signatures, m[1], 'sygnatura'));
const sigFromYaml = (yaml: string) => {
  const g = (k: string) => (new RegExp('^' + k + ':\\s*(.+)$', 'm').exec(yaml)?.[1] ?? '').trim().replace(/^['"]|['"]$/g, '');
  return { slug: g('id'), name: g('name'), category: g('category') || 'other', description: g('description') };
};
on('POST', '/signatures', 'signatures:create', (_m, c) => {
  const v = validateYaml(c.body.yaml ?? '');
  if (v.issues.some((i) => i.safety)) throw new HttpError(422, 'unsafe_signature', v.issues.find((i) => i.safety)!.message);
  if (!v.ok) throw new HttpError(422, 'validation', v.issues.find((i) => i.level === 'error')!.message);
  const meta = sigFromYaml(c.body.yaml);
  if (db.signatures.some((s) => s.slug === meta.slug)) throw new HttpError(409, 'conflict', 'Sygnatura o identyfikatorze „' + meta.slug + '” już istnieje');
  const s: Signature = { id: Math.max(...db.signatures.map((x) => x.id)) + 1, ...meta, yaml: c.body.yaml, enabled: c.body.enabled ?? true, builtin: false, author: c.user.email, tags: [meta.category], interest: 0, match_count: retroHunt(c.body.yaml).hits.length, created_at: iso(), updated_at: iso() };
  db.signatures.push(s); db.addAudit(c.user, 'signature.create', 'signature', s.slug, {});
  return s;
});
on('PATCH', '/signatures/:id', 'signatures:update', (m, c) => {
  const s = find(db.signatures, m[1], 'sygnatura');
  if (c.body.yaml !== undefined && c.body.yaml !== s.yaml) {
    if (s.builtin) throw new HttpError(409, 'conflict', 'Wbudowaną sygnaturę można tylko włączyć lub wyłączyć. Skopiuj ją, aby zmienić treść.');
    const v = validateYaml(c.body.yaml);
    if (v.issues.some((i) => i.safety)) throw new HttpError(422, 'unsafe_signature', v.issues.find((i) => i.safety)!.message);
    if (!v.ok) throw new HttpError(422, 'validation', v.issues.find((i) => i.level === 'error')!.message);
    Object.assign(s, sigFromYaml(c.body.yaml), { yaml: c.body.yaml, match_count: retroHunt(c.body.yaml).hits.length });
  }
  if (c.body.enabled !== undefined) s.enabled = c.body.enabled;
  s.updated_at = iso(); db.addAudit(c.user, 'signature.update', 'signature', s.slug, { enabled: s.enabled });
  return s;
});
on('DELETE', '/signatures/:id', 'signatures:delete', (m, c) => {
  const s = find(db.signatures, m[1], 'sygnatura');
  if (s.builtin) throw new HttpError(409, 'conflict', 'Wbudowanych sygnatur nie można usuwać');
  db.signatures.splice(db.signatures.indexOf(s), 1); db.addAudit(c.user, 'signature.delete', 'signature', s.slug, {});
});
on('POST', '/signatures/validate', 'signatures:read', (_m, c) => validateYaml(c.body.yaml ?? ''));
on('POST', '/signatures/retrohunt', 'signatures:read', async (_m, c) => { await sleep(250); return retroHunt(c.body.yaml ?? db.signatures.find((s) => s.id === Number(c.body.id))?.yaml ?? ''); });

on('POST', '/import/results', 'results:create', async (_m, c) => {
  const file = c.form?.get('file') as File | null;
  if (!file) throw new HttpError(400, 'bad_request', 'Brak pliku');
  const text = await file.text();
  await sleep(500);
  let format: string, hostsN: number, servicesN = 0, skipped = 0;
  const invalid: InvalidLine[] = [];
  if (/<nmaprun/.test(text)) { format = 'nmap-xml'; hostsN = (text.match(/<host[ >]/g) ?? []).length; servicesN = (text.match(/<port /g) ?? []).length; }
  else if (text.trim().startsWith('{') || text.trim().startsWith('[')) {
    try { const j = JSON.parse(text); const arr = Array.isArray(j) ? j : j.hosts ?? []; format = 'czujka-json'; hostsN = arr.length; servicesN = arr.reduce((a: number, h: any) => a + (h.services?.length ?? 0), 0); }
    catch (e) { throw new HttpError(422, 'validation', 'Plik JSON jest uszkodzony: ' + (e as Error).message); }
  } else {
    format = 'csv';
    const rows = text.split(/\r?\n/).filter((l) => l.trim());
    const ips = new Set<string>();
    rows.slice(1).forEach((l, i) => { const cells = l.split(/[;,]/); if (/^\d+\.\d+\.\d+\.\d+$/.test(cells[0]?.trim() ?? '')) { ips.add(cells[0].trim()); servicesN++; } else { skipped++; invalid.push({ line: i + 2, value: l.slice(0, 60), reason: 'pierwsza kolumna nie jest adresem IPv4' }); } });
    hostsN = ips.size;
  }
  if (hostsN === 0 && invalid.length === 0) throw new HttpError(422, 'validation', 'Nie rozpoznano formatu pliku. Obsługiwane: nmap XML, JSON Czujki, CSV.');
  const id = Math.max(...db.runs.filter((r) => r.id < 9000).map((r) => r.id)) + 1;
  db.runs.push({ ...db.scaleRun, id, profile_id: null, profile_name: 'Import: ' + file.name, status: 'completed', pause_reason: '', trigger: 'import', created_by: c.user.id, created_at: iso(), started_at: iso(), finished_at: iso(), import_file: file.name,
    stats: { ...db.scaleRun.stats, addresses_total: hostsN, addresses_done: hostsN, chunks_total: 0, chunks_done: 0, hosts_up: hostsN, services_open: servicesN, avg_pps: 0, elapsed_sec: 1, eta_sec: 0 }, summary: null });
  db.addAudit(c.user, 'import.results', 'run', id, { file: file.name, hosts: hostsN });
  return { format, run_id: id, hosts: hostsN, services: servicesN, targets: 0, skipped, invalid };
});

on('GET', '/dashboard', 'results:read', () => dashboard());
on('GET', '/settings/safety', 'scans:read', () => db.safety);
on('PUT', '/settings/safety', 'safety:manage', (_m, c) => {
  const methods: string[] = c.body.allowed_methods ?? ['GET', 'HEAD'];
  if (methods.some((x) => !['GET', 'HEAD'].includes(x))) throw new HttpError(422, 'validation', 'Dozwolone metody to wyłącznie GET i HEAD');
  if (!(c.body.max_pps > 0)) throw new HttpError(422, 'validation', 'Limit pakietów na sekundę musi być większy od zera');
  Object.assign(db.safety, c.body, { emergency_stop: db.safety.emergency_stop, updated_at: iso() });
  db.addAudit(c.user, 'safety.update', 'safety', '', { max_pps: db.safety.max_pps });
  return db.safety;
});
on('POST', '/emergency-stop', 'safety:stop', (_m, c) => {
  db.safety.emergency_stop = true; db.safety.updated_at = iso();
  for (const run of db.runs) if (run.status === 'running' || run.status === 'queued' || run.status === 'analyzing') {
    run.status = 'paused'; run.pause_reason = 'emergency_stop'; run.stats.current_pps = 0;
    for (const ch of db.chunksByRun.get(run.id) ?? []) if (ch.status === 'running') { ch.status = 'deferred'; remain.delete(ch.id); }
    emit('/runs/' + run.id + '/events', 'progress', run); emit('/events', 'run', run);
  }
  db.addAudit(c.user, 'safety.emergency_stop', 'safety', '', {});
  return db.safety;
});
on('POST', '/emergency-stop/release', 'safety:manage', (_m, c) => { db.safety.emergency_stop = false; db.safety.updated_at = iso(); db.addAudit(c.user, 'safety.release', 'safety', '', {}); return db.safety; });
on('GET', '/settings/defectdojo', 'integrations:manage', () => db.dojo);
on('PUT', '/settings/defectdojo', 'integrations:manage', (_m, c) => {
  const { api_key, ...rest } = c.body;
  Object.assign(db.dojo, rest);
  if (api_key) db.dojo.api_key_set = true;
  db.addAudit(c.user, 'defectdojo.update', 'settings', '', { url: db.dojo.url });
  return db.dojo;
});
on('POST', '/settings/defectdojo/test', 'integrations:manage', async (_m, c) => {
  await sleep(600);
  const url: string = c.body?.url ?? db.dojo.url;
  db.addAudit(c.user, 'defectdojo.test', 'settings', '', {});
  if (!/^https?:\/\//.test(url)) return { ok: false, message: 'Adres musi zaczynać się od http:// lub https://', version: '' };
  if (!db.dojo.api_key_set && !c.body?.api_key) return { ok: false, message: '401 Unauthorized: brak klucza API', version: '' };
  return { ok: true, message: 'Połączono. Użytkownik API: czujka-bot, produkt „' + db.dojo.product_name + '” istnieje.', version: '2.40.1' };
});

function exportData(kind: string, q: URLSearchParams): any[] {
  switch (kind) {
    case 'hosts': return filterHosts(q).map(strip);
    case 'services': return filterServices(q);
    case 'findings': return filterFindings(q);
    case 'changes': return filterChanges(q);
    case 'signatures': return filterSignatures(q);
    default: throw new HttpError(404, 'not_found', 'Nieznany rodzaj eksportu: ' + kind);
  }
}

async function handle(req: Request): Promise<Response> {
  const url = new URL(req.url, location.origin);
  const path = url.pathname.replace(/^\/api\/v1/, '');
  const json = (status: number, data: unknown) => new Response(data === undefined ? null : JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
  await sleep(40 + Math.random() * 90);
  try {
    if (req.method === 'POST' && path === '/auth/login') {
      const b = await req.json();
      const u = db.users.find((x) => x.email === String(b.email ?? '').toLowerCase().trim());
      if (!u || u.disabled || b.password !== 'czujka') { db.addAudit(null, 'auth.login_failed', 'session', '', { email: b.email }); throw new HttpError(401, 'unauthorized', 'Nieprawidłowy adres e-mail lub hasło'); }
      sessionStorage.setItem(SKEY, String(u.id)); u.last_login_at = iso(); db.addAudit(u, 'auth.login', 'session', '', {});
      return json(200, sessionOf(u));
    }
    if (req.method === 'POST' && path === '/auth/logout') { sessionStorage.removeItem(SKEY); return new Response(null, { status: 204 }); }
    const user = currentUser();
    if (!user && path !== '/healthz') throw new HttpError(401, 'unauthorized', 'Sesja wygasła. Zaloguj się ponownie.');
    const perms = user ? sessionOf(user).permissions : [];
    const ex = /^\/export\/(runs\/)?([a-z0-9]+)\.(json|csv|xml)$/.exec(path);
    if (ex && req.method === 'GET') {
      if (!perms.includes('export:run')) throw new HttpError(403, 'forbidden', 'Brak uprawnienia export:run');
      const rows = ex[1] ? db.hosts.slice(0, 40).map(strip) : exportData(ex[2], url.searchParams);
      db.addAudit(user, 'export.run', 'export', ex[2] + '.' + ex[3], { rows: rows.length });
      const body = ex[3] === 'json' ? JSON.stringify(rows, null, 2) : ex[3] === 'csv' ? toCsv(rows) : '<?xml version="1.0"?>\n<nmaprun scanner="czujka" args="export">\n' + rows.map((h: any) => '  <host><status state="' + (h.status === 'up' ? 'up' : 'down') + '"/><address addr="' + h.ip + '" addrtype="ipv4"/></host>').join('\n') + '\n</nmaprun>\n';
      return new Response(body, { status: 200, headers: { 'Content-Type': ex[3] === 'json' ? 'application/json' : ex[3] === 'csv' ? 'text/csv' : 'application/xml' } });
    }
    for (const [method, re, perm, h] of routes) {
      if (method !== req.method) continue;
      const m = re.exec(path);
      if (!m) continue;
      if (perm && !perms.includes(perm)) throw new HttpError(403, 'forbidden', 'Brak uprawnienia ' + perm);
      const ct = req.headers.get('Content-Type') ?? '';
      let body: any = {}, form: FormData | null = null;
      if (req.method !== 'GET' && req.method !== 'DELETE') {
        if (ct.includes('application/json')) { const text = await req.text(); body = text ? JSON.parse(text) : {}; }
        else if (ct.includes('multipart/form-data')) form = await req.formData();
      }
      const out = await h(m as unknown as string[], { q: url.searchParams, body, form, user: user! });
      return out === undefined ? new Response(null, { status: 204 }) : json(200, out);
    }
    throw new HttpError(404, 'not_found', 'Nieznana ścieżka API: ' + req.method + ' ' + path);
  } catch (e) {
    if (e instanceof HttpError) return json(e.status, { error: { code: e.code, message: e.message } });
    console.error(e);
    return json(500, { error: { code: 'internal', message: (e as Error).message } });
  }
}

let installed = false;
export function install() {
  if (installed) return;
  installed = true;
  seedLiveStats();
  setTransport(handle);
  setStreamFactory((path, handlers, onState) => {
    if (!subs.has(path)) subs.set(path, new Set());
    subs.get(path)!.add(handlers);
    setTimeout(() => onState?.(true), 0);
    return { close: () => { subs.get(path)?.delete(handlers); } };
  });
  const speed = Number(localStorage.getItem('czujka.fx.tick') ?? 1000);
  if (speed > 0) setInterval(tick, speed);
  console.info('[czujka] dev fixtures active: ' + db.hosts.length + ' hosts, ' + db.services.length + ' services');
}
