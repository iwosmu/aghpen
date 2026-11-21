import { getLang, t } from '../i18n';
import type { ScanRun } from '../api/types';
import { fmtInt } from './format';

/** Names of exposed admin panels, from the finding titles ("Panel administracyjny: pgAdmin (10.66.10.50:80)"). */
export function adminPanelNames(findings: { title: string; status: string }[]): string[] {
  const names: string[] = [];
  for (const f of findings) {
    if (f.status !== 'new' && f.status !== 'triaged') continue;
    const m = f.title.match(/^(?:Panel administracyjny|Admin panel):\s*(.+?)\s*\(/);
    if (m && !names.includes(m[1])) names.push(m[1]);
  }
  return names;
}

/** Names of exposed admin panels from services with the admin-panel class: the panel technology, else the page title. */
export function adminPanelServiceNames(services: { classes: string[] | null; title: string; product: string; technologies: { name: string; category: string }[] | null }[]): string[] {
  const names: string[] = [];
  const panels = services.filter((s) => (s.classes ?? []).includes('admin-panel'));
  // Panel products first (pgAdmin, phpMyAdmin, Portainer), then the CMS or server behind a panel, then the page title.
  const tiers: ((s: (typeof panels)[number]) => string | undefined)[] = [
    (s) => (s.technologies ?? []).find((x) => ['panel', 'database', 'devops'].includes(x.category))?.name,
    (s) => (s.technologies ?? []).find((x) => ['cms', 'app-server'].includes(x.category))?.name,
    (s) => s.title || s.product,
  ];
  // Each service gives one name, from its best tier; services with a panel product come first.
  const picked = panels.map((s) => { for (let i = 0; i < tiers.length; i++) { const n = tiers[i](s); if (n) return { n, i }; } return null; });
  for (const p of picked.filter((x) => x !== null).sort((a, b) => a.i - b.i)) if (!names.includes(p.n)) names.push(p.n);
  return names;
}

/** Parts of the change sentence, only the counts that are not zero. */
export function changeParts(c: { added: number; gone: number; changed: number; missing: number; unstable: number }, lang: 'pl' | 'en', plural: (n: number, pl: [string, string, string], en: [string, string]) => string): string[] {
  const parts: string[] = [];
  const add = (n: number, pl: [string, string, string], en: [string, string]) => { if (n > 0) parts.push(n + ' ' + plural(n, pl, en)); };
  void lang;
  add(c.added, ['nowa ekspozycja', 'nowe ekspozycje', 'nowych ekspozycji'], ['new exposure', 'new exposures']);
  add(c.gone, ['zniknięcie', 'zniknięcia', 'zniknięć'], ['gone', 'gone']);
  add(c.changed, ['zmiana', 'zmiany', 'zmian'], ['change', 'changes']);
  add(c.missing, ['host bez odpowiedzi', 'hosty bez odpowiedzi', 'hostów bez odpowiedzi'], ['host missing', 'hosts missing']);
  add(c.unstable, ['host niestabilny', 'hosty niestabilne', 'hostów niestabilnych'], ['unstable host', 'unstable hosts']);
  return parts;
}

/** Interest from which an open finding counts as needing a look. */
export const ATTENTION_INTEREST = 70;

/** A reported rate counts as over the cap above this margin (the limiter allows short bursts). */
export function overCap(current: number, cap: number): boolean {
  return cap > 0 && current > cap * 1.05;
}

/** What the live rate is: the set nmap pace, or a measurement from exact packet counts. */
export function paceTip(): string {
  return t('To tempo zadane nmap (--min-rate/--max-rate) dla etapów, które jeszcze trwają, nie pomiar. Dokładna liczba pakietów przychodzi po zakończeniu etapu.', 'This is the pace set for nmap (--min-rate/--max-rate) in stages still running, not a measurement. The exact packet count arrives when a stage ends.');
}

/** Triggers whose runs see only part of the network (they add facts, they do not show a change of it). */
export const PARTIAL_TRIGGERS = ['reprobe', 'manual-entry', 'import'];

/** A full run: a completed run of a profile over its whole scope (not ad hoc, not a re-probe, import or manual entry). */
export function isFullRun(r: Pick<ScanRun, 'status' | 'profile_id' | 'trigger' | 'ad_hoc'>): boolean {
  return r.status === 'completed' && r.profile_id != null && !r.ad_hoc && !PARTIAL_TRIGGERS.includes(r.trigger);
}

/** The last full run and the full run of the same profile before it, from runs in any order. */
export function lastFullPair(runs: ScanRun[]): { full?: ScanRun; prev?: ScanRun } {
  const sorted = [...runs].sort((a, b) => b.id - a.id);
  const full = sorted.find(isFullRun);
  if (!full) return {};
  const prev = sorted.find((r) => r.id < full.id && isFullRun(r) && r.profile_id === full.profile_id);
  return { full, prev };
}

/** One short phrase for a partial run: what it looked at. */
export function partialRunPhrase(r: ScanRun): string {
  const n = r.stats?.addresses_total ?? 0;
  if (r.trigger === 'import') return t('import pliku', 'a file import') + (r.import_file ? ' ' + r.import_file : '');
  if (r.trigger === 'manual-entry') return t('wpis ręczny', 'a manual entry');
  const what = r.trigger === 'reprobe' && !r.ad_hoc?.reason ? t('ponowne sprawdzenie', 're-probe') : t('sprawdzenie', 'a check of');
  return what + ' ' + fmtInt(n) + ' ' + (getLang() === 'pl' ? (n === 1 ? 'adresu' : 'adresów') : n === 1 ? 'address' : 'addresses');
}

