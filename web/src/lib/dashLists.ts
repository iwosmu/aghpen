import type { Change, Finding } from '../api/types';
import { plural, t } from '../i18n';
import { groupFindings, type FindingGroup } from './findingGroups';

export interface AddressRow { ip: string; latest: Change; items: Change[]; spanSec: number }

/**
 * One dashboard row per address: a flapping host takes one row, not six.
 * Expected changes never take a row. Rows follow each address's latest change;
 * the input is newest first.
 */
export function rowsByAddress(changes: Change[], max = 7): AddressRow[] {
  const m = new Map<string, AddressRow>();
  for (const c of changes) {
    if (c.expected) continue;
    const r = m.get(c.ip);
    if (r) r.items.push(c);
    else m.set(c.ip, { ip: c.ip, latest: c, items: [c], spanSec: 0 });
  }
  const rows = [...m.values()];
  for (const r of rows) {
    const times = r.items.map((c) => new Date(c.at).getTime());
    r.spanSec = Math.round((Math.max(...times) - Math.min(...times)) / 1000);
  }
  return rows.slice(0, max);
}

/** "w 2 godz." for the time a run of changes took; '' under a minute. */
export function spanText(sec: number): string {
  if (sec < 60) return '';
  if (sec < 3600) { const m = Math.round(sec / 60); return t('w ' + m + ' min', 'in ' + m + ' min'); }
  if (sec < 48 * 3600) { const h = Math.max(1, Math.round(sec / 3600)); return t('w ' + h + ' godz.', 'in ' + h + ' h'); }
  const d = Math.round(sec / 86400);
  return t('w ' + d + ' ' + plural(d, ['dzień', 'dni', 'dni'], ['', '']).trim(), 'in ' + d + ' days');
}

export interface FindingRow { group: FindingGroup; newest: string; to: string }

/** The worst finding kinds, grouped as on the findings page: one row per kind, at most six. */
export function findingRows(findings: Finding[], max = 6): FindingRow[] {
  return groupFindings(findings).slice(0, max).map((g) => {
    const newest = g.items.reduce((a, f) => (f.first_seen > a ? f.first_seen : a), g.items[0].first_seen);
    const to = '/findings?type=' + encodeURIComponent(g.items[0].type) + '&q=' + encodeURIComponent(g.title);
    return { group: g, newest, to };
  });
}
