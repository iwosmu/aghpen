import type { Finding } from '../api/types';

const SEV_RANK: Record<string, number> = { high: 3, medium: 2, low: 1, info: 0 };

/** The title without the address it repeats ("Panel … — 10.66.10.11:8080", "… (10.66.70.11:31337)"). */
export function baseTitle(title: string): string {
  return title
    .replace(/\s+[—–-]\s+(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\s*$/, '')
    .replace(/\s*\((?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\)\s*$/, '')
    .trim();
}

/** What a finding is: the rule for a policy violation, otherwise its type and title without the address. */
export function groupKey(f: Pick<Finding, 'type' | 'signature' | 'title'>): string {
  if (f.type === 'policy-violation' && f.signature) return f.signature;
  return f.type + '|' + baseTitle(f.title);
}

export interface FindingGroup {
  key: string;
  title: string;
  items: Finding[];
  /** distinct address:port pairs (or addresses) */
  places: number;
  severity: string;
  interest: number;
  statuses: Record<string, number>;
}

/** Groups findings by what they are; the order follows the highest interest, then severity, then size. */
export function groupFindings(list: Finding[]): FindingGroup[] {
  const m = new Map<string, FindingGroup>();
  for (const f of list) {
    const k = groupKey(f);
    let g = m.get(k);
    if (!g) { g = { key: k, title: baseTitle(f.title), items: [], places: 0, severity: f.severity, interest: f.interest, statuses: {} }; m.set(k, g); }
    g.items.push(f);
    if ((SEV_RANK[f.severity] ?? 0) > (SEV_RANK[g.severity] ?? 0)) g.severity = f.severity;
    g.interest = Math.max(g.interest, f.interest);
    g.statuses[f.status] = (g.statuses[f.status] ?? 0) + 1;
  }
  for (const g of m.values()) {
    g.places = new Set(g.items.map((f) => (f.ip ?? '') + ':' + (f.port ?? ''))).size;
    g.items.sort((a, b) => b.interest - a.interest || String(a.ip).localeCompare(String(b.ip), undefined, { numeric: true }) || (a.port ?? 0) - (b.port ?? 0));
  }
  return [...m.values()].sort((a, b) => b.interest - a.interest || (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0) || b.items.length - a.items.length || a.title.localeCompare(b.title));
}
