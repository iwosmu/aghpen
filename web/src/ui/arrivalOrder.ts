type Seen = { map: Map<number, { n: number; at: number }>; loaded: boolean; live: boolean };
// Per list key (for example the run id), so a remount of the list during a
// run keeps the order the rows arrived in.
const lists = new Map<string, Seen>();

/**
 * Live lists keep the order in which rows arrived, so a row found by the first
 * port pass never moves when a later pass adds more; rows of one poll arrive in
 * batchSort order. A list watched live keeps that order after the run ends; a
 * list opened after the end uses finalSort. fresh holds the rows that arrived
 * in the last 1.5 s after the first load (for a short entrance).
 */
export function useArrivalOrder<T extends { id: number }>(key: string, items: T[], live: boolean, batchSort: (a: T, b: T) => number, finalSort: (a: T, b: T) => number): { rows: T[]; fresh: Set<number> } {
  let s = lists.get(key);
  if (!s) { s = { map: new Map(), loaded: false, live: false }; lists.set(key, s); }
  if (live) s.live = true;
  const now = Date.now();
  const newcomers = items.filter((i) => !s.map.has(i.id)).sort(batchSort);
  for (const i of newcomers) s.map.set(i.id, { n: s.map.size, at: s.loaded ? now : 0 });
  if (items.length) s.loaded = true;
  const byArrival = (a: T, b: T) => (s.map.get(a.id)?.n ?? 0) - (s.map.get(b.id)?.n ?? 0);
  const rows = [...items].sort(s.live ? byArrival : finalSort);
  const fresh = live ? new Set(items.filter((i) => now - (s.map.get(i.id)?.at ?? 0) < 1500).map((i) => i.id)) : new Set<number>();
  return { rows, fresh };
}
