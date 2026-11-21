import { useRef } from 'react';

/**
 * Live lists keep the order in which rows arrived, so a row found by the first
 * port pass never moves when a later pass adds more; rows of one poll arrive in
 * the given order. When the list is not live, finalSort orders it. fresh holds
 * the rows that arrived in the last 1.5 s after the first load (for a short
 * entrance), never the rows of the first load.
 */
export function useArrivalOrder<T extends { id: number }>(items: T[], live: boolean, batchSort: (a: T, b: T) => number, finalSort: (a: T, b: T) => number): { rows: T[]; fresh: Set<number> } {
  const seen = useRef(new Map<number, { n: number; at: number }>());
  const loaded = useRef(false);
  const now = Date.now();
  const map = seen.current;
  const newcomers = items.filter((i) => !map.has(i.id)).sort(batchSort);
  for (const i of newcomers) map.set(i.id, { n: map.size, at: loaded.current ? now : 0 });
  if (items.length) loaded.current = true;
  const fresh = new Set(items.filter((i) => now - (map.get(i.id)?.at ?? 0) < 1500).map((i) => i.id));
  const rows = [...items].sort(live ? (a, b) => (map.get(a.id)?.n ?? 0) - (map.get(b.id)?.n ?? 0) : finalSort);
  return { rows, fresh: live ? fresh : new Set() };
}
