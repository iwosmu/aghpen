import type { Window } from '../api/types';

/** True when "now" (in the browser clock) is inside one of the windows; no windows means always open. */
export function windowOpen(windows: Window[], now = new Date()): boolean {
  if (!windows.length) return true;
  const day = now.getDay();
  const min = now.getHours() * 60 + now.getMinutes();
  const m = (s: string) => { const [h, mm] = s.split(':').map(Number); return h * 60 + mm; };
  return windows.some((w) => {
    const s = m(w.start), e = m(w.end);
    if (s <= e) return w.days.includes(day) && min >= s && min < e;
    const prev = (day + 6) % 7;
    return (w.days.includes(day) && min >= s) || (w.days.includes(prev) && min < e);
  });
}
