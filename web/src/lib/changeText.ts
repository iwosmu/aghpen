// Readable details of the change kinds service_returned, response_slower and response_recovered
// (shapes from the integrator's contract: before {away_seconds, runs_away, last_open_at},
// before {baseline_ms, ms} / after {ms} or {ms: null, error}).
import type { Change } from '../api/types';
import { t, plural } from '../i18n';
import { fmtDuration, fmtMs } from './format';

function field(v: unknown, k: string): unknown {
  return v && typeof v === 'object' ? (v as Record<string, unknown>)[k] : undefined;
}

/** Scans the service was away: before.runs_away. */
export function runsAway(c: Change): number | null {
  const n = field(c.before, 'runs_away');
  return typeof n === 'number' ? n : null;
}

/** How long a returned service was away: before.away_seconds (or the time since before.last_open_at). */
export function awaySeconds(c: Change): number | null {
  const pick = (v: unknown): number | null => {
    if (v && typeof v === 'object') {
      const o = v as Record<string, unknown>;
      if (typeof o.away_seconds === 'number') return o.away_seconds;
      if (typeof o.last_open_at === 'string') { const d = Date.parse(o.last_open_at); return Number.isNaN(d) ? null : (Date.parse(c.at) - d) / 1000; }
    }
    return null;
  };
  return pick(c.after) ?? pick(c.before);
}

/** "120 ms → 640 ms" for a response-time change (before.baseline_ms → after.ms), or ''. */
export function responseDelta(c: Change): string {
  const ms = field(c.after, 'ms');
  // Never two equal values with an arrow: then only the current one.
  const arrow = (a: string, b: string) => (a === b ? t('teraz ', 'now ') + b : a + ' → ' + b);
  if (c.kind === 'response_recovered') {
    // from the slow answer (or no answer) back to the usual time: "901 ms → 1 ms"
    const was = field(c.before, 'ms');
    if (typeof ms !== 'number') return '';
    return arrow(typeof was === 'number' ? fmtMs(was) : t('nie odpowiadała', 'no response'), fmtMs(ms));
  }
  const base = field(c.before, 'baseline_ms') ?? field(c.before, 'ms');
  if (typeof base !== 'number') return '';
  if (typeof ms === 'number') return arrow(fmtMs(base), fmtMs(ms));
  if (ms === null || field(c.after, 'error')) return fmtMs(base) + ' → ' + t('brak odpowiedzi HTTP', 'no HTTP response');
  return '';
}

/** "nie było jej 5 min (1 skan)" for a returned service, or ''. */
export function awayText(c: Change): string {
  const a = awaySeconds(c), r = runsAway(c);
  if (!a || a <= 0) return '';
  const runs = r ? ' (' + r + ' ' + plural(r, ['skan', 'skany', 'skanów'], ['scan', 'scans']) + ')' : '';
  return t('nie było jej ' + fmtDuration(a), 'away for ' + fmtDuration(a)) + runs;
}
