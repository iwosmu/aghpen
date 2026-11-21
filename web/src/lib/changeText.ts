// Readable details of the change kinds service_returned, response_slower and response_recovered
// (shapes from the integrator's contract: before {away_seconds, runs_away, last_open_at},
// before {baseline_ms, ms} / after {ms} or {ms: null, error}).
import type { Change } from '../api/types';
import { t, plural, getLang } from '../i18n';
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


/**
 * The summary line of a change. The API writes it in Polish; for the change
 * kinds of the one-machine story the English view gets its own sentence.
 */
export function changeSummary(c: Change): string {
  if (getLang() !== 'en') return c.summary;
  const where = c.ip + (c.port ? ':' + c.port : '');
  const usual = field(c.before, 'baseline_ms');
  const usualText = typeof usual === 'number' ? ' (usually ' + fmtMs(usual) + ')' : '';
  switch (c.kind) {
    case 'service_returned': {
      const a = awaySeconds(c), r = runsAway(c);
      return 'Service ' + where + ' is back' + (a && a > 0 ? ' after ' + fmtDuration(a) : '') + (r ? ' (away in ' + r + ' ' + (r === 1 ? 'scan' : 'scans') + ')' : '');
    }
    case 'response_slower': {
      const ms = field(c.after, 'ms');
      return typeof ms === 'number' ? 'Service ' + where + ' responds slower: ' + fmtMs(ms) + usualText : 'Service ' + where + ': the port is open, but HTTP did not answer in time' + usualText;
    }
    case 'response_recovered': {
      const ms = field(c.after, 'ms');
      return 'Service ' + where + ' answers in its usual time again' + (typeof ms === 'number' ? ': ' + fmtMs(ms) : '') + usualText;
    }
    case 'host_gone':
      return 'Host ' + c.ip + ' reported down';
    case 'service_gone':
      return 'Service ' + where + ' is gone';
    case 'host_missing':
      return 'Host ' + c.ip + ' is not answering (unconfirmed): it answered in the previous run; Czujka checks it again';
    case 'service_unreachable':
      return 'Service ' + where + ' is not answering (unconfirmed): the host did not answer in this run';
    default: return c.summary;
  }
}
