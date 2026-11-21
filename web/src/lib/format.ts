import { locale, t, plural } from '../i18n';

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ');
}

export function fmtInt(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '–';
  return new Intl.NumberFormat(locale(), { useGrouping: 'always' } as Intl.NumberFormatOptions).format(Math.round(n));
}

export function fmtCompact(n: number): string {
  if (Math.abs(n) < 10000) return fmtInt(n);
  return new Intl.NumberFormat(locale(), { notation: 'compact', maximumFractionDigits: 1 }).format(n);
}

export function fmtPct(x: number, digits = 0): string {
  return new Intl.NumberFormat(locale(), { style: 'percent', maximumFractionDigits: digits }).format(x);
}

export function fmtSigned(n: number): string {
  if (n === 0) return '0';
  return (n > 0 ? '+' : '−') + fmtInt(Math.abs(n));
}

/** A date the server really set. Go writes an unset time as year 1. */
export function realDate(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime()) || d.getUTCFullYear() < 1971) return null;
  return d;
}

export function fmtDateTime(iso: string | null | undefined): string {
  const d = realDate(iso);
  if (!d) return '–';
  return new Intl.DateTimeFormat(locale(), { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(d);
}

export function fmtDate(iso: string | null | undefined): string {
  const d = realDate(iso);
  if (!d) return '–';
  return new Intl.DateTimeFormat(locale(), { year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
}

export function fmtTime(iso: string | null | undefined): string {
  const d = realDate(iso);
  if (!d) return '–';
  return new Intl.DateTimeFormat(locale(), { hour: '2-digit', minute: '2-digit' }).format(d);
}

/** "3 min temu", "za 2 h". */
export function fmtRelative(iso: string | null | undefined, now = Date.now()): string {
  const real = realDate(iso);
  if (!real) return '–';
  const diff = real.getTime() - now;
  const abs = Math.abs(diff);
  const rtf = new Intl.RelativeTimeFormat(locale(), { numeric: 'auto', style: 'short' });
  if (abs < 45_000) return t('przed chwilą', 'just now');
  if (abs < 3_600_000) return rtf.format(Math.round(diff / 60_000), 'minute');
  if (abs < 86_400_000) return rtf.format(Math.round(diff / 3_600_000), 'hour');
  if (abs < 30 * 86_400_000) return rtf.format(Math.round(diff / 86_400_000), 'day');
  return fmtDate(iso);
}

/** 4310 -> "1 h 11 min", 95 -> "1 min 35 s". */
export function fmtDuration(sec: number | null | undefined): string {
  if (sec === null || sec === undefined || sec < 0 || !Number.isFinite(sec)) return '–';
  const s = Math.round(sec);
  if (s < 60) return s + ' s';
  const m = Math.floor(s / 60);
  if (m < 60) return m + ' min ' + (s % 60 ? (s % 60) + ' s' : '').trim();
  const h = Math.floor(m / 60);
  if (h < 48) return h + ' h ' + (m % 60 ? (m % 60) + ' min' : '').trim();
  const d = Math.floor(h / 24);
  return d + ' ' + plural(d, ['dzień', 'dni', 'dni'], ['day', 'days']) + ' ' + (h % 24) + ' h';
}

export function fmtBytes(n: number): string {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' kB';
  return (n / 1024 / 1024).toFixed(1) + ' MB';
}

export function shortHash(h: string | null | undefined, n = 12): string {
  if (!h) return '–';
  return h.length > n ? h.slice(0, n) + '…' : h;
}

export function ipToNum(ip: string): number {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

export function show(v: unknown): string {
  if (v === null || v === undefined || v === '') return '–';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (Array.isArray(v)) return v.map(show).join(', ');
  return JSON.stringify(v);
}

export const WEEKDAYS_PL = ['nd', 'pn', 'wt', 'śr', 'cz', 'pt', 'sb'];
export const WEEKDAYS_EN = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
export function weekday(i: number): string { return t(WEEKDAYS_PL[i], WEEKDAYS_EN[i]); }
/** Monday-first display order of weekday indexes (0 = Sunday on the wire). */
export const WEEK_ORDER = [1, 2, 3, 4, 5, 6, 0];
