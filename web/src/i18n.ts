// Small i18n layer. Every UI string is written as a Polish/English pair at the
// call site: t('Zakresy', 'Scopes'). Polish is the default language.
import { useSyncExternalStore } from 'react';

export type Lang = 'pl' | 'en';

function initial(): Lang {
  try {
    const v = localStorage.getItem('czujka.lang');
    if (v === 'pl' || v === 'en') return v;
  } catch { /* storage not available */ }
  return 'pl';
}

let lang: Lang = initial();
const listeners = new Set<() => void>();

export function getLang(): Lang { return lang; }
export function setLang(l: Lang) {
  lang = l;
  try { localStorage.setItem('czujka.lang', l); } catch { /* ignore */ }
  if (typeof document !== 'undefined') document.documentElement.lang = l;
  listeners.forEach((fn) => fn());
}
export function useLang(): Lang {
  return useSyncExternalStore((fn) => { listeners.add(fn); return () => listeners.delete(fn); }, () => lang);
}

export function t(pl: string, en: string): string { return lang === 'pl' ? pl : en; }

/** Polish has three plural forms: 1 host, 2 hosty, 5 hostów. */
export function plural(n: number, pl: [string, string, string], en: [string, string]): string {
  if (lang === 'en') return n === 1 ? en[0] : en[1];
  const a = Math.abs(n);
  if (a === 1) return pl[0];
  const d = a % 10, h = a % 100;
  if (d >= 2 && d <= 4 && !(h >= 12 && h <= 14)) return pl[1];
  return pl[2];
}

export function locale(): string { return lang === 'pl' ? 'pl-PL' : 'en-GB'; }
