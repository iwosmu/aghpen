import { t } from '../i18n';
import { fmtMs, show } from './format';
import { classLabel, hostStatusInfo, serviceStateInfo } from '../ui/marks';

/** The user-facing name of a change or history field ("state" → "stan"). Unknown fields keep their name. */
export function fieldLabel(field: string, context: 'change' | 'service' = 'change'): string {
  if (field.startsWith('technologies.')) return t('wersja ', 'version of ') + field.slice('technologies.'.length);
  const m: Record<string, [string, string]> = {
    state: ['stan', 'state'],
    status: context === 'service' ? ['kod HTTP', 'HTTP status'] : ['stan hosta', 'host status'],
    name: ['usługa', 'service'], product: ['produkt', 'product'], version: ['wersja', 'version'], banner: ['baner', 'banner'],
    title: ['tytuł strony', 'page title'], certificate: ['certyfikat', 'certificate'], headers: ['nagłówki HTTP', 'HTTP headers'],
    technologies: ['technologie', 'technologies'], classes: ['klasy', 'classes'], hostnames: ['nazwy hosta', 'host names'],
    os_guess: ['system', 'OS'], mac: ['adres MAC', 'MAC address'],
    response_ms: ['czas odpowiedzi', 'response time'], 'http.response_ms': ['czas odpowiedzi', 'response time'],
    'http.title': ['tytuł strony', 'page title'], 'http.status': ['kod HTTP', 'HTTP status'], 'http.headers': ['nagłówki HTTP', 'HTTP headers'],
    'http.cookies': ['ciasteczka', 'cookies'], 'http.body_simhash': ['treść strony (odcisk)', 'page content (fingerprint)'],
    'http.server': ['serwer HTTP', 'HTTP server'], 'http.redirect': ['przekierowanie', 'redirect'], 'http.favicon': ['ikona strony', 'favicon'],
    'tls.sha256': ['certyfikat TLS (odcisk)', 'TLS certificate (fingerprint)'], 'tls.subject': ['certyfikat TLS: podmiot', 'TLS certificate: subject'],
    'tls.issuer': ['certyfikat TLS: wystawca', 'TLS certificate: issuer'], 'tls.not_after': ['certyfikat TLS: ważny do', 'TLS certificate: valid until'],
  };
  const v = m[field];
  return v ? t(v[0], v[1]) : field;
}

/** A field value as the user reads it: states and classes translated, empty as "", objects shortened. */
export function fieldValue(field: string, v: unknown): string {
  if (v === null || v === undefined || v === '') return '';
  if (typeof v === 'object' && !Array.isArray(v)) {
    const o = v as Record<string, unknown>;
    const fp = o.sha256 ?? o.fingerprint ?? o.value;
    if (typeof fp === 'string') return fp.length > 16 ? fp.slice(0, 16) + '…' : fp;
  }
  if (field === 'response_ms' || field === 'http.response_ms') {
    if (typeof v === 'number') return fmtMs(v);
    if (typeof v === 'object' && !Array.isArray(v)) {
      // response_slower / response_recovered: before {baseline_ms, ms}, after {ms} or {ms: null, error}
      const o = v as Record<string, unknown>;
      if (typeof o.baseline_ms === 'number') return t('zwykle ', 'usually ') + fmtMs(o.baseline_ms);
      if (typeof o.ms === 'number') return fmtMs(o.ms);
      if ('ms' in o) return t('brak odpowiedzi HTTP', 'no HTTP response');
    }
  }
  if (field === 'state' && typeof v === 'object' && !Array.isArray(v) && typeof (v as Record<string, unknown>).state === 'string') {
    // service_returned: before {state: "gone", away_seconds, runs_away, ...}
    return fieldValue('state', (v as Record<string, unknown>).state);
  }
  const s = show(v);
  if (field === 'state') return s === 'host-down' ? t('host nieaktywny', 'host down') : s === 'closed' ? t('zamknięta', 'closed') : serviceStateInfo(s).label;
  if (field === 'status' && /^[a-z-]+$/.test(s)) return s === 'not responding' ? t('nie odpowiada', 'not responding') : hostStatusInfo(s).label;
  if (field === 'classes') return s.split(',').filter(Boolean).map((c) => classLabel(c.trim())).join(', ');
  return s;
}
