import type { ReactNode } from 'react';
import { cx, fmtPct } from '../lib/format';
import { t } from '../i18n';
import type { ChangeKind, ChunkStatus, FindingStatus, HostStatus, InterestReason, RunStatus, ServiceState, Severity } from '../api/types';

// State marks. Every state is a drawn glyph plus a colour plus a word, so
// colour is never the only signal.
export type Tone = 'new' | 'gone' | 'changed' | 'unstable' | 'expected' | 'neutral' | 'accent' | 'danger';
export type GlyphName = 'plus' | 'minus' | 'delta' | 'wave' | 'dashring' | 'dot' | 'ring' | 'check' | 'x' | 'pause' | 'run' | 'half' | 'back' | 'hatch' | 'returned' | 'slow';

const TONE_VAR: Record<Tone, string> = {
  new: 'var(--st-new)', gone: 'var(--st-gone)', changed: 'var(--st-changed)', unstable: 'var(--st-unstable)',
  expected: 'var(--st-expected)', neutral: 'var(--ink-2)', accent: 'var(--accent)', danger: 'var(--danger)',
};
export function toneColor(tone: Tone): string { return TONE_VAR[tone]; }

export function Glyph({ name, tone = 'neutral', size = 14, pulse }: { name: GlyphName; tone?: Tone; size?: number; pulse?: boolean }) {
  const c = TONE_VAR[tone];
  const s = { stroke: c, strokeWidth: 2, fill: 'none', strokeLinecap: 'square' as const };
  let body: ReactNode;
  switch (name) {
    case 'plus': body = <path d="M7 2.5v9M2.5 7h9" {...s} />; break;
    case 'minus': body = <path d="M2.5 7h9" {...s} />; break;
    case 'delta': body = <path d="M7 2.2 12.2 11.5H1.8Z" fill={c} />; break;
    case 'wave': body = <path d="M1 7c1.5-3.6 3-3.6 4.500 0s3 3.600 4.500 0 2-2.400 3-1.400" {...s} strokeWidth={1.8} />; break;
    case 'dashring': body = <circle cx="7" cy="7" r="4.6" {...s} strokeWidth={1.6} strokeDasharray="2.4 2.2" strokeLinecap="butt" />; break;
    case 'dot': body = <circle cx="7" cy="7" r="3.6" fill={c} />; break;
    case 'ring': body = <circle cx="7" cy="7" r="4.2" {...s} strokeWidth={1.6} />; break;
    case 'half': body = <><circle cx="7" cy="7" r="4.2" {...s} strokeWidth={1.6} /><path d="M7 2.800a4.200 4.200 0 0 1 0 8.400Z" fill={c} /></>; break;
    case 'check': body = <path d="M2.500 7.500 5.500 10.500 11.500 3.500" {...s} />; break;
    case 'x': body = <path d="M3.200 3.200l7.600 7.600M10.800 3.200l-7.600 7.600" {...s} />; break;
    case 'pause': body = <path d="M4.500 3v8M9.500 3v8" {...s} />; break;
    case 'run': body = <path d="M4 2.500v9l7.500-4.500Z" fill={c} />; break;
    case 'back': body = <path d="M11.500 10V5.500H3.500M6 3 3.500 5.500 6 8" {...s} strokeWidth={1.8} />; break;
    case 'hatch': body = <path d="M2 12 12 2M2 7.500 7.500 2M6.500 12 12 6.500" {...s} strokeWidth={1.4} />; break;
    // a circular arrow: the same service is open again
    case 'returned': body = <><path d="M11.300 7.400A4.300 4.300 0 1 1 9.600 3.600" {...s} strokeWidth={1.7} strokeLinecap="butt" /><path d="M8.300 1.600 11.200 3.300 9.200 6" {...s} strokeWidth={1.7} /></>; break;
    // a clock: the response time moved
    case 'slow': body = <><circle cx="7" cy="7" r="4.900" {...s} strokeWidth={1.6} /><path d="M7 4v3.300l2.300 1.400" {...s} strokeWidth={1.6} strokeLinecap="butt" /></>; break;
  }
  return (
    <svg viewBox="0 0 14 14" width={size} height={size} aria-hidden="true" style={{ flex: 'none', animation: pulse ? 'pulse-ring 1.6s ease-in-out infinite' : undefined }}>
      {body}
    </svg>
  );
}

export function Mark({ glyph, tone, children, pulse, title, className }: { glyph: GlyphName; tone: Tone; children?: ReactNode; pulse?: boolean; title?: string; className?: string }) {
  return (
    <span className={cx('inline-flex items-center gap-1.5 whitespace-nowrap', className)} title={title}>
      <Glyph name={glyph} tone={tone} pulse={pulse} />
      {children !== undefined ? <span>{children}</span> : null}
    </span>
  );
}

// ---------- Change kinds ----------
export function changeKindInfo(kind: ChangeKind | string): { tone: Tone; glyph: GlyphName; label: string; group: 'new' | 'gone' | 'changed' | 'unstable' } {
  switch (kind) {
    case 'host_new': return { tone: 'new', glyph: 'plus', label: t('nowy host', 'new host'), group: 'new' };
    case 'host_back': return { tone: 'new', glyph: 'back', label: t('host wrócił', 'host is back'), group: 'new' };
    case 'service_new': return { tone: 'new', glyph: 'plus', label: t('nowa usługa', 'new service'), group: 'new' };
    case 'tech_new': return { tone: 'new', glyph: 'plus', label: t('nowa technologia', 'new technology'), group: 'new' };
    case 'host_gone': return { tone: 'gone', glyph: 'minus', label: t('host nieaktywny', 'host down'), group: 'gone' };
    case 'service_gone': return { tone: 'gone', glyph: 'minus', label: t('usługa zniknęła', 'service gone'), group: 'gone' };
    case 'service_returned': return { tone: 'new', glyph: 'returned', label: t('usługa wróciła', 'service is back'), group: 'new' };
    case 'response_slower': return { tone: 'changed', glyph: 'slow', label: t('usługa odpowiada wolniej', 'service responds slower'), group: 'changed' };
    case 'response_recovered': return { tone: 'new', glyph: 'slow', label: t('usługa znów szybka', 'service fast again'), group: 'changed' };
    case 'tech_gone': return { tone: 'gone', glyph: 'minus', label: t('technologia zniknęła', 'technology gone'), group: 'gone' };
    case 'host_unstable': return { tone: 'unstable', glyph: 'wave', label: t('host niestabilny', 'host unstable'), group: 'unstable' };
    // Silent in this run, answered in the previous one; not reported inactive yet. Its services are unknown, not gone.
    case 'host_missing': return { tone: 'changed', glyph: 'half', label: t('host nie odpowiada (niepotwierdzone)', 'host not responding (unconfirmed)'), group: 'gone' };
    case 'service_unreachable': return { tone: 'changed', glyph: 'half', label: t('usługa nie odpowiada (niepotwierdzone)', 'service not responding (unconfirmed)'), group: 'gone' };
    case 'service_changed': return { tone: 'changed', glyph: 'delta', label: t('usługa zmieniona', 'service changed'), group: 'changed' };
    case 'tech_version': return { tone: 'changed', glyph: 'delta', label: t('zmiana wersji', 'version changed'), group: 'changed' };
    case 'title_changed': return { tone: 'changed', glyph: 'delta', label: t('zmiana tytułu', 'title changed'), group: 'changed' };
    case 'status_changed': return { tone: 'changed', glyph: 'delta', label: t('zmiana kodu HTTP', 'HTTP status changed'), group: 'changed' };
    case 'cert_changed': return { tone: 'changed', glyph: 'delta', label: t('zmiana certyfikatu', 'certificate changed'), group: 'changed' };
    case 'headers_changed': return { tone: 'changed', glyph: 'delta', label: t('zmiana nagłówków', 'headers changed'), group: 'changed' };
    case 'cookies_changed': return { tone: 'changed', glyph: 'delta', label: t('zmiana ciasteczek', 'cookies changed'), group: 'changed' };
    case 'content_changed': return { tone: 'changed', glyph: 'delta', label: t('zmiana treści', 'content changed'), group: 'changed' };
    case 'redirect_changed': return { tone: 'changed', glyph: 'delta', label: t('zmiana przekierowania', 'redirect changed'), group: 'changed' };
    case 'class_changed': return { tone: 'changed', glyph: 'delta', label: t('zmiana klasy', 'class changed'), group: 'changed' };
    default: return { tone: 'changed', glyph: 'delta', label: String(kind), group: 'changed' };
  }
}

export const CHANGE_KINDS: ChangeKind[] = [
  'host_new', 'host_gone', 'host_missing', 'service_unreachable', 'host_back', 'host_unstable', 'service_new', 'service_gone', 'service_returned', 'service_changed',
  'response_slower', 'response_recovered', 'tech_new',
  'tech_gone', 'tech_version', 'title_changed', 'status_changed', 'cert_changed', 'headers_changed', 'cookies_changed',
  'content_changed', 'redirect_changed', 'class_changed',
];

export function ChangeMark({ kind, expected }: { kind: ChangeKind | string; expected?: boolean }) {
  const i = changeKindInfo(kind);
  if (expected) {
    return <Mark glyph="dashring" tone="expected" title={t('Zmiana zgodna ze wzorcem dostępności hosta', 'The change fits the host availability pattern')}><span className="text-ink-3">{i.label} · {t('oczekiwana', 'expected')}</span></Mark>;
  }
  return <Mark glyph={i.glyph} tone={i.tone}>{i.label}</Mark>;
}

// ---------- Host, service, run, chunk status ----------
export function hostStatusInfo(s: HostStatus | string): { tone: Tone; glyph: GlyphName; label: string } {
  switch (s) {
    case 'up': return { tone: 'neutral', glyph: 'dot', label: t('aktywny', 'up') };
    case 'unstable': return { tone: 'unstable', glyph: 'wave', label: t('niestabilny', 'unstable') };
    case 'down': return { tone: 'gone', glyph: 'minus', label: t('nieaktywny', 'down') };
    case 'expected-offline': return { tone: 'expected', glyph: 'dashring', label: t('poza godzinami', 'outside usual hours') };
    default: return { tone: 'expected', glyph: 'ring', label: t('nieznany', 'unknown') };
  }
}
export const HOST_STATUSES: HostStatus[] = ['up', 'unstable', 'expected-offline', 'down', 'unknown'];
export function HostStatusMark({ status }: { status: HostStatus | string }) {
  const i = hostStatusInfo(status);
  return <Mark glyph={i.glyph} tone={i.tone}>{i.label}</Mark>;
}

export function serviceStateInfo(s: ServiceState | string): { tone: Tone; glyph: GlyphName; label: string } {
  switch (s) {
    case 'open': return { tone: 'neutral', glyph: 'dot', label: t('otwarta', 'open') };
    case 'gone': return { tone: 'gone', glyph: 'minus', label: t('zniknęła', 'gone') };
    case 'filtered': return { tone: 'expected', glyph: 'half', label: t('filtrowana', 'filtered') };
    default: return { tone: 'expected', glyph: 'ring', label: t('nieznana', 'unknown') };
  }
}
export function ServiceStateMark({ state }: { state: ServiceState | string }) {
  const i = serviceStateInfo(state);
  return <Mark glyph={i.glyph} tone={i.tone}>{i.label}</Mark>;
}

export function runStatusInfo(s: RunStatus | string, pauseReason?: string): { tone: Tone; glyph: GlyphName; label: string; live: boolean } {
  switch (s) {
    case 'queued': return { tone: 'expected', glyph: 'ring', label: t('w kolejce', 'queued'), live: false };
    case 'running': return { tone: 'accent', glyph: 'run', label: t('w toku', 'running'), live: true };
    case 'analyzing': return { tone: 'accent', glyph: 'half', label: t('analiza', 'analysing'), live: true };
    case 'paused': {
      const why = pauseReason === 'window_closed' ? t('okno zamknięte', 'window closed') : pauseReason === 'emergency_stop' ? t('stop awaryjny', 'emergency stop') : pauseReason === 'restart' ? t('restart serwera', 'server restart') : t('ręcznie', 'manual');
      return { tone: pauseReason === 'emergency_stop' ? 'danger' : 'changed', glyph: 'pause', label: t('wstrzymany', 'paused') + ' · ' + why, live: false };
    }
    case 'completed': return { tone: 'neutral', glyph: 'check', label: t('zakończony', 'completed'), live: false };
    case 'failed': return { tone: 'danger', glyph: 'x', label: t('błąd', 'failed'), live: false };
    case 'cancelled': return { tone: 'expected', glyph: 'x', label: t('anulowany', 'cancelled'), live: false };
    default: return { tone: 'expected', glyph: 'ring', label: String(s), live: false };
  }
}
export const RUN_STATUSES: RunStatus[] = ['queued', 'running', 'paused', 'analyzing', 'completed', 'failed', 'cancelled'];
export function RunStatusMark({ status, pauseReason }: { status: RunStatus | string; pauseReason?: string }) {
  const i = runStatusInfo(status, pauseReason);
  return <Mark glyph={i.glyph} tone={i.tone} pulse={i.live}>{i.label}</Mark>;
}

export function chunkStatusInfo(s: ChunkStatus | string): { tone: Tone; glyph: GlyphName; label: string } {
  switch (s) {
    case 'pending': return { tone: 'expected', glyph: 'ring', label: t('oczekuje', 'pending') };
    case 'running': return { tone: 'accent', glyph: 'run', label: t('w toku', 'running') };
    case 'done': return { tone: 'neutral', glyph: 'check', label: t('gotowy', 'done') };
    case 'deferred': return { tone: 'changed', glyph: 'hatch', label: t('odroczony', 'deferred') };
    case 'failed': return { tone: 'danger', glyph: 'x', label: t('błąd', 'failed') };
    default: return { tone: 'expected', glyph: 'ring', label: String(s) };
  }
}
export function ChunkStatusMark({ status }: { status: ChunkStatus | string }) {
  const i = chunkStatusInfo(status);
  return <Mark glyph={i.glyph} tone={i.tone} pulse={status === 'running'}>{i.label}</Mark>;
}

// ---------- Severity: signal bars plus a word ----------
const SEV_LEVEL: Record<string, number> = { info: 1, low: 2, medium: 3, high: 4 };
export const SEVERITIES: Severity[] = ['high', 'medium', 'low', 'info'];
export function severityLabel(s: Severity | string): string {
  switch (s) {
    case 'high': return t('wysoka', 'high');
    case 'medium': return t('średnia', 'medium');
    case 'low': return t('niska', 'low');
    default: return t('informacyjna', 'info');
  }
}
export function Sev({ level, compact }: { level: Severity | string; compact?: boolean }) {
  const n = SEV_LEVEL[level] ?? 1;
  const color = n === 4 ? 'var(--st-gone)' : n === 3 ? 'var(--st-changed)' : n === 2 ? 'var(--accent)' : 'var(--ink-3)';
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap" title={t('Waga: ', 'Severity: ') + severityLabel(level)}>
      <svg viewBox="0 0 14 14" width="14" height="14" aria-hidden="true" style={{ flex: 'none' }}>
        {[0, 1, 2, 3].map((i) => (
          <rect key={i} x={1 + i * 3.2} y={10.5 - i * 2.6} width="2.200" height={2.5 + i * 2.6} fill={i < n ? color : 'var(--rule-strong)'} />
        ))}
      </svg>
      {compact ? <span className="sr-only">{severityLabel(level)}</span> : <span>{severityLabel(level)}</span>}
    </span>
  );
}

// ---------- Finding status ----------
export const FINDING_STATUSES: FindingStatus[] = ['new', 'triaged', 'accepted', 'false_positive', 'resolved'];
export function findingStatusInfo(s: FindingStatus | string): { tone: Tone; glyph: GlyphName; label: string } {
  switch (s) {
    case 'new': return { tone: 'accent', glyph: 'dot', label: t('nowe', 'new') };
    case 'triaged': return { tone: 'neutral', glyph: 'half', label: t('w analizie', 'in analysis') };
    case 'accepted': return { tone: 'neutral', glyph: 'check', label: t('zaakceptowane', 'accepted') };
    case 'false_positive': return { tone: 'expected', glyph: 'x', label: t('fałszywy alarm', 'false positive') };
    case 'resolved': return { tone: 'expected', glyph: 'ring', label: t('rozwiązane', 'resolved') };
    default: return { tone: 'expected', glyph: 'ring', label: String(s) };
  }
}
export function FindingStatusMark({ status }: { status: FindingStatus | string }) {
  const i = findingStatusInfo(status);
  return <Mark glyph={i.glyph} tone={i.tone}>{i.label}</Mark>;
}

// ---------- Classes and categories ----------
export function classLabel(c: string): string {
  const m: Record<string, [string, string]> = {
    'admin-panel': ['panel administracyjny', 'admin panel'], login: ['strona logowania', 'login page'],
    staging: ['środowisko testowe', 'staging'], iot: ['urządzenie IoT', 'IoT device'],
    'default-page': ['strona domyślna', 'default page'], api: ['API', 'API'], 'dev-tool': ['narzędzie deweloperskie', 'dev tool'],
    database: ['baza danych', 'database'], 'remote-access': ['zdalny dostęp', 'remote access'],
    'directory-listing': ['listing katalogu', 'directory listing'], 'error-page': ['strona błędu', 'error page'],
  };
  const v = m[c];
  return v ? t(v[0], v[1]) : c;
}
export const SERVICE_CLASSES = ['admin-panel', 'login', 'staging', 'iot', 'default-page', 'api', 'dev-tool', 'database', 'remote-access', 'directory-listing', 'error-page'];

export function ClassChips({ classes, max = 3 }: { classes: string[] | null | undefined; max?: number }) {
  if (!classes || classes.length === 0) return null;
  return (
    <span className={max <= 1 ? 'inline-flex items-center gap-1 whitespace-nowrap' : 'inline-flex flex-wrap items-center gap-1'}>
      {classes.slice(0, max).map((c) => (
        <span key={c} className="inline-flex h-[18px] items-center rounded-sm bg-accent-wash px-1.5 text-2xs text-ink">{classLabel(c)}</span>
      ))}
      {classes.length > max ? <span className="text-xs text-ink-3">+{classes.length - max}</span> : null}
    </span>
  );
}

export function categoryLabel(c: string): string {
  const m: Record<string, [string, string]> = {
    cms: ['CMS', 'CMS'], framework: ['framework', 'framework'], 'app-server': ['serwer aplikacyjny', 'app server'],
    'web-server': ['serwer WWW', 'web server'], iot: ['IoT', 'IoT'], panel: ['panel', 'panel'], database: ['baza danych', 'database'],
    devops: ['DevOps', 'DevOps'], language: ['język', 'language'], proxy: ['proxy', 'proxy'], security: ['bezpieczeństwo', 'security'],
    os: ['system', 'OS'], library: ['biblioteka', 'library'], environment: ['środowisko', 'environment'],
    header: ['nagłówek', 'header'], cookie: ['ciasteczko', 'cookie'], other: ['inne', 'other'],
  };
  const v = m[c];
  return v ? t(v[0], v[1]) : c;
}
export const TECH_CATEGORIES = ['cms', 'framework', 'app-server', 'web-server', 'iot', 'panel', 'database', 'devops', 'language', 'proxy', 'security', 'os', 'library', 'environment', 'header', 'cookie', 'other'];

// ---------- Scores: never a bare number ----------
export function InterestScore({ value, reasons, showTip }: { value: number; reasons?: InterestReason[] | null; showTip?: (e: React.MouseEvent | React.FocusEvent, body: ReactNode) => void }) {
  const tone = value >= 70 ? 'var(--st-gone)' : value >= 40 ? 'var(--st-changed)' : 'var(--ink-3)';
  const title = reasons && reasons.length ? reasons.map((r) => '+' + r.points + ' ' + r.text).join('\n') : undefined;
  return (
    <span className="inline-flex items-center gap-1.5" title={showTip ? undefined : title}>
      <span className="num w-[22px] text-right text-sm text-ink">{value}</span>
      <span className="relative h-[4px] w-[34px] bg-rule" aria-hidden="true">
        <span className="absolute inset-y-0 left-0" style={{ width: Math.min(100, value) + '%', background: tone }} />
      </span>
    </span>
  );
}

export function InterestBreakdown({ value, reasons }: { value: number; reasons: InterestReason[] | null | undefined }) {
  const list = reasons ?? [];
  const sum = list.reduce((a, r) => a + r.points, 0);
  return (
    <div>
      <div className="flex items-baseline gap-2">
        <span className="text-xl font-semibold leading-none text-ink">{value}</span>
        <span className="text-xs text-ink-3">/ 100 · {t('ocena ciekawości', 'interest score')}</span>
      </div>
      {list.length === 0 ? (
        <p className="mt-2 text-sm text-ink-2">{t('Brak czynników podnoszących ocenę.', 'No factor raises the score.')}</p>
      ) : (
        <ul className="mt-2">
          {list.map((r, i) => (
            <li key={i} className="flex min-h-[26px] items-center gap-2 border-b border-rule py-1 last:border-b-0">
              <span className="num w-[34px] flex-none text-right text-sm text-ink">+{r.points}</span>
              <span className="h-[4px] flex-none bg-accent" style={{ width: Math.max(3, Math.round((r.points / Math.max(1, sum)) * 72)) }} aria-hidden="true" />
              <span className="min-w-0 flex-1 text-sm text-ink">{r.text}</span>
              <span className="mono hidden text-2xs text-ink-3 sm:inline">{r.code}</span>
            </li>
          ))}
          {sum > 100 ? <li className="pt-1 text-xs text-ink-3">{t('Suma ' + sum + ' punktów, ograniczona do 100.', 'Sum of ' + sum + ' points, capped at 100.')}</li> : null}
        </ul>
      )}
    </div>
  );
}

export function Confidence({ value, width = 34 }: { value: number; width?: number }) {
  const label = value >= 0.85 ? t('wysoka', 'high') : value >= 0.5 ? t('średnia', 'medium') : t('niska', 'low');
  return (
    <span className="inline-flex items-center gap-1.5" title={t('Pewność identyfikacji: ', 'Identification confidence: ') + label}>
      <span className="num text-sm text-ink">{fmtPct(value)}</span>
      <span className="relative h-[4px] bg-rule" style={{ width }} aria-hidden="true">
        <span className="absolute inset-y-0 left-0 bg-accent" style={{ width: Math.round(value * 100) + '%', opacity: 0.45 + value * 0.55 }} />
      </span>
    </span>
  );
}

export function Crit({ value }: { value: number }) {
  if (!value) return <span className="text-ink-3">–</span>;
  return (
    <span className="inline-flex items-center gap-1" title={t('Krytyczność ' + value + ' z 5', 'Criticality ' + value + ' of 5')}>
      <span className="inline-flex gap-px" aria-hidden="true">
        {[1, 2, 3, 4, 5].map((i) => <span key={i} className="h-[9px] w-[3px]" style={{ background: i <= value ? 'var(--ink-2)' : 'var(--rule-strong)' }} />)}
      </span>
      <span className="num text-xs text-ink-2">{value}</span>
    </span>
  );
}
