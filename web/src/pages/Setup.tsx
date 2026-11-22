import { useEffect, useState, type ReactNode } from 'react';
import { Navigate, useNavigate } from 'react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { invalidate, useItem } from '../api/hooks';
import { patch, post, put, setCsrfToken } from '../api/client';
import type { SafetyPolicy, ScanProfile, ScanRun, Scope, Session, TargetPreview } from '../api/types';
import { windowOpen } from '../lib/windows';
import { t } from '../i18n';
import { cx, fmtInt } from '../lib/format';
import { Button, Check, Field, InlineError } from '../ui/kit';
import { Glyph } from '../ui/marks';
import { Icon } from '../ui/Icon';
import { useDebounced } from '../ui/edit';
import { useSession } from '../session';
import { LoopbackNote, OperatorLockNote, PreviewReport, ThisComputerChip } from './Targets';
import { THIS_COMPUTER, THIS_COMPUTER_SCOPE, startThisComputer } from '../lib/thisComputer';
import { EstimateBox } from './ProfileEdit';

export const SETUP_DONE_KEY = 'czujka.setup.done';

type Plan = 'nightly' | 'offhours' | 'every4h' | 'manual';
const ALL_DAYS = [0, 1, 2, 3, 4, 5, 6];

function plans(): { id: Plan; label: string; text: string }[] {
  return [
    { id: 'nightly', label: t('Co noc', 'Every night'), text: t('Start o 22:00, okno 22:00–06:00.', 'Starts at 22:00, window 22:00–06:00.') },
    { id: 'offhours', label: t('Poza godzinami pracy', 'Outside office hours'), text: t('Dni robocze 18:00–07:00 i cały weekend, start o 18:30.', 'Weekdays 18:00–07:00 and the whole weekend, start at 18:30.') },
    { id: 'every4h', label: t('Co 4 godziny', 'Every 4 hours'), text: t('Bez okien czasowych. Więcej ruchu.', 'No time windows. More traffic.') },
    { id: 'manual', label: t('Tylko ręcznie', 'Manual only'), text: t('Bez harmonogramu.', 'No schedule.') },
  ];
}

function scheduleFor(plan: Plan): ScanProfile['schedule'] {
  const tz = 'Europe/Warsaw';
  switch (plan) {
    case 'nightly': return { enabled: true, cron: '0 22 * * *', interval_minutes: 0, windows: [{ days: ALL_DAYS, start: '22:00', end: '06:00' }], timezone: tz };
    case 'offhours': return { enabled: true, cron: '30 18 * * 1-5', interval_minutes: 0, windows: [{ days: [1, 2, 3, 4, 5], start: '18:00', end: '07:00' }, { days: [0, 6], start: '00:00', end: '23:59' }], timezone: tz };
    case 'every4h': return { enabled: true, cron: '', interval_minutes: 240, windows: [], timezone: tz };
    default: return { enabled: false, cron: '', interval_minutes: 0, windows: [], timezone: tz };
  }
}

function Step({ n, title, done, active, children, summary }: { n: number; title: string; done: boolean; active: boolean; children: ReactNode; summary?: ReactNode }) {
  return (
    <section className={cx('border-b border-rule', active ? 'bg-panel' : '')} aria-current={active ? 'step' : undefined} data-testid={'setup-step-' + n}>
      <header className="flex items-center gap-3 px-4 py-3 sm:px-6">
        <span className={cx('num inline-flex size-[22px] flex-none items-center justify-center border text-xs', done ? 'border-st-new text-st-new' : active ? 'border-accent bg-accent text-accent-ink' : 'border-rule-strong text-ink-3')}>
          {done ? <Icon name="check" size={12} /> : n}
        </span>
        <h2 className={cx('text-sm font-semibold', !active && !done && 'text-ink-3')}>{title}</h2>
        {!active && done && summary ? <span className="ml-auto min-w-0 truncate text-xs text-ink-2">{summary}</span> : null}
      </header>
      {active ? <div className="px-4 pb-5 sm:pl-[60px] sm:pr-6">{children}</div> : null}
    </section>
  );
}

export default function Setup() {
  const { session, can } = useSession();
  // The wizard creates scopes, profiles and runs: a role without those rights (for example the jury's viewer) goes to the dashboard.
  const allowed = can('targets:create') && can('scans:configure') && can('scans:run');
  const navigate = useNavigate();
  const qc = useQueryClient();
  const policyQ = useItem<SafetyPolicy>('/settings/safety');
  const [step, setStep] = useState(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [startedAt] = useState(() => Date.now());

  // 1. password
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [pwDone, setPwDone] = useState(false);
  // 2. network
  const [netName, setNetName] = useState('');
  const [ranges, setRanges] = useState('');
  const debounced = useDebounced(ranges, 300);
  const preview = useQuery<TargetPreview>({ queryKey: ['/targets/preview', debounced], queryFn: () => post<TargetPreview>('/targets/preview', { text: debounced }), enabled: debounced.trim().length > 0, placeholderData: (p) => p });
  const [scope, setScope] = useState<Scope | null>(null);
  // 3. limits
  const [pps, setPps] = useState(300);
  const [httpRps, setHttpRps] = useState(10);
  const [ports, setPorts] = useState('');
  const [exclusions, setExclusions] = useState('');
  const [limitsDone, setLimitsDone] = useState(false);
  useEffect(() => {
    if (!policyQ.data) return;
    setPps(policyQ.data.max_pps); setHttpRps(policyQ.data.max_http_rps); setPorts(policyQ.data.allowed_ports);
    setExclusions((policyQ.data.exclusions ?? []).join('\n'));
  }, [policyQ.data]);
  // 4. schedule
  const [plan, setPlan] = useState<Plan>('nightly');
  const [portSet, setPortSet] = useState('top-1000');
  const [profile, setProfile] = useState<ScanProfile | null>(null);

  const go = async (fn: () => Promise<void>) => {
    setBusy(true); setError(null);
    try { await fn(); } catch (e) { setError(e); } finally { setBusy(false); }
  };

  const savePassword = () => go(async () => {
    await patch('/users/' + session.user.id, { password: pw });
    // The server ends every session of the user when the password changes. Sign in again with the new password and keep going.
    const s = await post<Session>('/auth/login', { email: session.user.email, password: pw });
    setCsrfToken(s.csrf_token);
    qc.setQueryData(['/me'], s);
    setPw(''); setPw2('');
    setPwDone(true); setStep(2);
  });
  const saveNetwork = () => go(async () => {
    const s = scope ?? await post<Scope>('/scopes', { name: netName.trim(), description: '', owner: '', criticality: 3, tags: [] });
    setScope(s);
    await post<TargetPreview>('/scopes/' + s.id + '/targets', { text: ranges });
    invalidate(qc, '/scopes', '/dashboard');
    setStep(3);
  });
  const saveLimits = () => go(async () => {
    const cur = policyQ.data!;
    await put<SafetyPolicy>('/settings/safety', { ...cur, max_pps: pps, max_http_rps: httpRps, allowed_ports: ports.trim(), exclusions: exclusions.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean) });
    invalidate(qc, '/settings/safety');
    setLimitsDone(true); setStep(4);
  });
  const saveProfile = () => go(async () => {
    const base = await post<ScanProfile>('/profiles', {
      name: netName.trim() + t(': skan cykliczny', ': scheduled scan'), description: '',
      scope_ids: [scope!.id], ports: portSet,
      discovery: { icmp_echo: true, icmp_timestamp: false, tcp_syn_ports: [22, 80, 443], tcp_ack_ports: [80], arp: true, skip_discovery: false, mode: 'balanced' },
      service_detection: true, version_intensity: 5,
      http: { enabled: true, max_redirects: 5, signature_paths: true, max_body_bytes: 262144, timeout_ms: 8000, favicon: true },
      rate: { max_pps: pps, max_parallel_chunks: 4, max_parallel_hosts: 16, http_rps: Math.min(httpRps, 10), per_host_concurrency: 2, per_host_delay_ms: 0 },
      chunking: { adaptive: true, initial_size: 256, min_size: 256, max_size: 4096, target_seconds: 60 },
      retry: { unstable_retries: 2, backoff_ms: 1500, down_after_misses: 0 },
      schedule: scheduleFor(plan), enabled: true,
    });
    invalidate(qc, '/profiles');
    setProfile(base); setStep(5);
  });
  const outside = profile ? !windowOpen(profile.schedule.windows ?? []) : false;
  const [reprobe, setReprobe] = useState(true);
  const start = () => go(async () => {
    let id = profile!.id;
    if (outside) {
      // The window of the cyclic profile is closed now: the first scan runs from a one-off copy without windows, so it starts at once.
      const { id: _drop, next_run_at: _n, last_run_id: _l, created_at: _c, updated_at: _u, ...rest } = profile!;
      void _drop; void _n; void _l; void _c; void _u;
      const once = await post<ScanProfile>('/profiles', { ...rest, name: netName.trim() + t(': pierwszy skan', ': first scan'), schedule: scheduleFor('manual') });
      id = once.id;
    }
    const run = await post<ScanRun>('/runs', { profile_id: id });
    // Re-probing is on in a fresh installation; an unchecked box turns it off.
    // A server without the module (404/405/501) does not block the first scan.
    if (!reprobe) await put('/settings/reprobe', { enabled: false }).catch(() => undefined);
    try { localStorage.setItem(SETUP_DONE_KEY, String(Math.round((Date.now() - startedAt) / 1000))); } catch { /* ignore */ }
    invalidate(qc, '/runs', '/dashboard', '/profiles');
    navigate('/runs/' + run.id, { replace: true });
  });
  // Quick start: this computer in two clicks (choose, start), without the five steps.
  const [quick, setQuick] = useState(false);
  const quickPreview = useQuery<TargetPreview>({ queryKey: ['/targets/preview', THIS_COMPUTER], queryFn: () => post<TargetPreview>('/targets/preview', { text: THIS_COMPUTER }), enabled: quick });
  const startQuick = () => go(async () => {
    const id = await startThisComputer();
    try { localStorage.setItem(SETUP_DONE_KEY, String(Math.round((Date.now() - startedAt) / 1000))); } catch { /* ignore */ }
    invalidate(qc, '/runs', '/dashboard', '/profiles', '/scopes');
    navigate('/runs/' + id, { replace: true });
  });
  const skip = () => { try { localStorage.setItem(SETUP_DONE_KEY, 'skipped'); } catch { /* ignore */ } navigate('/', { replace: true }); };

  const pwError = pw && pw.length < 10 ? t('Hasło musi mieć co najmniej 10 znaków.', 'The password needs at least 10 characters.') : pw2 && pw !== pw2 ? t('Hasła się różnią.', 'The passwords do not match.') : '';
  const p = preview.data;
  const netOk = netName.trim().length > 0 && Boolean(p && p.valid.length > 0 && p.address_count > 0) && debounced === ranges;

  if (!allowed) return <Navigate to="/" replace />;
  return (
    <div className="mx-auto max-w-[880px]" data-testid="setup">
      <div className="flex flex-wrap items-end justify-between gap-3 px-4 pb-4 pt-6 sm:px-6">
        <div>
          <p className="text-xs text-ink-3">{t('Kreator', 'Wizard')}</p>
          <h1 className="font-display mt-1 text-[24px] leading-[1.15] sm:text-[28px]">{t('Pierwszy skan', 'First scan')}</h1>
                  </div>
        <button type="button" className="link text-sm" onClick={skip}>{t('Pomiń kreator', 'Skip wizard')}</button>
      </div>
      <section className="mx-4 mb-4 border border-rule bg-panel px-4 py-3 sm:mx-6" data-testid="setup-quick">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 max-w-[60ch]">
            <h2 className="text-sm font-semibold">{t('Zeskanuj ten komputer', 'Scan this computer')}</h2>
            <p className="mt-0.5 text-sm text-ink-2">{t('Czujka utworzy zakres „Ten komputer”, kopię profilu domyślnego i uruchomi skan.', 'Czujka creates the scope "This computer", a copy of the default profile, and starts the scan.')}</p>
          </div>
          <button type="button" aria-pressed={quick} onClick={() => setQuick(!quick)} data-testid="setup-this-computer"
            className={cx('inline-flex h-[30px] flex-none items-center gap-2 border px-3 text-sm', quick ? 'border-accent bg-accent-wash text-ink' : 'border-rule-strong hover:border-accent')}>
            <Icon name={quick ? 'check' : 'hosts'} size={14} />{t('Ten komputer', 'This computer')} <span className="mono text-ink-3">(localhost)</span>
          </button>
        </div>
        {quick ? (
          <div className="mt-3 border-t border-rule pt-3">
            <LoopbackNote targets={quickPreview.data?.valid ?? [{ value: THIS_COMPUTER }]} />
                        <div className="mt-3 flex flex-wrap items-center gap-3">
              <Button variant="primary" icon="play" busy={busy} onClick={startQuick} data-testid="setup-quick-start">{t('Uruchom skan', 'Start scan')}</Button>
                          </div>
          </div>
        ) : null}
      </section>
      <div className="border-t border-rule">
        <Step n={1} title={t('Zmień hasło administratora', 'Change the administrator password')} done={pwDone} active={step === 1} summary={t('hasło zmienione', 'password changed')}>
          <p className="mb-3 text-sm text-ink-2"><span className="mono text-xs text-ink-3">{session.user.email}</span></p>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label={t('Nowe hasło (co najmniej 10 znaków)', 'New password (at least 10 characters)')}><input type="password" autoComplete="new-password" className="field" value={pw} onChange={(e) => setPw(e.target.value)} data-testid="setup-pw" /></Field>
            <Field label={t('Powtórz hasło', 'Repeat the password')} error={pwError || undefined}><input type="password" autoComplete="new-password" className="field" value={pw2} onChange={(e) => setPw2(e.target.value)} data-testid="setup-pw2" /></Field>
          </div>
          <div className="mt-4 flex items-center gap-3">
            <Button variant="primary" icon="check" busy={busy} disabled={!pw || pw !== pw2 || Boolean(pwError)} onClick={savePassword}>{t('Zapisz hasło i dalej', 'Save password and continue')}</Button>
            <button type="button" className="link text-sm" onClick={() => setStep(2)}>{t('Hasło już zmienione', 'The password is changed already')}</button>
          </div>
        </Step>

        <Step n={2} title={t('Nazwij zakres i wklej cele', 'Name the scope and paste the targets')} done={Boolean(scope)} active={step === 2} summary={scope ? scope.name + ' · ' + fmtInt(p?.address_count ?? 0) + ' ' + t('adresów', 'addresses') : ''}>
          <div className="grid gap-3">
            <Field label={t('Nazwa zakresu', 'Scope name')} hint={t('np. Kampus główny, Akademiki, DMZ', 'for example Main campus, Dormitories, DMZ')}><input className="field" value={netName} onChange={(e) => setNetName(e.target.value)} data-testid="setup-net-name" /></Field>
            <div className="flex flex-wrap items-center gap-2 text-xs text-ink-3"><span>{t('Gotowe cele:', 'Ready targets:')}</span><ThisComputerChip text={ranges} onChange={(v) => { setRanges(v); if (!netName.trim()) setNetName(THIS_COMPUTER_SCOPE()); }} /></div>
            <Field label={t('Cele, jeden w wierszu (IP, CIDR, przedział a-b, domena)', 'Targets, one per line (IP, CIDR, range a-b, domain)')}>
              <textarea className="field mono min-h-[110px] py-2" value={ranges} onChange={(e) => setRanges(e.target.value)} placeholder={(policyQ.data?.operator_networks?.[0] ?? '10.0.0.0/16') + '\n192.168.10.1-192.168.10.50\nportal.example.edu'} data-testid="setup-ranges" />
            </Field>
            <OperatorLockNote networks={policyQ.data?.operator_networks} />
            {p && ranges.trim() ? <PreviewReport p={p} pending={preview.isFetching || debounced !== ranges} /> : null}
          </div>
          <div className="mt-4"><Button variant="primary" icon="check" busy={busy} disabled={!netOk} onClick={saveNetwork}>{t('Zapisz zakres i dalej', 'Save scope and continue')}</Button></div>
        </Step>

        <Step n={3} title={t('Ustaw limity od właściciela sieci', 'Set limits from the network owner')} done={limitsDone} active={step === 3} summary={fmtInt(pps) + ' pps · ' + httpRps + ' HTTP/s · ' + (ports.trim() || t('wszystkie porty', 'all ports'))}>
                    <div className="grid gap-3 sm:grid-cols-2">
            <Field label={t('Pakiety na sekundę (łącznie)', 'Packets per second (total)')}><input type="number" min={10} className="field num" value={pps} onChange={(e) => setPps(Number(e.target.value))} data-testid="setup-pps" /></Field>
            <Field label={t('Żądania HTTP na sekundę (łącznie)', 'HTTP requests per second (total)')}><input type="number" min={1} step={1} className="field num" value={httpRps} onChange={(e) => setHttpRps(Number(e.target.value))} /></Field>
            <Field label={t('Dozwolone porty (składnia nmap)', 'Allowed ports (nmap syntax)')} hint={t('puste: wszystkie porty; np. 1-1024,3306,5432,8000-8999', 'empty: all ports; for example 1-1024,3306,5432,8000-8999')}><input className="field mono" value={ports} onChange={(e) => setPorts(e.target.value)} data-testid="setup-ports" /></Field>
            <Field label={t('Nigdy nie skanuj (wykluczenia)', 'Never scan (exclusions)')} hint={t('IP, CIDR albo domeny; np. adres samej Czujki', 'IPs, CIDRs or domains; for example the address of Czujka itself')}><textarea className="field mono min-h-[60px] py-1.5" value={exclusions} onChange={(e) => setExclusions(e.target.value)} data-testid="setup-exclusions" /></Field>
          </div>
          <div className="mt-4"><Button variant="primary" icon="check" busy={busy} disabled={!policyQ.data || pps < 1 || httpRps <= 0} onClick={saveLimits}>{t('Zapisz limity i dalej', 'Save limits and continue')}</Button></div>
        </Step>

        <Step n={4} title={t('Wybierz harmonogram', 'Choose a schedule')} done={Boolean(profile)} active={step === 4} summary={plans().find((x) => x.id === plan)?.label + ' · ' + portSet}>
          <div className="grid gap-px border border-rule bg-rule sm:grid-cols-2" role="radiogroup" aria-label={t('Harmonogram', 'Schedule')}>
            {plans().map((x) => (
              <button key={x.id} type="button" role="radio" aria-checked={plan === x.id} onClick={() => setPlan(x.id)} className={cx('relative bg-panel px-3 py-2.5 text-left outline-offset-[-2px]', plan === x.id ? 'bg-raised' : 'hover:bg-raised/60')} data-testid={'setup-plan-' + x.id}>
                {plan === x.id ? <span className="absolute inset-x-0 top-0 h-[2px] bg-accent" aria-hidden="true" /> : null}
                <span className="text-sm font-medium">{x.label}</span>
                <span className="mt-0.5 block text-xs text-ink-3">{x.text}</span>
              </button>
            ))}
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
            <span className="text-ink-2">{t('Porty:', 'Ports:')}</span>
            {(['top-100', 'top-1000'] as const).map((x) => <Button key={x} size="sm" onClick={() => setPortSet(x)} className={portSet === x ? 'border-accent' : ''}><span className="mono">{x}</span>{x === 'top-1000' ? <span className="text-ink-3"> · {t('zalecane', 'recommended')}</span> : null}</Button>)}
            <span className="text-xs text-ink-3">{t('Wykrywanie hostów: tryb zrównoważony.', 'Host discovery: balanced mode.')}</span>
          </div>
          <div className="mt-4"><Button variant="primary" icon="check" busy={busy} onClick={saveProfile}>{t('Utwórz profil i policz budżet', 'Create profile and compute budget')}</Button></div>
        </Step>

        <Step n={5} title={t('Sprawdź budżet ruchu i uruchom', 'Check the traffic budget and start')} done={false} active={step === 5}>
          {profile ? <EstimateBox profileId={profile.id} /> : null}
          {outside ? (
            <p className="mt-3 flex items-start gap-2 text-sm text-ink-2"><Glyph name="pause" tone="changed" /><span>{t('Okno czasowe jest teraz zamknięte. Pierwszy skan ruszy od razu, kolejne według harmonogramu.', 'The time window is closed now. The first scan starts at once, the next ones follow the schedule.')}</span></p>
          ) : null}
          <div className="mt-3">
            <Check checked={reprobe} onChange={setReprobe} label={t('Sprawdzaj ponownie hosty, które przestały odpowiadać', 'Re-probe hosts that stopped responding')} />
                      </div>
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <Button variant="primary" icon="play" busy={busy} onClick={start} data-testid="setup-start">{t('Uruchom pierwszy skan', 'Start the first scan')}</Button>
                      </div>
        </Step>
      </div>
      {error ? <div className="px-4 py-3 sm:px-6"><InlineError error={error} /></div> : null}
    </div>
  );
}
