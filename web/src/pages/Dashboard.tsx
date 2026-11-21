import { useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { useItem, usePage } from '../api/hooks';
import type { Change, Dashboard as Dash, RunMap, ScanProfile, ScanRun, Scope } from '../api/types';
import { t, plural } from '../i18n';
import { cx, fmtDateTime, fmtDuration, fmtInt, fmtPct, fmtRelative, fmtSigned } from '../lib/format';
import { useLiveRun, useNow } from '../lib/hooks';
import { ErrorState, Panel, SkeletonRows } from '../ui/kit';
import { Icon } from '../ui/Icon';
import { ClassChips, Glyph, InterestScore, RunStatusMark, Sev, type GlyphName, type Tone } from '../ui/marks';
import { AddressMap } from '../viz/AddressMap';
import { BarList, ProgressBar, RateGauge, TrendRows } from '../viz/charts';
import { useSession } from '../session';

function Count({ n, glyph, tone, label, to }: { n: number; glyph: GlyphName; tone: Tone; label: string; to: string }) {
  const zero = n === 0;
  return (
    <Link to={to} className={cx('group inline-flex items-center gap-1.5 whitespace-nowrap py-0.5', zero ? 'text-ink-3' : 'text-ink hover:underline')}>
      <Glyph name={glyph} tone={zero ? 'expected' : tone} />
      <span className="num text-base font-medium">{n}</span>
      <span className="text-sm text-ink-2 group-hover:text-ink">{label}</span>
    </Link>
  );
}

/** The handover report: one sentence that says what changed and whether anything needs attention. */
function Handover({ d }: { d: Dash }) {
  const h = d.headline;
  const run = d.last_run;
  const s = run?.summary;
  const expected = (d.recent_changes ?? []).filter((c) => c.expected).length;
  const attention = h.findings_high > 0;
  if (!run) {
    return (
      <div>
        <p className="text-xl font-semibold tracking-[-0.015em]">{t('Nie ma jeszcze zakończonego skanu.', 'No scan has completed yet.')}</p>
        <p className="mt-2 text-base text-ink-2">{t('Dodaj cele, przygotuj profil i uruchom pierwszy przebieg. Pulpit pokaże wtedy, co działa w sieci.', 'Add targets, prepare a profile and start the first run. The dashboard then shows what is on the network.')}</p>
        <Link to="/targets" className="link mt-3 inline-block text-sm">{t('Dodaj cele', 'Add targets')}</Link>
      </div>
    );
  }
  const changed = s ? s.services_changed : 0;
  const quiet = s ? s.hosts_new + s.hosts_gone + s.services_new + s.services_gone + changed + s.hosts_unstable === 0 : true;
  return (
    <div>
      <p className="max-w-[30ch] text-xl font-semibold tracking-[-0.015em] text-ink sm:max-w-none" data-testid="handover">
        {quiet
          ? t('Bez zmian od poprzedniego skanu.', 'No change since the previous scan.')
          : t('Od poprzedniego skanu: ' + h.new_since_last_run + ' ' + plural(h.new_since_last_run, ['nowa ekspozycja', 'nowe ekspozycje', 'nowych ekspozycji'], ['', '']) + ', ' + h.gone_since_last_run + ' ' + plural(h.gone_since_last_run, ['zniknięcie', 'zniknięcia', 'zniknięć'], ['', '']) + ', ' + changed + ' ' + plural(changed, ['zmiana', 'zmiany', 'zmian'], ['', '']) + '.',
              'Since the previous scan: ' + h.new_since_last_run + ' new, ' + h.gone_since_last_run + ' gone, ' + changed + ' changed.')}
      </p>
      <p className={cx('mt-2 flex items-start gap-2 text-base', attention ? 'text-ink' : 'text-ink-2')}>
        {attention ? <Icon name="alert" className="mt-[3px] text-st-gone" /> : <Icon name="check" className="mt-[3px] text-st-new" />}
        <span>
          {attention ? (
            <>
              <Link to="/findings?severity=high&status=new,triaged" className="font-medium underline decoration-[var(--st-gone)] decoration-2 underline-offset-4 hover:decoration-[var(--ink)]">
                {h.findings_high} {plural(h.findings_high, ['znalezisko wysokiej wagi', 'znaleziska wysokiej wagi', 'znalezisk wysokiej wagi'], ['high-severity finding', 'high-severity findings'])}
              </Link>
              {' '}{t(plural(h.findings_high, ['wymaga', 'wymagają', 'wymaga'], ['', '']) + ' uwagi.', (h.findings_high === 1 ? 'needs' : 'need') + ' attention.')}
            </>
          ) : t('Nic nie wymaga pilnej uwagi.', 'Nothing needs urgent attention.')}
          {' '}
          <span className="text-ink-2">
            {t('Skan', 'Run')} <Link to={'/runs/' + run.id} className="num link">#{run.id}</Link> {t('zakończony', 'finished')} {fmtRelative(run.finished_at)}.
          </span>
        </span>
      </p>
      {s ? (
        <div className="mt-3 flex flex-wrap gap-x-5 gap-y-0.5 border-t border-rule pt-2.5">
          <Count n={s.hosts_new} glyph="plus" tone="new" label={plural(s.hosts_new, ['nowy host', 'nowe hosty', 'nowych hostów'], ['new host', 'new hosts'])} to={'/changes?run_id=' + run.id + '&kind=host_new'} />
          <Count n={s.services_new} glyph="plus" tone="new" label={plural(s.services_new, ['nowa usługa', 'nowe usługi', 'nowych usług'], ['new service', 'new services'])} to={'/changes?run_id=' + run.id + '&kind=service_new'} />
          <Count n={s.hosts_gone} glyph="minus" tone="gone" label={plural(s.hosts_gone, ['host nieaktywny', 'hosty nieaktywne', 'hostów nieaktywnych'], ['host inactive', 'hosts inactive'])} to={'/changes?run_id=' + run.id + '&kind=host_gone&expected=false'} />
          <Count n={s.services_gone} glyph="minus" tone="gone" label={plural(s.services_gone, ['usługa zniknęła', 'usługi zniknęły', 'usług zniknęło'], ['service gone', 'services gone'])} to={'/changes?run_id=' + run.id + '&kind=service_gone&expected=false'} />
          <Count n={changed} glyph="delta" tone="changed" label={plural(changed, ['zmiana', 'zmiany', 'zmian'], ['change', 'changes'])} to={'/changes?run_id=' + run.id} />
          <Count n={s.hosts_unstable} glyph="wave" tone="unstable" label={plural(s.hosts_unstable, ['host niestabilny', 'hosty niestabilne', 'hostów niestabilnych'], ['unstable host', 'unstable hosts'])} to={'/hosts?status=unstable'} />
          <Count n={expected} glyph="dashring" tone="expected" label={plural(expected, ['zmiana oczekiwana', 'zmiany oczekiwane', 'zmian oczekiwanych'], ['expected change', 'expected changes'])} to={'/changes?run_id=' + run.id + '&expected=true'} />
        </div>
      ) : null}
    </div>
  );
}

function Stat({ label, value, delta, to, mono = true }: { label: string; value: ReactNode; delta?: number | null; to?: string; mono?: boolean }) {
  const inner = (
    <>
      <dt className="text-xs text-ink-3">{label}</dt>
      <dd className="flex items-baseline gap-2">
        <span className={cx('text-base font-medium text-ink', mono && 'num')}>{value}</span>
        {delta !== undefined && delta !== null ? (
          <span className="num text-xs text-ink-3" title={t('zmiana względem poprzedniego skanu', 'change against the previous scan')}>{delta === 0 ? '±0' : fmtSigned(delta)}</span>
        ) : null}
      </dd>
    </>
  );
  return to
    ? <Link to={to} className="flex items-baseline justify-between gap-3 border-b border-rule py-1.5 hover:bg-raised">{inner}</Link>
    : <div className="flex items-baseline justify-between gap-3 border-b border-rule py-1.5">{inner}</div>;
}

function Inventory({ d }: { d: Dash }) {
  const h = d.headline;
  const tr = d.trend ?? [];
  const last = tr[tr.length - 1], prev = tr[tr.length - 2];
  return (
    <dl className="grid grid-cols-1 gap-x-6 sm:grid-cols-2">
      <Stat label={t('Adresy w zakresie', 'Addresses in scope')} value={fmtInt(h.addresses_in_scope)} to="/targets" />
      <Stat label={t('Aktywne hosty', 'Hosts up')} value={fmtInt(h.hosts_up)} delta={last && prev ? last.hosts - prev.hosts : null} to="/hosts?status=up" />
      <Stat label={t('Otwarte usługi', 'Open services')} value={fmtInt(h.services_open)} delta={last && prev ? last.services - prev.services : null} to="/services?state=open" />
      <Stat label={t('Usługi WWW', 'Web services')} value={fmtInt(h.web_services)} to="/services?name=http" />
      <Stat label={t('Otwarte znaleziska', 'Open findings')} value={fmtInt(h.findings_open)} to="/findings?status=new,triaged" />
      <Stat label={t('Niepotwierdzone zmiany', 'Unacknowledged changes')} value={fmtInt(h.changes_unacked)} to="/changes?acked=false&expected=false" />
      <Stat label={t('Panele administracyjne', 'Admin panels')} value={fmtInt(h.admin_panels)} to="/services?class=admin-panel" />
      <Stat label={t('Środowiska testowe', 'Staging environments')} value={fmtInt(h.staging_envs)} to="/services?class=staging" />
    </dl>
  );
}

function ActiveRun({ initial, d }: { initial: ScanRun; d: Dash }) {
  const { can } = useSession();
  const live = useLiveRun(initial.id);
  const run = live.run.data ?? initial;
  const map = useItem<RunMap>('/runs/' + run.id + '/map', undefined, { enabled: can('scans:read') });
  const s = run.stats;
  const pct = s.addresses_total ? s.addresses_done / s.addresses_total : 0;
  return (
    <Panel
      title={<><RunStatusMark status={run.status} pauseReason={run.pause_reason} /> <span className="font-normal text-ink-2">· {t('skan', 'run')} <span className="num">#{run.id}</span> · {run.profile_name}</span></>}
      actions={<Link to={'/runs/' + run.id} className="link inline-flex items-center gap-1 whitespace-nowrap">{t('Otwórz przebieg', 'Open the run')}<Icon name="arrowRight" size={12} /></Link>}
    >
      <div className="grid gap-x-8 gap-y-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
        <div>
          <div className="flex items-baseline justify-between gap-3">
            <span><span className="num text-lg font-semibold">{fmtPct(pct)}</span> <span className="text-xs text-ink-3">{t('adresów', 'of addresses')}</span></span>
            <span className="text-xs text-ink-2">{run.status === 'analyzing' ? t('analiza zmian…', 'analysing changes…') : <>{t('pozostało', 'remaining')} <span className="num text-ink">{fmtDuration(s.eta_sec)}</span></>}</span>
          </div>
          <div className="mt-1.5"><ProgressBar value={s.addresses_done} max={s.addresses_total} label={t('Postęp skanu', 'Scan progress')} /></div>
          <div className="mt-1 flex justify-between text-2xs text-ink-3">
            <span className="num">{fmtInt(s.addresses_done)} / {fmtInt(s.addresses_total)}</span>
            <span>{t('podgrupy', 'chunks')} <span className="num text-ink-2">{s.chunks_done}/{s.chunks_total}</span></span>
          </div>
          <dl className="mt-3 flex gap-6 text-xs text-ink-2">
            <div><dt className="text-ink-3">{t('aktywne hosty', 'hosts up')}</dt><dd className="num text-sm text-ink">{fmtInt(s.hosts_up)}</dd></div>
            <div><dt className="text-ink-3">{t('usługi', 'services')}</dt><dd className="num text-sm text-ink">{fmtInt(s.services_open)}</dd></div>
            <div><dt className="text-ink-3">{t('czas', 'elapsed')}</dt><dd className="num text-sm text-ink">{fmtDuration(s.elapsed_sec)}</dd></div>
          </dl>
        </div>
        <RateGauge current={s.current_pps} cap={Math.min(800, d.safety.max_pps)} policyCap={d.safety.max_pps} />
        <div className="min-w-[150px] max-w-[320px]">
          {map.data ? <AddressMap blocks={map.data.blocks} compact /> : <div className="skeleton h-[104px] w-[220px]" />}
        </div>
      </div>
    </Panel>
  );
}

function IdleRun({ d }: { d: Dash }) {
  const run = d.last_run;
  return (
    <Panel title={t('Skanowanie', 'Scanning')} actions={<Link to="/runs" className="link">{t('Wszystkie przebiegi', 'All runs')}</Link>}>
      <div className="flex flex-wrap gap-x-10 gap-y-2 text-sm">
        <span className="text-ink-2">{t('Żaden skan teraz nie działa.', 'No scan is running now.')}</span>
        {run ? <span>{t('Ostatni:', 'Last:')} <Link className="link num" to={'/runs/' + run.id}>#{run.id}</Link> · {fmtDateTime(run.finished_at)} · {fmtDuration(run.stats.elapsed_sec)}</span> : null}
        <span>{t('Następny:', 'Next:')} {d.next_run_at ? <><span className="num text-ink">{fmtDateTime(d.next_run_at)}</span> <span className="text-ink-3">({fmtRelative(d.next_run_at)})</span></> : t('brak harmonogramu', 'not scheduled')}</span>
      </div>
    </Panel>
  );
}

function Row({ to, children }: { to: string; children: ReactNode }) {
  return <li><Link to={to} className="flex min-h-[44px] items-start gap-3 border-b border-rule px-3 py-2 hover:bg-raised">{children}</Link></li>;
}

function RecentChanges({ changes }: { changes: Change[] }) {
  const [showExpected, setShowExpected] = useState(false);
  const real = changes.filter((c) => !c.expected);
  const expected = changes.filter((c) => c.expected);
  const list = (showExpected ? [...real.slice(0, 7), ...expected] : real.slice(0, 7));
  return (
    <Panel title={t('Najnowsze zmiany', 'Recent changes')} count={real.length} flush actions={<Link to="/changes" className="link">{t('Dziennik zmian', 'Change log')}</Link>}>
      {real.length === 0 && expected.length === 0 ? <p className="p-3 text-sm text-ink-2">{t('Ostatni skan nie wykrył zmian.', 'The last scan found no change.')}</p> : null}
      <ul>
        {list.map((c) => (
          <Row key={c.id} to={c.service_id ? '/services/' + c.service_id : '/hosts/' + c.host_id}>
            <span className="mt-0.5"><Glyph name={c.expected ? 'dashring' : (c.kind.endsWith('_new') ? 'plus' : c.kind.endsWith('_gone') ? 'minus' : c.kind === 'host_unstable' ? 'wave' : c.kind === 'host_back' ? 'back' : 'delta')} tone={c.expected ? 'expected' : (c.kind.endsWith('_new') || c.kind === 'host_back' ? 'new' : c.kind.endsWith('_gone') ? 'gone' : c.kind === 'host_unstable' ? 'unstable' : 'changed')} /></span>
            <span className="min-w-0 flex-1">
              <span className={cx('block text-sm', c.expected ? 'text-ink-2' : 'text-ink')}>{c.summary}</span>
              <span className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-ink-3">
                <span className="mono">{c.ip}{c.port ? ':' + c.port : ''}</span>
                {c.expected ? <span>{t('oczekiwana', 'expected')}</span> : <Sev level={c.severity} />}
              </span>
            </span>
          </Row>
        ))}
      </ul>
      {expected.length > 0 ? (
        <button type="button" onClick={() => setShowExpected((v) => !v)} aria-expanded={showExpected} className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs text-ink-2 hover:bg-raised hover:text-ink">
          <Glyph name="dashring" tone="expected" />
          {showExpected
            ? t('Zwiń zmiany oczekiwane', 'Fold the expected changes')
            : <>{expected.length} {plural(expected.length, ['zmiana zgodna', 'zmiany zgodne', 'zmian zgodnych'], ['change that fits', 'changes that fit'])} {t('z profilem dostępności hostów. Pokaż', 'the availability profile of the hosts. Show')}</>}
          <Icon name={showExpected ? 'chevronDown' : 'chevronRight'} size={12} />
        </button>
      ) : null}
    </Panel>
  );
}

function SafetyPanel({ st }: { st: Dash['safety'] }) {
  const { can } = useSession();
  return (
    <Panel title={t('Bezpieczeństwo skanowania', 'Scan safety')} actions={<Link to="/admin?tab=safety" className="link">{can('safety:manage') ? t('Polityka', 'Policy') : t('Podgląd polityki', 'View the policy')}</Link>}>
      <p className={cx('mb-2 flex items-center gap-2 text-sm font-medium', st.emergency_stop ? 'text-danger' : 'text-ink')}>
        <Icon name={st.emergency_stop ? 'stop' : 'shield'} className={st.emergency_stop ? '' : 'text-st-new'} />
        {st.emergency_stop ? t('Stop awaryjny aktywny', 'Emergency stop is active') : t('Skaner działa w trybie bezpiecznej detekcji', 'The scanner runs in safe-detection mode')}
      </p>
      <dl>
        <Stat label={t('Limit pakietów', 'Packet cap')} value={<>{fmtInt(st.max_pps)} <span className="font-sans text-xs font-normal text-ink-3">pps</span></>} />
        <Stat label={t('Limit żądań HTTP', 'HTTP request cap')} value={<>{st.max_http_rps} <span className="font-sans text-xs font-normal text-ink-3">{t('na s, ', 'per s, ')}{st.max_per_host_rps} {t('na host', 'per host')}</span></>} />
        <Stat label={t('Metody HTTP', 'HTTP methods')} value={(st.allowed_methods ?? []).join(', ')} />
        <Stat label={t('Wykluczenia', 'Exclusions')} value={(st.exclusions ?? []).length} />
        <Stat label={t('Stop awaryjny', 'Emergency stop')} value={<HostlessState on={st.emergency_stop} />} mono={false} />
      </dl>
    </Panel>
  );
}

interface Step { done: boolean; title: string; text: string; state?: string; to?: string; cta?: string; blocked?: string }

/** A fresh installation: no scan and no imported result yet. Says what to do next, in order. */
function FirstRun({ d }: { d: Dash }) {
  const { can } = useSession();
  const scopes = usePage<Scope>('/scopes', { limit: 1 }, can('targets:read'));
  const profiles = usePage<ScanProfile>('/profiles', { limit: 50 }, can('scans:read'));
  const health = useItem<{ engine?: boolean }>('/healthz', undefined, { staleTime: 60_000 });
  const addresses = d.headline.addresses_in_scope;
  const hasTargets = addresses > 0;
  const list = profiles.data?.items ?? [];
  const ready = list.find((p) => p.enabled && (p.scope_ids ?? []).length > 0);
  const first = list[0];
  const engineOff = health.data?.engine === false;
  const steps: Step[] = [
    {
      done: hasTargets,
      title: t('Dodaj cele', 'Add targets'),
      text: t('Utwórz zakres i wpisz sieci, które wolno skanować. Skaner nigdy nie wychodzi poza tę listę.', 'Create a scope and enter the networks that may be scanned. The scanner never leaves this list.'),
      state: hasTargets ? fmtInt(addresses) + ' ' + plural(addresses, ['adres w zakresie', 'adresy w zakresie', 'adresów w zakresie'], ['address in scope', 'addresses in scope']) : (scopes.data?.total ? t('zakres istnieje, brakuje w nim celów', 'a scope exists, it has no target yet') : undefined),
      to: '/targets', cta: can('targets:create') ? t('Otwórz cele', 'Open targets') : t('Zobacz cele', 'View targets'),
    },
    {
      done: Boolean(ready),
      title: t('Przygotuj profil skanu', 'Prepare a scan profile'),
      text: first && !ready
        ? t('Profil „' + first.name + '” jest gotowy. Przypisz mu zakres, ustaw tempo i okna czasowe.', 'The profile "' + first.name + '" is ready. Give it a scope, then set the rate and the time windows.')
        : t('Profil łączy zakresy z portami, tempem i oknami czasowymi.', 'A profile joins scopes with ports, rate and time windows.'),
      state: ready ? t('profil „' + ready.name + '” ma przypisany zakres', 'the profile "' + ready.name + '" has a scope') : undefined,
      to: can('scans:configure') ? (first ? '/profiles/' + first.id : '/profiles/new') : '/profiles',
      cta: can('scans:configure') ? t('Otwórz profil', 'Open the profile') : t('Zobacz profile', 'View profiles'),
    },
    {
      done: false,
      title: t('Uruchom pierwszy skan', 'Start the first scan'),
      text: t('Przebieg pokaże postęp na mapie przestrzeni adresowej. Po nim pulpit powie, co działa w sieci i co się zmieniło.', 'The run shows its progress on the address-space map. After it the dashboard says what is on the network and what changed.'),
      blocked: engineOff ? t('Silnik skanowania nie jest podłączony w tej instalacji. Zaimportuj wyniki z pliku.', 'The scan engine is not connected in this installation. Import results from a file.') : undefined,
      to: '/profiles', cta: can('scans:run') ? t('Przejdź do uruchomienia', 'Go to start') : undefined,
    },
  ];
  const next = steps.findIndex((s) => !s.done);
  return (
    <section aria-labelledby="first-run-title" data-testid="first-run">
      <h2 id="first-run-title" className="text-xl font-semibold tracking-[-0.015em]">{t('Czujka nie ma jeszcze danych o sieci.', 'Czujka has no data about the network yet.')}</h2>
      <p className="mt-2 max-w-[70ch] text-base text-ink-2">{t('Trzy kroki dzielą tę instalację od pierwszego obchodu. Każdy krok można wykonać teraz albo wrócić do niego później.', 'Three steps stand between this installation and its first watch. Do each step now or come back to it later.')}</p>
      <ol className="mt-4 border-y border-rule">
        {steps.map((s, i) => (
          <li key={s.title} className="grid grid-cols-[28px_minmax(0,1fr)] items-start gap-x-3 gap-y-2 border-b border-rule py-3 last:border-b-0 sm:grid-cols-[28px_minmax(0,1fr)_auto]">
            <span className={cx('num mt-px flex h-[22px] w-[22px] items-center justify-center border text-xs', s.done ? 'border-st-new text-st-new' : i === next ? 'border-accent text-ink' : 'border-rule-strong text-ink-3')} aria-hidden="true">
              {s.done ? <Icon name="check" size={12} /> : i + 1}
            </span>
            <div className="min-w-0">
              <p className={cx('text-sm font-medium', s.done ? 'text-ink-2' : 'text-ink')}>{s.title}<span className="sr-only">{s.done ? ' (' + t('zrobione', 'done') + ')' : ''}</span></p>
              <p className="mt-0.5 max-w-[72ch] text-sm text-ink-2">{s.text}</p>
              {s.state ? <p className="mt-1 text-xs text-ink-3">{s.state}</p> : null}
              {s.blocked ? <p className="mt-1 flex items-start gap-1.5 text-xs text-ink-2"><Icon name="info" size={12} className="mt-0.5 flex-none text-ink-3" />{s.blocked}</p> : null}
            </div>
            {s.cta && s.to ? (
              <Link to={s.to} className={cx('col-start-2 inline-flex h-[30px] items-center gap-1.5 justify-self-start whitespace-nowrap border px-3 text-sm sm:col-start-3 sm:justify-self-end', i === next && !s.blocked ? 'border-accent bg-accent font-medium text-accent-ink hover:bg-accent-strong' : 'border-rule-strong text-ink hover:bg-raised')}>
                {s.cta}<Icon name="arrowRight" size={12} />
              </Link>
            ) : null}
          </li>
        ))}
      </ol>
      {can('results:create') ? (
        <p className="mt-3 flex flex-wrap items-center gap-x-2 text-sm text-ink-2">
          <Icon name="upload" size={14} className="text-ink-3" />
          {t('Masz już wyniki z nmap? Nie potrzebujesz skanu:', 'You already have nmap results? No scan is needed:')}
          <Link to="/transfer" className="link">{t('zaimportuj plik XML', 'import the XML file')}</Link>
        </p>
      ) : null}
    </section>
  );
}

export default function Dashboard() {
  const q = useItem<Dash>('/dashboard', undefined, { refetchInterval: 60_000 });
  const now = useNow();
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!q.data) return <div className="p-4 sm:p-6"><div className="skeleton mb-3 h-8 w-[min(520px,80%)]" /><div className="skeleton mb-6 h-4 w-[min(380px,60%)]" /><SkeletonRows rows={10} /></div>;
  const d = q.data;
  void now;
  const st = d.safety;
  const h0 = d.headline;
  const fresh = !d.last_run && !d.active_run && h0.hosts_up + h0.hosts_down + h0.hosts_unstable + h0.services_open + h0.findings_open + h0.changes_unacked === 0;
  if (fresh) {
    return (
      <div className="mx-auto max-w-[1480px] space-y-5 p-4 sm:p-6">
        <h1 className="sr-only">{t('Pulpit', 'Dashboard')}</h1>
        <div className="grid gap-x-10 gap-y-6 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
          <FirstRun d={d} />
          <div className="space-y-4">
            <SafetyPanel st={st} />
            <IdleRun d={d} />
          </div>
        </div>
        <p className="pb-2 text-2xs text-ink-3">{t('Stan na', 'As of')} {fmtDateTime(d.generated_at)}</p>
      </div>
    );
  }
  return (
    <div className="mx-auto max-w-[1480px] space-y-4 p-4 sm:p-6">
      <h1 className="sr-only">{t('Pulpit', 'Dashboard')}</h1>
      <div className="grid gap-x-10 gap-y-5 xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
        <Handover d={d} />
        <Inventory d={d} />
      </div>

      {d.active_run ? <ActiveRun initial={d.active_run} d={d} /> : <IdleRun d={d} />}

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title={t('Najważniejsze znaleziska', 'Top findings')} flush actions={<Link to="/findings" className="link">{t('Wszystkie', 'All')}</Link>}>
          {(d.top_findings ?? []).length === 0 ? <p className="p-3 text-sm text-ink-2">{t('Brak otwartych znalezisk.', 'No open finding.')}</p> : null}
          <ul>
            {(d.top_findings ?? []).slice(0, 7).map((f) => (
              <Row key={f.id} to={'/findings?open=' + f.id}>
                <span className="mt-0.5"><Sev level={f.severity} compact /></span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm text-ink">{f.title}</span>
                  <span className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-ink-3">
                    <span className="mono">{f.ip}{f.port ? ':' + f.port : ''}</span>
                    {f.first_run_id === d.last_run?.id ? <span className="inline-flex items-center gap-1 text-ink-2"><Glyph name="plus" tone="new" size={10} />{t('od ostatniego skanu', 'since the last scan')}</span> : <span>{t('od', 'since')} {fmtRelative(f.first_seen)}</span>}
                  </span>
                </span>
                <span className="mt-0.5 flex-none"><InterestScore value={f.interest} /></span>
              </Row>
            ))}
          </ul>
        </Panel>

        <RecentChanges changes={d.recent_changes ?? []} />

        <Panel title={t('Najciekawsze usługi', 'Most interesting services')} flush actions={<Link to="/services?sort=-interest" className="link">{t('Eksplorator', 'Explorer')}</Link>}>
          <ul>
            {(d.top_services ?? []).slice(0, 7).map((s) => (
              <Row key={s.id} to={'/services/' + s.id}>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-ink">{s.title || s.product || s.name}</span>
                  <span className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-ink-3">
                    <span className="mono">{s.hostname || s.ip}:{s.port}</span>
                    <ClassChips classes={s.classes} max={2} />
                  </span>
                  {s.interest_why && s.interest_why.length ? <span className="mt-1 block truncate text-xs text-ink-2">{s.interest_why.slice(0, 2).map((r) => '+' + r.points + ' ' + r.text).join(' · ')}</span> : null}
                </span>
                <span className="mt-0.5 flex-none"><InterestScore value={s.interest} reasons={s.interest_why} /></span>
              </Row>
            ))}
          </ul>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title={t('Technologie', 'Technologies')} actions={<span className="text-ink-3">{t('liczba usług', 'services')}</span>}>
          <BarList items={(d.technologies ?? []).slice(0, 10)} href={(i) => '/services?tech=' + encodeURIComponent(i.name)} labelWidth={150} />
        </Panel>
        <Panel title={t('Otwarte porty', 'Open ports')} actions={<span className="text-ink-3">{t('liczba usług', 'services')}</span>}>
          <BarList items={(d.ports ?? []).slice(0, 10)} mono href={(i) => '/services?port=' + i.name} labelWidth={150} extra={(i) => i.extra} />
        </Panel>
        <Panel title={t('Trend w kolejnych skanach', 'Trend over runs')}>
          <TrendRows points={d.trend ?? []} series={[
            { key: 'hosts', label: t('aktywne hosty', 'hosts up') },
            { key: 'services', label: t('otwarte usługi', 'open services') },
            { key: 'changes', label: t('zmiany', 'changes') },
          ]} />
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title={t('Hosty niestabilne', 'Unstable hosts')} count={d.headline.hosts_unstable} flush actions={<Link to="/hosts?status=unstable" className="link">{t('Wszystkie', 'All')}</Link>}>
          {(d.unstable_hosts ?? []).length === 0 ? <p className="p-3 text-sm text-ink-2">{t('Każdy znany host odpowiada zgodnie ze swoim profilem.', 'Every known host answers as its profile predicts.')}</p> : null}
          <ul>
            {(d.unstable_hosts ?? []).slice(0, 6).map((h) => (
              <li key={h.id}>
                <Link to={'/hosts/' + h.id} className="flex min-h-[30px] items-center gap-3 border-b border-rule px-3 py-1.5 hover:bg-raised">
                  <span className="mono w-[104px] flex-none text-sm">{h.ip}</span>
                  <span className="min-w-0 flex-1 truncate text-xs text-ink-2">{h.pattern}</span>
                  <span className="num flex-none text-xs text-ink-2" title={t('Prawdopodobieństwo, że host nadal istnieje', 'Probability that the host still exists')}>p {h.p_alive.toFixed(2)}</span>
                </Link>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title={t('Wygasające certyfikaty', 'Expiring certificates')} count={(d.certs_expiring ?? []).length} flush>
          {(d.certs_expiring ?? []).length === 0 ? <p className="p-3 text-sm text-ink-2">{t('Żaden certyfikat nie wygasa w ciągu 30 dni.', 'No certificate expires within 30 days.')}</p> : null}
          <ul>
            {(d.certs_expiring ?? []).slice(0, 6).map((s) => {
              const days = s.latest?.result.tls?.days_left ?? 0;
              return (
                <li key={s.id}>
                  <Link to={'/services/' + s.id} className="flex min-h-[30px] items-center gap-3 border-b border-rule px-3 py-1.5 hover:bg-raised">
                    <span className="mono min-w-0 flex-1 truncate text-sm">{s.hostname || s.ip}:{s.port}</span>
                    <span className="inline-flex flex-none items-center gap-1.5 text-xs">
                      <Glyph name={days < 0 ? 'x' : 'delta'} tone={days < 0 ? 'gone' : days <= 7 ? 'changed' : 'expected'} size={12} />
                      <span className={days <= 7 ? 'text-ink' : 'text-ink-2'}>{days < 0 ? t('wygasł ' + Math.abs(days) + ' dni temu', 'expired ' + Math.abs(days) + ' days ago') : t('za ' + days + ' dni', 'in ' + days + ' days')}</span>
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </Panel>
        <SafetyPanel st={st} />
      </div>
      <p className="pb-2 text-2xs text-ink-3">{t('Stan na', 'As of')} {fmtDateTime(d.generated_at)}</p>
    </div>
  );
}

function HostlessState({ on }: { on: boolean }) {
  return on
    ? <span className="inline-flex items-center gap-1.5 text-sm"><Glyph name="x" tone="danger" />{t('aktywny', 'active')}</span>
    : <span className="inline-flex items-center gap-1.5 text-sm font-normal text-ink-2"><Glyph name="ring" tone="expected" />{t('nieaktywny', 'off')}</span>;
}

