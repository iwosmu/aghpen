import { useState, type ReactNode } from 'react';
import { Link, Navigate } from 'react-router';
import { SETUP_DONE_KEY } from './Setup';
import { useItem, usePage } from '../api/hooks';
import type { Change, Dashboard as Dash, Page, RunMap, ScanProfile, ScanRun, Scope, Service } from '../api/types';
import { t, plural } from '../i18n';
import { cx, fmtDateTime, fmtDec, fmtDuration, fmtInt, fmtPct, fmtRelative, fmtSigned, titleWithoutAddress } from '../lib/format';
import { useLiveRun, useNow } from '../lib/hooks';
import { ErrorState, Panel, SkeletonRows } from '../ui/kit';
import { Icon } from '../ui/Icon';
import { ClassChips, Glyph, InterestScore, RunStatusMark, Sev, changeKindInfo, type GlyphName, type Tone } from '../ui/marks';
import { BarList, ProgressBar, TrendRows } from '../viz/charts';
import { useSession } from '../session';
import { RunStory } from '../ui/RunStory';
import { useHostVerdicts } from '../ui/MissingHosts';
import { PartialNote } from '../ui/RunPasses';
import { useArrivalOrder } from '../ui/arrivalOrder';
import { SMALL_RUN } from './RunDetail';
import { serviceName } from '../lib/serviceName';
import { ReprobePanel } from './Reprobe';
import { ATTENTION_INTEREST, adminPanelNames, adminPanelServiceNames, isFullRun, lastFullPair, partialRunPhrase } from '../lib/headline';
import { changeSummary } from '../lib/changeText';

function Count({ n, glyph, tone, label, to }: { n: number; glyph: GlyphName; tone: Tone; label: string; to: string }) {
  const zero = n === 0;
  if (zero) return null; // the handover sentence already says what did not change
  return (
    <Link to={to} className={cx('group inline-flex items-center gap-1.5 whitespace-nowrap py-0.5', zero ? 'text-ink-3' : 'text-ink hover:underline')}>
      <Glyph name={glyph} tone={zero ? 'expected' : tone} />
      <span className="num text-base font-medium">{n}</span>
      <span className="text-sm text-ink-2 group-hover:text-ink">{label}</span>
    </Link>
  );
}

/** The handover report: what changed and, from the data, what needs attention. */
function Handover({ d, full }: { d: Dash; full?: ScanRun | null }) {
  const h = d.headline;
  // The headline compares the last two full runs of one profile; a partial run
  // (ad hoc, re-probe, import, manual entry) only gets its own short line.
  const last = d.last_run;
  const partial = last && !isFullRun(last) ? last : null;
  const run = full === undefined ? (partial ? null : last) : full;
  const s = run?.summary;
  const expected = (d.recent_changes ?? []).filter((c) => c.expected).length;
  // Hosts that did not answer in this run, and what the confirmation probe decided since.
  const missingQ = useItem<Page<Change>>('/changes', { run_id: run?.id, kind: 'host_missing,service_unreachable', limit: 500 }, { enabled: Boolean(run?.id) && (s?.hosts_missing ?? 0) > 0 });
  const missingItems = missingQ.data?.items ?? [];
  const verdicts = useHostVerdicts(missingItems.filter((c) => c.kind === 'host_missing'));
  // services of hosts the confirmation probe has decided about are no longer "not answering"
  const decidedServices = missingItems.filter((c) => c.kind === 'service_unreachable' && verdicts.has(c.host_id)).length;
  const confirmedGone = [...verdicts.values()].filter((v) => v.kind === 'host_gone').length;
  if (!run && partial) {
    return (
      <div>
        <p className="font-display text-[40px] leading-[1.02] sm:text-[52px]" data-testid="handover">{t('Nie ma jeszcze pełnego skanu profilu do porównania.', 'No full profile scan to compare yet.')}</p>
        <p className="mt-2 text-sm text-ink-2" data-testid="handover-partial">{t('Ostatnio', 'Last')}: {partialRunPhrase(partial)} (<Link to={'/runs/' + partial.id} className="num link">#{partial.id}</Link>, {fmtRelative(partial.finished_at)}).</p>
      </div>
    );
  }
  if (!run) {
    return (
      <div>
        <p className="font-display text-[40px] leading-[1.02] sm:text-[52px]">{t('Nie ma jeszcze zakończonego skanu.', 'No scan has completed yet.')}</p>
        <p className="mt-2 text-base text-ink-2">{t('Dodaj cele, przygotuj profil i uruchom skan.', 'Add targets, prepare a profile and start a scan.')}</p>
        <Link to="/targets" className="link mt-3 inline-block text-sm">{t('Dodaj cele', 'Add targets')}</Link>
      </div>
    );
  }
  const baseline = Boolean(s) && !s!.prev_run_id;
  const changed = s ? s.services_changed : 0;
  const missing = Math.max(0, (s?.hosts_missing ?? 0) - verdicts.size);
  const unreachable = Math.max(0, (s?.services_unreachable ?? 0) - decidedServices);
  const added = s ? s.hosts_new + s.services_new : 0;
  const gone = s ? s.hosts_gone + s.services_gone : 0;
  const returned = s?.services_returned ?? 0;
  const slower = s?.responses_slower ?? 0;
  const recovered = s?.by_kind?.response_recovered ?? 0;
  const quiet = s ? added + gone + changed + s.hosts_unstable + missing + confirmedGone + returned + slower + recovered === 0 : true;
  const open = (d.top_findings ?? []).filter((f) => f.status === 'new' || f.status === 'triaged');
  const important = open.filter((f) => f.severity === 'high' || f.interest >= ATTENTION_INTEREST);
  const panels = adminPanelNames(open);
  const attention = h.admin_panels > 0 || h.findings_high > 0 || important.length > 0;
  const named = (panels.length ? panels : adminPanelServiceNames(d.top_services ?? [])).slice(0, 2);
  const headline = baseline
    ? t('Pierwszy obraz sieci: ' + fmtInt(h.hosts_up) + ' ' + plural(h.hosts_up, ['aktywny host', 'aktywne hosty', 'aktywnych hostów'], ['', '']) + ', ' + fmtInt(h.services_open) + ' ' + plural(h.services_open, ['otwarta usługa', 'otwarte usługi', 'otwartych usług'], ['', '']) + '.',
      'First picture of the network: ' + fmtInt(h.hosts_up) + ' ' + (h.hosts_up === 1 ? 'host' : 'hosts') + ' up, ' + fmtInt(h.services_open) + ' open ' + (h.services_open === 1 ? 'service' : 'services') + '.')
    : quiet
      ? t('Bez zmian od poprzedniego skanu.', 'No change since the previous scan.')
      : (() => { const n = added + gone + changed + missing + s!.hosts_unstable + returned + slower + recovered + confirmedGone; return t(fmtInt(n) + ' ' + plural(n, ['zmiana', 'zmiany', 'zmian'], ['', '']) + ' od poprzedniego skanu.', fmtInt(n) + ' ' + (n === 1 ? 'change' : 'changes') + ' since the previous scan.'); })();
  return (
    <div>
      <p className="font-display max-w-[30ch] text-[40px] leading-[1.02] tracking-[-0.01em] text-ink sm:text-[52px] xl:text-[60px]" data-testid="handover">{headline}</p>
      <p className="mt-4 flex flex-wrap items-center gap-x-6 gap-y-1.5 text-sm text-ink-2" data-testid="handover-attention">
        {h.admin_panels > 0 ? (
          <Link to="/services?class=admin-panel" className="inline-flex items-center gap-2 text-ink hover:text-ink">
            <Icon name="alert" className="flex-none text-st-gone" />
            <span className="underline decoration-[var(--st-gone)] decoration-2 underline-offset-4">{fmtInt(h.admin_panels)} {plural(h.admin_panels, ['panel administracyjny', 'panele administracyjne', 'paneli administracyjnych'], ['admin panel', 'admin panels'])}</span>
            {named.length ? <span className="text-ink-3">{named.join(', ')}</span> : null}
          </Link>
        ) : attention ? null : <span className="inline-flex items-center gap-2"><Icon name="check" className="flex-none text-st-new" />{t('Nic pilnego', 'Nothing urgent')}</span>}
        <span>
          {t('Skan', 'Scan')} <Link to={'/runs/' + run.id} className="num link">#{run.id}</Link> · {fmtRelative(run.finished_at)}
          {baseline ? <span className="text-ink-3"> · {t('punkt odniesienia', 'baseline')}</span> : null}
        </span>
      </p>
      {partial ? (
        <p className="mt-1.5 text-sm text-ink-2" data-testid="handover-partial">
          {t('Ostatnio', 'Last')}: {partialRunPhrase(partial)} (<Link to={'/runs/' + partial.id} className="num link">#{partial.id}</Link>, {fmtRelative(partial.finished_at)}); {t('skan częściowy.', 'a partial scan.')}
        </p>
      ) : null}
      {s && !baseline ? <RunStory runId={run.id} className="mt-3 space-y-1" testId="handover-story" /> : null}
      {s && !baseline && !(quiet && !expected && !unreachable) ? (
        <div className="mt-3 flex flex-wrap gap-x-5 gap-y-0.5 border-t border-rule pt-2.5" data-testid="handover-counts">
          <Count n={s.hosts_new} glyph="plus" tone="new" label={plural(s.hosts_new, ['nowy host', 'nowe hosty', 'nowych hostów'], ['new host', 'new hosts'])} to={'/changes?run_id=' + run.id + '&kind=host_new'} />
          <Count n={s.services_new} glyph="plus" tone="new" label={plural(s.services_new, ['nowa usługa', 'nowe usługi', 'nowych usług'], ['new service', 'new services'])} to={'/changes?run_id=' + run.id + '&kind=service_new'} />
          <Count n={s.hosts_gone} glyph="minus" tone="gone" label={plural(s.hosts_gone, ['host nieaktywny', 'hosty nieaktywne', 'hostów nieaktywnych'], ['host down', 'hosts down'])} to={'/changes?run_id=' + run.id + '&kind=host_gone&expected=false'} />
          <Count n={s.services_gone} glyph="minus" tone="gone" label={plural(s.services_gone, ['usługa zniknęła', 'usługi zniknęły', 'usług zniknęło'], ['service gone', 'services gone'])} to={'/changes?run_id=' + run.id + '&kind=service_gone&expected=false'} />
          {s.services_returned ? <Count n={s.services_returned} glyph="returned" tone="new" label={plural(s.services_returned, ['usługa wróciła', 'usługi wróciły', 'usług wróciło'], ['service back', 'services back'])} to={'/changes?run_id=' + run.id + '&kind=service_returned'} /> : null}
          {s.responses_slower ? <Count n={s.responses_slower} glyph="slow" tone="changed" label={plural(s.responses_slower, ['usługa odpowiada wolniej', 'usługi odpowiadają wolniej', 'usług odpowiada wolniej'], ['service responds slower', 'services respond slower'])} to={'/changes?run_id=' + run.id + '&kind=response_slower'} /> : null}
          <Count n={changed} glyph="delta" tone="changed" label={plural(changed, ['zmiana', 'zmiany', 'zmian'], ['change', 'changes'])} to={'/changes?run_id=' + run.id} />
          <Count n={s.hosts_unstable} glyph="wave" tone="unstable" label={plural(s.hosts_unstable, ['host niestabilny', 'hosty niestabilne', 'hostów niestabilnych'], ['unstable host', 'unstable hosts'])} to={'/hosts?status=unstable'} />
          <Count n={missing} glyph="half" tone="expected" label={plural(missing, ['host nie odpowiada (niepotwierdzone)', 'hosty nie odpowiadają (niepotwierdzone)', 'hostów nie odpowiada (niepotwierdzone)'], ['host not responding (unconfirmed)', 'hosts not responding (unconfirmed)'])} to={'/changes?run_id=' + run.id + '&kind=host_missing'} />
          {unreachable ? <span className="inline-flex items-center gap-1.5 whitespace-nowrap py-0.5 text-sm text-ink-3" title={t('Host nie odpowiada, więc stan jego usług jest nieznany.', 'The host is not responding, so the status of its services is unknown.')}><span className="num text-base font-medium text-ink-2">{unreachable}</span>{plural(unreachable, ['usługa nie odpowiada (niepotwierdzone)', 'usługi nie odpowiadają (niepotwierdzone)', 'usług nie odpowiada (niepotwierdzone)'], ['service not responding (unconfirmed)', 'services not responding (unconfirmed)'])}</span> : null}
          {confirmedGone ? <Count n={confirmedGone} glyph="minus" tone="gone" label={plural(confirmedGone, ['host nieaktywny (potwierdzone)', 'hosty nieaktywne (potwierdzone)', 'hostów nieaktywnych (potwierdzone)'], ['host down (confirmed)', 'hosts down (confirmed)'])} to={'/changes?kind=host_gone'} /> : null}
          <Count n={expected} glyph="dashring" tone="expected" label={plural(expected, ['zmiana oczekiwana', 'zmiany oczekiwane', 'zmian oczekiwanych'], ['expected change', 'expected changes'])} to={'/changes?run_id=' + run.id + '&expected=true'} />
        </div>
      ) : null}
    </div>
  );
}

function Stat({ label, value, delta, deltaTitle, to, mono = true }: { label: string; value: ReactNode; delta?: number | null; deltaTitle?: string; to?: string; mono?: boolean }) {
  const inner = (
    <>
      <dd className="flex items-baseline gap-2">
        <span className={cx('text-ink', mono ? 'font-display text-[44px] leading-none sm:text-[56px]' : 'text-base font-medium')}>{value}</span>
        {delta !== undefined && delta !== null ? (
          <span className="num text-xs text-ink-3" title={deltaTitle ?? t('zmiana względem poprzedniego skanu', 'change against the previous scan')}>{delta === 0 ? '±0' : fmtSigned(delta)}</span>
        ) : null}
      </dd>
      <dt className="mt-1.5 text-xs text-ink-3 group-hover:text-ink-2">{label}</dt>
    </>
  );
  return to
    ? <Link to={to} className="group -mx-2 flex flex-col rounded-md px-2 py-1.5 transition-colors hover:bg-raised">{inner}</Link>
    : <div className="flex flex-col py-1.5">{inner}</div>;
}

function Inventory({ d, pair }: { d: Dash; pair?: { full?: ScanRun; prev?: ScanRun } }) {
  const h = d.headline;
  // Deltas only between two full runs of the same profile, never across a partial run.
  const full = pair?.full, prev = pair?.prev;
  const dHosts = full && prev ? full.stats.hosts_up - prev.stats.hosts_up : null;
  const dServices = full && prev ? full.stats.services_open - prev.stats.services_open : null;
  const deltaTitle = full && prev ? t('zmiana między pełnymi skanami #' + prev.id + ' i #' + full.id + (full.profile_name ? ' (' + full.profile_name + ')' : ''), 'change between the full scans #' + prev.id + ' and #' + full.id + (full.profile_name ? ' (' + full.profile_name + ')' : '')) : undefined;
  return (
    <dl className="grid max-w-[1100px] grid-cols-2 gap-x-8 gap-y-4 sm:grid-cols-4" data-testid="dash-numbers">
      <Stat label={t('Aktywne hosty', 'Hosts up')} value={fmtInt(h.hosts_up)} delta={dHosts} deltaTitle={deltaTitle} to="/hosts?status=up" />
      <Stat label={t('Otwarte usługi', 'Open services')} value={fmtInt(h.services_open)} delta={dServices} deltaTitle={deltaTitle} to="/services?state=open" />
      <Stat label={t('Nieprzejrzane zmiany', 'Unreviewed changes')} value={fmtInt(h.changes_unacked)} to="/changes?acked=false&expected=false" />
      <Stat label={t('Znaleziska wysokiej wagi', 'High-severity findings')} value={fmtInt(h.findings_high)} to="/findings?severity=high&status=new,triaged" />
    </dl>
  );
}

/** The open ports a one-machine run has found so far (polled), instead of the address map. */
function LivePorts({ runId }: { runId: number }) {
  const q = useItem<Page<Service>>('/services', { run_id: runId, limit: 500 }, { refetchInterval: 1500 });
  const byPort = (a: Service, b: Service) => a.port - b.port;
  const { rows: items } = useArrivalOrder('live-ports-' + runId, q.data?.items ?? [], true, byPort, byPort);
  return (
    <div data-testid="live-ports">
      <p className="text-xs text-ink-3">{t('Otwarte usługi', 'Open services')} <span className="num text-ink-2">{items.length}</span></p>
      {items.length ? (
        <ul className="mt-1.5 flex flex-wrap gap-1">
          {items.slice(0, 40).map((s) => <li key={s.id}><Link to={'/services/' + s.id} className="mono inline-block border border-rule-strong px-1.5 py-0.5 text-xs hover:border-accent" title={serviceName(s)}>{s.port}</Link></li>)}
        </ul>
      ) : <p className="mt-1.5 text-xs text-ink-2">{t('Oczekiwanie na odpowiedzi…', 'Waiting for responses…')}</p>}
    </div>
  );
}

function ActiveRun({ initial }: { initial: ScanRun; d?: Dash }) {
  const { can } = useSession();
  const live = useLiveRun(initial.id);
  const run = live.run.data ?? initial;
  const map = useItem<RunMap>('/runs/' + run.id + '/map', undefined, { enabled: can('scans:read') });
  const profile = useItem<ScanProfile>('/profiles/' + run.profile_id, undefined, { enabled: Boolean(run.profile_id) && can('scans:read') });
  const s = run.stats;
  const pct = s.addresses_total ? s.addresses_done / s.addresses_total : 0;
  const small = s.addresses_total > 0 && s.addresses_total <= SMALL_RUN;
  const activeAddrs = (map.data?.blocks ?? []).filter((b) => b.status === 'running').reduce((a, b) => a + b.size, 0);
  void profile;
  return (
    <section className="card px-4 py-3" data-testid="dash-active-run">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-sm">
        <RunStatusMark status={run.status} pauseReason={run.pause_reason} />
        <Link to={'/runs/' + run.id} className="text-ink hover:underline">{t('Skan', 'Scan')} <span className="num">#{run.id}</span> <span className="text-ink-2">· {run.profile_name}</span></Link>
        <span className="num text-ink">{small ? fmtInt(s.services_open) + ' ' + plural(s.services_open, ['usługa', 'usługi', 'usług'], ['service', 'services']) : fmtPct(pct)}</span>
        {run.status === 'analyzing' ? <span className="text-ink-2">{t('analiza zmian…', 'analysing changes…')}</span> : s.eta_sec > 0 ? <span className="text-ink-2">{t('pozostało', 'remaining')} <span className="num text-ink">{fmtDuration(s.eta_sec)}</span></span> : null}
        <span className="num text-ink-3">{fmtInt(s.current_pps)} pps</span>
        <Link to={'/runs/' + run.id} className="link ml-auto inline-flex items-center gap-1 whitespace-nowrap">{t('Otwórz skan', 'Open scan')}<Icon name="arrowRight" size={12} /></Link>
      </div>
      <div className="mt-2.5"><ProgressBar value={s.addresses_done} max={s.addresses_total} active={activeAddrs} label={t('Postęp skanu', 'Scan progress')} /></div>
      <PartialNote run={run} className="mt-2" />
      {small ? <div className="mt-3"><LivePorts runId={run.id} /></div> : null}
    </section>
  );
}

function IdleRun({ d }: { d: Dash }) {
  const run = d.last_run;
  return (
    <section className="flex flex-wrap items-center gap-x-6 gap-y-1 border-y border-rule/70 py-2.5 text-sm text-ink-2" data-testid="dash-idle-run">
      <span className="inline-flex items-center gap-2"><span className="inline-block h-1.5 w-1.5 rounded-full bg-ink-3" aria-hidden="true" />{t('Żaden skan teraz nie działa', 'No scan is running')}</span>
      {run ? <span>{t('Ostatni', 'Last')} <Link className="link num" to={'/runs/' + run.id}>#{run.id}</Link> · {fmtDateTime(run.finished_at)} · {fmtDuration(run.stats.elapsed_sec)}</span> : null}
      <span>{t('Następny', 'Next')} {d.next_run_at ? <><span className="text-ink">{fmtDateTime(d.next_run_at)}</span> <span className="text-ink-3">({fmtRelative(d.next_run_at)})</span></> : t('brak harmonogramu', 'not scheduled')}</span>
      <Link to="/runs" className="link ml-auto">{t('Wszystkie', 'All')}</Link>
    </section>
  );
}

function Row({ to, children }: { to: string; children: ReactNode }) {
  return <li><Link to={to} className="flex min-h-[48px] items-start gap-3 border-b border-rule/60 px-4 py-2.5 transition-colors last:border-b-0 hover:bg-raised">{children}</Link></li>;
}

function RecentChanges({ changes }: { changes: Change[] }) {
  const [showExpected, setShowExpected] = useState(false);
  const real = changes.filter((c) => !c.expected);
  const expected = changes.filter((c) => c.expected);
  const list = (showExpected ? [...real.slice(0, 7), ...expected] : real.slice(0, 7));
  return (
    <Panel title={t('Najnowsze zmiany', 'Recent changes')} count={real.length} flush actions={<Link to="/changes" className="link">{t('Wszystkie', 'All')}</Link>}>
      {real.length === 0 && expected.length === 0 ? <p className="p-3 text-sm text-ink-2">{t('Brak zmian w ostatnim skanie.', 'No changes in the last scan.')}</p> : null}
      <ul>
        {list.map((c) => (
          <Row key={c.id} to={c.service_id ? '/services/' + c.service_id : '/hosts/' + c.host_id}>
            <span className="mt-0.5"><Glyph name={c.expected ? 'dashring' : changeKindInfo(c.kind).glyph} tone={c.expected ? 'expected' : changeKindInfo(c.kind).tone} /></span>
            <span className="min-w-0 flex-1">
              <span className={cx('block truncate text-sm', c.expected ? 'text-ink-2' : 'text-ink')} title={changeSummary(c)}>{changeSummary(c)}</span>
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
            : <>{expected.length} {plural(expected.length, ['zmiana oczekiwana', 'zmiany oczekiwane', 'zmian oczekiwanych'], ['expected change', 'expected changes'])} {t('. Pokaż', '. Show')}</>}
          <Icon name={showExpected ? 'chevronDown' : 'chevronRight'} size={12} />
        </button>
      ) : null}
    </Panel>
  );
}

function SafetyPanel({ st }: { st: Dash['safety'] }) {
  const { can } = useSession();
  return (
    <Panel title={t('Bezpieczeństwo skanowania', 'Scan safety')} actions={<Link to="/admin?tab=safety" className="link">{can('safety:manage') ? t('Polityka', 'Policy') : t('Polityka', 'Policy')}</Link>}>
      <p className={cx('mb-2 flex items-center gap-2 text-sm font-medium', st.emergency_stop ? 'text-danger' : 'text-ink')}>
        <Icon name={st.emergency_stop ? 'stop' : 'shield'} className={st.emergency_stop ? '' : 'text-st-new'} />
        {st.emergency_stop ? t('Stop awaryjny włączony', 'Emergency stop is on') : t('Tylko GET i HEAD', 'GET and HEAD only')}
      </p>
      <dl>
        <Stat label={t('Limit pakietów', 'Packet limit')} value={<>{fmtInt(st.max_pps)} <span className="font-sans text-xs font-normal text-ink-3">pps</span></>} />
        <Stat label={t('Limit żądań HTTP', 'HTTP request limit')} value={<>{st.max_http_rps} <span className="font-sans text-xs font-normal text-ink-3">{t('na s, ', 'per s, ')}{st.max_per_host_rps} {t('na host', 'per host')}</span></>} />
        <Stat label={t('Metody HTTP', 'HTTP methods')} value={(st.allowed_methods ?? []).join(', ')} />
        <Stat label={t('Wykluczenia', 'Exclusions')} value={(st.exclusions ?? []).length} />
        <Stat label={t('Stop awaryjny', 'Emergency stop')} value={<HostlessState on={st.emergency_stop} />} mono={false} />
      </dl>
    </Panel>
  );
}

interface Step { done: boolean; title: string; text?: string; state?: string; to?: string; cta?: string; blocked?: string }

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
      state: hasTargets ? fmtInt(addresses) + ' ' + plural(addresses, ['adres w zakresie', 'adresy w zakresie', 'adresów w zakresie'], ['address in scope', 'addresses in scope']) : (scopes.data?.total ? t('zakres istnieje, brakuje w nim celów', 'a scope exists, it has no target yet') : undefined),
      to: '/targets', cta: can('targets:create') ? t('Otwórz cele', 'Open targets') : t('Zobacz cele', 'View targets'),
    },
    {
      done: Boolean(ready),
      title: t('Przygotuj profil skanu', 'Prepare a scan profile'),
      state: ready ? t('profil „' + ready.name + '” ma przypisany zakres', 'the profile "' + ready.name + '" has a scope') : undefined,
      to: can('scans:configure') ? (first ? '/profiles/' + first.id : '/profiles/new') : '/profiles',
      cta: can('scans:configure') ? t('Otwórz profil', 'Open profile') : t('Zobacz profile', 'View profiles'),
    },
    {
      done: false,
      title: t('Uruchom pierwszy skan', 'Start the first scan'),
      blocked: engineOff ? t('Brak skanera w tej instalacji. Zaimportuj wyniki z pliku.', 'No scanner in this installation. Import results from a file.') : undefined,
      to: '/profiles', cta: can('scans:run') ? t('Uruchom skan', 'Start a scan') : undefined,
    },
  ];
  const next = steps.findIndex((s) => !s.done);
  return (
    <section aria-labelledby="first-run-title" data-testid="first-run">
      <h2 id="first-run-title" className="text-xl font-semibold tracking-[-0.015em]">{t('Czujka nie ma jeszcze danych o sieci.', 'Czujka has no data about the network yet.')}</h2>
      {can('targets:create') && can('scans:configure') ? <p className="mt-2 text-sm"><Link to="/setup" className="link">{t('Albo użyj kreatora', 'Or use the wizard')}</Link></p> : null}
      <ol className="mt-4 border-y border-rule">
        {steps.map((s, i) => (
          <li key={s.title} className="grid grid-cols-[28px_minmax(0,1fr)] items-start gap-x-3 gap-y-2 border-b border-rule py-3 last:border-b-0 sm:grid-cols-[28px_minmax(0,1fr)_auto]">
            <span className={cx('num mt-px flex h-[22px] w-[22px] items-center justify-center border text-xs', s.done ? 'border-st-new text-st-new' : i === next ? 'border-accent text-ink' : 'border-rule-strong text-ink-3')} aria-hidden="true">
              {s.done ? <Icon name="check" size={12} /> : i + 1}
            </span>
            <div className="min-w-0">
              <p className={cx('text-sm font-medium', s.done ? 'text-ink-2' : 'text-ink')}>{s.title}<span className="sr-only">{s.done ? ' (' + t('zrobione', 'done') + ')' : ''}</span></p>
              {s.text ? <p className="mt-0.5 max-w-[72ch] text-sm text-ink-2">{s.text}</p> : null}
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
          {t('Albo', 'Or')}
          <Link to="/transfer" className="link">{t('zaimportuj wyniki z nmap', 'import nmap results')}</Link>
        </p>
      ) : null}
    </section>
  );
}

export default function Dashboard() {
  const { can } = useSession();
  const q = useItem<Dash>('/dashboard', undefined, { refetchInterval: 60_000 });
  const runs = usePage<ScanRun>('/runs', { limit: 100, status: 'completed', sort: '-id' }, can('scans:read'));
  const now = useNow();
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!q.data) return <div className="p-4 sm:p-6"><div className="skeleton mb-3 h-8 w-[min(520px,80%)]" /><div className="skeleton mb-6 h-4 w-[min(380px,60%)]" /><SkeletonRows rows={10} /></div>;
  const d = q.data;
  const pair = lastFullPair(runs.data?.items ?? []);
  void now;
  const st = d.safety;
  const h0 = d.headline;
  const fresh = !d.last_run && !d.active_run && h0.hosts_up + h0.hosts_down + h0.hosts_unstable + h0.services_open + h0.findings_open + h0.changes_unacked === 0;
  // A fresh installation with nothing configured leads the administrator into the first-run wizard once.
  const setupDone = (() => { try { return Boolean(localStorage.getItem(SETUP_DONE_KEY)); } catch { return true; } })();
  if (fresh && h0.addresses_in_scope === 0 && can('targets:create') && can('scans:configure') && !setupDone) return <Navigate to="/setup" replace />;
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
    <div className="mx-auto max-w-[1480px] space-y-6 p-4 sm:p-6 lg:p-8">
      <h1 className="sr-only">{t('Pulpit', 'Dashboard')}</h1>
      <div className="space-y-7 pt-1">
        <Handover d={d} full={runs.data ? (pair.full ?? null) : undefined} />
        <div className="border-t border-rule/70 pt-5"><Inventory d={d} pair={runs.data ? pair : undefined} /></div>
      </div>

      {d.active_run ? <ActiveRun initial={d.active_run} d={d} /> : <IdleRun d={d} />}

      <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <RecentChanges changes={d.recent_changes ?? []} />
        <div className="grid gap-5">
        <Panel title={t('Najważniejsze znaleziska', 'Top findings')} flush actions={<Link to="/findings" className="link">{t('Wszystkie', 'All')}</Link>}>
          {(d.top_findings ?? []).length === 0 ? <p className="p-3 text-sm text-ink-2">{t('Brak otwartych znalezisk.', 'No open findings.')}</p> : null}
          <ul>
            {(d.top_findings ?? []).slice(0, 7).map((f) => (
              <Row key={f.id} to={'/findings?open=' + f.id}>
                <span className="mt-0.5"><Sev level={f.severity} compact /></span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm text-ink">{titleWithoutAddress(f.title, f.ip, f.port)}</span>
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


        <Panel title={t('Najciekawsze usługi', 'Most interesting services')} flush actions={<Link to="/services?sort=-interest" className="link">{t('Wszystkie', 'All')}</Link>}>
          <ul>
            {(d.top_services ?? []).slice(0, 7).map((s) => (
              <Row key={s.id} to={'/services/' + s.id}>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-ink">{s.title || s.product || serviceName(s)}</span>
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
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title={t('Technologie', 'Technologies')} actions={<span className="text-ink-3">{t('liczba usług', 'services')}</span>}>
          <BarList items={(d.technologies ?? []).slice(0, 10)} href={(i) => '/services?tech=' + encodeURIComponent(i.name)} labelWidth={150} />
        </Panel>
        <Panel title={t('Otwarte porty', 'Open ports')} actions={<span className="text-ink-3">{t('liczba usług', 'services')}</span>}>
          <BarList items={(d.ports ?? []).slice(0, 10)} mono href={(i) => '/services?port=' + i.name} labelWidth={150} extra={(i) => i.extra} />
        </Panel>
        <Panel title={t('Trend w kolejnych skanach', 'Trend over scans')}>
          <TrendRows points={d.trend ?? []} series={[
            { key: 'hosts', label: t('aktywne hosty', 'hosts up') },
            { key: 'services', label: t('otwarte usługi', 'open services') },
            { key: 'changes', label: t('zmiany', 'changes') },
          ]} />
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="min-w-0 space-y-4">
        <Panel title={t('Hosty niestabilne', 'Unstable hosts')} count={d.headline.hosts_unstable} flush actions={<Link to="/hosts?status=unstable" className="link">{t('Wszystkie', 'All')}</Link>}>
          {(d.unstable_hosts ?? []).length === 0 ? <p className="p-3 text-sm text-ink-2">{t('Brak niestabilnych hostów.', 'No unstable hosts.')}</p> : null}
          <ul>
            {(d.unstable_hosts ?? []).slice(0, 6).map((h) => (
              <li key={h.id}>
                <Link to={'/hosts/' + h.id} className="flex min-h-[30px] items-center gap-3 border-b border-rule px-3 py-1.5 hover:bg-raised">
                  <span className="mono w-[104px] flex-none text-sm">{h.ip}</span>
                  <span className="min-w-0 flex-1 truncate text-xs text-ink-2">{h.pattern}</span>
                  <span className="num flex-none text-xs text-ink-2" title={t('Prawdopodobieństwo, że host nadal istnieje', 'Probability that the host still exists')}>p {fmtDec(h.p_alive)}</span>
                </Link>
              </li>
            ))}
          </ul>
        </Panel>
        <ReprobePanel limit={5} />
        </div>
        <Panel title={t('Wygasające certyfikaty', 'Expiring certificates')} count={(d.certs_expiring ?? []).length} flush>
          {(d.certs_expiring ?? []).length === 0 ? <p className="p-3 text-sm text-ink-2">{t('Żaden certyfikat nie wygasa w ciągu 30 dni.', 'No certificates expire within 30 days.')}</p> : null}
          <ul>
            {(d.certs_expiring ?? []).slice(0, 6).map((s) => {
              const days = s.latest?.result.tls?.days_left ?? 0;
              return (
                <li key={s.id}>
                  <Link to={'/services/' + s.id} className="flex min-h-[30px] items-center gap-3 border-b border-rule px-3 py-1.5 hover:bg-raised">
                    <span className="mono min-w-0 flex-1 truncate text-sm">{s.hostname || s.ip}:{s.port}</span>
                    <span className="inline-flex flex-none items-center gap-1.5 text-xs">
                      <Glyph name={days < 0 ? 'x' : 'delta'} tone={days < 0 ? 'gone' : days <= 7 ? 'changed' : 'expected'} size={12} />
                      <span className={days <= 7 ? 'text-ink' : 'text-ink-2'}>{days < 0 ? t('wygasł ' + Math.abs(days) + ' ' + plural(Math.abs(days), ['dzień', 'dni', 'dni'], ['day', 'days']) + ' temu', 'expired ' + Math.abs(days) + ' ' + plural(Math.abs(days), ['dzień', 'dni', 'dni'], ['day', 'days']) + ' ago') : t('za ' + days + ' ' + plural(days, ['dzień', 'dni', 'dni'], ['day', 'days']), 'in ' + days + ' ' + plural(days, ['dzień', 'dni', 'dni'], ['day', 'days']))}</span>
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
    ? <span className="inline-flex items-center gap-1.5 text-sm"><Glyph name="x" tone="danger" />{t('włączony', 'on')}</span>
    : <span className="inline-flex items-center gap-1.5 text-sm font-normal text-ink-2"><Glyph name="ring" tone="expected" />{t('wyłączony', 'off')}</span>;
}

