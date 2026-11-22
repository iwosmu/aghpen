import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link, Navigate } from 'react-router';
import { SETUP_DONE_KEY } from './Setup';
import { useItem, usePage } from '../api/hooks';
import type { Change, Dashboard as Dash, Finding, Host, Page, RunMap, ScanProfile, ScanRun, Scope, Service } from '../api/types';
import { t, plural } from '../i18n';
import { cx, fmtDateTime, fmtDec, fmtDuration, fmtInt, fmtPct, fmtRelative, fmtSigned } from '../lib/format';
import { useLiveRun, useNow, useWidth } from '../lib/hooks';
import { NetworkField, NightStrip, PortField, Ring, Spark, TickBars, networkFields } from '../viz/Night';
import { ErrorState, Panel, SkeletonRows } from '../ui/kit';
import { useIsNarrow } from '../ui/table';
import { Icon } from '../ui/Icon';
import { ClassChips, Glyph, InterestScore, RunStatusMark, Sev, changeKindInfo, type GlyphName, type Tone } from '../ui/marks';
import { BarList, ProgressBar } from '../viz/charts';
import { useSession } from '../session';
import { useRunStoryShown } from '../ui/RunStory';
import { useHostVerdicts } from '../ui/MissingHosts';
import { PartialNote } from '../ui/RunPasses';
import { useArrivalOrder } from '../ui/arrivalOrder';
import { SMALL_RUN } from './RunDetail';
import { serviceName } from '../lib/serviceName';
import { findingRows, rowsByAddress, spanText } from '../lib/dashLists';
import { ReprobePanel } from './Reprobe';
import { ATTENTION_INTEREST, adminPanelNames, adminPanelServiceNames, isFullRun, lastFullPair, partialRunPhrase } from '../lib/headline';

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
  const storyShown = useRunStoryShown(run?.id);
  if (!run && partial) {
    return (
      <div>
        <p className="font-display text-[34px] leading-[1.05] text-ink sm:text-[46px]" data-testid="handover">{t('Nie ma jeszcze pełnego skanu profilu do porównania.', 'No full profile scan to compare yet.')}</p>
        <p className="mt-2 text-sm text-ink-2" data-testid="handover-partial">{t('Ostatnio', 'Last')}: {partialRunPhrase(partial)} (<Link to={'/runs/' + partial.id} className="num link">#{partial.id}</Link>, {fmtRelative(partial.finished_at)}).</p>
      </div>
    );
  }
  if (!run) {
    return (
      <div>
        <p className="font-display text-[34px] leading-[1.05] text-ink sm:text-[46px]">{t('Nie ma jeszcze zakończonego skanu.', 'No scan has completed yet.')}</p>
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
      <p className="font-display text-[34px] leading-[1.05] text-ink sm:text-[46px] xl:text-[54px]" data-testid="handover">{headline}</p>
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
      {s && !baseline && storyShown === false && !(quiet && !expected && !unreachable) ? (
        <div className="mt-4 flex flex-wrap gap-x-5 gap-y-1" data-testid="handover-counts">
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

function useViewportHeight(): number {
  const [h, setH] = useState(() => (typeof window === 'undefined' ? 900 : window.innerHeight));
  useEffect(() => {
    const fn = () => setH(window.innerHeight);
    window.addEventListener('resize', fn);
    return () => window.removeEventListener('resize', fn);
  }, []);
  return h;
}

function Stat({ label, value, delta, deltaTitle, to, mono = true, pic }: { label: string; value: ReactNode; delta?: number | null; deltaTitle?: string; to?: string; mono?: boolean; pic?: ReactNode }) {
  const inner = (
    <>
      <dt className="text-[13px] font-medium text-ink">{label}</dt>
      <dd className="mt-auto flex items-end justify-between gap-3 pt-3 xl:flex-col xl:items-start xl:gap-1.5 xl:pt-1.5">
        <span className="flex items-baseline gap-2">
          <span className={cx('text-ink', mono ? 'font-display text-[40px] leading-none sm:text-[46px] xl:text-[40px] 2xl:text-[46px]' : 'text-base font-medium')}>{value}</span>
          {delta !== undefined && delta !== null ? (
            <span className="num text-xs text-ink-2" title={deltaTitle ?? t('zmiana względem poprzedniego skanu', 'change against the previous scan')}>{delta === 0 ? '±0' : fmtSigned(delta)}</span>
          ) : null}
        </span>
        {pic ? <span className="mb-1 flex-none">{pic}</span> : null}
      </dd>
    </>
  );
  if (!mono) return <div className="flex flex-col py-1.5">{inner}</div>;
  const cls = 'card group flex min-h-[116px] flex-col rounded-[22px] px-5 py-4 transition-colors xl:min-h-0 xl:py-3 2xl:py-4';
  return to
    ? <Link to={to} className={cx(cls, 'hover:bg-[color-mix(in_oklch,var(--panel),var(--ink)_5%)]')}>{inner}</Link>
    : <div className={cls}>{inner}</div>;
}

function Inventory({ d, pair, runs }: { d: Dash; pair?: { full?: ScanRun; prev?: ScanRun }; runs: ScanRun[] }) {
  const h = d.headline;
  // Deltas only between two full runs of the same profile, never across a partial run.
  const full = pair?.full, prev = pair?.prev;
  const dHosts = full && prev ? full.stats.hosts_up - prev.stats.hosts_up : null;
  const dServices = full && prev ? full.stats.services_open - prev.stats.services_open : null;
  const deltaTitle = full && prev ? t('zmiana między pełnymi skanami #' + prev.id + ' i #' + full.id + (full.profile_name ? ' (' + full.profile_name + ')' : ''), 'change between the full scans #' + prev.id + ' and #' + full.id + (full.profile_name ? ' (' + full.profile_name + ')' : '')) : undefined;
  // the same per-scan series as the API's trend, oldest first
  const trend = d.trend ?? [];
  void runs;
  return (
    <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4 sm:gap-4 xl:h-full xl:grid-cols-1 xl:grid-rows-4" data-testid="dash-numbers">
      <Stat label={t('Aktywne hosty', 'Hosts up')} value={fmtInt(h.hosts_up)} delta={dHosts} deltaTitle={deltaTitle} to="/hosts?status=up" pic={<Spark values={trend.map((p) => p.hosts)} width={96} height={34} />} />
      <Stat label={t('Otwarte usługi', 'Open services')} value={fmtInt(h.services_open)} delta={dServices} deltaTitle={deltaTitle} to="/services?state=open" pic={<Spark values={trend.map((p) => p.services)} width={96} height={34} />} />
      <Stat label={t('Nieprzejrzane zmiany', 'Unreviewed changes')} value={fmtInt(h.changes_unacked)} to="/changes?acked=false&expected=false" pic={<TickBars values={trend.map((p) => p.changes)} width={96} height={34} />} />
      <Stat label={t('Znaleziska wysokiej wagi', 'High-severity findings')} value={fmtInt(h.findings_high)} to="/findings?severity=high&status=new,triaged" pic={h.findings_open ? <Ring value={h.findings_high} max={h.findings_open} size={38} /> : undefined} />
    </dl>
  );
}

/** The network as the picture: every /24 of the scanned /16 (or every address of one /24) as a cell. */
function Stage({ d }: { d: Dash }) {
  const { can } = useSession();
  const hostsQ = usePage<Host>('/hosts', { limit: 1000 });
  const lastId = d.last_run?.id;
  const chQ = usePage<Change>('/changes', { run_id: lastId, expected: false, limit: 500 }, Boolean(lastId));
  const active = d.active_run;
  const map = useItem<RunMap>('/runs/' + (active?.id ?? 0) + '/map', undefined, { enabled: Boolean(active) && can('scans:read'), refetchInterval: 3000 });
  const hosts = hostsQ.data?.items;
  const changes = chQ.data?.items;
  const blocks = map.data?.blocks;
  const fields = useMemo(
    () => networkFields(hosts ?? [], changes ?? [], (blocks ?? []).filter((b) => b.status === 'running').map((b) => b.cidr)),
    [hosts, changes, blocks],
  );
  // one machine in scope: its open ports are the cells
  const oneHost = hosts && hosts.length === 1 ? hosts[0] : null;
  const portsQ = usePage<Service>('/services', { host_id: oneHost?.id, limit: 200 }, Boolean(oneHost));
  const [ref, w] = useWidth<HTMLDivElement>();
  const main = fields[0];
  const vh = useViewportHeight();
  const wide = !useIsNarrow(1280);
  // from 1280 px the field stays square beside the tiles and above the fold: about 500 to 540 px
  const size = Math.floor(Math.max(240, Math.min(w - 2 * Math.max(16, w / 32), wide ? Math.max(340, Math.min(540, vh - 340)) : 760)));
  const unitSteps = main?.unit === 'block' ? [['2', '1'], ['3', '2–3'], ['4', '4–9'], ['5', '10+']] : [];
  return (
    <section className="card relative flex h-full min-h-[320px] flex-col overflow-hidden rounded-[28px] bg-[radial-gradient(60%_55%_at_50%_52%,rgb(38_97_220/0.13),transparent_75%),var(--panel)] p-5 sm:p-6" data-testid="dash-field">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <p className="mono text-[15px] text-ink">{oneHost ? oneHost.ip : main?.label ?? ''}</p>
        {unitSteps.length && !oneHost ? (
          <p className="flex items-center gap-3 text-2xs text-ink-2" aria-hidden="true">
            {unitSteps.map(([s, l]) => <span key={s} className="num inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-[3px]" style={{ background: 'var(--seq-' + s + ')' }} />{l}</span>)}
          </p>
        ) : null}
      </div>
      <div ref={ref} className="flex flex-1 items-center justify-center py-4">
        {hostsQ.isPending ? <div className="skeleton rounded-[18px]" style={{ width: size, height: size }} /> : oneHost ? (portsQ.data && w ? <PortField services={(portsQ.data.items ?? []).filter((s) => s.state === 'open')} changes={changes ?? []} size={size} /> : null) : main && w ? <NetworkField field={main} size={size} /> : null}
      </div>
      {fields.length > 1 && !oneHost ? (
        <div className="flex flex-wrap gap-5">
          {fields.slice(1, 5).map((f) => (
            <div key={f.key} className="flex items-center gap-3">
              <NetworkField field={f} size={64} />
              <span className="mono text-xs text-ink-2">{f.label}</span>
            </div>
          ))}
        </div>
      ) : null}
    </section>
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
    <section data-testid="dash-active-run">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-sm">
        <RunStatusMark status={run.status} pauseReason={run.pause_reason} />
        <Link to={'/runs/' + run.id} className="text-ink hover:underline">{t('Skan', 'Scan')} <span className="num">#{run.id}</span> <span className="text-ink-2">· {run.profile_name}</span></Link>
        <span className="num text-ink">{small ? fmtInt(s.services_open) + ' ' + plural(s.services_open, ['usługa', 'usługi', 'usług'], ['service', 'services']) : fmtPct(pct)}</span>
        {run.status === 'analyzing' ? <span className="text-ink-2">{t('analiza zmian…', 'analysing changes…')}</span> : s.eta_sec > 0 ? <span className="text-ink-2">{t('pozostało', 'remaining')} <span className="num text-ink">{fmtDuration(s.eta_sec)}</span></span> : null}
        <span className="num text-ink-2">{fmtInt(s.current_pps)} pps</span>
        <Link to={'/runs/' + run.id} className="ml-auto inline-flex h-[30px] items-center gap-1.5 whitespace-nowrap rounded-full bg-primary px-3.5 text-xs font-semibold text-primary-ink hover:bg-primary-hover">{t('Otwórz skan', 'Open scan')}<Icon name="arrowRight" size={12} /></Link>
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
    <section className="grid gap-1.5 text-sm text-ink-2" data-testid="dash-idle-run">
      <span className="flex items-center justify-between gap-3">
        <span className="inline-flex items-center gap-2 font-medium text-ink"><span className="inline-block h-2 w-2 rounded-full bg-ink-3" aria-hidden="true" />{t('Żaden skan teraz nie działa', 'No scan is running')}</span>
        <Link to="/runs" className="link text-xs">{t('Wszystkie', 'All')}</Link>
      </span>
      {run ? <span>{t('Ostatni', 'Last')} <Link className="link num" to={'/runs/' + run.id}>#{run.id}</Link> · {fmtDateTime(run.finished_at)} · {fmtDuration(run.stats.elapsed_sec)}</span> : null}
      <span>{t('Następny', 'Next')} {d.next_run_at ? <><span className="text-ink">{fmtDateTime(d.next_run_at)}</span> <span className="text-ink-3">({fmtRelative(d.next_run_at)})</span></> : t('brak harmonogramu', 'not scheduled')}</span>
    </section>
  );
}

function Row({ to, children }: { to: string; children: ReactNode }) {
  return <li><Link to={to} className="-mx-3 flex min-h-[52px] items-start gap-3 rounded-[14px] px-3 py-2.5 transition-colors hover:bg-[var(--row-hover)]">{children}</Link></li>;
}

/** A list in the dashboard's side rail: a label in ink, an "all" link, roomy rows. */
function RailList({ title, to, children }: { title: string; to: string; children: ReactNode }) {
  return (
    <section>
      <div className="mb-1 flex items-center justify-between gap-3">
        <h2 className="eyebrow">{title}</h2>
        <Link to={to} className="link text-xs">{t('Wszystkie', 'All')}</Link>
      </div>
      {children}
    </section>
  );
}

/** One row per finding kind (as on the findings page): count of places, worst score, newest first seen. */
function TopFindings() {
  // No grouped endpoint: the open findings are grouped here, as the findings page does.
  const q = usePage<Finding>('/findings', { status: 'new,triaged', sort: '-interest', limit: 1000 });
  const rows = findingRows(q.data?.items ?? []);
  return (
    <RailList title={t('Najważniejsze znaleziska', 'Top findings')} to="/findings">
      {q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : !q.data ? <SkeletonRows rows={4} /> : rows.length === 0 ? <p className="py-3 text-sm text-ink-2">{t('Brak otwartych znalezisk.', 'No open findings.')}</p> : null}
      <ul data-testid="top-findings">
        {rows.slice(0, 6).map(({ group: g, newest, to }) => {
          const services = g.items.every((f) => f.port);
          return (
            <Row key={g.key} to={to}>
              <span className="mt-0.5"><Sev level={g.severity} compact /></span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm text-ink" title={g.title}>{g.title}</span>
                <span className="mt-1 flex flex-wrap gap-1.5"><span className="chip-fact"><span className="num text-ink">{g.places}</span> {services ? plural(g.places, ['usługa', 'usługi', 'usług'], ['service', 'services']) : plural(g.places, ['adres', 'adresy', 'adresów'], ['address', 'addresses'])}</span><span className="chip-fact">{t('najnowsze', 'newest')} {fmtRelative(newest)}</span></span>
              </span>
              <span className="mt-0.5 flex-none"><InterestScore value={g.interest} /></span>
            </Row>
          );
        })}
      </ul>
    </RailList>
  );
}

function RecentChanges({ fallback }: { fallback: Change[] }) {
  // One row per address over the last 100 changes; the dashboard's own list while they load.
  const q = usePage<Change>('/changes', { expected: false, sort: '-at', limit: 100 });
  const rows = rowsByAddress(q.data?.items ?? fallback);
  return (
    <RailList title={t('Najnowsze zmiany', 'Recent changes')} to="/changes">
      {rows.length === 0 ? <p className="py-3 text-sm text-ink-2">{t('Brak zmian w ostatnim skanie.', 'No changes in the last scan.')}</p> : null}
      <ul data-testid="recent-changes">
        {rows.slice(0, 6).map(({ ip, latest: c, items, spanSec }) => {
          const many = items.length > 1;
          const to = many ? '/changes?expected=false&q=' + encodeURIComponent(ip) : c.service_id ? '/services/' + c.service_id : '/hosts/' + c.host_id;
          return (
            <Row key={ip} to={to}>
              <span className="mt-0.5"><Glyph name={changeKindInfo(c.kind).glyph} tone={changeKindInfo(c.kind).tone} /></span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm text-ink" title={c.summary}>{c.summary}</span>
                <span className="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-ink-2">
                  <span className="chip-fact mono text-ink">{many ? ip : ip + (c.port ? ':' + c.port : '')}</span>
                  {many ? <span className="chip-fact" data-testid="change-run">{items.length} {plural(items.length, ['zmiana', 'zmiany', 'zmian'], ['change', 'changes'])}{spanText(spanSec) ? ' ' + spanText(spanSec) : ''}</span> : null}
                  <Sev level={c.severity} />
                </span>
              </span>
            </Row>
          );
        })}
      </ul>
    </RailList>
  );
}

function SafeRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex min-h-[36px] items-baseline justify-between gap-3 py-1.5">
      <dt className="text-xs text-ink-2">{label}</dt>
      <dd className="text-right text-sm font-medium text-ink">{value}</dd>
    </div>
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
        <SafeRow label={t('Limit pakietów', 'Packet limit')} value={<>{fmtInt(st.max_pps)} <span className="font-sans text-xs font-normal text-ink-3">pps</span></>} />
        <SafeRow label={t('Limit żądań HTTP', 'HTTP request limit')} value={<>{st.max_http_rps} <span className="font-sans text-xs font-normal text-ink-3">{t('na s, ', 'per s, ')}{st.max_per_host_rps} {t('na host', 'per host')}</span></>} />
        <SafeRow label={t('Metody HTTP', 'HTTP methods')} value={(st.allowed_methods ?? []).join(', ')} />
        <SafeRow label={t('Wykluczenia', 'Exclusions')} value={(st.exclusions ?? []).length} />
        <SafeRow label={t('Stop awaryjny', 'Emergency stop')} value={<HostlessState on={st.emergency_stop} />} />
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
  const allRuns = usePage<ScanRun>('/runs', { limit: 300, sort: '-id' }, can('scans:read'));
  const now = useNow();
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!q.data) return <div className="p-4 sm:p-6"><div className="skeleton mb-3 h-8 w-[min(520px,80%)]" /><div className="skeleton mb-6 h-4 w-[min(380px,60%)]" /><SkeletonRows rows={10} /></div>;
  const d = q.data;
  const pair = lastFullPair(runs.data?.items ?? []);
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
    <div className="mx-auto max-w-[1680px] space-y-5 px-4 pb-8 pt-1 sm:px-6 lg:px-8">
      <h1 className="sr-only">{t('Pulpit', 'Dashboard')}</h1>
      <Handover d={d} full={runs.data ? (pair.full ?? null) : undefined} />

      <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_340px] 2xl:grid-cols-[minmax(0,1fr)_400px]">
        <div className="min-w-0 space-y-4">
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_190px] 2xl:grid-cols-[minmax(0,1fr)_230px]">
            <div className="xl:order-2"><Inventory d={d} pair={runs.data ? pair : undefined} runs={allRuns.data?.items ?? []} /></div>
            <div className="min-w-0 xl:order-1"><Stage d={d} /></div>
          </div>
          <Panel title={t('Najciekawsze usługi', 'Most interesting services')} flush actions={<Link to="/services?sort=-interest" className="link">{t('Wszystkie', 'All')}</Link>}>
          <ul className="grid px-5 lg:grid-cols-2 lg:gap-x-8">
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
        <aside className="card min-w-0 space-y-7 rounded-[28px] p-5 sm:p-6">
          <div className="space-y-4">
            {d.active_run ? <ActiveRun initial={d.active_run} d={d} /> : <IdleRun d={d} />}
            <NightStrip runs={allRuns.data?.items ?? []} active={d.active_run} currentId={d.active_run ? undefined : d.last_run?.id} now={now} />
          </div>
          <RecentChanges fallback={d.recent_changes ?? []} />
          <TopFindings />
        </aside>
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-3">
        <Panel title={t('Technologie', 'Technologies')} actions={<span className="text-ink-3">{t('liczba usług', 'services')}</span>}>
          <BarList items={(d.technologies ?? []).slice(0, 10)} href={(i) => '/services?tech=' + encodeURIComponent(i.name)} labelWidth={150} />
        </Panel>
        <Panel title={t('Otwarte porty', 'Open ports')} actions={<span className="text-ink-3">{t('liczba usług', 'services')}</span>}>
          <BarList items={(d.ports ?? []).slice(0, 10)} mono href={(i) => '/services?port=' + i.name} labelWidth={150} extra={(i) => i.extra} />
        </Panel>
        <SafetyPanel st={st} />
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-3">
        <div className="contents">
        <Panel title={t('Hosty niestabilne', 'Unstable hosts')} count={d.headline.hosts_unstable} flush actions={<Link to="/hosts?status=unstable" className="link">{t('Wszystkie', 'All')}</Link>}>
          {(d.unstable_hosts ?? []).length === 0 ? <p className="px-5 pb-3 pt-1 text-sm text-ink-2">{t('Brak niestabilnych hostów.', 'No unstable hosts.')}</p> : null}
          <ul>
            {(d.unstable_hosts ?? []).slice(0, 6).map((h) => (
              <li key={h.id}>
                <Link to={'/hosts/' + h.id} className="flex min-h-[44px] items-center gap-3 border-b border-rule px-5 py-2 last:border-b-0 hover:bg-[var(--row-hover)]">
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
          {(d.certs_expiring ?? []).length === 0 ? <p className="px-5 pb-3 pt-1 text-sm text-ink-2">{t('Żaden certyfikat nie wygasa w ciągu 30 dni.', 'No certificates expire within 30 days.')}</p> : null}
          <ul>
            {(d.certs_expiring ?? []).slice(0, 6).map((s) => {
              const days = s.latest?.result.tls?.days_left ?? 0;
              return (
                <li key={s.id}>
                  <Link to={'/services/' + s.id} className="flex min-h-[44px] items-center gap-3 border-b border-rule px-5 py-2 last:border-b-0 hover:bg-[var(--row-hover)]">
                    <span className="mono min-w-0 flex-1 truncate text-[13px]">{s.hostname || s.ip}:{s.port}</span>
                    <span className="inline-flex flex-none items-center gap-1.5 text-xs">
                      <Glyph name={days < 0 ? 'x' : 'delta'} tone={days < 0 ? 'gone' : days <= 7 ? 'changed' : 'expected'} size={12} />
                      <span className={days <= 7 ? 'text-ink' : 'text-ink-2'}>{days < 0 ? t('wygasł ' + Math.abs(days) + ' ' + plural(Math.abs(days), ['dzień', 'dni', 'dni'], ['day', 'days']) + ' temu', 'expired ' + Math.abs(days) + ' ' + plural(Math.abs(days), ['dzień', 'dni', 'dni'], ['day', 'days']) + ' ago') : days === 0 ? t('dziś', 'today') : t('za ' + days + ' ' + plural(days, ['dzień', 'dni', 'dni'], ['day', 'days']), 'in ' + days + ' ' + plural(days, ['dzień', 'dni', 'dni'], ['day', 'days']))}</span>
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </Panel>
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

