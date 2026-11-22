import { useMemo, type ReactNode } from 'react';
import { Link, Navigate } from 'react-router';
import { SETUP_DONE_KEY } from './Setup';
import { useItem, usePage } from '../api/hooks';
import type { Change, Dashboard as Dash, Finding, Host, Page, RunMap, ScanProfile, ScanRun, Scope, Service } from '../api/types';
import { t, plural } from '../i18n';
import { cx, fmtDateTime, fmtDuration, fmtInt, fmtPct, fmtRelative, fmtSigned, fmtTime } from '../lib/format';
import { useLiveRun, useNow, useWidth } from '../lib/hooks';
import { LampLegend, NetworkField, NightStrip, PortField, networkFields, runChanges } from '../viz/Night';
import { ErrorState, Panel, SkeletonRows } from '../ui/kit';
import { Icon } from '../ui/Icon';
import { Glyph, changeKindInfo } from '../ui/marks';
import { useSession } from '../session';
import { useHostVerdicts } from '../ui/MissingHosts';
import { findingRows, rowsByAddress } from '../lib/dashLists';
import { isFullRun, lastFullPair, partialRunPhrase } from '../lib/headline';


/** The handover report: what changed and, from the data, what needs attention. */
/** One mono line under the title: the last scan, its age and the next one; while a scan runs, its lamp and percent. */
/** '3 min', '2 godz.': the relative time without 'temu' / 'ago'. */
function shortAge(iso: string | null | undefined): string { return fmtRelative(iso).replace(/\s+(temu|ago)$/, ''); }

function MetaLine({ d, run }: { d: Dash; run: ScanRun }) {
  const active = d.active_run;
  const live = useLiveRun(active?.id);
  if (active) {
    const r = live.run.data ?? active;
    const s = r.stats;
    const pct = s.addresses_total ? s.addresses_done / s.addresses_total : 0;
    return (
      <p className="mono mt-2 text-[13px] text-ink-3" data-testid="dash-active-run">
        <span className="lamp nf-pulse mr-2 inline-block align-[0px]" style={{ background: 'var(--accent)' }} aria-hidden="true" />
        <Link to={'/runs/' + r.id} className="text-ink hover:underline">{t('Skan', 'Scan')} #{r.id}</Link> · {fmtPct(pct)}
        {s.eta_sec > 0 ? <> · {fmtDuration(s.eta_sec)}</> : null}
      </p>
    );
  }
  const next = d.next_run_at;
  const soon = next ? new Date(next).getTime() - Date.now() < 20 * 3600_000 : false;
  return (
    <p className="mono mt-2 text-[13px] text-ink-3" data-testid="dash-idle-run">
      <Link to={'/runs/' + run.id} className="hover:text-ink hover:underline">{t('Skan', 'Scan')} #{run.id}</Link> · {fmtRelative(run.finished_at)}
      {next ? <> · {t('następny', 'next')} {soon ? fmtTime(next) : fmtDateTime(next)}</> : null}
    </p>
  );
}

function Handover({ d, full }: { d: Dash; full?: ScanRun | null }) {
  const h = d.headline;
  // The headline compares the last two full runs of one profile; a partial run
  // (ad hoc, re-probe, import, manual entry) only gets its own short line.
  const last = d.last_run;
  const partial = last && !isFullRun(last) ? last : null;
  const run = full === undefined ? (partial ? null : last) : full;
  const s = run?.summary;
  // Hosts that did not answer in this run, and what the confirmation probe decided since.
  const missingQ = useItem<Page<Change>>('/changes', { run_id: run?.id, kind: 'host_missing,service_unreachable', limit: 500 }, { enabled: Boolean(run?.id) && (s?.hosts_missing ?? 0) > 0 });
  const missingItems = missingQ.data?.items ?? [];
  const verdicts = useHostVerdicts(missingItems.filter((c) => c.kind === 'host_missing'));
  const confirmedGone = [...verdicts.values()].filter((v) => v.kind === 'host_gone').length;
  if (!run && partial) {
    return (
      <div>
        <p className="font-display text-[28px] leading-[1.15] text-ink sm:text-[34px]" data-testid="handover">{t('Nie ma jeszcze pełnego skanu profilu do porównania', 'No full profile scan to compare yet')}</p>
        <p className="mt-2 text-sm text-ink-2" data-testid="handover-partial">{t('Ostatnio', 'Last')}: {partialRunPhrase(partial)} (<Link to={'/runs/' + partial.id} className="num link">#{partial.id}</Link>, {fmtRelative(partial.finished_at)}).</p>
      </div>
    );
  }
  if (!run) {
    return (
      <div>
        <p className="font-display text-[28px] leading-[1.15] text-ink sm:text-[34px]">{t('Nie ma jeszcze zakończonego skanu', 'No scan has completed yet')}</p>
        <p className="mt-2 text-base text-ink-2">{t('Dodaj cele, przygotuj profil i uruchom skan.', 'Add targets, prepare a profile and start a scan.')}</p>
        <Link to="/targets" className="link mt-3 inline-block text-sm">{t('Dodaj cele', 'Add targets')}</Link>
      </div>
    );
  }
  const baseline = Boolean(s) && !s!.prev_run_id;
  const changed = s ? s.services_changed : 0;
  const missing = Math.max(0, (s?.hosts_missing ?? 0) - verdicts.size);
  const added = s ? s.hosts_new + s.services_new : 0;
  const gone = s ? s.hosts_gone + s.services_gone : 0;
  const returned = s?.services_returned ?? 0;
  const slower = s?.responses_slower ?? 0;
  const recovered = s?.by_kind?.response_recovered ?? 0;
  // with per-kind counts, the headline counts what the changes page lists for this run: rows that were not expected
  const listed = run && s?.by_kind ? runChanges(run) : null;
  const quiet = listed !== null ? listed === 0 : s ? added + gone + changed + s.hosts_unstable + missing + confirmedGone + returned + slower + recovered === 0 : true;
  const headline = baseline
    ? t('Pierwszy obraz sieci: ' + fmtInt(h.hosts_up) + ' ' + plural(h.hosts_up, ['aktywny host', 'aktywne hosty', 'aktywnych hostów'], ['', '']) + ', ' + fmtInt(h.services_open) + ' ' + plural(h.services_open, ['otwarta usługa', 'otwarte usługi', 'otwartych usług'], ['', '']) + '.',
      'First picture of the network: ' + fmtInt(h.hosts_up) + ' ' + (h.hosts_up === 1 ? 'host' : 'hosts') + ' up, ' + fmtInt(h.services_open) + ' open ' + (h.services_open === 1 ? 'service' : 'services') + '.')
    : quiet
      ? t('Bez zmian od poprzedniego skanu', 'No change since the previous scan')
      : (() => { const n = listed ?? added + gone + changed + missing + s!.hosts_unstable + returned + slower + recovered + confirmedGone; return t(fmtInt(n) + ' ' + plural(n, ['zmiana', 'zmiany', 'zmian'], ['', '']) + ' od poprzedniego skanu.', fmtInt(n) + ' ' + (n === 1 ? 'change' : 'changes') + ' since the previous scan.'); })();
  return (
    <div>
      <p className="font-display text-[28px] leading-[1.15] text-ink sm:text-[34px]" data-testid="handover">{headline.replace(/\.$/, '')}</p>
      <MetaLine d={d} run={run} />
    </div>
  );
}


function Stat({ label, value, note, noteTitle, to, mono = true }: { label: string; value: ReactNode; note?: ReactNode; noteTitle?: string; to?: string; mono?: boolean; delta?: number | null; deltaTitle?: string; pic?: ReactNode }) {
  const inner = (
    <>
      <dt className="text-[13px] text-ink-2 group-hover:text-ink">{label}</dt>
      <dd className="mt-2">
        <span className={cx('block text-ink', mono ? 'num text-[30px] font-medium leading-none' : 'text-base font-medium')}>{value}</span>
        <span className="mono mt-2 block min-h-[16px] text-[12px] leading-4 text-ink-3" title={noteTitle}>{note}</span>
      </dd>
    </>
  );
  if (!mono) return <div className="flex flex-col py-1.5">{inner}</div>;
  const cls = 'group flex flex-col';
  return to
    ? <Link to={to} className={cls}>{inner}</Link>
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
  void runs;
  // the same run the headline describes
  const lastRun = full ?? d.last_run;
  const lastChanges = lastRun ? runChanges(lastRun) : 0;
  const newHighQ = usePage<Finding>('/findings', { severity: 'high', status: 'new', limit: 1 });
  const newHigh = newHighQ.data?.total;
  // the change and what it compares to, as one muted mono line
  const vs = (n: number | null) => (n === null || !prev ? undefined : (n === 0 ? '±0' : fmtSigned(n)) + ' ' + t('względem skanu', 'vs scan') + ' #' + prev.id);
  return (
    <dl className="grid grid-cols-2 gap-x-8 gap-y-5 lg:grid-cols-4" data-testid="dash-numbers">
      <Stat label={t('Aktywne hosty', 'Hosts up')} value={fmtInt(h.hosts_up)} note={vs(dHosts)} noteTitle={deltaTitle} to="/hosts?status=up" />
      <Stat label={t('Otwarte usługi', 'Open services')} value={fmtInt(h.services_open)} note={vs(dServices)} noteTitle={deltaTitle} to="/services?state=open" />
      <Stat label={t('Nieprzejrzane zmiany', 'Unreviewed changes')} value={fmtInt(h.changes_unacked)} note={lastRun ? (lastChanges ? '+' + fmtInt(lastChanges) : '0') + ' ' + t('w skanie', 'in scan') + ' #' + lastRun.id : undefined} to="/changes?acked=false&expected=false" />
      <Stat label={t('Znaleziska wysokiej wagi', 'High-severity findings')} value={fmtInt(h.findings_high)} note={newHigh === undefined ? undefined : fmtInt(newHigh) + ' ' + plural(newHigh, ['nowe', 'nowe', 'nowych'], ['new', 'new'])} to="/findings?severity=high&status=new,triaged" />
    </dl>
  );
}

/** The network as the picture: every /24 of the scanned /16 (or every address of one /24) as a cell. */
function Stage({ d, scale }: { d: Dash; scale: ReactNode }) {
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
  const changedIn = d.last_run && (changes ?? []).length ? '#' + d.last_run.id : undefined;
  return (
    <section className="card p-5 sm:p-6" data-testid="dash-field">
      <div className="mb-4 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <p className="mono text-[13px] text-ink-2">{oneHost ? oneHost.ip : main?.label ?? ''}</p>
        {main && !oneHost ? <LampLegend unit={main.unit} changedLabel={changedIn} /> : null}
      </div>
      <div ref={ref} className="min-w-0">
        {hostsQ.isPending ? <div className="skeleton h-[200px] rounded-[10px]" /> : oneHost ? (portsQ.data && w ? <PortField services={(portsQ.data.items ?? []).filter((s) => s.state === 'open')} changes={changes ?? []} size={Math.min(w, 520)} /> : null) : main && w ? <NetworkField field={main} width={w} /> : null}
      </div>
      {fields.length > 1 && !oneHost ? (
        <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1">
          {fields.slice(1, 5).map((f) => <span key={f.key} className="mono text-[12px] text-ink-3">{f.label} · {f.up}</span>)}
        </div>
      ) : null}
      <div className="mt-5 border-t border-rule pt-4">{scale}</div>
    </section>
  );
}



function IdleRun({ d }: { d: Dash }) {
  const run = d.last_run;
  return (
    <section className="grid gap-1.5 text-sm text-ink-2" data-testid="dash-idle-run">
      <span className="flex items-center justify-between gap-3">
        <span className="inline-flex items-center gap-2 font-medium text-ink"><span className="lamp bg-ink-3" aria-hidden="true" />{t('Żaden skan teraz nie działa', 'No scan is running')}</span>
        <Link to="/runs" className="text-xs text-ink-3 decoration-[var(--rule-strong)] underline-offset-4 hover:text-ink hover:underline">{t('Wszystkie', 'All')}</Link>
      </span>
      {run ? <span>{t('Ostatni', 'Last')} <Link className="link num" to={'/runs/' + run.id}>#{run.id}</Link> · {fmtDateTime(run.finished_at)} · {fmtDuration(run.stats.elapsed_sec)}</span> : null}
      <span>{t('Następny', 'Next')} {d.next_run_at ? <><span className="text-ink">{fmtDateTime(d.next_run_at)}</span> <span className="text-ink-3">({fmtRelative(d.next_run_at)})</span></> : t('brak harmonogramu', 'not scheduled')}</span>
    </section>
  );
}

function Row({ to, children }: { to: string; children: ReactNode }) {
  return <li><Link to={to} className="-mx-3 flex h-[36px] items-center gap-3 rounded-[8px] px-3 transition-colors duration-150 ease-[var(--ease)] hover:bg-[var(--row-hover)]">{children}</Link></li>;
}

/** A list in the dashboard's side rail: a label in ink, an "all" link, roomy rows. */
function RailList({ title, to, children }: { title: string; to: string; children: ReactNode }) {
  return (
    <section>
      <div className="mb-2 flex items-center justify-between gap-3">
        <h2 className="caps">{title}</h2>
        <Link to={to} className="text-xs text-ink-3 decoration-[var(--rule-strong)] underline-offset-4 hover:text-ink hover:underline">{t('Wszystkie', 'All')}</Link>
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
    <RailList title={t('Znaleziska', 'Findings')} to="/findings">
      {q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : !q.data ? <SkeletonRows rows={4} /> : rows.length === 0 ? <p className="py-3 text-sm text-ink-2">{t('Brak otwartych znalezisk', 'No open findings')}</p> : null}
      <ul data-testid="top-findings">
        {rows.slice(0, 5).map(({ group: g, to }) => (
          <Row key={g.key} to={to}>
            <span className="min-w-0 flex-1 truncate text-sm text-ink" title={g.title}>{g.title}</span>
            <span className="num w-[32px] flex-none text-right text-sm text-ink-2">{g.interest}</span>
          </Row>
        ))}
      </ul>
    </RailList>
  );
}

function RecentChanges({ fallback }: { fallback: Change[] }) {
  // One row per address over the last 100 changes; the dashboard's own list while they load.
  const q = usePage<Change>('/changes', { expected: false, sort: '-at', limit: 100 });
  const rows = rowsByAddress(q.data?.items ?? fallback);
  return (
    <RailList title={t('Zmiany', 'Changes')} to="/changes?expected=false">
      {rows.length === 0 ? <p className="py-3 text-sm text-ink-2">{t('Brak zmian w ostatnim skanie', 'No changes in the last scan')}</p> : null}
      <ul data-testid="recent-changes">
        {rows.slice(0, 6).map(({ ip, latest: c, items }) => {
          const many = items.length > 1;
          const to = many ? '/changes?expected=false&q=' + encodeURIComponent(ip) : c.service_id ? '/services/' + c.service_id : '/hosts/' + c.host_id;
          const info = changeKindInfo(c.kind);
          return (
            <Row key={ip} to={to}>
              <Glyph name={info.glyph} tone={info.tone} />
              <span className="min-w-0 flex-1 truncate text-sm text-ink">{info.label}</span>
              <span className="mono flex-none text-[13px] text-ink-2">{many ? ip : ip + (c.port ? ':' + c.port : '')}</span>
              <span className="mono w-[64px] flex-none text-right text-[12px] text-ink-3" title={fmtDateTime(c.at)}>{shortAge(c.at)}</span>
            </Row>
          );
        })}
      </ul>
    </RailList>
  );
}

/** The only trace of the safety policy on the dashboard: one mono line to the policy page. */
function SafetyLine({ st }: { st: Dash['safety'] }) {
  return (
    <p className="mono text-[12px] text-ink-3" data-testid="dash-safety">
      <Link to="/admin?tab=safety" className="hover:text-ink hover:underline">
        {st.emergency_stop ? <span className="text-danger">{t('Stop awaryjny włączony', 'Emergency stop is on')}</span> : (st.allowed_methods ?? []).length ? t('Tylko', 'Only') + ' ' + (st.allowed_methods ?? []).join(' ' + t('i', 'and') + ' ') : t('Tylko GET i HEAD', 'GET and HEAD only')}
        {' · '}{fmtInt(st.max_pps)} pps · {fmtInt(st.max_http_rps)} {t('żądań/s', 'req/s')}
      </Link>
    </p>
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
        <Icon name={st.emergency_stop ? 'stop' : 'shield'} className={st.emergency_stop ? '' : 'text-ink-3'} />
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
      <h2 id="first-run-title" className="text-xl font-semibold tracking-[-0.015em]">{t('Czujka nie ma jeszcze danych o sieci', 'Czujka has no data about the network yet')}</h2>
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
      </div>
    );
  }
  return (
    <div className="mx-auto max-w-[1600px] space-y-6 px-4 pb-6 pt-6 sm:px-6 lg:px-8">
      <h1 className="sr-only">{t('Pulpit', 'Dashboard')}</h1>
      <Handover d={d} full={runs.data ? (pair.full ?? null) : undefined} />
      <Inventory d={d} pair={runs.data ? pair : undefined} runs={allRuns.data?.items ?? []} />
      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(300px,1fr)] xl:gap-10">
        <Stage d={d} scale={<NightStrip runs={allRuns.data?.items ?? []} active={d.active_run} currentId={d.active_run ? undefined : d.last_run?.id} now={now} />} />
        <aside className="min-w-0 space-y-6">
          <RecentChanges fallback={d.recent_changes ?? []} />
          <TopFindings />
        </aside>
      </div>
      <SafetyLine st={st} />
    </div>
  );
}

function HostlessState({ on }: { on: boolean }) {
  return on
    ? <span className="inline-flex items-center gap-1.5 text-sm"><Glyph name="x" tone="danger" />{t('włączony', 'on')}</span>
    : <span className="inline-flex items-center gap-1.5 text-sm font-normal text-ink-2"><Glyph name="ring" tone="expected" />{t('wyłączony', 'off')}</span>;
}

