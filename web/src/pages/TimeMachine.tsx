import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router';
import { useItem, usePage } from '../api/hooks';
import type { AtFinding, AtHost, AtService, FieldHistory, HostLife, LifeInterval, Page, RunMap, ScanRun, ServiceHistory, Snapshot, Timeline, RunPoint } from '../api/types';
import { t, plural } from '../i18n';
import { cx, fmtDateTime, fmtInt } from '../lib/format';
import { fieldLabel as sharedFieldLabel, fieldValue } from '../lib/fields';
import { useUrlState } from '../lib/hooks';
import { routeMissing } from '../lib/route';
import { Empty, ErrorState, PageHeader, Panel, Select, SkeletonRows, Tabs, Unavailable } from '../ui/kit';
import { DataTable, FilterBar, FilterField, Pager, type Col } from '../ui/table';
import { FindingStatusMark, HostStatusMark, ServiceStateMark, Sev } from '../ui/marks';
import { AddressMap } from '../viz/AddressMap';
import { triggerLabel } from './Runs';
import { NotScanned } from '../ui/NotScanned';

function useDebounced<T>(v: T, ms: number): T {
  const [d, setD] = useState(v);
  useEffect(() => { const h = setTimeout(() => setD(v), ms); return () => clearTimeout(h); }, [v, ms]);
  return d;
}

const isLight = (r: RunPoint) => r.trigger === 'reprobe' || r.trigger === 'manual-entry' || r.trigger === 'import';

/** The next run in a direction: partial runs (re-probe, ad hoc, import, manual entry) are skipped unless all is set. */
function stepRun(runs: RunPoint[], from: number, dir: 1 | -1, all: boolean): number {
  for (let i = from + dir; i >= 0 && i < runs.length; i += dir) if (all || !isLight(runs[i])) return i;
  return from;
}
const withModifier = (e: { shiftKey: boolean; altKey: boolean; ctrlKey: boolean; metaKey: boolean }) => e.shiftKey || e.altKey || e.ctrlKey || e.metaKey;

/** The scrubber: one mark per analysed run, height by the number of changes; re-probe runs are thin and short. */
function Scrubber({ runs, index, onIndex }: { runs: RunPoint[]; index: number; onIndex: (i: number) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const drag = useRef(false);
  const maxChanges = Math.max(1, ...runs.map((r) => r.changes));
  const pick = (clientX: number) => {
    const el = ref.current;
    if (!el || runs.length === 0) return;
    const b = el.getBoundingClientRect();
    const x = Math.min(Math.max(clientX - b.left, 0), b.width);
    onIndex(Math.round((x / b.width) * (runs.length - 1)));
  };
  const H = 56;
  const pos = (i: number) => (runs.length === 1 ? 50 : (i / (runs.length - 1)) * 100);
  const cur = runs[index];
  return (
    <div>
      <div
        ref={ref} role="slider" tabIndex={0} data-testid="tm-scrubber"
        aria-label={t('Skan na osi czasu', 'Scan on the timeline')} aria-valuemin={0} aria-valuemax={runs.length - 1} aria-valuenow={index}
        aria-valuetext={cur ? '#' + cur.run_id + ' ' + fmtDateTime(cur.at) : ''}
        className="relative mx-2 cursor-pointer touch-none select-none outline-none focus-visible:ring-2 focus-visible:ring-accent"
        style={{ height: H + 8 }}
        onPointerDown={(e) => { drag.current = true; (e.target as Element).setPointerCapture?.(e.pointerId); pick(e.clientX); }}
        onPointerMove={(e) => { if (drag.current) pick(e.clientX); }}
        onPointerUp={() => { drag.current = false; }}
        onKeyDown={(e) => {
          if (e.key === 'ArrowLeft') { e.preventDefault(); onIndex(stepRun(runs, index, -1, withModifier(e))); }
          if (e.key === 'ArrowRight') { e.preventDefault(); onIndex(stepRun(runs, index, 1, withModifier(e))); }
          if (e.key === 'Home') { e.preventDefault(); onIndex(0); }
          if (e.key === 'End') { e.preventDefault(); onIndex(runs.length - 1); }
        }}
      >
        <div className="absolute inset-x-0 bottom-1 h-px bg-rule-strong" />
        {runs.map((r, i) => {
          const light = isLight(r);
          const h = light ? 8 : 10 + Math.round(Math.sqrt(r.changes / maxChanges) * (H - 12));
          const sel = i === index;
          return (
            <span key={r.run_id} title={'#' + r.run_id + ' · ' + fmtDateTime(r.at) + ' · ' + triggerLabel(r.trigger) + ' · ' + r.changes + ' ' + t('zmiana / zmiany / zmian (plural())', 'change / changes')}
              className={cx('absolute bottom-1 -translate-x-1/2', sel ? 'bg-accent' : r.changes - r.changes_expected > 0 ? 'bg-ink-2' : 'bg-ink-3', light && !sel && 'opacity-60')}
              style={{ left: pos(i) + '%', height: h, width: light ? 2 : sel ? 6 : 4 }} />
          );
        })}
        {cur ? <span className="pointer-events-none absolute -bottom-0.5 h-2.5 w-2.5 -translate-x-1/2 rotate-45 border-b border-r border-accent bg-panel" style={{ left: pos(index) + '%' }} /> : null}
      </div>
      <div className="mt-1 flex justify-between px-2 text-2xs text-ink-3">
        <span className="num">{runs[0] ? fmtDateTime(runs[0].at) : ''}</span>
        <span>{t('← → pełne skany, z Shift także częściowe', '← → full scans, with Shift also partial ones')}</span>
        <span className="num">{runs.length ? fmtDateTime(runs[runs.length - 1].at) : ''}</span>
      </div>
    </div>
  );
}

function Count({ label, value, now, tone }: { label: string; value: number; now?: number; tone?: string }) {
  const d = now === undefined ? 0 : now - value;
  return (
    <div className="flex min-w-0 flex-col-reverse">
      <dt className="mt-1.5 text-xs text-ink-3">{label}{d ? <span className="num ml-1.5 text-ink-2" title={t('zmiana do dziś', 'change to today')}>{d > 0 ? '+' : ''}{fmtInt(d)} {t('dziś', 'today')}</span> : null}</dt>
      <dd className={cx('font-display text-[32px] leading-none text-ink sm:text-[38px]', tone)}>{fmtInt(value)}</dd>
    </div>
  );
}

const ip24 = (ip: string) => ip.split('.').slice(0, 3).join('.') + '.0/24';

/** The address map of a moment; hidden when the run covered a single /24 block (one machine: the lists say it all). */
function MapPanel({ runId, frameRunId }: { runId: number; frameRunId?: number }) {
  const frame = useItem<RunMap>('/runs/' + frameRunId + '/map', undefined, { enabled: Boolean(frameRunId), staleTime: 300_000 });
  if (frame.data && frame.data.blocks.length <= 1) return null;
  return <Panel title={t('Mapa przestrzeni adresowej wtedy', 'Address-space map then')}><SnapshotMap runId={runId} frameRunId={frameRunId} /></Panel>;
}

function SnapshotMap({ runId, frameRunId }: { runId: number; frameRunId?: number }) {
  const hosts = useItem<Page<AtHost>>('/timeline/at/hosts', { run_id: runId, limit: 1000 }, { staleTime: 60_000 });
  const services = useItem<Page<AtService>>('/timeline/at/services', { run_id: runId, limit: 1000 }, { staleTime: 60_000 });
  const frame = useItem<RunMap>('/runs/' + frameRunId + '/map', undefined, { enabled: Boolean(frameRunId), staleTime: 300_000 });
  const { blocks, gone, per } = useMemo(() => {
    const per = new Map<string, { up: number; goneNow: number; svcGone: number }>();
    for (const h of hosts.data?.items ?? []) {
      const k = ip24(h.ip);
      const v = per.get(k) ?? { up: 0, goneNow: 0, svcGone: 0 };
      if (h.up || h.status === 'up') { v.up++; if (h.status_now !== 'up') v.goneNow++; }
      per.set(k, v);
    }
    for (const s of services.data?.items ?? []) {
      if (s.state !== 'open' || s.state_now === 'open') continue;
      const k = ip24(s.ip);
      const v = per.get(k) ?? { up: 0, goneNow: 0, svcGone: 0 };
      v.svcGone++;
      per.set(k, v);
    }
    const cidrs = new Set<string>([...(frame.data?.blocks ?? []).map((b) => b.cidr), ...per.keys()]);
    const blocks = [...cidrs].map((cidr) => ({ cidr, size: 256, status: 'done' as const, hosts_up: per.get(cidr)?.up ?? 0 }));
    const gone = new Set([...per.entries()].filter(([, v]) => v.goneNow > 0 || v.svcGone > 0).map(([k]) => k));
    return { blocks, gone, per };
  }, [hosts.data, services.data, frame.data]);
  if (hosts.error) return <ErrorState error={hosts.error} retry={() => hosts.refetch()} />;
  if (!hosts.data) return <SkeletonRows rows={6} />;
  return (
    <div data-testid="tm-map">
      <AddressMap blocks={blocks} highlight={gone} maxCell={24} snapshot
        describe={(b) => {
          const v = per.get(b.cidr);
          if (!v || (!v.goneNow && !v.svcGone)) return null;
          return <span className="text-st-gone">{[
            v.goneNow ? v.goneNow + ' ' + plural(v.goneNow, ['host z tamtej chwili dziś nie odpowiada', 'hosty z tamtej chwili dziś nie odpowiadają', 'hostów z tamtej chwili dziś nie odpowiada'], ['host from then is not responding today', 'hosts from then are not responding today']) : '',
            v.svcGone ? v.svcGone + ' ' + plural(v.svcGone, ['usługa z tamtej chwili dziś nie odpowiada', 'usługi z tamtej chwili dziś nie odpowiadają', 'usług z tamtej chwili dziś nie odpowiada'], ['service from then is not open today', 'services from then are not open today']) : '',
          ].filter(Boolean).join(' · ')}</span>;
        }} />
      <p className="mt-2 text-xs text-ink-3">{t('Kolor: liczba aktywnych hostów. Obwódka: host albo usługa dziś nie odpowiada.', 'Colour: hosts up. Outline: a host or a service is not responding today.')}</p>
    </div>
  );
}

function SnapshotLists({ runId }: { runId: number }) {
  const u = useUrlState();
  const tab = u.get('list', 'hosts');
  const limit = 25;
  const offset = Number(u.get('offset', '0'));
  const status = u.get('hstatus');
  const state = u.get('sstate');
  const sev = u.get('fsev');
  const hosts = useItem<Page<AtHost>>('/timeline/at/hosts', { run_id: runId, limit, offset, status }, { enabled: tab === 'hosts' });
  const services = useItem<Page<AtService>>('/timeline/at/services', { run_id: runId, limit, offset, state }, { enabled: tab === 'services' });
  const findings = useItem<Page<AtFinding>>('/timeline/at/findings', { run_id: runId, limit, offset, severity: sev }, { enabled: tab === 'findings' });
  const hCols: Col<AtHost>[] = [
    { id: 'ip', header: 'IP', cell: (h) => <Link to={'/hosts/' + h.id} className="mono link">{h.ip}</Link> },
    { id: 'st', header: t('Wtedy', 'Then'), cell: (h) => <HostStatusMark status={h.status} /> },
    { id: 'now', header: t('Dziś', 'Today'), cell: (h) => <span className={cx(h.status_now !== h.status && 'font-medium')}><HostStatusMark status={h.status_now} /></span> },
    { id: 'ports', header: t('Porty wtedy', 'Ports then'), hide: 'md', cell: (h) => <span className="mono text-xs text-ink-2">{(h.open_ports ?? []).slice(0, 8).join(', ') || '–'}</span> },
    { id: 'obs', header: t('Ostatnia obserwacja', 'Last observation'), hide: 'lg', cell: (h) => <span className="num text-xs text-ink-3">{fmtDateTime(h.observed_at)} · #{h.run_id}</span> },
  ];
  const sCols: Col<AtService>[] = [
    { id: 'ep', header: t('Usługa', 'Service'), cell: (s) => <Link to={'/services/' + s.id} className="mono link">{s.ip}:{s.port}/{s.proto}</Link> },
    { id: 'st', header: t('Wtedy', 'Then'), cell: (s) => s.carried ? <span className="inline-flex flex-col leading-tight"><ServiceStateMark state={s.state} /><NotScanned /></span> : <ServiceStateMark state={s.state} /> },
    { id: 'now', header: t('Dziś', 'Today'), cell: (s) => <ServiceStateMark state={s.state_now} /> },
    { id: 'prod', header: t('Produkt wtedy', 'Product then'), cell: (s) => <span className="text-sm">{[s.product, s.version].filter(Boolean).join(' ') || s.name || '–'}{s.changed_since ? <span className="ml-1.5 text-2xs text-st-changed">{t('zmienione od tamtej pory', 'changed since')}</span> : null}</span> },
    { id: 'title', header: t('Tytuł', 'Title'), hide: 'lg', cell: (s) => <span className="block max-w-[260px] truncate text-xs text-ink-2">{s.title || '–'}</span> },
  ];
  const fCols: Col<AtFinding>[] = [
    { id: 'sev', header: t('Waga', 'Severity'), width: 90, cell: (f) => <Sev level={f.severity} compact /> },
    { id: 'title', header: t('Znalezisko', 'Finding'), cell: (f) => <span className="block max-w-[420px] truncate">{f.title}</span> },
    { id: 'ep', header: t('Gdzie', 'Where'), hide: 'md', cell: (f) => <span className="mono text-xs">{f.ip}{f.port ? ':' + f.port : ''}</span> },
    { id: 'now', header: t('Status dziś', 'Status today'), cell: (f) => <FindingStatusMark status={f.status_now} /> },
  ];
  const cur = tab === 'hosts' ? hosts : tab === 'services' ? services : findings;
  return (
    <Panel flush>
      <Tabs value={tab} onChange={(id) => u.set({ list: id })} tabs={[
        { id: 'hosts', label: t('Hosty', 'Hosts'), count: hosts.data?.total },
        { id: 'services', label: t('Usługi', 'Services'), count: services.data?.total },
        { id: 'findings', label: t('Znaleziska', 'Findings'), count: findings.data?.total },
      ]} />
      <FilterBar onClear={() => u.clear(['hstatus', 'sstate', 'fsev'])} active={[status, state, sev].filter(Boolean).length}>
        {tab === 'hosts' ? <FilterField label={t('Stan wtedy', 'Status then')} width={180}><Select value={status} onChange={(v) => u.set({ hstatus: v })} options={[{ value: '', label: t('wszystkie', 'all') }, { value: 'up', label: t('aktywne', 'up') }, { value: 'not responding', label: t('nie odpowiada', 'not responding') }, { value: 'unstable', label: t('niestabilne', 'unstable') }, { value: 'expected-offline', label: t('poza godzinami', 'outside usual hours') }, { value: 'down', label: t('nieaktywne', 'down') }]} /></FilterField> : null}
        {tab === 'services' ? <FilterField label={t('Stan wtedy', 'Status then')} width={180}><Select value={state} onChange={(v) => u.set({ sstate: v })} options={[{ value: '', label: t('otwarte i nieznane', 'open and unknown') }, { value: 'open', label: t('otwarte', 'open') }, { value: 'unknown', label: t('nieznane', 'unknown') }, { value: 'gone', label: t('zniknęły', 'gone') }, { value: 'all', label: t('wszystkie', 'all') }]} /></FilterField> : null}
        {tab === 'findings' ? <FilterField label={t('Waga', 'Severity')} width={140}><Select value={sev} onChange={(v) => u.set({ fsev: v })} options={[{ value: '', label: t('dowolna', 'any') }, { value: 'high', label: t('wysoka', 'high') }, { value: 'medium', label: t('średnia', 'medium') }, { value: 'low', label: t('niska', 'low') }, { value: 'info', label: 'info' }]} /></FilterField> : null}
      </FilterBar>
      {tab === 'hosts' ? <DataTable rows={hosts.data?.items} cols={hCols} rowKey={(h) => h.id} loading={hosts.isPending} error={hosts.error} retry={() => hosts.refetch()} empty={<p className="p-4 text-sm text-ink-2">{t('Brak hostów dla tych filtrów.', 'No hosts for these filters.')}</p>} mobile={(h) => <div className="flex justify-between"><span className="mono">{h.ip}</span><HostStatusMark status={h.status} /></div>} /> : null}
      {tab === 'services' ? <DataTable rows={services.data?.items} cols={sCols} rowKey={(s) => s.id} rowClass={(s) => (s.carried ? 'text-ink-3 [&_.link]:text-ink-2' : undefined)} loading={services.isPending} error={services.error} retry={() => services.refetch()} empty={<p className="p-4 text-sm text-ink-2">{t('Brak usług dla tych filtrów.', 'No services for these filters.')}</p>} mobile={(s) => <div className={cx('flex justify-between gap-2', s.carried && 'text-ink-3')}><span className="mono">{s.ip}:{s.port}</span>{s.carried ? <NotScanned /> : <ServiceStateMark state={s.state} />}</div>} /> : null}
      {tab === 'findings' ? <DataTable rows={findings.data?.items} cols={fCols} rowKey={(f) => f.id} loading={findings.isPending} error={findings.error} retry={() => findings.refetch()} empty={<p className="p-4 text-sm text-ink-2">{t('Brak otwartych znalezisk.', 'No open findings.')}</p>} mobile={(f) => <div><Sev level={f.severity} compact /> {f.title}</div>} /> : null}
      {cur.data ? <Pager total={cur.data.total} limit={limit} offset={offset} onOffset={(o) => u.set({ offset: o || null }, { keepOffset: true })} /> : null}
    </Panel>
  );
}

export default function TimeMachine() {
  const u = useUrlState();
  const tl = useItem<Timeline>('/timeline');
  const runs = useMemo(() => tl.data?.runs ?? [], [tl.data]);
  const wanted = Number(u.get('run', '0'));
  const fromUrl = runs.findIndex((r) => r.run_id === wanted);
  const [index, setIndex] = useState<number | null>(null);
  const cur = index ?? (fromUrl >= 0 ? fromUrl : runs.length - 1);
  const run = runs[cur];
  const runId = useDebounced(run?.run_id ?? 0, 140);
  useEffect(() => { if (runId && runId !== wanted) u.set({ run: runId }, { keepOffset: false }); }, [runId]); // eslint-disable-line react-hooks/exhaustive-deps
  const snap = useItem<Snapshot>('/timeline/at', { run_id: runId, limit: 1 }, { enabled: runId > 0, staleTime: 60_000 });
  const latest = runs[runs.length - 1];
  // The map frame is the widest finished run (the whole scope), so the time machine shows the full address space.
  const recent = usePage<ScanRun>('/runs', { status: 'completed', limit: 100, sort: '-id' });
  const frameRun = (recent.data?.items ?? []).filter((r) => r.trigger !== 'reprobe' && r.trigger !== 'manual-entry' && r.trigger !== 'import')
    .reduce<ScanRun | undefined>((best, r) => (!best || r.stats.addresses_total > best.stats.addresses_total ? r : best), undefined);
  // Arrow keys step one run anywhere on the page, unless the focus is in a form field.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el.closest('input, textarea, select, [role=slider]')) return;
      if (e.key === 'ArrowLeft') setIndex(stepRun(runs, cur, -1, withModifier(e)));
      if (e.key === 'ArrowRight') setIndex(stepRun(runs, cur, 1, withModifier(e)));
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [cur, runs]);

  const header = <PageHeader title={t('Oś czasu', 'Timeline')} />;
  if (tl.error) return <div>{header}<div className="p-4 sm:p-6">{routeMissing(tl.error) ? <Unavailable /> : <ErrorState error={tl.error} retry={() => tl.refetch()} />}</div></div>;
  if (!tl.data) return <div>{header}<SkeletonRows rows={10} /></div>;
  if (runs.length === 0) return <div>{header}<div className="p-4 sm:p-6"><Empty icon="history" title={t('Brak skanów', 'No scans yet')} /></div></div>;
  if (runs.length === 1) {
    return (
      <div>{header}<div className="p-4 sm:p-6" data-testid="tm-one-run">
        <Empty icon="history" title={t('Potrzeba co najmniej dwóch skanów', 'At least two scans are needed')}          action={<Link to={'/runs/' + runs[0].run_id} className="link text-sm">{t('Otwórz skan', 'Open scan')} #{runs[0].run_id}</Link>} />
      </div></div>
    );
  }
  const s = snap.data?.summary;
  // With few runs the content uses the width: what changed first, the lists right under it, the map last.
  const few = runs.length <= 5;
  const counts = s ? (
    <dl className={cx('grid gap-y-3', few ? 'grid-cols-3 sm:grid-cols-6' : 'grid-cols-3')}>
      <Count label={t('Aktywne hosty', 'Hosts up')} value={s.hosts_up} now={latest.hosts_up} />
      <Count label={t('Nie odpowiadają', 'Not responding')} value={s.hosts_missing} now={latest.hosts_missing} />
      <Count label={t('Nieaktywne hosty', 'Hosts down')} value={s.hosts_down} now={latest.hosts_down} />
      <Count label={t('Otwarte usługi', 'Open services')} value={s.services_open} now={latest.services_open} />
      <Count label={t('Nieznane usługi', 'Unknown services')} value={s.services_unknown} now={latest.services_unknown} />
      <Count label={t('Otwarte znaleziska', 'Open findings')} value={s.findings_open} now={latest.findings_open} />
    </dl>
  ) : null;
  const sentences = s ? ((s.diff_to_now?.sentences ?? []).length && run.run_id !== latest.run_id ? (
    <ul className="space-y-1 text-sm" data-testid="tm-sentences">{(s.diff_to_now.sentences ?? []).map((x, i) => <li key={i} className="flex gap-2"><span className="mt-2 h-1 w-1 flex-none bg-ink-3" />{x}</li>)}</ul>
  ) : <p className="text-sm text-ink-2">{run.run_id === latest.run_id ? t('To najnowszy skan.', 'This is the latest scan.') : t('Brak zmian od tamtej chwili.', 'No changes since then.')}</p>) : null;
  if (few) {
    return (
      <div>
        {header}
        <div className="space-y-4 p-4 sm:p-6">
          <Panel title={<span>{t('Skan', 'Scan')} <Link to={'/runs/' + run.run_id} className="num link">#{run.run_id}</Link> <span className="font-normal text-ink-2">· {fmtDateTime(run.at)} · {run.profile_name} · {triggerLabel(run.trigger)}</span></span>}
            actions={<span className="num text-ink-3">{cur + 1} / {runs.length}</span>}>
            <Scrubber runs={runs} index={cur} onIndex={setIndex} />
          </Panel>
          <Panel title={t('Od tamtej chwili do dziś', 'From then to today')}>
            {snap.error ? <ErrorState error={snap.error} retry={() => snap.refetch()} /> : !s ? <SkeletonRows rows={3} /> : (
              <div className={cx('space-y-4', snap.isFetching && 'opacity-70 transition-opacity')} data-testid="tm-summary">{sentences}<div className="border-t border-rule pt-3">{counts}</div></div>
            )}
          </Panel>
          {runId ? <SnapshotLists runId={runId} /> : null}
          {runId ? <MapPanel runId={runId} frameRunId={frameRun?.id} /> : null}
        </div>
      </div>
    );
  }
  return (
    <div>
      {header}
      <div className="space-y-4 p-4 sm:p-6">
        <Panel title={<span>{t('Skan', 'Scan')} <Link to={'/runs/' + run.run_id} className="num link">#{run.run_id}</Link> <span className="font-normal text-ink-2">· {fmtDateTime(run.at)} · {run.profile_name} · {triggerLabel(run.trigger)}</span></span>}
          actions={<span className="num text-ink-3">{cur + 1} / {runs.length}</span>}>
          <Scrubber runs={runs} index={cur} onIndex={setIndex} />
        </Panel>
        <Panel title={t('Stan w tamtej chwili', 'Status at that moment')}>
          {snap.error ? <ErrorState error={snap.error} retry={() => snap.refetch()} /> : !s ? <SkeletonRows rows={4} /> : (
            <div className={cx('grid gap-6 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]', snap.isFetching && 'opacity-70 transition-opacity')} data-testid="tm-summary">
              <dl className="grid grid-cols-3 gap-x-4 gap-y-6">
                <Count label={t('Aktywne hosty', 'Hosts up')} value={s.hosts_up} now={latest.hosts_up} />
                <Count label={t('Nie odpowiadają', 'Not responding')} value={s.hosts_missing} now={latest.hosts_missing} />
                <Count label={t('Nieaktywne hosty', 'Hosts down')} value={s.hosts_down} now={latest.hosts_down} />
                <Count label={t('Otwarte usługi', 'Open services')} value={s.services_open} now={latest.services_open} />
                <Count label={t('Nieznane usługi', 'Unknown services')} value={s.services_unknown} now={latest.services_unknown} />
                <Count label={t('Otwarte znaleziska', 'Open findings')} value={s.findings_open} now={latest.findings_open} />
              </dl>
              <div className="border-t border-rule pt-4 lg:border-l lg:border-t-0 lg:pl-6 lg:pt-0">
                <p className="label mb-2">{t('Od tamtej chwili do dziś', 'From then to today')}</p>
                {(s.diff_to_now?.sentences ?? []).length ? (
                  <ul className="space-y-2 text-base text-ink" data-testid="tm-sentences">{(s.diff_to_now.sentences ?? []).map((x, i) => <li key={i} className="flex gap-2.5"><span className="mt-[11px] h-1 w-1 flex-none bg-ink-3" />{x}</li>)}</ul>
                ) : <p className="text-base text-ink-2">{run.run_id === latest.run_id ? t('To najnowszy skan.', 'This is the latest scan.') : t('Brak zmian od tamtej chwili.', 'No changes since then.')}</p>}
              </div>
            </div>
          )}
        </Panel>
        {runId ? <MapPanel runId={runId} frameRunId={frameRun?.id} /> : null}
        {runId ? <SnapshotLists runId={runId} /> : null}
      </div>
    </div>
  );
}

// ---------- host swim lanes and service field history ----------

const laneColor: Record<string, string> = { up: 'var(--st-new)', open: 'var(--accent)', missing: 'var(--st-changed)', unknown: 'var(--ink-3)', down: 'var(--st-gone)' };

function Lane({ intervals, t0, t1, height = 10 }: { intervals: LifeInterval[]; t0: number; t1: number; height?: number }) {
  const span = Math.max(1, t1 - t0);
  return (
    <div className="relative w-full bg-sunk" style={{ height }}>
      {intervals.map((iv, i) => {
        const a = (new Date(iv.from).getTime() - t0) / span;
        const b = ((iv.ongoing ? t1 : new Date(iv.to).getTime()) - t0) / span;
        return <span key={i} className="absolute top-0 h-full" title={iv.state + (iv.status && iv.status !== iv.state ? ' (' + iv.status + ')' : '') + ' · ' + fmtDateTime(iv.from) + ' – ' + (iv.ongoing ? t('teraz', 'now') : fmtDateTime(iv.to)) + ' · #' + iv.from_run + '–#' + iv.to_run + ' · ' + iv.observations + ' ' + t('obserwacji', 'obserwacji')}
          style={{ left: a * 100 + '%', width: Math.max(0.4, (b - a) * 100) + '%', background: laneColor[iv.state] ?? 'var(--ink-3)', opacity: iv.state === 'unknown' ? 0.5 : 1 }} />;
      })}
    </div>
  );
}

export function HostLifePanel({ hostId }: { hostId: number }) {
  const q = useItem<HostLife>('/timeline/hosts/' + hostId);
  if (q.error && routeMissing(q.error)) return <Panel title={t('Dostępność hosta', 'Host availability')}><Unavailable /></Panel>;
  if (q.error) return <Panel title={t('Dostępność hosta', 'Host availability')}><ErrorState error={q.error} retry={() => q.refetch()} /></Panel>;
  if (!q.data) return <Panel title={t('Dostępność hosta', 'Host availability')}><SkeletonRows rows={3} /></Panel>;
  const L = q.data;
  const t0 = new Date(L.first_seen).getTime();
  const t1 = Math.max(Date.now(), new Date(L.last_seen).getTime());
  return (
    <Panel title={t('Dostępność hosta', 'Host availability')} actions={<span className="num text-ink-3">{fmtDateTime(L.first_seen)} – {t('teraz', 'now')}</span>}>
      <div className="grid grid-cols-[110px_minmax(0,1fr)] items-center gap-x-3 gap-y-1.5 text-xs" data-testid="host-lanes">
        <span className="font-medium">{t('host', 'host')}</span><Lane intervals={L.host ?? []} t0={t0} t1={t1} height={14} />
        {(L.services ?? []).map((s) => (
          <FragmentLane key={s.service_id} label={<Link to={'/services/' + s.service_id} className="mono link">{s.port}/{s.proto} <span className="text-ink-3">{s.name || t('nierozpoznana', 'unidentified')}</span></Link>} intervals={s.intervals ?? []} versions={s.versions ?? []} t0={t0} t1={t1} />
        ))}
      </div>
      <p className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-2xs text-ink-3">
        {[['up', t('host odpowiada', 'host responds')], ['missing', t('nie odpowiada', 'not responding')], ['down', t('nieaktywny', 'down')], ['open', t('usługa otwarta', 'service open')], ['unknown', t('stan nieznany', 'status unknown')]].map(([k, l]) => <span key={k} className="inline-flex items-center gap-1"><span className="inline-block h-2 w-3" style={{ background: laneColor[k], opacity: k === 'unknown' ? 0.5 : 1 }} />{l}</span>)}
        <span className="inline-flex items-center gap-1"><span className="inline-block h-2.5 w-px bg-ink" />{t('zmiana wersji', 'version change')}</span>
      </p>
    </Panel>
  );
}

function FragmentLane({ label, intervals, versions, t0, t1 }: { label: React.ReactNode; intervals: LifeInterval[]; versions: { at: string; run_id: number; before: string; after: string }[]; t0: number; t1: number }) {
  const span = Math.max(1, t1 - t0);
  return (
    <>
      <span className="truncate">{label}</span>
      <div className="relative">
        <Lane intervals={intervals} t0={t0} t1={t1} />
        {versions.map((v, i) => <span key={i} className="absolute -top-0.5 h-3.5 w-px bg-ink" style={{ left: ((new Date(v.at).getTime() - t0) / span) * 100 + '%' }} title={fmtDateTime(v.at) + ' #' + v.run_id + ': ' + (v.before || '–') + ' → ' + (v.after || '–')} />)}
      </div>
    </>
  );
}

const fieldLabel = (f: string) => sharedFieldLabel(f, 'service');

export function ServiceHistoryPanel({ serviceId }: { serviceId: number }) {
  const q = useItem<ServiceHistory>('/timeline/services/' + serviceId);
  const title = t('Zmiany pól', 'Field changes');
  if (q.error && routeMissing(q.error)) return <Panel title={title}><Unavailable /></Panel>;
  if (q.error) return <Panel title={title}><ErrorState error={q.error} retry={() => q.refetch()} /></Panel>;
  if (!q.data) return <Panel title={title}><SkeletonRows rows={3} /></Panel>;
  const h = q.data;
  return (
    <Panel title={title} count={h.observations} flush>
      <div data-testid="service-fields">
        {(h.changed ?? []).length === 0 ? <p className="px-3 py-3 text-sm text-ink-2 sm:px-4">{t('Bez zmian w ' + h.observations + ' ' + plural(h.observations, ['obserwacji', 'obserwacjach', 'obserwacjach'], ['observation', 'observations']) + '.', 'No changes in ' + h.observations + ' ' + (h.observations === 1 ? 'observation' : 'observations') + '.')}</p> : (
          <ul>
            {(h.changed ?? []).map((f: FieldHistory) => (
              <li key={f.field} className="border-b border-rule px-3 py-2 sm:px-4">
                <p className="label mb-1">{fieldLabel(f.field)}</p>
                <ol className="space-y-0.5">
                  {f.values.map((v, i) => (
                    <li key={i} className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 text-sm">
                      <span className={cx('mono truncate', i === f.values.length - 1 ? 'text-ink' : 'text-ink-2')} title={v.value}>{(f.field === 'state' || f.field === 'classes' ? fieldValue(f.field, v.value) : v.value) || '–'}</span>
                      <span className="num text-2xs text-ink-3">{fmtDateTime(v.from)} – {fmtDateTime(v.to)} · #{v.from_run}–#{v.to_run}</span>
                    </li>
                  ))}
                </ol>
              </li>
            ))}
          </ul>
        )}
        {h.unchanged && Object.keys(h.unchanged).length ? <p className="px-3 py-2 text-xs text-ink-3 sm:px-4">{t('Bez zmian: ', 'Unchanged: ')}{Object.entries(h.unchanged).map(([k, v]) => fieldLabel(k) + ' ' + v).join(' · ')}</p> : null}
      </div>
    </Panel>
  );
}
