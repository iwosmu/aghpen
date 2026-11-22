import { useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { useAction, useItem } from '../api/hooks';
import { patch, post } from '../api/client';
import type { Chunk, MapBlock, Page, RunMap, SafetyPolicy, ScanProfile, ScanRun, Service } from '../api/types';
import { serviceName, isSelf } from '../lib/serviceName';
import { ServiceStateMark } from '../ui/marks';
import { t, plural } from '../i18n';
import { cx, fmtDateTime, fmtDuration, fmtInt, fmtPct, fmtRelative, fmtTime } from '../lib/format';
import { MenuButton } from '../ui/edit';
import { Button, Dialog, ErrorState, Field, InlineError, PageHeader, Panel, SkeletonRows, Tabs } from '../ui/kit';
import { triggerLabel } from './Runs';
import { Icon } from '../ui/Icon';
import { ChunkStatusMark, Glyph, RunStatusMark } from '../ui/marks';
import { AddressMap } from '../viz/AddressMap';
import { NetworkField, networkFields } from '../viz/Night';
import { useLiveRun, useUrlState, useWidth } from '../lib/hooks';
import { PacketCount, ProgressBar, RateGauge } from '../viz/charts';
import { useCan } from '../session';
import { RunStory } from '../ui/RunStory';
import { PartialNote, RunPasses } from '../ui/RunPasses';
import { useArrivalOrder } from '../ui/arrivalOrder';
import { SelfTag } from '../ui/serviceBits';
import { NotScanned, notScannedHint, scannedFirst } from '../ui/NotScanned';
import { runNoteText } from '../lib/runNotes';
import { ProductValue } from '../ui/ProductValue';

/** A run over this many addresses or fewer is a "one machine" run: the page shows its services instead of the address map. */
export const SMALL_RUN = 4;
/** A larger run shows this many of its services (most interesting first) under the map, with a link to all of them. */
export const RUN_SERVICES_CAP = 50;

/** The services of one run, as they arrive (polled while the run is live). */
function RunServices({ run, live, cap }: { run: ScanRun; live: boolean; cap?: number }) {
  // One small run: all rows, cheap to poll often. A larger run: the most interesting rows, polled less often.
  const q = useItem<Page<Service>>('/services', cap ? { run_id: run.id, limit: cap, sort: '-interest' } : { run_id: run.id, limit: 500 }, { refetchInterval: live ? (cap ? 5000 : 1500) : false });
  // While the run is live, rows keep their arrival order: a service of the
  // first pass never moves when a later pass adds more. When the run is over:
  // open services first, then the ones that are gone now; by address and port.
  const byAddr = (a: Service, b: Service) => a.ip.localeCompare(b.ip, undefined, { numeric: true }) || a.port - b.port;
  const { rows: ordered, fresh } = useArrivalOrder('run-services-' + run.id, q.data?.items ?? [], live, byAddr, (a, b) => Number(a.state !== 'open') - Number(b.state !== 'open') || byAddr(a, b));
  const items = scannedFirst(ordered);
  const carried = items.filter((s) => s.carried).length;
  const hosts = [...new Set(items.map((s) => s.host_id))];
  return (
    <Panel title={t('Znalezione usługi', 'Services found')} count={q.data ? q.data.total - carried : undefined} flush
      actions={hosts.length === 1 ? <Link to={'/hosts/' + hosts[0]} className="link">{t('Host', 'Host')} <span className="mono">{items[0].ip}</span></Link> : undefined}>
      {q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : !q.data ? <SkeletonRows rows={5} /> : items.length === 0 ? (
        <p className="p-3 text-sm text-ink-2" data-testid="run-services-empty">{live ? t('Oczekiwanie na otwarte porty…', 'Waiting for open ports…') : t('Brak otwartych usług', 'No open services')}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm" data-testid="run-services">
            <thead><tr className="border-b border-rule-strong text-left text-xs text-ink-3">
              <th className="h-[30px] px-3 font-medium">{hosts.length > 1 ? t('Adres', 'Address') : t('Port', 'Port')}</th>
              <th className="hidden px-3 font-medium sm:table-cell">{live ? t('Stan', 'Status') : t('Stan dziś', 'Status today')}</th>
              <th className="hidden px-3 font-medium sm:table-cell">{t('Usługa', 'Service')}</th>
              <th className="hidden px-3 font-medium md:table-cell">{t('Produkt', 'Product')}</th>
              <th className="px-3 font-medium">{t('Tytuł strony', 'Page title')}</th>
            </tr></thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id} className={cx('border-b border-rule last:border-b-0', s.carried && 'text-ink-3 [&_.link]:text-ink-2')} data-carried={s.carried ? 'true' : undefined} title={s.carried ? notScannedHint() : undefined} style={fresh.has(s.id) && !s.carried ? { animation: 'rise-in 240ms var(--ease-out-expo)' } : undefined}>
                  <td className="h-[30px] whitespace-nowrap px-3"><Link to={'/services/' + s.id} className="mono link">{hosts.length > 1 ? s.ip + ':' + s.port : s.port + '/' + s.proto}</Link></td>
                  <td className="hidden whitespace-nowrap px-3 sm:table-cell">{s.carried ? <NotScanned /> : <ServiceStateMark state={live ? 'open' : s.state} />}</td>
                  <td className="hidden max-w-[200px] truncate whitespace-nowrap px-3 sm:table-cell">{serviceName(s)}{isSelf(s) ? <SelfTag /> : null}</td>
                  <td className={cx('hidden max-w-[220px] truncate whitespace-nowrap px-3 md:table-cell', !s.carried && 'text-ink-2')}><ProductValue s={s} /></td>
                  <td className="w-full max-w-0 truncate whitespace-nowrap px-3 text-ink-2" title={s.title || undefined}>{s.title || '–'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {q.data.total > items.length ? (
            <p className="border-t border-rule px-3 py-2 text-sm" data-testid="run-services-more">
              <span className="text-ink-2">{t('Pokazano ' + items.length + ' z ' + fmtInt(q.data.total) + '.', 'Showing ' + items.length + ' of ' + fmtInt(q.data.total) + '.')}</span>{' '}
              <Link to={'/services?run_id=' + run.id + '&state=all'} className="link">{t('Wszystkie usługi', 'All services')}</Link>
            </p>
          ) : null}
          {carried > 0 ? <p className="border-t border-rule px-3 py-2 text-xs text-ink-3" data-testid="run-services-carried">{t('Poza tym skanem', 'Outside this scan')}: {carried}</p> : null}
        </div>
      )}
    </Panel>
  );
}

/** "Bez zmian względem poprzedniego przebiegu." when the summary has no change at all. */
function NoStory({ run }: { run: ScanRun }) {
  const s = run.summary;
  if (!s) return null;
  const n = s.hosts_new + s.hosts_gone + s.hosts_back + s.services_new + s.services_gone + s.services_changed + (s.services_returned ?? 0) + (s.responses_slower ?? 0) + (s.hosts_missing ?? 0);
  return n === 0 ? <p className="font-display text-[22px] leading-tight text-ink sm:text-[26px]" data-testid="run-story-none">{t('Bez zmian', 'No changes')}</p> : null;
}

function Fact({ label, children, wide }: { label: string; children: React.ReactNode; wide?: boolean }) {
  return (
    <div className={cx('min-w-0 border-b border-rule py-2 sm:border-b-0 sm:border-l sm:px-4 sm:py-0 sm:[&:nth-child(4n+1)]:border-l-0 sm:[&:nth-child(4n+1)]:pl-0', wide && 'sm:min-w-[220px]')}>
      <dt className="text-xs text-ink-3">{label}</dt>
      <dd className="mt-0.5 text-base font-medium text-ink">{children}</dd>
    </div>
  );
}

function ReportButtons({ onOpen }: { onOpen: (print: boolean) => void }) {
  return <MenuButton label={t('Raport', 'Report')} icon="external" testId="run-report-menu" items={[{ label: t('Otwórz', 'Open'), onSelect: () => onOpen(false), testId: 'run-report' }, { label: t('Drukuj', 'Print'), onSelect: () => onOpen(true) }]} />;
}

function specLabel(c: Chunk): string {
  if (c.spec.length === 1) return c.spec[0];
  return c.spec[0] + ' +' + (c.spec.length - 1);
}

/** A run over one /24: every address of the block is a cell, lit where this run found open services. */
function RunAddressField({ runId, cidr, live, fallback }: { runId: number; cidr: string; live: boolean; fallback: React.ReactNode }) {
  const q = useItem<Page<Service>>('/services', { run_id: runId, limit: 1000 }, live ? { refetchInterval: 3000 } : undefined);
  const field = useMemo(() => {
    const ips = [...new Set((q.data?.items ?? []).map((s) => s.ip))];
    return networkFields(ips.map((ip) => ({ ip, status: 'up' as const })), [], live ? [cidr] : [])[0];
  }, [q.data, cidr, live]);
  const [ref, w] = useWidth<HTMLDivElement>();
  if (q.data && !field) return <>{fallback}</>;
  return (
    <div ref={ref} className="flex flex-col gap-3 py-2">
      <p className="mono text-[13px] text-ink-2">{cidr}</p>
      {field && w ? <NetworkField field={field} width={w} /> : <div className="skeleton h-[160px] rounded-[10px]" />}
    </div>
  );
}

export default function RunDetail() {
  const u = useUrlState();
  const id = Number(useParams().id);
  const navigate = useNavigate();
  const canRun = useCan('scans:run');
  const canExport = useCan('export:run');
  const { run: runQ, recent, connected } = useLiveRun(id, { withChunks: true });
  const run = runQ.data;
  const chunks = useItem<Chunk[]>('/runs/' + id + '/chunks', undefined, { enabled: Boolean(run) });
  const map = useItem<RunMap>('/runs/' + id + '/map', undefined, { enabled: Boolean(run) });
  const profile = useItem<ScanProfile>('/profiles/' + run?.profile_id, undefined, { enabled: Boolean(run?.profile_id) });
  const safety = useItem<SafetyPolicy>('/settings/safety');
  const [hoverChunk, setHoverChunk] = useState<number | null>(null);
  const [hoverCidr, setHoverCidr] = useState<string | null>(null);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const act = useAction((a: 'pause' | 'resume' | 'cancel') => post<ScanRun>('/runs/' + id + '/' + a), { invalidate: ['/runs', '/dashboard'] });

  const chunkOf = useMemo(() => {
    const m = new Map<string, Chunk>();
    for (const c of chunks.data ?? []) for (const cidr of c.spec) m.set(cidr, c);
    return m;
  }, [chunks.data]);
  // Hovering a chunk lights up its whole work group: the chunks one scanner process took together.
  const hoverGroup = useMemo(() => {
    const c = (chunks.data ?? []).find((x) => x.id === hoverChunk) ?? (hoverCidr ? chunkOf.get(hoverCidr) : undefined);
    return c && c.group ? c.group : null;
  }, [chunks.data, hoverChunk, hoverCidr, chunkOf]);
  const highlight = useMemo(() => {
    const all = chunks.data ?? [];
    const c = all.find((x) => x.id === hoverChunk);
    if (!c) return undefined;
    const members = c.group ? all.filter((x) => x.group === c.group) : [c];
    return new Set(members.flatMap((x) => x.spec));
  }, [chunks.data, hoverChunk]);
  const hoveredChunkId = hoverCidr ? chunkOf.get(hoverCidr)?.id : null;

  if (runQ.error) return <ErrorState error={runQ.error} retry={() => runQ.refetch()} />;
  if (!run) return <SkeletonRows rows={12} />;
  const s = run.stats;
  const pct = s.addresses_total ? s.addresses_done / s.addresses_total : 0;
  const isLive = run.status === 'running' || run.status === 'analyzing';
  const defaultTab = isLive || run.status === 'paused' || run.status === 'queued' ? 'progress' : 'services';
  const tab = u.get('tab', defaultTab);
  const policyCap = safety.data?.max_pps ?? 0;
  const cap = Math.min(profile.data?.rate.max_pps ?? policyCap, policyCap || Infinity) || policyCap;
  const maxSize = Math.max(1, ...(chunks.data ?? []).map((c) => c.size));
  const running = (chunks.data ?? []).filter((c) => c.status === 'running');
  const runningChunks = running.length;
  const runningAddrs = running.reduce((a, c) => a + c.size, 0);
  const sortedChunks = [...(chunks.data ?? [])].sort((a, b) => a.seq - b.seq);
  const groupSizes = new Map<number, number>();
  for (const c of sortedChunks) if (c.group) groupSizes.set(c.group, (groupSizes.get(c.group) ?? 0) + 1);
  const openReport = (print: boolean) => {
    const w = window.open('/api/v1/runs/' + run.id + '/report.html', '_blank');
    if (print && w) w.addEventListener('load', () => w.print(), { once: true });
  };
  const reportReady = ['completed', 'cancelled', 'failed', 'paused'].includes(run.status);
  const small = s.addresses_total > 0 && s.addresses_total <= SMALL_RUN;

  return (
    <div>
      <PageHeader
        back={{ to: '/runs', label: t('Skany', 'Scans') }}
        title={<span className="flex flex-wrap items-center gap-x-3 gap-y-1"><span>{t('Skan', 'Scan')} #{run.id}</span><span className="font-sans text-[15px] font-normal tracking-normal"><RunStatusMark status={run.status} pauseReason={run.pause_reason} /></span></span>}
        sub={<>{run.profile_id ? <Link to={'/profiles/' + run.profile_id} className="link">{run.profile_name}</Link> : run.profile_name} · {run.trigger === 'schedule' ? t('z harmonogramu', 'from the schedule') : run.trigger === 'import' ? t('import pliku', 'file import') : run.trigger === 'manual' ? t('uruchomiony ręcznie', 'started manually') : triggerLabel(run.trigger)} · {fmtDateTime(run.started_at)}
          {isLive ? <span className="ml-2 inline-flex items-center gap-1 text-xs text-ink-3"><span className={cx('lamp', connected ? 'bg-st-new' : 'bg-st-changed')} />{connected ? t('na żywo', 'live') : t('łączenie…', 'connecting…')}</span> : null}</>}
        readOnly={!canRun && (isLive || run.status === 'paused')}
        actions={canRun ? (
          <>
            {run.status === 'running' ? <Button icon="pause" busy={act.isPending && act.variables === 'pause'} onClick={() => act.mutate('pause')}>{t('Wstrzymaj', 'Pause')}</Button> : null}
            {run.status === 'paused' ? <Button variant="primary" icon="play" busy={act.isPending && act.variables === 'resume'} disabled={safety.data?.emergency_stop} title={safety.data?.emergency_stop ? t('Najpierw wyłącz stop awaryjny', 'Turn off the emergency stop first') : undefined} onClick={() => act.mutate('resume')}>{t('Wznów', 'Resume')}</Button> : null}
            {['running', 'paused', 'queued'].includes(run.status) ? <Button variant="danger" icon="x" onClick={() => setConfirmCancel(true)}>{t('Anuluj skan', 'Cancel scan')}</Button> : null}
            {run.status === 'completed' && run.summary?.prev_run_id ? <Button icon="compare" onClick={() => navigate('/changes/compare?from=' + run.summary!.prev_run_id + '&to=' + run.id)}>{t('Porównaj z poprzednim', 'Compare with previous')}</Button> : null}
            {reportReady ? <ReportButtons onOpen={openReport} /> : null}
            {run.status === 'completed' && canExport ? <DojoRunButton runId={run.id} /> : null}
          </>
        ) : (
          <>
            {run.status === 'completed' && run.summary?.prev_run_id ? <Button icon="compare" onClick={() => navigate('/changes/compare?from=' + run.summary!.prev_run_id + '&to=' + run.id)}>{t('Porównaj z poprzednim', 'Compare with previous')}</Button> : null}
            {reportReady ? <ReportButtons onOpen={openReport} /> : null}
          </>
        )}
      />

      <div className="space-y-5 px-4 pb-6 sm:px-6 lg:px-8">
        <RunNote run={run} canEdit={canRun} />
        {run.error ? (
          <div role="alert" className="flex items-start gap-2 rounded-[10px] bg-st-gone-wash px-4 py-3 text-sm">
            <Icon name="alert" className="mt-0.5 text-danger" /><span><span className="font-medium">{t('Skan zakończył się błędem', 'The scan failed')}</span> <span className="mono text-xs">{run.error}</span></span>
          </div>
        ) : null}
        {run.status === 'paused' && run.pause_reason === 'emergency_stop' ? (
          <div role="status" className="flex items-start gap-2 rounded-[10px] bg-st-gone-wash px-4 py-3 text-sm" data-testid="paused-emergency">
            <Icon name="stop" className="mt-0.5 text-danger" />
            <span>{t('Stop awaryjny wstrzymał ten skan. Po wyłączeniu stopu wznów skan ręcznie.', 'The emergency stop paused this scan. After the stop is off, resume the scan manually.')}</span>
          </div>
        ) : null}
        {run.status === 'paused' && run.pause_reason === 'manual' ? (
          <div role="status" className="flex items-start gap-2 rounded-[10px] bg-raised px-4 py-3 text-sm">
            <Glyph name="pause" tone="neutral" />
            <span>{t('Skan wstrzymany ręcznie', 'The scan is paused manually')}</span>
          </div>
        ) : null}
        {run.status === 'paused' && run.pause_reason === 'window_closed' ? (
          <div className="flex items-start gap-2 rounded-[10px] bg-st-changed-wash px-4 py-3 text-sm">
            <Glyph name="pause" tone="changed" />
            <span>
              {t('Okno czasowe zamknęło się o ', 'The time window closed at ')}<span className="num">{fmtTime(run.window_end)}</span>{t('.', '.')}{' '}
              {run.resume_at ? <>{t('Skan wznowi się sam w następnym oknie: ', 'The scan resumes by itself in the next window: ')}<span className="num font-medium">{fmtDateTime(run.resume_at)}</span> ({fmtRelative(run.resume_at)}).</> : null}
            </span>
          </div>
        ) : null}

        {run.status === 'completed' && run.summary?.prev_run_id ? (
          <section className="py-1" data-testid="run-story-panel">
            <RunStory runId={run.id} className="space-y-2 [&_.mono]:text-[0.86em] [&_li]:text-[19px] [&_li]:leading-[28px] sm:[&_li]:text-[21px]" />
            <NoStory run={run} />
          </section>
        ) : null}
        {s.warnings && s.warnings.length > 0 ? (
          <div role="alert" data-testid="run-warnings" className="flex items-start gap-2 rounded-[10px] bg-st-gone-wash px-4 py-3 text-sm">
            <Icon name="alert" className="mt-0.5 text-danger" />
            <span>
              <span className="font-medium">{t('Wynik skanu jest niepełny', 'The scan result is incomplete')}</span>
              {s.warnings.map((w) => <span key={w} className="block">{w}</span>)}
            </span>
          </div>
        ) : null}
        {s.notes && s.notes.length > 0 ? (
          <div data-testid="run-notes" className="card px-4 py-3 text-sm text-ink-2">
            {s.notes.map((n) => <span key={n} className="block">{runNoteText(n)}</span>)}
          </div>
        ) : null}

        <Tabs value={tab} onChange={(v) => u.set({ tab: v === defaultTab ? null : v })} tabs={[
          { id: 'services', label: t('Usługi', 'Services') },
          ...(run.summary ? [{ id: 'changes', label: t('Zmiany', 'Changes') }] : []),
          ...(small ? [] : [{ id: 'map', label: t('Mapa', 'Map') }, { id: 'chunks', label: t('Podgrupy', 'Chunks') }]),
          { id: 'progress', label: t('Przebieg', 'Progress') },
        ]} />
        {tab === 'services' ? <RunServices run={run} live={isLive} cap={small ? undefined : RUN_SERVICES_CAP} /> : null}
        {tab === 'changes' ? (run.summary ? (
            <Panel title={t('Zmiany w tym skanie', 'Changes in this scan')} actions={<Link className="link" to={'/changes?run_id=' + run.id}>{t('Wszystkie', 'All')}</Link>}>
              <dl className="grid grid-cols-2 gap-x-6 sm:grid-cols-3">
                {([
                  ['plus', 'new', t('nowe hosty', 'new hosts'), run.summary.hosts_new], ['plus', 'new', t('nowe usługi', 'new services'), run.summary.services_new], ['back', 'new', t('hosty wróciły', 'hosts back'), run.summary.hosts_back], ['returned', 'new', t('usługi wróciły', 'services back'), run.summary.services_returned ?? 0], ['slow', 'changed', t('usługi odpowiadają wolniej', 'services respond slower'), run.summary.responses_slower ?? 0],
                  ['minus', 'gone', t('hosty nieaktywne', 'hosts down'), run.summary.hosts_gone], ['minus', 'gone', t('usługi zniknęły', 'services gone'), run.summary.services_gone], ['wave', 'unstable', t('hosty niestabilne', 'hosts unstable'), run.summary.hosts_unstable],
                  ['delta', 'changed', t('zmienione usługi', 'changed services'), run.summary.services_changed], ['dot', 'accent', t('nowe znaleziska', 'new findings'), run.summary.findings_new],
                  ['half', 'changed', t('hosty nie odpowiadają (niepotwierdzone)', 'hosts not responding (unconfirmed)'), run.summary.hosts_missing ?? 0], ['half', 'changed', t('usługi nie odpowiadają (niepotwierdzone)', 'services not responding (unconfirmed)'), run.summary.services_unreachable ?? 0],
                ] as const).map(([g, tone, label, n]) => (
                  <div key={label} className={cx('flex min-h-[40px] items-center justify-between gap-2 border-b border-rule py-1.5', !n && 'opacity-55')}>
                    <dt className="flex items-center gap-1.5 text-sm text-ink-2"><Glyph name={g} tone={n ? tone : 'expected'} />{label}</dt>
                    <dd className={cx('num text-sm font-medium', n ? 'text-ink' : 'text-ink-3')}>{n}</dd>
                  </div>
                ))}
              </dl>
            </Panel>
          ) : null) : null}
        {tab === 'map' && !small ? <Panel title={t('Mapa przestrzeni adresowej', 'Address-space map')} count={(map.data?.blocks.length ?? 0) + ' × /24'}>
            {map.error ? <ErrorState error={map.error} retry={() => map.refetch()} /> : !map.data ? <div className="skeleton h-[260px]" /> : map.data.blocks.length === 1 ? (
              <RunAddressField runId={run.id} cidr={map.data.blocks[0].cidr} live={isLive} fallback={
                <AddressMap blocks={map.data.blocks} highlight={highlight} onHover={setHoverCidr} onSelect={(b: MapBlock) => navigate('/hosts?cidr=' + encodeURIComponent(b.cidr))} />
              } />
            ) : (
              <AddressMap
                blocks={map.data.blocks} highlight={highlight} onHover={setHoverCidr}
                onSelect={(b: MapBlock) => navigate('/hosts?cidr=' + encodeURIComponent(b.cidr))}
                describe={(b) => { const c = chunkOf.get(b.cidr); return c ? t('podgrupa', 'chunk') + ' #' + c.seq : null; }}
              />
            )}
          </Panel> : null}
        {tab === 'chunks' && !small ? <Panel title={t('Podgrupy adresów', 'Address chunks')} count={sortedChunks.length} flush>
            {chunks.error ? <ErrorState error={chunks.error} retry={() => chunks.refetch()} /> : !chunks.data ? <SkeletonRows rows={8} /> : sortedChunks.length === 0 ? (
              <p className="p-3 text-sm text-ink-2">{run.trigger === 'import' ? t('Import nie ma podgrup', 'An import has no chunks') : t('Plan podgrup pojawi się po starcie skanu', 'The chunk plan appears when the scan starts')}</p>
            ) : (
              <div className="max-h-[520px] overflow-auto">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 z-10 bg-[var(--panel-solid)]">
                    <tr className="border-b border-rule text-left text-2xs text-ink-2">
                      <th className="h-[40px] w-[36px] pl-5 pr-2 font-medium">#</th>
                      <th className="px-2 font-medium">{t('Adresy', 'Addresses')}</th>
                      <th className="px-2 font-medium" title={t('Grupa robocza: podgrupy, które jeden proces skanera wziął razem', 'Work group: the chunks that one scanner process took together')}>{t('Grupa', 'Group')}</th>
                      <th className="px-2 font-medium">{t('Rozmiar', 'Size')}</th>
                      <th className="px-2 font-medium">{t('Stan', 'Status')}</th>
                      <th className="px-2 text-right font-medium">{t('Czas', 'Time')}</th>
                      <th className="px-2 text-right font-medium">{t('Hosty', 'Hosts')}</th>
                      <th className="hidden px-2 text-right font-medium sm:table-cell">pps</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedChunks.map((c) => (
                      <tr
                        key={c.id} onPointerEnter={() => setHoverChunk(c.id)} onPointerLeave={() => setHoverChunk(null)} tabIndex={0} onFocus={() => setHoverChunk(c.id)} onBlur={() => setHoverChunk(null)}
                        className={cx('border-b border-rule last:border-b-0 outline-offset-[-2px]', (hoverChunk === c.id || hoveredChunkId === c.id) ? 'bg-raised' : hoverGroup && c.group === hoverGroup ? 'bg-accent-wash/50' : '')}
                      >
                        <td className="num h-[42px] pl-5 pr-2 text-ink-2">{c.seq}</td>
                        <td className="mono whitespace-nowrap px-2" title={c.spec.join(', ')}>{specLabel(c)}</td>
                        <td className="num whitespace-nowrap px-2 text-ink-2">{c.group ? <span className="inline-flex items-center gap-1">{(groupSizes.get(c.group) ?? 0) > 1 ? <span className="inline-block h-[14px] w-[3px] bg-accent" aria-hidden="true" /> : null}G{c.group}{(groupSizes.get(c.group) ?? 0) > 1 ? <span className="text-2xs text-ink-3">×{groupSizes.get(c.group)}</span> : null}</span> : '–'}</td>
                        <td className="px-2"><span className="flex items-center gap-2"><span className="num w-[38px] text-right">{fmtInt(c.size)}</span><span className="hidden h-[4px] bg-ink-3 sm:block" style={{ width: Math.max(3, (c.size / maxSize) * 28) }} /></span></td>
                        <td className="whitespace-nowrap px-2"><ChunkStatusMark status={c.status} /></td>
                        <td className="num whitespace-nowrap px-2 text-right text-ink-2">{c.duration_ms ? fmtDuration(c.duration_ms / 1000) : '–'}</td>
                        <td className="num px-2 text-right">{c.status === 'done' ? c.hosts_up : '–'}</td>
                        <td className="num hidden px-2 text-right text-ink-2 sm:table-cell">{c.pps ? fmtInt(c.pps) : '–'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel> : null}
        {tab === 'progress' ? <>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
          <section className="card p-5">
            <div className="flex items-baseline justify-between gap-3">
              {small && isLive ? (
                <span><span className="font-display text-[36px] leading-none">{fmtInt(s.services_open)}</span> <span className="text-sm text-ink-2">{plural(s.services_open, ['otwarta usługa', 'otwarte usługi', 'otwartych usług'], ['open service', 'open services'])} {t('do tej pory', 'so far')}</span></span>
              ) : (
                <span><span className="font-display text-[36px] leading-none">{fmtPct(pct, pct > 0 && pct < 1 ? 1 : 0)}</span> <span className="text-sm text-ink-2">{t('adresów', 'of addresses')}</span></span>
              )}
              <span className="num text-sm text-ink-2">{fmtInt(s.addresses_done)} / {fmtInt(s.addresses_total)}</span>
            </div>
            <div className="mt-2"><ProgressBar value={s.addresses_done} max={s.addresses_total} active={isLive ? runningAddrs : 0} label={t('Postęp skanu', 'Scan progress')} /></div>
            <RunPasses passes={s.passes} className="mt-1.5" />
            <PartialNote run={run} className="mt-2" />
            {run.status === 'running' && runningChunks > 0 ? (
              <p className="mt-2.5 flex items-center gap-2.5 text-sm text-ink" data-testid="run-phase">
                <span className="bar-active inline-block h-1.5 w-5 flex-none rounded-[2px]" aria-hidden="true" />
                {small ? smallPhaseText(s) : phaseText(s, runningChunks, runningAddrs)}
              </p>
            ) : null}
            <dl className="mt-5 grid grid-cols-2 gap-y-4 pt-1 sm:grid-cols-4">
              <Fact label={run.status === 'completed' ? t('Czas trwania', 'Duration') : t('Czas aktywny', 'Active time')}><span className="num">{fmtDuration(s.elapsed_sec)}</span></Fact>
              <Fact label={t('Pozostało', 'Remaining')}><span className="num">{isLive || run.status === 'paused' ? (run.status === 'analyzing' ? t('analiza', 'analysing') : s.eta_sec > 0 ? fmtDuration(s.eta_sec) : '–') : '–'}</span></Fact>
              <Fact label={t('Podgrupy', 'Chunks')}><span className="num">{s.chunks_done} / {s.chunks_total}</span></Fact>
              <Fact label={t('Aktywne hosty', 'Hosts up')}><span className="num">{fmtInt(s.hosts_up)}</span></Fact>
              <Fact label={t('Otwarte usługi', 'Open services')}><span className="num">{fmtInt(s.services_open)}</span> <span className="text-xs font-normal text-ink-3">({fmtInt(s.http_services)} WWW)</span></Fact>
              <Fact label={t('Pakiety', 'Packets')}><PacketCount sent={s.packets_sent} estimated={s.packets_estimated} /></Fact>
              <Fact label={t('Żądania HTTP', 'HTTP requests')}><span className="num">{fmtInt(s.http_requests)}</span></Fact>
              <Fact label={t('Hosty sprawdzone ponownie', 'Hosts probed again')}><span className="num">{fmtInt(s.retried)}</span></Fact>
            </dl>
          </section>
          <section className="card p-5">
            <h2 className="label mb-3">{t('Tempo skanowania', 'Scan rate')}</h2>
            {policyCap ? <RateGauge current={isLive ? s.current_pps : 0} cap={cap} policyCap={policyCap} basis={isLive ? s.current_pps_basis : undefined} /> : <div className="skeleton h-12" />}
            <p className="mt-2 text-xs text-ink-2">{t('Średnio', 'Average')} <span className="num text-ink">{fmtInt(s.avg_pps)}</span> pps. {profile.data && profile.data.rate.max_pps > policyCap ? t('Polityka bezpieczeństwa ogranicza tempo do ' + fmtInt(policyCap) + ' pps.', 'The safety policy limits the rate to ' + fmtInt(policyCap) + ' pps.') : null}</p>
          </section>
        </div>
        {!small && (isLive || recent.length > 0) ? (
            <Panel title={t('Ostatnio wykryte hosty', 'Hosts just found')} flush>
              {recent.length === 0 ? <p className="p-3 text-sm text-ink-2">{t('Oczekiwanie na odpowiedzi…', 'Waiting for responses…')}</p> : (
                <ul>
                  {recent.map((h, i) => (
                    <li key={h.ip + h.at} className="flex h-[30px] items-center gap-3 border-b border-rule px-3 last:border-b-0" style={i === 0 ? { animation: 'rise-in 240ms var(--ease-out-expo)' } : undefined}>
                      <Glyph name="dot" tone="neutral" size={12} />
                      <Link to={'/hosts?q=' + h.ip} className="mono link">{h.ip}</Link>
                      <span className="text-xs text-ink-2">{h.services} {plural(h.services, ['usługa', 'usługi', 'usług'], ['service', 'services'])}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          ) : null}
        </> : null}
      </div>

      <Dialog
        open={confirmCancel} onClose={() => setConfirmCancel(false)} title={t('Anulować skan #' + run.id + '?', 'Cancel scan #' + run.id + '?')} width={440}
        footer={<><Button onClick={() => setConfirmCancel(false)}>{t('Wróć', 'Back')}</Button><Button variant="dangerSolid" busy={act.isPending} onClick={() => act.mutate('cancel', { onSuccess: () => setConfirmCancel(false) })}>{t('Anuluj skan', 'Cancel scan')}</Button></>}
      >
        <p className="text-sm">{t('Wyniki z gotowych podgrup zostają. Anulowanego skanu nie da się wznowić.', 'Results of finished chunks stay. A cancelled scan cannot be resumed.')}</p>
      </Dialog>
    </div>
  );
}

/** Analyst note and label of a run (PATCH /runs/{id}). */
function RunNote({ run, canEdit }: { run: ScanRun; canEdit: boolean }) {
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState(run.label ?? '');
  const [note, setNote] = useState(run.note ?? '');
  const save = useAction(() => patch<ScanRun>('/runs/' + run.id, { label: label.trim(), note: note.trim() }), {
    invalidate: ['/runs/' + run.id, '/runs'], silent: true, success: t('Notatka zapisana', 'Note saved'), onSuccess: () => setOpen(false),
  });
  const has = Boolean(run.label || run.note);
  if (!has && !canEdit) return null;
  return (
    <div className="flex flex-wrap items-start gap-x-3 gap-y-1 text-sm" data-testid="run-note">
      {run.label ? <span className="border border-rule-strong px-1.5 py-0.5 text-xs font-medium">{run.label}</span> : null}
      {run.note ? <p className="max-w-[90ch] whitespace-pre-wrap text-ink-2">{run.note}</p> : null}
      {canEdit ? <button type="button" className="link text-xs" onClick={() => { setLabel(run.label ?? ''); setNote(run.note ?? ''); setOpen(true); }}>{has ? t('Zmień notatkę', 'Edit note') : t('Dodaj notatkę lub etykietę', 'Add note or label')}</button> : null}
      <Dialog open={open} onClose={() => setOpen(false)} width={520} title={t('Notatka do skanu #' + run.id, 'Note on scan #' + run.id)}
        footer={<><Button onClick={() => setOpen(false)}>{t('Anuluj', 'Cancel')}</Button><Button variant="primary" icon="check" busy={save.isPending} disabled={label.length > 100 || note.length > 4000} onClick={() => save.mutate(undefined)}>{t('Zapisz', 'Save')}</Button></>}>
        <div className="space-y-3">
          <Field label={t('Etykieta', 'Label')} hint={t('do 100 znaków', 'up to 100 characters')}><input className="field" value={label} maxLength={100} onChange={(e) => setLabel(e.target.value.replace(/\n/g, ' '))} data-testid="run-label" /></Field>
          <Field label={t('Notatka', 'Note')} hint={t('do 4000 znaków', 'up to 4000 characters')}><textarea className="field" rows={4} value={note} maxLength={4000} onChange={(e) => setNote(e.target.value)} data-testid="run-note-text" /></Field>
          <InlineError error={save.error} />
        </div>
      </Dialog>
    </div>
  );
}

/** The phase of a one-machine scan in words. */
export function smallPhaseText(s: ScanRun['stats']): string {
  if (s.http_requests > 0) return t('Rozpoznawanie usług WWW: ' + s.services_open + ' ' + plural(s.services_open, ['otwarty port', 'otwarte porty', 'otwartych portów'], ['', '']) + ' do tej pory.', 'Identifying web services: ' + s.services_open + ' open ' + (s.services_open === 1 ? 'port' : 'ports') + ' so far.');
  if (s.services_open > 0) return t('Rozpoznawanie usług na ' + s.services_open + ' ' + plural(s.services_open, ['otwartym porcie', 'otwartych portach', 'otwartych portach'], ['', '']) + '.', 'Identifying the services on ' + s.services_open + ' open ' + (s.services_open === 1 ? 'port' : 'ports') + '.');
  return t('Skanowanie portów', 'Scanning ports');
}

/** The phase of a running scan in words, from what the counters show so far. */
export function phaseText(s: ScanRun['stats'], chunks: number, addrs: number): string {
  const where = t(chunks + ' ' + plural(chunks, ['podgrupie', 'podgrupach', 'podgrupach'], ['', '']) + ' (' + fmtInt(addrs) + ' adresów)', chunks + ' ' + (chunks === 1 ? 'chunk' : 'chunks') + ' (' + fmtInt(addrs) + ' addresses)');
  if (s.http_requests > 0) return t('Rozpoznawanie usług WWW i wykrywanie hostów w ', 'Identifying web services and discovering hosts in ') + where;
  if (s.services_open > 0) return t('Wykrywanie hostów i usług w ', 'Discovering hosts and services in ') + where;
  return t('Wykrywanie hostów w ', 'Discovering hosts in ') + where + '.';
}

interface DojoRunResult { test_id: number; test_url: string; reimport: boolean; mode?: 'import' | 'reimport'; title?: string; created: number; closed: number; reactivated: number; untouched: number; total: number }

/** Uploads the nmap XML of a completed run to DefectDojo as an "Nmap Scan" import (a second upload re-imports into the same test). */
export function DojoRunButton({ runId }: { runId: number }) {
  const [res, setRes] = useState<DojoRunResult | null>(null);
  const send = useAction(() => post<DojoRunResult>('/runs/' + runId + '/export/defectdojo'), { silent: true, onSuccess: setRes });
  return (
    <>
      <Button icon="upload" busy={send.isPending} onClick={() => send.mutate(undefined)} data-testid="run-dojo">{t('Wyślij do DefectDojo', 'Send to DefectDojo')}</Button>
      <Dialog open={res !== null || Boolean(send.error)} onClose={() => { setRes(null); send.reset(); }} width={480} title={t('Skan w DefectDojo (Nmap Scan)', 'The scan in DefectDojo (Nmap Scan)')}
        footer={<Button variant="primary" onClick={() => { setRes(null); send.reset(); }}>{t('Gotowe', 'Done')}</Button>}>
        {res ? (
          <div className="space-y-3 text-sm" data-testid="run-dojo-result">
            <p className="flex items-center gap-2"><Glyph name="check" tone="new" />{(res.mode ?? (res.reimport ? 'reimport' : 'import')) === 'reimport' ? t('Ponowny import. DefectDojo zamknie to, czego ten skan nie widzi.', 'Re-import. DefectDojo closes what this scan no longer sees.') : t('Pierwszy import: nowy test w DefectDojo.', 'First import: a new test in DefectDojo.')}</p>
            <p className="text-xs text-ink-2" data-testid="run-dojo-mode">{t('Tryb', 'Mode')} <span className="mono text-ink">{res.mode ?? (res.reimport ? 'reimport' : 'import')}</span>{res.title ? <> · {t('test', 'test')} <span className="text-ink">{res.title}</span></> : null}</p>
            <dl className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-4 gap-y-1">
              <dt className="text-ink-2">{t('Nowe znaleziska', 'New findings')}</dt><dd className="num">{res.created}</dd>
              <dt className="text-ink-2">{t('Zamknięte (zniknęły)', 'Closed (gone)')}</dt><dd className="num">{res.closed}</dd>
              <dt className="text-ink-2">{t('Otwarte ponownie', 'Reopened')}</dt><dd className="num">{res.reactivated}</dd>
              <dt className="text-ink-2">{t('Bez zmian', 'Unchanged')}</dt><dd className="num">{res.untouched}</dd>
              <dt className="text-ink-2">{t('Razem w teście', 'Total in the test')}</dt><dd className="num">{res.total}</dd>
            </dl>
            <a className="link inline-flex items-center gap-1" href={res.test_url} target="_blank" rel="noreferrer noopener">{t('Otwórz test', 'Open test')} #{res.test_id}<Icon name="external" size={11} /></a>
          </div>
        ) : <InlineError error={send.error} />}
      </Dialog>
    </>
  );
}
