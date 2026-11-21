import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { usePage, useAction } from '../api/hooks';
import { post } from '../api/client';
import type { ScanProfile, ScanRun } from '../api/types';
import { t } from '../i18n';
import { fmtDateTime, fmtDuration, fmtInt, fmtPct, fmtRelative } from '../lib/format';
import { useUrlState } from '../lib/hooks';
import { Button, Dialog, Empty, InlineError, PageHeader, Select } from '../ui/kit';
import { DataTable, FilterBar, FilterField, Pager, type Col } from '../ui/table';
import { RUN_STATUSES, RunStatusMark, runStatusInfo, Glyph } from '../ui/marks';
import { ProgressBar } from '../viz/charts';
import { useCan } from '../session';
import { EstimateBox } from './ProfileEdit';

function triggerLabel(x: string): string {
  return x === 'schedule' ? t('harmonogram', 'schedule') : x === 'import' ? t('import', 'import') : t('ręcznie', 'manual');
}

export function StartRunDialog({ open, onClose, profileId }: { open: boolean; onClose: () => void; profileId?: number }) {
  const profiles = usePage<ScanProfile>('/profiles', { limit: 100 }, open);
  const [pid, setPid] = useState<string>(profileId ? String(profileId) : '');
  const navigate = useNavigate();
  // Default to the first profile that can run: enabled and with at least one scope.
  const items = profiles.data?.items ?? [];
  const firstReady = items.find((p) => p.enabled && (p.scope_ids ?? []).length > 0) ?? items[0];
  const chosen = pid || (firstReady ? String(firstReady.id) : '');
  const chosenProfile = items.find((p) => String(p.id) === chosen);
  const noScope = Boolean(chosenProfile && (chosenProfile.scope_ids ?? []).length === 0);
  const start = useAction((id: number) => post<ScanRun>('/runs', { profile_id: id }), {
    invalidate: ['/runs', '/dashboard'], silent: true,
    onSuccess: (run) => { onClose(); navigate('/runs/' + run.id); },
  });
  return (
    <Dialog
      open={open} onClose={onClose} title={t('Uruchom skan', 'Start a scan')} width={560}
      footer={<>
        <Button onClick={onClose}>{t('Anuluj', 'Cancel')}</Button>
        <Button variant="primary" icon="play" busy={start.isPending} disabled={!chosen || noScope} onClick={() => start.mutate(Number(chosen))}>{t('Uruchom', 'Start')}</Button>
      </>}
    >
      <label className="block">
        <span className="label mb-1 block">{t('Profil skanu', 'Scan profile')}</span>
        <Select value={chosen} onChange={setPid} options={items.map((p) => ({ value: String(p.id), label: p.name + ((p.scope_ids ?? []).length === 0 ? t(' (bez zakresu)', ' (no scope)') : '') }))} />
      </label>
      {noScope ? <p className="mt-3 text-sm text-ink-2">{t('Ten profil nie ma przypisanego zakresu, więc nie ma czego skanować. ', 'This profile has no scope, so there is nothing to scan. ')}<Link to={'/profiles/' + chosen} className="link">{t('Przypisz zakres w profilu', 'Assign a scope in the profile')}</Link>.</p> : chosen ? <div className="mt-4"><p className="label mb-1.5">{t('Budżet ruchu przed startem', 'Traffic budget before the start')}</p><EstimateBox profileId={Number(chosen)} /></div> : null}
      <div className="mt-3"><InlineError error={start.error} /></div>
    </Dialog>
  );
}

export default function Runs() {
  const u = useUrlState();
  const canRun = useCan('scans:run');
  const [startOpen, setStartOpen] = useState(false);
  const limit = 25;
  const offset = Number(u.get('offset', '0'));
  const q = usePage<ScanRun>('/runs', { status: u.get('status'), profile_id: u.get('profile_id'), sort: u.get('sort', '-id'), limit, offset });
  const profiles = usePage<ScanProfile>('/profiles', { limit: 100 });
  const cols: Col<ScanRun>[] = [
    { id: 'id', header: '#', sort: 'id', width: 64, cell: (r) => <Link to={'/runs/' + r.id} className="num link">#{r.id}</Link> },
    { id: 'status', header: t('Stan', 'Status'), cell: (r) => <RunStatusMark status={r.status} pauseReason={r.pause_reason} /> },
    { id: 'profile', header: t('Profil / źródło', 'Profile / source'), cell: (r) => <span className="block max-w-[280px] truncate" title={r.profile_name}>{r.profile_name}</span> },
    { id: 'trigger', header: t('Start', 'Trigger'), hide: 'lg', cell: (r) => <span className="text-ink-2">{triggerLabel(r.trigger)}</span> },
    { id: 'started', header: t('Rozpoczęty', 'Started'), sort: 'started_at', cell: (r) => <span className="num text-ink-2" title={fmtDateTime(r.started_at)}>{fmtRelative(r.started_at)}</span> },
    { id: 'dur', header: t('Czas', 'Duration'), align: 'right', hide: 'md', cell: (r) => <span className="num">{fmtDuration(r.stats.elapsed_sec)}</span> },
    { id: 'progress', header: t('Adresy', 'Addresses'), width: 170, cell: (r) => {
      const pct = r.stats.addresses_total ? r.stats.addresses_done / r.stats.addresses_total : 0;
      const live = runStatusInfo(r.status).live || r.status === 'paused';
      return live
        ? <span className="flex items-center gap-2"><span className="w-[84px]"><ProgressBar value={r.stats.addresses_done} max={r.stats.addresses_total} /></span><span className="num text-xs text-ink-2">{fmtPct(pct)}</span></span>
        : <span className="num text-ink-2">{fmtInt(r.stats.addresses_done)}</span>;
    } },
    { id: 'hosts', header: t('Hosty', 'Hosts'), align: 'right', cell: (r) => <span className="num">{fmtInt(r.stats.hosts_up)}</span> },
    { id: 'svc', header: t('Usługi', 'Services'), align: 'right', hide: 'md', cell: (r) => <span className="num">{fmtInt(r.stats.services_open)}</span> },
    { id: 'diff', header: t('Zmiany', 'Changes'), hide: 'lg', cell: (r) => r.summary ? (
      <span className="inline-flex items-center gap-2.5 text-xs">
        <span className="inline-flex items-center gap-1"><Glyph name="plus" tone="new" size={11} /><span className="num">{r.summary.hosts_new + r.summary.services_new}</span></span>
        <span className="inline-flex items-center gap-1"><Glyph name="minus" tone="gone" size={11} /><span className="num">{r.summary.hosts_gone + r.summary.services_gone}</span></span>
        <span className="inline-flex items-center gap-1"><Glyph name="delta" tone="changed" size={11} /><span className="num">{r.summary.services_changed}</span></span>
      </span>
    ) : <span className="text-ink-3">–</span> },
  ];
  const active = ['status', 'profile_id'].filter((k) => u.get(k)).length;
  return (
    <div>
      <PageHeader
        title={t('Przebiegi skanów', 'Scan runs')}
        sub={t('Każdy przebieg to jeden obchód sieci: zaplanowany, uruchomiony ręcznie albo zaimportowany z pliku.', 'A run is one round of the network: scheduled, started by hand or imported from a file.')}
        readOnly={!canRun}
        actions={<>
          <Link to="/changes/compare" className="link inline-flex h-[30px] items-center gap-1.5 text-sm">{t('Porównaj dwa przebiegi', 'Compare two runs')}</Link>
          {canRun ? <Button variant="primary" icon="play" onClick={() => setStartOpen(true)}>{t('Uruchom skan', 'Start a scan')}</Button> : null}
        </>}
      />
      <FilterBar onClear={() => u.clear(['status', 'profile_id'])} active={active}>
        <FilterField label={t('Stan', 'Status')}>
          <Select value={u.get('status')} onChange={(v) => u.set({ status: v })} options={[{ value: '', label: t('wszystkie', 'all') }, ...RUN_STATUSES.map((s) => ({ value: s, label: runStatusInfo(s).label.split(' · ')[0] }))]} />
        </FilterField>
        <FilterField label={t('Profil', 'Profile')} width={220}>
          <Select value={u.get('profile_id')} onChange={(v) => u.set({ profile_id: v })} options={[{ value: '', label: t('wszystkie', 'all') }, ...(profiles.data?.items ?? []).map((p) => ({ value: String(p.id), label: p.name }))]} />
        </FilterField>
      </FilterBar>
      <DataTable
        rows={q.data?.items} cols={cols} rowKey={(r) => r.id} rowHref={(r) => '/runs/' + r.id} loading={q.isPending} error={q.error} retry={() => q.refetch()} dim={q.isPlaceholderData}
        sort={u.get('sort', '-id')} onSort={(s) => u.set({ sort: s })}
        empty={<Empty icon="runs" title={active ? t('Żaden przebieg nie pasuje do filtrów', 'No run matches the filters') : t('Nie było jeszcze żadnego skanu', 'No scan has run yet')} hint={active ? undefined : t('Przygotuj profil skanu i uruchom pierwszy przebieg. Zobaczysz tu postęp, czas trwania i wykryte zmiany.', 'Prepare a scan profile and start the first run. Progress, duration and the detected changes appear here.')} action={canRun && !active ? <Button variant="primary" icon="play" onClick={() => setStartOpen(true)}>{t('Uruchom skan', 'Start a scan')}</Button> : undefined} />}
        mobile={(r) => (
          <div>
            <div className="flex items-center justify-between gap-2"><span className="num text-sm font-medium">#{r.id}</span><RunStatusMark status={r.status} pauseReason={r.pause_reason} /></div>
            <div className="mt-0.5 truncate text-sm text-ink-2">{r.profile_name}</div>
            <div className="mt-0.5 text-xs text-ink-3">{fmtRelative(r.started_at)} · {fmtInt(r.stats.hosts_up)} {t('hostów', 'hosts')} · {fmtDuration(r.stats.elapsed_sec)}</div>
          </div>
        )}
      />
      {q.data ? <Pager total={q.data.total} limit={limit} offset={offset} onOffset={(o) => u.set({ offset: o || null })} /> : null}
      <StartRunDialog open={startOpen} onClose={() => setStartOpen(false)} />
    </div>
  );
}
