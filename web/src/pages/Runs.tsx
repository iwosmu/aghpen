import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { usePage, useAction, useItem } from '../api/hooks';
import { post } from '../api/client';
import type { SafetyPolicy, ScanProfile, ScanRun } from '../api/types';
import { t } from '../i18n';
import { fmtDateTime, fmtDuration, fmtInt, fmtPct, fmtRelative } from '../lib/format';
import { useUrlState } from '../lib/hooks';
import { Button, Dialog, Empty, InlineError, PageHeader, Select } from '../ui/kit';
import { DataTable, FilterBar, FilterField, Pager, type Col } from '../ui/table';
import { RUN_STATUSES, RunStatusMark, runStatusInfo } from '../ui/marks';
import { runChanges } from '../viz/Night';
import { ReprobeLine } from './Reprobe';
import { useCan } from '../session';
import { EstimateBox } from './ProfileEdit';
import { OperatorLockNote } from './Targets';
import { outsideLock } from '../lib/lock';
import { Icon } from '../ui/Icon';
import { isFullRun, partialRunPhrase } from '../lib/headline';

export function triggerLabel(x: string): string {
  switch (x) {
    case 'schedule': return t('harmonogram', 'schedule');
    case 'import': return t('import', 'import');
    case 'reprobe': return t('ponowne sprawdzenie', 're-probe');
    case 'manual-entry': return t('wpis ręczny', 'manual entry');
    default: return t('ręcznie', 'manual');
  }
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
      open={open} onClose={onClose} title={t('Uruchom skan', 'Start scan')} width={560}
      footer={<>
        <Button onClick={onClose}>{t('Anuluj', 'Cancel')}</Button>
        <Button variant="primary" icon="play" busy={start.isPending} disabled={!chosen || noScope} onClick={() => start.mutate(Number(chosen))}>{t('Uruchom', 'Tryb')}</Button>
      </>}
    >
      <label className="block">
        <span className="label mb-1 block">{t('Profil skanu', 'Scan profile')}</span>
        <Select value={chosen} onChange={setPid} options={items.map((p) => ({ value: String(p.id), label: p.name + ((p.scope_ids ?? []).length === 0 ? t(' (bez zakresu)', ' (no scope)') : '') }))} />
      </label>
      {noScope ? <p className="mt-3 text-sm text-ink-2">{t('Ten profil nie ma zakresu. ', 'This profile has no scope. ')}<Link to={'/profiles/' + chosen} className="link">{t('Przypisz zakres', 'Assign a scope')}</Link>.</p> : chosen ? <div className="mt-4"><p className="label mb-1.5">{t('Budżet ruchu', 'Traffic budget')}</p><EstimateBox profileId={Number(chosen)} /></div> : null}
      <div className="mt-3"><InlineError error={start.error} /></div>
    </Dialog>
  );
}

/** A run over chosen addresses (POST /runs/adhoc): the profile gives rate, discovery and HTTP settings; the policy and the operator lock apply. */
export function AdHocRunDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const profiles = usePage<ScanProfile>('/profiles', { limit: 100 }, open);
  const safety = useItem<SafetyPolicy>('/settings/safety', undefined, { enabled: open });
  const [pid, setPid] = useState('');
  const [addrs, setAddrs] = useState('');
  const [ports, setPorts] = useState('');
  const [reason, setReason] = useState('');
  const navigate = useNavigate();
  const items = profiles.data?.items ?? [];
  const chosen = pid || (items[0] ? String(items[0].id) : '');
  const list = addrs.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  const outside = outsideLock(list, safety.data?.operator_networks ?? []);
  const start = useAction(() => post<ScanRun>('/runs/adhoc', { profile_id: Number(chosen) || 0, addresses: list, ports: ports.trim(), reason: reason.trim() }), {
    invalidate: ['/runs', '/dashboard'], silent: true,
    onSuccess: (run) => { onClose(); navigate('/runs/' + run.id); },
  });
  return (
    <Dialog
      open={open} onClose={onClose} title={t('Skan wybranych adresów', 'Scan chosen addresses')} width={560}
      footer={<>
        <Button onClick={onClose}>{t('Anuluj', 'Cancel')}</Button>
        <Button variant="primary" icon="play" busy={start.isPending} disabled={list.length === 0} onClick={() => start.mutate(undefined)} data-testid="adhoc-start">{t('Uruchom', 'Tryb')}</Button>
      </>}
    >
            <div className="grid gap-3">
        <label className="block"><span className="label mb-1 block">{t('Ustawienia z profilu', 'Settings from the profile')}</span>
          <Select value={chosen} onChange={setPid} options={items.map((p) => ({ value: String(p.id), label: p.name }))} />
        </label>
        <label className="block"><span className="label mb-1 block">{t('Adresy: IP albo CIDR do /16', 'Addresses: IP or CIDR up to /16')}</span>
          <textarea className="field mono" rows={4} value={addrs} onChange={(e) => setAddrs(e.target.value)} placeholder={(safety.data?.operator_networks?.[0]?.replace(/\.0\/\d+$/, '.10') ?? '10.66.70.20') + '\n10.66.3.0/24'} data-testid="adhoc-addresses" aria-invalid={outside.length > 0} />
        </label>
        <OperatorLockNote networks={safety.data?.operator_networks} />
        {outside.length ? <p className="flex items-start gap-1.5 text-xs text-st-changed" data-testid="adhoc-outside-lock"><Icon name="lock" size={13} className="mt-px flex-none" /><span>{t('Poza blokadą operatora: ', 'Outside the operator lock: ')}<span className="mono">{outside.join(', ')}</span>{t('. Czujka nie zeskanuje tych adresów.', '. Czujka will not scan these addresses.')}</span></p> : null}
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block"><span className="label mb-1 block">{t('Porty (puste: porty profilu)', 'Ports (empty: the profile ports)')}</span><input className="field mono" value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="80,443,8080" /></label>
          <label className="block"><span className="label mb-1 block">{t('Powód', 'Reason')}</span><input className="field" value={reason} onChange={(e) => setReason(e.target.value)} /></label>
        </div>
      </div>
      <div className="mt-3" data-testid="adhoc-error"><InlineError error={start.error} /></div>
    </Dialog>
  );
}

/** The profile, a small tag for a run that is not a full profile run, and the state only when it is not 'completed'. */
function RunProfileCell({ r }: { r: ScanRun }) {
  const full = isFullRun(r) || (r.status !== 'completed' && r.profile_id != null && !r.ad_hoc);
  const tag = full ? null : r.trigger === 'reprobe' || r.trigger === 'import' || r.trigger === 'manual-entry' ? triggerLabel(r.trigger) : t('wybrane adresy', 'chosen addresses');
  const live = runStatusInfo(r.status).live || r.status === 'paused';
  const pct = r.stats.addresses_total ? r.stats.addresses_done / r.stats.addresses_total : 0;
  return (
    <span className="flex min-w-0 max-w-[340px] items-center gap-2" title={partialRunPhrase(r) + (r.note ? ' · ' + r.note : '')}>
      {r.status !== 'completed' ? <span className="flex-none"><RunStatusMark status={r.status} pauseReason={r.pause_reason} /></span> : null}
      {live ? <span className="num flex-none text-xs text-ink-2">{fmtPct(pct)}</span> : null}
      <span className="min-w-0 truncate">{r.profile_name || r.import_file || ''}</span>
      {tag ? <span className="chip-fact flex-none">{tag}</span> : null}
      {r.label ? <span className="chip-fact flex-none">{r.label}</span> : null}
    </span>
  );
}

export default function Runs() {
  const u = useUrlState();
  const canRun = useCan('scans:run');
  const [startOpen, setStartOpen] = useState(false);
  const [adhocOpen, setAdhocOpen] = useState(false);
  const limit = 25;
  const offset = Number(u.get('offset', '0'));
  const q = usePage<ScanRun>('/runs', { status: u.get('status'), profile_id: u.get('profile_id'), sort: u.get('sort', '-id'), limit, offset });
  const profiles = usePage<ScanProfile>('/profiles', { limit: 100 });
  const cols: Col<ScanRun>[] = [
    { id: 'id', header: '#', sort: 'id', width: 64, cell: (r) => <Link to={'/runs/' + r.id} className="num link">#{r.id}</Link> },
    { id: 'profile', header: t('Profil', 'Profile'), cell: (r) => <RunProfileCell r={r} /> },
    { id: 'started', header: t('Kiedy', 'When'), sort: 'started_at', cell: (r) => <span className="num text-ink-2" title={fmtDateTime(r.started_at)}>{fmtRelative(r.started_at)}</span> },
    { id: 'dur', header: t('Czas', 'Duration'), align: 'right', hide: 'md', cell: (r) => <span className="num text-ink-2">{fmtDuration(r.stats.elapsed_sec)}</span> },
    { id: 'host / hosts', header: t('Hosty', 'Hosts'), align: 'right', cell: (r) => <span className="num">{fmtInt(r.stats.hosts_up)}</span> },
    { id: 'svc', header: t('Usługi', 'Services'), align: 'right', hide: 'md', cell: (r) => <span className="num">{fmtInt(r.stats.services_open)}</span> },
    { id: 'diff', header: t('Zmiany', 'Changes'), align: 'right', cell: (r) => { const n = r.summary ? runChanges(r) : 0; return n ? <Link to={'/changes?run_id=' + r.id + '&expected=false'} className="num link" onClick={(e) => e.stopPropagation()}>{fmtInt(n)}</Link> : <span className="text-ink-3">–</span>; } },
  ];
  const active = ['status', 'profile_id'].filter((k) => u.get(k)).length;
  return (
    <div>
      <PageHeader
        title={t('Skany', 'Scans')}
        readOnly={!canRun}
        actions={<>
          <Link to="/changes/compare" className="link inline-flex h-[30px] items-center gap-1.5 text-sm">{t('Porównaj dwa skany', 'Compare two scans')}</Link>
          {canRun ? <Button icon="targets" onClick={() => setAdhocOpen(true)} data-testid="adhoc-open">{t('Skan wybranych adresów', 'Scan chosen addresses')}</Button> : null}
          {canRun ? <Button variant="primary" icon="play" onClick={() => setStartOpen(true)}>{t('Uruchom skan', 'Start scan')}</Button> : null}
        </>}
      />
      <ReprobeLine />
      <FilterBar onClear={() => u.clear(['status', 'profile_id'])} active={active}>
        <FilterField label={t('Stan', 'Status')}>
          <Select value={u.get('status')} onChange={(v) => u.set({ status: v })} options={[{ value: '', label: t('wszystkie', 'all') }, ...RUN_STATUSES.map((s) => ({ value: s, label: runStatusInfo(s).label.split(' · ')[0] }))]} />
        </FilterField>
        <FilterField label={t('Profil', 'Profile')} width={220}>
          <Select value={u.get('profile_id')} onChange={(v) => u.set({ profile_id: v })} options={[{ value: '', label: t('wszystkie', 'all') }, ...(profiles.data?.items ?? []).map((p) => ({ value: String(p.id), label: p.name }))]} />
        </FilterField>
      </FilterBar>
      <DataTable
        rows={q.data?.items} cols={cols} rowKey={(r) => r.id} rowHref={(r) => '/runs/' + r.id}
        group={u.get('sort', '-id').match(/id|started_at/) ? (r) => { const day = fmtDateTime(r.started_at).slice(0, 10); return { key: day, label: <span className="num">{day}</span> }; } : undefined} loading={q.isPending} error={q.error} retry={() => q.refetch()} dim={q.isPlaceholderData}
        sort={u.get('sort', '-id')} onSort={(s) => u.set({ sort: s })}
        empty={<Empty icon="runs" title={active ? t('Żaden skan nie pasuje do filtrów', 'No scans match the filters') : t('Brak skanów', 'No scans yet')} hint={active ? undefined : t('Przygotuj profil i uruchom pierwszy skan.', 'Prepare a profile and start the first scan.')} action={canRun && !active ? <Button variant="primary" icon="play" onClick={() => setStartOpen(true)}>{t('Uruchom skan', 'Start scan')}</Button> : undefined} />}
        mobile={(r) => (
          <div className="flex items-center gap-3">
            <span className="num flex-none text-sm font-medium">#{r.id}</span>
            <span className="min-w-0 flex-1 truncate text-sm text-ink-2"><RunProfileCell r={r} /></span>
            <span className="num flex-none text-xs text-ink-3">{fmtRelative(r.started_at)}</span>
          </div>
        )}
      />
      {q.data ? <Pager total={q.data.total} limit={limit} offset={offset} onOffset={(o) => u.set({ offset: o || null })} /> : null}
      <StartRunDialog open={startOpen} onClose={() => setStartOpen(false)} />
      <AdHocRunDialog open={adhocOpen} onClose={() => setAdhocOpen(false)} />
    </div>
  );
}
