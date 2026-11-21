import { useState } from 'react';
import { Link } from 'react-router';
import { usePage } from '../api/hooks';
import type { ScanProfile, Scope } from '../api/types';
import { t } from '../i18n';
import { fmtDateTime, fmtInt, fmtRelative } from '../lib/format';
import { Button, Empty, LinkButton, PageHeader } from '../ui/kit';
import { DataTable, type Col } from '../ui/table';
import { Glyph } from '../ui/marks';
import { describeWindows } from '../viz/WindowPicker';
import { useCan } from '../session';
import { StartRunDialog } from './Runs';
import { portsShort } from '../lib/portsShort';

export function scheduleText(p: ScanProfile): string {
  if (!p.schedule.enabled) return t('tylko ręcznie', 'manual only');
  if (p.schedule.interval_minutes > 0) {
    const m = p.schedule.interval_minutes;
    return m % 60 === 0 ? t('co ' + m / 60 + ' godz.', 'every ' + m / 60 + ' h') : t('co ' + m + ' min', 'every ' + m + ' min');
  }
  return 'cron ' + p.schedule.cron;
}

export default function Profiles() {
  const canEdit = useCan('scans:configure');
  const canRun = useCan('scans:run');
  const q = usePage<ScanProfile>('/profiles', { limit: 100 });
  const scopes = usePage<Scope>('/scopes', { limit: 200 });
  const [start, setStart] = useState<number | null>(null);
  const scopeName = (id: number) => scopes.data?.items.find((s) => s.id === id)?.name ?? '#' + id;
  const cols: Col<ScanProfile>[] = [
    { id: 'name', header: t('Profil', 'Profile'), wrap: true, cell: (p) => (
      <div className="min-w-[200px] py-1">
        <Link to={'/profiles/' + p.id} className="link font-medium">{p.name}</Link>
        <div className="text-xs text-ink-3">{p.description}</div>
      </div>
    ) },
    { id: 'scopes', header: t('Zakresy', 'Scopes'), wrap: true, hide: 'lg', cell: (p) => <span className="text-ink-2">{p.scope_ids.map(scopeName).join(', ')}</span> },
    { id: 'ports', header: t('Porty', 'Ports'), cell: (p) => <span className="mono" title={p.ports}>{portsShort(p.ports)}</span> },
    { id: 'rate', header: t('Tempo', 'Rate'), align: 'right', hide: 'md', cell: (p) => <span className="num">{fmtInt(p.rate.max_pps)} <span className="font-sans text-xs text-ink-3">pps</span></span> },
    { id: 'schedule', header: t('Harmonogram', 'Schedule'), wrap: true, cell: (p) => (
      <div className="py-1">
        <div className={p.schedule.enabled ? 'mono whitespace-nowrap text-sm' : 'text-ink-3'}>{scheduleText(p)}</div>
        <div className="text-xs text-ink-3">{t('okna:', 'windows:')} {describeWindows(p.schedule.windows)}</div>
      </div>
    ) },
    { id: 'next', header: t('Następny skan', 'Next scan'), hide: 'md', cell: (p) => p.next_run_at ? <span title={fmtDateTime(p.next_run_at)}><span className="num">{fmtDateTime(p.next_run_at)}</span> <span className="text-xs text-ink-3">{fmtRelative(p.next_run_at)}</span></span> : <span className="text-ink-3">–</span> },
    { id: 'last', header: t('Ostatni', 'Last'), hide: 'lg', cell: (p) => p.last_run_id ? <Link to={'/runs/' + p.last_run_id} className="num link">#{p.last_run_id}</Link> : <span className="text-ink-3">–</span> },
    { id: 'enabled', header: t('Stan', 'Status'), cell: (p) => p.enabled ? <span className="inline-flex items-center gap-1.5"><Glyph name="dot" tone="neutral" />{t('włączony', 'enabled')}</span> : <span className="inline-flex items-center gap-1.5 text-ink-3"><Glyph name="ring" tone="expected" />{t('wyłączony', 'disabled')}</span> },
    ...(canRun ? [{ id: 'act', header: '', align: 'right' as const, cell: (p: ScanProfile) => <Button size="sm" icon="play" disabled={!p.enabled} onClick={() => setStart(p.id)}>{t('Uruchom', 'Start')}</Button> }] : []),
  ];
  return (
    <div>
      <PageHeader
        title={t('Profile skanów', 'Scan profiles')}
        readOnly={!canEdit}
        actions={canEdit ? <LinkButton to="/profiles/new" variant="primary" icon="plus">{t('Nowy profil', 'New profile')}</LinkButton> : null}
      />
      <DataTable
        rows={q.data?.items} cols={cols} rowKey={(p) => p.id} rowHref={(p) => '/profiles/' + p.id} loading={q.isPending} error={q.error} retry={() => q.refetch()}
        empty={<Empty icon="profiles" title={t('Brak profili', 'No profiles yet')} action={canEdit ? <LinkButton to="/profiles/new" variant="primary" icon="plus">{t('Nowy profil', 'New profile')}</LinkButton> : undefined} />}
        mobile={(p) => (
          <div>
            <div className="text-sm font-medium">{p.name}</div>
            <div className="mt-0.5 text-xs text-ink-3"><span className="mono" title={p.ports}>{portsShort(p.ports)}</span> · {scheduleText(p)}</div>
            <div className="text-xs text-ink-3">{describeWindows(p.schedule.windows)}</div>
          </div>
        )}
      />
      {start !== null ? <StartRunDialog open onClose={() => setStart(null)} profileId={start} /> : null}
    </div>
  );
}
