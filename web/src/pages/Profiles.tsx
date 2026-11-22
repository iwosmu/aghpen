import { useState } from 'react';
import { Link } from 'react-router';
import { usePage } from '../api/hooks';
import type { ScanProfile, Scope } from '../api/types';
import { t } from '../i18n';
import { cx, fmtDateTime } from '../lib/format';
import { Button, Empty, LinkButton, PageHeader } from '../ui/kit';
import { DataTable, type Col } from '../ui/table';
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
    { id: 'name', header: t('Profil', 'Profile'), cell: (p) => <span className="block max-w-[320px] truncate" title={p.description}><Link to={'/profiles/' + p.id} className={cx('link', !p.enabled && 'text-ink-3')}>{p.name}</Link></span> },
    { id: 'scopes', header: t('Zakresy', 'Scopes'), hide: 'lg', cell: (p) => <span className="block max-w-[220px] truncate text-ink-2" title={p.scope_ids.map(scopeName).join(', ')}>{p.scope_ids.map(scopeName).join(', ') || '–'}</span> },
    { id: 'ports', header: t('Porty', 'Ports'), cell: (p) => <span className="mono" title={p.ports}>{portsShort(p.ports)}</span> },
    { id: 'schedule', header: t('Harmonogram', 'Schedule'), cell: (p) => (
      <span className="whitespace-nowrap" title={t('okna: ', 'windows: ') + describeWindows(p.schedule.windows)}>
        <span className={p.schedule.enabled ? 'mono text-sm' : 'text-ink-3'}>{scheduleText(p)}</span>
        {p.next_run_at ? <span className="num text-ink-3" title={fmtDateTime(p.next_run_at)}> · {fmtDateTime(p.next_run_at)}</span> : null}
      </span>
    ) },
    { id: 'last', header: t('Ostatni', 'Last'), hide: 'lg', cell: (p) => p.last_run_id ? <Link to={'/runs/' + p.last_run_id} className="num link">#{p.last_run_id}</Link> : <span className="text-ink-3">–</span> },
    { id: 'act', header: '', align: 'right' as const, cell: (p: ScanProfile) => !p.enabled ? <span className="text-xs text-ink-3">{t('wyłączony', 'disabled')}</span> : canRun ? <Button size="sm" icon="play" onClick={(e) => { e.preventDefault(); e.stopPropagation(); setStart(p.id); }}>{t('Uruchom', 'Start')}</Button> : null },
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
          <div className="flex items-center gap-3">
            <span className="min-w-0 flex-1 truncate text-sm">{p.name}</span>
            <span className="flex-none text-xs text-ink-3">{scheduleText(p)}</span>
          </div>
        )}
      />
      {start !== null ? <StartRunDialog open onClose={() => setStart(null)} profileId={start} /> : null}
    </div>
  );
}
