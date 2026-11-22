import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { NextSteps } from '../ui/NextSteps';
import { useAction, usePage } from '../api/hooks';
import { post } from '../api/client';
import type { Change, ScanRun } from '../api/types';
import { t, plural } from '../i18n';
import { cx, fmtDateTime, fmtRelative, show } from '../lib/format';
import { fieldLabel, fieldValue } from '../lib/fields';
import { useUrlState } from '../lib/hooks';
import { Button, Empty, LinkButton, PageHeader, Select } from '../ui/kit';
import { Icon } from '../ui/Icon';
import { DataTable, FilterBar, FilterField, Pager, SearchField, type Col } from '../ui/table';
import { CHANGE_KINDS, ChangeMark, Glyph, SEVERITIES, Sev, changeKindInfo, severityLabel } from '../ui/marks';
import { ExportButtons, useDraft } from '../ui/edit';
import { useCan } from '../session';

const FILTERS = ['q', 'run_id', 'kind', 'severity', 'acked', 'expected', 'host_id'];

export function BeforeAfter({ c }: { c: Change }) {
  // response_recovered: before is the slow answer (or none) it recovers from, not the usual time
  const before = c.kind === 'response_recovered' && c.before && typeof c.before === 'object' && 'ms' in c.before ? { ms: (c.before as { ms: number | null }).ms } : c.before;
  const b = c.field ? fieldValue(c.field, before) : show(before), a = c.field ? fieldValue(c.field, c.after) : show(c.after);
  if (!b && !a) return null;
  // never two equal values with an arrow
  if (b && a && b === a) return <span className="flex min-w-0 max-w-full items-center gap-x-1.5 overflow-hidden whitespace-nowrap text-xs">{c.field ? <span className="min-w-0 max-w-[45%] flex-none truncate text-ink-3" title={c.field}>{fieldLabel(c.field)}:</span> : null}<span className="mono min-w-0 truncate text-ink" title={a}>{a}</span></span>;
  return (
    <span className="flex min-w-0 max-w-full items-center gap-x-1.5 overflow-hidden whitespace-nowrap text-xs">
      {c.field ? <span className="min-w-0 max-w-[40%] flex-none truncate text-ink-3" title={c.field}>{fieldLabel(c.field)}:</span> : null}
      {b ? <span className="mono min-w-0 max-w-[40%] truncate text-ink-3 line-through decoration-[var(--ink-3)]" title={b}>{b}</span> : <span className="text-ink-3">{t('brak', 'none')}</span>}
      <Icon name="arrowRight" size={11} className="text-ink-3" />
      {a ? <span className="mono min-w-0 truncate text-ink" title={a}>{a}</span> : <span className="text-ink-3">{t('brak', 'none')}</span>}
    </span>
  );
}

/** The internal measures of a change, folded: small mono key/value pairs. */
export function ChangeDetail({ c, withSummary }: { c: Change; withSummary?: boolean }) {
  const entries = Object.entries(c.detail ?? {}).filter(([, v]) => v !== null && v !== undefined && v !== '');
  if (!entries.length && !(withSummary && c.summary)) return null;
  const val = (v: unknown) => (typeof v === 'object' ? JSON.stringify(v) : String(v));
  return (
    <details className="mt-0.5 text-xs open:basis-full" data-testid="change-detail">
      <summary className="cursor-pointer select-none text-ink-3 hover:text-ink-2">{t('Szczegóły', 'Details')}</summary>
      {withSummary && c.summary ? <p className="mt-1 whitespace-normal text-sm text-ink-2">{c.summary}</p> : null}
      {entries.length ? <dl className="mono mt-1 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-2xs text-ink-2">
        {entries.map(([k, v]) => <div key={k} className="contents"><dt className="text-ink-3">{k}</dt><dd className="break-all">{val(v)}</dd></div>)}
      </dl> : null}
    </details>
  );
}

export default function Changes() {
  const u = useUrlState();
  const canAck = useCan('results:update');
  const limit = 50;
  const offset = Number(u.get('offset', '0'));
  const filters = useMemo(() => {
    const q: Record<string, string> = {};
    for (const k of FILTERS) { const v = u.get(k); if (v) q[k] = v; }
    return q;
  }, [u]);
  const q = usePage<Change>('/changes', { ...filters, sort: u.get('sort', '-at'), limit, offset });
  const runs = usePage<ScanRun>('/runs', { limit: 100, status: 'completed' });
  const [selected, setSelected] = useState<Set<string | number>>(new Set());
  const [text, setText] = useDraft(u.get('q'), (v) => u.set({ q: v }));
  const ackMany = useAction((ids: number[]) => post<{ acked: number }>('/changes/ack', { ids }), {
    invalidate: ['/changes', '/dashboard'], onSuccess: () => setSelected(new Set()),
    success: (r) => t('Przejrzane zmiany: ' + r.acked, 'Changes reviewed: ' + r.acked),
  });
  const ackOne = useAction((id: number) => post('/changes/' + id + '/ack'), { invalidate: ['/changes', '/dashboard'] });
  const active = FILTERS.filter((k) => u.get(k)).length;
  const rows = q.data?.items;
  // grouped by run, the group heading already says when; the column would repeat it
  const grouped = u.get('sort', '-at').endsWith('at');
  const cols: Col<Change>[] = [
    { id: 'kind', header: t('Rodzaj', 'Type'), cell: (c) => <span className="flex max-w-[clamp(140px,14vw,230px)]" title={changeKindInfo(c.kind).label}><ChangeMark kind={c.kind} expected={c.expected} plain /></span> },
    { id: 'addr', header: t('Adres', 'Address'), sort: 'ip', cell: (c) => <Link to={c.service_id ? '/services/' + c.service_id : '/hosts/' + c.host_id} className="mono link">{c.ip}{c.port ? ':' + c.port : ''}</Link> },
    { id: 'what', header: t('Przed → po', 'Before → after'), wrap: true, cell: (c) => (
      <div className={cx('flex min-w-0', grouped ? 'w-[clamp(170px,calc(100vw-1120px),560px)]' : 'w-[clamp(150px,calc(100vw-1250px),440px)]', 'flex-wrap items-baseline gap-x-3 py-1.5')} title={c.summary}><BeforeAfter c={c} /><ChangeDetail c={c} withSummary /></div>
    ) },
    { id: 'sev', header: t('Waga', 'Severity'), sort: 'severity', hide: 'md', cell: (c) => c.expected ? <span className="text-xs text-ink-3">{t('oczekiwana', 'expected')}</span> : <Sev level={c.severity} /> },
    { id: 'at', header: t('Kiedy', 'When'), sort: 'at', hide: 'xl', cell: (c) => <span className="num text-ink-2" title={fmtDateTime(c.at)}>{fmtRelative(c.at)}</span> },
    { id: 'ack', header: t('Przejrzana', 'Reviewed'), cell: (c) => c.acked_at
      ? <span className="inline-flex items-center gap-1.5 text-xs text-ink-2" title={fmtDateTime(c.acked_at)}><Icon name="check" size={12} className="text-st-new" />{c.acked_by.split('@')[0]}</span>
      : canAck ? <Button size="sm" onClick={(e) => { e.stopPropagation(); e.preventDefault(); ackOne.mutate(c.id); }}>{t('Oznacz', 'Mark')}</Button> : <span className="text-xs text-ink-3">{t('nie', 'no')}</span> },
  ];
  const shown = grouped ? cols.filter((c) => c.id !== 'at') : cols;
  return (
    <div>
      <PageHeader
        title={t('Zmiany', 'Changes')}
        readOnly={!canAck}
        actions={<><ExportButtons kind="changes" query={filters} /><LinkButton to="/changes/compare" icon="compare">{t('Porównaj dwa skany', 'Compare two scans')}</LinkButton></>}
      />
      <div className="flex items-center gap-2 overflow-x-auto px-4 pb-4 [scrollbar-width:none] sm:flex-wrap sm:overflow-visible sm:px-6 lg:px-8" role="group" aria-label={t('Szybkie filtry', 'Quick filters')} data-testid="change-quick">
        {(['service_gone', 'host_missing', 'service_unreachable', 'service_returned', 'service_new', 'response_slower', 'response_recovered'] as const).map((k) => {
          const i = changeKindInfo(k);
          const on = u.get('kind') === k;
          return (
            <button key={k} type="button" aria-pressed={on} onClick={() => u.set({ kind: on ? null : k })}
              className={cx('inline-flex h-[28px] flex-none items-center gap-2 whitespace-nowrap rounded-[6px] pl-2.5 text-xs transition-colors duration-150 ease-[var(--ease)]', on ? 'bg-raised pr-2 text-ink shadow-[inset_0_0_0_1px_var(--rule-strong)]' : 'pr-3 text-ink-2 shadow-[inset_0_0_0_1px_var(--rule)] hover:bg-[var(--row-hover)] hover:text-ink')}>
              <Glyph name={i.glyph} tone={i.tone} size={12} />{i.label}{on ? <Icon name="x" size={12} className="ml-0.5" /> : null}
            </button>
          );
        })}
      </div>
      <FilterBar onClear={() => u.clear(FILTERS)} active={active} moreActive={['run_id', 'kind', 'severity', 'expected', 'acked'].filter((k) => u.get(k)).length} more={<>
        <FilterField label={t('Skan', 'Scan')} width={150}>
          <Select value={u.get('run_id')} onChange={(v) => u.set({ run_id: v })} options={[{ value: '', label: t('wszystkie', 'all') }, ...(runs.data?.items ?? []).map((r) => ({ value: String(r.id), label: '#' + r.id + ' · ' + fmtDateTime(r.finished_at).slice(0, 10) }))]} />
        </FilterField>
        <FilterField label={t('Rodzaj', 'Type')} width={200}>
          <Select value={u.get('kind')} onChange={(v) => u.set({ kind: v })} options={[{ value: '', label: t('wszystkie', 'all') }, ...CHANGE_KINDS.map((k) => ({ value: k, label: changeKindInfo(k).label }))]} />
        </FilterField>
        <FilterField label={t('Waga', 'Severity')} width={120}>
          <Select value={u.get('severity')} onChange={(v) => u.set({ severity: v })} options={[{ value: '', label: t('dowolna', 'any') }, ...SEVERITIES.map((s) => ({ value: s, label: severityLabel(s) }))]} />
        </FilterField>
        <FilterField label={t('Oczekiwane', 'Expected')} width={150}>
          <Select value={u.get('expected')} onChange={(v) => u.set({ expected: v })} options={[{ value: '', label: t('pokaż wszystkie', 'show all') }, { value: 'false', label: t('ukryj oczekiwane', 'hide expected') }, { value: 'true', label: t('tylko oczekiwane', 'expected only') }]} />
        </FilterField>
        <FilterField label={t('Przejrzane', 'Reviewed')} width={140}>
          <Select value={u.get('acked')} onChange={(v) => u.set({ acked: v })} options={[{ value: '', label: t('wszystkie', 'all') }, { value: 'false', label: t('nieprzejrzane', 'not reviewed') }, { value: 'true', label: t('przejrzane', 'reviewed') }]} />
        </FilterField>
      </>}>
        <SearchField value={text} onChange={setText} placeholder={t('adres albo opis', 'address or text')} />
      </FilterBar>
      {canAck && selected.size > 0 ? (
        <div className="sticky top-0 z-20 flex flex-wrap items-center gap-3 border-b border-rule-strong bg-raised px-4 py-1.5 text-sm sm:px-6" role="region" aria-label={t('Akcje zbiorcze', 'Bulk actions')}>
          <span><span className="num font-medium">{selected.size}</span> {plural(selected.size, ['zaznaczona zmiana', 'zaznaczone zmiany', 'zaznaczonych zmian'], ['change selected', 'changes selected'])}</span>
          <Button size="sm" variant="primary" icon="check" busy={ackMany.isPending} onClick={() => ackMany.mutate([...selected].map(Number))}>{t('Oznacz jako przejrzane', 'Mark as reviewed')}</Button>
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>{t('Odznacz', 'Deselect')}</Button>
        </div>
      ) : null}
      <DataTable
        rows={rows} cols={shown} rowKey={(c) => c.id} loading={q.isPending} error={q.error} retry={() => q.refetch()} dim={q.isPlaceholderData}
        sort={u.get('sort', '-at')} onSort={(s) => u.set({ sort: s })}
        selected={canAck ? selected : undefined} onSelect={canAck ? setSelected : undefined}
        rowClass={(c) => cx(c.acked_at && 'opacity-70')}
        groupNote={(rows) => { const n = rows.filter((c) => !c.expected).length; return n < rows.length ? <span className="text-ink-3">, {t('w tym', 'of which')} <span className="num text-ink-2">{n}</span> {plural(n, ['nieoczekiwana', 'nieoczekiwane', 'nieoczekiwanych'], ['unexpected', 'unexpected'])}</span> : null; }}
        group={u.get('sort', '-at').endsWith('at') ? (c) => ({ key: String(c.run_id), label: <><Link to={'/runs/' + c.run_id} className="link">{t('Skan', 'Scan')} #{c.run_id}</Link><span className="text-ink-3"> · </span><span>{fmtRelative(c.at)}</span></> }) : undefined}
        empty={<Empty icon="changes" title={active ? t('Żadna zmiana nie pasuje do filtrów', 'No changes match the filters') : t('Brak zmian', 'No changes yet')} hint={active ? undefined : t('Zmiany pojawią się po drugim skanie', 'Changes appear after the second scan')} action={active ? undefined : <NextSteps />} />}
        mobile={(c) => (
          <div>
            <div className="flex items-center justify-between gap-2"><ChangeMark kind={c.kind} expected={c.expected} /><span className="mono truncate text-xs text-ink-2">{c.ip}{c.port ? ':' + c.port : ''}</span></div>
            <div className="mt-0.5 min-w-0 overflow-hidden"><BeforeAfter c={c} /></div>
          </div>
        )}
      />
      {q.data ? <Pager total={q.data.total} limit={limit} offset={offset} onOffset={(o) => u.set({ offset: o || null })} /> : null}
          </div>
  );
}
