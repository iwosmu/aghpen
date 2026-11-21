import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router';
import { NextSteps } from '../ui/NextSteps';
import { useQueryClient } from '@tanstack/react-query';
import { invalidate, useAction, useItem, usePage } from '../api/hooks';
import { ApiError, del, patch, post } from '../api/client';
import type { DojoExportResult, Finding, FindingStatus, Severity } from '../api/types';
import { t, plural } from '../i18n';
import { cx, fmtDateTime, fmtRelative } from '../lib/format';
import { useUrlState } from '../lib/hooks';
import { Button, Dialog, Empty, ErrorState, Field, InlineError, KV, PageHeader, Select, SkeletonRows, Tabs, TagInput, Tags } from '../ui/kit';
import { groupFindings, type FindingGroup } from '../lib/findingGroups';
import { Icon } from '../ui/Icon';
import { DataTable, FilterBar, FilterField, Pager, SearchField, type Col } from '../ui/table';
import { FINDING_STATUSES, FindingStatusMark, Glyph, InterestScore, SEVERITIES, Sev, findingStatusInfo, severityLabel } from '../ui/marks';
import { ExportButtons, InlineText, OverrideNote, useDraft } from '../ui/edit';
import { useSession } from '../session';

const FILTERS = ['q', 'status', 'severity', 'type', 'assignee', 'tag', 'exported', 'host_id', 'min_interest'];
const statusOpts = () => FINDING_STATUSES.map((s) => ({ value: s, label: findingStatusInfo(s).label }));
const sevOpts = () => SEVERITIES.map((s) => ({ value: s, label: severityLabel(s) }));

function typeLabel(x: string): string {
  const m: Record<string, [string, string]> = { signature: ['sygnatura', 'signature'], change: ['zmiana', 'change'], tls: ['certyfikat', 'certificate'], exposure: ['ekspozycja', 'exposure'], manual: ['ręczne', 'manual'], 'policy-violation': ['naruszenie reguły', 'rule violation'] };
  return m[x] ? t(m[x][0], m[x][1]) : x;
}

function DetailDialog({ id, onClose }: { id: number; onClose: () => void }) {
  const { can } = useSession();
  const canEdit = can('results:update');
  const q = useItem<Finding>('/findings/' + id);
  const save = useAction((body: Record<string, unknown>) => patch<Finding>('/findings/' + id, body), { invalidate: ['/findings', '/dashboard'], success: t('Zapisano', 'Saved') });
  const qc = useQueryClient();
  // Close first, then refresh the lists: a refetch of the deleted finding would answer 404.
  const remove = useAction(() => del('/findings/' + id), { success: t('Znalezisko usunięte', 'Finding deleted'), onSuccess: () => { onClose(); window.setTimeout(() => invalidate(qc, '/findings', '/dashboard'), 60); } });
  const f = q.data;
  return (
    <Dialog open onClose={onClose} width={720} title={f ? <span className="flex items-center gap-2"><Sev level={f.severity} compact />{f.title}</span> : t('Znalezisko', 'Finding')}
      footer={<>
        {f && can('results:delete') && f.manual ? <Button variant="danger" icon="trash" busy={remove.isPending} onClick={() => remove.mutate(undefined)}>{t('Usuń', 'Delete')}</Button> : null}
        <Button onClick={onClose}>{t('Zamknij', 'Close')}</Button>
      </>}>
      {q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : !f ? <SkeletonRows rows={6} /> : (
        <div className="space-y-4">
          <p className="text-sm text-ink-2">{f.description || t('Brak opisu.', 'No description.')}</p>
          <OverrideNote o={f.overrides?.title} canEdit={canEdit} onRevert={() => save.mutate({ title: null })} />
          <div className="grid gap-x-8 sm:grid-cols-2">
            <dl>
              <KV k={t('Status', 'Status')}>{canEdit ? <Select label={t('Status', 'Status')} value={f.status} onChange={(v) => save.mutate({ status: v })} options={statusOpts()} /> : <FindingStatusMark status={f.status} />}</KV>
              <KV k={t('Waga', 'Severity')}>
                {canEdit ? <Select label={t('Waga', 'Severity')} value={f.severity} onChange={(v) => save.mutate({ severity: v })} options={sevOpts()} /> : <Sev level={f.severity} />}
                <OverrideNote o={f.overrides?.severity} canEdit={canEdit} onRevert={() => save.mutate({ severity: null })} />
              </KV>
              <KV k={t('Przypisane do', 'Assignee')}><InlineText label={t('Przypisane do', 'Assignee')} value={f.assignee} canEdit={canEdit} placeholder={t('nikt', 'nobody')} onSave={(v) => save.mutate({ assignee: v })} /></KV>
              <KV k={t('Tagi', 'Tags')}>{canEdit ? <TagInput value={f.tags ?? []} onChange={(v) => save.mutate({ tags: v })} placeholder={t('dodaj tag', 'add a tag')} /> : <Tags tags={f.tags} max={10} />}</KV>
            </dl>
            <dl>
              <KV k={t('Adres', 'Address')} mono><Link className="link" to={f.service_id ? '/services/' + f.service_id : '/hosts/' + f.host_id} onClick={onClose}>{f.ip}{f.port ? ':' + f.port : ''}</Link></KV>
              {f.url ? <KV k="URL" mono><span className="break-all text-xs">{f.url}</span></KV> : null}
              <KV k={t('Rodzaj', 'Type')}>{typeLabel(f.type)}{f.signature?.startsWith('policy:') ? <Link to={'/rules?slug=' + encodeURIComponent(f.signature.slice(7))} className="link mono ml-2 text-xs">{t('reguła ', 'rule ')}{f.signature.slice(7)}</Link> : f.signature ? <span className="mono ml-2 text-xs text-ink-3">{f.signature}</span> : null}</KV>
              <KV k={t('Ciekawość', 'Interest')}><InterestScore value={f.interest} /></KV>
              <KV k={t('Pierwszy raz', 'First seen')}><span className="num">{fmtDateTime(f.first_seen)}</span>{f.first_run_id ? <Link to={'/runs/' + f.first_run_id} onClick={onClose} className="num link ml-2 text-xs">#{f.first_run_id}</Link> : null}</KV>
              <KV k="DefectDojo">{f.dojo_id ? <a className="link inline-flex items-center gap-1" href={f.dojo_url} target="_blank" rel="noreferrer noopener">#{f.dojo_id}<Icon name="external" size={11} /></a> : <span className="text-ink-3">{t('nie wyeksportowano', 'not exported')}</span>}</KV>
            </dl>
          </div>
          <div>
            <h3 className="label mb-1">{t('Notatka', 'Note')}</h3>
            <InlineText label={t('Notatka', 'Note')} multiline value={f.note} canEdit={canEdit} placeholder={t('brak notatki', 'no note')} onSave={(v) => save.mutate({ note: v })} />
          </div>
          {(f.evidence ?? []).length ? (
            <div>
              <h3 className="label mb-1">{t('Dowody', 'Evidence')}</h3>
              <ul className="border-t border-rule">
                {(f.evidence ?? []).map((e, i) => (
                  <li key={i} className="grid grid-cols-[80px_minmax(0,1fr)] gap-x-3 border-b border-rule py-1 text-xs sm:grid-cols-[80px_180px_minmax(0,1fr)]">
                    <span className="text-ink-3">{e.matcher}</span><span className="mono hidden text-ink-2 sm:block">{e.where}</span><span className="mono break-all">{e.snippet}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      )}
    </Dialog>
  );
}

function ManualDialog({ onClose }: { onClose: () => void }) {
  const [f, setF] = useState({ title: '', description: '', severity: 'medium' as Severity, ip: '', port: '', url: '', note: '', tags: [] as string[] });
  const create = useAction(() => post<Finding>('/findings', { ...f, port: Number(f.port) || 0 }), { invalidate: ['/findings', '/dashboard'], silent: true, success: t('Dodano znalezisko', 'Finding added'), onSuccess: onClose });
  const ipOk = !f.ip || /^\d{1,3}(\.\d{1,3}){3}$/.test(f.ip);
  return (
    <Dialog open onClose={onClose} width={560} title={t('Nowe znalezisko', 'New finding')}
      footer={<><Button onClick={onClose}>{t('Anuluj', 'Cancel')}</Button><Button variant="primary" icon="plus" busy={create.isPending} disabled={!f.title.trim() || !ipOk} onClick={() => create.mutate(undefined)}>{t('Dodaj znalezisko', 'Add finding')}</Button></>}>
      <div className="space-y-3">
        <Field label={t('Tytuł', 'Title')}><input className="field" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} autoFocus /></Field>
        <Field label={t('Opis', 'Description')}><textarea className="field" rows={3} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label={t('Waga', 'Severity')}><Select value={f.severity} onChange={(v) => setF({ ...f, severity: v as Severity })} options={sevOpts()} /></Field>
          <Field label={t('Adres IP', 'IP address')} error={ipOk ? undefined : t('błędny adres IPv4', 'invalid IPv4 address')}><input className="field mono" value={f.ip} onChange={(e) => setF({ ...f, ip: e.target.value.trim() })} placeholder="10.30.4.20" /></Field>
          <Field label={t('Port', 'Port')}><input className="field mono" inputMode="numeric" value={f.port} onChange={(e) => setF({ ...f, port: e.target.value.replace(/\D/g, '') })} placeholder="443" /></Field>
        </div>
        <Field label="URL"><input className="field mono" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} placeholder="https://" /></Field>
        <Field label={t('Tagi', 'Tags')}><TagInput value={f.tags} onChange={(v) => setF({ ...f, tags: v })} placeholder={t('dodaj tag', 'add a tag')} /></Field>
        <InlineError error={create.error} />
      </div>
    </Dialog>
  );
}

const STATUS_ORDER = ['new', 'triaged', 'accepted', 'false_positive', 'resolved'];

/** Findings grouped by what they are ("Panel administracyjny poza siecią zarządzania · 7 usług"), each expandable to its addresses. */
function FindingGroupList({ q, active, onOpen }: { q: ReturnType<typeof usePage<Finding>>; active: boolean; onOpen: (id: number) => void }) {
  const [openKeys, setOpenKeys] = useState<Set<string>>(new Set());
  const groups = useMemo(() => groupFindings(q.data?.items ?? []), [q.data]);
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!q.data) return <div className="px-4 py-3 sm:px-6"><SkeletonRows rows={8} /></div>;
  if (!groups.length) return <Empty icon="findings" title={active ? t('Żadne znalezisko nie pasuje do filtrów', 'No findings match the filters') : t('Brak otwartych znalezisk', 'No open findings')} />;
  const toggle = (k: string) => setOpenKeys((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; });
  const shown = q.data.items.length;
  return (
    <div className={cx(q.isPlaceholderData && 'opacity-60')} data-testid="finding-groups">
      <div className="hidden grid-cols-[110px_minmax(0,1fr)_minmax(0,220px)_86px] gap-x-3 border-b border-rule px-4 py-1.5 text-xs text-ink-3 sm:grid sm:px-6">
        <span>{t('Waga', 'Severity')}</span><span>{t('Znalezisko', 'Finding')}</span><span>{t('Status', 'Status')}</span><span className="text-right">{t('Ciekawość', 'Interest')}</span>
      </div>
      <ul>
        {groups.map((g: FindingGroup) => {
          const isOpen = openKeys.has(g.key) || groups.length === 1;
          const statusText = STATUS_ORDER.filter((s) => g.statuses[s]).map((s) => g.statuses[s] + ' ' + findingStatusInfo(s as FindingStatus).label).join(', ');
          return (
            <li key={g.key} className="border-b border-rule">
              <button type="button" aria-expanded={isOpen} onClick={() => toggle(g.key)} data-testid="finding-group"
                className="grid w-full grid-cols-[110px_minmax(0,1fr)] items-center gap-x-3 px-4 py-2 text-left text-sm hover:bg-raised sm:grid-cols-[110px_minmax(0,1fr)_minmax(0,220px)_86px] sm:px-6">
                <span><Sev level={g.severity} /></span>
                <span className="flex min-w-0 items-baseline gap-2">
                  <Icon name={isOpen ? 'chevronDown' : 'chevronRight'} size={12} className="flex-none self-center text-ink-3" />
                  <span className="truncate text-ink">{g.title}</span>
                  <span className="flex-none whitespace-nowrap text-ink-2">· <span className="num">{g.places}</span> {g.items.every((f) => f.port) ? plural(g.places, ['usługa', 'usługi', 'usług'], ['service', 'services']) : plural(g.places, ['adres', 'adresy', 'adresów'], ['address', 'addresses'])}</span>
                </span>
                <span className="col-start-2 truncate text-xs text-ink-2 sm:col-start-auto">{statusText}</span>
                <span className="hidden justify-self-end sm:block"><InterestScore value={g.interest} /></span>
              </button>
              {isOpen ? (
                <ul className="pb-1.5" data-testid="finding-group-items">
                  {g.items.map((f) => (
                    <li key={f.id}>
                      <button type="button" onClick={() => onOpen(f.id)} className="grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 py-1 pl-[calc(1rem+110px+0.75rem+20px)] pr-4 text-left text-sm hover:bg-raised sm:grid-cols-[minmax(0,1fr)_minmax(0,220px)_86px] sm:pr-6">
                        <span className="mono truncate text-ink-2">{f.ip}{f.port ? ':' + f.port : ''}{f.manual ? <span className="ml-1.5 font-sans text-2xs text-ink-3">{t('ręczne', 'manual')}</span> : null}</span>
                        <span className="text-xs"><FindingStatusMark status={f.status} /></span>
                        <span className="hidden justify-self-end sm:block"><InterestScore value={f.interest} /></span>
                      </button>
                    </li>
                  ))}
                </ul>
              ) : null}
            </li>
          );
        })}
      </ul>
      <p className="px-4 py-2 text-xs text-ink-3 sm:px-6">
        {t(groups.length + ' ' + plural(groups.length, ['rodzaj', 'rodzaje', 'rodzajów'], ['', '']) + ', ' + shown + ' ' + plural(shown, ['znalezisko', 'znaleziska', 'znalezisk'], ['', '']), groups.length + ' kinds, ' + shown + ' findings')}
        {q.data.total > shown ? t('; pokazano ' + shown + ' z ' + q.data.total + ' (zawęź filtry)', '; showing ' + shown + ' of ' + q.data.total + ' (narrow the filters)') : ''}.
      </p>
    </div>
  );
}

export default function Findings() {
  const u = useUrlState();
  const qc = useQueryClient();
  const { can } = useSession();
  const canEdit = can('results:update');
  const canExport = can('export:run');
  const limit = 50;
  const offset = Number(u.get('offset', '0'));
  const filters = useMemo(() => {
    const q: Record<string, string> = {};
    for (const k of FILTERS) { const v = u.get(k); if (v) q[k] = v; }
    // Default: open findings only (new and triaged); "all" shows resolved ones too.
    const st = u.get('status', 'open');
    if (st === 'all') delete q.status; else q.status = st === 'open' ? 'new,triaged' : st;
    return q;
  }, [u]);
  const view = u.get('view', 'groups');
  const q = usePage<Finding>('/findings', { ...filters, sort: u.get('sort', '-interest'), limit, offset }, view === 'list');
  // The grouped view groups every matching finding (the server caps a page at 1000).
  const gq = usePage<Finding>('/findings', { ...filters, sort: '-interest', limit: 1000 }, view === 'groups');
  const total = (view === 'groups' ? gq.data?.total : q.data?.total) ?? 0;
  const [selected, setSelected] = useState<Set<string | number>>(new Set());
  const [manual, setManual] = useState(false);
  const [assignee, setAssignee] = useState('');
  const [result, setResult] = useState<DojoExportResult | null>(null);
  const [text, setText] = useDraft(u.get('q'), (v) => u.set({ q: v }));
  const open = Number(u.get('open', '0'));
  useEffect(() => { setSelected(new Set()); }, [filters, offset]);
  const ids = [...selected].map(Number);
  const bulk = useAction(async (body: Record<string, unknown>) => { await Promise.all(ids.map((id) => patch('/findings/' + id, body))); return ids.length; }, {
    success: (n) => t('Zmieniono znalezisk: ' + n, 'Findings updated: ' + n), onSuccess: () => { invalidate(qc, '/findings', '/dashboard'); setSelected(new Set()); },
  });
  const [confirmAll, setConfirmAll] = useState(false);
  const dojoFilter = () => {
    const list = (k: string) => (u.get(k) ? u.get(k).split(',').filter(Boolean) : undefined);
    return {
      status: filters.status ? filters.status.split(',') : undefined, severity: list('severity'), type: u.get('type') || undefined, tag: u.get('tag') || undefined, q: u.get('q') || undefined,
      host_id: u.get('host_id') ? Number(u.get('host_id')) : undefined, min_interest: u.get('min_interest') ? Number(u.get('min_interest')) : undefined,
      exported: u.get('exported') ? u.get('exported') === 'true' : undefined,
    };
  };
  const exportAll = useAction(() => post<DojoExportResult>('/findings/export/defectdojo', { filter: dojoFilter() }), { silent: true, onSuccess: (r) => { setResult(r); setConfirmAll(false); invalidate(qc, '/findings'); } });
  const exportDojo = useAction(() => post<DojoExportResult>('/findings/export/defectdojo', { ids }), { silent: false, onSuccess: (r) => { setResult(r); invalidate(qc, '/findings'); setSelected(new Set()); } });
  const active = FILTERS.filter((k) => u.get(k)).length;
  const cols: Col<Finding>[] = [
    { id: 'sev', header: t('Waga', 'Severity'), sort: 'severity', width: 110, cell: (f) => <Sev level={f.severity} /> },
    { id: 'title', header: t('Znalezisko', 'Finding'), wrap: true, cell: (f) => (
      <div className="min-w-[220px] py-1">
        <div className="text-ink">{f.title}{f.manual ? <span className="ml-1.5 text-2xs text-ink-3">{t('ręczne', 'manual')}</span> : null}</div>
        <div className="mono text-xs text-ink-3">{f.ip}{f.port ? ':' + f.port : ''}</div>
      </div>
    ) },
    { id: 'status', header: t('Status', 'Status'), sort: 'status', cell: (f) => <FindingStatusMark status={f.status} /> },
    { id: 'assignee', header: t('Przypisane do', 'Assignee'), hide: 'lg', cell: (f) => f.assignee ? <span className="text-ink-2">{f.assignee.split('@')[0]}</span> : <span className="text-ink-3">–</span> },
    { id: 'tags', header: t('Tagi', 'Tags'), hide: 'xl', cell: (f) => <span className="inline-flex whitespace-nowrap"><Tags tags={f.tags} max={1} /></span> },
    { id: 'note', header: t('Notatka', 'Note'), hide: 'xl', cell: (f) => <span className="block max-w-[140px] truncate text-xs text-ink-2" title={f.note}>{f.note || '–'}</span> },
    { id: 'seen', header: t('Od', 'Since'), sort: 'first_seen', hide: 'md', cell: (f) => <span className="num text-ink-2" title={fmtDateTime(f.first_seen)}>{fmtRelative(f.first_seen)}</span> },
    { id: 'dojo', header: 'DefectDojo', hide: 'lg', cell: (f) => f.dojo_id ? <a className="num link inline-flex items-center gap-1" href={f.dojo_url} target="_blank" rel="noreferrer noopener" onClick={(e) => e.stopPropagation()}>#{f.dojo_id}<Icon name="external" size={11} /></a> : <span className="text-ink-3">–</span> },
    { id: 'interest', header: t('Ciekawość', 'Interest'), sort: 'interest', align: 'right', cell: (f) => <InterestScore value={f.interest} /> },
  ];
  return (
    <div>
      <PageHeader
        title={t('Znaleziska', 'Findings')}
        readOnly={!canEdit}
        actions={<>{canExport && total > 0 ? <Button icon="upload" onClick={() => setConfirmAll(true)} disabled={Boolean(u.get('assignee'))} title={u.get('assignee') ? t('Eksport pomija filtr „przypisane”. Usuń go albo zaznacz znaleziska.', 'The export ignores the assignee filter. Clear it or select findings.') : undefined} data-testid="dojo-export-filtered">{active ? t('Pasujące do DefectDojo', 'Export matching to DefectDojo') : t('Wszystkie do DefectDojo', 'Export all to DefectDojo')}</Button> : null}<ExportButtons kind="findings" query={filters} />{can('results:create') ? <Button variant="primary" icon="plus" onClick={() => setManual(true)}>{t('Dodaj', 'Add')}</Button> : null}</>}
      />
      <div className="px-4 pt-2 sm:px-6">
        <Tabs value={view} onChange={(v) => u.set({ view: v === 'groups' ? null : v })} tabs={[{ id: 'groups', label: t('Według rodzaju', 'By type') }, { id: 'list', label: t('Lista', 'List') }]} />
      </div>
      <FilterBar onClear={() => u.clear(FILTERS)} active={active}>
        <SearchField value={text} onChange={setText} placeholder={t('tytuł, adres, opis', 'title, address, text')} />
        <FilterField label={t('Status', 'Status')} width={170}>
          <Select value={u.get('status', 'open')} onChange={(v) => u.set({ status: v === 'open' ? null : v })} options={[{ value: 'open', label: t('otwarte (nowe i w analizie)', 'open (new and in analysis)') }, { value: 'all', label: t('wszystkie', 'all') }, ...statusOpts()]} />
        </FilterField>
        <FilterField label={t('Waga', 'Severity')} width={120}><Select value={u.get('severity')} onChange={(v) => u.set({ severity: v })} options={[{ value: '', label: t('dowolna', 'any') }, ...sevOpts()]} /></FilterField>
        <FilterField label={t('Rodzaj', 'Type')} width={130}><Select value={u.get('type')} onChange={(v) => u.set({ type: v })} options={[{ value: '', label: t('dowolny', 'any') }, ...['signature', 'exposure', 'policy-violation', 'tls', 'change', 'manual'].map((x) => ({ value: x, label: typeLabel(x) }))]} /></FilterField>
        <FilterField label="DefectDojo" width={150}><Select value={u.get('exported')} onChange={(v) => u.set({ exported: v })} options={[{ value: '', label: t('wszystkie', 'all') }, { value: 'false', label: t('niewyeksportowane', 'not exported') }, { value: 'true', label: t('wyeksportowane', 'exported') }]} /></FilterField>
      </FilterBar>
      {view === 'groups' ? (
        <FindingGroupList q={gq} active={active > 0} onOpen={(id) => u.set({ open: id }, { keepOffset: true })} />
      ) : null}
      {view === 'list' && selected.size > 0 && (canEdit || canExport) ? (
        <div className="sticky top-0 z-20 flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-rule-strong bg-accent-wash px-4 py-1.5 text-sm sm:px-6" role="region" aria-label={t('Akcje zbiorcze', 'Bulk actions')} data-testid="bulk-bar">
          <span><span className="num font-medium">{selected.size}</span> {plural(selected.size, ['zaznaczone', 'zaznaczone', 'zaznaczonych'], ['selected', 'selected'])}</span>
          {canEdit ? (
            <>
              <span className="w-[190px]"><Select label={t('Ustaw status', 'Set status')} value="" onChange={(v) => { if (v) bulk.mutate({ status: v as FindingStatus }); }} options={[{ value: '', label: t('Ustaw status…', 'Set status…') }, ...statusOpts()]} /></span>
              <span className="flex items-center gap-1.5"><input className="field w-[170px]" value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder={t('przypisz do (e-mail)', 'assign to (e-mail)')} aria-label={t('Przypisz do', 'Assign to')} /><Button size="sm" disabled={!assignee.trim()} busy={bulk.isPending} onClick={() => bulk.mutate({ assignee: assignee.trim() })}>{t('Przypisz', 'Assign')}</Button></span>
            </>
          ) : null}
          {canExport ? <Button size="sm" variant="primary" icon="upload" busy={exportDojo.isPending} onClick={() => exportDojo.mutate(undefined)}>{t('Eksportuj do DefectDojo', 'Export to DefectDojo')}</Button> : null}
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>{t('Odznacz', 'Deselect')}</Button>
        </div>
      ) : null}
      {view === 'list' ? <><DataTable
        rows={q.data?.items} cols={cols} rowKey={(f) => f.id} onRowClick={(f) => u.set({ open: f.id }, { keepOffset: true })} loading={q.isPending} error={q.error} retry={() => q.refetch()} dim={q.isPlaceholderData}
        sort={u.get('sort', '-interest')} onSort={(s) => u.set({ sort: s })}
        selected={canEdit || canExport ? selected : undefined} onSelect={canEdit || canExport ? setSelected : undefined}
        rowClass={(f) => (f.status === 'resolved' || f.status === 'false_positive' ? 'text-ink-2' : undefined)}
        empty={<Empty icon="findings" title={active ? t('Żadne znalezisko nie pasuje do filtrów', 'No findings match the filters') : t('Brak znalezisk', 'No findings yet')} action={active ? undefined : <NextSteps />} />}
        mobile={(f) => (
          <div>
            <div className="flex items-center justify-between gap-2"><Sev level={f.severity} /><FindingStatusMark status={f.status} /></div>
            <div className="mt-1 text-sm">{f.title}</div>
            <div className="mono mt-0.5 text-xs text-ink-3">{f.ip}{f.port ? ':' + f.port : ''}</div>
          </div>
        )}
      />
      {q.data ? <Pager total={q.data.total} limit={limit} offset={offset} onOffset={(o) => u.set({ offset: o || null })} /> : null}</> : null}
      {open ? <DetailDialog id={open} onClose={() => u.set({ open: null }, { keepOffset: true })} /> : null}
      {manual ? <ManualDialog onClose={() => setManual(false)} /> : null}
      <Dialog open={confirmAll} onClose={() => setConfirmAll(false)} width={460} title={t('Eksportować pasujące znaleziska?', 'Export matching findings?')}
        footer={<><Button onClick={() => setConfirmAll(false)}>{t('Anuluj', 'Cancel')}</Button><Button variant="primary" icon="upload" busy={exportAll.isPending} onClick={() => exportAll.mutate(undefined)} data-testid="dojo-export-filtered-go">{t('Eksportuj', 'Export')} {q.data?.total ?? 0}</Button></>}>
        <p className="text-sm">{active
          ? t('Do DefectDojo trafi ' + total + ' ' + plural(q.data?.total ?? 0, ['znalezisko', 'znaleziska', 'znalezisk'], ['', '']) + ' pasujących do bieżących filtrów. Te, które już tam są, zostaną zaktualizowane, nie zdublowane.', total + ' findings that match the current filters go to DefectDojo. Those already there are updated, not duplicated.')
          : t('Do DefectDojo trafią wszystkie znaleziska (' + total + '). Te, które już tam są, zostaną zaktualizowane, nie zdublowane.', 'All findings (' + total + ') go to DefectDojo. Those already there are updated, not duplicated.')}</p>
        <div className="mt-3"><InlineError error={exportAll.error} /></div>
        {exportAll.error && !(exportAll.error instanceof ApiError && exportAll.error.code === 'dojo_unconfirmed') ? <p className="mt-2 text-xs text-ink-2" data-testid="dojo-export-retry-hint">{t('Część znalezisk mogła już trafić do DefectDojo. Ponów eksport, duplikaty nie powstaną.', 'Some findings may already be in DefectDojo. Repeat the export. No duplicates are created.')}</p> : null}
      </Dialog>
      <Dialog open={result !== null} onClose={() => setResult(null)} title={t('Eksport do DefectDojo', 'Export to DefectDojo')} width={480} footer={<Button variant="primary" onClick={() => setResult(null)}>{t('Gotowe', 'Done')}</Button>}>
        {result ? (
          <div className="space-y-3 text-sm" data-testid="dojo-result">
            <p className="flex items-center gap-2"><Glyph name={result.failed ? 'delta' : 'check'} tone={result.failed ? 'changed' : 'new'} />{result.failed ? t('Eksport zakończony z błędami.', 'Export finished with errors.') : t('Eksport zakończony.', 'Export finished.')}</p>
            <dl>
              <KV k={t('Nowe w DefectDojo', 'New in DefectDojo')}><span className="num">{result.exported}</span></KV>
              <KV k={t('Zaktualizowane', 'Updated')}><span className="num">{result.updated}</span></KV>
              <KV k={t('Nieudane', 'Failed')}><span className="num">{result.failed}</span></KV>
              <KV k={t('Test', 'Test')}><a className="link inline-flex items-center gap-1" href={result.test_url} target="_blank" rel="noreferrer noopener">{t('Otwórz test', 'Open test')} #{result.test_id}<Icon name="external" size={11} /></a></KV>
            </dl>
            {(result.errors ?? []).length ? <ul className="mono text-xs text-danger">{(result.errors ?? []).map((e, i) => <li key={i}>{e}</li>)}</ul> : null}
          </div>
        ) : null}
      </Dialog>
    </div>
  );
}
