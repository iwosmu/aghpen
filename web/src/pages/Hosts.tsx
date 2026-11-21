import { useEffect, useMemo, useRef, type ReactNode } from 'react';
import { Link, useNavigate } from 'react-router';
import { NextSteps } from '../ui/NextSteps';
import { useInfiniteQuery } from '@tanstack/react-query';
import { useVirtualizer } from '@tanstack/react-virtual';
import { get } from '../api/client';
import { useItem, usePage } from '../api/hooks';
import type { Host, NameCount, Page, Scope } from '../api/types';
import { t, plural } from '../i18n';
import { cx, fmtDateTime, fmtInt, fmtRelative } from '../lib/format';
import { useUrlState, useWidth } from '../lib/hooks';
import { Empty, ErrorState, PageHeader, Select, SkeletonRows, Spinner, Tags } from '../ui/kit';
import { Icon } from '../ui/Icon';
import { FilterBar, FilterField, SearchField } from '../ui/table';
import { HOST_STATUSES, HostStatusMark, InterestScore, hostStatusInfo } from '../ui/marks';
import { ExportButtons, useDraft } from '../ui/edit';
import { useCan } from '../session';

const PAGE = 500;
const FILTERS = ['q', 'status', 'scope_id', 'tag', 'tech', 'port', 'min_interest', 'cidr'];

interface VCol { id: string; header: string; width: string; min: number; sort?: string; align?: 'right'; cell: (h: Host) => ReactNode }

export default function Hosts() {
  const u = useUrlState();
  const navigate = useNavigate();
  const canEdit = useCan('results:update');
  const query = useMemo(() => {
    const q: Record<string, string> = {};
    for (const k of FILTERS) { const v = u.get(k); if (v) q[k] = v; }
    q.sort = u.get('sort', '-interest');
    return q;
  }, [u]);
  const inf = useInfiniteQuery<Page<Host>>({
    queryKey: ['/hosts', query, 'infinite'],
    queryFn: ({ pageParam }) => get<Page<Host>>('/hosts', { ...query, limit: PAGE, offset: pageParam as number }),
    initialPageParam: 0,
    getNextPageParam: (last) => (last.offset + last.items.length < last.total ? last.offset + last.limit : undefined),
  });
  const scopes = usePage<Scope>('/scopes', { limit: 200 });
  const tags = useItem<NameCount[]>('/tags');
  const rows = useMemo(() => inf.data?.pages.flatMap((p) => p.items) ?? [], [inf.data]);
  const total = inf.data?.pages[0]?.total ?? 0;

  const [q, setQ] = useDraft(u.get('q'), (v) => u.set({ q: v }));
  const [cidr, setCidr] = useDraft(u.get('cidr'), (v) => u.set({ cidr: v }));
  const [tech, setTech] = useDraft(u.get('tech'), (v) => u.set({ tech: v }));
  const [port, setPort] = useDraft(u.get('port'), (v) => u.set({ port: v.replace(/\D/g, '') }));

  const [wrapRef, width] = useWidth<HTMLDivElement>();
  const scrollRef = useRef<HTMLDivElement>(null);
  const narrow = width > 0 && width < 640;
  const rowH = narrow ? 58 : 30;
  // TanStack Virtual keeps its own mutable state; the component is not memoised by the compiler.
  const virt = useVirtualizer({ count: rows.length, getScrollElement: () => scrollRef.current, estimateSize: () => rowH, overscan: 14 });
  const items = virt.getVirtualItems();
  const lastIndex = items.length ? items[items.length - 1].index : 0;
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = inf;
  useEffect(() => {
    if (hasNextPage && !isFetchingNextPage && lastIndex >= rows.length - 60) void fetchNextPage();
  }, [lastIndex, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage]);
  useEffect(() => { virt.measure(); }, [rowH]); // eslint-disable-line react-hooks/exhaustive-deps

  const allCols: VCol[] = [
    { id: 'status', header: t('Stan', 'Status'), width: '168px', min: 0, cell: (h) => <HostStatusMark status={h.status} /> },
    { id: 'ip', header: 'IP', width: '124px', min: 0, sort: 'ip', cell: (h) => <span className="mono">{h.ip}</span> },
    { id: 'name', header: t('Nazwa / etykieta', 'Name / label'), width: 'minmax(160px, 1.4fr)', min: 0, cell: (h) => (
      <span className="block truncate">
        {h.label ? <span className="text-ink">{h.label}</span> : null}
        {h.label && h.hostnames?.length ? <span className="text-ink-3"> · </span> : null}
        <span className={cx('mono', h.label ? 'text-ink-3' : 'text-ink-2')}>{h.hostnames?.[0] ?? (h.label ? '' : '–')}</span>
      </span>
    ) },
    { id: 'ports', header: t('Otwarte porty', 'Open ports'), width: 'minmax(120px, 1fr)', min: 900, sort: 'service_count', cell: (h) => <span className="mono block truncate text-ink-2">{(h.open_ports ?? []).join(' ') || '–'}</span> },
    { id: 'tech', header: t('Technologie', 'Technologies'), width: 'minmax(140px, 1.2fr)', min: 1080, cell: (h) => <span className="block truncate text-ink-2">{(h.technologies ?? []).join(', ') || '–'}</span> },
    { id: 'tags', header: t('Tagi', 'Tags'), width: '150px', min: 1320, cell: (h) => <Tags tags={h.tags} max={2} /> },
    { id: 'palive', header: 'p_alive', width: '62px', min: 760, sort: 'p_alive', align: 'right', cell: (h) => <span className="num text-ink-2">{h.p_alive.toFixed(2)}</span> },
    { id: 'seen', header: t('Ostatnio widziany', 'Last seen'), width: '128px', min: 700, sort: 'last_seen', cell: (h) => <span className="num text-ink-2" title={fmtDateTime(h.last_seen)}>{fmtRelative(h.last_seen)}</span> },
    { id: 'interest', header: t('Ciekawość', 'Interest'), width: '86px', min: 0, sort: 'interest', align: 'right', cell: (h) => <InterestScore value={h.interest} /> },
  ];
  const cols = allCols.filter((c) => width === 0 || width >= c.min);
  const grid = cols.map((c) => c.width).join(' ');
  const sort = u.get('sort', '-interest');
  const active = FILTERS.filter((k) => u.get(k)).length;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader
        title={t('Hosty', 'Hosts')}
        sub={inf.data ? <><span className="num text-ink">{fmtInt(total)}</span> {plural(total, ['host', 'hosty', 'hostów'], ['host', 'hosts'])}{active ? t(' po filtrach', ' after filters') : t(' w inwentarzu', ' in the inventory')}</> : t('Wczytywanie…', 'Loading…')}
        readOnly={!canEdit}
        actions={<ExportButtons kind="hosts" query={query} />}
      />
      <FilterBar onClear={() => u.clear(FILTERS)} active={active}>
        <SearchField value={q} onChange={setQ} placeholder={t('IP, nazwa, etykieta', 'IP, name, label')} width={200} />
        <FilterField label={t('Stan', 'Status')} width={150}>
          <Select value={u.get('status')} onChange={(v) => u.set({ status: v })} options={[{ value: '', label: t('wszystkie', 'all') }, ...HOST_STATUSES.map((s) => ({ value: s, label: hostStatusInfo(s).label }))]} />
        </FilterField>
        <FilterField label={t('Zakres', 'Scope')} width={160}>
          <Select value={u.get('scope_id')} onChange={(v) => u.set({ scope_id: v })} options={[{ value: '', label: t('wszystkie', 'all') }, ...(scopes.data?.items ?? []).map((s) => ({ value: String(s.id), label: s.name }))]} />
        </FilterField>
        <FilterField label={t('Tag', 'Tag')} width={120}>
          <Select value={u.get('tag')} onChange={(v) => u.set({ tag: v })} options={[{ value: '', label: t('dowolny', 'any') }, ...(tags.data ?? []).map((x) => ({ value: x.name, label: x.name + ' (' + x.count + ')' }))]} />
        </FilterField>
        <FilterField label={t('Technologia', 'Technology')} width={120}><input className="field" value={tech} onChange={(e) => setTech(e.target.value)} placeholder="WordPress" /></FilterField>
        <FilterField label={t('Port', 'Port')} width={64}><input className="field mono" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} placeholder="443" /></FilterField>
        <FilterField label="CIDR" width={136}><input className="field mono" value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="10.20.4.0/24" /></FilterField>
        <FilterField label={t('Ciekawość od', 'Interest from')} width={96}>
          <Select value={u.get('min_interest')} onChange={(v) => u.set({ min_interest: v })} options={[{ value: '', label: '0' }, { value: '25', label: '25' }, { value: '50', label: '50' }, { value: '75', label: '75' }]} />
        </FilterField>
      </FilterBar>

      <div ref={wrapRef} className="flex min-h-0 flex-1 flex-col">
        {inf.error ? <ErrorState error={inf.error} retry={() => inf.refetch()} /> : inf.isPending ? <SkeletonRows rows={14} /> : rows.length === 0 ? (
          <Empty icon="hosts" title={active ? t('Żaden host nie pasuje do filtrów', 'No host matches the filters') : t('Inwentarz jest pusty', 'The inventory is empty')}
            hint={active ? t('Zmień albo wyczyść filtry.', 'Change or clear the filters.') : t('Hosty pojawią się po pierwszym skanie albo po imporcie wyników.', 'Hosts appear after the first scan or after an import of results.')}
            action={active ? undefined : <NextSteps />} />
        ) : (
          <>
            {!narrow ? (
              <div className="grid h-[30px] flex-none items-center gap-x-3 border-b border-rule-strong bg-panel px-4 text-xs font-medium text-ink-3 sm:px-6" style={{ gridTemplateColumns: grid }} role="row">
                {cols.map((c) => {
                  const dir = sort === c.sort ? 'asc' : sort === '-' + c.sort ? 'desc' : null;
                  return c.sort ? (
                    <button key={c.id} type="button" role="columnheader" aria-sort={dir === 'asc' ? 'ascending' : dir === 'desc' ? 'descending' : 'none'}
                      className={cx('flex items-center gap-1 text-left hover:text-ink', c.align === 'right' && 'justify-end', dir && 'text-ink')}
                      onClick={() => u.set({ sort: dir === 'desc' ? c.sort! : '-' + c.sort })}>
                      {c.header}{dir ? <Icon name={dir === 'asc' ? 'chevronUp' : 'chevronDown'} size={11} /> : null}
                    </button>
                  ) : <span key={c.id} role="columnheader" className={c.align === 'right' ? 'text-right' : ''}>{c.header}</span>;
                })}
              </div>
            ) : null}
            <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto" style={{ height: 'max(320px, calc(100dvh - 300px))' }} role="table" aria-rowcount={total} aria-label={t('Hosty', 'Hosts')} data-testid="hosts-scroll">
              <div style={{ height: virt.getTotalSize(), position: 'relative' }}>
                {items.map((vi) => {
                  const h = rows[vi.index];
                  return (
                    <Link
                      key={h.id} to={'/hosts/' + h.id} role="row" aria-rowindex={vi.index + 1}
                      onKeyDown={(e) => { if (e.key === 'Enter') navigate('/hosts/' + h.id); }}
                      className={cx('absolute left-0 right-0 border-b border-rule px-4 text-sm outline-offset-[-2px] hover:bg-raised sm:px-6', narrow ? 'flex flex-col justify-center' : 'grid items-center gap-x-3', (h.status === 'down' || h.status === 'expected-offline') && 'text-ink-2')}
                      style={{ top: vi.start, height: rowH, gridTemplateColumns: narrow ? undefined : grid }}
                    >
                      {narrow ? (
                        <>
                          <span className="flex items-center justify-between gap-2"><span className="mono text-sm text-ink">{h.ip}</span><InterestScore value={h.interest} /></span>
                          <span className="flex items-center justify-between gap-2 text-xs"><span className="truncate text-ink-2">{h.label || h.hostnames?.[0] || (h.open_ports ?? []).join(' ') || '–'}</span><span className="flex-none"><HostStatusMark status={h.status} /></span></span>
                        </>
                      ) : cols.map((c) => <span key={c.id} role="cell" className={cx('min-w-0 whitespace-nowrap', c.align === 'right' && 'flex justify-end')}>{c.cell(h)}</span>)}
                    </Link>
                  );
                })}
              </div>
            </div>
            <div className="flex h-[30px] flex-none items-center justify-between gap-3 border-t border-rule px-4 text-xs text-ink-3 sm:px-6">
              <span>{t('Wczytano', 'Loaded')} <span className="num text-ink-2">{fmtInt(rows.length)}</span> {t('z', 'of')} <span className="num text-ink-2">{fmtInt(total)}</span>{t('. Lista rysuje tylko widoczne wiersze.', '. The list draws only the visible rows.')}</span>
              {isFetchingNextPage ? <span className="inline-flex items-center gap-1.5"><Spinner />{t('kolejna porcja', 'next batch')}</span> : null}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
