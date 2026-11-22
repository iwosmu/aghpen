import { useMemo } from 'react';
import { Link } from 'react-router';
import { NextSteps } from '../ui/NextSteps';
import { useItem, usePage } from '../api/hooks';
import type { Dashboard, NameCount, Service, ServiceGroup } from '../api/types';
import { t } from '../i18n';
import { cx, fmtInt } from '../lib/format';
import { useUrlState } from '../lib/hooks';
import { Chip, Empty, ErrorState, PageHeader, Select, SkeletonRows, Tabs } from '../ui/kit';
import { DataTable, FilterBar, FilterField, Pager, SearchField, type Col } from '../ui/table';
import { ClassChips, InterestScore, SERVICE_CLASSES, classLabel } from '../ui/marks';
import { ExportButtons, useDraft } from '../ui/edit';
import { useCan } from '../session';
import { serviceName, isSelf } from '../lib/serviceName';
import { SelfTag } from '../ui/serviceBits';
import { ProductValue } from '../ui/ProductValue';
import { productLine, shownProduct } from '../lib/shownProduct';

const FILTERS = ['q', 'state', 'port', 'name', 'tech', 'class', 'tag', 'min_interest', 'tls', 'group_key', 'host_id', 'run_id'];

/** how many technology chips fit the column: two short ones, else one */
const svcTechFit = (s: Service) => { const xs = (s.technologies ?? []).map((x) => x.name + (x.version && (x.name + x.version).length <= 16 ? ' ' + x.version : '')); return xs.length > 1 && xs[0].length + xs[1].length <= 22 ? 2 : 1; };

/** The fingerprint overview: technologies and open ports ranked by how many services carry them. A click filters the list. */
function TechRanking() {
  const q = useItem<Dashboard>('/dashboard', undefined, { staleTime: 60_000 });
  const u = useUrlState();
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!q.data) return <div className="px-4 sm:px-6 lg:px-8"><SkeletonRows rows={8} /></div>;
  const list = (title: string, items: NameCount[], set: (name: string) => Record<string, string | null>, mono?: boolean, testId?: string) => (
    <section className="min-w-0">
      <h2 className="caps mb-1">{title}</h2>
      <ul className="divide-y divide-rule" data-testid={testId}>
        {items.map((i) => (
          <li key={i.name}>
            <button type="button" className="-mx-2 flex h-[36px] w-[calc(100%+16px)] items-center gap-3 rounded-[6px] px-2 text-left text-sm hover:bg-[var(--row-hover)]" onClick={() => u.set({ view: null, offset: null, ...set(i.name) })}>
              <span className={cx('min-w-0 flex-1 truncate text-ink', mono && 'mono')}>{i.name}</span>
              <span className="num flex-none text-ink-2">{fmtInt(i.count)}</span>
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
  return (
    <div className="grid gap-x-12 gap-y-8 px-4 pb-6 sm:px-6 md:grid-cols-2 lg:px-8">
      {list(t('Technologie', 'Technologies'), q.data.technologies ?? [], (n) => ({ tech: n }), false, 'tech-ranking')}
      {list(t('Porty', 'Ports'), q.data.ports ?? [], (n) => ({ port: n }), true, 'port-ranking')}
    </div>
  );
}

export default function Services() {
  const u = useUrlState();
  const canEdit = useCan('results:update');
  const view = u.get('view', 'list');
  const limit = 50;
  const offset = Number(u.get('offset', '0'));
  const filters = useMemo(() => {
    const q: Record<string, string> = {};
    for (const k of FILTERS) { const v = u.get(k); if (v) q[k] = v; }
    // Default: open services only. "all" shows gone ones too, below the live ones.
    const st = u.get('state', 'open');
    if (st === 'all') delete q.state; else q.state = st;
    return q;
  }, [u]);
  const state = u.get('state', 'open');
  const sortSv = u.get('sort', '-interest');
  const list = usePage<Service>('/services', { ...filters, sort: state === 'all' && /interest/.test(sortSv) ? '-state,' + sortSv : sortSv, limit, offset }, view === 'list');
  const groups = usePage<ServiceGroup>('/service-groups', { ...filters, sort: u.get('gsort', '-count'), limit, offset }, view === 'groups');
  const [q, setQ] = useDraft(u.get('q'), (v) => u.set({ q: v }));
  const [tech, setTech] = useDraft(u.get('tech'), (v) => u.set({ tech: v }));
  const [port, setPort] = useDraft(u.get('port'), (v) => u.set({ port: v.replace(/\D/g, '') }));
  const active = FILTERS.filter((k) => u.get(k)).length;

  const cols: Col<Service>[] = [
    { id: 'addr', header: t('Adres', 'Address'), sort: 'ip', cell: (s) => <span className="whitespace-nowrap"><Link to={'/services/' + s.id} className="mono link">{s.ip}:{s.port}</Link>{s.tls ? <span className="ml-1.5 text-2xs text-ink-3">TLS</span> : null}{isSelf(s) ? <SelfTag /> : null}</span> },
    { id: 'title', header: t('Tytuł / produkt', 'Title / product'), cell: (s) => (
      <span className="block max-w-[340px] truncate text-ink" title={s.title}>{s.title || <span className="text-ink-2">{productLine(shownProduct(s)) ? <ProductValue s={s} /> : serviceName(s)}</span>}
        {s.overrides && Object.keys(s.overrides).length ? <span className="ml-1.5 text-2xs text-st-changed" title={t('wartość poprawiona przez analityka', 'value corrected by an analyst')}>{t('poprawione', 'edited')}</span> : null}</span>
    ) },
    { id: 'tech', header: t('Technologie', 'Technologies'), hide: 'md', cell: (s) => (s.technologies ?? []).length ? <span className="flex max-w-[230px] gap-1 overflow-hidden" title={(s.technologies ?? []).map((x) => x.name + (x.version ? ' ' + x.version : '')).join(', ')}>{(s.technologies ?? []).slice(0, Math.min(2, svcTechFit(s))).map((x) => <span key={x.name} className="chip-fact max-w-[170px]"><span className="truncate">{x.name}{x.version && (x.name + x.version).length <= 16 ? ' ' + x.version : ''}</span></span>)}{(s.technologies ?? []).length > Math.min(2, svcTechFit(s)) ? <span className="chip-fact num">+{(s.technologies ?? []).length - Math.min(2, svcTechFit(s))}</span> : null}</span> : <span className="text-ink-3">–</span> },
    { id: 'class', header: t('Klasy', 'Classes'), hide: 'lg', cell: (s) => <span className="inline-flex whitespace-nowrap"><ClassChips classes={s.classes} max={1} /></span> },
    { id: 'interest', header: t('Ciekawość', 'Interest'), sort: 'interest', align: 'right', cell: (s) => <InterestScore value={s.interest} reasons={s.interest_why} /> },
  ];
  const gcols: Col<ServiceGroup>[] = [
    { id: 'label', header: t('Grupa', 'Group'), cell: (g) => <Link to={'/services?group_key=' + encodeURIComponent(g.key)} className="link font-medium">{g.label}</Link> },
    { id: 'count', header: t('Usługi', 'Services'), sort: 'count', align: 'right', width: 90, cell: (g) => <span className="num">{fmtInt(g.count)}</span> },
    { id: 'title', header: t('Tytuł strony', 'Page title'), cell: (g) => <span className="block max-w-[380px] truncate text-ink-2">{g.title || '–'}</span> },
    { id: 'tech', header: t('Technologie', 'Technologies'), hide: 'md', cell: (g) => <span className="block max-w-[320px] truncate text-ink-2">{(g.technologies ?? []).join(', ') || '–'}</span> },
    { id: 'key', header: t('Klucz', 'Key'), hide: 'xl', cell: (g) => <span className="mono text-xs text-ink-3">{g.key.slice(0, 12)}</span> },
    { id: 'interest', header: t('Najwyższa ciekawość', 'Top interest'), sort: 'interest', align: 'right', cell: (g) => <InterestScore value={g.interest} /> },
  ];
  const total = view === 'list' ? list.data?.total : groups.data?.total;
  return (
    <div>
      <PageHeader
        title={t('Usługi', 'Services')}
        readOnly={!canEdit}
        actions={view === 'list' ? <ExportButtons kind="services" query={filters} /> : null}
        sub={total !== undefined && view !== 'tech' ? <span className="num">{fmtInt(total)}</span> : null}
      />
      <div className="px-4 pb-3 sm:px-6 lg:px-8">
        <Tabs value={view} onChange={(v) => u.set({ view: v === 'list' ? null : v })} tabs={[{ id: 'list', label: t('Lista', 'List') }, { id: 'groups', label: t('Grupy', 'Groups') }, { id: 'tech', label: t('Technologie', 'Technologies') }]} />
      </div>
      {view === 'tech' ? <TechRanking /> : <>
      <FilterBar onClear={() => u.clear(FILTERS)} active={active} moreActive={['class', 'tech', 'port', 'name', 'tls', 'min_interest'].filter((k) => u.get(k)).length} more={<>
        <FilterField label={t('Klasa', 'Class')} width={170}>
          <Select value={u.get('class')} onChange={(v) => u.set({ class: v })} options={[{ value: '', label: t('dowolna', 'any') }, ...SERVICE_CLASSES.map((c) => ({ value: c, label: classLabel(c) }))]} />
        </FilterField>
        <FilterField label={t('Technologia', 'Technology')} width={140}><input className="field" value={tech} onChange={(e) => setTech(e.target.value)} placeholder="Jenkins" /></FilterField>
        <FilterField label={t('Port', 'Port')} width={76}><input className="field mono" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} placeholder="8080" /></FilterField>
        <FilterField label={t('Protokół', 'Protocol')} width={110}>
          <Select value={u.get('name')} onChange={(v) => u.set({ name: v })} options={[{ value: '', label: t('dowolny', 'any') }, ...['http', 'ssh', 'mysql', 'postgresql', 'redis', 'rtsp', 'ipp', 'smtp', 'ms-wbt-server'].map((n) => ({ value: n, label: n }))]} />
        </FilterField>
        <FilterField label="TLS" width={90}>
          <Select value={u.get('tls')} onChange={(v) => u.set({ tls: v })} options={[{ value: '', label: t('dowolnie', 'any') }, { value: 'true', label: t('tak', 'yes') }, { value: 'false', label: t('nie', 'no') }]} />
        </FilterField>
        <FilterField label={t('Ciekawość od', 'Interest from')} width={110}>
          <Select value={u.get('min_interest')} onChange={(v) => u.set({ min_interest: v })} options={[{ value: '', label: '0' }, { value: '25', label: '25' }, { value: '50', label: '50' }, { value: '75', label: '75' }]} />
        </FilterField>
      </>}>
        <SearchField value={q} onChange={setQ} placeholder={t('adres, tytuł, produkt, technologia', 'address, title, product, technology')} width={250} />
        <FilterField label={t('Stan', 'Status')} width={120}>
          <Select value={state} onChange={(v) => u.set({ state: v === 'open' ? null : v })} options={[{ value: 'open', label: t('otwarte', 'open') }, { value: 'all', label: t('wszystkie', 'all') }, { value: 'gone', label: t('zniknęły', 'gone') }, { value: 'filtered', label: t('filtrowane', 'filtered') }]} />
        </FilterField>
      </FilterBar>
      {u.get('group_key') || u.get('host_id') || u.get('tag') || u.get('run_id') ? (
        <div className="flex flex-wrap items-center gap-2 border-b border-rule px-4 py-1.5 text-xs text-ink-2 sm:px-6">
          {u.get('group_key') ? <Chip tone="accent" onRemove={() => u.set({ group_key: null })}>{t('grupa', 'group')} <span className="mono">{u.get('group_key').slice(0, 12)}</span></Chip> : null}
          {u.get('host_id') ? <Chip tone="accent" onRemove={() => u.set({ host_id: null })}>{t('host', 'host')} #{u.get('host_id')}</Chip> : null}
          {u.get('run_id') ? <Chip tone="accent" onRemove={() => u.set({ run_id: null })}>{t('skan', 'scan')} #{u.get('run_id')}</Chip> : null}
          {u.get('tag') ? <Chip tone="accent" onRemove={() => u.set({ tag: null })}>{t('tag', 'tag')} {u.get('tag')}</Chip> : null}
        </div>
      ) : null}
      {view === 'list' ? (
        <DataTable
          rows={list.data?.items} cols={cols} rowKey={(s) => s.id} rowHref={(s) => '/services/' + s.id} loading={list.isPending} error={list.error} retry={() => list.refetch()} dim={list.isPlaceholderData}
          sort={u.get('sort', '-interest')} onSort={(s) => u.set({ sort: s })} rowClass={(s) => (s.state === 'gone' ? 'text-ink-3' : undefined)}
          empty={<Empty icon="services" title={active ? t('Żadna usługa nie pasuje do filtrów', 'No services match the filters') : t('Brak usług', 'No services yet')} action={active ? undefined : <NextSteps />} />}
          mobile={(s) => (
            <div className="flex items-center gap-3">
              <span className="mono flex-none text-sm">{s.ip}:{s.port}</span>
              <span className="min-w-0 flex-1 truncate text-sm text-ink-2">{s.title || productLine(shownProduct(s)) || serviceName(s)}</span>
              <InterestScore value={s.interest} />
            </div>
          )}
        />
      ) : (
        <DataTable
          rows={groups.data?.items} cols={gcols} rowKey={(g) => g.key} rowHref={(g) => '/services?group_key=' + encodeURIComponent(g.key)} loading={groups.isPending} error={groups.error} retry={() => groups.refetch()} dim={groups.isPlaceholderData}
          sort={u.get('gsort', '-count')} onSort={(s) => u.set({ gsort: s })}
          empty={<Empty icon="services" title={t('Brak grup dla tych filtrów', 'No groups for these filters')} />}
          mobile={(g) => (
            <div>
              <div className="flex items-center justify-between gap-2"><span className="text-sm font-medium">{g.label}</span><span className="num text-sm">×{g.count}</span></div>
              <div className="mt-0.5 truncate text-xs text-ink-3">{g.title || (g.technologies ?? []).join(', ')}</div>
            </div>
          )}
        />
      )}
      {total !== undefined ? <Pager total={total} limit={limit} offset={offset} onOffset={(o) => u.set({ offset: o || null })} /> : null}
      </>}
    </div>
  );
}
