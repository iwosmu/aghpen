import { useMemo } from 'react';
import { Link } from 'react-router';
import { useAction, usePage } from '../api/hooks';
import { patch } from '../api/client';
import type { Signature } from '../api/types';
import { t } from '../i18n';
import { fmtInt, fmtRelative } from '../lib/format';
import { useUrlState } from '../lib/hooks';
import { Empty, LinkButton, PageHeader, Select, Tags } from '../ui/kit';
import { DataTable, FilterBar, FilterField, Pager, SearchField, type Col } from '../ui/table';
import { Glyph, TECH_CATEGORIES, categoryLabel } from '../ui/marks';
import { useDraft } from '../ui/edit';
import { useSession } from '../session';

const FILTERS = ['q', 'category', 'enabled', 'builtin'];

export function Switch({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} disabled={disabled}
      onClick={(e) => { e.stopPropagation(); e.preventDefault(); onChange(!checked); }}
      className={'relative inline-flex h-[18px] w-[32px] flex-none items-center border transition-colors disabled:opacity-50 ' + (checked ? 'border-accent bg-accent' : 'border-rule-strong bg-raised')}>
      <span className={'block h-[12px] w-[12px] transition-transform ' + (checked ? 'translate-x-[16px] bg-accent-ink' : 'translate-x-[2px] bg-ink-3')} />
    </button>
  );
}

export default function Signatures() {
  const u = useUrlState();
  const { can } = useSession();
  const canToggle = can('signatures:update');
  const limit = 50;
  const offset = Number(u.get('offset', '0'));
  const filters = useMemo(() => {
    const q: Record<string, string> = {};
    for (const k of FILTERS) { const v = u.get(k); if (v) q[k] = v; }
    return q;
  }, [u]);
  const q = usePage<Signature>('/signatures', { ...filters, sort: u.get('sort', 'name'), limit, offset });
  const [text, setText] = useDraft(u.get('q'), (v) => u.set({ q: v }));
  const toggle = useAction((s: Signature) => patch<Signature>('/signatures/' + s.id, { enabled: !s.enabled }), { invalidate: ['/signatures'] });
  const active = FILTERS.filter((k) => u.get(k)).length;
  const cols: Col<Signature>[] = [
    { id: 'on', header: t('Aktywna', 'Active'), width: 76, cell: (s) => canToggle
      ? <Switch checked={s.enabled} disabled={toggle.isPending} onChange={() => toggle.mutate(s)} label={(s.enabled ? t('Wyłącz sygnaturę ', 'Disable signature ') : t('Włącz sygnaturę ', 'Enable signature ')) + s.name} />
      : s.enabled ? <span className="inline-flex items-center gap-1.5 text-xs"><Glyph name="check" tone="new" size={12} />{t('tak', 'yes')}</span> : <span className="inline-flex items-center gap-1.5 text-xs text-ink-3"><Glyph name="ring" tone="expected" size={12} />{t('nie', 'no')}</span> },
    { id: 'name', header: t('Sygnatura', 'Signature'), sort: 'name', wrap: true, cell: (s) => (
      <div className="min-w-[200px] py-1">
        <Link to={'/signatures/' + s.id} className="link font-medium">{s.name}</Link>
        <div className="max-w-[460px] truncate text-xs text-ink-3" title={s.description}>{s.description}</div>
      </div>
    ) },
    { id: 'slug', header: 'ID', hide: 'xl', cell: (s) => <span className="mono text-xs text-ink-2">{s.slug}</span> },
    { id: 'cat', header: t('Kategoria', 'Category'), sort: 'category', cell: (s) => <span className="text-ink-2">{categoryLabel(s.category)}</span> },
    { id: 'tags', header: t('Tagi', 'Tags'), hide: 'lg', cell: (s) => <Tags tags={s.tags} max={3} /> },
    { id: 'src', header: t('Źródło', 'Source'), hide: 'md', cell: (s) => s.builtin ? <span className="text-ink-3">{t('wbudowana', 'built-in')}</span> : <span>{t('własna', 'custom')} <span className="text-xs text-ink-3">{s.author.split('@')[0]}</span></span> },
    { id: 'matches', header: t('Trafienia', 'Matches'), sort: 'match_count', align: 'right', cell: (s) => s.match_count ? <span className="num">{fmtInt(s.match_count)}</span> : <span className="num text-ink-3">0</span> },
    { id: 'upd', header: t('Zmieniona', 'Updated'), hide: 'xl', cell: (s) => <span className="num text-ink-2">{fmtRelative(s.updated_at)}</span> },
  ];
  return (
    <div>
      <PageHeader
        title={t('Sygnatury', 'Signatures')}
        sub={t('Reguły, które rozpoznają technologie i rodzaje usług po odpowiedzi serwera. Sygnatura tylko czyta: metody GET i HEAD, bez danych wysyłanych do usługi.', 'Rules that recognise technologies and kinds of services from the server response. A signature only reads: GET and HEAD, no data sent to the service.')}
        readOnly={!canToggle && !can('signatures:create')}
        actions={can('signatures:create') ? <LinkButton to="/signatures/new" variant="primary" icon="plus">{t('Nowa sygnatura', 'New signature')}</LinkButton> : null}
      />
      <FilterBar onClear={() => u.clear(FILTERS)} active={active}>
        <SearchField value={text} onChange={setText} placeholder={t('nazwa, identyfikator, opis', 'name, id, description')} width={240} />
        <FilterField label={t('Kategoria', 'Category')} width={170}><Select value={u.get('category')} onChange={(v) => u.set({ category: v })} options={[{ value: '', label: t('wszystkie', 'all') }, ...TECH_CATEGORIES.map((c) => ({ value: c, label: categoryLabel(c) }))]} /></FilterField>
        <FilterField label={t('Stan', 'State')} width={130}><Select value={u.get('enabled')} onChange={(v) => u.set({ enabled: v })} options={[{ value: '', label: t('wszystkie', 'all') }, { value: 'true', label: t('aktywne', 'active') }, { value: 'false', label: t('wyłączone', 'disabled') }]} /></FilterField>
        <FilterField label={t('Źródło', 'Source')} width={130}><Select value={u.get('builtin')} onChange={(v) => u.set({ builtin: v })} options={[{ value: '', label: t('wszystkie', 'all') }, { value: 'true', label: t('wbudowane', 'built-in') }, { value: 'false', label: t('własne', 'custom') }]} /></FilterField>
      </FilterBar>
      <DataTable
        rows={q.data?.items} cols={cols} rowKey={(s) => s.id} rowHref={(s) => '/signatures/' + s.id} loading={q.isPending} error={q.error} retry={() => q.refetch()} dim={q.isPlaceholderData}
        sort={u.get('sort', 'name')} onSort={(s) => u.set({ sort: s })} rowClass={(s) => (s.enabled ? undefined : 'text-ink-3')}
        empty={<Empty icon="signatures" title={active ? t('Żadna sygnatura nie pasuje do filtrów', 'No signature matches the filters') : t('Biblioteka sygnatur jest pusta', 'The signature library is empty')} hint={active ? undefined : t('Napisz pierwszą regułę w edytorze i sprawdź ją na zapisanych wynikach, zanim ją włączysz.', 'Write the first rule in the editor and test it on stored results before you enable it.')} />}
        mobile={(s) => (
          <div>
            <div className="flex items-center justify-between gap-2"><span className="text-sm font-medium">{s.name}</span><span className="num text-xs text-ink-2">{s.match_count}</span></div>
            <div className="mt-0.5 text-xs text-ink-3">{categoryLabel(s.category)} · {s.builtin ? t('wbudowana', 'built-in') : t('własna', 'custom')} · {s.enabled ? t('aktywna', 'active') : t('wyłączona', 'disabled')}</div>
          </div>
        )}
      />
      {q.data ? <Pager total={q.data.total} limit={limit} offset={offset} onOffset={(o) => u.set({ offset: o || null })} /> : null}
    </div>
  );
}
