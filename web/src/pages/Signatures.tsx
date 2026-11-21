import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { useAction, usePage } from '../api/hooks';
import { ApiError, patch, upload } from '../api/client';
import type { Signature, SignatureImportReport } from '../api/types';
import { t } from '../i18n';
import { fmtInt, fmtRelative } from '../lib/format';
import { useUrlState } from '../lib/hooks';
import { Button, Dialog, Empty, InlineError, LinkButton, PageHeader, Select, Tags } from '../ui/kit';
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

/** Import a whole signature file (Czujka YAML, a YAML or JSON list, a map keyed by name, passive nuclei templates) and show the result per signature. */
function ImportDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [report, setReport] = useState<{ rep: SignatureImportReport; stored: boolean } | null>(null);
  const run = useAction(async (f: File) => {
    const fd = new FormData();
    fd.append('file', f);
    try {
      return { rep: await upload<SignatureImportReport>('/signatures/import', fd), stored: true };
    } catch (e) {
      // 422: nothing was stored; the same report is in the error details.
      if (e instanceof ApiError && e.status === 422 && e.details && typeof e.details === 'object' && 'validation' in e.details) return { rep: e.details as SignatureImportReport, stored: false };
      throw e;
    }
  }, { invalidate: ['/signatures'], silent: true, onSuccess: (r) => setReport(r) });
  const close = () => { setFile(null); setReport(null); run.reset(); onClose(); };
  const rep = report?.rep;
  const issues = rep?.validation.issues ?? [];
  return (
    <Dialog open={open} onClose={close} title={t('Import sygnatur z pliku', 'Import signatures from a file')} width={620}
      footer={<><Button onClick={close}>{report ? t('Zamknij', 'Close') : t('Anuluj', 'Cancel')}</Button>{!report ? <Button variant="primary" icon="upload" busy={run.isPending} disabled={!file} onClick={() => file && run.mutate(file)}>{t('Importuj', 'Import')}</Button> : null}</>}>
      {!report ? (
        <div className="space-y-3">
          <p className="text-sm text-ink-2">{t('Przyjmowane formaty: plik sygnatur Czujki (YAML), lista YAML lub JSON, mapa nazwa → sygnatura, pasywne szablony nuclei. Każda sygnatura przechodzi walidację bezpieczeństwa; odrzucona nie jest zapisywana. Sygnatur wbudowanych import nie zastępuje.', 'Accepted formats: a Czujka signature file (YAML), a YAML or JSON list, a name → signature map, passive nuclei templates. Every signature goes through the safety validation; a rejected one is not stored. The import never replaces built-in signatures.')}</p>
          <label className="block">
            <span className="label mb-1 block">{t('Plik', 'File')}</span>
            <input type="file" accept=".yaml,.yml,.json,.txt" className="field py-1" data-testid="sig-import-file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          </label>
          <InlineError error={run.error} />
        </div>
      ) : (
        <div className="space-y-3" data-testid="sig-import-report">
          <p className="flex items-start gap-2 text-sm">
            <Glyph name={report.stored ? 'check' : 'x'} tone={report.stored ? 'new' : 'gone'} />
            <span>{report.stored ? t('Zapisano: ', 'Stored: ') : t('Nic nie zapisano. ', 'Nothing was stored. ')}<span className="num font-medium">{(rep?.created ?? []).length}</span> {t('nowych', 'new')}, <span className="num font-medium">{(rep?.updated ?? []).length}</span> {t('zastąpionych', 'replaced')}, <span className="num font-medium">{(rep?.skipped ?? []).length}</span> {t('pominiętych', 'skipped')}, <span className="num font-medium">{issues.filter((i) => i.level === 'error').length}</span> {t('błędów', 'errors')}.</span>
          </p>
          <ul className="max-h-[320px] overflow-auto border-t border-rule text-sm">
            {(rep?.created ?? []).map((s) => <li key={'c' + s} className="flex h-[30px] items-center gap-2 border-b border-rule"><Glyph name="plus" tone="new" size={12} /><span className="mono">{s}</span><span className="ml-auto text-xs text-ink-3">{t('nowa', 'new')}</span></li>)}
            {(rep?.updated ?? []).map((s) => <li key={'u' + s} className="flex h-[30px] items-center gap-2 border-b border-rule"><Glyph name="delta" tone="changed" size={12} /><span className="mono">{s}</span><span className="ml-auto text-xs text-ink-3">{t('zastąpiona', 'replaced')}</span></li>)}
            {(rep?.skipped ?? []).map((s) => <li key={'s' + s.slug} className="flex min-h-[30px] items-center gap-2 border-b border-rule py-1"><Glyph name="ring" tone="expected" size={12} /><span className="mono">{s.slug}</span><span className="ml-auto text-right text-xs text-ink-3">{s.reason}</span></li>)}
            {issues.map((i, n) => <li key={'i' + n} className="flex min-h-[30px] items-start gap-2 border-b border-rule py-1"><Glyph name={i.level === 'error' ? 'x' : 'delta'} tone={i.level === 'error' ? 'gone' : 'changed'} size={12} /><span className="min-w-0"><span className="mono text-xs text-ink-2">{i.path}</span> <span className={i.safety ? 'text-danger' : ''}>{i.message}</span>{i.safety ? <span className="ml-1 text-2xs text-danger">{t('(bezpieczeństwo)', '(safety)')}</span> : null}</span></li>)}
          </ul>
        </div>
      )}
    </Dialog>
  );
}

export default function Signatures() {
  const [importOpen, setImportOpen] = useState(false);
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
        actions={can('signatures:create') ? <><Button icon="upload" onClick={() => setImportOpen(true)} data-testid="sig-import">{t('Importuj z pliku', 'Import from a file')}</Button><LinkButton to="/signatures/new" variant="primary" icon="plus">{t('Nowa sygnatura', 'New signature')}</LinkButton></> : null}
      />
      <ImportDialog open={importOpen} onClose={() => setImportOpen(false)} />
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
