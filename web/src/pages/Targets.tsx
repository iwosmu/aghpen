import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAction, usePage } from '../api/hooks';
import { del, patch, post, upload } from '../api/client';
import type { Scope, Target, TargetPreview } from '../api/types';
import { t, plural } from '../i18n';
import { cx, fmtInt } from '../lib/format';
import { useUrlState } from '../lib/hooks';
import { Button, Dialog, Empty, ErrorState, Field, IconButton, InlineError, PageHeader, Panel, Select, SkeletonRows, Spinner, Tabs, Tags } from '../ui/kit';
import { DataTable, Pager, type Col } from '../ui/table';
import { Crit, Glyph } from '../ui/marks';
import { useDebounced } from '../ui/edit';
import { useSession } from '../session';
import { Switch } from './Signatures';

function kindLabel(k: string): string {
  return k === 'cidr' ? 'CIDR' : k === 'range' ? t('zakres', 'range') : k === 'domain' ? t('domena', 'domain') : 'IP';
}

export function PreviewReport({ p, pending }: { p: TargetPreview; pending?: boolean }) {
  const cell = (n: number, label: string, glyph: 'check' | 'x' | 'ring' | 'dashring', tone: 'new' | 'gone' | 'expected' | 'changed') => (
    <div className="flex items-center gap-2 border-b border-rule py-1.5 sm:border-b-0 sm:border-r sm:px-3 sm:first:pl-0 sm:last:border-r-0">
      <Glyph name={glyph} tone={n ? tone : 'expected'} /><span className="num text-base font-medium">{fmtInt(n)}</span><span className="text-xs text-ink-2">{label}</span>
    </div>
  );
  return (
    <div className={cx('border border-rule bg-panel p-3', pending && 'opacity-60')} data-testid="target-preview" aria-live="polite">
      <div className="grid sm:flex sm:flex-wrap">
        {cell(p.valid.length, plural(p.valid.length, ['poprawny wpis', 'poprawne wpisy', 'poprawnych wpisów'], ['valid entry', 'valid entries']), 'check', 'new')}
        {cell(p.invalid.length, plural(p.invalid.length, ['błędny', 'błędne', 'błędnych'], ['invalid', 'invalid']), 'x', 'gone')}
        {cell(p.duplicates, plural(p.duplicates, ['duplikat', 'duplikaty', 'duplikatów'], ['duplicate', 'duplicates']), 'ring', 'changed')}
        {cell(p.excluded, plural(p.excluded, ['adres wykluczony polityką', 'adresy wykluczone polityką', 'adresów wykluczonych polityką'], ['address excluded by the policy', 'addresses excluded by the policy']), 'dashring', 'changed')}
      </div>
      <p className="mt-2 border-t border-rule pt-2 text-sm">{t('Do zakresu trafi ', 'The scope gains ')}<span className="num text-base font-semibold">{fmtInt(p.address_count)}</span> {plural(p.address_count, ['adres', 'adresy', 'adresów'], ['address', 'addresses'])}.</p>
      {p.invalid.length ? (
        <ul className="mt-2 max-h-[150px] overflow-auto border-t border-rule">
          {p.invalid.map((l) => (
            <li key={l.line} className="grid grid-cols-[64px_minmax(0,1fr)] gap-x-2 border-b border-rule py-1 text-xs sm:grid-cols-[64px_minmax(0,150px)_minmax(0,1fr)]">
              <span className="num text-ink-3">{t('wiersz', 'line')} {l.line}</span><span className="mono truncate text-ink">{l.value}</span><span className="col-span-2 text-danger sm:col-span-1">{l.reason}</span>
            </li>
          ))}
        </ul>
      ) : null}
      {p.valid.length ? (
        <p className="mono mt-2 max-h-[64px] overflow-auto text-xs text-ink-2">{p.valid.slice(0, 40).map((v) => v.value).join('  ')}{p.valid.length > 40 ? '  …' : ''}</p>
      ) : null}
    </div>
  );
}

function AddTargets({ scope }: { scope: Scope }) {
  const [tab, setTab] = useState('manual');
  const [text, setText] = useState('');
  const debounced = useDebounced(text, 300);
  const preview = useQuery<TargetPreview>({ queryKey: ['/targets/preview', debounced], queryFn: () => post<TargetPreview>('/targets/preview', { text: debounced }), enabled: debounced.trim().length > 0, placeholderData: (p) => p });
  const add = useAction(() => post<TargetPreview>('/scopes/' + scope.id + '/targets', { text }), {
    invalidate: ['/scopes', '/dashboard'], silent: true, onSuccess: () => setText(''),
    success: (r) => t('Dodano celów: ' + r.valid.length, 'Targets added: ' + r.valid.length),
  });
  const [file, setFile] = useState<File | null>(null);
  const [dry, setDry] = useState<TargetPreview | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const send = (f: File, dryRun: boolean) => { const fd = new FormData(); fd.append('file', f); fd.append('dry_run', String(dryRun)); return upload<TargetPreview>('/scopes/' + scope.id + '/targets/import', fd); };
  const dryRun = useAction((f: File) => send(f, true), { silent: true, onSuccess: (r) => setDry(r) });
  const imp = useAction((f: File) => send(f, false), {
    invalidate: ['/scopes', '/dashboard'], silent: true, success: (r) => t('Zaimportowano celów: ' + r.valid.length, 'Targets imported: ' + r.valid.length),
    onSuccess: () => { setFile(null); setDry(null); if (input.current) input.current.value = ''; },
  });
  useEffect(() => { setDry(null); setFile(null); }, [scope.id]);
  const p = preview.data;
  const stale = preview.isFetching || debounced !== text;
  return (
    <Panel title={t('Dodaj cele do zakresu', 'Add targets to the scope')}>
      <Tabs value={tab} onChange={setTab} tabs={[{ id: 'manual', label: t('Wpisz ręcznie', 'Type by hand') }, { id: 'file', label: t('Z pliku CSV lub JSON', 'From a CSV or JSON file') }]} />
      {tab === 'manual' ? (
        <div className="mt-3 grid gap-4 lg:grid-cols-2">
          <div>
            <Field label={t('Cele, jeden w wierszu', 'Targets, one per line')} hint={t('Adres IP, CIDR, zakres a-b albo domena. Tekst po # jest komentarzem.', 'An IP address, CIDR, range a-b or a domain. Text after # is a comment.')}>
              <textarea className="field mono" rows={8} spellCheck={false} value={text} onChange={(e) => setText(e.target.value)} placeholder={'10.20.48.0/24\n10.30.6.10-10.30.6.40\nlab.uczelnia.example'} />
            </Field>
            <div className="mt-2 flex items-center gap-2">
              <Button variant="primary" icon="plus" busy={add.isPending} disabled={!p || p.valid.length === 0 || stale || !text.trim()} onClick={() => add.mutate(undefined)}>
                {p && p.valid.length && text.trim() ? t('Dodaj ' + p.valid.length + ' ' + plural(p.valid.length, ['cel', 'cele', 'celów'], ['', '']), 'Add ' + p.valid.length + ' ' + (p.valid.length === 1 ? 'target' : 'targets')) : t('Dodaj cele', 'Add targets')}
              </Button>
              {stale && text.trim() ? <span className="inline-flex items-center gap-1.5 text-xs text-ink-3"><Spinner />{t('sprawdzam', 'checking')}</span> : null}
            </div>
            <div className="mt-2"><InlineError error={add.error ?? preview.error} /></div>
          </div>
          <div>
            <p className="label mb-1.5">{t('Podgląd przed zapisem', 'Preview before saving')}</p>
            {text.trim() && p ? <PreviewReport p={p} pending={stale} /> : <p className="border border-dashed border-rule-strong p-3 text-sm text-ink-2">{t('Zacznij pisać: Czujka na bieżąco policzy poprawne wpisy, błędy z powodem, duplikaty, wykluczenia i liczbę adresów.', 'Start typing: Czujka counts valid entries, errors with a reason, duplicates, exclusions and the number of addresses as you go.')}</p>}
          </div>
        </div>
      ) : (
        <div className="mt-3 grid gap-4 lg:grid-cols-2">
          <div>
            <Field label={t('Plik z celami', 'Target file')} hint={t('CSV: cel w pierwszej kolumnie. JSON: tablica tekstów albo obiektów z polem value.', 'CSV: the target in the first column. JSON: an array of strings or of objects with a value field.')}>
              <input ref={input} type="file" accept=".csv,.json,.txt,text/csv,application/json" className="field py-1" onChange={(e) => { const f = e.target.files?.[0] ?? null; setFile(f); setDry(null); if (f) dryRun.mutate(f); }} />
            </Field>
            <div className="mt-2 flex items-center gap-2">
              <Button variant="primary" icon="upload" busy={imp.isPending} disabled={!file || !dry || dry.valid.length === 0} onClick={() => file && imp.mutate(file)}>{dry && dry.valid.length ? t('Importuj ' + dry.valid.length, 'Import ' + dry.valid.length) : t('Importuj', 'Import')}</Button>
              {dryRun.isPending ? <span className="inline-flex items-center gap-1.5 text-xs text-ink-3"><Spinner />{t('próba na sucho', 'dry run')}</span> : null}
            </div>
            <div className="mt-2"><InlineError error={dryRun.error ?? imp.error} /></div>
          </div>
          <div>
            <p className="label mb-1.5">{t('Wynik próby na sucho', 'Dry-run result')}</p>
            {dry ? <PreviewReport p={dry} /> : <p className="border border-dashed border-rule-strong p-3 text-sm text-ink-2">{t('Po wybraniu pliku Czujka sprawdzi go bez zapisywania. Import ruszy dopiero po Twoim potwierdzeniu.', 'When you choose a file, Czujka checks it without saving. The import starts only after you confirm.')}</p>}
          </div>
        </div>
      )}
    </Panel>
  );
}

function ScopeDialog({ scope, onClose, onSaved }: { scope: Scope | null; onClose: () => void; onSaved: (s: Scope) => void }) {
  const [f, setF] = useState({ name: scope?.name ?? '', description: scope?.description ?? '', owner: scope?.owner ?? '', criticality: scope?.criticality ?? 3 });
  const save = useAction(() => (scope ? patch<Scope>('/scopes/' + scope.id, f) : post<Scope>('/scopes', f)), { invalidate: ['/scopes'], silent: true, success: t('Zakres zapisany', 'Scope saved'), onSuccess: (s) => { onSaved(s); onClose(); } });
  return (
    <Dialog open onClose={onClose} width={480} title={scope ? t('Edycja zakresu', 'Edit the scope') : t('Nowy zakres', 'New scope')}
      footer={<><Button onClick={onClose}>{t('Anuluj', 'Cancel')}</Button><Button variant="primary" busy={save.isPending} disabled={!f.name.trim()} onClick={() => save.mutate(undefined)}>{t('Zapisz zakres', 'Save the scope')}</Button></>}>
      <div className="space-y-3">
        <Field label={t('Nazwa', 'Name')}><input className="field" autoFocus value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        <Field label={t('Opis', 'Description')}><input className="field" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('Właściciel', 'Owner')}><input className="field" value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} /></Field>
          <Field label={t('Krytyczność', 'Criticality')}><Select value={String(f.criticality)} onChange={(v) => setF({ ...f, criticality: Number(v) })} options={[1, 2, 3, 4, 5].map((n) => ({ value: String(n), label: String(n) }))} /></Field>
        </div>
        <InlineError error={save.error} />
      </div>
    </Dialog>
  );
}

export default function Targets() {
  const u = useUrlState();
  const { can } = useSession();
  const canCreate = can('targets:create'), canUpdate = can('targets:update'), canDelete = can('targets:delete');
  const scopes = usePage<Scope>('/scopes', { limit: 200 });
  const list = scopes.data?.items ?? [];
  const scopeId = Number(u.get('scope', '0')) || list[0]?.id || 0;
  const scope = list.find((s) => s.id === scopeId) ?? null;
  const limit = 50;
  const offset = Number(u.get('offset', '0'));
  const targets = usePage<Target>('/scopes/' + scopeId + '/targets', { limit, offset }, scopeId > 0);
  const [dialog, setDialog] = useState<'new' | 'edit' | null>(null);
  const [confirm, setConfirm] = useState<{ kind: 'scope' | 'target'; id: number; label: string } | null>(null);
  const toggle = useAction((x: Target) => patch<Target>('/targets/' + x.id, { enabled: !x.enabled }), { invalidate: ['/scopes'] });
  const remove = useAction((c: { kind: 'scope' | 'target'; id: number }) => del(c.kind === 'scope' ? '/scopes/' + c.id : '/targets/' + c.id), {
    invalidate: ['/scopes', '/dashboard'], success: t('Usunięto', 'Deleted'), onSuccess: (_r, c) => { setConfirm(null); if (c.kind === 'scope') u.set({ scope: null }); },
  });
  const cols: Col<Target>[] = [
    { id: 'value', header: t('Cel', 'Target'), cell: (x) => <span className={cx('mono', !x.enabled && 'text-ink-3 line-through')}>{x.value}</span> },
    { id: 'kind', header: t('Rodzaj', 'Kind'), cell: (x) => <span className="text-ink-2">{kindLabel(x.kind)}</span> },
    { id: 'addr', header: t('Adresy', 'Addresses'), align: 'right', cell: (x) => <span className="num">{fmtInt(x.addresses)}</span> },
    { id: 'note', header: t('Notatka', 'Note'), hide: 'md', cell: (x) => <span className="block max-w-[260px] truncate text-ink-2">{x.note || '–'}</span> },
    { id: 'tags', header: t('Tagi', 'Tags'), hide: 'lg', cell: (x) => <Tags tags={x.tags} max={2} /> },
    { id: 'source', header: t('Źródło', 'Source'), hide: 'lg', cell: (x) => <span className="text-ink-3">{x.source === 'manual' ? t('ręcznie', 'manual') : x.source}</span> },
    { id: 'enabled', header: t('Skanowany', 'Scanned'), cell: (x) => canUpdate
      ? <Switch checked={x.enabled} disabled={toggle.isPending} onChange={() => toggle.mutate(x)} label={(x.enabled ? t('Wyłącz cel ', 'Disable target ') : t('Włącz cel ', 'Enable target ')) + x.value} />
      : <span className="text-xs text-ink-2">{x.enabled ? t('tak', 'yes') : t('nie', 'no')}</span> },
    ...(canDelete ? [{ id: 'del', header: '', align: 'right' as const, width: 44, cell: (x: Target) => <IconButton icon="trash" label={t('Usuń cel ', 'Delete target ') + x.value} onClick={() => setConfirm({ kind: 'target', id: x.id, label: x.value })} /> }] : []),
  ];
  return (
    <div>
      <PageHeader
        title={t('Cele i zakresy', 'Targets and scopes')}
        sub={t('Zakres to nazwany zbiór celów z właścicielem. Skaner nigdy nie wychodzi poza cele wpisane tutaj.', 'A scope is a named set of targets with an owner. The scanner never leaves the targets entered here.')}
        readOnly={!canCreate && !canUpdate}
        actions={canCreate ? <Button variant="primary" icon="plus" onClick={() => setDialog('new')}>{t('Nowy zakres', 'New scope')}</Button> : null}
      />
      {scopes.error ? <ErrorState error={scopes.error} retry={() => scopes.refetch()} /> : scopes.isPending ? <SkeletonRows rows={8} /> : list.length === 0 ? (
        <Empty icon="targets" title={t('Nie ma jeszcze żadnego zakresu', 'There is no scope yet')} hint={t('Utwórz zakres, na przykład „Kampus główny”, i dodaj do niego sieci, które wolno skanować.', 'Create a scope, for example "Main campus", and add the networks that may be scanned.')} action={canCreate ? <Button variant="primary" icon="plus" onClick={() => setDialog('new')}>{t('Nowy zakres', 'New scope')}</Button> : undefined} />
      ) : (
        <div className="grid gap-4 p-4 sm:p-6 xl:grid-cols-[300px_minmax(0,1fr)]">
          <nav aria-label={t('Zakresy', 'Scopes')}>
            <ul className="border border-rule bg-panel">
              {list.map((s) => (
                <li key={s.id} className="border-b border-rule last:border-b-0">
                  <button type="button" aria-current={s.id === scopeId ? 'true' : undefined} onClick={() => u.set({ scope: s.id })}
                    className={cx('block w-full px-3 py-2 text-left outline-offset-[-2px] hover:bg-raised', s.id === scopeId && 'bg-accent-wash')}>
                    <span className="flex items-center justify-between gap-2"><span className={cx('text-sm', s.id === scopeId ? 'font-semibold text-ink' : 'text-ink')}>{s.name}</span><Crit value={s.criticality} /></span>
                    <span className="mt-0.5 block text-xs text-ink-2"><span className="num">{fmtInt(s.address_count)}</span> {t('adresów', 'addresses')} · <span className="num">{s.target_count}</span> {plural(s.target_count, ['cel', 'cele', 'celów'], ['target', 'targets'])}</span>
                    {s.owner ? <span className="block truncate text-xs text-ink-3">{s.owner}</span> : null}
                  </button>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-ink-3">{t('Razem', 'Total')} <span className="num text-ink-2">{fmtInt(list.reduce((a, s) => a + s.address_count, 0))}</span> {t('adresów w', 'addresses in')} {list.length} {plural(list.length, ['zakresie', 'zakresach', 'zakresach'], ['scope', 'scopes'])}.</p>
          </nav>
          {scope ? (
            <div className="min-w-0 space-y-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <h2 className="text-lg font-semibold">{scope.name}</h2>
                  <p className="text-sm text-ink-2">{scope.description || t('Bez opisu.', 'No description.')}</p>
                  <div className="mt-1"><Tags tags={scope.tags} max={6} /></div>
                </div>
                <div className="flex gap-1.5">
                  {canUpdate ? <Button size="sm" icon="edit" onClick={() => setDialog('edit')}>{t('Edytuj zakres', 'Edit the scope')}</Button> : null}
                  {canDelete ? <Button size="sm" variant="danger" icon="trash" onClick={() => setConfirm({ kind: 'scope', id: scope.id, label: scope.name })}>{t('Usuń zakres', 'Delete the scope')}</Button> : null}
                </div>
              </div>
              {canCreate ? <AddTargets scope={scope} /> : null}
              <Panel title={t('Cele w zakresie', 'Targets in the scope')} count={targets.data?.total} flush>
                <DataTable inPanel rows={targets.data?.items} cols={cols} rowKey={(x) => x.id} loading={targets.isPending} error={targets.error} retry={() => targets.refetch()} dim={targets.isPlaceholderData}
                  empty={<p className="p-3 text-sm text-ink-2">{t('Ten zakres nie ma jeszcze celów.', 'This scope has no target yet.')}{canCreate ? ' ' + t('Dodaj je w formularzu powyżej.', 'Add them in the form above.') : ''}</p>}
                  mobile={(x) => (
                    <div className="flex items-center justify-between gap-2"><span><span className="mono text-sm">{x.value}</span><span className="ml-2 text-xs text-ink-3">{kindLabel(x.kind)} · {fmtInt(x.addresses)}</span></span>{canDelete ? <IconButton icon="trash" label={t('Usuń cel ', 'Delete target ') + x.value} onClick={() => setConfirm({ kind: 'target', id: x.id, label: x.value })} /> : null}</div>
                  )} />
                {targets.data ? <Pager total={targets.data.total} limit={limit} offset={offset} onOffset={(o) => u.set({ offset: o || null })} /> : null}
              </Panel>
            </div>
          ) : null}
        </div>
      )}
      {dialog ? <ScopeDialog scope={dialog === 'edit' ? scope : null} onClose={() => setDialog(null)} onSaved={(s) => u.set({ scope: s.id })} /> : null}
      <Dialog open={confirm !== null} onClose={() => setConfirm(null)} width={440} title={confirm?.kind === 'scope' ? t('Usunąć zakres?', 'Delete the scope?') : t('Usunąć cel?', 'Delete the target?')}
        footer={<><Button onClick={() => setConfirm(null)}>{t('Anuluj', 'Cancel')}</Button><Button variant="dangerSolid" busy={remove.isPending} onClick={() => confirm && remove.mutate(confirm)}>{t('Usuń', 'Delete')}</Button></>}>
        <p className="text-sm"><span className="mono">{confirm?.label}</span>{confirm?.kind === 'scope' ? t(': zakres zniknie razem ze wszystkimi celami. Zebrane wyniki zostają w inwentarzu.', ': the scope goes away with all of its targets. Collected results stay in the inventory.') : t(': skaner przestanie sprawdzać te adresy. Zebrane wyniki zostają.', ': the scanner stops probing these addresses. Collected results stay.')}</p>
      </Dialog>
    </div>
  );
}
