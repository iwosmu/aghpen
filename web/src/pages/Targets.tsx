import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAction, useItem, usePage } from '../api/hooks';
import { del, patch, post, upload } from '../api/client';
import type { Health, SafetyPolicy, Scope, Target, TargetPreview } from '../api/types';
import { THIS_COMPUTER, isLoopback, loopbackLine } from '../lib/thisComputer';
import { t, plural } from '../i18n';
import { cx, fmtInt } from '../lib/format';
import { useUrlState } from '../lib/hooks';
import { isLockRefusal } from '../lib/lock';
import { Icon } from '../ui/Icon';
import { Button, Dialog, Empty, ErrorState, Field, IconButton, InlineError, PageHeader, Panel, Select, SkeletonRows, Spinner, Tabs, Tags, FileInput } from '../ui/kit';
import { PassivePanel } from './Passive';
import { DataTable, Pager, type Col } from '../ui/table';
import { Crit, Glyph } from '../ui/marks';
import { useDebounced } from '../ui/edit';
import { useSession } from '../session';
import { Switch } from './Signatures';

function kindLabel(k: string): string {
  return k === 'cidr' ? 'CIDR' : k === 'range' ? t('przedział', 'range') : k === 'domain' ? t('domena', 'domain') : 'IP';
}

/** One line about the operator lock, shown where targets are entered. */
export function OperatorLockNote({ networks }: { networks: string[] | null | undefined }) {
  if (!networks?.length) return null;
  return (
    <p className="flex items-start gap-1.5 text-xs text-ink-2" data-testid="lock-note">
      <Icon name="lock" size={13} className="mt-px flex-none text-ink-3" />
      <span>{t('Operator ograniczył skanowanie do ', 'The operator limits scanning to ')}<span className="mono text-ink">{networks.join(', ')}</span>{t('.', '.')}</span>
    </p>
  );
}

/** "localhost = host Dockera 192.168.65.254": what each loopback entry is scanned as. */
export function LoopbackNote({ targets }: { targets: { value: string; maps_to?: string }[] }) {
  const health = useItem<Health>('/healthz', undefined, { staleTime: 60_000 });
  const lines = [...new Set(targets.map((x) => loopbackLine(x.value, x.maps_to, health.data?.host_gateway)).filter((x): x is string => Boolean(x)))];
  if (!lines.length) return null;
  return (
    <div className="space-y-0.5" data-testid="loopback-note">
      {lines.map((l) => <p key={l} className="flex items-start gap-1.5 text-sm text-ink"><Icon name="info" size={14} className="mt-[3px] flex-none text-ink-3" /><span className="mono">{l}</span></p>)}
    </div>
  );
}

/** The ready "Ten komputer (localhost)" target, next to the ranges field. */
export function ThisComputerChip({ text, onChange }: { text: string; onChange: (next: string) => void }) {
  const has = text.split(/\r?\n/).some((l) => isLoopback(l.replace(/#.*/, '')));
  return (
    <button type="button" className={cx('inline-flex h-[26px] items-center gap-1.5 border px-2 text-xs', has ? 'border-accent text-ink' : 'border-rule-strong text-ink-2 hover:border-accent hover:text-ink')}
      aria-pressed={has} data-testid="this-computer"
      onClick={() => onChange(has ? text : (text.trim() ? text.replace(/\s+$/, '') + '\n' : '') + THIS_COMPUTER)}>
      <Icon name={has ? 'check' : 'plus'} size={12} />{t('Ten komputer', 'This computer')} <span className="mono text-ink-3">(localhost)</span>
    </button>
  );
}

export function PreviewReport({ p, pending }: { p: TargetPreview; pending?: boolean }) {
  const cell = (n: number, label: string, glyph: 'check' | 'x' | 'ring' | 'dashring', tone: 'new' | 'gone' | 'expected' | 'changed') => (
    <div className="flex items-center gap-2 border-b border-rule py-1.5 sm:border-b-0 sm:border-r sm:px-3 sm:first:pl-0 sm:last:border-r-0">
      <Glyph name={glyph} tone={n ? tone : 'expected'} /><span className="num text-base font-medium">{fmtInt(n)}</span><span className="text-xs text-ink-2">{label}</span>
    </div>
  );
  const locked = p.invalid.filter((l) => isLockRefusal(l.reason)).length;
  return (
    <div className={cx('border border-rule bg-panel p-3', pending && 'opacity-60')} data-testid="target-preview" aria-live="polite">
      <div className="grid sm:flex sm:flex-wrap">
        {cell(p.valid.length, plural(p.valid.length, ['poprawny wpis', 'poprawne wpisy', 'poprawnych wpisów'], ['valid entry', 'valid entries']), 'check', 'new')}
        {cell(p.invalid.length, plural(p.invalid.length, ['błędny', 'błędne', 'błędnych'], ['invalid', 'invalid']), 'x', 'gone')}
        {cell(p.duplicates, plural(p.duplicates, ['duplikat', 'duplikaty', 'duplikatów'], ['duplicate', 'duplicates']), 'ring', 'changed')}
        {cell(p.excluded, plural(p.excluded, ['adres wykluczony polityką', 'adresy wykluczone polityką', 'adresów wykluczonych polityką'], ['address excluded by the policy', 'addresses excluded by the policy']), 'dashring', 'changed')}
      </div>
      <div className="mt-2"><LoopbackNote targets={p.valid} /></div>
      <p className="mt-2 border-t border-rule pt-2 text-sm">{t('Nowe adresy w zakresie: ', 'New addresses in the scope: ')}<span className="num text-base font-semibold">{fmtInt(p.address_count)}</span></p>
      {locked ? (
        <p className="mt-2 flex items-start gap-1.5 border-t border-rule pt-2 text-sm text-ink" data-testid="preview-lock">
          <Icon name="lock" size={14} className="mt-0.5 flex-none text-ink-2" />
          <span><span className="num font-semibold">{fmtInt(locked)}</span> {plural(locked, ['wpis leży', 'wpisy leżą', 'wpisów leży'], ['entry lies', 'entries lie'])} {t('poza blokadą operatora', 'outside the operator lock')}: {plural(locked, ['nie trafi', 'nie trafią', 'nie trafi'], ['it stays out of the scope', 'they stay out of the scope'])}{t(' do zakresu.', '.')}</span>
        </p>
      ) : null}
      {p.invalid.length ? (
        <ul className="mt-2 max-h-[150px] overflow-auto border-t border-rule">
          {p.invalid.map((l, i) => {
            const lock = isLockRefusal(l.reason);
            return (
              <li key={i} className="grid grid-cols-[64px_minmax(0,1fr)] gap-x-2 border-b border-rule py-1 text-xs sm:grid-cols-[64px_minmax(0,150px)_minmax(0,1fr)]" data-lock={lock || undefined}>
                <span className="num inline-flex items-center gap-1 text-ink-3">{lock ? <Icon name="lock" size={12} className="text-ink-2" /> : null}{t('wiersz', 'line')} {l.line}</span><span className="mono truncate text-ink">{l.value}</span><span className="col-span-2 text-danger sm:col-span-1">{l.reason}</span>
              </li>
            );
          })}
        </ul>
      ) : null}
      {p.valid.length ? (
        <p className="mono mt-2 max-h-[64px] overflow-auto text-xs text-ink-2">{p.valid.slice(0, 40).map((v) => v.value).join('  ')}{p.valid.length > 40 ? '  …' : ''}</p>
      ) : null}
    </div>
  );
}

function AddTargets({ scope }: { scope: Scope }) {
  const safety = useItem<SafetyPolicy>('/settings/safety', undefined, { staleTime: 60_000 });
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
      <Tabs value={tab} onChange={setTab} tabs={[{ id: 'manual', label: t('Wpisz', 'Type') }, { id: 'file', label: t('Z pliku CSV lub JSON', 'From a CSV or JSON file') }]} />
      {tab === 'manual' ? (
        <div className="mt-3 grid gap-4 lg:grid-cols-2">
          <div>
            <div className="mb-2 flex flex-wrap items-center gap-2 text-xs text-ink-3"><span>{t('Gotowe cele:', 'Ready targets:')}</span><ThisComputerChip text={text} onChange={setText} /></div>
            <Field label={t('Cele, jeden w wierszu', 'Targets, one per line')} hint={t('Adres IP, CIDR, przedział a-b albo domena. Tekst po # jest komentarzem.', 'An IP address, CIDR, range a-b or a domain. Text after # is a comment.')}>
              <textarea className="field mono" rows={8} spellCheck={false} value={text} onChange={(e) => setText(e.target.value)} placeholder={'10.20.48.0/24\n10.30.6.10-10.30.6.40\nlab.uczelnia.example'} data-testid="targets-text" />
            </Field>
            <div className="mt-2"><OperatorLockNote networks={safety.data?.operator_networks} /></div>
            <div className="mt-2 flex items-center gap-2">
              <Button variant="primary" icon="plus" busy={add.isPending} disabled={!p || p.valid.length === 0 || stale || !text.trim()} onClick={() => add.mutate(undefined)}>
                {p && p.valid.length && text.trim() ? t('Dodaj ' + p.valid.length + ' ' + plural(p.valid.length, ['cel', 'cele', 'celów'], ['', '']), 'Add ' + p.valid.length + ' ' + (p.valid.length === 1 ? 'target' : 'targets')) : t('Dodaj cele', 'Add targets')}
              </Button>
              {stale && text.trim() ? <span className="inline-flex items-center gap-1.5 text-xs text-ink-3"><Spinner />{t('sprawdzanie', 'checking')}</span> : null}
            </div>
            <div className="mt-2"><InlineError error={add.error ?? preview.error} /></div>
          </div>
          <div>
            {text.trim() && p ? <><p className="label mb-1.5">{t('Podgląd przed zapisem', 'Preview before saving')}</p><PreviewReport p={p} pending={stale} /></> : null}
          </div>
        </div>
      ) : (
        <div className="mt-3 grid gap-4 lg:grid-cols-2">
          <div>
            <Field label={t('Plik z celami', 'Target file')} hint={t('CSV: cel w pierwszej kolumnie. JSON: tablica tekstów albo obiektów z polem value.', 'CSV: the target in the first column. JSON: an array of strings or of objects with a value field.')}>
              <FileInput inputRef={input} accept=".csv,.json,.txt,text/csv,application/json" file={file} onFile={(f) => { setFile(f); setDry(null); if (f) dryRun.mutate(f); }} />
            </Field>
            <div className="mt-2 flex items-center gap-2">
              <Button variant="primary" icon="upload" busy={imp.isPending} disabled={!file || !dry || dry.valid.length === 0} onClick={() => file && imp.mutate(file)}>{dry && dry.valid.length ? t('Importuj ' + dry.valid.length, 'Import ' + dry.valid.length) : t('Importuj', 'Import')}</Button>
              {dryRun.isPending ? <span className="inline-flex items-center gap-1.5 text-xs text-ink-3"><Spinner />{t('sprawdzenie', 'check')}</span> : null}
            </div>
            <div className="mt-2"><InlineError error={dryRun.error ?? imp.error} /></div>
          </div>
          <div>
            <p className="label mb-1.5">{t('Wynik sprawdzenia', 'Check result')}</p>
            {dry ? <PreviewReport p={dry} /> : <p className="border border-dashed border-rule-strong p-3 text-sm text-ink-2">{t('Czujka sprawdzi plik bez zapisywania.', 'Czujka checks the file without saving.')}</p>}
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
    <Dialog open onClose={onClose} width={480} title={scope ? t('Edytuj zakres', 'Edit scope') : t('Nowy zakres', 'New scope')}
      footer={<><Button onClick={onClose}>{t('Anuluj', 'Cancel')}</Button><Button variant="primary" busy={save.isPending} disabled={!f.name.trim()} onClick={() => save.mutate(undefined)}>{t('Zapisz zakres', 'Save scope')}</Button></>}>
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
    { id: 'value', header: t('Cel', 'Target'), cell: (x) => <span className={cx('mono', !x.enabled && 'text-ink-3 line-through')}>{x.value}{x.maps_to ? <span className="ml-2 font-sans text-xs text-ink-3" data-testid="target-maps-to">{t('skanowany jako', 'scanned as')} <span className="mono text-ink-2">{x.maps_to}</span></span> : null}</span> },
    { id: 'kind', header: t('Rodzaj', 'Type'), cell: (x) => <span className="text-ink-2">{kindLabel(x.kind)}</span> },
    { id: 'addr', header: t('Adresy', 'Addresses'), align: 'right', cell: (x) => <span className="num">{fmtInt(x.addresses)}</span> },
    { id: 'note', header: t('Notatka', 'Note'), hide: 'md', cell: (x) => <span className="block max-w-[260px] truncate text-ink-2">{x.note || '–'}</span> },
    { id: 'tags', header: t('Tagi', 'Tags'), hide: 'lg', cell: (x) => <Tags tags={x.tags} max={2} /> },
    { id: 'source', header: t('Źródło', 'Source'), hide: 'lg', cell: (x) => <span className="text-ink-3">{x.source === 'manual' ? t('ręcznie', 'manual') : x.source}</span> },
    { id: 'enabled', header: t('Włączony', 'Enabled'), cell: (x) => canUpdate
      ? <Switch checked={x.enabled} disabled={toggle.isPending} onChange={() => toggle.mutate(x)} label={(x.enabled ? t('Wyłącz cel ', 'Disable target ') : t('Włącz cel ', 'Enable target ')) + x.value} />
      : <span className="text-xs text-ink-2">{x.enabled ? t('tak', 'yes') : t('nie', 'no')}</span> },
    ...(canDelete ? [{ id: 'del', header: '', align: 'right' as const, width: 44, cell: (x: Target) => <IconButton icon="trash" label={t('Usuń cel ', 'Delete target ') + x.value} onClick={() => setConfirm({ kind: 'target', id: x.id, label: x.value })} /> }] : []),
  ];
  return (
    <div>
      <PageHeader
        title={t('Cele', 'Targets')}
        readOnly={!canCreate && !canUpdate}
        actions={canCreate ? <Button variant="primary" icon="plus" onClick={() => setDialog('new')}>{t('Nowy zakres', 'New scope')}</Button> : null}
      />
      {scopes.error ? <ErrorState error={scopes.error} retry={() => scopes.refetch()} /> : scopes.isPending ? <SkeletonRows rows={8} /> : list.length === 0 ? (
        <Empty icon="targets" title={t('Brak zakresów', 'No scopes yet')} hint={t('Utwórz zakres i dodaj sieci, które wolno skanować.', 'Create a scope and add the networks that may be scanned.')} action={canCreate ? <Button variant="primary" icon="plus" onClick={() => setDialog('new')}>{t('Nowy zakres', 'New scope')}</Button> : undefined} />
      ) : (
        <div className="grid gap-4 p-4 sm:p-6 xl:grid-cols-[300px_minmax(0,1fr)]">
          <nav aria-label={t('Zakresy', 'Scopes')}>
            <ul className="border border-rule bg-panel">
              {list.map((s) => (
                <li key={s.id} className="border-b border-rule last:border-b-0">
                  <button type="button" aria-current={s.id === scopeId ? 'true' : undefined} onClick={() => u.set({ scope: s.id })}
                    className={cx('block w-full px-3 py-2 text-left outline-offset-[-2px] hover:bg-raised', s.id === scopeId && 'bg-accent-wash')}>
                    <span className="flex items-center justify-between gap-2"><span className={cx('text-sm', s.id === scopeId ? 'font-semibold text-ink' : 'text-ink')}>{s.name}</span><Crit value={s.criticality} /></span>
                    <span className="mt-0.5 block text-xs text-ink-2"><span className="num">{fmtInt(s.address_count)}</span> {plural(s.address_count, ['adres', 'adresy', 'adresów'], ['address', 'addresses'])} · <span className="num">{s.target_count}</span> {plural(s.target_count, ['cel', 'cele', 'celów'], ['target', 'targets'])}</span>
                    {s.owner ? <span className="block truncate text-xs text-ink-3">{s.owner}</span> : null}
                  </button>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-ink-3">{t('Razem', 'Total')} <span className="num text-ink-2">{fmtInt(list.reduce((a, s) => a + s.address_count, 0))}</span> {plural(list.reduce((a, s) => a + s.address_count, 0), ['adres', 'adresy', 'adresów'], ['address', 'addresses'])} {t('w', 'in')} {list.length} {plural(list.length, ['zakresie', 'zakresach', 'zakresach'], ['scope', 'scopes'])}.</p>
          </nav>
          {scope ? (
            <div className="min-w-0 space-y-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <h2 className="text-lg font-semibold">{scope.name}</h2>
                  <p className="text-sm text-ink-2">{scope.description || t('Bez opisu', 'No description')}</p>
                  <div className="mt-1"><Tags tags={scope.tags} max={6} /></div>
                </div>
                <div className="flex gap-1.5">
                  {canUpdate ? <Button size="sm" icon="edit" onClick={() => setDialog('edit')}>{t('Edytuj zakres', 'Edit scope')}</Button> : null}
                  {canDelete ? <Button size="sm" variant="danger" icon="trash" onClick={() => setConfirm({ kind: 'scope', id: scope.id, label: scope.name })}>{t('Usuń zakres', 'Delete scope')}</Button> : null}
                </div>
              </div>
              {canCreate ? <AddTargets scope={scope} /> : null}
              {canCreate ? <PassivePanel scope={scope} /> : null}
              <Panel title={t('Cele', 'Targets')} count={targets.data?.total} flush>
                <DataTable inPanel rows={targets.data?.items} cols={cols} rowKey={(x) => x.id} loading={targets.isPending} error={targets.error} retry={() => targets.refetch()} dim={targets.isPlaceholderData}
                  empty={<p className="p-3 text-sm text-ink-2">{t('Brak celów', 'No targets yet')}</p>}
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
      <Dialog open={confirm !== null} onClose={() => setConfirm(null)} width={440} title={confirm?.kind === 'scope' ? t('Usunąć zakres?', 'Delete scope?') : t('Usunąć cel?', 'Delete target?')}
        footer={<><Button onClick={() => setConfirm(null)}>{t('Anuluj', 'Cancel')}</Button><Button variant="dangerSolid" busy={remove.isPending} onClick={() => confirm && remove.mutate(confirm)}>{t('Usuń', 'Delete')}</Button></>}>
        <p className="text-sm"><span className="mono">{confirm?.label}</span>{confirm?.kind === 'scope' ? t('. Zakres i jego cele zostaną usunięte. Wyniki zostają.', '. The scope and its targets are deleted. Results stay.') : t('. Czujka przestanie skanować te adresy. Wyniki zostają.', '. Czujka stops scanning these addresses. Results stay.')}</p>
      </Dialog>
    </div>
  );
}
