import { useState } from 'react';
import { useAction, useItem } from '../api/hooks';
import { ApiError, post, put, upload } from '../api/client';
import type { PassiveCandidate, PassiveResult, PassiveSettings, Scope, TargetPreview } from '../api/types';
import { t, plural } from '../i18n';
import { cx, fmtInt, fmtRelative } from '../lib/format';
import { Button, Check, InlineError, Panel, Tabs, FileInput } from '../ui/kit';
import { Glyph } from '../ui/marks';
import { useSession } from '../session';
import { Switch } from './Signatures';

type Source = 'file' | 'ptr' | 'crtsh';

/** What the passive sources found: candidates to confirm as targets, hostname hints for known hosts, facts outside every scope. */
function ResultView({ res, scope, onDone }: { res: PassiveResult; scope: Scope; onDone: () => void }) {
  const { can } = useSession();
  const cands = res.candidates ?? [];
  const [picked, setPicked] = useState<Set<string>>(() => new Set(cands.map((c) => c.value)));
  const confirm = useAction((list: PassiveCandidate[]) => post<TargetPreview>('/passive/confirm', { scope_id: scope.id, candidates: list.map((c) => ({ value: c.value, sources: c.sources, note: c.reason })) }), {
    invalidate: ['/scopes', '/targets'],
    success: (r) => t('Dodano ' + r.valid.length + ' ' + plural(r.valid.length, ['cel', 'cele', 'celów'], ['', '']) + ' do zakresu „' + scope.name + '”.', 'Targets added to the scope "' + scope.name + '": ' + r.valid.length + '.'),
    onSuccess: onDone,
  });
  const toggle = (v: string, on: boolean) => { const n = new Set(picked); if (on) n.add(v); else n.delete(v); setPicked(n); };
  const hints = res.hints ?? [];
  const oos = res.out_of_scope ?? [];
  return (
    <div className="space-y-3" data-testid="passive-result">
      <p className="text-sm text-ink-2">
        <span className="num text-ink">{fmtInt((res.facts ?? []).length)}</span> {plural((res.facts ?? []).length, ['fakt w zakresie', 'fakty w zakresie', 'faktów w zakresie'], ['fact in scope', 'facts in scope'])}
        {' · '}<span className="num text-ink">{cands.length}</span> {plural(cands.length, ['kandydat', 'kandydaci', 'kandydatów'], ['candidate', 'candidates'])}
        {' · '}<span className="num text-ink">{hints.length}</span> {t('podpowiedzi nazw', 'name hints')}
        {' · '}<span className="num text-ink">{oos.length}</span> {t('poza zakresem', 'out of scope')}
        {res.hosts_updated !== undefined ? <>{' · '}{t('hosty z nową nazwą', 'hosts named')}: <span className="num text-ink">{res.hosts_updated}</span></> : null}
      </p>
      {res.file ? <p className="text-xs text-ink-3">{t('Plik', 'File')}: {res.file.format}, {t('rekordy', 'records')}: {fmtInt(res.file.records)}, {t('pominięte', 'skipped')}: {fmtInt(res.file.skipped)}, {t('błędne', 'invalid')}: {fmtInt(res.file.invalid_total)}{(res.file.invalid ?? []).slice(0, 3).map((i) => <span key={i.line} className="block">{t('wiersz', 'line')} <span className="num">{i.line}</span>: <span className="mono">{i.value}</span>: {i.reason}</span>)}</p> : null}
      {(res.sources ?? []).filter((s) => s.error || s.skipped).map((s) => <p key={s.name} className="flex items-start gap-1.5 text-xs text-st-changed"><Glyph name="delta" tone="changed" size={12} />{s.name}: {s.skipped ? t('pominięte (źródło zewnętrzne wyłączone)', 'skipped (external source disabled)') : s.error}</p>)}
      {cands.length ? (
        <div className="border border-rule">
          <div className="flex items-center justify-between gap-2 border-b border-rule bg-raised px-3 py-1.5 text-xs text-ink-2">
            <span>{t('Kandydaci na cele', 'Target candidates')}</span>
            <button type="button" className="link" onClick={() => setPicked(picked.size === cands.length ? new Set() : new Set(cands.map((c) => c.value)))}>{picked.size === cands.length ? t('odznacz wszystkie', 'clear all') : t('zaznacz wszystkie', 'select all')}</button>
          </div>
          <ul className="max-h-[300px] overflow-auto">
            {cands.map((c) => (
              <li key={c.value} className="border-b border-rule px-3 py-1.5 last:border-b-0">
                <Check checked={picked.has(c.value)} onChange={(v) => toggle(c.value, v)} label={<span><span className="mono">{c.value}</span>{c.hostnames?.length ? <span className="ml-2 text-xs text-ink-2">{c.hostnames.join(', ')}</span> : null}</span>}
                  hint={<>{c.reason} <span className="text-ink-3">· {c.sources.join(', ')}{c.ports?.length ? ' · ' + t('porty ', 'ports ') + c.ports.join(', ') : ''}{c.last_seen ? ' · ' + fmtRelative(c.last_seen) : ''}</span></>} />
              </li>
            ))}
          </ul>
          {can('targets:create') ? (
            <div className="flex items-center justify-between gap-2 border-t border-rule px-3 py-2">
              <InlineError error={confirm.error} />
              <Button variant="primary" icon="plus" size="sm" busy={confirm.isPending} disabled={picked.size === 0} onClick={() => confirm.mutate(cands.filter((c) => picked.has(c.value)))} data-testid="passive-confirm">
                {t('Dodaj ' + picked.size + ' jako cele', 'Add ' + picked.size + ' as targets')}
              </Button>
            </div>
          ) : null}
        </div>
      ) : <p className="text-sm text-ink-2">{t('Brak nowych kandydatów', 'No new candidates')}</p>}
      {hints.length ? (
        <details className="border border-rule px-3 py-1.5 text-sm">
          <summary className="cursor-pointer text-ink-2">{t('Podpowiedzi nazw dla adresów w zakresie', 'Name hints for addresses in scope')} ({hints.length})</summary>
          <ul className="mt-1">{hints.map((h) => <li key={h.ip} className="flex gap-2 py-0.5 text-xs"><span className="mono w-[120px] flex-none">{h.ip}</span><span className="text-ink-2">{h.hostnames.join(', ')}</span>{h.known ? <span className="ml-auto text-ink-3">{t('znany host', 'known host')}</span> : null}</li>)}</ul>
        </details>
      ) : null}
      {oos.length ? (
        <details className="border border-rule px-3 py-1.5 text-sm">
          <summary className="cursor-pointer text-ink-2">{t('Poza zakresami (nieskanowane)', 'Outside every scope (not scanned)')} ({oos.length})</summary>
          <ul className="mt-1">{oos.slice(0, 50).map((f, i) => <li key={i} className="flex gap-2 py-0.5 text-xs"><span className="mono">{f.ip || f.hostname}</span><span className="text-ink-3">{f.kind} · {f.source}</span></li>)}</ul>
        </details>
      ) : null}
    </div>
  );
}

function CrtshTab({ run, busy }: { run: () => void; busy: boolean }) {
  const { can } = useSession();
  const admin = can('integrations:manage');
  const settings = useItem<PassiveSettings>('/settings/passive', undefined, { enabled: admin });
  const save = useAction((v: boolean) => put<PassiveSettings>('/settings/passive', { crtsh_enabled: v }), { invalidate: ['/settings/passive'], success: t('Ustawienie zapisane', 'Setting saved') });
  const enabled = settings.data?.crtsh_enabled;
  return (
    <div className="space-y-3">
      <p className="flex items-start gap-2 border border-rule-strong bg-st-changed-wash px-3 py-2 text-sm">
        <Glyph name="delta" tone="changed" />
        <span>{t('crt.sh to usługa zewnętrzna. Zapytanie wysyła do niej nazwy domen z zakresu.', 'crt.sh is an external service. A query sends it the domain names of the scope.')}</span>
      </p>
      {admin ? (
        <label className="flex items-center gap-2 text-sm">
          <Switch checked={Boolean(enabled)} disabled={save.isPending || !settings.data} onChange={(v) => save.mutate(v)} label={t('Pozwól na zapytania do crt.sh', 'Allow queries to crt.sh')} />
          {t('Pozwól na zapytania do crt.sh', 'Allow queries to crt.sh')}
        </label>
      ) : null}
      <Button icon="globe" busy={busy} disabled={admin && !enabled} onClick={run}>{t('Zapytaj crt.sh o certyfikaty domen zakresu', 'Ask crt.sh for the certificates of the scope domains')}</Button>
    </div>
  );
}

export function PassivePanel({ scope }: { scope: Scope }) {
  const { can } = useSession();
  const [tab, setTab] = useState<Source>('file');
  const [file, setFile] = useState<File | null>(null);
  const [res, setRes] = useState<PassiveResult | null>(null);
  const [disabled, setDisabled] = useState(false);
  const runIt = useAction(async (src: Source) => {
    setDisabled(false);
    if (src === 'file') { const fd = new FormData(); fd.append('file', file!); return upload<PassiveResult>('/passive/import', fd); }
    if (src === 'ptr') return post<PassiveResult>('/passive/ptr');
    try { return await post<PassiveResult>('/passive/crtsh'); } catch (e) { if (e instanceof ApiError && e.status === 409) setDisabled(true); throw e; }
  }, { silent: true, invalidate: ['/hosts'], onSuccess: (r) => setRes(r) });
  const tabs: { id: Source; label: string }[] = [
    { id: 'file', label: t('Plik (strefa DNS, CSV, JSON)', 'File (DNS zone, CSV, JSON)') },
    ...(can('results:update') ? [{ id: 'ptr' as Source, label: t('Odwrotny DNS', 'Reverse DNS') }] : []),
    { id: 'crtsh', label: 'crt.sh' },
  ];
  return (
    <Panel title={t('Źródła pasywne', 'Passive sources')}>
      <Tabs value={tab} onChange={(v) => { setTab(v as Source); setRes(null); runIt.reset(); }} tabs={tabs} />
      <div className="mt-3 space-y-3">
        {tab === 'file' ? (
          <div className="flex flex-wrap items-end gap-2">
            <label className="block min-w-[240px] flex-1">
              <span className="label mb-1 block">{t('Plik ze strefą DNS, CSV, JSON albo JSONL (nazwy i adresy)', 'A DNS zone, CSV, JSON or JSONL file (names and addresses)')}</span>
              <FileInput testId="passive-file" file={file} onFile={setFile} />
            </label>
            <Button icon="upload" busy={runIt.isPending} disabled={!file} onClick={() => runIt.mutate('file')}>{t('Importuj', 'Import')}</Button>
          </div>
        ) : tab === 'ptr' ? (
          <div className="space-y-2">
            <Button icon="refresh" busy={runIt.isPending} onClick={() => runIt.mutate('ptr')} data-testid="passive-ptr">{t('Uruchom odwrotny DNS', 'Run reverse DNS')}</Button>
          </div>
        ) : <CrtshTab run={() => runIt.mutate('crtsh')} busy={runIt.isPending} />}
        {disabled ? <p className="text-sm text-ink-2">{t('crt.sh jest wyłączone. Włącza je administrator.', 'crt.sh is off. An administrator turns it on.')}</p> : <InlineError error={runIt.error} />}
        {res ? <div className={cx(runIt.isPending && 'opacity-60')}><ResultView key={JSON.stringify(res.candidates?.map((c) => c.value))} res={res} scope={scope} onDone={() => setRes(null)} /></div> : null}
      </div>
    </Panel>
  );
}
