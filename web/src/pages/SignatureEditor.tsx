import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { useAction, useItem } from '../api/hooks';
import { del, patch, post } from '../api/client';
import type { RetroHuntResult, Signature, SignatureValidation } from '../api/types';
import { t, plural } from '../i18n';
import { cx, fmtInt } from '../lib/format';
import { Button, Dialog, ErrorState, InlineError, PageHeader, Panel, SkeletonRows, Spinner } from '../ui/kit';
import { Icon } from '../ui/Icon';
import { Confidence, Glyph } from '../ui/marks';
import { useDebounced } from '../ui/edit';
import { useSession } from '../session';
import { Switch } from './Signatures';

const TEMPLATE = [
  'id: moja-sygnatura',
  'name: Moja sygnatura',
  'category: panel',
  'description: Co rozpoznaje ta regula',
  'safe: true',
  'paths: [/login]',
  'match:',
  '  any:',
  '    - type: title',
  '      regex: (?i)sign in',
  '      weight: 0.6',
  '    - type: header',
  '      name: Server',
  '      regex: (?i)nginx',
  '      weight: 0.3',
  '',
].join('\n');

/** Finds the line a validation path points at, so the gutter can mark it. */
function lineOfPath(yaml: string, path: string): number {
  const lines = yaml.split('\n');
  const m = /^match\.(any|all)\[(\d+)\]\.(\w+)$/.exec(path);
  if (m) {
    let idx = -1;
    let inMatch = false;
    for (let i = 0; i < lines.length; i++) {
      if (/^match:/.test(lines[i])) { inMatch = true; continue; }
      if (inMatch && /^\S/.test(lines[i])) inMatch = false;
      if (!inMatch) continue;
      if (/^\s*- /.test(lines[i])) idx++;
      if (idx === Number(m[2]) && new RegExp('^\\s*(- )?' + m[3] + ':').test(lines[i])) return i;
    }
    return -1;
  }
  const key = path.split('.')[0];
  return key ? lines.findIndex((l) => l.startsWith(key + ':')) : -1;
}

export default function SignatureEditor() {
  const params = useParams();
  const [sp] = useSearchParams();
  const isNew = !params.id;
  const id = Number(params.id ?? 0);
  const fromId = Number(sp.get('from') ?? 0);
  const navigate = useNavigate();
  const { can } = useSession();
  const q = useItem<Signature>('/signatures/' + (isNew ? fromId : id), undefined, { enabled: !isNew || fromId > 0 });
  const [yaml, setYaml] = useState<string | null>(isNew && !fromId ? TEMPLATE : null);
  const [enabled, setEnabled] = useState(true);
  const [hunt, setHunt] = useState<{ yaml: string; result: RetroHuntResult } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const gutter = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!q.data || yaml !== null) return;
    setYaml(isNew ? q.data.yaml.replace(/^id:\s*(.+)$/m, 'id: $1-kopia').replace(/^name:\s*(.+)$/m, 'name: $1 (kopia)') : q.data.yaml);
    if (!isNew) setEnabled(q.data.enabled);
  }, [q.data]); // eslint-disable-line react-hooks/exhaustive-deps
  const sig = isNew ? null : q.data;
  const builtin = Boolean(sig?.builtin);
  const canWrite = isNew ? can('signatures:create') : can('signatures:update') && !builtin;
  const debounced = useDebounced(yaml ?? '', 350);
  const validation = useQuery<SignatureValidation>({ queryKey: ['/signatures/validate', debounced], queryFn: () => post<SignatureValidation>('/signatures/validate', { yaml: debounced }), enabled: debounced.length > 0, placeholderData: (p) => p, staleTime: 60_000 });
  const retro = useAction((y: string) => post<RetroHuntResult>('/signatures/retrohunt', { yaml: y }), { onSuccess: (r, y) => setHunt({ yaml: y, result: r }) });
  const save = useAction(() => (isNew ? post<Signature>('/signatures', { yaml, enabled }) : patch<Signature>('/signatures/' + id, { yaml, enabled })), {
    invalidate: ['/signatures'], silent: true, success: t('Sygnatura zapisana', 'Signature saved'), onSuccess: (s) => { if (isNew) navigate('/signatures/' + s.id, { replace: true }); },
  });
  const toggle = useAction((v: boolean) => patch<Signature>('/signatures/' + id, { enabled: v }), { invalidate: ['/signatures'], onSuccess: (s) => setEnabled(s.enabled) });
  const remove = useAction(() => del('/signatures/' + id), { invalidate: ['/signatures'], success: t('Sygnatura usunięta', 'Signature deleted'), onSuccess: () => navigate('/signatures') });

  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (yaml === null) return <SkeletonRows rows={12} />;
  const v = validation.data;
  const issues = v?.issues ?? [];
  const pending = validation.isFetching || debounced !== yaml;
  const lines = yaml.split('\n');
  const marks = new Map<number, 'safety' | 'error' | 'warning'>();
  for (const i of issues) {
    const ln = lineOfPath(yaml, i.path);
    if (ln < 0) continue;
    const level = i.safety ? 'safety' : i.level === 'error' ? 'error' : 'warning';
    const cur = marks.get(ln);
    if (!cur || level === 'safety' || (level === 'error' && cur === 'warning')) marks.set(ln, level);
  }
  const errors = issues.filter((i) => i.level === 'error');
  const safety = issues.filter((i) => i.safety);
  const dirty = isNew || yaml !== sig?.yaml || enabled !== sig?.enabled;
  const huntFresh = hunt !== null && hunt.yaml === yaml;
  return (
    <div>
      <PageHeader
        back={{ to: '/signatures', label: t('Sygnatury', 'Signatures') }}
        title={isNew ? t('Nowa sygnatura', 'New signature') : sig?.name ?? ''}
        sub={builtin ? t('Sygnatura wbudowana: treści nie można zmienić. Można ją wyłączyć albo skopiować jako własną.', 'A built-in signature: its text cannot be changed. You can disable it or copy it as your own.') : t('Edytor reguły w YAML. Walidacja działa w trakcie pisania, a test na zapisanych wynikach nie wysyła żadnego pakietu.', 'The YAML rule editor. Validation runs as you type, and the test on stored results sends no packet.')}
        readOnly={!canWrite && !(builtin && can('signatures:update'))}
        actions={<>
          {builtin && can('signatures:update') ? <span className="flex items-center gap-2 text-sm text-ink-2">{t('Aktywna', 'Active')}<Switch checked={enabled} disabled={toggle.isPending} onChange={(x) => toggle.mutate(x)} label={t('Sygnatura aktywna', 'Signature active')} /></span> : null}
          {!isNew && can('signatures:create') ? <Button icon="copy" onClick={() => navigate('/signatures/new?from=' + id)}>{t('Kopiuj jako własną', 'Copy as custom')}</Button> : null}
          {!isNew && !builtin && can('signatures:delete') ? <Button variant="danger" icon="trash" onClick={() => setConfirmDelete(true)}>{t('Usuń', 'Delete')}</Button> : null}
          {canWrite ? <Button variant="primary" icon="check" busy={save.isPending} disabled={!v?.ok || pending || !dirty} onClick={() => save.mutate(undefined)}>{t('Zapisz sygnaturę', 'Save the signature')}</Button> : null}
        </>}
      />
      <div className="grid gap-4 p-4 sm:p-6 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <div className="min-w-0">
          <div className="flex items-center justify-between gap-3 border border-b-0 border-rule bg-panel px-3 py-1.5 text-xs text-ink-2">
            <span className="mono">{isNew ? t('nowa.yaml', 'new.yaml') : (sig?.slug ?? '') + '.yaml'}</span>
            {canWrite ? <span className="flex items-center gap-2">{t('Aktywna po zapisie', 'Active after saving')}<Switch checked={enabled} onChange={setEnabled} label={t('Aktywna po zapisie', 'Active after saving')} /></span> : null}
          </div>
          <div className="relative flex border border-rule bg-[var(--sunk)]" style={{ height: 'max(360px, calc(100dvh - 330px))' }}>
            <div ref={gutter} className="mono w-[46px] flex-none select-none overflow-hidden border-r border-rule py-2 text-right text-xs leading-[20px] text-ink-3" aria-hidden="true">
              {lines.map((_, i) => {
                const m = marks.get(i);
                return <div key={i} className={cx('pr-2', m === 'safety' && 'bg-danger-solid text-danger-ink', m === 'error' && 'bg-st-gone-wash text-danger', m === 'warning' && 'bg-st-changed-wash text-ink')}>{i + 1}</div>;
              })}
            </div>
            <textarea
              className="mono min-w-0 flex-1 resize-none whitespace-pre bg-transparent px-3 py-2 text-xs leading-[20px] text-ink outline-none focus-visible:outline-none"
              style={{ tabSize: 2 }} spellCheck={false} wrap="off" value={yaml} readOnly={!canWrite}
              aria-label={t('Treść sygnatury w YAML', 'Signature text in YAML')} aria-invalid={errors.length > 0}
              onScroll={(e) => { if (gutter.current) gutter.current.scrollTop = e.currentTarget.scrollTop; }}
              onChange={(e) => setYaml(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Tab' && !e.shiftKey && canWrite) {
                  e.preventDefault();
                  const el = e.currentTarget, s = el.selectionStart, en = el.selectionEnd;
                  const next = yaml.slice(0, s) + '  ' + yaml.slice(en);
                  setYaml(next);
                  requestAnimationFrame(() => { el.selectionStart = el.selectionEnd = s + 2; });
                }
              }}
            />
          </div>
          <p className="mt-1.5 text-2xs text-ink-3">{t('Tab wstawia dwie spacje. Escape, potem Tab przenosi fokus dalej.', 'Tab inserts two spaces. Escape, then Tab moves the focus on.')}</p>
          <div className="mt-2"><InlineError error={save.error} /></div>
        </div>

        <div className="min-w-0 space-y-4">
          <Panel title={t('Walidacja', 'Validation')} actions={pending ? <span className="inline-flex items-center gap-1.5 text-ink-3"><Spinner />{t('sprawdzam', 'checking')}</span> : undefined}>
            {validation.error ? <InlineError error={validation.error} /> : !v ? <div className="skeleton h-10" /> : (
              <div data-testid="validation">
                <p className="flex items-center gap-2 text-sm font-medium">
                  {safety.length ? <><Icon name="shield" className="text-danger" />{t('Sygnatura łamie zasadę bezpiecznej detekcji', 'The signature breaks the safe-detection rule')}</>
                    : v.ok ? <><Glyph name="check" tone="new" />{t('Sygnatura jest poprawna i bezpieczna', 'The signature is valid and safe')}</>
                    : <><Glyph name="x" tone="gone" />{errors.length} {plural(errors.length, ['błąd', 'błędy', 'błędów'], ['error', 'errors'])}</>}
                </p>
                {issues.length ? (
                  <ul className="mt-2 border-t border-rule">
                    {issues.map((i, n) => {
                      const ln = lineOfPath(yaml, i.path);
                      return (
                        <li key={n} className={cx('border-b border-rule py-1.5 pl-2 text-sm', i.safety && 'bg-st-gone-wash')}>
                          <div className="flex flex-wrap items-center gap-x-2 text-xs">
                            {i.safety ? <span className="inline-flex items-center gap-1 font-medium text-danger"><Icon name="shield" size={12} />{t('bezpieczeństwo', 'safety')}</span> : i.level === 'error' ? <span className="inline-flex items-center gap-1 text-danger"><Glyph name="x" tone="gone" size={11} />{t('błąd', 'error')}</span> : <span className="inline-flex items-center gap-1 text-ink-2"><Glyph name="delta" tone="changed" size={11} />{t('ostrzeżenie', 'warning')}</span>}
                            {i.path ? <span className="mono text-ink-2">{i.path}</span> : null}
                            {ln >= 0 ? <span className="num text-ink-3">{t('wiersz', 'line')} {ln + 1}</span> : null}
                          </div>
                          <div className="mt-0.5 text-ink">{i.message}</div>
                        </li>
                      );
                    })}
                  </ul>
                ) : null}
                {(v.paths ?? []).length ? <p className="mt-2 text-xs text-ink-2">{t('Dodatkowe żądania GET na usługę:', 'Extra GET requests per service:')} {(v.paths ?? []).map((p) => <span key={p} className="mono mr-2 text-ink">{p}</span>)}</p> : <p className="mt-2 text-xs text-ink-3">{t('Sygnatura nie prosi o dodatkowe ścieżki: korzysta z danych już zebranych.', 'The signature asks for no extra path: it uses data that is already collected.')}</p>}
              </div>
            )}
          </Panel>

          <Panel title={t('Test na zapisanych wynikach', 'Test on stored results')} actions={<Button size="sm" icon="history" busy={retro.isPending} disabled={!v?.ok || pending} onClick={() => retro.mutate(yaml)}>{t('Uruchom test', 'Run the test')}</Button>}>
            {!hunt ? <p className="text-sm text-ink-2">{t('Sprawdź regułę na danych z poprzednich skanów, zanim ją zapiszesz. Test czyta bazę i nie dotyka sieci.', 'Check the rule against data of earlier scans before you save it. The test reads the database and does not touch the network.')}</p> : (
              <div className={cx(!huntFresh && 'opacity-60')} data-testid="retrohunt">
                <p className="text-sm">
                  {t('Dopasowano ', 'Matched ')}<span className="num text-base font-semibold">{fmtInt((hunt.result.hits ?? []).length)}</span> {plural((hunt.result.hits ?? []).length, ['zapisaną usługę', 'zapisane usługi', 'zapisanych usług'], ['stored service', 'stored services'])}{t(', wysłano ', ', ')}<span className="num text-base font-semibold">{hunt.result.packets_sent}</span> {t('pakietów.', 'packets sent.')}
                </p>
                <p className="text-xs text-ink-3">{t('Przejrzano ' + fmtInt(hunt.result.scanned) + ' obserwacji w ' + hunt.result.took_ms + ' ms.', 'Checked ' + fmtInt(hunt.result.scanned) + ' observations in ' + hunt.result.took_ms + ' ms.')}{!huntFresh ? ' ' + t('Treść zmieniła się od tego testu.', 'The text has changed since this test.') : ''}</p>
                {(hunt.result.hits ?? []).length ? (
                  <ul className="mt-2 max-h-[300px] overflow-auto border-t border-rule">
                    {(hunt.result.hits ?? []).map((h) => (
                      <li key={h.service_id} className="border-b border-rule py-1.5">
                        <div className="flex items-center justify-between gap-3"><Link to={'/services/' + h.service_id} className="mono link text-sm">{h.ip}:{h.port}</Link><Confidence value={h.match.confidence} width={40} /></div>
                        {(h.match.evidence ?? []).slice(0, 2).map((e, i) => <div key={i} className="mono truncate text-xs text-ink-2"><span className="font-sans text-ink-3">{e.where}</span> {e.snippet}</div>)}
                      </li>
                    ))}
                  </ul>
                ) : <p className="mt-2 text-sm text-ink-2">{t('Żadna zapisana usługa nie pasuje. Reguła może być zbyt wąska.', 'No stored service matches. The rule may be too narrow.')}</p>}
              </div>
            )}
          </Panel>
        </div>
      </div>
      <Dialog open={confirmDelete} onClose={() => setConfirmDelete(false)} title={t('Usunąć sygnaturę?', 'Delete the signature?')} width={420}
        footer={<><Button onClick={() => setConfirmDelete(false)}>{t('Anuluj', 'Cancel')}</Button><Button variant="dangerSolid" busy={remove.isPending} onClick={() => remove.mutate(undefined)}>{t('Usuń sygnaturę', 'Delete the signature')}</Button></>}>
        <p className="text-sm">{t('Dotychczasowe dopasowania zostają w historii. Kolejne skany nie będą już używać tej reguły.', 'Past matches stay in the history. Later scans no longer use this rule.')}</p>
      </Dialog>
    </div>
  );
}
