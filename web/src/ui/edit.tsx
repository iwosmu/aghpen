import { useEffect, useRef, useState, type ReactNode } from 'react';
import { download, qs, type Query } from '../api/client';
import type { Override } from '../api/types';
import { t } from '../i18n';
import { cx, fmtBytes, fmtDateTime, show } from '../lib/format';
import { Button, IconButton, toast, toastError } from './kit';
import { Icon } from './Icon';
import { useCan } from '../session';

/** A value that turns into an input on demand. Enter saves, Escape cancels. Without the permission it is plain text. */
export function InlineText({ value, onSave, canEdit, placeholder, mono, multiline, label, busy }: { value: string; onSave: (v: string) => void; canEdit: boolean; placeholder?: string; mono?: boolean; multiline?: boolean; label: string; busy?: boolean }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);
  const ref = useRef<HTMLInputElement & HTMLTextAreaElement>(null);
  useEffect(() => { if (editing) ref.current?.focus(); }, [editing]);
  const commit = () => { setEditing(false); if (draft.trim() !== value) onSave(draft.trim()); };
  if (!editing) {
    return (
      <span className="group inline-flex min-h-[24px] max-w-full items-start gap-1.5">
        <span className={cx('min-w-0 whitespace-pre-wrap break-words', mono && 'mono', !value && 'text-ink-3')}>{value || placeholder || '–'}</span>
        {canEdit ? <IconButton icon="edit" label={t('Edytuj: ', 'Edit: ') + label} disabled={busy} className="-my-1 flex-none opacity-60 hover:opacity-100 focus-visible:opacity-100" onClick={() => { setDraft(value); setEditing(true); }} /> : null}
      </span>
    );
  }
  const common = {
    ref, value: draft, 'aria-label': label, className: cx('field', mono && 'mono'),
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setDraft(e.target.value),
    onKeyDown: (e: React.KeyboardEvent) => {
      if (e.key === 'Escape') { e.preventDefault(); setEditing(false); }
      if (e.key === 'Enter' && (!multiline || e.metaKey || e.ctrlKey)) { e.preventDefault(); commit(); }
    },
  };
  return (
    <span className="flex w-full items-start gap-1.5">
      {multiline ? <textarea rows={3} {...common} /> : <input {...common} />}
      <Button size="sm" variant="primary" onClick={commit}>{t('Zapisz', 'Save')}</Button>
      <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>{t('Anuluj', 'Cancel')}</Button>
    </span>
  );
}

/** Shows that an analyst replaced an observed value, and lets an editor give the field back to the scanner. */
export function OverrideNote({ o, onRevert, canEdit }: { o: Override | undefined; onRevert: () => void; canEdit: boolean }) {
  if (!o) return null;
  return (
    <span className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-ink-2" data-testid="override-note">
      <Icon name="edit" size={12} className="text-st-changed" />
      <span>{t('skaner zaobserwował', 'the scanner observed')} <span className="mono text-ink">{show(o.observed) || t('(pusto)', '(empty)')}</span>, {t('analityk ustawił', 'the analyst set')} <span className="mono text-ink">{show(o.value)}</span></span>
      <span className="text-ink-3">{o.by} · {fmtDateTime(o.at)}</span>
      {canEdit ? <button type="button" className="link inline-flex items-center gap-1" onClick={onRevert}><Icon name="undo" size={12} />{t('Przywróć wartość ze skanu', 'Restore scanned value')}</button> : null}
    </span>
  );
}

/** Export of the rows the current filters select. Not rendered without export:run. */
export function ExportButtons({ kind, query, label }: { kind: 'hosts' | 'services' | 'findings' | 'changes'; query?: Query; label?: ReactNode }) {
  const can = useCan('export:run');
  const [busy, setBusy] = useState('');
  if (!can) return null;
  const run = async (fmt: 'json' | 'csv') => {
    setBusy(fmt);
    try {
      const q: Query = { ...(query ?? {}) };
      delete q.limit; delete q.offset;
      const size = await download('/export/' + kind + '.' + fmt + qs(q), 'czujka-' + kind + '.' + fmt);
      toast(t('Pobrano plik czujka-' + kind + '.' + fmt + ' (' + fmtBytes(size) + ')', 'Downloaded czujka-' + kind + '.' + fmt + ' (' + fmtBytes(size) + ')'));
    } catch (e) { toastError(e); }
    setBusy('');
  };
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="hidden text-xs text-ink-3 lg:inline">{label ?? t('Eksport widoku', 'Export view')}</span>
      <Button size="sm" icon="download" busy={busy === 'csv'} onClick={() => run('csv')}>CSV</Button>
      <Button size="sm" icon="download" busy={busy === 'json'} onClick={() => run('json')}>JSON</Button>
    </span>
  );
}

/** Debounced copy of a fast-changing value. */
export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => { const id = setTimeout(() => setV(value), ms); return () => clearTimeout(id); }, [value, ms]);
  return v;
}

/** A text filter that writes to the URL after a short pause. */
export function useDraft(value: string, commit: (v: string) => void, ms = 300): [string, (v: string) => void] {
  const [draft, setDraft] = useState(value);
  const last = useRef(value);
  useEffect(() => { if (value !== last.current) { last.current = value; setDraft(value); } }, [value]);
  useEffect(() => {
    if (draft === last.current) return;
    const id = setTimeout(() => { last.current = draft; commit(draft); }, ms);
    return () => clearTimeout(id);
  }, [draft]); // eslint-disable-line react-hooks/exhaustive-deps
  return [draft, setDraft];
}
