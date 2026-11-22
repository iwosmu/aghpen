import { useEffect, useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router';
import { cx, fmtInt } from '../lib/format';
import { plural, t } from '../i18n';
import { Icon } from './Icon';
import { Button, Empty, ErrorState, SkeletonRows } from './kit';

export interface Col<T> {
  id: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  width?: number | string;
  align?: 'right';
  sort?: string;
  /** hide the column under this breakpoint */
  hide?: 'md' | 'lg' | 'xl' | '2xl';
  wrap?: boolean;
}

const HIDE = { md: 'hidden md:table-cell', lg: 'hidden lg:table-cell', xl: 'hidden xl:table-cell', '2xl': 'hidden 2xl:table-cell' };

export function useIsNarrow(px = 640): boolean {
  const [narrow, setNarrow] = useState(() => typeof window !== 'undefined' && window.matchMedia('(max-width: ' + (px - 1) + 'px)').matches);
  useEffect(() => {
    const mq = window.matchMedia('(max-width: ' + (px - 1) + 'px)');
    const fn = () => setNarrow(mq.matches);
    mq.addEventListener('change', fn);
    return () => mq.removeEventListener('change', fn);
  }, [px]);
  return narrow;
}

export interface TableProps<T> {
  rows: T[] | undefined;
  cols: Col<T>[];
  rowKey: (row: T) => string | number;
  rowHref?: (row: T) => string | undefined;
  onRowClick?: (row: T) => void;
  sort?: string;
  onSort?: (s: string) => void;
  selected?: Set<string | number>;
  onSelect?: (s: Set<string | number>) => void;
  loading?: boolean;
  error?: unknown;
  retry?: () => void;
  empty?: ReactNode;
  /** compact two-line rendering used under 640px */
  mobile?: (row: T) => ReactNode;
  rowClass?: (row: T) => string | undefined;
  dim?: boolean;
  caption?: string;
  /** the table sits inside a Panel: keep the narrow cell padding instead of the page gutter */
  inPanel?: boolean;
  /** consecutive rows with the same key sit under one small caps heading with their count */
  group?: (row: T) => { key: string; label: ReactNode };
  /** A short addition after a group's count, from the rows in that group. */
  groupNote?: (rows: T[]) => ReactNode;
}

/** Runs of rows that share a group key, in the order given. */
export function groupRuns<T>(rows: T[], group?: (row: T) => { key: string; label: ReactNode }): { key: string; label: ReactNode; rows: T[] }[] {
  if (!group) return [{ key: '', label: null, rows }];
  const out: { key: string; label: ReactNode; rows: T[] }[] = [];
  for (const r of rows) {
    const g = group(r);
    const last = out[out.length - 1];
    if (last && last.key === g.key) last.rows.push(r); else out.push({ key: g.key, label: g.label, rows: [r] });
  }
  return out;
}

export function GroupHead({ label, count, note, className }: { label: ReactNode; count: number; note?: ReactNode; className?: string }) {
  return <p className={cx('caps', className)}>{label} <span className="text-ink-3">· </span><span className="num">{count}</span>{note}</p>;
}

export function DataTable<T>(p: TableProps<T>) {
  const edge = p.inPanel ? 'first:pl-5 last:pr-5' : 'first:pl-5 last:pr-5 sm:first:pl-6 sm:last:pr-6';
  const navigate = useNavigate();
  const narrow = useIsNarrow();
  if (p.error) return <ErrorState error={p.error} retry={p.retry} />;
  if (p.loading && !p.rows) return <SkeletonRows rows={8} />;
  const rows = p.rows ?? [];
  if (rows.length === 0) return <>{p.empty ?? <Empty title={t('Brak wierszy', 'No rows')} />}</>;
  const sel = p.selected;
  const allSelected = sel ? rows.every((r) => sel.has(p.rowKey(r))) : false;
  const toggleAll = () => {
    if (!sel || !p.onSelect) return;
    const next = new Set(sel);
    if (allSelected) rows.forEach((r) => next.delete(p.rowKey(r)));
    else rows.forEach((r) => next.add(p.rowKey(r)));
    p.onSelect(next);
  };
  const toggle = (k: string | number) => {
    if (!sel || !p.onSelect) return;
    const next = new Set(sel);
    if (next.has(k)) next.delete(k); else next.add(k);
    p.onSelect(next);
  };
  const go = (row: T) => {
    if (p.onRowClick) return p.onRowClick(row);
    const href = p.rowHref?.(row);
    if (href) navigate(href);
  };
  const clickable = Boolean(p.rowHref || p.onRowClick);

  if (narrow && p.mobile) {
    return (
      <ul className={cx('transition-opacity', !p.inPanel && 'card mx-3 overflow-hidden rounded-[14px] py-1 sm:mx-6', p.dim && 'opacity-60')}>
        {groupRuns(rows, p.group).flatMap((g) => [
          ...(g.label ? [<li key={'g-' + g.key} className="px-4 pb-1.5 pt-4"><GroupHead label={g.label} count={g.rows.length} note={p.groupNote?.(g.rows)} /></li>] : []),
          ...g.rows.map((row) => {
          const k = p.rowKey(row);
          return (
            <li key={k} className={cx('flex items-start gap-2 border-b border-rule px-4 py-3 last:border-b-0', sel?.has(k) && 'bg-[var(--row-selected)]')}>
              {sel ? <input type="checkbox" className="mt-1" checked={sel.has(k)} onChange={() => toggle(k)} aria-label={t('Zaznacz wiersz', 'Select row')} /> : null}
              <div className="min-w-0 flex-1" onClick={clickable ? () => go(row) : undefined} role={clickable ? 'link' : undefined}>{p.mobile!(row)}</div>
            </li>
          );
        })])}
      </ul>
    );
  }

  return (
    <div className={cx('overflow-x-auto transition-opacity', !p.inPanel && 'card mx-3 rounded-[14px] sm:mx-6 lg:mx-8', p.dim && 'opacity-60')}>
      <table className="w-full min-w-max text-sm sm:min-w-0">
        {p.caption ? <caption className="sr-only">{p.caption}</caption> : null}
        <thead>
          <tr className="border-b border-rule text-left text-2xs text-ink-2">
            {sel ? (
              <th className={cx('w-[34px] px-3 py-0', edge)}>
                <input type="checkbox" checked={allSelected} onChange={toggleAll} aria-label={t('Zaznacz wszystkie', 'Select all')} />
              </th>
            ) : null}
            {p.cols.map((c) => {
              const active = c.sort && (p.sort === c.sort || p.sort === '-' + c.sort);
              const desc = p.sort === '-' + c.sort;
              return (
                <th key={c.id} scope="col" style={{ width: c.width }} className={cx('h-[44px] whitespace-nowrap px-3 py-0 font-medium', edge, c.align === 'right' && 'text-right', c.hide && HIDE[c.hide])} aria-sort={active ? (desc ? 'descending' : 'ascending') : undefined}>
                  {c.sort && p.onSort ? (
                    <button type="button" className={cx('inline-flex items-center gap-1 hover:text-ink', active && 'text-ink')} onClick={() => p.onSort!(p.sort === '-' + c.sort ? c.sort! : '-' + c.sort)}>
                      {c.header}
                      <Icon name={active ? (desc ? 'arrowDown' : 'arrowUp') : 'arrowDown'} size={10} className={active ? '' : 'opacity-30'} />
                    </button>
                  ) : c.header}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {groupRuns(rows, p.group).flatMap((g) => [
            ...(g.label ? [<tr key={'g-' + g.key} className="border-b border-rule"><td colSpan={p.cols.length + (sel ? 1 : 0)} className={cx('px-3 pb-2 pt-5', edge)}><GroupHead label={g.label} count={g.rows.length} note={p.groupNote?.(g.rows)} /></td></tr>] : []),
            ...g.rows.map((row) => {
            const k = p.rowKey(row);
            return (
              <tr
                key={k}
                onClick={clickable ? (e) => { if (!(e.target as HTMLElement).closest('a,button,input,select,label')) go(row); } : undefined}
                className={cx('border-b border-rule last:border-b-0', clickable && 'cursor-pointer hover:bg-[var(--row-hover)]', sel?.has(k) && 'bg-[var(--row-selected)]', p.rowClass?.(row))}
              >
                {sel ? (
                  <td className={cx('px-3 py-0', edge)}><input type="checkbox" checked={sel.has(k)} onChange={() => toggle(k)} aria-label={t('Zaznacz wiersz', 'Select row')} /></td>
                ) : null}
                {p.cols.map((c) => (
                  <td key={c.id} className={cx('h-[46px] px-3 py-1.5 align-middle', edge, c.align === 'right' && 'text-right', c.hide && HIDE[c.hide], !c.wrap && 'whitespace-nowrap')}>
                    {c.cell(row)}
                  </td>
                ))}
              </tr>
            );
          })])}
        </tbody>
      </table>
    </div>
  );
}

export function Pager({ total, limit, offset, onOffset }: { total: number; limit: number; offset: number; onOffset: (o: number) => void }) {
  if (total === 0) return null;
  if (total <= limit && offset === 0) {
    return <div className="px-5 py-3 text-xs text-ink-2 sm:px-8">{fmtInt(total)} {plural(total, ['wiersz', 'wiersze', 'wierszy'], ['row', 'rows'])}</div>;
  }
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(total, offset + limit);
  return (
    <div className="flex items-center justify-between gap-3 px-5 py-3 text-xs text-ink-2 sm:px-8">
      <span className="num">{fmtInt(from)}–{fmtInt(to)} {t('z', 'of')} {fmtInt(total)}</span>
      <span className="flex gap-1">
        <Button size="sm" icon="chevronLeft" disabled={offset <= 0} onClick={() => onOffset(Math.max(0, offset - limit))}>{t('Poprzednie', 'Previous')}</Button>
        <Button size="sm" disabled={to >= total} onClick={() => onOffset(offset + limit)}>{t('Następne', 'Next')}<Icon name="chevronRight" size={14} /></Button>
      </span>
    </div>
  );
}

/** A row of filters above the content they scope. */
export function FilterBar({ children, onClear, active, more, moreActive = 0 }: { children: ReactNode; onClear?: () => void; active?: number; more?: ReactNode; moreActive?: number }) {
  // search and up to two controls stay visible; the rest sits behind one 'Filtry' button
  const [open, setOpen] = useState(false);
  return (
    <div className="px-4 pb-4 sm:px-6 lg:px-8">
      <div className="flex flex-wrap items-end gap-2.5">
        {children}
        {more ? (
          <Button size="md" icon="filter" aria-expanded={open} onClick={() => setOpen((v) => !v)} data-testid="filters-more">
            {t('Filtry', 'Filters')}{moreActive ? <span className="num text-ink-2"> {moreActive}</span> : null}
          </Button>
        ) : null}
        {onClear && active ? (
          <Button variant="ghost" size="md" icon="x" onClick={onClear}>{t('Wyczyść filtry', 'Clear filters')} ({active})</Button>
        ) : null}
      </div>
      {more && open ? <div className="mt-3 flex flex-wrap items-end gap-2.5">{more}</div> : null}
    </div>
  );
}

export function FilterField({ label, children, width = 150 }: { label: string; children: ReactNode; width?: number }) {
  return (
    <label className="block" style={{ width }}>
      <span className="label mb-1.5 block pl-1">{label}</span>
      {children}
    </label>
  );
}

export function SearchField({ value, onChange, placeholder, width = 220 }: { value: string; onChange: (v: string) => void; placeholder?: string; width?: number }) {
  const [local, setLocal] = useState(value);
  useEffect(() => { setLocal(value); }, [value]);
  useEffect(() => {
    if (local === value) return;
    const id = setTimeout(() => onChange(local), 250);
    return () => clearTimeout(id);
  }, [local]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <label className="relative block" style={{ width }}>
      <Icon name="search" size={14} className="pointer-events-none absolute bottom-3 left-3 text-ink-3" />
      <input type="search" className="field pl-8" value={local} placeholder={placeholder} aria-label={t('Szukaj', 'Search')} onChange={(e) => setLocal(e.target.value)} />
    </label>
  );
}
