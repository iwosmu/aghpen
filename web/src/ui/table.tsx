import { useEffect, useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router';
import { cx, fmtInt } from '../lib/format';
import { t } from '../i18n';
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
  hide?: 'md' | 'lg' | 'xl';
  wrap?: boolean;
}

const HIDE = { md: 'hidden md:table-cell', lg: 'hidden lg:table-cell', xl: 'hidden xl:table-cell' };

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
}

export function DataTable<T>(p: TableProps<T>) {
  const edge = p.inPanel ? '' : 'first:pl-4 last:pr-4 sm:first:pl-6 sm:last:pr-6';
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
      <ul className={cx('transition-opacity', p.dim && 'opacity-60')}>
        {rows.map((row) => {
          const k = p.rowKey(row);
          return (
            <li key={k} className={cx('flex items-start gap-2 border-b border-rule px-4 py-2.5', sel?.has(k) && 'bg-accent-wash')}>
              {sel ? <input type="checkbox" className="mt-1" checked={sel.has(k)} onChange={() => toggle(k)} aria-label={t('Zaznacz wiersz', 'Select row')} /> : null}
              <div className="min-w-0 flex-1" onClick={clickable ? () => go(row) : undefined} role={clickable ? 'link' : undefined}>{p.mobile!(row)}</div>
            </li>
          );
        })}
      </ul>
    );
  }

  return (
    <div className={cx('overflow-x-auto transition-opacity', p.dim && 'opacity-60')}>
      <table className="w-full min-w-max text-sm sm:min-w-0">
        {p.caption ? <caption className="sr-only">{p.caption}</caption> : null}
        <thead>
          <tr className="border-b border-rule-strong text-left text-xs text-ink-3">
            {sel ? (
              <th className={cx('w-[34px] px-3 py-0', edge)}>
                <input type="checkbox" checked={allSelected} onChange={toggleAll} aria-label={t('Zaznacz wszystkie', 'Select all')} />
              </th>
            ) : null}
            {p.cols.map((c) => {
              const active = c.sort && (p.sort === c.sort || p.sort === '-' + c.sort);
              const desc = p.sort === '-' + c.sort;
              return (
                <th key={c.id} scope="col" style={{ width: c.width }} className={cx('h-[30px] whitespace-nowrap px-3 py-0 font-medium', edge, c.align === 'right' && 'text-right', c.hide && HIDE[c.hide])} aria-sort={active ? (desc ? 'descending' : 'ascending') : undefined}>
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
          {rows.map((row) => {
            const k = p.rowKey(row);
            return (
              <tr
                key={k}
                onClick={clickable ? (e) => { if (!(e.target as HTMLElement).closest('a,button,input,select,label')) go(row); } : undefined}
                className={cx('border-b border-rule last:border-b-0', clickable && 'cursor-pointer hover:bg-raised', sel?.has(k) && 'bg-accent-wash', p.rowClass?.(row))}
              >
                {sel ? (
                  <td className={cx('px-3 py-0', edge)}><input type="checkbox" checked={sel.has(k)} onChange={() => toggle(k)} aria-label={t('Zaznacz wiersz', 'Select row')} /></td>
                ) : null}
                {p.cols.map((c) => (
                  <td key={c.id} className={cx('h-[30px] px-3 py-1 align-middle', edge, c.align === 'right' && 'text-right', c.hide && HIDE[c.hide], !c.wrap && 'whitespace-nowrap')}>
                    {c.cell(row)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function Pager({ total, limit, offset, onOffset }: { total: number; limit: number; offset: number; onOffset: (o: number) => void }) {
  if (total === 0) return null;
  if (total <= limit && offset === 0) {
    return <div className="border-t border-rule px-4 py-2 text-xs text-ink-3 sm:px-6">{fmtInt(total)} {t('wierszy', 'rows')}</div>;
  }
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(total, offset + limit);
  return (
    <div className="flex items-center justify-between gap-3 border-t border-rule px-4 py-2 text-xs text-ink-3 sm:px-6">
      <span className="num">{fmtInt(from)}–{fmtInt(to)} {t('z', 'of')} {fmtInt(total)}</span>
      <span className="flex gap-1">
        <Button size="sm" icon="chevronLeft" disabled={offset <= 0} onClick={() => onOffset(Math.max(0, offset - limit))}>{t('Poprzednie', 'Previous')}</Button>
        <Button size="sm" disabled={to >= total} onClick={() => onOffset(offset + limit)}>{t('Następne', 'Next')}<Icon name="chevronRight" size={14} /></Button>
      </span>
    </div>
  );
}

/** A row of filters above the content they scope. */
export function FilterBar({ children, onClear, active }: { children: ReactNode; onClear?: () => void; active?: number }) {
  return (
    <div className="flex flex-wrap items-end gap-2 border-b border-rule px-4 py-2.5 sm:px-6">
      {children}
      {onClear && active ? (
        <Button variant="ghost" size="md" icon="x" onClick={onClear}>{t('Wyczyść filtry', 'Clear filters')} ({active})</Button>
      ) : null}
    </div>
  );
}

export function FilterField({ label, children, width = 150 }: { label: string; children: ReactNode; width?: number }) {
  return (
    <label className="block" style={{ width }}>
      <span className="label mb-1 block">{label}</span>
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
      <span className="label mb-1 block">{t('Szukaj', 'Search')}</span>
      <Icon name="search" size={14} className="pointer-events-none absolute bottom-2 left-2 text-ink-3" />
      <input type="search" className="field pl-7" value={local} placeholder={placeholder} onChange={(e) => setLocal(e.target.value)} />
    </label>
  );
}
