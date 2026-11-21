import { useRef, useState, type KeyboardEvent } from 'react';
import type { Window } from '../api/types';
import { WEEK_ORDER, weekday, cx } from '../lib/format';
import { t } from '../i18n';
import { Button } from '../ui/kit';

// Weekly time-window picker: a 7 x 24 grid you paint with the pointer or the
// keyboard. Days use 0 = Sunday on the wire; the grid shows Monday first.

export function windowsToGrid(windows: Window[]): boolean[] {
  const g = new Array<boolean>(168).fill(false);
  for (const w of windows) {
    const [sh, sm] = w.start.split(':').map(Number);
    const [eh, em] = w.end.split(':').map(Number);
    const s = Math.min(23, sh + (sm >= 30 ? 1 : 0));
    const e = eh + (em > 0 ? 1 : 0);
    for (const d of w.days) {
      if (e > s) for (let h = s; h < Math.min(24, e); h++) g[d * 24 + h] = true;
      else {
        for (let h = s; h < 24; h++) g[d * 24 + h] = true;
        for (let h = 0; h < e; h++) g[((d + 1) % 7) * 24 + h] = true;
      }
    }
  }
  return g;
}

/**
 * Painted hours to windows. A run shorter than 24 h becomes one window (it may
 * cross midnight: end before start). A longer run is cut at midnight. Windows
 * with the same hours are merged into one entry with several days.
 */
export function gridToWindows(g: boolean[]): Window[] {
  const pieces: { day: number; start: number; end: string }[] = [];
  const hh = (h: number) => String(h % 24).padStart(2, '0') + ':00';
  if (g.every(Boolean)) return [{ days: [0, 1, 2, 3, 4, 5, 6], start: '00:00', end: '23:59' }];
  for (let i = 0; i < 168; i++) {
    if (!g[i] || g[(i + 167) % 168]) continue;
    let len = 0;
    while (g[(i + len) % 168]) len++;
    let day = Math.floor(i / 24);
    let h = i % 24;
    if (len < 24) { pieces.push({ day, start: h, end: hh(h + len) }); continue; }
    let left = len;
    while (left > 0) {
      const take = Math.min(left, 24 - h);
      pieces.push({ day, start: h, end: h === 0 && take === 24 ? '23:59' : hh(h + take) });
      left -= take;
      day = (day + 1) % 7;
      h = 0;
    }
  }
  const groups = new Map<string, Window>();
  for (const f of pieces) {
    const key = f.start + '-' + f.end;
    const w = groups.get(key) ?? { days: [], start: hh(f.start), end: f.end };
    w.days.push(f.day);
    groups.set(key, w);
  }
  return [...groups.values()].map((w) => ({ ...w, days: [...w.days].sort((x, y) => x - y) }));
}

export function describeWindows(windows: Window[]): string {
  if (windows.length === 0) return t('bez ograniczeń, o każdej porze', 'no limit, any time');
  return windows.map((w) => {
    const days = w.days.length === 7 ? t('codziennie', 'every day') : w.days.slice().sort((a, b) => ((a + 6) % 7) - ((b + 6) % 7)).map(weekday).join(', ');
    return days + ' ' + w.start + '–' + w.end;
  }).join('; ');
}

export function WindowPicker({ value, onChange, disabled }: { value: Window[]; onChange: (w: Window[]) => void; disabled?: boolean }) {
  const grid = windowsToGrid(value);
  const paint = useRef<boolean | null>(null);
  const draft = useRef<boolean[] | null>(null);
  const [, force] = useState(0);
  const [focus, setFocus] = useState<[number, number]>([0, 0]);
  const cells = draft.current ?? grid;

  const start = (i: number) => {
    if (disabled) return;
    paint.current = !grid[i];
    draft.current = [...grid];
    draft.current[i] = paint.current;
    force((x) => x + 1);
  };
  const over = (i: number) => {
    if (paint.current === null || !draft.current) return;
    if (draft.current[i] !== paint.current) { draft.current[i] = paint.current; force((x) => x + 1); }
  };
  const end = () => {
    if (draft.current) onChange(gridToWindows(draft.current));
    draft.current = null;
    paint.current = null;
  };
  const onKey = (e: KeyboardEvent, row: number, hr: number) => {
    let r = row, h = hr;
    if (e.key === 'ArrowRight') h = Math.min(23, hr + 1);
    else if (e.key === 'ArrowLeft') h = Math.max(0, hr - 1);
    else if (e.key === 'ArrowDown') r = Math.min(6, row + 1);
    else if (e.key === 'ArrowUp') r = Math.max(0, row - 1);
    else if (e.key === ' ' || e.key === 'Enter') {
      e.preventDefault();
      if (disabled) return;
      const next = [...grid];
      const i = WEEK_ORDER[row] * 24 + hr;
      next[i] = !next[i];
      onChange(gridToWindows(next));
      return;
    } else return;
    e.preventDefault();
    setFocus([r, h]);
    (document.getElementById('wp-' + r + '-' + h) as HTMLElement | null)?.focus();
  };
  const preset = (fn: (d: number, h: number) => boolean) => {
    const g = new Array<boolean>(168).fill(false);
    for (let d = 0; d < 7; d++) for (let h = 0; h < 24; h++) g[d * 24 + h] = fn(d, h);
    onChange(gridToWindows(g));
  };
  const hours = cells.filter(Boolean).length;
  return (
    <div>
      <div
        className={cx('grid select-none gap-px', disabled && 'opacity-70')} style={{ gridTemplateColumns: '26px repeat(24, minmax(0, 1fr))', touchAction: 'none' }}
        onPointerUp={end} onPointerLeave={end} role="grid" aria-label={t('Okna czasowe skanowania: dni w wierszach, godziny w kolumnach', 'Scan time windows: days in rows, hours in columns')}
      >
        <span />
        {Array.from({ length: 24 }).map((_, hr) => <span key={hr} className="num h-[14px] text-center text-2xs text-ink-3">{hr % 2 === 0 ? String(hr).padStart(2, '0') : ''}</span>)}
        {WEEK_ORDER.map((wd, row) => (
          <div key={wd} className="contents" role="row">
            <span className="flex items-center text-2xs text-ink-3">{weekday(wd)}</span>
            {Array.from({ length: 24 }).map((_, hr) => {
              const i = wd * 24 + hr;
              const on = cells[i];
              return (
                <button
                  key={hr} id={'wp-' + row + '-' + hr} type="button" role="gridcell" aria-selected={on} disabled={disabled}
                  tabIndex={focus[0] === row && focus[1] === hr ? 0 : -1}
                  aria-label={weekday(wd) + ' ' + String(hr).padStart(2, '0') + ':00, ' + (on ? t('skanowanie dozwolone', 'scanning allowed') : t('skanowanie zabronione', 'scanning not allowed'))}
                  onPointerDown={(e) => { (e.target as HTMLElement).releasePointerCapture?.(e.pointerId); start(i); }}
                  onPointerEnter={() => over(i)}
                  onKeyDown={(e) => onKey(e, row, hr)}
                  className={cx('block h-[22px] w-full min-w-0 focus-visible:z-10', on ? 'bg-accent' : 'bg-raised hover:bg-rule', !disabled && 'cursor-crosshair')}
                  style={on ? undefined : { boxShadow: 'inset 0 0 0 1px var(--rule)' }}
                />
              );
            })}
          </div>
        ))}
      </div>
      <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-ink-2">
          {hours === 0
            ? t('Brak okien. Skan może ruszyć o każdej porze.', 'No windows. A scan can start at any time.')
            : <><span className="num text-ink">{hours}</span> {t('godz. w tygodniu', 'hours a week')} · {describeWindows(value)}</>}
        </p>
        {!disabled ? (
          <div className="flex flex-wrap gap-1.5">
            <Button size="sm" onClick={() => preset((_d, h) => h >= 22 || h < 6)}>{t('Noce 22–06', 'Nights 22–06')}</Button>
            <Button size="sm" onClick={() => preset((d) => d === 6 || d === 0)}>{t('Weekend', 'Weekend')}</Button>
            <Button size="sm" onClick={() => preset((d, h) => d >= 1 && d <= 5 && (h >= 18 || h < 7))}>{t('Poza godzinami pracy', 'Outside office hours')}</Button>
            <Button size="sm" variant="ghost" onClick={() => onChange([])}>{t('Wyczyść', 'Clear')}</Button>
          </div>
        ) : null}
      </div>
    </div>
  );
}
