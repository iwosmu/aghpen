import { useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import type { CountPoint, NameCount } from '../api/types';
import { useWidth } from '../lib/hooks';
import { cx, fmtDate, fmtInt, fmtSigned } from '../lib/format';
import { t } from '../i18n';

/** Ranked horizontal bars: one series, one colour, the value at the tip. */
export function BarList({ items, href, mono, labelWidth = 132, extra }: { items: NameCount[]; href?: (i: NameCount) => string; mono?: boolean; labelWidth?: number; extra?: (i: NameCount) => ReactNode }) {
  const max = Math.max(1, ...items.map((i) => i.count));
  if (items.length === 0) return <p className="text-sm text-ink-3">{t('Brak danych.', 'No data.')}</p>;
  return (
    <ul>
      {items.map((i) => {
        const row = (
          <>
            <span className={cx('flex-none truncate text-sm text-ink', mono && 'num')} style={{ width: labelWidth }} title={i.name}>{i.name}{extra ? <span className="ml-1.5 font-sans text-2xs text-ink-3">{extra(i)}</span> : null}</span>
            <span className="flex min-w-0 flex-1 items-center gap-2">
              <span className="h-[8px] rounded-r-sm bg-[var(--seq-3)] transition-[width] duration-500 group-hover:bg-accent-strong" style={{ width: Math.max(2, (i.count / max) * 100) + '%', maxWidth: 'calc(100% - 44px)' }} />
              <span className="num flex-none text-xs text-ink-2">{fmtInt(i.count)}</span>
            </span>
          </>
        );
        return (
          <li key={i.name}>
            {href ? <Link to={href(i)} className="group flex h-[24px] items-center gap-2 hover:bg-raised">{row}</Link> : <div className="group flex h-[24px] items-center gap-2">{row}</div>}
          </li>
        );
      })}
    </ul>
  );
}

interface Series { key: keyof Pick<CountPoint, 'hosts' | 'services' | 'changes' | 'findings'>; label: string }

/**
 * Trend over runs as small multiples: one row per measure, each with its own
 * scale and a shared x position. No dual axis. A crosshair reads every measure
 * at the run under the pointer; focusable for the keyboard.
 */
export function TrendRows({ points, series }: { points: CountPoint[]; series: Series[] }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [at, setAt] = useState<number | null>(null);
  if (points.length < 2) return <p className="text-sm text-ink-3">{t('Trend pojawi się po dwóch zakończonych przebiegach.', 'The trend appears after two completed runs.')}</p>;
  const labelW = 92, valueW = 86, rowH = 40, pad = 6;
  const plotW = Math.max(60, width - labelW - valueW);
  const x = (i: number) => (i / (points.length - 1)) * (plotW - 8) + 4;
  const idx = at ?? points.length - 1;
  const onMove = (clientX: number, el: Element) => {
    const r = el.getBoundingClientRect();
    const rel = (clientX - r.left - 4) / Math.max(1, plotW - 8);
    setAt(Math.max(0, Math.min(points.length - 1, Math.round(rel * (points.length - 1)))));
  };
  return (
    <div ref={ref}>
      <div
        tabIndex={0} role="group" className="outline-offset-2"
        aria-label={t('Trend w kolejnych przebiegach. Strzałki w lewo i w prawo wybierają przebieg.', 'Trend over runs. Left and right arrows choose a run.')}
        onKeyDown={(e) => {
          if (e.key === 'ArrowLeft') { e.preventDefault(); setAt(Math.max(0, idx - 1)); }
          if (e.key === 'ArrowRight') { e.preventDefault(); setAt(Math.min(points.length - 1, idx + 1)); }
        }}
        onBlur={() => setAt(null)}
      >
        {series.map((s) => {
          const vals = points.map((p) => p[s.key] as number);
          const lo = Math.min(...vals), hi = Math.max(...vals);
          const y = (v: number) => (hi === lo ? rowH / 2 : rowH - pad - ((v - lo) / (hi - lo)) * (rowH - pad * 2));
          const d = vals.map((v, i) => (i === 0 ? 'M' : 'L') + x(i).toFixed(1) + ' ' + y(v).toFixed(1)).join('');
          const delta = vals[idx] - vals[Math.max(0, idx - 1)];
          return (
            <div key={s.key} className="flex items-center border-b border-rule last:border-b-0" style={{ height: rowH }}>
              <span className="flex-none text-xs text-ink-2" style={{ width: labelW }}>{s.label}</span>
              <svg
                width={plotW} height={rowH} className="flex-none"
                onPointerMove={(e) => onMove(e.clientX, e.currentTarget)} onPointerLeave={() => setAt(null)}
              >
                <path d={d + 'L' + x(vals.length - 1) + ' ' + rowH + 'L' + x(0) + ' ' + rowH + 'Z'} fill="var(--seq-3)" opacity={0.1} />
                <path d={d} fill="none" stroke="var(--seq-3)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
                {at !== null ? <line x1={x(idx)} x2={x(idx)} y1={0} y2={rowH} stroke="var(--ink-3)" strokeWidth={1} /> : null}
                <circle cx={x(idx)} cy={y(vals[idx])} r={4} fill="var(--seq-3)" stroke="var(--panel)" strokeWidth={2} />
              </svg>
              <span className="flex flex-none items-baseline justify-end gap-1.5" style={{ width: valueW }}>
                <span className="num text-sm text-ink">{fmtInt(vals[idx])}</span>
                <span className="num w-[34px] text-right text-2xs text-ink-3">{idx > 0 ? fmtSigned(delta) : ''}</span>
              </span>
            </div>
          );
        })}
      </div>
      <p className="mt-1.5 flex justify-between text-2xs text-ink-3" style={{ paddingLeft: labelW }}>
        <span className="num">#{points[0].run_id}</span>
        <span className="num text-ink-2">{at !== null ? '#' + points[idx].run_id + ' · ' + fmtDate(points[idx].at) : t('ostatni: #', 'latest: #') + points[idx].run_id + ' · ' + fmtDate(points[idx].at)}</span>
      </p>
    </div>
  );
}

export function ProgressBar({ value, max, label }: { value: number; max: number; label?: string }) {
  const pct = max > 0 ? Math.min(1, value / max) : 0;
  return (
    <div className="h-[6px] w-full bg-[color-mix(in_oklch,var(--accent)_14%,var(--raised))]" role="progressbar" aria-valuemin={0} aria-valuemax={max} aria-valuenow={value} aria-label={label}>
      <div className="h-full bg-accent transition-[width] duration-700 ease-out" style={{ width: pct * 100 + '%' }} />
    </div>
  );
}

/** Rate against its caps: the fill is the current rate, the tick marks the profile cap, the track ends at the policy cap. */
export function RateGauge({ current, cap, policyCap, unit = 'pps' }: { current: number; cap: number; policyCap: number; unit?: string }) {
  const max = Math.max(policyCap, cap, 1);
  const over = current > cap;
  return (
    <div>
      <div className="flex items-baseline justify-between gap-3">
        <span><span className="num text-lg font-semibold text-ink">{fmtInt(current)}</span> <span className="text-xs text-ink-3">{unit}</span></span>
        <span className="text-xs text-ink-2">{t('limit skanu', 'run cap')} <span className="num text-ink">{fmtInt(cap)}</span></span>
      </div>
      <div className="relative mt-1.5 h-[8px] bg-[color-mix(in_oklch,var(--accent)_14%,var(--raised))]" role="meter" aria-valuemin={0} aria-valuemax={max} aria-valuenow={current} aria-label={t('Tempo pakietów względem limitu', 'Packet rate against the cap')}>
        <div className="h-full transition-[width] duration-700 ease-out" style={{ width: Math.min(100, (current / max) * 100) + '%', background: over ? 'var(--danger)' : 'var(--accent)' }} />
        <div className="absolute -bottom-1 -top-1 w-[2px] bg-ink" style={{ left: 'calc(' + Math.min(100, (cap / max) * 100) + '% - 1px)' }} title={t('limit skanu', 'run cap')} />
      </div>
      <div className="mt-1 flex justify-between text-2xs text-ink-3">
        <span className="num">0</span>
        <span>{t('limit polityki bezpieczeństwa', 'safety policy cap')} <span className="num text-ink-2">{fmtInt(policyCap)}</span></span>
      </div>
    </div>
  );
}
