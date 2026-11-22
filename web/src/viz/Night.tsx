import { useMemo, useState, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router';
import { Link } from 'react-router';
import type { Host, ScanRun, Service } from '../api/types';
import { serviceName } from '../lib/serviceName';
import { useWidth } from '../lib/hooks';
import { cx, fmtDateTime, fmtInt, fmtTime } from '../lib/format';
import { isFullRun } from '../lib/headline';
import { t, plural } from '../i18n';
import { useTip } from '../ui/kit';

// Two pictures of the night for the dashboard, drawn only from API data:
// the network as a field of /24 cells (one /16 is 16 x 16 cells on a Hilbert
// curve) and the night as a ruler with one tick per scan.

export interface FieldCell { idx: number; label: string; up: number; other: number; changed: boolean; running: boolean; note?: string; href: string }
export interface Field { key: string; label: string; unit: 'block' | 'address'; cells: FieldCell[]; up: number }

function net24(ip: string): number | null {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((x) => !Number.isFinite(x))) return null;
  return ((p[0] << 16) >>> 0) + (p[1] << 8) + p[2];
}
const label24 = (n: number) => [(n >>> 16) & 255, (n >>> 8) & 255, n & 255, 0].join('.') + '/24';
const label16 = (k: number) => [(k >>> 8) & 255, k & 255, 0, 0].join('.') + '/16';

function upStep(n: number, unit: Field['unit']): number {
  if (n <= 0) return 0;
  if (unit === 'address') return 4;
  if (n === 1) return 2;
  if (n <= 3) return 3;
  if (n <= 9) return 4;
  return 5;
}

/**
 * The network as fields of 256 cells. Hosts in more than one /24: one field per /16, a cell per /24.
 * All hosts in one /24: one field of that /24, a cell per address. The fullest field comes first.
 */
export function networkFields(hosts: Pick<Host, 'ip' | 'status'>[], changes: { ip: string; summary: string }[], runningCidrs?: string[]): Field[] {
  const nets = new Set<number>();
  for (const h of hosts) { const n = net24(h.ip); if (n !== null) nets.add(n); }
  for (const c of runningCidrs ?? []) { const n = net24(c.split('/')[0]); if (n !== null) nets.add(n); }
  const note = new Map<string, string>();
  for (const c of changes) if (!note.has(c.ip)) note.set(c.ip, c.summary);
  if (nets.size === 1) {
    const n = [...nets][0];
    const prefix = label24(n).replace('.0/24', '.');
    const cells = new Map<number, FieldCell>();
    for (const h of hosts) {
      if (net24(h.ip) !== n) continue;
      const i = Number(h.ip.split('.')[3]);
      const up = h.status === 'up' || h.status === 'unstable' ? 1 : 0;
      cells.set(i, { idx: i, label: h.ip, up, other: 1 - up, changed: note.has(h.ip), running: false, note: note.get(h.ip), href: '/hosts?q=' + encodeURIComponent(h.ip) + '&status=all' });
    }
    if (runningCidrs?.length) for (const c of cells.values()) c.running = true;
    const list = [...cells.values()];
    return [{ key: prefix, label: label24(n), unit: 'address', cells: list, up: list.reduce((a, c) => a + c.up, 0) }];
  }
  const cells = new Map<number, FieldCell>();
  const get = (n: number) => {
    let c = cells.get(n);
    if (!c) { c = { idx: n & 255, label: label24(n), up: 0, other: 0, changed: false, running: false, href: '/hosts?cidr=' + encodeURIComponent(label24(n)) + '&status=all' }; cells.set(n, c); }
    return c;
  };
  for (const h of hosts) {
    const n = net24(h.ip);
    if (n === null) continue;
    const c = get(n);
    if (h.status === 'up' || h.status === 'unstable') c.up++; else c.other++;
    if (note.has(h.ip)) { c.changed = true; c.note ??= note.get(h.ip); }
  }
  for (const cidr of runningCidrs ?? []) { const n = net24(cidr.split('/')[0]); if (n !== null) get(n).running = true; }
  const by16 = new Map<number, FieldCell[]>();
  for (const [n, c] of cells) {
    const k = n >>> 8;
    if (!by16.has(k)) by16.set(k, []);
    by16.get(k)!.push(c);
  }
  return [...by16.entries()]
    .map(([k, list]): Field => ({ key: String(k), label: label16(k), unit: 'block', cells: list, up: list.reduce((a, c) => a + c.up, 0) }))
    .sort((a, b) => b.up - a.up || b.cells.length - a.cells.length);
}

/** Rows of lamps in address order: 32 columns x 8 rows, so 10.66.70.x sits at row 3, column 7. */
export const LAMP_COLS = 32;
export function lampPitch(width: number): number { return Math.max(6, (width - 44) / LAMP_COLS); }

export function NetworkField({ field, width }: { field: Field; width: number }) {
  const nav = useNavigate();
  const tip = useTip();
  const [hot, setHot] = useState<number | null>(null);
  const labelW = 44, top = 18;
  const pitch = lampPitch(width);
  const gap = Math.max(2, Math.round(pitch * 0.2));
  const S = pitch - gap;
  const r = Math.min(3, Math.max(2, S * 0.18));
  const H = top + 8 * pitch;
  const byIndex = useMemo(() => new Map(field.cells.map((c) => [c.idx, c])), [field.cells]);
  const body = (c: FieldCell) => (
    <span className="block min-w-[150px]">
      <span className="mono block text-[13px] text-ink">{c.label}</span>
      {field.unit === 'block' && c.up ? <span className="mt-0.5 block text-ink-2"><span className="num text-ink">{fmtInt(c.up)}</span> {plural(c.up, ['aktywny host', 'aktywne hosty', 'aktywnych hostów'], ['host up', 'hosts up'])}</span> : null}
      {c.note ? <span className="mt-1 flex items-start gap-1.5 text-ink"><span className="lamp mt-[5px] bg-coral" aria-hidden="true" />{c.note}</span> : null}
    </span>
  );
  const cells = [];
  for (let i = 0; i < 256; i++) {
    const col = i % LAMP_COLS, row = Math.floor(i / LAMP_COLS);
    const X = labelW + col * pitch + gap / 2, Y = top + row * pitch + gap / 2;
    const c = byIndex.get(i);
    if (!c) { cells.push(<rect key={i} x={X} y={Y} width={S} height={S} rx={r} fill="var(--seq-0)" />); continue; }
    const step = upStep(c.up, field.unit);
    const fill = c.running && !c.up ? 'var(--accent)' : step ? 'var(--seq-' + step + ')' : 'var(--seq-0)';
    cells.push(
      <g
        key={i} role="link" tabIndex={0} aria-label={c.label + (c.up && field.unit === 'block' ? ', ' + c.up : '')}
        className="cursor-pointer outline-none"
        onMouseEnter={(e) => { setHot(i); tip.show(e, body(c)); }}
        onMouseMove={(e) => tip.show(e, body(c))}
        onMouseLeave={() => { setHot(null); tip.hide(); }}
        onFocus={(e) => { setHot(i); tip.showAt(e.currentTarget, body(c)); }}
        onBlur={() => { setHot(null); tip.hide(); }}
        onClick={() => nav(c.href)}
        onKeyDown={(e: KeyboardEvent) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); nav(c.href); } }}
      >
        <rect x={X} y={Y} width={S} height={S} rx={r} fill={fill} className={c.running ? 'nf-pulse' : undefined} />
        {!c.up && c.other && !c.running ? <rect x={X + 0.75} y={Y + 0.75} width={S - 1.5} height={S - 1.5} rx={Math.max(1, r - 0.75)} fill="none" stroke="var(--ink-3)" strokeWidth={1} strokeDasharray="2 2" /> : null}
        {c.changed ? <rect x={X - 2} y={Y - 2} width={S + 4} height={S + 4} rx={r + 1.5} fill="none" stroke="var(--coral)" strokeWidth={1.5} /> : null}
        {hot === i ? <rect x={X - 2} y={Y - 2} width={S + 4} height={S + 4} rx={r + 1.5} fill="none" stroke="var(--ink)" strokeWidth={1.5} /> : null}
      </g>,
    );
  }
  // the engraved scale: row starts at the left, a tick every eight columns above
  const rowLabel = (row: number) => '.' + row * LAMP_COLS;
  return (
    <>
      <svg width={width} height={H} className="block overflow-visible" role="group" aria-label={field.label}>
        {[0, 8, 16, 24].map((col) => (
          <g key={col} aria-hidden="true">
            <line x1={labelW + col * pitch + gap / 2} x2={labelW + col * pitch + gap / 2} y1={top - 6} y2={top - 2} stroke="var(--ink-3)" strokeWidth={1} />
            <text x={labelW + col * pitch + gap / 2 + 3} y={top - 7} className="mono" fontSize={10} fill="var(--ink-3)">{col}</text>
          </g>
        ))}
        {Array.from({ length: 8 }, (_, row) => (pitch < 14 && row % 2 ? null :
          <text key={row} x={labelW - 10} y={top + row * pitch + gap / 2 + S / 2 + 3.5} textAnchor="end" className="mono" fontSize={pitch < 14 ? 10 : 11} fill="var(--ink-3)" aria-hidden="true">{rowLabel(row)}</text>
        ))}
        {cells}
      </svg>
      {tip.node}
    </>
  );
}

/** The lamp legend: the same lamps, numbers only. */
export function LampLegend({ unit, changedLabel }: { unit: Field['unit']; changedLabel?: string }) {
  const steps: [number, string][] = unit === 'block' ? [[2, '1'], [3, '2–3'], [4, '4–9'], [5, '10+']] : [];
  return (
    <p className="mono flex items-center gap-3 text-[12px] text-ink-3" aria-hidden="true">
      {steps.map(([s, l]) => <span key={s} className="inline-flex items-center gap-1.5"><span className="lamp" style={{ background: 'var(--seq-' + s + ')' }} />{l}</span>)}
      {changedLabel ? <span className="inline-flex items-center gap-1.5"><span className="lamp shadow-[0_0_0_1.5px_var(--coral)]" style={{ background: 'var(--seq-3)' }} />{changedLabel}</span> : null}
    </p>
  );
}

/** A line of the last values with the newest one as a dot. */
export function Spark({ values, width = 120, height = 36, tone = 'var(--accent)' }: { values: number[]; width?: number; height?: number; tone?: string }) {
  if (values.length < 2) return null;
  const vmin = Math.min(...values), vmax = Math.max(...values);
  const padv = Math.max(1, (vmax - vmin) * 0.35, vmax * 0.08);
  const lo = vmin - padv, hi = vmax + padv;
  const y = (v: number) => height - 2 - ((v - lo) / (hi - lo)) * (height - 4);
  const xs = (i: number) => (i / (values.length - 1)) * (width - 6) + 3;
  const d = values.map((v, i) => (i ? 'L' : 'M') + xs(i).toFixed(1) + ' ' + y(v).toFixed(1)).join(' ');
  const last = values.length - 1;
  return (
    <svg width={width} height={height} aria-hidden="true" className="block overflow-visible">
      <path d={d + ' L' + xs(last) + ' ' + height + ' L' + xs(0) + ' ' + height + ' Z'} fill={tone} opacity={0.1} />
      <path d={d} fill="none" stroke={tone} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={xs(last)} cy={y(values[last])} r={3} fill={tone} />
    </svg>
  );
}

/** One tick per scan; the height is the count, zero stays a dot. */
export function TickBars({ values, width = 120, height = 36, tone = 'var(--coral)' }: { values: number[]; width?: number; height?: number; tone?: string }) {
  if (!values.length) return null;
  const hi = Math.max(1, ...values);
  const step = width / values.length;
  return (
    <svg width={width} height={height} aria-hidden="true" className="block">
      {values.map((v, i) => {
        const x = i * step + step / 2;
        const h = v ? 4 + (v / hi) * (height - 6) : 0;
        return v ? <line key={i} x1={x} x2={x} y1={height} y2={height - h} stroke={tone} strokeWidth={Math.max(1.5, Math.min(3, step * 0.5))} strokeLinecap="round" /> : <circle key={i} cx={x} cy={height - 1.5} r={1.2} fill="var(--ink-3)" opacity={0.6} />;
      })}
    </svg>
  );
}

/** A share as a ring. */
export function Ring({ value, max, size = 40, tone = 'var(--coral)' }: { value: number; max: number; size?: number; tone?: string }) {
  const r = size / 2 - 3, c = 2 * Math.PI * r;
  const f = max > 0 ? Math.min(1, value / max) : 0;
  return (
    <svg width={size} height={size} aria-hidden="true" className="block -rotate-90">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--rule-strong)" strokeWidth={4} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={tone} strokeWidth={4} strokeLinecap="round" strokeDasharray={f * c + ' ' + c} />
    </svg>
  );
}

/** Changes a run found, as the dashboard counts them. */
export function runChanges(r: ScanRun): number {
  const s = r.summary;
  if (!s || !s.prev_run_id) return 0;
  return s.hosts_new + s.hosts_gone + s.services_new + s.services_gone + s.services_changed + (s.hosts_back ?? 0) + (s.services_returned ?? 0) + (s.responses_slower ?? 0);
}

const when = (r: ScanRun) => new Date(r.started_at || r.created_at).getTime();

/** The night as a ruler: one tick per scan, a coral mark where a scan found changes, the latest one in ink. */
export function NightStrip({ runs, active, currentId, now }: { runs: ScanRun[]; active?: ScanRun | null; currentId?: number; now: number }) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const nav = useNavigate();
  const tip = useTip();
  const [hot, setHot] = useState<number | null>(null);
  const list = useMemo(() => {
    const all = runs.filter((r) => r.started_at || r.created_at).sort((a, b) => when(a) - when(b));
    if (!all.length) return all;
    const last = when(all[all.length - 1]);
    return all.filter((r) => when(r) >= last - 24 * 3600_000);
  }, [runs]);
  const H = 92, base = 64;
  if (!list.length) return <div ref={ref} className="h-[92px]" />;
  const t0 = when(list[0]);
  const lastRun = list[list.length - 1];
  const tEnd = Math.max(active ? now : new Date(lastRun.finished_at || lastRun.started_at || lastRun.created_at).getTime(), t0 + 3600_000);
  const pad = (tEnd - t0) * 0.02;
  const lo = t0 - pad, hi = tEnd + pad;
  const W = Math.max(200, w);
  const x = (ms: number) => ((ms - lo) / (hi - lo)) * W;
  // hour ticks: every hour, a label every k hours so labels never touch
  const hours: number[] = [];
  const startH = new Date(lo); startH.setMinutes(0, 0, 0);
  for (let h = startH.getTime() + 3600_000; h < hi; h += 3600_000) hours.push(h);
  const every = Math.max(1, Math.ceil(hours.length / Math.max(1, Math.floor(W / 70))));
  const maxCh = Math.max(1, ...list.map(runChanges));
  const near = (px: number) => {
    let best: ScanRun | null = null, bd = 9;
    for (const r of list) { const d = Math.abs(x(when(r)) - px); if (d < bd) { bd = d; best = r; } }
    return best;
  };
  const body = (r: ScanRun) => {
    const n = runChanges(r);
    return (
      <span className="block">
        <span className="block text-ink"><span className="num">#{r.id}</span> · {fmtDateTime(r.started_at || r.created_at)}</span>
        <span className="block text-ink-2">{r.profile_name}</span>
        {n ? <span className="block text-ink"><span className="num">{n}</span> {plural(n, ['zmiana', 'zmiany', 'zmian'], ['change', 'changes'])}</span> : null}
      </span>
    );
  };
  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const box = e.currentTarget.getBoundingClientRect();
    const r = near(e.clientX - box.left);
    setHot(r?.id ?? null);
    if (r) tip.show(e, body(r)); else tip.hide();
  };
  return (
    <div ref={ref} className="w-full min-w-0">
      <svg
        width={W} height={H} className={cx('block', hot !== null && 'cursor-pointer')} role="img"
        aria-label={t('Skany', 'Scans') + ': ' + list.length}
        onMouseMove={onMove} onMouseLeave={() => { setHot(null); tip.hide(); }}
        onClick={() => { if (hot !== null) nav('/runs/' + hot); }}
      >
        <line x1={0} x2={W} y1={base + 0.5} y2={base + 0.5} stroke="var(--rule-strong)" />
        {hours.map((h, i) => (
          <g key={h}>
            <line x1={x(h)} x2={x(h)} y1={base + 1} y2={base + (i % every === 0 ? 7 : 4)} stroke="var(--ink-3)" opacity={i % every === 0 ? 0.9 : 0.5} />
            {i % every === 0 ? <text x={x(h)} y={base + 22} textAnchor="middle" className="mono" fontSize={11} fill="var(--ink-3)">{fmtTime(new Date(h).toISOString())}</text> : null}
          </g>
        ))}
        {list.map((r) => {
          const cx0 = x(when(r));
          const full = isFullRun(r);
          const n = runChanges(r);
          const cur = r.id === currentId;
          // an engraved tick per scan: taller with more changes, a coral cap when the scan found any
          const h = (full ? 16 : r.trigger === 'reprobe' ? 8 : 12) + (n ? 30 * Math.sqrt(n / maxCh) : 0);
          const sw = cur ? 2 : Math.max(1, Math.min(1.5, W / list.length / 3));
          return (
            <g key={r.id}>
              <line x1={cx0} x2={cx0} y1={base} y2={base - h} stroke={cur || hot === r.id ? 'var(--ink)' : 'var(--ink-3)'} strokeWidth={sw} opacity={cur || hot === r.id ? 1 : full ? 0.7 : 0.45} />
              {n ? <line x1={cx0} x2={cx0} y1={base - h} y2={base - h + Math.min(6, h / 2)} stroke="var(--coral)" strokeWidth={Math.max(sw, 1.5)} /> : null}
            </g>
          );
        })}
        {active ? (() => {
          const a = x(when(active)), b = x(now);
          return (
            <g>
              <rect x={a} y={base - 48} width={Math.max(2, b - a)} height={48} rx={2} fill="var(--accent)" opacity={0.14} />
              <line x1={a} x2={a} y1={base} y2={base - 52} stroke="var(--accent)" strokeWidth={2} className="nf-pulse" />
            </g>
          );
        })() : null}
      </svg>
      {tip.node}
    </div>
  );
}


/** Columns and cell size for n port cells in a square of the given size. */
export function portGrid(n: number, size: number): { cols: number; cell: number; gap: number } {
  // up to four ports stand in one row; more fill a square
  const cols = n <= 4 ? Math.max(1, n) : Math.min(8, Math.ceil(Math.sqrt(n)));
  const gap = Math.round(size / 40);
  const cell = Math.min(120, Math.floor((size - gap * (cols - 1)) / cols));
  return { cols, cell, gap };
}

/** One machine in scope: its open ports are the cells. A changed port carries a coral ring and its change as a tip. */
export function PortField({ services, changes, size }: { services: Service[]; changes: { port?: number; summary: string }[]; size: number }) {
  const tip = useTip();
  const list = [...services].sort((a, b) => a.port - b.port);
  const { cols, cell, gap } = portGrid(list.length, size);
  const note = new Map<number, string>();
  for (const c of changes) if (c.port && !note.has(c.port)) note.set(c.port, c.summary);
  return (
    <ul className="grid" style={{ gridTemplateColumns: 'repeat(' + cols + ', ' + cell + 'px)', gap }} data-testid="port-field">
      {list.map((s) => {
        const changed = note.has(s.port);
        const body = <><span className="mono">{s.ip}:{s.port}</span><span className="block text-ink-2">{serviceName(s)}</span>{changed ? <span className="mt-1 block max-w-[260px] text-ink">{note.get(s.port)}</span> : null}</>;
        return (
          <li key={s.id}>
            <Link to={'/services/' + s.id} onPointerEnter={(e) => tip.show(e, body)} onPointerLeave={tip.hide} onFocus={(e) => tip.showAt(e.currentTarget, body)} onBlur={tip.hide}
              className={cx('flex flex-col justify-between rounded-[10px] bg-raised p-3 shadow-[inset_0_0_0_1px_var(--rule)] transition-colors duration-150 ease-[var(--ease)] hover:bg-[color-mix(in_oklch,var(--raised),var(--ink)_6%)]', changed && 'shadow-[inset_0_0_0_1.5px_var(--coral)]')}
              style={{ width: cell, height: cell }}>
              <span className="lamp" style={{ background: 'var(--seq-4)' }} aria-hidden="true" />
              <span className="block min-w-0">
                <span className="mono block leading-none text-ink" style={{ fontSize: Math.max(14, Math.min(24, cell / 4.5)) }}>{s.port}</span>
                {cell >= 72 ? <span className="mt-1 block truncate text-[12px] text-ink-3">{serviceName(s)}</span> : null}
              </span>
            </Link>
          </li>
        );
      })}
      {tip.node}
    </ul>
  );
}
