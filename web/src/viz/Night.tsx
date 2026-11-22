import { useMemo, useState, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router';
import type { Host, ScanRun } from '../api/types';
import { d2xy } from '../lib/hilbert';
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

export function NetworkField({ field, size }: { field: Field; size: number }) {
  const nav = useNavigate();
  const tip = useTip();
  const [hot, setHot] = useState<number | null>(null);
  const side = 16;
  const px = size;
  const cell = px / side;
  const gap = Math.max(2, Math.round(cell * 0.16));
  const r = Math.max(2, Math.round(cell * 0.22));
  const byIndex = useMemo(() => new Map(field.cells.map((c) => [c.idx, c])), [field.cells]);
  const body = (c: FieldCell) => (
    <span className="block min-w-[150px]">
      <span className="mono block text-[13px] text-ink">{c.label}</span>
      {field.unit === 'block' && c.up ? <span className="mt-0.5 block text-ink-2"><span className="num text-ink">{fmtInt(c.up)}</span> {plural(c.up, ['aktywny host', 'aktywne hosty', 'aktywnych hostów'], ['host up', 'hosts up'])}</span> : null}
      {c.note ? <span className="mt-1 flex items-start gap-1.5 text-ink"><span className="mt-[5px] h-1.5 w-1.5 flex-none rounded-full bg-coral" aria-hidden="true" />{c.note}</span> : null}
    </span>
  );
  const rects = [];
  for (let i = 0; i < 256; i++) {
    const [x, y] = d2xy(side, i);
    const c = byIndex.get(i);
    const X = x * cell + gap / 2, Y = y * cell + gap / 2, S = cell - gap;
    if (!c) { rects.push(<rect key={i} x={X} y={Y} width={S} height={S} rx={r} fill="var(--seq-0)" />); continue; }
    const step = upStep(c.up, field.unit);
    const fill = step ? 'var(--seq-' + step + ')' : 'var(--seq-0)';
    const on = hot === i;
    rects.push(
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
        {step >= 2 ? <rect x={X - 2} y={Y - 2} width={S + 4} height={S + 4} rx={r + 2} fill={fill} opacity={0.55} filter="url(#nf-glow)" /> : null}
        <rect x={X} y={Y} width={S} height={S} rx={r} fill={fill} />
        {!c.up && c.other ? <rect x={X + 1.5} y={Y + 1.5} width={S - 3} height={S - 3} rx={Math.max(1, r - 1)} fill="none" stroke="var(--ink-3)" strokeWidth={1.2} strokeDasharray="2 2" /> : null}
        {c.running ? <rect x={X - 2} y={Y - 2} width={S + 4} height={S + 4} rx={r + 2} fill="none" stroke="var(--accent)" strokeWidth={2} className="nf-pulse" /> : null}
        {c.changed ? (
          <g>
            <circle cx={X + S / 2} cy={Y + S / 2} r={S * 0.95} fill="var(--coral)" opacity={0.14} />
            <circle cx={X + S / 2} cy={Y + S / 2} r={S * 0.72} fill="none" stroke="var(--coral)" strokeWidth={1.5} opacity={0.7} />
            <circle cx={X + S / 2} cy={Y + S / 2} r={Math.max(3, S * 0.2)} fill="var(--coral)" />
          </g>
        ) : null}
        {on ? <rect x={X - 1.5} y={Y - 1.5} width={S + 3} height={S + 3} rx={r + 1.5} fill="none" stroke="var(--ink)" strokeWidth={1.5} /> : null}
      </g>,
    );
  }
  const pad = cell;
  return (
    <>
      <svg width={px} height={px} viewBox={(-pad) + ' ' + (-pad) + ' ' + (px + 2 * pad) + ' ' + (px + 2 * pad)} style={{ width: px + 2 * pad, height: px + 2 * pad, margin: -pad }} className="block overflow-visible" role="group" aria-label={field.label}>
        <defs><filter id="nf-glow" x="-100%" y="-100%" width="300%" height="300%"><feGaussianBlur stdDeviation={Math.max(3, cell * 0.32)} /></filter></defs>
        {rects}
      </svg>
      {tip.node}
    </>
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
  const H = 150, base = 118;
  if (!list.length) return <div ref={ref} className="h-[150px]" />;
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
            {i % every === 0 ? <text x={x(h)} y={base + 22} textAnchor="middle" className="num" fontSize={12} fill="var(--ink-3)">{fmtTime(new Date(h).toISOString())}</text> : null}
          </g>
        ))}
        {list.map((r) => {
          const cx0 = x(when(r));
          const full = isFullRun(r);
          const n = runChanges(r);
          const cur = r.id === currentId;
          const h = cur ? 64 : full ? 44 : r.trigger === 'reprobe' ? 12 : 26;
          return (
            <g key={r.id}>
              <line x1={cx0} x2={cx0} y1={base} y2={base - h} stroke={cur ? 'var(--ink)' : hot === r.id ? 'var(--ink)' : 'var(--ink-3)'} strokeWidth={cur ? 2 : Math.max(0.75, Math.min(1.5, W / list.length / 3))} opacity={cur || hot === r.id ? 1 : full ? 0.6 : 0.4} strokeLinecap="round" />
              {n ? <circle cx={cx0} cy={base - h - 10 - 26 * Math.sqrt(n / maxCh)} r={2.5 + 3 * Math.sqrt(n / maxCh)} fill="var(--coral)" stroke="var(--panel-solid)" strokeWidth={1.5} /> : null}
            </g>
          );
        })}
        {active ? (() => {
          const a = x(when(active)), b = x(now);
          return (
            <g>
              <rect x={a} y={base - 60} width={Math.max(2, b - a)} height={60} rx={2} fill="var(--accent)" opacity={0.18} />
              <line x1={a} x2={a} y1={base} y2={base - 70} stroke="var(--accent)" strokeWidth={2} style={{ animation: 'pulse-ring 1.6s ease-in-out infinite' }} />
            </g>
          );
        })() : null}
      </svg>
      {tip.node}
    </div>
  );
}
