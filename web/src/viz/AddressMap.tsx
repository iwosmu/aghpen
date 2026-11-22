import { useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { layoutTiles, type MapCell, type MapTile } from '../lib/hilbert';
import type { MapBlock } from '../api/types';
import { useWidth } from '../lib/hooks';
import { cx, fmtInt } from '../lib/format';
import { t, plural } from '../i18n';
import { chunkStatusInfo } from '../ui/marks';
import { useTip } from '../ui/kit';

// The address-space map. One cell is one /24 block of the scope, placed on a
// Hilbert curve so neighbouring networks stay neighbours. State is drawn as a
// shape (hollow, hatched, outlined, filled) and density as a one-hue ramp.

export const DENSITY_STEPS: { max: number; label: string }[] = [
  { max: 0, label: '0' }, { max: 2, label: '1–2' }, { max: 5, label: '3–5' }, { max: 10, label: '6–10' }, { max: 20, label: '11–20' }, { max: Infinity, label: '21+' },
];
function densityStep(n: number): number {
  for (let i = 0; i < DENSITY_STEPS.length; i++) if (n <= DENSITY_STEPS[i].max) return i;
  return DENSITY_STEPS.length - 1;
}

interface Props {
  blocks: MapBlock[];
  /** CIDRs to outline, for example the blocks of the chunk under the pointer in the chunk table */
  highlight?: Set<string>;
  onHover?: (cidr: string | null) => void;
  onSelect?: (block: MapBlock) => void;
  /** extra line for the readout, for example the chunk number of a block */
  describe?: (block: MapBlock) => ReactNode;
  compact?: boolean;
  maxCell?: number;
  /** a state of the network, not a scan in progress: no chunk statuses in the readout and the legend */
  snapshot?: boolean;
}

function Tile({ tile, cell, p, active, setActive, tip }: { tile: MapTile<MapBlock>; cell: number; p: Props; active: string | null; setActive: (c: string | null) => void; tip: ReturnType<typeof useTip> }) {
  const px = tile.side * cell;
  const gap = cell >= 16 ? Math.round(cell * 0.14) : cell >= 12 ? 2 : 1;
  const rx = cell >= 12 ? Math.round(cell * 0.2) : 1;
  const hatchId = 'hatch-' + tile.base;
  const occupied = useMemo(() => new Set(tile.cells.map((c) => c.x + ',' + c.y)), [tile.cells]);
  const empties: ReactNode[] = [];
  if (tile.cells.length < tile.span) {
    for (let y = 0; y < tile.side; y++) for (let x = 0; x < tile.side; x++) {
      if (!occupied.has(x + ',' + y)) empties.push(<rect key={x + ',' + y} x={x * cell + cell / 2 - 1} y={y * cell + cell / 2 - 1} width={2} height={2} fill="var(--rule-strong)" />);
    }
  }
  const body = (c: MapCell<MapBlock>) => {
    const b = c.block;
    const x = c.x * cell + gap / 2, y = c.y * cell + gap / 2, s = cell - gap;
    const hl = p.highlight?.has(b.cidr);
    const isActive = active === b.cidr;
    let node: ReactNode;
    if (b.status === 'done') {
      const step = densityStep(b.hosts_up);
      node = <>{step >= 2 && cell >= 12 ? <rect x={x - 2} y={y - 2} width={s + 4} height={s + 4} rx={rx + 2} fill={'var(--seq-' + step + ')'} opacity={0.5} filter={'url(#glow-' + tile.base + ')'} /> : null}<rect x={x} y={y} width={s} height={s} rx={rx} fill={'var(--seq-' + step + ')'} style={{ transition: 'fill 600ms var(--ease-out-expo)' }} /></>;
    }
    else if (b.status === 'running') node = <rect x={x + 0.75} y={y + 0.75} width={s - 1.5} height={s - 1.5} rx={rx} fill="var(--accent-wash)" stroke="var(--accent)" strokeWidth={1.5} className="nf-pulse" />;
    else if (b.status === 'deferred') node = <><rect x={x} y={y} width={s} height={s} fill={'url(#' + hatchId + ')'} /><rect x={x + 0.5} y={y + 0.5} width={s - 1} height={s - 1} fill="none" stroke="var(--st-changed)" strokeWidth={1} /></>;
    else if (b.status === 'failed') node = <><rect x={x + 0.5} y={y + 0.5} width={s - 1} height={s - 1} fill="var(--st-gone-wash)" stroke="var(--danger)" strokeWidth={1} /><path d={'M' + (x + 3) + ' ' + (y + 3) + 'L' + (x + s - 3) + ' ' + (y + s - 3) + 'M' + (x + s - 3) + ' ' + (y + 3) + 'L' + (x + 3) + ' ' + (y + s - 3)} stroke="var(--danger)" strokeWidth={1.2} /></>;
    else node = <rect x={x + 0.75} y={y + 0.75} width={s - 1.5} height={s - 1.5} rx={rx} fill="none" stroke="var(--rule-strong)" strokeWidth={1.2} />;
    return (
      <g
        key={b.cidr}
        onPointerEnter={(e) => { setActive(b.cidr); p.onHover?.(b.cidr); tip.show(e, <CellTip block={b} extra={p.describe?.(b)} />); }}
        onPointerMove={(e) => tip.show(e, <CellTip block={b} extra={p.describe?.(b)} />)}
        onPointerLeave={() => { setActive(null); p.onHover?.(null); tip.hide(); }}
        onClick={() => p.onSelect?.(b)}
        style={{ cursor: p.onSelect ? 'pointer' : 'default' }}
      >
        <rect x={c.x * cell} y={c.y * cell} width={cell} height={cell} fill="transparent" />
        {node}
        {hl || isActive ? <rect x={x - 1} y={y - 1} width={s + 2} height={s + 2} rx={rx + 1} fill="none" stroke="var(--ink)" strokeWidth={isActive ? 2 : 1.5} pointerEvents="none" /> : null}
      </g>
    );
  };
  const done = tile.cells.filter((c) => c.block.status === 'done').length;
  return (
    <figure className="m-0 flex-none">
      <svg width={px} height={px} viewBox={'0 0 ' + px + ' ' + px} role="presentation" style={{ display: 'block', overflow: 'visible' }}>
        <defs>
          <filter id={'glow-' + tile.base} x="-100%" y="-100%" width="300%" height="300%"><feGaussianBlur stdDeviation={Math.max(2, cell * 0.3)} /></filter>
          <pattern id={hatchId} width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <rect width="5" height="5" fill="var(--st-changed-wash)" />
            <rect width="1.6" height="5" fill="var(--st-changed)" />
          </pattern>
        </defs>
        {empties}
        {tile.cells.map(body)}
      </svg>
      {!p.compact ? (
        <figcaption className="mt-1.5 flex items-baseline justify-between gap-3 text-2xs text-ink-3" style={{ width: Math.max(px, 120) }}>
          <span className="mono text-ink-2">{tile.label}</span>
          <span className="num">{done}/{tile.cells.length}</span>
        </figcaption>
      ) : null}
    </figure>
  );
}

function CellTip({ block, extra }: { block: MapBlock; extra?: ReactNode }) {
  const st = chunkStatusInfo(block.status);
  return (
    <div>
      <div className="mono text-sm text-ink">{block.cidr}</div>
      <div className="text-ink-2">{st.label}{block.status === 'done' ? ' · ' + block.hosts_up + ' ' + plural(block.hosts_up, ['aktywny host', 'aktywne hosty', 'aktywnych hostów'], ['host up', 'hosts up']) : ''}</div>
      {extra ? <div className="text-ink-3">{extra}</div> : null}
    </div>
  );
}

export function AddressMap(p: Props) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [active, setActive] = useState<string | null>(null);
  const tip = useTip();
  const wrapRef = useRef<HTMLDivElement>(null);
  const tiles = useMemo(() => layoutTiles(p.blocks), [p.blocks]);
  const ordered = useMemo(() => tiles.flatMap((tl) => [...tl.cells].sort((a, b) => a.net - b.net)), [tiles]);
  const gapPx = p.compact ? 10 : 20;
  const sumSides = tiles.reduce((a, tl) => a + tl.side, 0);
  const maxCell = p.maxCell ?? (p.compact ? 13 : 44);
  const minCell = p.compact ? 5 : 11;
  let cell = width > 0 && sumSides > 0 ? Math.floor((width - (tiles.length - 1) * gapPx) / sumSides) : minCell;
  cell = Math.max(minCell, Math.min(maxCell, cell));

  const activeBlock = active ? p.blocks.find((b) => b.cidr === active) : undefined;
  const onKey = (e: KeyboardEvent) => {
    if (!['ArrowRight', 'ArrowLeft', 'ArrowDown', 'ArrowUp', 'Home', 'End', 'Enter'].includes(e.key) || ordered.length === 0) return;
    e.preventDefault();
    const i = ordered.findIndex((c) => c.block.cidr === active);
    if (e.key === 'Enter') { if (activeBlock) p.onSelect?.(activeBlock); return; }
    let n = i;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') n = Math.min(ordered.length - 1, i + 1);
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') n = Math.max(0, i - 1);
    else if (e.key === 'Home') n = 0;
    else if (e.key === 'End') n = ordered.length - 1;
    if (i < 0) n = 0;
    setActive(ordered[n].block.cidr);
    p.onHover?.(ordered[n].block.cidr);
  };

  const counts = useMemo(() => {
    const c = { pending: 0, running: 0, done: 0, deferred: 0, failed: 0, hosts: 0 };
    for (const b of p.blocks) { c[b.status] = (c[b.status] ?? 0) + 1; c.hosts += b.hosts_up; }
    return c;
  }, [p.blocks]);

  if (p.blocks.length === 0) {
    return <p className="text-sm text-ink-3">{t('Brak bloków adresowych.', 'No address blocks.')}</p>;
  }
  return (
    <div ref={ref} className="min-w-0">
      <div
        ref={wrapRef} tabIndex={p.compact ? -1 : 0} onKeyDown={p.compact ? undefined : onKey} onBlur={() => { setActive(null); p.onHover?.(null); }}
        role="group"
        aria-label={t(
          'Mapa przestrzeni adresowej: ' + p.blocks.length + ' bloków /24, gotowych ' + counts.done + ', w toku ' + counts.running + ', oczekujących ' + counts.pending + ', odroczonych ' + counts.deferred + '. Strzałki przechodzą po blokach.',
          'Address-space map: ' + p.blocks.length + ' /24 blocks, ' + counts.done + ' done, ' + counts.running + ' running, ' + counts.pending + ' pending, ' + counts.deferred + ' deferred. Arrow keys move between blocks.',
        )}
        className={cx('flex flex-wrap items-start outline-offset-4', p.compact ? 'gap-x-2.5 gap-y-2.5' : 'gap-x-5 gap-y-4')}
      >
        {tiles.map((tile) => <Tile key={tile.base + '/' + tile.span} tile={tile} cell={cell} p={p} active={active} setActive={setActive} tip={tip} />)}
      </div>
      {!p.compact ? (
        <>
          <p className="mt-2 min-h-[18px] text-xs text-ink-2" aria-live="polite">
            {activeBlock ? (
              <>
                <span className="mono text-ink">{activeBlock.cidr}</span>{p.snapshot ? null : <> · {chunkStatusInfo(activeBlock.status).label}</>}
                {activeBlock.status === 'done' ? <> · <span className="num">{activeBlock.hosts_up}</span> {plural(activeBlock.hosts_up, ['aktywny host', 'aktywne hosty', 'aktywnych hostów'], ['host up', 'hosts up'])}</> : null}
                {p.describe ? <> · {p.describe(activeBlock)}</> : null}
              </>
            ) : (
              <span className="text-ink-3">{t('Jedna komórka to blok /24 (256 adresów).', 'One cell is a /24 block (256 addresses).')}</span>
            )}
          </p>
          <MapLegend counts={counts} densityOnly={p.snapshot} />
        </>
      ) : null}
      {tip.node}
    </div>
  );
}

function Swatch({ children, label, n }: { children: ReactNode; label: string; n?: number }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">{children}</svg>
      {label}{n !== undefined ? <span className="num text-ink-3">{fmtInt(n)}</span> : null}
    </span>
  );
}

export function MapLegend({ counts, densityOnly }: { counts: { pending: number; running: number; done: number; deferred: number; failed: number; hosts: number }; densityOnly?: boolean }) {
  return (
    <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-rule pt-2 text-xs text-ink-2">
      {densityOnly ? null : <>
      <Swatch label={t('oczekuje', 'pending')} n={counts.pending}><rect x="0.500" y="0.500" width="11" height="11" fill="var(--panel)" stroke="var(--rule-strong)" /></Swatch>
      <Swatch label={t('w toku', 'running')} n={counts.running}><rect x="0.750" y="0.750" width="10.500" height="10.500" fill="var(--accent-wash)" stroke="var(--accent)" strokeWidth="1.500" /></Swatch>
      <Swatch label={t('odroczony', 'deferred')} n={counts.deferred}>
        <defs><pattern id="lg-hatch" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="4" height="4" fill="var(--st-changed-wash)" /><rect width="1.400" height="4" fill="var(--st-changed)" /></pattern></defs>
        <rect width="12" height="12" fill="url(#lg-hatch)" /><rect x="0.500" y="0.500" width="11" height="11" fill="none" stroke="var(--st-changed)" />
      </Swatch>
      </>}
      {counts.failed > 0 && !densityOnly ? <Swatch label={t('błąd', 'failed')} n={counts.failed}><rect x="0.500" y="0.500" width="11" height="11" fill="var(--st-gone-wash)" stroke="var(--danger)" /></Swatch> : null}
      <span className="inline-flex items-center gap-1.5">
        <span>{densityOnly ? t('aktywne hosty w bloku:', 'hosts up in the block:') : t('gotowy, aktywne hosty w bloku:', 'done, hosts up in the block:')}</span>
        <span className="inline-flex items-center gap-px">
          {DENSITY_STEPS.map((s, i) => (
            <span key={i} className="inline-flex flex-col items-center gap-0.5">
              <span className="block h-[10px] w-[38px]" style={{ background: 'var(--seq-' + i + ')' }} />
              <span className="num text-2xs text-ink-3">{s.label}</span>
            </span>
          ))}
        </span>
      </span>
    </div>
  );
}
