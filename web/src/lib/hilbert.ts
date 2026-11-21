// Hilbert curve helpers for the address-space map. One cell is one /24 block.
// Neighbouring addresses stay neighbours on the plane, so a contiguous range
// shows as a compact region.

/** Distance d along a Hilbert curve of side n (a power of two) to x, y. */
export function d2xy(n: number, d: number): [number, number] {
  let x = 0, y = 0, t = d;
  for (let s = 1; s < n; s *= 2) {
    const rx = 1 & (t >> 1);
    const ry = 1 & (t ^ rx);
    if (ry === 0) {
      if (rx === 1) { x = s - 1 - x; y = s - 1 - y; }
      const tmp = x; x = y; y = tmp;
    }
    x += s * rx;
    y += s * ry;
    t >>= 2;
  }
  return [x, y];
}

export interface BlockIn { cidr: string; size: number; status: string; hosts_up: number }

export interface MapCell<B extends BlockIn = BlockIn> {
  /** index of the /24 (address >>> 8) */
  net: number;
  x: number;
  y: number;
  block: B;
}

export interface MapTile<B extends BlockIn = BlockIn> {
  /** first /24 index of the tile and the number of /24 blocks it spans (1, 4, 16, 64, 256) */
  base: number;
  span: number;
  side: number;
  prefix: number;
  label: string;
  cells: MapCell<B>[];
}

function parseNet24(cidr: string): number {
  const ip = cidr.split('/')[0].split('.').map(Number);
  return (((ip[0] << 16) >>> 0) + (ip[1] << 8) + ip[2]) >>> 0;
}

function netLabel(net: number, prefix: number): string {
  return [(net >>> 16) & 255, (net >>> 8) & 255, net & 255, 0].join('.') + '/' + prefix;
}

/**
 * Lay the /24 blocks out as Hilbert tiles. Start from the enclosing /16 of
 * each block. A sparse tile is split into its four quadrants (a /18, then a
 * /20, then a /22) and the empty quadrants are dropped, so a scope of a few
 * /24s is not lost inside a 16 x 16 grid while a full /16 keeps its 256 cells.
 */
export function layoutTiles<B extends BlockIn>(blocks: B[], minFill = 0.34): MapTile<B>[] {
  const items = blocks.map((b) => ({ net: parseNet24(b.cidr), block: b })).sort((a, b) => a.net - b.net);
  const tiles: MapTile<B>[] = [];
  const place = (base: number, span: number, list: { net: number; block: B }[]) => {
    if (list.length === 0) return;
    if (span > 1 && list.length / span < minFill) {
      const q = span / 4;
      for (let i = 0; i < 4; i++) {
        const lo = base + i * q;
        place(lo, q, list.filter((it) => it.net >= lo && it.net < lo + q));
      }
      return;
    }
    const side = Math.sqrt(span);
    const prefix = 24 - Math.log2(span);
    tiles.push({
      base, span, side, prefix, label: netLabel(base, prefix),
      cells: list.map((it) => {
        const [x, y] = d2xy(side, it.net - base);
        return { net: it.net, x, y, block: it.block };
      }),
    });
  };
  const by16 = new Map<number, { net: number; block: B }[]>();
  for (const it of items) {
    const k = it.net >>> 8;
    if (!by16.has(k)) by16.set(k, []);
    by16.get(k)!.push(it);
  }
  for (const [k, list] of [...by16.entries()].sort((a, b) => a[0] - b[0])) place((k << 8) >>> 0, 256, list);
  return tiles;
}

export function block24Label(net: number): string {
  return [(net >>> 16) & 255, (net >>> 8) & 255, net & 255].join('.');
}
