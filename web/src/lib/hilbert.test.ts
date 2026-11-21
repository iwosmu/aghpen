import { describe, expect, it } from 'vitest';
import { d2xy, layoutTiles } from './hilbert';

describe('d2xy', () => {
  it('walks the 2 x 2 curve in the standard order', () => {
    expect([0, 1, 2, 3].map((d) => d2xy(2, d))).toEqual([[0, 0], [0, 1], [1, 1], [1, 0]]);
  });

  it('visits every cell of a 16 x 16 grid once and moves one step at a time', () => {
    const seen = new Set<string>();
    let prev: [number, number] | null = null;
    for (let d = 0; d < 256; d++) {
      const p = d2xy(16, d);
      expect(p[0]).toBeGreaterThanOrEqual(0);
      expect(p[0]).toBeLessThan(16);
      expect(p[1]).toBeGreaterThanOrEqual(0);
      expect(p[1]).toBeLessThan(16);
      seen.add(p.join(','));
      if (prev) expect(Math.abs(p[0] - prev[0]) + Math.abs(p[1] - prev[1])).toBe(1);
      prev = p;
    }
    expect(seen.size).toBe(256);
  });
});

const block = (third: number, second = 20) => ({ cidr: '10.' + second + '.' + third + '.0/24', size: 256, status: 'done', hosts_up: 1 });

describe('layoutTiles', () => {
  it('keeps a full /16 as one 16 x 16 tile', () => {
    const tiles = layoutTiles(Array.from({ length: 256 }, (_, i) => block(i)));
    expect(tiles).toHaveLength(1);
    expect(tiles[0]).toMatchObject({ span: 256, side: 16, prefix: 16, label: '10.20.0.0/16' });
    expect(new Set(tiles[0].cells.map((c) => c.x + ',' + c.y)).size).toBe(256);
  });

  it('splits a sparse /16 into smaller tiles and loses no block', () => {
    const tiles = layoutTiles([block(0), block(1), block(2), block(200)]);
    expect(tiles.length).toBeGreaterThan(1);
    expect(tiles.every((t) => t.prefix > 16)).toBe(true);
    expect(tiles.reduce((n, t) => n + t.cells.length, 0)).toBe(4);
    for (const t of tiles) for (const c of t.cells) {
      expect(c.net).toBeGreaterThanOrEqual(t.base);
      expect(c.net).toBeLessThan(t.base + t.span);
      expect(c.x).toBeLessThan(t.side);
      expect(c.y).toBeLessThan(t.side);
    }
  });

  it('makes one tile group per /16', () => {
    const tiles = layoutTiles([block(4, 30), block(5, 30), block(0, 20)]);
    expect(tiles.map((t) => t.label.split('.').slice(0, 2).join('.'))).toEqual(expect.arrayContaining(['10.20', '10.30']));
  });
});
