import { describe, expect, it } from 'vitest';
import { gridToWindows, windowsToGrid } from './WindowPicker';

const ALL = [0, 1, 2, 3, 4, 5, 6];

describe('time windows', () => {
  it('paints a night window across midnight', () => {
    const g = windowsToGrid([{ days: ALL, start: '22:00', end: '06:00' }]);
    expect(g.filter(Boolean)).toHaveLength(7 * 8);
    expect(g[1 * 24 + 22]).toBe(true);
    expect(g[2 * 24 + 5]).toBe(true);
    expect(g[2 * 24 + 6]).toBe(false);
  });

  it('turns the painted night hours back into one window for all days', () => {
    const w = gridToWindows(windowsToGrid([{ days: ALL, start: '22:00', end: '06:00' }]));
    expect(w).toEqual([{ days: ALL, start: '22:00', end: '06:00' }]);
  });

  it('round-trips a working-hours window', () => {
    const src = [{ days: [1, 2, 3, 4, 5], start: '08:00', end: '16:00' }];
    expect(gridToWindows(windowsToGrid(src))).toEqual(src);
  });

  it('gives no window for an empty grid and one full-week window for a full grid', () => {
    expect(gridToWindows(new Array<boolean>(168).fill(false))).toEqual([]);
    expect(gridToWindows(new Array<boolean>(168).fill(true))).toEqual([{ days: ALL, start: '00:00', end: '23:59' }]);
  });

  it('keeps the painted hours when a run is longer than a day', () => {
    const g = new Array<boolean>(168).fill(false);
    for (let i = 6 * 24; i < 168; i++) g[i] = true; // Saturday
    for (let i = 0; i < 24; i++) g[i] = true; // Sunday
    expect(windowsToGrid(gridToWindows(g))).toEqual(g);
  });
});
