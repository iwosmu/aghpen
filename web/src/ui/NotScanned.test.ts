import { describe, expect, it } from 'vitest';
import { scannedFirst } from './NotScanned';

describe('scannedFirst', () => {
  it('moves rows not scanned in the run to the end and keeps the order inside each part', () => {
    const rows = [{ id: 1, carried: true }, { id: 2 }, { id: 3, carried: true }, { id: 4, carried: false }];
    expect(scannedFirst(rows).map((r) => r.id)).toEqual([2, 4, 1, 3]);
  });
  it('leaves a list from an older server (no carried field) as it is', () => {
    const rows: { id: number; carried?: boolean }[] = [{ id: 2 }, { id: 1 }];
    expect(scannedFirst(rows).map((r) => r.id)).toEqual([2, 1]);
  });
});
