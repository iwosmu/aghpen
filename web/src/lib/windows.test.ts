import { describe, expect, it } from 'vitest';
import { windowOpen } from './windows';

// 2026-11-21 is a Saturday (day 6).
const at = (d: string) => new Date(d);

describe('windowOpen', () => {
  it('is open when the profile has no windows', () => {
    expect(windowOpen([], at('2026-11-21T15:00:00'))).toBe(true);
  });
  it('handles a window inside one day', () => {
    const w = [{ days: [6], start: '09:00', end: '17:00' }];
    expect(windowOpen(w, at('2026-11-21T15:00:00'))).toBe(true);
    expect(windowOpen(w, at('2026-11-21T17:00:00'))).toBe(false);
    expect(windowOpen(w, at('2026-11-22T10:00:00'))).toBe(false);
  });
  it('handles a window that crosses midnight', () => {
    const w = [{ days: [6], start: '22:00', end: '06:00' }];
    expect(windowOpen(w, at('2026-11-21T23:30:00'))).toBe(true);
    expect(windowOpen(w, at('2026-11-22T05:59:00'))).toBe(true); // Sunday morning belongs to the Saturday window
    expect(windowOpen(w, at('2026-11-22T06:00:00'))).toBe(false);
    expect(windowOpen(w, at('2026-11-21T15:00:00'))).toBe(false);
  });
});
