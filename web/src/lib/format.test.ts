import { describe, expect, it } from 'vitest';
import { fmtBytes, fmtDuration, ipToNum, shortHash, show } from './format';

describe('format', () => {
  it('formats durations', () => {
    expect(fmtDuration(42)).toBe('42 s');
    expect(fmtDuration(95)).toBe('1 min 35 s');
    expect(fmtDuration(4310)).toBe('1 h 11 min');
    // the same table as internal/analyze TestDurationTextMatchesTheUI
    expect(fmtDuration(108)).toBe('1 min 48 s');
    expect(fmtDuration(120)).toBe('2 min');
    expect(fmtDuration(7200)).toBe('2 h');
    expect(fmtDuration(3 * 86400)).toBe('3 dni');
    expect(fmtDuration(3 * 86400 + 4 * 3600)).toBe('3 dni 4 h');
    expect(fmtDuration(-1)).toBe('–');
    expect(fmtDuration(null)).toBe('–');
  });

  it('formats sizes and hashes', () => {
    expect(fmtBytes(512)).toBe('512 B');
    expect(fmtBytes(74035)).toBe('72,3 kB');
    expect(shortHash('7880d9e95d4fe30315772178ff', 8)).toBe('7880d9e9…');
    expect(shortHash(null)).toBe('–');
  });

  it('converts addresses to numbers that sort in address order', () => {
    expect(ipToNum('10.0.0.1')).toBe(167772161);
    expect(ipToNum('10.20.4.9')).toBeLessThan(ipToNum('10.20.4.10'));
    expect(ipToNum('200.1.1.1')).toBeGreaterThan(ipToNum('10.255.255.255'));
  });

  it('shows empty values as a dash', () => {
    expect(show('')).toBe('–');
    expect(show(['a', 'b'])).toBe('a, b');
    expect(show({ a: 1 })).toBe('{"a":1}');
  });
});
