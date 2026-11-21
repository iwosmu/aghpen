import { describe, expect, it } from 'vitest';
import { isLocalMac } from './mac';

describe('isLocalMac', () => {
  it('detects locally administered addresses', () => {
    expect(isLocalMac('02:42:0a:42:46:0b')).toBe(true);
    expect(isLocalMac('0A:00:27:00:00:01')).toBe(true);
    expect(isLocalMac('de:ad:be:ef:00:01')).toBe(true);
    expect(isLocalMac('f6:12:34:56:78:9a')).toBe(true);
  });
  it('keeps vendor addresses', () => {
    expect(isLocalMac('00:1a:2b:3c:4d:5e')).toBe(false);
    expect(isLocalMac('3c:22:fb:00:00:01')).toBe(false);
    expect(isLocalMac('')).toBe(false);
  });
});
