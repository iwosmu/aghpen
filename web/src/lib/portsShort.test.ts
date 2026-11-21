import { describe, expect, it } from 'vitest';
import { setLang } from '../i18n';
import { portsShort } from './portsShort';

describe('portsShort', () => {
  it('keeps short lists', () => {
    expect(portsShort('top-100')).toBe('top-100');
    expect(portsShort('80,2222,8888,18443')).toBe('80, 2222, 8888, 18443');
  });
  it('folds long lists', () => {
    setLang('pl');
    const many = 'top-1000,' + Array.from({ length: 43 }, (_, i) => 9000 + i).join(',');
    expect(portsShort(many)).toBe('top-1000 + 43 porty');
    expect(portsShort('80,443,8080,8443,9000,9001')).toBe('80, 443, 8080 + 3 porty');
    setLang('en');
    expect(portsShort('80,443,8080,8443,9000')).toBe('80, 443, 8080 + 2 ports');
    setLang('pl');
  });
});
