import { describe, expect, it } from 'vitest';
import { titleWithoutAddress } from './format';

describe('titleWithoutAddress', () => {
  it('drops a trailing address that is shown next to the title anyway', () => {
    expect(titleWithoutAddress('Panel administracyjny poza siecią zarządzania — 10.66.128.1:80', '10.66.128.1', 80)).toBe('Panel administracyjny poza siecią zarządzania');
    expect(titleWithoutAddress('Baza danych dostępna z sieci: Redis 7.4.12 (172.30.5.1:6379)', '172.30.5.1', 6379)).toBe('Baza danych dostępna z sieci: Redis 7.4.12');
    expect(titleWithoutAddress('Host — 10.0.0.1', '10.0.0.1', 0)).toBe('Host');
  });
  it('keeps a title with no address or another address', () => {
    expect(titleWithoutAddress('Wygasły certyfikat TLS', '10.0.0.1', 443)).toBe('Wygasły certyfikat TLS');
    expect(titleWithoutAddress('X — 10.0.0.2:80', '10.0.0.1', 80)).toBe('X — 10.0.0.2:80');
  });
});
