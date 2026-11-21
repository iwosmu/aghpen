import { describe, expect, it } from 'vitest';
import { isLockRefusal, lockMessage, outsideLock } from './lock';

describe('operator lock helpers', () => {
  it('finds entries outside the lock', () => {
    expect(outsideLock(['10.66.70.0/24', '10.66.0.0/16', '127.0.0.0/8', '10.0.0.0/8', '8.8.8.8', 'example.org', '::1'], ['10.66.0.0/16'])).toEqual(['127.0.0.0/8', '10.0.0.0/8', '8.8.8.8']);
    expect(outsideLock(['127.0.0.1'], [])).toEqual([]);
  });
  it('translates the 422 for a policy network', () => {
    const m = 'validation: allowed_networks: 10.0.0.0/8 lies outside the operator lock (CZUJKA_ALLOWED_NETWORKS: 10.66.0.0/16); only the operator can widen it';
    expect(lockMessage(m, 'pl')).toMatch(/^Sieć 10\.0\.0\.0\/8 leży poza blokadą operatora wdrożenia \(10\.66\.0\.0\/16\)/);
    expect(isLockRefusal(m)).toBe(true);
  });
  it('translates the 422 for an ad-hoc run and keeps the per-address reasons', () => {
    const m = 'invalid: every target lies outside the allowed networks of the safety policy or the operator lock (CZUJKA_ALLOWED_NETWORKS: 10.66.0.0/16); 192.168.1.10: poza sieciami';
    expect(lockMessage(m, 'pl')).toBe('Żaden adres nie leży w dozwolonych sieciach i w blokadzie operatora wdrożenia (10.66.0.0/16). 192.168.1.10: poza sieciami');
  });
  it('translates the Polish server texts in both languages', () => {
    const n = 'validation: allowed_networks: sieć 10.0.0.0/8 leży poza blokadą operatora (CZUJKA_ALLOWED_NETWORKS: 10.66.0.0/16); poszerzyć ją może tylko operator wdrożenia';
    expect(lockMessage(n, 'pl')).toMatch(/^Sieć 10\.0\.0\.0\/8 leży poza blokadą operatora wdrożenia \(10\.66\.0\.0\/16\)/);
    expect(lockMessage(n, 'en')).toMatch(/^The network 10\.0\.0\.0\/8 lies outside the deployment operator lock \(10\.66\.0\.0\/16\)/);
    const a = 'invalid: każdy cel leży poza dozwolonymi sieciami polityki bezpieczeństwa albo blokadą operatora (CZUJKA_ALLOWED_NETWORKS: 10.66.0.0/16); 192.168.1.10: poza sieciami';
    expect(lockMessage(a, 'en')).toBe('No address lies inside the allowed networks and the deployment operator lock (10.66.0.0/16). 192.168.1.10: poza sieciami');
    expect(lockMessage(a, 'pl')).toMatch(/^Żaden adres nie leży/);
    expect(isLockRefusal(n)).toBe(true);
  });
  it('ignores other messages', () => {
    expect(lockMessage('max_pps must be between 1 and 100000', 'pl')).toBeNull();
    expect(isLockRefusal('poza dozwolonymi sieciami polityki bezpieczeństwa')).toBe(false);
  });
});
