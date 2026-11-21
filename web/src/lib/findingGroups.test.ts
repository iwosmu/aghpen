import { describe, expect, it } from 'vitest';
import type { Finding } from '../api/types';
import { baseTitle, groupFindings, groupKey } from './findingGroups';

const f = (id: number, title: string, extra: Partial<Finding> = {}) => ({ id, title, type: 'policy-violation', signature: 'policy:admin-panel-outside-mgmt', severity: 'high', interest: 90, status: 'new', ip: '10.66.10.' + id, port: 80, ...extra }) as Finding;

describe('finding groups', () => {
  it('strips the repeated address from titles', () => {
    expect(baseTitle('Panel administracyjny poza siecią zarządzania — 10.66.10.11:8080')).toBe('Panel administracyjny poza siecią zarządzania');
    expect(baseTitle('Nowa ekspozycja: Panel serwisowy (10.66.70.11:31337)')).toBe('Nowa ekspozycja: Panel serwisowy');
    expect(baseTitle('Samopodpisany certyfikat TLS: serwis.local')).toBe('Samopodpisany certyfikat TLS: serwis.local');
  });
  it('groups policy findings by rule and others by type and title', () => {
    expect(groupKey(f(1, 'X — 10.0.0.1:80'))).toBe('policy:admin-panel-outside-mgmt');
    expect(groupKey(f(1, 'Nowa ekspozycja: A (10.0.0.1:80)', { type: 'new-exposure', signature: '' }))).toBe('new-exposure|Nowa ekspozycja: A');
  });
  it('counts places, keeps the top severity and orders by interest', () => {
    const gs = groupFindings([
      f(1, 'Panel administracyjny poza siecią zarządzania — 10.66.10.1:80', { interest: 98 }),
      f(2, 'Panel administracyjny poza siecią zarządzania — 10.66.10.2:80', { interest: 100, status: 'triaged' }),
      f(3, 'Nowa ekspozycja: B (10.66.10.3:80)', { type: 'new-exposure', signature: '', severity: 'low', interest: 40 }),
    ]);
    expect(gs.map((g) => [g.title, g.items.length, g.places, g.interest])).toEqual([
      ['Panel administracyjny poza siecią zarządzania', 2, 2, 100],
      ['Nowa ekspozycja: B', 1, 1, 40],
    ]);
    expect(gs[0].statuses).toEqual({ new: 1, triaged: 1 });
    expect(gs[0].items[0].id).toBe(2);
  });
});
