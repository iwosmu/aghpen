import { describe, expect, it } from 'vitest';
import { adminPanelNames, adminPanelServiceNames, changeParts, overCap } from './headline';

const pl = (n: number, p: [string, string, string]) => (n === 1 ? p[0] : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? p[1] : p[2]);

describe('headline helpers', () => {
  it('names admin panels from open findings, once each', () => {
    expect(adminPanelNames([
      { title: 'Panel administracyjny: pgAdmin (10.66.10.50:80)', status: 'new' },
      { title: 'Panel administracyjny: pgAdmin (10.66.10.51:80)', status: 'triaged' },
      { title: 'Panel administracyjny: Portainer (10.66.10.40:9000)', status: 'resolved' },
      { title: 'Panel administracyjny poza siecią zarządzania — 10.66.1.10:80', status: 'new' },
    ])).toEqual(['pgAdmin']);
  });
  it('falls back to the panel technology of admin-panel services', () => {
    expect(adminPanelServiceNames([
      { classes: ['admin-panel'], title: 'Login', product: 'Apache httpd', technologies: [{ name: 'phpMyAdmin', category: 'panel' }] },
      { classes: ['login'], title: 'Blog', product: '', technologies: null },
      { classes: ['admin-panel'], title: 'Portainer', product: '', technologies: null },
    ])).toEqual(['phpMyAdmin', 'Portainer']);
  });
  it('lists only the non-zero change counts', () => {
    expect(changeParts({ added: 0, gone: 0, changed: 0, missing: 1, unstable: 0 }, 'pl', pl)).toEqual(['1 host bez odpowiedzi']);
    expect(changeParts({ added: 96, gone: 2, changed: 0, missing: 0, unstable: 0 }, 'pl', pl)).toEqual(['96 nowych ekspozycji', '2 zniknięcia']);
  });
  it('treats a rate within 5 % of the cap as normal', () => {
    expect(overCap(800, 800)).toBe(false);
    expect(overCap(830, 800)).toBe(false);
    expect(overCap(2000, 800)).toBe(true);
    expect(overCap(10, 0)).toBe(false);
  });
});
