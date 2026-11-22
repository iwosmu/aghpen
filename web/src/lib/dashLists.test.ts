import { describe, expect, it } from 'vitest';
import type { Change, Finding } from '../api/types';
import { setLang } from '../i18n';
import { findingRows, rowsByAddress, spanText } from './dashLists';

const ch = (id: number, ip: string, at: string, expected = false): Change => ({ id, ip, at, expected, kind: 'host_gone', summary: 's' + id } as unknown as Change);
const fd = (id: number, title: string, ip: string, interest: number, first: string): Finding => ({ id, type: 'policy-violation', signature: 'rule-' + title.length, title: title + ' — ' + ip + ':80', ip, port: 80, interest, severity: 'high', status: 'new', first_seen: first } as unknown as Finding);

describe('rowsByAddress', () => {
  it('folds one address into one row with its latest change and drops expected ones', () => {
    const rows = rowsByAddress([
      ch(9, '10.0.0.20', '2026-11-21T22:47:00Z'), ch(8, '10.0.0.15', '2026-11-21T22:38:00Z'),
      ch(7, '10.0.0.20', '2026-11-21T22:30:00Z'), ch(6, '10.0.0.9', '2026-11-21T22:29:00Z', true),
      ch(5, '10.0.0.20', '2026-11-21T20:47:00Z'),
    ]);
    expect(rows.map((r) => r.ip)).toEqual(['10.0.0.20', '10.0.0.15']);
    expect(rows[0].latest.id).toBe(9);
    expect(rows[0].items).toHaveLength(3);
    expect(rows[0].spanSec).toBe(7200);
  });
  it('writes the span', () => {
    setLang('pl');
    expect(spanText(30)).toBe('');
    expect(spanText(7200)).toBe('w 2 godz.');
    expect(spanText(900)).toBe('w 15 min');
  });
});

describe('findingRows', () => {
  it('groups by kind with the count, the worst score and the newest first seen', () => {
    const rows = findingRows([
      fd(1, 'Formularz logowania', '10.0.0.1', 100, '2026-11-21T10:00:00Z'),
      fd(2, 'Formularz logowania', '10.0.0.2', 90, '2026-11-21T12:00:00Z'),
      fd(3, 'Panel administracyjny', '10.0.0.1', 95, '2026-11-21T11:00:00Z'),
    ]);
    expect(rows).toHaveLength(2);
    expect(rows[0].group.title).toBe('Formularz logowania');
    expect(rows[0].group.places).toBe(2);
    expect(rows[0].group.interest).toBe(100);
    expect(rows[0].newest).toBe('2026-11-21T12:00:00Z');
    expect(rows[0].to).toBe('/findings?type=policy-violation&q=Formularz%20logowania');
  });
});
