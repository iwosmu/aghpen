import { describe, expect, it } from 'vitest';
import type { Change, ScanProfile } from '../api/types';
import { setLang } from '../i18n';
import { awayText, responseDelta, awaySeconds } from './changeText';
import { defaultProfile, isLoopback, loopbackLine } from './thisComputer';
import { isSelf, serviceName } from './serviceName';
import { fieldValue } from './fields';
import { passState } from '../ui/RunPasses';

const ch = (x: Partial<Change>) => ({ id: 1, run_id: 6, prev_run_id: 5, at: '2026-11-21T16:15:12Z', kind: 'service_returned', severity: 'low', host_id: 1, ip: '192.168.65.254', service_id: 3, port: 8787, summary: '', field: 'state', before: null, after: null, expected: false, acked_by: '', acked_at: null, ...x }) as Change;

describe('this computer', () => {
  it('recognises loopback targets', () => {
    expect(isLoopback('localhost')).toBe(true);
    expect(isLoopback(' 127.0.0.1 ')).toBe(true);
    expect(isLoopback('::1')).toBe(true);
    expect(isLoopback('10.66.0.0/16')).toBe(false);
    expect(isLoopback('localhost.example.com')).toBe(false);
  });
  it('says what localhost is scanned as', () => {
    setLang('pl');
    expect(loopbackLine('localhost', '192.168.65.254')).toBe('localhost = host Dockera 192.168.65.254');
    expect(loopbackLine('localhost', undefined, '')).toMatch(/ten komputer/);
    expect(loopbackLine('localhost', undefined, undefined)).toBeNull();
    expect(loopbackLine('10.0.0.1', '192.168.65.254')).toBeNull();
    setLang('en');
    expect(loopbackLine('localhost', '172.17.0.1')).toBe('localhost = the Docker host 172.17.0.1');
  });
  it('picks the seeded default profile (the oldest)', () => {
    expect(defaultProfile([{ id: 7 }, { id: 1 }, { id: 3 }] as ScanProfile[])?.id).toBe(1);
    expect(defaultProfile([])).toBeUndefined();
  });
});

describe('returned and slower', () => {
  it('reads how long a service was away', () => {
    setLang('pl');
    const c = ch({ before: { state: 'gone', last_open_run_id: 4, last_open_at: '2026-11-21T16:10:00Z', away_seconds: 312, runs_away: 1 }, after: 'open' });
    expect(awaySeconds(c)).toBe(312);
    expect(awayText(c)).toBe('nie było jej 5 min 12 s (1 skan)');
    expect(awaySeconds(ch({ before: { state: 'gone', last_open_at: '2026-11-21T16:10:12Z' } }))).toBe(300);
    expect(awayText(ch({ before: 'gone' }))).toBe('');
  });
  it('reads a response-time change', () => {
    setLang('pl');
    expect(responseDelta(ch({ kind: 'response_slower', field: 'http.response_ms', before: { baseline_ms: 120, ms: 118 }, after: { ms: 640 } }))).toBe('120 ms → 640 ms');
    expect(responseDelta(ch({ kind: 'response_slower', before: { baseline_ms: 120 }, after: { ms: null, error: 'no_answer' } }))).toBe('120 ms → brak odpowiedzi HTTP');
    expect(responseDelta(ch({ kind: 'response_recovered', before: { baseline_ms: 120, ms: 640 }, after: { ms: 1300 } }))).toBe('120 ms → 1,3 s');
    expect(responseDelta(ch({ before: null, after: null }))).toBe('');
  });
  it('shows change values in words', () => {
    setLang('pl');
    expect(fieldValue('http.response_ms', { baseline_ms: 120, ms: 118 })).toBe('zwykle 120 ms');
    expect(fieldValue('http.response_ms', { ms: 640 })).toBe('640 ms');
    expect(fieldValue('http.response_ms', { ms: null, error: 'no_answer' })).toBe('brak odpowiedzi HTTP');
    expect(fieldValue('state', { state: 'gone', away_seconds: 312 })).toBe('zniknęła');
  });
});

describe('service names', () => {
  it('never returns an empty name', () => {
    setLang('pl');
    expect(serviceName({ name: '', product: '', version: '' })).toBe('nierozpoznana');
    expect(serviceName({ name: '', product: 'RabbitMQ', version: '3.13.7' })).toBe('RabbitMQ 3.13.7');
    expect(serviceName({ name: 'amqp', product: 'RabbitMQ', version: '3.13.7' })).toBe('amqp');
    expect(serviceName({ name: 'http', product: 'nginx', version: '1.31.9' }, { short: true })).toBe('nginx');
    expect(serviceName({ name: '', product: '', version: '' }, { short: true })).toBe('usługa nierozpoznana');
  });
  it('knows Czujka itself', () => {
    expect(isSelf({ tags: ['czujka'] })).toBe(true);
    expect(isSelf({ tags: null })).toBe(false);
  });
});

describe('port passes', () => {
  it('shows each pass state', () => {
    setLang('pl');
    expect(passState({ name: 'top_ports', state: 'done', hosts: 1, ports_total: 1000, ports_done: 1000 })).toBe('gotowe');
    expect(passState({ name: 'full_range', state: 'running', hosts: 1, ports_total: 65535, ports_done: 21000 })).toMatch(/^32/);
    expect(passState({ name: 'full_range', state: 'pending', hosts: 1, ports_total: 65535, ports_done: 0 })).toBe('czeka');
  });
});
