import { describe, expect, it } from 'vitest';
import { ApiError } from '../api/client';
import { routeMissing } from './route';
import { parseServiceLines } from '../pages/Hosts';

describe('routeMissing', () => {
  it('treats an unmounted route, a GET-only path and a not wired module as missing', () => {
    expect(routeMissing(new ApiError(404, 'not_found', 'no such route'))).toBe(true);
    expect(routeMissing(new ApiError(405, 'bad_request', 'method not allowed'))).toBe(true);
    expect(routeMissing(new ApiError(501, 'not_wired', 'x'))).toBe(true);
  });
  it('keeps a missing object and other errors as errors', () => {
    expect(routeMissing(new ApiError(404, 'not_found', 'not found'))).toBe(false);
    expect(routeMissing(new ApiError(500, 'internal', 'boom'))).toBe(false);
    expect(routeMissing(new Error('x'))).toBe(false);
  });
});

describe('parseServiceLines', () => {
  it('reads port, protocol, name, product and version', () => {
    const r = parseServiceLines('22/tcp ssh OpenSSH 9.6\n161/udp snmp\n\n443');
    expect(r.bad).toEqual([]);
    expect(r.services).toEqual([
      { port: 22, proto: 'tcp', name: 'ssh', product: 'OpenSSH', version: '9.6' },
      { port: 161, proto: 'udp', name: 'snmp', product: '', version: '' },
      { port: 443, proto: 'tcp', name: '', product: '', version: '' },
    ]);
  });
  it('rejects a line without a valid port', () => {
    expect(parseServiceLines('http 80\n70000/tcp').bad).toEqual(['http 80', '70000/tcp']);
  });
});
