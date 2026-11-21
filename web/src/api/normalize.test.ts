import { describe, expect, it } from 'vitest';
import { parseJSON } from './normalize';

describe('parseJSON', () => {
  it('turns a null list field into an empty array, at any depth', () => {
    const p = parseJSON<{ schedule: { windows: unknown[] }; scope_ids: unknown[] }>('{"scope_ids":null,"schedule":{"enabled":false,"windows":null}}');
    expect(p.scope_ids).toEqual([]);
    expect(p.schedule.windows).toEqual([]);
  });

  it('keeps a null scalar and a filled list', () => {
    const p = parseJSON<{ last_run: unknown; tags: string[]; ports: unknown }>('{"last_run":null,"tags":["a"],"ports":null}');
    expect(p.last_run).toBeNull();
    expect(p.tags).toEqual(['a']);
    expect(p.ports).toBeNull();
  });
});
