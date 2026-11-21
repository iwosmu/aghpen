import { ApiError } from '../api/client';

/** True when the server does not mount the route yet (404 "no such route") or reports the module as not wired (501). */
export function routeMissing(e: unknown): boolean {
  if (!(e instanceof ApiError)) return false;
  if (e.status === 501 || e.code === 'not_wired') return true;
  if (e.status === 405) return true; // a POST on a path that only a GET route matches, e.g. /signatures/suggest vs /signatures/{id}
  return e.status === 404 && /no such route/i.test(e.message);
}
