// Typed client for the Czujka REST API (docs/API.md). One origin, base path /api/v1.
// The transport is replaceable so the dev-only fixture layer can answer requests
// without the pages knowing.

import { parseJSON } from './normalize';
import { getLang } from '../i18n';

const BASE = '/api/v1';

export class ApiError extends Error {
  status: number;
  code: string;
  details?: unknown;
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

/** The route exists but its component is not connected in this installation (HTTP 501, code not_wired). */
export function isUnavailable(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 501 || e.code === 'not_wired');
}

export type Transport = (req: Request) => Promise<Response>;

let transport: Transport = (req) => fetch(req);
let csrfToken = '';
let onUnauthorized: (() => void) | null = null;

export function setTransport(t: Transport) { transport = t; }
export function setCsrfToken(t: string) { csrfToken = t; }
export function setUnauthorizedHandler(fn: (() => void) | null) { onUnauthorized = fn; }

export type Query = Record<string, string | number | boolean | null | undefined>;

export function qs(q?: Query): string {
  if (!q) return '';
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined || v === null || v === '') continue;
    p.set(k, String(v));
  }
  const s = p.toString();
  return s ? '?' + s : '';
}

/** Reads the session again and returns its CSRF token. Used once when the server rejects a stale token. */
async function refreshCsrf(): Promise<boolean> {
  try {
    const res = await transport(new Request(BASE + '/me', { headers: { Accept: 'application/json' }, credentials: 'same-origin' }));
    if (!res.ok) return false;
    const s = await res.json();
    if (!s?.csrf_token || s.csrf_token === csrfToken) return false;
    csrfToken = s.csrf_token;
    return true;
  } catch {
    return false;
  }
}

async function send(method: string, path: string, body?: BodyInit | null, headers?: Record<string, string>, retried = false): Promise<Response> {
  const h = new Headers(headers);
  h.set('Accept', 'application/json');
  // The server renders change summaries in this language (contract: ?lang=, then Accept-Language).
  h.set('Accept-Language', getLang());
  if (method !== 'GET' && method !== 'HEAD' && csrfToken) h.set('X-CSRF-Token', csrfToken);
  const req = new Request(BASE + path, { method, body: body ?? undefined, headers: h, credentials: 'same-origin' });
  let res: Response;
  try {
    res = await transport(req);
  } catch (e) {
    throw new ApiError(0, 'network', e instanceof Error ? e.message : 'network error');
  }
  if (!res.ok) {
    let code = res.status === 501 ? 'not_wired' : res.status >= 500 ? 'internal' : 'error';
    let message = res.statusText || 'HTTP ' + res.status;
    let details: unknown;
    try {
      const j = await res.json();
      if (j && j.error) { code = j.error.code ?? code; message = j.error.message ?? message; details = j.error.details; }
    } catch { /* body was not JSON */ }
    // The session changed in another tab: its CSRF token is new. Read it and send the request once more.
    if (res.status === 403 && /csrf/i.test(message) && !retried && !path.startsWith('/auth/') && (await refreshCsrf())) {
      return send(method, path, body, headers, true);
    }
    // The session probe itself answers 401 when there is no session: it must not trigger another probe.
    if (res.status === 401 && onUnauthorized && !path.startsWith('/auth/') && path !== '/me') onUnauthorized();
    throw new ApiError(res.status, code, message, details);
  }
  return res;
}

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const hasBody = body !== undefined;
  const res = await send(method, path, hasBody ? JSON.stringify(body) : null, hasBody ? { 'Content-Type': 'application/json' } : undefined);
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return text ? parseJSON<T>(text) : (undefined as T);
}

export const get = <T>(path: string, q?: Query) => api<T>('GET', path + qs(q));
export const post = <T>(path: string, body?: unknown) => api<T>('POST', path, body ?? {});
export const patch = <T>(path: string, body: unknown) => api<T>('PATCH', path, body);
export const put = <T>(path: string, body: unknown) => api<T>('PUT', path, body);
export const del = <T = void>(path: string) => api<T>('DELETE', path);

export async function upload<T>(path: string, form: FormData): Promise<T> {
  const res = await send('POST', path, form);
  return parseJSON<T>(await res.text());
}

/** Fetch an export and hand it to the browser as a file download. */
export async function download(path: string, filename: string): Promise<number> {
  const res = await send('GET', path);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  return blob.size;
}
