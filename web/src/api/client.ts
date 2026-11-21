// Typed client for the Czujka REST API (docs/API.md). One origin, base path /api/v1.
// The transport is replaceable so the dev-only fixture layer can answer requests
// without the pages knowing.

const BASE = '/api/v1';

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
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

async function send(method: string, path: string, body?: BodyInit | null, headers?: Record<string, string>): Promise<Response> {
  const h = new Headers(headers);
  h.set('Accept', 'application/json');
  if (method !== 'GET' && method !== 'HEAD' && csrfToken) h.set('X-CSRF-Token', csrfToken);
  const req = new Request(BASE + path, { method, body: body ?? undefined, headers: h, credentials: 'same-origin' });
  let res: Response;
  try {
    res = await transport(req);
  } catch (e) {
    throw new ApiError(0, 'network', e instanceof Error ? e.message : 'network error');
  }
  if (!res.ok) {
    let code = 'internal';
    let message = res.statusText || 'HTTP ' + res.status;
    try {
      const j = await res.json();
      if (j && j.error) { code = j.error.code ?? code; message = j.error.message ?? message; }
    } catch { /* body was not JSON */ }
    if (res.status === 401 && onUnauthorized && !path.startsWith('/auth/')) onUnauthorized();
    throw new ApiError(res.status, code, message);
  }
  return res;
}

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const hasBody = body !== undefined;
  const res = await send(method, path, hasBody ? JSON.stringify(body) : null, hasBody ? { 'Content-Type': 'application/json' } : undefined);
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export const get = <T>(path: string, q?: Query) => api<T>('GET', path + qs(q));
export const post = <T>(path: string, body?: unknown) => api<T>('POST', path, body ?? {});
export const patch = <T>(path: string, body: unknown) => api<T>('PATCH', path, body);
export const put = <T>(path: string, body: unknown) => api<T>('PUT', path, body);
export const del = <T = void>(path: string) => api<T>('DELETE', path);

export async function upload<T>(path: string, form: FormData): Promise<T> {
  const res = await send('POST', path, form);
  return (await res.json()) as T;
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
