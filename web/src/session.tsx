import { createContext, useContext, useEffect, useRef, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, useLocation } from 'react-router';
import { ApiError, get, setCsrfToken, setUnauthorizedHandler } from './api/client';
import type { Permission, Session } from './api/types';
import { t } from './i18n';

interface Ctx { session: Session; can: (...p: Permission[]) => boolean }
const SessionCtx = createContext<Ctx | null>(null);

export function useSession(): Ctx {
  const c = useContext(SessionCtx);
  if (!c) throw new Error('useSession outside of RequireSession');
  return c;
}

/** True when the session holds at least one of the permissions. */
export function useCan(...perms: Permission[]): boolean {
  return useSession().can(...perms);
}

export function Can({ perm, children, fallback = null }: { perm: Permission | Permission[]; children: ReactNode; fallback?: ReactNode }) {
  const { can } = useSession();
  const list = Array.isArray(perm) ? perm : [perm];
  return <>{can(...list) ? children : fallback}</>;
}

export function useMe() {
  return useQuery<Session, ApiError>({ queryKey: ['/me'], queryFn: () => get<Session>('/me'), retry: false, staleTime: 60_000 });
}

export function RequireSession({ children }: { children: ReactNode }) {
  const me = useMe();
  const qc = useQueryClient();
  const loc = useLocation();
  // True after the server answered 401 to a request of a session that worked before.
  const expired = useRef(false);
  useEffect(() => {
    if (me.data) setCsrfToken(me.data.csrf_token);
  }, [me.data]);
  useEffect(() => {
    setUnauthorizedHandler(() => { expired.current = true; qc.setQueryData(['/me'], undefined); qc.invalidateQueries({ queryKey: ['/me'] }); });
    return () => setUnauthorizedHandler(null);
  }, [qc]);
  if (me.isPending) {
    return <div className="flex min-h-dvh items-center justify-center text-sm text-ink-3" aria-busy="true">{t('Wczytywanie sesji…', 'Loading the session…')}</div>;
  }
  if (me.isError || !me.data) {
    if (me.error && me.error.status !== 401) {
      return (
        <div className="flex min-h-dvh flex-col items-center justify-center gap-2 px-6 text-center">
          <p className="text-base font-semibold">{t('Brak połączenia z serwerem Czujki', 'Cannot reach the Czujka server')}</p>
          <p className="text-sm text-ink-2"><span className="mono text-xs text-ink-3">{me.error.code}</span> {me.error.message}</p>
          <button className="link text-sm" onClick={() => me.refetch()}>{t('Spróbuj ponownie', 'Try again')}</button>
        </div>
      );
    }
    return <Navigate to="/login" replace state={{ from: loc.pathname + loc.search, expired: expired.current }} />;
  }
  const session = me.data;
  setCsrfToken(session.csrf_token);
  const set = new Set(session.permissions);
  const can = (...p: Permission[]) => p.some((x) => set.has(x));
  return <SessionCtx.Provider value={{ session, can }}>{children}</SessionCtx.Provider>;
}

export function roleLabel(slug: string, name: string): string {
  switch (slug) {
    case 'admin': return t('Administrator', 'Administrator');
    case 'editor': return t('Edytor', 'Editor');
    case 'analyst': return t('Analityk', 'Analyst');
    case 'viewer': return t('Odczyt', 'Viewer');
    default: return name || slug;
  }
}
export function roleScope(slug: string): string {
  switch (slug) {
    case 'admin': return t('pełna administracja', 'full administration');
    case 'editor': return t('dodawanie, usuwanie, modyfikacja', 'create, delete, modify');
    case 'analyst': return t('modyfikacja i odczyt', 'modify and read');
    case 'viewer': return t('tylko odczyt', 'read only');
    default: return t('rola niestandardowa', 'custom role');
  }
}
