import { keepPreviousData, useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { get, type Query } from './client';
import type { Page } from './types';
import { toast, toastError } from '../ui/kit';

export function usePage<T>(path: string, q?: Query, enabled = true) {
  return useQuery<Page<T>>({ queryKey: [path, q ?? {}], queryFn: () => get<Page<T>>(path, q), placeholderData: keepPreviousData, enabled });
}

export function useItem<T>(path: string, q?: Query, opts?: { enabled?: boolean; refetchInterval?: number | false; staleTime?: number }) {
  return useQuery<T>({ queryKey: [path, q ?? {}], queryFn: () => get<T>(path, q), enabled: opts?.enabled ?? true, refetchInterval: opts?.refetchInterval, staleTime: opts?.staleTime });
}

export function invalidate(qc: QueryClient, ...prefixes: string[]) {
  return qc.invalidateQueries({ predicate: (q) => prefixes.some((p) => String(q.queryKey[0]).startsWith(p)) });
}

/** A mutation that refreshes the listed path prefixes and reports the outcome in a toast. */
export function useAction<TVars, TRes = unknown>(fn: (v: TVars) => Promise<TRes>, opts?: { invalidate?: string[]; success?: string | ((r: TRes) => string); silent?: boolean; onSuccess?: (r: TRes, v: TVars) => void }) {
  const qc = useQueryClient();
  return useMutation<TRes, Error, TVars>({
    mutationFn: fn,
    onSuccess: (r, v) => {
      if (opts?.invalidate) invalidate(qc, ...opts.invalidate);
      if (opts?.success) toast(typeof opts.success === 'function' ? opts.success(r) : opts.success);
      opts?.onSuccess?.(r, v);
    },
    onError: (e) => { if (!opts?.silent) toastError(e); },
  });
}
