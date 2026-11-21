import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { openStream } from '../api/events';
import { invalidate, useItem } from '../api/hooks';
import type { Chunk, HostEvent, RunMap, ScanRun } from '../api/types';

export function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [w, setW] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    setW(el.clientWidth);
    const ro = new ResizeObserver((entries) => setW(Math.floor(entries[0].contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

/** Filters live in the URL so a view can be shared and survives a reload. */
export function useUrlState() {
  const [sp, setSp] = useSearchParams();
  const get = useCallback((k: string, def = '') => sp.get(k) ?? def, [sp]);
  const set = useCallback((patch: Record<string, string | number | null | undefined>, opts?: { keepOffset?: boolean }) => {
    setSp((prev) => {
      const next = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(patch)) {
        if (v === null || v === undefined || v === '') next.delete(k); else next.set(k, String(v));
      }
      if (!opts?.keepOffset && !('offset' in patch)) next.delete('offset');
      return next;
    }, { replace: true });
  }, [setSp]);
  const clear = useCallback((keys: string[]) => {
    setSp((prev) => { const next = new URLSearchParams(prev); keys.forEach((k) => next.delete(k)); next.delete('offset'); return next; }, { replace: true });
  }, [setSp]);
  return useMemo(() => ({ get, set, clear, sp }), [get, set, clear, sp]);
}

/** A run that follows its event stream: progress, chunk and host events update the query cache. */
export function useLiveRun(id: number | null | undefined, opts?: { withChunks?: boolean }) {
  const qc = useQueryClient();
  const enabled = Boolean(id);
  const run = useItem<ScanRun>('/runs/' + id, undefined, { enabled });
  const [recent, setRecent] = useState<(HostEvent & { at: number })[]>([]);
  const [connected, setConnected] = useState(false);
  const status = run.data?.status;
  // The server ends the stream of a paused or finished run right after its state, so only an
  // active run keeps a stream. A resume arrives through the global "run" event (Layout).
  const live = status === 'running' || status === 'analyzing' || status === 'queued';
  useEffect(() => {
    if (!id || !live) return;
    const s = openStream('/runs/' + id + '/events', {
      progress: (r: ScanRun) => { qc.setQueryData(['/runs/' + id, {}], r); },
      chunk: (c: Chunk) => {
        if (opts?.withChunks) {
          qc.setQueryData<Chunk[]>(['/runs/' + id + '/chunks', {}], (cur) => (cur ? cur.map((x) => (x.id === c.id ? c : x)) : cur));
        }
        qc.setQueryData<RunMap>(['/runs/' + id + '/map', {}], (cur) => cur ? { blocks: cur.blocks.map((b) => (c.spec.includes(b.cidr) ? { ...b, status: c.status } : b)) } : cur);
        if (c.status === 'done') invalidate(qc, '/runs/' + id + '/map');
      },
      host: (h: HostEvent) => setRecent((cur) => [{ ...h, at: Date.now() }, ...cur].slice(0, 12)),
      done: (r: ScanRun | null) => {
        // "done" is the last event: close, or EventSource reconnects to a stream that ends again.
        s.close();
        setConnected(false);
        if (r && r.id) qc.setQueryData(['/runs/' + id, {}], r);
        invalidate(qc, '/runs', '/dashboard', '/changes', '/hosts', '/services', '/findings');
      },
    }, setConnected);
    return () => { s.close(); setConnected(false); };
  }, [id, live, qc, opts?.withChunks]);
  return { run, recent, connected: connected && live };
}

export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const i = setInterval(() => setNow(Date.now()), intervalMs); return () => clearInterval(i); }, [intervalMs]);
  return now;
}
