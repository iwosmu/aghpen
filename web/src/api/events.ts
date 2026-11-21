// Server-sent events. Production uses EventSource; the dev fixture layer swaps the factory.

import { parseJSON } from './normalize';

export interface EventStream { close(): void }
export type EventHandlers = Record<string, (data: any) => void>;
export type StreamFactory = (path: string, handlers: EventHandlers, onState?: (open: boolean) => void) => EventStream;

let factory: StreamFactory = (path, handlers, onState) => {
  const es = new EventSource('/api/v1' + path, { withCredentials: true });
  for (const [name, fn] of Object.entries(handlers)) {
    es.addEventListener(name, (ev) => {
      let data: unknown = null;
      try { data = parseJSON((ev as MessageEvent).data); } catch { /* event without JSON data */ }
      fn(data);
    });
  }
  es.onopen = () => onState?.(true);
  es.onerror = () => onState?.(false);
  return { close: () => es.close() };
};

export function setStreamFactory(f: StreamFactory) { factory = f; }
export function openStream(path: string, handlers: EventHandlers, onState?: (open: boolean) => void): EventStream {
  return factory(path, handlers, onState);
}
