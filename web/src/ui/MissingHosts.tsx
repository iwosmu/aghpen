import { useEffect } from 'react';
import { Link } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { invalidate, useItem } from '../api/hooks';
import type { Change, Page } from '../api/types';
import { t, plural } from '../i18n';
import { fmtTime } from '../lib/format';
import { Glyph } from './marks';

export type Verdict = { kind: 'host_gone' | 'host_back'; at: string; runId: number };

/**
 * What a confirmation probe decided about each host that did not answer
 * (host_missing): the first host_gone or host_back of that host after the
 * miss. Polls every 5 s while a host still waits, so the page changes from
 * "nie odpowiada (niepotwierdzone)" to "zniknął (potwierdzone)" without a
 * click; then it refreshes the dashboard, the runs and the changes.
 */
export function useHostVerdicts(missing: Change[]): Map<number, Verdict> {
  const qc = useQueryClient();
  const on = missing.length > 0;
  const since = on ? missing.reduce((a, c) => (c.at < a ? c.at : a), missing[0].at) : '';
  const q = useItem<Page<Change>>('/changes', { kind: 'host_gone,host_back', limit: 200 }, { enabled: on, refetchInterval: (query) => {
    const items = (query.state.data as Page<Change> | undefined)?.items ?? [];
    const open = missing.some((m) => !items.some((c) => c.host_id === m.host_id && c.at > m.at));
    return open ? 5000 : false;
  } });
  const out = new Map<number, Verdict>();
  for (const m of missing) {
    const v = (q.data?.items ?? []).filter((c) => c.host_id === m.host_id && c.at > m.at).sort((a, b) => a.at.localeCompare(b.at))[0];
    if (v) out.set(m.host_id, { kind: v.kind as Verdict['kind'], at: v.at, runId: v.run_id });
  }
  const n = out.size;
  useEffect(() => { if (n > 0) invalidate(qc, '/dashboard', '/runs', '/hosts', '/services'); }, [n, qc]);
  void since;
  return out;
}

/** "(nginx 1.30.7)" from the API sentence of a service_unreachable change, or ''. */
function nameOf(c: Change): string {
  const m = /\(([^)]+)\)\s*nie odpowiada/.exec(c.summary ?? '');
  if (!m) return '';
  // "redis Redis key-value store" -> "Redis key-value store": the name repeated by the product
  const [first, ...rest] = m[1].split(' ');
  return rest.length && rest[0].toLowerCase().startsWith(first.toLowerCase()) ? rest.join(' ') : m[1];
}

/**
 * One line per host that did not answer, with the services it had:
 * "Host 172.30.5.3 nie odpowiada (niepotwierdzone): :80 nginx, :6379 redis",
 * later "Host 172.30.5.3 zniknął (potwierdzone 20:05): …".
 */
export function MissingHostLines({ changes, names }: { changes: Change[]; names?: (c: Change) => string }) {
  const missing = changes.filter((c) => c.kind === 'host_missing' && !c.expected);
  const verdicts = useHostVerdicts(missing);
  if (!missing.length) return null;
  return (
    <>
      {missing.map((m, mi) => {
        const svcs = changes.filter((c) => c.kind === 'service_unreachable' && c.host_id === m.host_id).sort((a, b) => (a.port ?? 0) - (b.port ?? 0));
        const v = verdicts.get(m.host_id);
        const state = !v ? 'unconfirmed' : v.kind === 'host_gone' ? 'gone' : 'back';
        const head = state === 'unconfirmed'
          ? t('nie odpowiada (niepotwierdzone)', 'is not responding (unconfirmed)')
          : state === 'gone'
            ? t('nieaktywny (potwierdzone ' + fmtTime(v!.at) + ')', 'is down (confirmed ' + fmtTime(v!.at) + ')')
            : t('znów odpowiada (' + fmtTime(v!.at) + ')', 'responds again (' + fmtTime(v!.at) + ')');
        return (
          <li key={'m:' + mi + ':' + m.ip + ':' + (m.id || 0)} className="flex items-start gap-2 text-base" data-testid="missing-host" data-state={state}>
            <span className="mt-[5px]">{state === 'unconfirmed' ? <Glyph name="half" tone="changed" /> : state === 'gone' ? <Glyph name="minus" tone="gone" /> : <Glyph name="back" tone="new" />}</span>
            <span className="min-w-0">
              <span className="font-medium">{t('Host ', 'Host ')}<Link to={'/hosts/' + m.host_id} className="mono link">{m.ip}</Link> {head}</span>
              {svcs.length ? <>{t(', miał ', ', it had ')}{svcs.length} {plural(svcs.length, ['usługę', 'usługi', 'usług'], ['service', 'services'])}{': '}{svcs.slice(0, 8).map((c, i) => (
                <span key={'s:' + i + ':' + (c.port ?? '') + ':' + (c.id || 0)}>{i ? ', ' : ''}<Link to={c.service_id ? '/services/' + c.service_id : '/hosts/' + c.host_id} className="mono link">:{c.port}{(names?.(c) || nameOf(c)) ? ' ' + (names?.(c) || nameOf(c)) : ''}</Link></span>
              ))}{svcs.length > 8 ? t(' i ' + (svcs.length - 8) + ' więcej', ' and ' + (svcs.length - 8) + ' more') : ''}</> : null}
            </span>
          </li>
        );
      })}
    </>
  );
}
