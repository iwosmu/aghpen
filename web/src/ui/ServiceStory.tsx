import { Link } from 'react-router';
import { usePage, useItem } from '../api/hooks';
import type { Change, ResponseTimes, Service } from '../api/types';
import { t } from '../i18n';
import { cx, fmtDateTime, fmtMs } from '../lib/format';
import { routeMissing } from '../lib/route';
import { Panel } from './kit';
import { Glyph, changeKindInfo } from './marks';
import { awayText, responseDelta } from '../lib/changeText';

const LIFE = ['service_new', 'service_gone', 'service_returned', 'response_slower', 'response_recovered', 'host_gone', 'host_back', 'host_missing'];

/** The life of one service as one story: first seen, gone, back, slower, oldest first. */
export function ServiceStory({ s }: { s: Service }) {
  const q = usePage<Change>('/changes', { host_id: s.host_id, limit: 500 });
  const events = (q.data?.items ?? [])
    .filter((c) => LIFE.includes(c.kind) && (c.port === s.port || c.kind.startsWith('host_')))
    .sort((a, b) => a.at.localeCompare(b.at) || a.id - b.id);
  const hasStory = events.some((c) => c.kind !== 'service_new');
  if (!hasStory) return null;
  return (
    <Panel title={t('Historia usługi', 'Service story')} flush>
      <ol className="divide-y divide-rule" data-testid="service-story">
        <li className="grid grid-cols-[18px_minmax(0,1fr)_auto] items-start gap-x-2 px-3 py-1.5 text-sm">
          <span className="mt-[3px]"><Glyph name="plus" tone="new" /></span>
          <span>{t('Pierwszy raz otwarta', 'First seen open')}</span>
          <span className="num whitespace-nowrap text-xs text-ink-3">{fmtDateTime(s.first_seen)}</span>
        </li>
        {events.filter((c) => c.kind !== 'service_new' || events.indexOf(c) > 0).map((c) => {
          const i = changeKindInfo(c.kind);
          const extra = c.kind === 'service_returned' ? awayText(c) : c.kind.startsWith('response_') ? responseDelta(c) : '';
          return (
            <li key={c.id} className="grid grid-cols-[18px_minmax(0,1fr)_auto] items-start gap-x-2 px-3 py-1.5 text-sm" data-kind={c.kind}>
              <span className="mt-[3px]"><Glyph name={i.glyph} tone={i.tone} /></span>
              <span><span className="font-medium">{i.label}</span>{extra ? <span className="num text-ink-2">{' · ' + extra}</span> : null}</span>
              <span className="whitespace-nowrap text-xs text-ink-3"><Link to={'/runs/' + c.run_id} className="num link">#{c.run_id}</Link> · <span className="num">{fmtDateTime(c.at)}</span></span>
            </li>
          );
        })}
      </ol>
    </Panel>
  );
}

/** Response time over runs (GET /services/{id}/response-times): one bar per run, slow ones marked. */
export function ResponseTimeChart({ serviceId }: { serviceId: number }) {
  const q = useItem<ResponseTimes>('/services/' + serviceId + '/response-times', { limit: 50 });
  if (q.error && routeMissing(q.error)) return null;
  const pts = q.data?.points ?? [];
  if (!q.data || pts.length === 0) return null;
  const max = Math.max(1, ...pts.map((p) => Math.max(p.ms ?? 0, p.baseline_ms ?? 0)));
  const last = pts[pts.length - 1];
  const base = [...pts].reverse().find((p) => p.baseline_ms !== null)?.baseline_ms ?? null;
  const H = 72;
  return (
    <Panel title={t('Czas odpowiedzi HTTP', 'HTTP response time')} actions={<span className="text-ink-3">{t('ostatnio', 'last')} <span className={cx('num', last.slow ? 'text-st-changed' : 'text-ink')}>{last.ms === null ? t('brak odpowiedzi', 'no answer') : fmtMs(last.ms)}</span>{base !== null ? <> · {t('zwykle', 'usually')} <span className="num text-ink-2">{fmtMs(base)}</span></> : null}</span>}>
      <div className="relative" style={{ height: H }} data-testid="response-chart" role="img" aria-label={t('Czas odpowiedzi w kolejnych skanach', 'Response time over runs')}>
        {base !== null ? <div className="absolute inset-x-0 border-t border-dashed border-ink-3" style={{ bottom: (base / max) * H }} title={t('zwykły czas (mediana)', 'usual time (median)')} /> : null}
        <div className="absolute inset-0 flex items-end gap-[3px]">
          {pts.map((p) => (
            <Link key={p.run_id} to={'/runs/' + p.run_id} className="group relative flex h-full min-w-[4px] max-w-[22px] flex-1 items-end" title={'#' + p.run_id + ' · ' + fmtDateTime(p.at) + ' · ' + (p.ms === null ? t('brak odpowiedzi HTTP', 'no HTTP answer') : fmtMs(p.ms)) + (p.slow ? ' · ' + t('wolniej niż zwykle', 'slower than usual') : '')}>
              {p.ms === null
                ? <span className="mb-0 w-full text-center text-xs leading-none text-st-gone">×</span>
                : <span className={cx('w-full group-hover:opacity-80', p.slow ? 'bg-st-changed' : 'bg-accent')} style={{ height: Math.max(2, (p.ms / max) * H) }} />}
            </Link>
          ))}
        </div>
      </div>
      <div className="mt-1 flex justify-between text-2xs text-ink-3">
        <span className="num">#{pts[0].run_id}</span>
        <span>{t('słupek = skan; wyróżniony = wolniej niż zwykle; × = brak odpowiedzi HTTP', 'bar = run; highlighted = slower than usual; × = no HTTP answer')}</span>
        <span className="num">#{last.run_id}</span>
      </div>
    </Panel>
  );
}
