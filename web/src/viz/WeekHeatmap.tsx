import type { AvailBucket } from '../api/types';
import { WEEK_ORDER, weekday, fmtPct } from '../lib/format';
import { t } from '../i18n';
import { useTip } from '../ui/kit';

// Hour-of-week availability: 7 rows (Monday first) by 24 hours. The fill is the
// share of probes the host answered in that hour; an hour with no probe is hollow.
function step(rate: number): number {
  if (rate >= 0.9) return 5;
  if (rate >= 0.7) return 4;
  if (rate >= 0.5) return 3;
  if (rate >= 0.25) return 2;
  if (rate > 0.05) return 1;
  return 0;
}

export function WeekHeatmap({ buckets, nowIndex }: { buckets: AvailBucket[]; nowIndex?: number }) {
  const tip = useTip();
  const body = (wd: number, hr: number) => {
    const b = buckets[wd * 24 + hr] ?? { up: 0, down: 0 };
    const n = b.up + b.down;
    const label = weekday(wd) + ' ' + String(hr).padStart(2, '0') + ':00–' + String((hr + 1) % 24).padStart(2, '0') + ':00';
    return (
      <div>
        <div className="font-medium text-ink">{label}</div>
        {n === 0
          ? <div className="text-ink-3">{t('brak prób w tej godzinie', 'no probes in this hour')}</div>
          : <div className="text-ink-2"><span className="num text-ink">{fmtPct(b.up / n)}</span> · {t('odpowiedź w ' + b.up + ' z ' + n + ' prób', 'responded ' + b.up + ' of ' + n + ' probes')}</div>}
      </div>
    );
  };
  return (
    <div>
      <div className="grid gap-px" style={{ gridTemplateColumns: '26px repeat(24, minmax(0, 1fr))' }} role="img" aria-label={t('Mapa dostępności hosta: dni tygodnia w wierszach, godziny w kolumnach', 'Host availability map: weekdays in rows, hours in columns')}>
        <span />
        {Array.from({ length: 24 }).map((_, hr) => (
          <span key={hr} className="num h-[14px] text-center text-2xs text-ink-3">{hr % 3 === 0 ? String(hr).padStart(2, '0') : ''}</span>
        ))}
        {WEEK_ORDER.map((wd) => (
          <div key={wd} className="contents">
            <span className="flex items-center text-2xs text-ink-3">{weekday(wd)}</span>
            {Array.from({ length: 24 }).map((_, hr) => {
              const i = wd * 24 + hr;
              const b = buckets[i] ?? { up: 0, down: 0 };
              const n = b.up + b.down;
              const isNow = nowIndex === i;
              return (
                <button
                  key={hr} type="button" tabIndex={-1}
                  onPointerEnter={(e) => tip.show(e, body(wd, hr))} onPointerLeave={tip.hide}
                  onFocus={(e) => tip.showAt(e.currentTarget, body(wd, hr))} onBlur={tip.hide}
                  className="relative block aspect-square min-h-[10px] w-full cursor-default"
                  style={n === 0 ? { boxShadow: 'inset 0 0 0 1px var(--rule)' } : { background: 'var(--seq-' + step(b.up / n) + ')' }}
                  aria-label={weekday(wd) + ' ' + hr + ':00, ' + (n === 0 ? t('brak danych', 'no data') : fmtPct(b.up / n))}
                >
                  {isNow ? <span className="absolute inset-[-2px] border-[1.5px] border-ink" aria-hidden="true" /> : null}
                </button>
              );
            })}
          </div>
        ))}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-2">
        <span className="inline-flex items-center gap-1.5">
          {t('odpowiedzi:', 'responses:')}
          <span className="num text-2xs text-ink-3">0%</span>
          <span className="inline-flex gap-px">{[0, 1, 2, 3, 4, 5].map((s) => <span key={s} className="block h-[10px] w-[18px]" style={{ background: 'var(--seq-' + s + ')' }} />)}</span>
          <span className="num text-2xs text-ink-3">100%</span>
        </span>
        <span className="inline-flex items-center gap-1.5"><span className="block h-[10px] w-[10px]" style={{ boxShadow: 'inset 0 0 0 1px var(--rule-strong)' }} />{t('brak prób', 'no probes')}</span>
        {nowIndex !== undefined ? <span className="inline-flex items-center gap-1.5"><span className="block h-[10px] w-[10px] border-[1.5px] border-ink" />{t('teraz', 'now')}</span> : null}
      </div>
      {tip.node}
    </div>
  );
}
