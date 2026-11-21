import { WEEK_ORDER, weekday } from '../lib/format';
import { t } from '../i18n';

// A schematic, not data: the hour-of-week rhythm of one made-up office host,
// drawn in the language of WeekHeatmap. Weekdays 8-17 it answers, nights and
// weekends it is silent (expected), and one working hour is silent although the
// host usually answers then: that silence is what Czujka reports.

const ALARM = { row: 2, hour: 10 }; // Wednesday 10:00 (row index in WEEK_ORDER)
const NIGHT = { rows: 5, from: 0, to: 6 }; // Monday-Friday 00:00-06:00

function level(row: number, hour: number): number {
  if (row >= 5) return 0; // weekend
  const fri = row === 4;
  if (hour >= 8 && hour <= (fri ? 14 : 17)) return 4;
  if (hour === 7 || hour === (fri ? 15 : 18)) return 3;
  if (hour === 6 || hour === (fri ? 16 : 19)) return 1;
  return 0;
}

/** The rhythm diagram as a card: the object of the login page. */
export function RhythmFigure({ compact = false }: { compact?: boolean }) {
  const alarmDay = weekday(WEEK_ORDER[ALARM.row]);
  return (
    <figure className="m-0 border border-rule bg-panel shadow-[0_40px_80px_-30px_rgb(0_0_0/0.85),0_2px_0_0_rgb(255_255_255/0.03)_inset]" data-testid="rhythm-figure">
      <div className="mono flex items-center justify-between gap-3 border-b border-rule px-4 py-2 text-2xs uppercase tracking-[0.14em] text-ink-3">
        <span>{t('Schemat · tydzień jednego hosta', 'Diagram · one host\'s week')}</span>
        <span>{t('nie dane', 'not data')}</span>
      </div>
      <div className={compact ? 'p-4' : 'p-5 xl:p-6'}>
        <figcaption className="mb-4">
          <span className={'font-display block leading-none text-ink ' + (compact ? 'text-[28px]' : 'text-[34px] xl:text-[40px]')}>{t('Jak Czujka czyta ciszę', 'How Czujka reads a silence')}</span>
          <span className="mt-2 block text-xs text-ink-3">{t('Czujka uczy się, w których godzinach host zwykle odpowiada.', 'Czujka learns in which hours a host usually answers.')}</span>
        </figcaption>
        <div
          className="grid gap-[2px]"
          style={{ gridTemplateColumns: (compact ? '22px' : '30px') + ' repeat(24, minmax(0, 1fr))', gridTemplateRows: '16px repeat(7, auto)' }}
          role="img"
          aria-label={t(
            'Schemat rytmu hosta: w dni robocze odpowiada od 8 do 17, nocą i w weekend milczy, co jest oczekiwane. W środę o 10:00 milczy, choć zwykle wtedy odpowiada: to jest alarm.',
            'Diagram of a host rhythm: on weekdays it answers from 8 to 17, at night and at the weekend it is silent, which is expected. On Wednesday at 10:00 it is silent although it usually answers then: that is the alarm.',
          )}
        >
          {Array.from({ length: 24 }).map((_, h) => (
            <span key={'h' + h} className="num text-center text-2xs leading-none text-ink-3" style={{ gridRow: 1, gridColumn: h + 2 }} aria-hidden="true">
              {h % (compact ? 6 : 3) === 0 ? String(h).padStart(2, '0') : ''}
            </span>
          ))}
          {WEEK_ORDER.map((wd, row) => (
            <span key={'d' + wd} className="flex items-center text-2xs text-ink-3" style={{ gridRow: row + 2, gridColumn: 1 }} aria-hidden="true">{weekday(wd)}</span>
          ))}
          {WEEK_ORDER.flatMap((_, row) => Array.from({ length: 24 }).map((__, h) => {
            const alarm = row === ALARM.row && h === ALARM.hour;
            return (
              <span
                key={row + '-' + h}
                aria-hidden="true"
                className={'relative block aspect-square' + (alarm ? ' z-[2]' : '')}
                style={{
                  gridRow: row + 2, gridColumn: h + 2,
                  background: alarm ? 'var(--st-gone-wash)' : 'var(--seq-' + level(row, h) + ')',
                  boxShadow: alarm ? 'inset 0 0 0 2px var(--st-gone)' : undefined,
                }}
              >
                {alarm ? <><span className="rhythm-alarm-ring absolute inset-0" /><span className="absolute left-1/2 top-1/2 h-[2px] w-1/2 -translate-x-1/2 -translate-y-1/2 bg-st-gone" /></> : null}
              </span>
            );
          }))}
          <span aria-hidden="true" className="rhythm-sweep z-[1]" style={{ gridRow: '2 / span 7', gridColumn: 2 }} />
          <span
            aria-hidden="true"
            className={'pointer-events-none z-[1] border-dashed border-ink-2 ' + (compact ? '-m-[2px] border-[1.5px]' : '-m-[3px] border-2')}
            style={{ gridRow: '2 / span ' + NIGHT.rows, gridColumn: NIGHT.from + 2 + ' / span ' + (NIGHT.to - NIGHT.from) }}
          />
        </div>
        <ul className={'mt-4 grid gap-x-6 gap-y-2 text-ink-2 ' + (compact ? 'text-xs' : 'text-sm sm:grid-cols-2')}>
          <li className="flex items-start gap-2.5">
            <span className="mt-[2px] block h-3.5 w-3.5 flex-none border-2 border-dashed border-ink-2" aria-hidden="true" />
            <span><span className="font-medium text-ink">{t('zwykle milczy', 'usually silent')}</span>{t(' · noc: cisza oczekiwana, bez alarmu', ' · night: an expected silence, no alarm')}</span>
          </li>
          <li className="flex items-start gap-2.5">
            <span className="relative mt-[2px] block h-3.5 w-3.5 flex-none bg-st-gone-wash" style={{ boxShadow: 'inset 0 0 0 2px var(--st-gone)' }} aria-hidden="true">
              <span className="absolute left-1/2 top-1/2 h-[2px] w-1.5 -translate-x-1/2 -translate-y-1/2 bg-st-gone" />
            </span>
            <span><span className="font-medium text-ink">{t('alarm', 'alarm')}</span>{t(' · ' + alarmDay + ' 10:00 milczy, choć zwykle odpowiada. Czujka sprawdza ponownie i zgłasza.', ' · ' + alarmDay + ' 10:00 silent, though it usually answers. Czujka checks again and reports it.')}</span>
          </li>
        </ul>
      </div>
    </figure>
  );
}
