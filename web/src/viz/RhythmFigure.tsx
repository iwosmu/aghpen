import { useCallback, useEffect, useRef } from 'react';
import { WEEK_ORDER, weekday } from '../lib/format';
import { t } from '../i18n';

// A schematic, not data: one made-up office host, told in time.
// 1. Four weeks of observation build the pattern: days answer, nights are silent.
// 2. The silent night gets its outline: silence there is usual.
// 3. This week a scan cursor walks the grid; answering cells tick, night cells stay dark.
// 4. Wednesday 10:00: the host should answer and does not. Three re-checks, then the alarm.
// WAAPI on transform and opacity only; under prefers-reduced-motion the last frame shows at once.

const COLS = 12; // two-hour columns
const ALARM = { row: 2, col: 5 }; // Wednesday 10:00-12:00
const NIGHT = { rows: 5, cols: 3 }; // Monday-Friday 00:00-06:00

function level(row: number, col: number): number {
  if (row >= 5) return 0;
  const fri = row === 4;
  if (col === 3) return 2;
  if (col >= 4 && col <= (fri ? 7 : 8)) return 4;
  if (col === (fri ? 8 : 9)) return 1;
  return 0;
}

const T_LEARN = 300, WEEK = 900, T_NIGHT = 4000, T_WALK = 4900, MOVE = 70;
const DWELL_NIGHT_SLOW = 520, DWELL_NIGHT = 260, DWELL = 115;

type Step = { row: number; col: number; at: number; dwell: number };
function walk(): Step[] {
  const out: Step[] = [];
  let at = T_WALK;
  for (let row = 0; row <= ALARM.row; row++) {
    for (let col = 0; col < COLS; col++) {
      if (row === ALARM.row && col > ALARM.col) break;
      const night = col < NIGHT.cols;
      const dwell = night ? (row === 0 ? DWELL_NIGHT_SLOW : DWELL_NIGHT) : DWELL;
      out.push({ row, col, at, dwell });
      at += dwell;
    }
  }
  return out;
}
const STEPS = walk();
const T_ALARM = STEPS[STEPS.length - 1].at; // the cursor arrives at Wednesday 10:00
const T_PULSE = T_ALARM + 500, PULSE = 700;
const T_CORAL = T_PULSE + 3 * PULSE + 100;
export const RHYTHM_PLAY_MS = T_CORAL + 600;

const pos = (row: number, col: number) => 'translate(calc(' + col + ' * (100% + 3px)), calc(' + row + ' * (100% + 3px)))';

function play(root: HTMLElement) {
  root.getAnimations({ subtree: true }).forEach((a) => a.cancel());
  const q = (s: string) => Array.from(root.querySelectorAll<HTMLElement>(s));
  const ease = 'cubic-bezier(0.22, 1, 0.36, 1)';

  // 1. learning: each answering cell gains a quarter of its colour per week
  for (const el of q('[data-learn]')) {
    const kf: Keyframe[] = [{ opacity: 0, offset: 0 }];
    for (let w = 1; w <= 4; w++) { kf.push({ opacity: (w - 1) / 4, offset: (w - 1) / 4 }); kf.push({ opacity: w / 4, offset: (w - 1) / 4 + 0.12 }); }
    kf.push({ opacity: 1, offset: 1 });
    el.animate(kf, { duration: 4 * WEEK, delay: T_LEARN, fill: 'both' });
  }
  q('[data-week]').forEach((el) => {
    const w = Number(el.dataset.week);
    const start = w <= 4 ? T_LEARN + (w - 1) * WEEK : T_WALK - 200;
    const dur = w <= 4 ? WEEK : RHYTHM_PLAY_MS - start - 100;
    el.animate([{ opacity: 0 }, { opacity: 1, offset: 0.08 }, { opacity: 1, offset: 0.92 }, { opacity: 0 }], { duration: dur, delay: start, fill: 'both' });
  });

  // 2. the usual silence gets its outline
  for (const el of q('[data-night]')) el.animate([{ opacity: 0, transform: 'scale(1.04)' }, { opacity: 1, transform: 'none' }], { duration: 600, delay: T_NIGHT, easing: ease, fill: 'both' });
  for (const el of q('[data-legend="night"]')) el.animate([{ opacity: 0, transform: 'translateY(4px)' }, { opacity: 1, transform: 'none' }], { duration: 500, delay: T_NIGHT + 200, easing: ease, fill: 'both' });

  // 3. this week: the cursor walks, answering cells tick, night cells do nothing
  const cursor = root.querySelector<HTMLElement>('[data-cursor]');
  if (cursor) {
    const end = T_CORAL + 300;
    const kf: Keyframe[] = [{ transform: pos(0, 0), opacity: 0, offset: 0 }, { transform: pos(0, 0), opacity: 0, offset: (T_WALK - 250) / end }];
    STEPS.forEach((s, i) => {
      kf.push({ transform: pos(s.row, s.col), opacity: 1, offset: s.at / end });
      if (i < STEPS.length - 1) kf.push({ transform: pos(s.row, s.col), opacity: 1, offset: (s.at + s.dwell - MOVE) / end });
    });
    kf.push({ transform: pos(ALARM.row, ALARM.col), opacity: 1, offset: T_CORAL / end });
    kf.push({ transform: pos(ALARM.row, ALARM.col), opacity: 0, offset: 1 });
    cursor.animate(kf, { duration: end, fill: 'both' });
  }
  for (const s of STEPS) {
    if (level(s.row, s.col) === 0 || (s.row === ALARM.row && s.col === ALARM.col)) continue;
    const tick = root.querySelector<HTMLElement>('[data-tick="' + s.row + '-' + s.col + '"]');
    tick?.animate([{ opacity: 0, transform: 'scale(0.3)' }, { opacity: 1, transform: 'scale(1)', offset: 0.25 }, { opacity: 0, transform: 'scale(1.5)' }], { duration: 480, delay: s.at, easing: 'ease-out', fill: 'both' });
  }

  // 4. Wednesday 10:00: expected, silent, re-checked three times, then the alarm
  const learnA = root.querySelector<HTMLElement>('[data-alarm-learn]');
  learnA?.animate([{ opacity: 1 }, { opacity: 0.12 }], { duration: 350, delay: T_ALARM, fill: 'forwards' });
  const ghost = root.querySelector<HTMLElement>('[data-ghost]');
  ghost?.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 250, delay: T_ALARM, fill: 'both' });
  ghost?.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 300, delay: T_CORAL, fill: 'forwards' });
  q('[data-pulse]').forEach((el, i) => el.animate([{ opacity: 0.95, transform: 'scale(1)' }, { opacity: 0, transform: 'scale(2.6)' }], { duration: PULSE, delay: T_PULSE + i * PULSE, easing: 'ease-out', fill: 'forwards' }));
  for (const el of q('[data-coral]')) el.animate([{ opacity: 0, transform: 'scale(0.6)' }, { opacity: 1, transform: 'none' }], { duration: 380, delay: T_CORAL, easing: ease, fill: 'both' });
  for (const el of q('[data-legend="alarm"]')) el.animate([{ opacity: 0, transform: 'translateY(4px)' }, { opacity: 1, transform: 'none' }], { duration: 500, delay: T_CORAL + 150, easing: ease, fill: 'both' });
}

/** The rhythm card of the login page: a short storyboard of how Czujka reads a silence. */
export function RhythmFigure() {
  const root = useRef<HTMLDivElement>(null);
  const busyUntil = useRef(0);
  const start = useCallback(() => {
    const el = root.current;
    if (!el || typeof el.animate !== 'function') return;
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
    if (performance.now() < busyUntil.current) return;
    busyUntil.current = performance.now() + RHYTHM_PLAY_MS;
    play(el);
  }, []);
  useEffect(() => {
    const el = root.current;
    start();
    const id = window.setInterval(start, RHYTHM_PLAY_MS + 30000);
    return () => { window.clearInterval(id); busyUntil.current = 0; el?.getAnimations({ subtree: true }).forEach((a) => a.cancel()); };
  }, [start]);

  const alarmLabel = t('alarm', 'alarm') + ' · ' + weekday(WEEK_ORDER[ALARM.row]) + ' 10:00';
  return (
    <figure className="login-glass m-0 overflow-hidden !bg-[rgb(8_12_19/0.72)]" data-testid="rhythm-figure" onMouseEnter={start} onClick={start}>
      <p className="sr-only">{t(
        'Schemat: przez kilka tygodni Czujka uczy się, kiedy host odpowiada. Cisza w nocy jest zwykła i nie budzi alarmu. W środę o 10:00 host milczy, choć zwykle wtedy odpowiada: Czujka sprawdza go trzy razy i zgłasza alarm.',
        'Diagram: over a few weeks Czujka learns when a host answers. Silence at night is usual and raises no alarm. On Wednesday at 10:00 the host is silent although it usually answers then: Czujka checks it three times and raises an alarm.',
      )}</p>
      <div ref={root} aria-hidden="true" className="p-5 sm:p-6 xl:p-7">
        <div className="mono mb-4 flex items-baseline justify-between gap-3 text-2xs uppercase tracking-[0.16em] text-ink-3">
          <span>{t('schemat', 'diagram')}</span>
          <span className="grid justify-items-end whitespace-nowrap text-ink-2">
            {[1, 2, 3, 4, 5].map((w) => (
              <span key={w} data-week={w} className="opacity-0 [grid-area:1/1]">{w <= 4 ? t('tydzień ' + w, 'week ' + w) : t('ten tydzień', 'this week')}</span>
            ))}
          </span>
        </div>
        <div className="grid gap-[3px]" style={{ gridTemplateColumns: '26px repeat(' + COLS + ', minmax(0, 1fr))', gridTemplateRows: '14px repeat(7, auto)' }}>
          {[0, 3, 6, 9].map((c) => (
            <span key={'h' + c} className="num text-2xs leading-none text-ink-3" style={{ gridRow: 1, gridColumn: c + 2 }}>{String(c * 2).padStart(2, '0')}</span>
          ))}
          {WEEK_ORDER.map((wd, row) => (
            <span key={'d' + wd} className="flex items-center text-2xs text-ink-3" style={{ gridRow: row + 2, gridColumn: 1 }}>{weekday(wd)}</span>
          ))}
          {WEEK_ORDER.flatMap((_, row) => Array.from({ length: COLS }).map((__, col) => {
            const L = level(row, col);
            const alarm = row === ALARM.row && col === ALARM.col;
            return (
              <span key={row + '-' + col} className={'relative block aspect-square rounded-[3px] bg-[var(--seq-0)]' + (alarm ? ' z-[3]' : '')} style={{ gridRow: row + 2, gridColumn: col + 2 }}>
                {L > 0 ? <span data-learn="" {...(alarm ? { 'data-alarm-learn': '' } : {})} className="absolute inset-0 rounded-[3px]" style={{ background: 'var(--seq-' + L + ')', opacity: alarm ? 0.12 : 1 }} /> : null}
                {L > 0 && !alarm ? <span data-tick={row + '-' + col} className="absolute inset-[30%] rounded-full bg-[#f4f1e9] opacity-0 shadow-[0_0_12px_2px_rgb(244_241_233/0.6)]" /> : null}
                {alarm ? (
                  <>
                    <span data-ghost className="absolute inset-0 rounded-[3px] opacity-0" style={{ boxShadow: 'inset 0 0 0 2px var(--seq-4)' }} />
                    {[0, 1, 2].map((i) => <span key={i} data-pulse className="absolute inset-0 rounded-[3px] border-2 border-[#f2907f] opacity-0" />)}
                    <span data-coral className="absolute inset-0 rounded-[3px] bg-st-gone-wash" style={{ boxShadow: 'inset 0 0 0 2px var(--st-gone)' }}>
                      <span className="absolute left-1/2 top-1/2 h-[2px] w-1/2 -translate-x-1/2 -translate-y-1/2 bg-st-gone" />
                    </span>
                  </>
                ) : null}
              </span>
            );
          }))}
          <span data-night className="pointer-events-none z-[2] -m-[3px] rounded-[5px] border-2 border-dashed border-ink-2" style={{ gridRow: '2 / span ' + NIGHT.rows, gridColumn: '2 / span ' + NIGHT.cols }} />
          <span data-cursor className="pointer-events-none z-[4] aspect-square rounded-[3px] opacity-0 shadow-[0_0_0_2px_#f4f1e9,0_0_18px_4px_rgb(244_241_233/0.35)]" style={{ gridRow: 2, gridColumn: 2 }} />
        </div>
        <ul className="mt-5 flex flex-wrap gap-x-8 gap-y-2 text-sm">
          <li data-legend="night" className="flex items-center gap-2.5">
            <span className="block h-3.5 w-3.5 flex-none rounded-[3px] border-2 border-dashed border-ink-2" />
            <span className="font-medium text-ink">{t('zwykle milczy', 'usually silent')}</span>
          </li>
          <li data-legend="alarm" className="flex items-center gap-2.5">
            <span className="relative block h-3.5 w-3.5 flex-none rounded-[3px] bg-st-gone-wash" style={{ boxShadow: 'inset 0 0 0 2px var(--st-gone)' }}>
              <span className="absolute left-1/2 top-1/2 h-[2px] w-1.5 -translate-x-1/2 -translate-y-1/2 bg-st-gone" />
            </span>
            <span className="font-medium text-ink">{alarmLabel}</span>
          </li>
        </ul>
      </div>
    </figure>
  );
}
