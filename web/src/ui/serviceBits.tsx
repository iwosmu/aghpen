import type { Service } from '../api/types';
import { t } from '../i18n';
import { cx, fmtMs } from '../lib/format';

/** The tag the server puts on Czujka's own UI port on the scanned host. */
export function SelfTag() {
  return <span className="ml-2 whitespace-nowrap rounded-[4px] border border-rule-strong px-1 text-2xs text-ink-2" title={t('To interfejs tej Czujki.', 'The UI of this Czujka.')} data-testid="self-tag">{t('ta Czujka', 'this Czujka')}</span>;
}

/** The latest HTTP response time of a service; "wolniej" when the server marks it slow. */
export function ResponseCell({ s }: { s: Pick<Service, 'response_ms' | 'response_slow'> }) {
  if (s.response_ms === undefined || s.response_ms === null) return <span className="num text-ink-3">–</span>;
  return <span className={cx('num whitespace-nowrap', s.response_slow ? 'text-st-changed' : 'text-ink-2')} title={s.response_slow ? t('wolniej niż zwykle', 'slower than usual') : undefined}>{fmtMs(s.response_ms)}{s.response_slow ? ' ▲' : ''}</span>;
}
