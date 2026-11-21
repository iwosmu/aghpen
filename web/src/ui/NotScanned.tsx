import { t } from '../i18n';

/** Why a row is dimmed: the run did not cover this port, so the row repeats the last observation. */
export function notScannedHint(): string {
  return t(
    'Ten przebieg nie sprawdzał tego portu (na przykład znalazł go wcześniej pełny zakres 1-65535, a ten skan objął tylko wybrane porty). Stan pochodzi z ostatniej obserwacji.',
    'This run did not check this port (for example the full range 1-65535 found it earlier and this scan covered only chosen ports). The state comes from the last observation.',
  );
}

/** "nie skanowany w tym przebiegu", shown in place of a fresh state. */
export function NotScanned() {
  return (
    <span className="whitespace-nowrap text-xs text-ink-3" title={notScannedHint()} data-testid="not-scanned">
      {t('nie skanowany w tym przebiegu', 'not scanned in this run')}
    </span>
  );
}

/** Rows not scanned in a run go after the scanned ones; the order inside each part stays. */
export function scannedFirst<T extends { carried?: boolean }>(rows: T[]): T[] {
  return [...rows.filter((r) => !r.carried), ...rows.filter((r) => r.carried)];
}
