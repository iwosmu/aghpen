import { t } from '../i18n';

/** Why a row is dimmed: the run did not cover this port, so the row repeats the last observation. */
export function notScannedHint(): string {
  return t(
    'Ten skan nie sprawdzał tego portu. Stan pochodzi z ostatniej obserwacji.',
    'This scan did not check this port. The status comes from the last observation.',
  );
}

/** "nie skanowany w tym przebiegu", shown in place of a fresh state. */
export function NotScanned() {
  return (
    <span className="whitespace-nowrap text-xs text-ink-3" title={notScannedHint()} data-testid="not-scanned">
      {t('poza tym skanem', 'outside this scan')}
    </span>
  );
}

/** Rows not scanned in a run go after the scanned ones; the order inside each part stays. */
export function scannedFirst<T extends { carried?: boolean }>(rows: T[]): T[] {
  return [...rows.filter((r) => !r.carried), ...rows.filter((r) => r.carried)];
}
