import { getLang } from '../i18n';

/** The full-range note of RunStats.notes, as the engine writes it (Polish). */
const FULL_RANGE = /^pełny zakres portów \(1-65535\) objął (\d+) z (\d+) aktywnych hostów; pozostałe: porty z profilu$/;

/**
 * One run note for the reader. The API writes notes in Polish; a note whose
 * pattern is known gets an English sentence in the EN view. An unknown note
 * stays as the API wrote it. The first letter is upper case.
 */
export function runNoteText(note: string, lang: 'pl' | 'en' = getLang()): string {
  const m = FULL_RANGE.exec(note.trim());
  let s = note.trim();
  if (m && lang === 'en') {
    s = 'the full port range (1-65535) covered ' + m[1] + ' of ' + m[2] + ' live hosts; the others: the ports of the profile';
  }
  return s.charAt(0).toUpperCase() + s.slice(1);
}
