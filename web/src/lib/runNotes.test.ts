import { describe, expect, it } from 'vitest';
import { runNoteText } from './runNotes';

const note = 'pełny zakres portów (1-65535) objął 0 z 19 aktywnych hostów; pozostałe: porty z profilu';

describe('runNoteText', () => {
  it('keeps the Polish note and starts it with a capital letter', () => {
    expect(runNoteText(note, 'pl')).toBe('Pełny zakres portów (1-65535) objął 0 z 19 aktywnych hostów; pozostałe: porty z profilu');
  });
  it('gives the known full-range note in English', () => {
    expect(runNoteText(note, 'en')).toBe('The full port range (1-65535) covered 0 of 19 live hosts; the others: the ports of the profile');
  });
  it('leaves an unknown note as the API wrote it', () => {
    expect(runNoteText('inna uwaga', 'en')).toBe('Inna uwaga');
  });
});
