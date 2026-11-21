import { describe, expect, it } from 'vitest';
import { setLang } from '../i18n';
import { passwordProblem } from './PasswordDialog';

describe('passwordProblem', () => {
  it('checks the current password, the length and the repeat', () => {
    setLang('en');
    expect(passwordProblem('', 'abcdefghij', 'abcdefghij')).toMatch(/current/);
    expect(passwordProblem('old', 'short', 'short')).toMatch(/at least 10/);
    expect(passwordProblem('old', 'x'.repeat(257), 'x'.repeat(257))).toMatch(/at most 256/);
    expect(passwordProblem('old', 'abcdefghij', 'abcdefghik')).toMatch(/different/);
    expect(passwordProblem('old', 'abcdefghij', 'abcdefghij')).toBe('');
    setLang('pl');
  });
});
