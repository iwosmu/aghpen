import { useState, type FormEvent } from 'react';
import { ApiError, post } from '../api/client';
import { t } from '../i18n';
import { Button, Dialog, InlineError, toast } from '../ui/kit';

export const MIN_PASSWORD = 10;
export const MAX_PASSWORD = 256;

/** Client-side checks before the request; the server checks again. '' = fine. */
export function passwordProblem(current: string, next: string, repeat: string): string {
  if (!current) return t('Wpisz obecne hasło.', 'Enter the current password.');
  if (next.length < MIN_PASSWORD) return t('Nowe hasło musi mieć co najmniej ' + MIN_PASSWORD + ' znaków.', 'The new password needs at least ' + MIN_PASSWORD + ' characters.');
  if (next.length > MAX_PASSWORD) return t('Nowe hasło może mieć najwyżej ' + MAX_PASSWORD + ' znaków.', 'The new password can have at most ' + MAX_PASSWORD + ' characters.');
  if (next !== repeat) return t('Powtórzone hasło jest inne.', 'The repeated password is different.');
  return '';
}

/** "Zmień hasło": current, new, repeat. 204 keeps this session and ends the others. */
export function PasswordDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [problem, setProblem] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const close = () => { setCurrent(''); setNext(''); setRepeat(''); setProblem(''); setError(null); onClose(); };
  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    const p = passwordProblem(current, next, repeat);
    setProblem(p);
    setError(null);
    if (p) return;
    setBusy(true);
    try {
      await post('/auth/password', { current_password: current, new_password: next });
      toast(t('Hasło zmienione. Inne sesje tego konta zostały zakończone.', 'Password changed. Other sessions of this account have ended.'));
      close();
    } catch (err) {
      if (err instanceof ApiError && err.status === 422) {
        // the server names the field: "current_password: …" or "new_password: …"
        setProblem(/^current_password/.test(err.message) ? t('Obecne hasło jest błędne.', 'The current password is wrong.')
          : /^new_password/.test(err.message) ? t('Nowe hasło musi mieć od 10 do 256 znaków.', 'The new password needs 10 to 256 characters.')
            : err.message);
      }
      else setError(err);
    } finally {
      setBusy(false);
    }
  };
  const field = (id: string, label: string, value: string, set: (v: string) => void, auto: string) => (
    <label className="block">
      <span className="label mb-1 block">{label}</span>
      <input type="password" className="field w-full" data-testid={id} autoComplete={auto} value={value} onChange={(e) => set(e.target.value)} aria-invalid={problem ? true : undefined} />
    </label>
  );
  return (
    <Dialog open={open} onClose={close} title={t('Zmień hasło', 'Change password')} width={400}
      footer={<><Button variant="ghost" onClick={close}>{t('Anuluj', 'Cancel')}</Button><Button variant="primary" busy={busy} data-testid="password-submit" onClick={() => submit()}>{t('Zmień hasło', 'Change password')}</Button></>}>
      <form onSubmit={submit} className="grid gap-3" noValidate>
        {field('password-current', t('Obecne hasło', 'Current password'), current, setCurrent, 'current-password')}
        {field('password-new', t('Nowe hasło (co najmniej 10 znaków)', 'New password (at least 10 characters)'), next, setNext, 'new-password')}
        {field('password-repeat', t('Powtórz nowe hasło', 'Repeat the new password'), repeat, setRepeat, 'new-password')}
        <button type="submit" className="hidden" aria-hidden="true" tabIndex={-1} />
        {problem ? <p role="alert" className="text-sm text-danger" data-testid="password-problem">{problem}</p> : null}
        <InlineError error={error} />
      </form>
    </Dialog>
  );
}
