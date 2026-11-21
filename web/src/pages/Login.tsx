import { useState, type FormEvent } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { post, setCsrfToken, ApiError } from '../api/client';
import type { Session } from '../api/types';
import { t, setLang, getLang } from '../i18n';
import { Button, Field, InlineError } from '../ui/kit';
import { Icon } from '../ui/Icon';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const qc = useQueryClient();
  const navigate = useNavigate();
  const loc = useLocation();
  const lang = getLang();
  const fixtures = __CZUJKA_FIXTURES__;
  const expired = Boolean((loc.state as { expired?: boolean } | null)?.expired);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const s = await post<Session>('/auth/login', { email, password });
      setCsrfToken(s.csrf_token);
      qc.clear();
      qc.setQueryData(['/me'], s);
      const from = (loc.state as { from?: string } | null)?.from;
      navigate(from && from !== '/login' ? from : '/', { replace: true });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setError(new Error(t('Nieprawidłowy adres e-mail lub hasło.', 'Wrong e-mail address or password.')));
      else if (err instanceof ApiError && err.status === 429) setError(new Error(t('Zbyt wiele nieudanych prób. Logowanie jest chwilowo zablokowane, spróbuj ponownie za kilka minut.', 'Too many failed attempts. Sign-in is locked for a while, try again in a few minutes.')));
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-dvh lg:grid-cols-[minmax(0,1fr)_440px]">
      <div className="hidden flex-col justify-between bg-rail p-10 text-rail-ink lg:flex">
        <div className="flex items-center gap-3">
          <svg viewBox="0 0 24 24" width="28" height="28" aria-hidden="true">
            <path d="M4 16a8 8 0 0 1 16 0" fill="none" stroke="currentColor" strokeWidth="1.800" />
            <path d="M8 16a4 4 0 0 1 8 0" fill="none" stroke="var(--accent)" strokeWidth="1.800" />
            <rect x="10.800" y="14.800" width="2.400" height="2.400" fill="currentColor" />
            <path d="M2.500 20h19" stroke="currentColor" strokeWidth="1.400" />
          </svg>
          <span className="text-lg font-semibold">Czujka</span>
        </div>
        <div className="max-w-[46ch]">
          <p className="text-xl font-semibold leading-[1.25] tracking-[-0.015em]">
            {t('Co zmieniło się w sieci od ostatniego obchodu.', 'What changed on the network since the last watch.')}
          </p>
          <p className="mt-4 text-base text-rail-ink-2">
            {t(
              'Cykliczne, bezpieczne skany discovery dużych sieci. Każda ocena pokazuje swoje dowody, a zmiany zgodne z rytmem hosta nie budzą alarmu.',
              'Cyclic, safe discovery scans of large networks. Every score shows its evidence, and a change that fits the rhythm of a host raises no alarm.',
            )}
          </p>
        </div>
        <ul className="grid max-w-[60ch] grid-cols-3 gap-6 border-t border-rail-rule pt-5 text-xs text-rail-ink-2">
          <li><span className="mono block text-sm text-rail-ink">GET / HEAD</span>{t('wyłącznie odczyt, bez logowania i payloadów', 'read only, no logins, no payloads')}</li>
          <li><span className="mono block text-sm text-rail-ink">pps ≤ {t('limit', 'cap')}</span>{t('tempo ograniczone polityką bezpieczeństwa', 'rate held by the safety policy')}</li>
          <li><span className="mono block text-sm text-rail-ink">AES-256-GCM</span>{t('dane wrażliwe szyfrowane w spoczynku', 'sensitive data encrypted at rest')}</li>
        </ul>
      </div>
      <div className="flex flex-col justify-center border-l border-rule bg-panel px-6 py-10 sm:px-10">
        <div className="mx-auto w-full max-w-[340px]">
          <div className="mb-8 flex items-center justify-between lg:hidden">
            <span className="text-lg font-semibold">Czujka</span>
          </div>
          <h1 className="text-lg font-semibold">{t('Logowanie', 'Sign in')}</h1>
          <p className="mt-1 text-sm text-ink-2">{t('Konsola analityka bezpieczeństwa.', 'Security analyst console.')}</p>
          {expired && !error ? (
            <p role="status" data-testid="session-expired" className="mt-4 flex items-start gap-2 border border-rule bg-sunk px-3 py-2 text-xs text-ink-2">
              <Icon name="clock" size={14} className="mt-px flex-none text-ink-3" />
              {t('Sesja wygasła. Zaloguj się ponownie, a wrócisz do tej samej strony.', 'The session has expired. Sign in again and you return to the same page.')}
            </p>
          ) : null}
          <form onSubmit={submit} className="mt-6 space-y-4" noValidate>
            <Field label={t('Adres e-mail', 'E-mail address')}>
              <input className="field" type="email" name="email" autoComplete="username" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} />
            </Field>
            <Field label={t('Hasło', 'Password')}>
              <input className="field" type="password" name="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
            </Field>
            <div data-testid="login-error"><InlineError error={error} /></div>
            <button type="submit" disabled={busy || !email || !password} className="flex h-[34px] w-full items-center justify-center gap-2 rounded-sm bg-accent text-sm font-medium text-accent-ink hover:bg-accent-strong disabled:opacity-50">
              {busy ? t('Logowanie…', 'Signing in…') : t('Zaloguj się', 'Sign in')}
              <Icon name="arrowRight" />
            </button>
          </form>
          {fixtures ? (
            <div className="mt-6 border border-rule p-3 text-xs text-ink-2" data-testid="fixture-accounts">
              <p className="mb-1.5 font-medium text-ink">{t('Tryb deweloperski: dane z fixtures', 'Development mode: fixture data')}</p>
              <p className="mb-2 text-ink-3">{t('Konta testowe, hasło dla każdego: czujka', 'Test accounts, the password for each: czujka')}</p>
              <ul className="space-y-1">
                {['admin', 'editor', 'analyst', 'viewer'].map((r) => (
                  <li key={r}>
                    <button type="button" className="mono link" onClick={() => { setEmail(r + '@cbi.example'); setPassword('czujka'); }}>{r}@cbi.example</button>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          <div className="mt-8 flex items-center gap-3 text-xs text-ink-3">
            <Button variant="ghost" size="sm" icon="globe" onClick={() => setLang(lang === 'pl' ? 'en' : 'pl')}>{lang === 'pl' ? 'English' : 'Polski'}</Button>
          </div>
        </div>
      </div>
    </div>
  );
}
