import { useState, type FormEvent } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { post, setCsrfToken, ApiError } from '../api/client';
import type { Session } from '../api/types';
import { t, setLang, getLang } from '../i18n';
import { Button } from '../ui/kit';
import { Icon } from '../ui/Icon';
import { RhythmFigure } from '../viz/RhythmFigure';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [missing, setMissing] = useState(false);
  const qc = useQueryClient();
  const navigate = useNavigate();
  const loc = useLocation();
  const lang = getLang();
  const fixtures = __CZUJKA_FIXTURES__;
  const expired = Boolean((loc.state as { expired?: boolean } | null)?.expired);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setMissing(true);
      setError(new Error(t('Wpisz e-mail i hasło.', 'Enter your e-mail and password.')));
      return;
    }
    setMissing(false);
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
      if (err instanceof ApiError && err.status === 401) setError(new Error(t('Błędny e-mail lub hasło.', 'Wrong e-mail or password.')));
      else if (err instanceof ApiError && err.status === 429) setError(new Error(t('Zbyt wiele nieudanych prób. Spróbuj ponownie za kilka minut.', 'Too many failed attempts. Try again in a few minutes.')));
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const numbers: [string, string][] = [
    ['154/155', t('portów', 'ports')],
    ['17 min', t('sieć\u00a0/16', 'a\u00a0/16 network')],
    ['0', t('fałszywych zmian', 'false changes')],
  ];

  return (
    <div className="night relative isolate min-h-dvh overflow-hidden text-ink">
      <div className="night-field" aria-hidden="true" />
      <div className="relative z-10 mx-auto flex min-h-dvh w-full max-w-[1720px] flex-col px-5 py-5 sm:px-10 lg:px-14 2xl:px-20">
        <header className="flex items-center justify-between gap-3">
          <Brand />
          <Button variant="ghost" size="sm" icon="globe" onClick={() => setLang(lang === 'pl' ? 'en' : 'pl')}>{lang === 'pl' ? 'English' : 'Polski'}</Button>
        </header>

        <div className="flex flex-1 flex-col gap-10 pb-2 pt-8 lg:pt-6">
        <main className="grid flex-1 content-center gap-10 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,0.95fr)] lg:items-center lg:gap-14 2xl:gap-24">
          <div>
            <p className="font-display max-w-[12ch] text-[clamp(56px,7.4vw,148px)] leading-[0.92] tracking-[-0.015em] text-ink">
              {lang === 'pl' ? <>Co zmieniło się w&nbsp;<em className="text-ink-2">sieci</em>.</> : <>What changed on the <em className="text-ink-2">network</em>.</>}
            </p>

            <section className="login-glass mt-10 w-full lg:mt-12 max-w-[420px] p-6 sm:p-7" aria-labelledby="login-title">
              <h1 id="login-title" className="sr-only">{t('Logowanie', 'Sign in')}</h1>
              <form onSubmit={submit} className="grid gap-4" noValidate>
                <label className="grid gap-2">
                  <span className="mono text-2xs uppercase tracking-[0.16em] text-ink-3">{t('Adres e-mail', 'E-mail address')}</span>
                  <input className="login-field" aria-label={t('Adres e-mail', 'E-mail address')} type="email" name="email" autoComplete="username" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} aria-invalid={missing && !email ? true : undefined} />
                </label>
                <label className="grid gap-2">
                  <span className="mono text-2xs uppercase tracking-[0.16em] text-ink-3">{t('Hasło', 'Password')}</span>
                  <input className="login-field" aria-label={t('Hasło', 'Password')} type="password" name="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} aria-invalid={missing && !password ? true : undefined} />
                </label>
                <button type="submit" disabled={busy} className="login-submit group mt-2">
                  <span>{busy ? t('Logowanie…', 'Signing in…') : t('Zaloguj się', 'Sign in')}</span>
                  <Icon name="arrowRight" className="transition-transform duration-200 ease-out group-hover:translate-x-1" />
                </button>
                <div data-testid="login-error" aria-live="polite" className="empty:hidden">
                  {error ? (
                    <p role="alert" className="flex items-start gap-2.5 text-sm text-ink-2">
                      <span className="mt-[6px] block h-2 w-2 flex-none rounded-full bg-[#f2907f]" aria-hidden="true" />
                      <span>{errorText(error)}</span>
                    </p>
                  ) : expired ? (
                    <p role="status" data-testid="session-expired" className="flex items-start gap-2.5 text-sm text-ink-2">
                      <Icon name="clock" size={14} className="mt-[3px] flex-none text-ink-3" />
                      {t('Sesja wygasła. Zaloguj się ponownie.', 'Session expired. Sign in again.')}
                    </p>
                  ) : null}
                </div>
              </form>
              {fixtures ? (
                <div className="mt-5 border-t border-white/10 pt-4 text-xs text-ink-2" data-testid="fixture-accounts">
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
            </section>
          </div>

          <div className="lg:pl-2">
            <div>
              <RhythmFigure />
            </div>
          </div>
        </main>

        <footer className="border-t border-white/10 pt-6">
          <ul className="grid grid-cols-3 gap-4 sm:gap-10" data-testid="login-numbers">
            {numbers.map(([k, v]) => (
              <li key={k}>
                <span className="font-display block text-[clamp(30px,3vw,52px)] leading-none text-ink">{k}</span>
                <span className="mono mt-2 block text-2xs uppercase leading-[1.45] tracking-[0.1em] text-ink-3">{v}</span>
              </li>
            ))}
          </ul>
        </footer>
        </div>
      </div>
    </div>
  );
}

function errorText(e: unknown): string {
  if (e instanceof Error && e.message) return e.message;
  return t('Logowanie nie powiodło się. Spróbuj ponownie.', 'Sign-in failed. Try again.');
}

function Brand() {
  return (
    <span className="inline-flex items-center gap-2.5">
      <svg viewBox="0 0 24 24" width="26" height="26" aria-hidden="true">
        <path d="M4 16a8 8 0 0 1 16 0" fill="none" stroke="currentColor" strokeWidth="1.800" />
        <path d="M8 16a4 4 0 0 1 8 0" fill="none" stroke="var(--accent)" strokeWidth="1.800" />
        <rect x="10.800" y="14.800" width="2.400" height="2.400" fill="currentColor" />
        <path d="M2.500 20h19" stroke="currentColor" strokeWidth="1.400" />
      </svg>
      <span className="text-lg font-semibold">Czujka</span>
    </span>
  );
}
