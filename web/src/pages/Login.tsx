import { useState, type FormEvent } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { post, setCsrfToken, ApiError } from '../api/client';
import type { Session } from '../api/types';
import { t, setLang, getLang, type Lang } from '../i18n';
import { Icon } from '../ui/Icon';
import { FlutedField } from '../viz/FlutedField';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [missing, setMissing] = useState(false);
  const qc = useQueryClient();
  const navigate = useNavigate();
  const loc = useLocation();
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

  return (
    <div className="night lgn">
      <FlutedField className="lgn-bg" />
      <header className="lgn-top">
        <Mark />
        <LangSwitch />
      </header>
      <p className="lgn-word" aria-hidden="true">Czujka</p>

      <main className="lgn-main">
        <section className="lgn-panel" aria-labelledby="login-title">
          <h1 id="login-title" className="sr-only">{t('Czujka: logowanie', 'Czujka: sign in')}</h1>
          <form onSubmit={submit} className="lgn-form" noValidate>
            <label className="lgn-label">
              <span>{t('Adres e-mail', 'E-mail address')}</span>
              <input className="lgn-input" type="email" name="email" autoComplete="username" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} aria-invalid={missing && !email ? true : undefined} />
            </label>
            <label className="lgn-label">
              <span>{t('Hasło', 'Password')}</span>
              <input className="lgn-input" type="password" name="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} aria-invalid={missing && !password ? true : undefined} />
            </label>
            <button type="submit" disabled={busy} className="lgn-submit">
              <span>{busy ? t('Logowanie…', 'Signing in…') : t('Zaloguj się', 'Sign in')}</span>
              <Icon name="arrowRight" className="lgn-submit-arrow" />
            </button>
            <div data-testid="login-error" aria-live="polite" className="lgn-status">
              {error ? (
                <p role="alert" className="lgn-msg">
                  <span className="lgn-dot" aria-hidden="true" />
                  <span>{errorText(error)}</span>
                </p>
              ) : expired ? (
                <p role="status" data-testid="session-expired" className="lgn-msg">
                  <Icon name="clock" size={14} className="lgn-msg-icon" />
                  {t('Sesja wygasła. Zaloguj się ponownie.', 'Session expired. Sign in again.')}
                </p>
              ) : null}
            </div>
          </form>
          {fixtures ? (
            <div className="lgn-fixtures" data-testid="fixture-accounts">
              <p className="lgn-fixtures-title">{t('Tryb deweloperski: dane z fixtures', 'Development mode: fixture data')}</p>
              <p>{t('Konta testowe, hasło dla każdego: czujka', 'Test accounts, the password for each: czujka')}</p>
              <ul>
                {['admin', 'editor', 'analyst', 'viewer'].map((r) => (
                  <li key={r}>
                    <button type="button" className="mono" onClick={() => { setEmail(r + '@cbi.example'); setPassword('czujka'); }}>{r}@cbi.example</button>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </section>
      </main>
    </div>
  );
}

function errorText(e: unknown): string {
  if (e instanceof Error && e.message) return e.message;
  return t('Logowanie nie powiodło się. Spróbuj ponownie.', 'Sign-in failed. Try again.');
}

function LangSwitch() {
  const lang = getLang();
  const opts: [Lang, string, string][] = [['pl', 'PL', 'Polski'], ['en', 'EN', 'English']];
  return (
    <div className="lgn-pill" role="group" aria-label={t('Język', 'Language')}>
      {opts.map(([l, short, full]) => (
        <button key={l} type="button" lang={l} aria-label={full} aria-pressed={lang === l} onClick={() => setLang(l)}>{short}</button>
      ))}
    </div>
  );
}

function Mark() {
  return (
    <span className="lgn-mark" title="Czujka">
      <svg viewBox="0 0 24 24" width="32" height="32" aria-hidden="true">
        <path d="M4 16a8 8 0 0 1 16 0" fill="none" stroke="currentColor" strokeWidth="1.8" />
        <path d="M8 16a4 4 0 0 1 8 0" fill="none" stroke="#8fb8f6" strokeWidth="1.8" />
        <rect x="10.8" y="14.8" width="2.4" height="2.4" fill="currentColor" />
        <path d="M2.5 20h19" stroke="currentColor" strokeWidth="1.4" />
      </svg>
    </span>
  );
}
