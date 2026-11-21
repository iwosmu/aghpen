import { useState, type FormEvent } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { post, setCsrfToken, ApiError } from '../api/client';
import type { Session } from '../api/types';
import { t, setLang, getLang } from '../i18n';
import { Button, Field, InlineError } from '../ui/kit';
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
      setError(new Error(t('Wpisz adres e-mail i hasło.', 'Enter the e-mail address and the password.')));
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
      if (err instanceof ApiError && err.status === 401) setError(new Error(t('Nieprawidłowy adres e-mail lub hasło.', 'Wrong e-mail address or password.')));
      else if (err instanceof ApiError && err.status === 429) setError(new Error(t('Zbyt wiele nieudanych prób. Logowanie jest chwilowo zablokowane, spróbuj ponownie za kilka minut.', 'Too many failed attempts. Sign-in is locked for a while, try again in a few minutes.')));
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const numbers: [string, string][] = [
    ['154/155', t('otwartych portów znalezionych', 'open ports found')],
    ['13 min', t('pełny skan sieci\u00a0/16', 'full scan of a\u00a0/16')],
    ['0', t('sekund ponad limit pakietów', 'seconds over the packet cap')],
  ];

  return (
    <div className="night relative isolate min-h-dvh overflow-hidden text-ink">
      <div className="night-field" aria-hidden="true" />
      <div className="relative z-10 mx-auto flex min-h-dvh w-full max-w-[1720px] flex-col px-5 py-5 sm:px-10 lg:px-14 2xl:px-20">
        <header className="flex items-center justify-between gap-3">
          <Brand />
          <Button variant="ghost" size="sm" icon="globe" onClick={() => setLang(lang === 'pl' ? 'en' : 'pl')}>{lang === 'pl' ? 'English' : 'Polski'}</Button>
        </header>

        <main className="grid flex-1 content-center gap-10 py-8 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,0.95fr)] lg:items-center lg:gap-14 lg:py-6 2xl:gap-24">
          <div>
            <p className="mono flex items-center gap-3 text-2xs uppercase tracking-[0.2em] text-accent">
              <span className="h-px w-8 flex-none bg-accent" aria-hidden="true" />
              {t('Attack surface intelligence · CBI AGH · HackNation 2026', 'Attack surface intelligence · CBI AGH · HackNation 2026')}
            </p>
            <p className="font-display mt-5 text-[clamp(44px,5vw,100px)] leading-[0.98] tracking-[-0.012em] text-ink">
              {lang === 'pl'
                ? <><span className="block">Adres milczy o&nbsp;3&nbsp;w&nbsp;nocy.</span><span className="block max-w-[13ch] text-ink-2">Wyłączony na noc czy <em className="text-[#f2907f]">zniknął</em>?</span></>
                : <><span className="block">An address is silent at&nbsp;3&nbsp;a.m.</span><span className="block max-w-[15ch] text-ink-2">Switched off for the night, or <em className="text-[#f2907f]">gone</em>?</span></>}
            </p>
            <p className="mt-5 max-w-[50ch] text-base text-ink-2">
              {t('Czujka zna rytm każdego hosta w sieci. Cisza zgodna z rytmem nie budzi alarmu; cisza poza nim jest sprawdzana ponownie i zgłaszana.', 'Czujka knows the rhythm of every host on the network. A silence that fits it raises no alarm; a silence outside it is checked again and reported.')}
            </p>

            <section className="mt-8 max-w-[560px] border border-rule bg-panel/95 p-5 shadow-[0_30px_60px_-28px_rgb(0_0_0/0.9)] sm:p-6" aria-labelledby="login-title">
              <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
                <h1 id="login-title" className="text-lg font-semibold">{t('Logowanie', 'Sign in')}</h1>
                <p className="text-xs text-ink-3" data-testid="login-about">{t('Tylko wykrywa: GET i HEAD, bez logowania do usług.', 'It only detects: GET and HEAD, no logins to services.')}</p>
              </div>
              {expired && !error ? (
                <p role="status" data-testid="session-expired" className="mt-4 flex items-start gap-2 border border-rule bg-sunk px-3 py-2 text-xs text-ink-2">
                  <Icon name="clock" size={14} className="mt-px flex-none text-ink-3" />
                  {t('Sesja wygasła. Zaloguj się ponownie, a wrócisz do tej samej strony.', 'The session has expired. Sign in again and you return to the same page.')}
                </p>
              ) : null}
              <form onSubmit={submit} className="mt-4 grid gap-3 sm:grid-cols-2" noValidate>
                <Field label={t('Adres e-mail', 'E-mail address')}>
                  <input className="field h-10 px-3 text-base" type="email" name="email" autoComplete="username" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} aria-invalid={missing && !email ? true : undefined} />
                </Field>
                <Field label={t('Hasło', 'Password')}>
                  <input className="field h-10 px-3 text-base" type="password" name="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} aria-invalid={missing && !password ? true : undefined} />
                </Field>
                <div className="sm:col-span-2" data-testid="login-error"><InlineError error={error} /></div>
                <button type="submit" disabled={busy} className="flex h-11 w-full items-center justify-center gap-2 rounded-sm bg-accent text-base font-semibold text-accent-ink shadow-[0_10px_24px_-10px_rgb(110_163_242/0.6)] transition-colors duration-150 hover:bg-accent-strong focus-visible:outline-offset-2 disabled:opacity-60 sm:col-span-2">
                  {busy ? t('Logowanie…', 'Signing in…') : t('Zaloguj się', 'Sign in')}
                  <Icon name="arrowRight" />
                </button>
              </form>
              {fixtures ? (
                <div className="mt-5 border border-rule p-3 text-xs text-ink-2" data-testid="fixture-accounts">
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
            <div className="lg:rotate-[-1.2deg] lg:translate-y-2">
              <RhythmFigure compact={false} />
            </div>
          </div>
        </main>

        <footer className="grid gap-6 border-t border-white/10 pt-6 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,0.95fr)] lg:gap-14 2xl:gap-24">
          <ul className="grid grid-cols-3 gap-4 sm:gap-8" data-testid="login-numbers">
            {numbers.map(([k, v]) => (
              <li key={k}>
                <span className="font-display block text-[clamp(30px,3vw,52px)] leading-none text-ink">{k}</span>
                <span className="mono mt-2 block text-2xs uppercase leading-[1.45] tracking-[0.1em] text-ink-3">{v}</span>
              </li>
            ))}
          </ul>
          <div className="flex flex-col justify-end gap-2 lg:items-end lg:text-right">
            <p className="mono text-2xs uppercase tracking-[0.16em] text-ink-2" data-testid="login-proofs">GET / HEAD · pps ≤ {t('limit', 'cap')} · AES-256-GCM</p>
            <p className="text-2xs text-ink-3">{t('Liczby z pomiarów w laboratorium 70 kontenerów (docs/WYNIKI.md).', 'Numbers measured in the 70-container lab (docs/WYNIKI.md).')}</p>
          </div>
        </footer>
      </div>
    </div>
  );
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
