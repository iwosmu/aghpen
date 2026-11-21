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

  const proofs: [string, string][] = [
    ['GET / HEAD', t('wyłącznie odczyt: bez logowania do usług i bez payloadów', 'read only: no logins to services, no payloads')],
    ['pps ≤ ' + t('limit', 'cap'), t('tempo skanu ograniczone polityką bezpieczeństwa', 'scan rate held by the safety policy')],
    ['AES-256-GCM', t('dane wrażliwe szyfrowane w spoczynku', 'sensitive data encrypted at rest')],
  ];

  return (
    <div className="grid min-h-dvh lg:grid-cols-[minmax(0,1fr)_440px] 2xl:grid-cols-[minmax(0,1fr)_520px]">
      <section className="on-rail hidden flex-col bg-rail px-10 py-8 text-rail-ink lg:flex xl:px-14">
        <Brand />
        <div className="flex flex-1 items-center py-10">
          <div className="mx-auto w-full max-w-[820px] 2xl:max-w-[1000px]">
            <p className="max-w-[24ch] text-[clamp(32px,2.5vw,46px)] font-semibold leading-[1.1] tracking-[-0.02em]">
              {t('Co zmieniło się w sieci od ostatniego obchodu.', 'What changed on the network since the last watch.')}
            </p>
            <p className="mt-5 max-w-[58ch] text-base text-rail-ink-2">
              {t(
                'Cykliczne, bezpieczne skany discovery dużych sieci. Każda ocena pokazuje swoje dowody, a zmiany zgodne z rytmem hosta nie budzą alarmu.',
                'Cyclic, safe discovery scans of large networks. Every score shows its evidence, and a change that fits the rhythm of a host raises no alarm.',
              )}
            </p>
            <ul className="mt-8 grid grid-cols-3 border-t border-rail-rule" data-testid="login-proofs">
              {proofs.map(([k, v], i) => (
                <li key={k} className={i > 0 ? 'border-l border-rail-rule py-4 pl-5 pr-4' : 'py-4 pr-4'}>
                  <span className="mono block text-base text-rail-ink">{k}</span>
                  <span className="mt-1 block text-sm text-rail-ink-2">{v}</span>
                </li>
              ))}
            </ul>
            <div className="mt-10">
              <RhythmFigure />
            </div>
          </div>
        </div>
      </section>
      <section className="flex flex-col border-rule bg-panel px-6 py-6 sm:px-10 lg:border-l lg:py-8">
        <div className="flex items-center justify-between gap-3">
          <span className="lg:invisible"><Brand /></span>
          <Button variant="ghost" size="sm" icon="globe" onClick={() => setLang(lang === 'pl' ? 'en' : 'pl')}>{lang === 'pl' ? 'English' : 'Polski'}</Button>
        </div>
        <div className="flex flex-1 items-center py-8 lg:py-10">
          <div className="mx-auto w-full max-w-[360px]">
            <p className="mb-8 text-lg font-semibold leading-[1.2] tracking-[-0.01em] lg:hidden">
              {t('Co zmieniło się w sieci od ostatniego obchodu.', 'What changed on the network since the last watch.')}
            </p>
            <h1 className="text-lg font-semibold">{t('Logowanie', 'Sign in')}</h1>
            <p className="mt-1.5 text-sm text-ink-2" data-testid="login-about">{t('Czujka mapuje usługi w sieci i pokazuje, co się w niej zmienia. Tylko wykrywa: wysyła żądania GET i HEAD, nigdy nie próbuje się logować.', 'Czujka maps the services on a network and shows what changes. It only detects: it sends GET and HEAD requests and never tries to log in.')}</p>
            {expired && !error ? (
              <p role="status" data-testid="session-expired" className="mt-4 flex items-start gap-2 border border-rule bg-sunk px-3 py-2 text-xs text-ink-2">
                <Icon name="clock" size={14} className="mt-px flex-none text-ink-3" />
                {t('Sesja wygasła. Zaloguj się ponownie, a wrócisz do tej samej strony.', 'The session has expired. Sign in again and you return to the same page.')}
              </p>
            ) : null}
            <form onSubmit={submit} className="mt-7 space-y-4" noValidate>
              <Field label={t('Adres e-mail', 'E-mail address')}>
                <input className="field h-10 px-3 text-base" type="email" name="email" autoComplete="username" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} aria-invalid={missing && !email ? true : undefined} />
              </Field>
              <Field label={t('Hasło', 'Password')}>
                <input className="field h-10 px-3 text-base" type="password" name="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} aria-invalid={missing && !password ? true : undefined} />
              </Field>
              <div data-testid="login-error"><InlineError error={error} /></div>
              <button type="submit" disabled={busy} className="flex h-10 w-full items-center justify-center gap-2 rounded-sm bg-accent text-base font-semibold text-accent-ink transition-colors duration-150 hover:bg-accent-strong focus-visible:outline-offset-2 disabled:opacity-60">
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
          </div>
        </div>
        <div className="mx-auto w-full max-w-[360px] border-t border-rule pt-5 lg:hidden">
          <ul className="space-y-3" data-testid="login-proofs-mobile">
            {proofs.map(([k, v]) => (
              <li key={k} className="grid grid-cols-[110px_minmax(0,1fr)] gap-3 text-sm">
                <span className="mono text-ink">{k}</span>
                <span className="text-ink-2">{v}</span>
              </li>
            ))}
          </ul>
          <div className="mt-8 [--rail-ink:var(--ink)] [--rail-ink-2:var(--ink-2)]">
            <RhythmFigure compact />
          </div>
        </div>
      </section>
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
