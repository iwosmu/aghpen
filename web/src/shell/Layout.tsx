import { useEffect, useState, type ReactNode } from 'react';
import { NavLink, Link, Outlet, useLocation, useNavigate } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { cx, fmtInt, fmtPct } from '../lib/format';
import { t, setLang, getLang } from '../i18n';
import { Icon } from '../ui/Icon';
import { Button, Dialog, IconButton, InlineError } from '../ui/kit';
import { roleLabel, roleScope, useSession } from '../session';
import { invalidate, useAction, useItem, usePage } from '../api/hooks';
import { post } from '../api/client';
import { openStream } from '../api/events';
import { ErrorBoundary } from '../ui/ErrorBoundary';
import { PasswordDialog } from './PasswordDialog';
import type { Health, Permission, SafetyPolicy, ScanProfile, ScanRun } from '../api/types';
import { overCap, paceTip } from '../lib/headline';
import { Glyph } from '../ui/marks';

interface NavItem { to: string; label: string; icon: string; perms: Permission[]; end?: boolean }

function navItems(): { title: string; items: NavItem[] }[] {
  return [
    {
      title: t('Obserwacja', 'Watch'),
      items: [
        { to: '/', label: t('Pulpit', 'Dashboard'), icon: 'dashboard', perms: ['results:read'], end: true },
        { to: '/runs', label: t('Skany', 'Scans'), icon: 'runs', perms: ['scans:read'] },
        { to: '/hosts', label: t('Hosty', 'Hosts'), icon: 'hosts', perms: ['results:read'] },
        { to: '/services', label: t('Usługi', 'Services'), icon: 'services', perms: ['results:read'] },
        { to: '/changes', label: t('Zmiany', 'Changes'), icon: 'changes', perms: ['results:read'] },
        { to: '/time', label: t('Oś czasu', 'Timeline'), icon: 'history', perms: ['results:read'] },
        { to: '/findings', label: t('Znaleziska', 'Findings'), icon: 'findings', perms: ['results:read'] },
      ],
    },
    {
      title: t('Konfiguracja', 'Configuration'),
      items: [
        { to: '/signatures', label: t('Sygnatury', 'Signatures'), icon: 'signatures', perms: ['signatures:read'] },
        { to: '/rules', label: t('Reguły ekspozycji', 'Exposure rules'), icon: 'shield', perms: ['results:read'] },
        { to: '/targets', label: t('Cele', 'Targets'), icon: 'targets', perms: ['targets:read'] },
        { to: '/profiles', label: t('Profile skanów', 'Scan profiles'), icon: 'profiles', perms: ['scans:read'] },
        { to: '/transfer', label: t('Import i eksport', 'Import and export'), icon: 'transfer', perms: ['results:create', 'export:run'] },
        { to: '/admin', label: t('Administracja', 'Administration'), icon: 'admin', perms: ['scans:read', 'users:manage', 'roles:manage', 'audit:read'] },
      ],
    },
  ];
}

function Logo() {
  return (
    <Link to="/" className="flex h-[56px] items-center gap-2.5 px-5 text-rail-ink">
      <svg viewBox="0 0 24 24" width="26" height="26" aria-hidden="true">
        <path d="M4 16a8 8 0 0 1 16 0" fill="none" stroke="currentColor" strokeWidth="1.8" />
        <path d="M8 16a4 4 0 0 1 8 0" fill="none" stroke="currentColor" strokeWidth="1.8" />
        <rect x="10.800" y="14.800" width="2.400" height="2.400" fill="currentColor" />
        <path d="M2.500 20h19" stroke="currentColor" strokeWidth="1.400" />
      </svg>
      <span className="text-[17px] font-medium tracking-[-0.02em]">Czujka</span>
    </Link>
  );
}

function Rail({ onNavigate }: { onNavigate?: () => void }) {
  const { session, can } = useSession();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [pwOpen, setPwOpen] = useState(false);
  const logout = useAction(() => post('/auth/logout'), {
    silent: true,
    onSuccess: () => { qc.clear(); navigate('/login', { replace: true }); },
  });
  const u = session.user;
  return (
    <div className="flex h-full w-[240px] flex-col bg-rail text-rail-ink shadow-[inset_-1px_0_0_var(--rail-rule)]" data-rail>
      <Logo />
      <nav className="min-h-0 flex-1 overflow-y-auto px-3 pb-2" aria-label={t('Nawigacja główna', 'Main navigation')}>
        {navItems().map((group) => {
          const items = group.items.filter((i) => can(...i.perms));
          if (items.length === 0) return null;
          return (
            <div key={group.title}>
              <p className="caps px-3 pb-2 pt-6">{group.title}</p>
              <ul className="space-y-0.5">
                {items.map((i) => (
                  <li key={i.to}>
                    <NavLink
                      to={i.to} end={i.end} onClick={onNavigate}
                      className={({ isActive }) => cx(
                        'relative flex h-[34px] items-center gap-2.5 rounded-[8px] px-3 text-sm transition-colors duration-150 ease-[var(--ease)]',
                        isActive ? 'bg-rail-active text-rail-ink shadow-[inset_0_0_0_1px_var(--rail-rule),inset_0_1px_0_rgb(255_255_255/0.05)]' : 'text-rail-ink-2 hover:bg-rail-active/60 hover:text-rail-ink',
                      )}
                    >
                      {({ isActive }) => (
                        <>
                          <Icon name={i.icon} className={isActive ? 'text-rail-ink' : 'text-ink-3'} />
                          {i.label}
                        </>
                      )}
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </nav>
      <div className="flex items-center gap-2 border-t border-rail-rule px-4 py-3" data-testid="whoami">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-rail-ink" title={u.email}>{u.name || u.email}</p>
          <p className="truncate text-xs text-rail-ink-2" title={u.email + ' · ' + roleScope(u.role_slug)}>{roleLabel(u.role_slug, u.role_name) === (u.name || u.email) ? u.email : roleLabel(u.role_slug, u.role_name)}</p>
        </div>
        <button type="button" onClick={() => setPwOpen(true)} className="inline-flex h-[28px] w-[28px] items-center justify-center rounded-[6px] text-ink-3 hover:bg-rail-active hover:text-rail-ink" title={t('Zmień hasło', 'Change password')} aria-label={t('Zmień hasło', 'Change password')} data-testid="password-open">
          <Icon name="lock" size={14} />
        </button>
        <button type="button" onClick={() => logout.mutate(undefined)} className="inline-flex h-[28px] w-[28px] items-center justify-center rounded-[6px] text-ink-3 hover:bg-rail-active hover:text-rail-ink" title={t('Wyloguj', 'Sign out')} aria-label={t('Wyloguj', 'Sign out')}>
          <Icon name="logout" size={14} />
        </button>
      </div>
      <PasswordDialog open={pwOpen} onClose={() => setPwOpen(false)} />
    </div>
  );
}

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme || 'dark');
  const toggle = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('czujka.theme', next); } catch { /* ignore */ }
    setTheme(next);
  };
  return [theme, toggle];
}

/** Keeps the run indicator and the dashboard fresh from the global event stream. */
function useGlobalEvents(enabled: boolean) {
  const qc = useQueryClient();
  useEffect(() => {
    if (!enabled) return;
    const s = openStream('/events', {
      run: (run: ScanRun) => {
        qc.setQueryData(['/runs/' + run.id, {}], run);
        invalidate(qc, '/runs', '/dashboard');
      },
      change: () => { invalidate(qc, '/changes', '/dashboard'); },
      finding: () => { invalidate(qc, '/findings', '/dashboard'); },
    });
    return () => s.close();
  }, [enabled, qc]);
}

function ActiveRunStrip() {
  const { can } = useSession();
  const onDashboard = useLocation().pathname === '/';
  const q = usePage<ScanRun>('/runs', { status: 'running', limit: 1 }, can('scans:read'));
  const listed = q.data?.items[0];
  // The list is refreshed only on run events; the live detail query (kept fresh by the run page and polling) has the current rate.
  const detail = useItem<ScanRun>('/runs/' + (listed?.id ?? 0), undefined, { enabled: Boolean(listed), refetchInterval: 4000 });
  const run = listed ? (detail.data?.status === 'running' ? detail.data : listed) : undefined;
  const profile = useItem<ScanProfile>('/profiles/' + (run?.profile_id ?? 0), undefined, { enabled: Boolean(run?.profile_id) });
  const safety = useItem<SafetyPolicy>('/settings/safety', undefined, { enabled: Boolean(run) });
  if (!run || onDashboard) return null;
  const pct = run.stats.addresses_total ? run.stats.addresses_done / run.stats.addresses_total : 0;
  // The run cap is the stricter of the profile cap and the policy cap, as on the run page and the dashboard.
  const policyCap = safety.data?.max_pps ?? 0;
  const cap = Math.min(profile.data?.rate.max_pps ?? policyCap, policyCap || Infinity) || policyCap;
  const over = overCap(run.stats.current_pps, cap);
  const pace = run.stats.current_pps_basis === 'pace';
  const tip = (over ? t('Tempo powyżej limitu skanu ' + fmtInt(cap) + ' pps. ', 'Rate above the scan limit of ' + fmtInt(cap) + ' pps. ') : '') + (pace ? paceTip() : '');
  return (
    <Link to={'/runs/' + run.id} className="hidden h-[32px] min-w-0 items-center gap-2.5 rounded-[8px] px-3 text-xs text-ink-2 shadow-[inset_0_0_0_1px_var(--rule)] hover:text-ink md:inline-flex">
      <Glyph name="run" tone="accent" pulse size={12} />
      <span className="truncate">{t('Skan', 'Scan')} <span className="num">#{run.id}</span> · {run.profile_name}</span>
      <span className="num text-ink">{fmtPct(pct)}</span>
      <span className={cx('num inline-flex items-center gap-1', over ? 'font-medium text-danger' : 'text-ink-3')} title={tip || undefined} data-testid={over ? 'strip-over-cap' : pace ? 'strip-pace' : undefined}>{over ? <Icon name="alert" size={11} /> : null}{pace ? <span className="font-sans text-ink-3">{t('zadane', 'set')}</span> : null}{pace ? '≈' : ''}{fmtInt(run.stats.current_pps)}{cap ? <span className="text-ink-3"> / {fmtInt(cap)}</span> : null} pps</span>
    </Link>
  );
}

function EmergencyStop({ policy }: { policy: SafetyPolicy | undefined }) {
  const { can } = useSession();
  const [open, setOpen] = useState(false);
  const stop = useAction(() => post<SafetyPolicy>('/emergency-stop'), {
    invalidate: ['/settings/safety', '/runs', '/dashboard'], silent: true,
    success: t('Stop awaryjny włączony', 'Emergency stop is on'),
    onSuccess: () => setOpen(false),
  });
  if (!can('safety:stop') || !policy || policy.emergency_stop) return null;
  return (
    <>
      <Button variant="danger" size="sm" icon="stop" onClick={() => { stop.reset(); setOpen(true); }} data-testid="emergency-stop">
        <span className="hidden sm:inline">{t('Stop awaryjny', 'Emergency stop')}</span>
        <span className="sm:hidden">Stop</span>
      </Button>
      <Dialog
        open={open} onClose={() => setOpen(false)} title={t('Zatrzymać wszystkie skany?', 'Stop all scans?')} width={460}
        footer={
          <>
            <Button onClick={() => setOpen(false)}>{t('Anuluj', 'Cancel')}</Button>
            <Button variant="dangerSolid" icon="stop" busy={stop.isPending} onClick={() => stop.mutate(undefined)}>{t('Zatrzymaj wszystkie skany', 'Stop all scans')}</Button>
          </>
        }
      >
        <ul className="list-disc space-y-1.5 pl-4 text-sm text-ink">
          <li>{t('Wszystkie trwające skany zostaną wstrzymane.', 'All running scans pause.')}</li>
          <li>{t('Nowe skany nie ruszą, także z harmonogramu.', 'No new scan starts, including scheduled ones.')}</li>
          <li>{t('Stop wyłącza administrator.', 'An administrator turns the stop off.')}</li>
        </ul>
                <div className="mt-2"><InlineError error={stop.error} /></div>
      </Dialog>
    </>
  );
}

function StopBanner({ policy }: { policy: SafetyPolicy | undefined }) {
  const { can } = useSession();
  const release = useAction(() => post<SafetyPolicy>('/emergency-stop/release'), {
    invalidate: ['/settings/safety', '/runs', '/dashboard'],
    success: t('Stop awaryjny wyłączony', 'Emergency stop is off'),
  });
  if (!policy?.emergency_stop) return null;
  return (
    <div role="alert" className="mx-3 mb-2 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 rounded-[10px] bg-danger-solid px-4 py-2.5 text-sm text-danger-ink sm:mx-4 mt-2" data-testid="stop-banner">
      <span className="flex items-center gap-2 font-medium">
        <Icon name="stop" />
        {t('Stop awaryjny jest włączony. Żaden skan nie działa.', 'The emergency stop is on. No scan is running.')}
      </span>
      {can('safety:manage') ? (
        <button type="button" disabled={release.isPending} onClick={() => release.mutate(undefined)} className="inline-flex h-[28px] items-center gap-1.5 rounded-[6px] bg-white/15 px-3 text-xs font-medium hover:bg-white/25">
          <Icon name="undo" size={14} />{t('Wyłącz stop', 'Turn off the stop')}
        </button>
      ) : (
        <span className="text-xs opacity-90">{t('Stop wyłącza administrator.', 'An administrator turns the stop off.')}</span>
      )}
    </div>
  );
}

/** How the scanner reaches the network, in words an administrator checks before a scan. */
export function probeModeLabel(mode: string | undefined): { short: string; long: string } {
  switch (mode) {
    case 'nmap-raw': return { short: 'nmap SYN', long: t('nmap z surowymi gniazdami: skan SYN, wykrywanie ICMP/ARP', 'nmap with raw sockets: SYN scan, ICMP/ARP discovery') };
    case 'nmap-connect': return { short: 'nmap connect', long: t('nmap bez surowych gniazd: pełne połączenie TCP (-sT), bez UDP', 'nmap without raw sockets: full TCP connect (-sT), no UDP') };
    case 'native': return { short: t('wbudowany TCP', 'built-in TCP'), long: t('wbudowany skaner Go (połączenie TCP), bez nmap', 'built-in Go scanner (TCP connect), no nmap') };
    default: return { short: mode || '–', long: mode || '' };
  }
}

function SafetyChip({ policy }: { policy: SafetyPolicy | undefined }) {
  const health = useItem<Health>('/healthz', undefined, { staleTime: 60_000 });
  if (!policy) return null;
  const op = policy.operator_networks ?? [];
  const title = t('Polityka bezpieczeństwa', 'Safety policy')
    + (op.length ? '. ' + t('Operator ograniczył skanowanie do ' + op.join(', ') + '.', 'The operator limits scanning to ' + op.join(', ') + '.') : '');
  return (
    <Link
      to="/admin?tab=safety" className="hidden h-[28px] items-center gap-1.5 rounded-[8px] px-2 text-xs text-ink-2 hover:bg-raised hover:text-ink lg:inline-flex"
      title={title} data-testid="safety-chip"
    >
      <Icon name="shield" size={14} className="text-ink-3" />
      {op.length ? <span className="inline-flex items-center gap-1" data-testid="safety-chip-lock"><Icon name="lock" size={12} className="text-ink-3" /><span className="mono text-ink">{op.length === 1 ? op[0] : op.length + ' ' + t('sieci', 'networks')}</span></span> : null}
      {health.data && health.data.engine === false ? <span className="text-st-changed">{t('brak skanera', 'no scanner')}</span> : null}
    </Link>
  );
}

export function Layout() {
  const { session, can } = useSession();
  usePresentMode();
  const [menu, setMenu] = useState(false);
  const [theme, toggleTheme] = useTheme();
  const loc = useLocation();
  const safety = useItem<SafetyPolicy>('/settings/safety', undefined, { enabled: can('scans:read'), staleTime: 15_000 });
  useGlobalEvents(can('results:read'));
  useEffect(() => { setMenu(false); }, [loc.pathname]);
  const lang = getLang();
  const u = session.user;
  return (
    <div className="flex h-dvh min-h-0">
      <div className="app-ground" aria-hidden="true" />
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:bg-accent focus:px-3 focus:py-1.5 focus:text-accent-ink">
        {t('Przejdź do treści', 'Skip to content')}
      </a>
      <aside className="hidden flex-none lg:block"><Rail /></aside>
      {menu ? (
        <div className="fixed inset-0 z-40 lg:hidden">
          <button type="button" className="absolute inset-0 bg-black/55" aria-label={t('Zamknij menu', 'Close menu')} onClick={() => setMenu(false)} />
          <div className="absolute inset-y-0 left-0" style={{ animation: 'slide-in 180ms var(--ease-out-expo) reverse backwards' }}><Rail onNavigate={() => setMenu(false)} /></div>
        </div>
      ) : null}
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex h-[56px] flex-none items-center justify-between gap-3 border-b border-rule px-3 sm:px-4 lg:px-8">
          <div className="flex min-w-0 items-center gap-2">
            <IconButton icon="menu" label={t('Menu', 'Menu')} className="lg:hidden" onClick={() => setMenu(true)} />
            <span className="hidden text-[15px] font-medium tracking-[-0.02em] sm:inline lg:hidden">Czujka</span>
            <ActiveRunStrip />
          </div>
          <div className="flex flex-none items-center gap-1 sm:gap-2">
            <SafetyChip policy={safety.data} />
            <EmergencyStop policy={safety.data} />
            <button
              type="button" onClick={() => setLang(lang === 'pl' ? 'en' : 'pl')}
              className="inline-flex h-[28px] items-center rounded-[8px] bg-sunk p-[2px] text-2xs font-medium text-ink-3 shadow-[inset_0_0_0_1px_var(--rule)] hover:text-ink"
              aria-label={t('Zmień język na angielski', 'Switch language to Polish')} data-testid="lang-toggle"
            >
              <span className={cx('inline-flex h-[24px] items-center rounded-[6px] px-2', lang === 'pl' ? 'bg-raised text-ink shadow-[inset_0_0_0_1px_var(--rule-strong)]' : '')}>PL</span>
              <span className={cx('inline-flex h-[24px] items-center rounded-[6px] px-2', lang === 'en' ? 'bg-raised text-ink shadow-[inset_0_0_0_1px_var(--rule-strong)]' : '')}>EN</span>
            </button>
            <IconButton icon={theme === 'dark' ? 'sun' : 'moon'} label={theme === 'dark' ? t('Jasny motyw', 'Light theme') : t('Ciemny motyw', 'Dark theme')} onClick={toggleTheme} data-testid="theme-toggle" />
            <span className="mr-1 inline-flex h-[24px] items-center gap-1.5 rounded-[6px] bg-raised px-2 text-2xs font-medium text-ink-2 lg:hidden" title={u.email} data-testid="role-chip">
              <Icon name={u.role_slug === 'viewer' ? 'eye' : u.role_slug === 'admin' ? 'shield' : 'user'} size={12} />
              {roleLabel(u.role_slug, u.role_name)}
            </span>
          </div>
        </div>
        <StopBanner policy={safety.data} />
        <main id="main" className="relative min-h-0 flex-1 overflow-y-auto" tabIndex={-1}>
          <ErrorBoundary key={loc.pathname}><Outlet /></ErrorBoundary>
        </main>
      </div>
    </div>
  );
}

export function NoAccess({ children }: { children?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-1.5 px-6 py-10">
      <Icon name="lock" className="text-ink-3" size={18} />
      <p className="text-sm font-medium">{t('Twoja rola nie ma dostępu do tej strony.', 'Your role has no access to this page.')}</p>
      {children}
      <Link to="/" className="link text-sm">{t('Wróć na pulpit', 'Back to the dashboard')}</Link>
    </div>
  );
}

/** Presentation mode for recording: ?present=1 (or Shift+P) enlarges the whole UI one step; the safety strip stays. Nothing else changes. */
export function usePresentMode() {
  const loc = useLocation();
  useEffect(() => {
    const q = new URLSearchParams(loc.search).get('present');
    if (q === '1') sessionStorage.setItem('czujka.present', '1');
    if (q === '0') sessionStorage.removeItem('czujka.present');
    const apply = () => { if (sessionStorage.getItem('czujka.present')) document.documentElement.dataset.present = ''; else delete document.documentElement.dataset.present; };
    apply();
    const onKey = (e: KeyboardEvent) => {
      if (!(e.shiftKey && (e.key === 'P' || e.key === 'p')) || e.metaKey || e.ctrlKey || e.altKey) return;
      if ((e.target as HTMLElement).closest('input, textarea, select, [contenteditable]')) return;
      if (sessionStorage.getItem('czujka.present')) sessionStorage.removeItem('czujka.present'); else sessionStorage.setItem('czujka.present', '1');
      apply();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [loc.search]);
}
