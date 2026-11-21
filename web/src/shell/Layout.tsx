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
        { to: '/runs', label: t('Przebiegi skanów', 'Scan runs'), icon: 'runs', perms: ['scans:read'] },
        { to: '/hosts', label: t('Hosty', 'Hosts'), icon: 'hosts', perms: ['results:read'] },
        { to: '/services', label: t('Usługi', 'Services'), icon: 'services', perms: ['results:read'] },
        { to: '/changes', label: t('Zmiany', 'Changes'), icon: 'changes', perms: ['results:read'] },
        { to: '/time', label: t('Wehikuł czasu', 'Time machine'), icon: 'history', perms: ['results:read'] },
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
        { to: '/transfer', label: t('Import / eksport', 'Import / export'), icon: 'transfer', perms: ['results:create', 'export:run'] },
        { to: '/admin', label: t('Administracja', 'Administration'), icon: 'admin', perms: ['scans:read', 'users:manage', 'roles:manage', 'audit:read'] },
      ],
    },
  ];
}

function Logo() {
  return (
    <Link to="/" className="flex h-[44px] items-center gap-2.5 px-4 text-rail-ink">
      <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">
        <path d="M4 16a8 8 0 0 1 16 0" fill="none" stroke="currentColor" strokeWidth="1.8" />
        <path d="M8 16a4 4 0 0 1 8 0" fill="none" stroke="var(--accent)" strokeWidth="1.8" />
        <rect x="10.800" y="14.800" width="2.400" height="2.400" fill="currentColor" />
        <path d="M2.500 20h19" stroke="currentColor" strokeWidth="1.400" />
      </svg>
      <span className="text-base font-semibold tracking-[-0.01em]">Czujka</span>
    </Link>
  );
}

function Rail({ onNavigate }: { onNavigate?: () => void }) {
  const { session, can } = useSession();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const logout = useAction(() => post('/auth/logout'), {
    silent: true,
    onSuccess: () => { qc.clear(); navigate('/login', { replace: true }); },
  });
  const u = session.user;
  return (
    <div className="flex h-full w-[216px] flex-col bg-rail text-rail-ink">
      <div className="border-b border-rail-rule"><Logo /></div>
      <nav className="min-h-0 flex-1 overflow-y-auto py-2" aria-label={t('Nawigacja główna', 'Main navigation')}>
        {navItems().map((group) => {
          const items = group.items.filter((i) => can(...i.perms));
          if (items.length === 0) return null;
          return (
            <div key={group.title} className="mb-2">
              <p className="px-4 pb-1 pt-2 text-2xs font-medium text-rail-ink-2">{group.title}</p>
              <ul>
                {items.map((i) => (
                  <li key={i.to}>
                    <NavLink
                      to={i.to} end={i.end} onClick={onNavigate}
                      className={({ isActive }) => cx(
                        'relative flex h-[30px] items-center gap-2.5 px-4 text-sm outline-offset-[-2px]',
                        isActive ? 'bg-rail-active font-medium text-rail-ink' : 'text-rail-ink-2 hover:bg-rail-active/50 hover:text-rail-ink',
                      )}
                    >
                      {({ isActive }) => (
                        <>
                          {isActive ? <span className="absolute inset-y-0 left-0 w-px bg-accent" aria-hidden="true" /> : null}
                          <Icon name={i.icon} />
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
      <div className="border-t border-rail-rule px-4 py-3" data-testid="whoami">
        <p className="text-2xs text-rail-ink-2">{t('Zalogowano jako', 'Signed in as')}</p>
        <p className="mt-0.5 truncate text-sm font-medium text-rail-ink" title={u.email}>{u.name || u.email}</p>
        <p className="mono truncate text-2xs text-rail-ink-2">{u.email}</p>
        <div className="mt-2 flex items-center justify-between gap-2">
          <span className="inline-flex min-w-0 items-center gap-1.5 border border-rail-rule px-1.5 py-0.5 text-xs text-rail-ink" title={roleScope(u.role_slug)}>
            <Icon name={u.role_slug === 'viewer' ? 'eye' : u.role_slug === 'admin' ? 'shield' : 'user'} size={12} />
            <span className="truncate">{roleLabel(u.role_slug, u.role_name)}</span>
          </span>
          <button type="button" onClick={() => logout.mutate(undefined)} className="inline-flex items-center gap-1 text-xs text-rail-ink-2 hover:text-rail-ink">
            <Icon name="logout" size={12} />{t('Wyloguj', 'Sign out')}
          </button>
        </div>
        <p className="mt-1.5 text-2xs text-rail-ink-2">{roleScope(u.role_slug)}</p>
      </div>
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
  const q = usePage<ScanRun>('/runs', { status: 'running', limit: 1 }, can('scans:read'));
  const listed = q.data?.items[0];
  // The list is refreshed only on run events; the live detail query (kept fresh by the run page and polling) has the current rate.
  const detail = useItem<ScanRun>('/runs/' + (listed?.id ?? 0), undefined, { enabled: Boolean(listed), refetchInterval: 4000 });
  const run = listed ? (detail.data?.status === 'running' ? detail.data : listed) : undefined;
  const profile = useItem<ScanProfile>('/profiles/' + (run?.profile_id ?? 0), undefined, { enabled: Boolean(run?.profile_id) });
  const safety = useItem<SafetyPolicy>('/settings/safety', undefined, { enabled: Boolean(run) });
  if (!run) return null;
  const pct = run.stats.addresses_total ? run.stats.addresses_done / run.stats.addresses_total : 0;
  // The run cap is the stricter of the profile cap and the policy cap, as on the run page and the dashboard.
  const policyCap = safety.data?.max_pps ?? 0;
  const cap = Math.min(profile.data?.rate.max_pps ?? policyCap, policyCap || Infinity) || policyCap;
  const over = overCap(run.stats.current_pps, cap);
  const pace = run.stats.current_pps_basis === 'pace';
  const tip = (over ? t('Tempo powyżej limitu skanu ' + fmtInt(cap) + ' pps. ', 'Rate above the run cap of ' + fmtInt(cap) + ' pps. ') : '') + (pace ? paceTip() : run.stats.current_pps_basis === 'measured' ? t('Tempo zmierzone z dokładnych liczników pakietów.', 'Rate measured from exact packet counts.') : '');
  return (
    <Link to={'/runs/' + run.id} className="hidden min-w-0 items-center gap-2 text-xs text-ink-2 hover:text-ink md:inline-flex">
      <Glyph name="run" tone="accent" pulse size={12} />
      <span className="truncate">{t('Skan', 'Run')} <span className="num">#{run.id}</span> · {run.profile_name}</span>
      <span className="num text-ink">{fmtPct(pct)}</span>
      <span className={cx('num inline-flex items-center gap-1', over ? 'font-medium text-danger' : 'text-ink-3')} title={tip || undefined} data-testid={over ? 'strip-over-cap' : pace ? 'strip-pace' : undefined}>{over ? <Icon name="alert" size={11} /> : null}{pace ? <span className="font-sans text-ink-3">{t('tempo zadane', 'set pace')}</span> : null}{pace ? '≈' : ''}{fmtInt(run.stats.current_pps)}{cap ? <span className="text-ink-3"> / {fmtInt(cap)}</span> : null} pps</span>
    </Link>
  );
}

function EmergencyStop({ policy }: { policy: SafetyPolicy | undefined }) {
  const { can } = useSession();
  const [open, setOpen] = useState(false);
  const stop = useAction(() => post<SafetyPolicy>('/emergency-stop'), {
    invalidate: ['/settings/safety', '/runs', '/dashboard'], silent: true,
    success: t('Stop awaryjny włączony. Skany zatrzymane.', 'Emergency stop is on. Scans are stopped.'),
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
          <li>{t('Wszystkie trwające przebiegi zostaną natychmiast przerwane.', 'Every running scan is cancelled at once.')}</li>
          <li>{t('Żaden nowy skan nie wystartuje, także z harmonogramu.', 'No new scan starts, scheduled ones included.')}</li>
          <li>{t('Blokadę zwalnia osoba z uprawnieniem ', 'A person with the permission ')}<span className="mono text-xs">safety:manage</span>{t('.', ' releases the stop.')}</li>
        </ul>
        <p className="mt-3 text-xs text-ink-3">{t('Operacja trafia do dziennika audytu.', 'The action is written to the audit log.')}</p>
        <div className="mt-2"><InlineError error={stop.error} /></div>
      </Dialog>
    </>
  );
}

function StopBanner({ policy }: { policy: SafetyPolicy | undefined }) {
  const { can } = useSession();
  const release = useAction(() => post<SafetyPolicy>('/emergency-stop/release'), {
    invalidate: ['/settings/safety', '/runs', '/dashboard'],
    success: t('Blokada zwolniona. Skany mogą startować.', 'The stop is released. Scans can start.'),
  });
  if (!policy?.emergency_stop) return null;
  return (
    <div role="alert" className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 bg-danger-solid px-4 py-2 text-sm text-danger-ink sm:px-6" data-testid="stop-banner">
      <span className="flex items-center gap-2 font-medium">
        <Icon name="stop" />
        {t('Stop awaryjny jest aktywny. Żaden skan nie działa i żaden nie wystartuje.', 'The emergency stop is active. No scan runs and none will start.')}
      </span>
      {can('safety:manage') ? (
        <button type="button" disabled={release.isPending} onClick={() => release.mutate(undefined)} className="inline-flex h-[26px] items-center gap-1.5 border border-white/70 px-2 text-xs font-medium hover:bg-white/15">
          <Icon name="undo" size={14} />{t('Zwolnij blokadę', 'Release the stop')}
        </button>
      ) : (
        <span className="text-xs opacity-90">{t('Blokadę zwalnia administrator.', 'An administrator releases the stop.')}</span>
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
  const probe = health.data?.probe;
  const pm = probeModeLabel(probe?.mode);
  const op = policy.operator_networks ?? [];
  const title = t('Polityka bezpieczeństwa skanowania', 'Scan safety policy')
    + (op.length ? '. ' + t('Blokada operatora wdrożenia: skanowanie tylko w ' + op.join(', ') + '. Żaden użytkownik, także administrator, nie może jej poszerzyć.', 'Deployment operator lock: scanning only inside ' + op.join(', ') + '. No user, an administrator included, can widen it.') : '');
  return (
    <Link
      to="/admin?tab=safety" className="hidden items-center gap-1.5 text-xs text-ink-2 hover:text-ink lg:inline-flex"
      title={title} data-testid="safety-chip"
    >
      <Icon name="shield" size={14} className="text-st-new" />
      {op.length ? <><span className="inline-flex items-center gap-1" data-testid="safety-chip-lock"><Icon name="lock" size={12} className="text-ink-3" /><span className="mono text-ink">{op.length === 1 ? op[0] : op.length + ' ' + t('sieci', 'networks')}</span></span><span className="text-ink-3">·</span></> : null}
      <span>{t('limit', 'cap')} <span className="num text-ink">{fmtInt(policy.max_pps)}</span> pps</span>
      <span className="text-ink-3">·</span>
      <span className="mono text-ink">{(policy.allowed_methods ?? []).join('/') || 'GET/HEAD'}</span>
      {probe ? <><span className="text-ink-3">·</span><span className="text-ink-2" title={pm.long} data-testid="probe-mode">{pm.short}</span></> : health.data && health.data.engine === false ? <><span className="text-ink-3">·</span><span className="text-st-changed">{t('skaner niepodłączony', 'scanner not wired')}</span></> : null}
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
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:bg-accent focus:px-3 focus:py-1.5 focus:text-accent-ink">
        {t('Przejdź do treści', 'Skip to content')}
      </a>
      <aside className="hidden flex-none border-r border-rail-rule lg:block"><Rail /></aside>
      {menu ? (
        <div className="fixed inset-0 z-40 lg:hidden">
          <button type="button" className="absolute inset-0 bg-black/55" aria-label={t('Zamknij menu', 'Close menu')} onClick={() => setMenu(false)} />
          <div className="absolute inset-y-0 left-0 shadow-[var(--shadow)]" style={{ animation: 'slide-in 180ms var(--ease-out-expo) reverse backwards' }}><Rail onNavigate={() => setMenu(false)} /></div>
        </div>
      ) : null}
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex h-[44px] flex-none items-center justify-between gap-3 border-b border-rule bg-panel px-2 sm:px-4">
          <div className="flex min-w-0 items-center gap-2">
            <IconButton icon="menu" label={t('Menu', 'Menu')} className="lg:hidden" onClick={() => setMenu(true)} />
            <span className="text-sm font-semibold lg:hidden">Czujka</span>
            <ActiveRunStrip />
          </div>
          <div className="flex flex-none items-center gap-1.5 sm:gap-3">
            <SafetyChip policy={safety.data} />
            <EmergencyStop policy={safety.data} />
            <span className="hidden h-4 w-px bg-rule sm:block" />
            <button
              type="button" onClick={() => setLang(lang === 'pl' ? 'en' : 'pl')}
              className="inline-flex h-[26px] items-center gap-1 rounded-sm px-1.5 text-xs text-ink-2 hover:bg-raised hover:text-ink"
              aria-label={t('Zmień język na angielski', 'Switch language to Polish')} data-testid="lang-toggle"
            >
              <span className={lang === 'pl' ? 'font-semibold text-ink' : ''}>PL</span>
              <span className="text-ink-3">/</span>
              <span className={lang === 'en' ? 'font-semibold text-ink' : ''}>EN</span>
            </button>
            <IconButton icon={theme === 'dark' ? 'sun' : 'moon'} label={theme === 'dark' ? t('Jasny motyw', 'Light theme') : t('Ciemny motyw', 'Dark theme')} onClick={toggleTheme} data-testid="theme-toggle" />
            <span className="inline-flex items-center gap-1.5 border border-rule-strong px-1.5 py-0.5 text-xs text-ink lg:hidden" title={u.email} data-testid="role-chip">
              <Icon name={u.role_slug === 'viewer' ? 'eye' : u.role_slug === 'admin' ? 'shield' : 'user'} size={12} />
              {roleLabel(u.role_slug, u.role_name)}
            </span>
          </div>
        </div>
        <StopBanner policy={safety.data} />
        <main id="main" className="min-h-0 flex-1 overflow-y-auto" tabIndex={-1}>
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
      <p className="text-sm font-medium">{t('Ta strona wymaga uprawnień, których Twoja rola nie ma.', 'This page needs permissions that your role does not have.')}</p>
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
