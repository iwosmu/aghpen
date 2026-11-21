// Dev-only fixture data: a university network (about 12 800 addresses in scope,
// about 420 known hosts). Loaded only when VITE_FIXTURES=1 in a dev server.
// Nothing here ships in the production bundle.
import type {
  AuditEntry, AvailabilityProfile, Change, ChangeKind, Chunk, Cookie, DefectDojoSettings, Evidence, Finding, Host, HostStatus,
  InterestReason, MapBlock, Permission, PermissionInfo, Role, SafetyPolicy, ScanProfile, ScanRun, Scope, Service,
  ServiceObservation, ServiceResult, Severity, Signature, SigMatch, Target, Technology, TLSInfo, User, RunStats,
} from '../api/types';
import { ALL_PERMISSIONS } from '../api/types';

// ---------- deterministic random ----------
function mulberry32(a: number) {
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let x = Math.imul(a ^ (a >>> 15), 1 | a);
    x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x;
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(20261122);
const int = (a: number, b: number) => a + Math.floor(rnd() * (b - a + 1));
const pick = <T,>(arr: T[]): T => arr[Math.floor(rnd() * arr.length)];
const chance = (p: number) => rnd() < p;
function hex(n: number): string {
  let s = '';
  for (let i = 0; i < n; i++) s += '0123456789abcdef'[Math.floor(rnd() * 16)];
  return s;
}
function hashStr(s: string): string {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return ('0000000' + (h >>> 0).toString(16)).slice(-8);
}

export const NOW = Date.now();
const H = 3600_000;
const D = 24 * H;
const iso = (ms: number) => new Date(ms).toISOString();
/** Last occurrence of hh:mm local time that is at least minAgoH hours ago. */
function lastAt(hour: number, minAgoH = 0, daysBack = 0): number {
  const d = new Date(NOW - minAgoH * H);
  d.setMinutes(0, 0, 0);
  if (d.getHours() < hour) d.setDate(d.getDate() - 1);
  d.setHours(hour);
  d.setDate(d.getDate() - daysBack);
  return d.getTime();
}

// ---------- RBAC ----------
const P_LABELS: Record<Permission, [string, string, string]> = {
  'targets:read': ['Cele', 'Odczyt celów i zakresów', 'Read targets and scopes'],
  'targets:create': ['Cele', 'Dodawanie celów', 'Create targets'],
  'targets:update': ['Cele', 'Edycja celów', 'Update targets'],
  'targets:delete': ['Cele', 'Usuwanie celów', 'Delete targets'],
  'scans:read': ['Skany', 'Odczyt przebiegów i profili', 'Read runs and profiles'],
  'scans:run': ['Skany', 'Uruchamianie, pauza, anulowanie', 'Start, pause, cancel runs'],
  'scans:configure': ['Skany', 'Konfiguracja profili i harmonogramów', 'Configure profiles and schedules'],
  'results:read': ['Wyniki', 'Odczyt hostów, usług, zmian, znalezisk', 'Read hosts, services, changes, findings'],
  'results:update': ['Wyniki', 'Edycja wyników i potwierdzanie zmian', 'Edit results and acknowledge changes'],
  'results:create': ['Wyniki', 'Ręczne znaleziska i import wyników', 'Manual findings and result import'],
  'results:delete': ['Wyniki', 'Usuwanie wyników', 'Delete results'],
  'signatures:read': ['Sygnatury', 'Odczyt sygnatur', 'Read signatures'],
  'signatures:create': ['Sygnatury', 'Tworzenie sygnatur', 'Create signatures'],
  'signatures:update': ['Sygnatury', 'Edycja i włączanie sygnatur', 'Update and toggle signatures'],
  'signatures:delete': ['Sygnatury', 'Usuwanie sygnatur', 'Delete signatures'],
  'export:run': ['Integracje', 'Eksport JSON/CSV i wysyłka do DefectDojo', 'JSON/CSV export and DefectDojo push'],
  'integrations:manage': ['Integracje', 'Ustawienia DefectDojo', 'DefectDojo settings'],
  'safety:manage': ['Bezpieczeństwo', 'Polityka bezpieczeństwa, zwolnienie stopu', 'Safety policy, release the stop'],
  'safety:stop': ['Bezpieczeństwo', 'Stop awaryjny', 'Emergency stop'],
  'users:manage': ['Administracja', 'Zarządzanie użytkownikami', 'Manage users'],
  'roles:manage': ['Administracja', 'Zarządzanie rolami', 'Manage roles'],
  'audit:read': ['Administracja', 'Odczyt dziennika audytu', 'Read the audit log'],
};
export const permissions: PermissionInfo[] = ALL_PERMISSIONS.map((p) => ({ permission: p, group: P_LABELS[p][0], label_pl: P_LABELS[p][1], label_en: P_LABELS[p][2] }));

const READ: Permission[] = ['targets:read', 'scans:read', 'results:read', 'signatures:read'];
export const roles: Role[] = [
  { id: 1, slug: 'admin', name: 'Administrator', description: 'Administracja: wszystkie uprawnienia', builtin: true, permissions: [...ALL_PERMISSIONS], user_count: 0 },
  { id: 2, slug: 'editor', name: 'Edytor', description: 'Dodawanie, usuwanie, modyfikacja', builtin: true, user_count: 0,
    permissions: [...READ, 'targets:create', 'targets:update', 'targets:delete', 'scans:run', 'scans:configure', 'results:update', 'results:create', 'results:delete', 'signatures:create', 'signatures:update', 'signatures:delete', 'export:run', 'safety:stop'] },
  { id: 3, slug: 'analyst', name: 'Analityk', description: 'Modyfikacja i odczyt', builtin: true, user_count: 0,
    permissions: [...READ, 'targets:update', 'scans:run', 'results:update', 'signatures:update', 'export:run', 'safety:stop'] },
  { id: 4, slug: 'viewer', name: 'Odczyt', description: 'Tylko odczyt', builtin: true, permissions: [...READ], user_count: 0 },
  { id: 5, slug: 'audytor-zewnetrzny', name: 'Audytor zewnętrzny', description: 'Odczyt wyników, dziennik audytu i eksport', builtin: false, permissions: ['results:read', 'scans:read', 'audit:read', 'export:run'], user_count: 0 },
];

export const users: User[] = [
  { id: 1, email: 'admin@cbi.example', name: 'Tomasz Nowicki', role_id: 1, role_slug: 'admin', role_name: 'Administrator', disabled: false, created_at: iso(NOW - 210 * D), last_login_at: iso(NOW - 2 * H) },
  { id: 2, email: 'editor@cbi.example', name: 'Katarzyna Wrona', role_id: 2, role_slug: 'editor', role_name: 'Edytor', disabled: false, created_at: iso(NOW - 180 * D), last_login_at: iso(NOW - 26 * H) },
  { id: 3, email: 'analyst@cbi.example', name: 'Anna Zielińska', role_id: 3, role_slug: 'analyst', role_name: 'Analityk', disabled: false, created_at: iso(NOW - 150 * D), last_login_at: iso(NOW - 40 * 60_000) },
  { id: 4, email: 'viewer@cbi.example', name: 'Piotr Maj', role_id: 4, role_slug: 'viewer', role_name: 'Odczyt', disabled: false, created_at: iso(NOW - 90 * D), last_login_at: iso(NOW - 3 * D) },
  { id: 5, email: 'm.kowal@cbi.example', name: 'Marek Kowal', role_id: 3, role_slug: 'analyst', role_name: 'Analityk', disabled: false, created_at: iso(NOW - 120 * D), last_login_at: iso(NOW - 5 * H) },
  { id: 6, email: 'audyt@partner.example', name: 'Audyt zewnętrzny', role_id: 5, role_slug: 'audytor-zewnetrzny', role_name: 'Audytor zewnętrzny', disabled: true, created_at: iso(NOW - 45 * D), last_login_at: iso(NOW - 31 * D) },
];
for (const r of roles) r.user_count = users.filter((u) => u.role_id === r.id).length;

// ---------- Scopes and targets ----------
export const scopes: Scope[] = [
  { id: 1, name: 'Sieć kampusowa — wydziały', description: 'Budynki dydaktyczne, laboratoria, administracja', owner: 'Dział Sieci', criticality: 3, tags: ['kampus'], target_count: 3, address_count: 8192, created_at: iso(NOW - 200 * D), updated_at: iso(NOW - 12 * D) },
  { id: 2, name: 'Akademiki — Miasteczko Studenckie', description: 'Sieć mieszkańców domów studenckich', owner: 'Administracja DS', criticality: 2, tags: ['akademiki'], target_count: 2, address_count: 4096, created_at: iso(NOW - 200 * D), updated_at: iso(NOW - 30 * D) },
  { id: 3, name: 'Serwerownia / DMZ', description: 'Usługi publiczne uczelni', owner: 'Centrum Informatyki', criticality: 5, tags: ['dmz', 'publiczne'], target_count: 6, address_count: 518, created_at: iso(NOW - 200 * D), updated_at: iso(NOW - 2 * D) },
];
let targetId = 0;
const tg = (scope_id: number, kind: Target['kind'], value: string, addresses: number, note = '', source = 'manual', enabled = true): Target => ({
  id: ++targetId, scope_id, kind, value, note, tags: [], enabled, source, addresses, created_at: iso(NOW - int(20, 190) * D), created_by: pick([1, 2]),
});
export const targets: Target[] = [
  tg(1, 'cidr', '10.20.0.0/20', 4096, 'Pawilony A–D', 'csv'),
  tg(1, 'cidr', '10.20.16.0/21', 2048, 'Laboratoria', 'csv'),
  tg(1, 'cidr', '10.20.24.0/21', 2048, 'Biblioteka i administracja', 'csv'),
  tg(2, 'cidr', '10.20.32.0/21', 2048, 'DS 1–8'),
  tg(2, 'cidr', '10.20.40.0/21', 2048, 'DS 9–17'),
  tg(3, 'cidr', '10.30.4.0/23', 512, 'DMZ'),
  tg(3, 'domain', 'www.uczelnia.example', 1, '', 'json'),
  tg(3, 'domain', 'moodle.uczelnia.example', 1, '', 'json'),
  tg(3, 'domain', 'poczta.uczelnia.example', 1, '', 'json'),
  tg(3, 'range', '10.30.8.10-10.30.8.12', 3, 'Zapasowe DNS'),
  tg(3, 'ip', '10.30.9.1', 1, 'Brama VPN — wyłączona z testów', 'manual', false),
];

export const safety: SafetyPolicy = {
  max_pps: 1000, max_http_rps: 40, max_per_host_rps: 2, max_paths_per_host: 6, allowed_ports: '', denied_ports: '9100,515',
  exclusions: ['10.20.31.240/28', '10.30.9.1', 'kadry.uczelnia.example'], allowed_methods: ['GET', 'HEAD'], emergency_stop: false,
  user_agent: 'Czujka/0.1 (+https://cbi.uczelnia.example/skaner; soc@cbi.example)', updated_at: iso(NOW - 9 * D),
};

// ---------- Profiles ----------
const baseProfile = (): Omit<ScanProfile, 'id' | 'name' | 'description' | 'scope_ids' | 'ports' | 'schedule' | 'next_run_at' | 'last_run_id'> => ({
  discovery: { icmp_echo: true, icmp_timestamp: false, tcp_syn_ports: [22, 80, 443, 3389], tcp_ack_ports: [80], arp: false, skip_discovery: false, mode: 'balanced' },
  service_detection: true, version_intensity: 5, udp: { enabled: false, ports: '' },
  http: { enabled: true, max_redirects: 5, signature_paths: true, max_body_bytes: 262144, timeout_ms: 8000, favicon: true },
  rate: { max_pps: 800, max_parallel_chunks: 2, max_parallel_hosts: 24, http_rps: 20, per_host_concurrency: 2, per_host_delay_ms: 250 },
  chunking: { adaptive: true, initial_size: 256, min_size: 64, max_size: 2048, target_seconds: 90 },
  retry: { unstable_retries: 2, backoff_ms: 1500, down_after_misses: 0 }, enabled: true, created_at: iso(NOW - 190 * D), updated_at: iso(NOW - 6 * D),
});
function nextAt(hour: number): string {
  const d = new Date(NOW);
  d.setMinutes(0, 0, 0);
  if (d.getHours() >= hour) d.setDate(d.getDate() + 1);
  d.setHours(hour);
  return d.toISOString();
}
export const profiles: ScanProfile[] = [
  { ...baseProfile(), id: 1, name: 'Nocny przegląd kampusu', description: 'Pełny przegląd wszystkich zakresów, co noc w oknie 22:00–06:00', scope_ids: [1, 2, 3], ports: 'top-1000',
    schedule: { enabled: true, cron: '0 22 * * *', interval_minutes: 0, windows: [{ days: [0, 1, 2, 3, 4, 5, 6], start: '22:00', end: '06:00' }], timezone: 'Europe/Warsaw' }, next_run_at: nextAt(22), last_run_id: 42 },
  { ...baseProfile(), id: 2, name: 'Szybki przegląd DMZ', description: 'Top 100 portów w DMZ, co 4 godziny', scope_ids: [3], ports: 'top-100',
    rate: { max_pps: 300, max_parallel_chunks: 1, max_parallel_hosts: 16, http_rps: 10, per_host_concurrency: 2, per_host_delay_ms: 300 },
    schedule: { enabled: true, cron: '', interval_minutes: 240, windows: [], timezone: 'Europe/Warsaw' }, next_run_at: iso(NOW + 95 * 60_000), last_run_id: 39 },
  { ...baseProfile(), id: 3, name: 'Akademiki — weekend', description: 'Pełne porty w sieci akademików, tylko w weekendowe noce', scope_ids: [2], ports: '1-10000',
    rate: { max_pps: 1500, max_parallel_chunks: 3, max_parallel_hosts: 32, http_rps: 20, per_host_concurrency: 2, per_host_delay_ms: 250 },
    schedule: { enabled: true, cron: '0 0 * * 6', interval_minutes: 0, windows: [{ days: [6, 0], start: '00:00', end: '06:00' }], timezone: 'Europe/Warsaw' }, next_run_at: iso(NOW + 5 * D), last_run_id: 40 },
];

// ---------- Service templates ----------
interface Tpl {
  port: number; name: string; product?: string; version?: string; tls?: boolean; banner?: string; conf?: number;
  title?: string; status?: number; server?: string; powered?: string; gen?: string; redirect?: string;
  cookies?: string[]; headers?: Record<string, string>; paths?: [string, number, string][];
  techs?: [string, string, string, number, Evidence[]][]; classes?: string[]; why?: [string, number, string][];
  cert?: 'ca' | 'le' | 'self'; favicon?: number;
}
const ev = (matcher: string, where: string, snippet: string): Evidence => ({ matcher, where, snippet });
const SEC_HEADERS = { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN' };
const TPL: Record<string, Tpl> = {
  ssh: { port: 22, name: 'ssh', product: 'OpenSSH', version: '9.6p1', banner: 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5', conf: 0.98, techs: [['OpenSSH', 'security', '9.6p1', 0.98, [ev('banner', 'banner', 'SSH-2.0-OpenSSH_9.6p1')]]] },
  sshOld: { port: 22, name: 'ssh', product: 'OpenSSH', version: '7.4', banner: 'SSH-2.0-OpenSSH_7.4', conf: 0.98, techs: [['OpenSSH', 'security', '7.4', 0.98, [ev('banner', 'banner', 'SSH-2.0-OpenSSH_7.4')]]], why: [['outdated', 15, 'Przestarzała wersja OpenSSH 7.4 (2016)']] },
  telnet: { port: 23, name: 'telnet', product: 'Cisco IOS telnetd', conf: 0.9, banner: 'User Access Verification', classes: ['remote-access'], why: [['remote-access', 25, 'Zdalny dostęp bez szyfrowania (telnet)']] },
  rdp: { port: 3389, name: 'ms-wbt-server', product: 'Microsoft Terminal Services', conf: 0.95, classes: ['remote-access'], why: [['remote-access', 15, 'Wystawiony zdalny pulpit (RDP)']] },
  vnc: { port: 5900, name: 'vnc', product: 'RealVNC', version: '5.3', banner: 'RFB 003.008', conf: 0.9, classes: ['remote-access'], why: [['remote-access', 20, 'Wystawiony zdalny pulpit (VNC)']] },
  smb: { port: 445, name: 'microsoft-ds', product: 'Samba smbd', version: '4.15', conf: 0.85, why: [['file-share', 10, 'Udział plików SMB widoczny w sieci']] },
  mysql: { port: 3306, name: 'mysql', product: 'MySQL', version: '8.0.36', banner: '8.0.36-0ubuntu0.22.04.1', conf: 0.97, classes: ['database'], techs: [['MySQL', 'database', '8.0.36', 0.97, [ev('banner', 'banner', '8.0.36-0ubuntu0.22.04.1')]]], why: [['database', 25, 'Port bazy danych dostępny z sieci']] },
  postgres: { port: 5432, name: 'postgresql', product: 'PostgreSQL', version: '14.11', conf: 0.92, classes: ['database'], techs: [['PostgreSQL', 'database', '14', 0.92, [ev('banner', 'nmap', 'PostgreSQL DB 14.9 - 14.11')]]], why: [['database', 25, 'Port bazy danych dostępny z sieci']] },
  redis: { port: 6379, name: 'redis', product: 'Redis key-value store', version: '6.2.6', conf: 0.95, classes: ['database'], techs: [['Redis', 'database', '6.2.6', 0.95, [ev('banner', 'nmap', 'Redis key-value store 6.2.6')]]], why: [['database', 30, 'Redis dostępny z sieci']] },
  smtp: { port: 25, name: 'smtp', product: 'Postfix smtpd', banner: '220 poczta.uczelnia.example ESMTP Postfix', conf: 0.96 },
  imaps: { port: 993, name: 'imap', product: 'Dovecot imapd', tls: true, cert: 'ca', conf: 0.95 },
  dns: { port: 53, name: 'domain', product: 'ISC BIND', version: '9.18.24', conf: 0.93 },
  ldap: { port: 389, name: 'ldap', product: 'OpenLDAP', version: '2.5.16', conf: 0.9, why: [['directory', 10, 'Usługa katalogowa LDAP bez TLS']] },
  ftp: { port: 21, name: 'ftp', product: 'vsftpd', version: '3.0.5', banner: '220 (vsFTPd 3.0.5)', conf: 0.97, why: [['cleartext', 10, 'FTP bez szyfrowania']] },
  ipp: { port: 631, name: 'ipp', product: 'CUPS', version: '2.3', conf: 0.8 },
  rtsp: { port: 554, name: 'rtsp', product: 'Hikvision RTSP', conf: 0.85 },
  winbox: { port: 8291, name: 'winbox', product: 'MikroTik WinBox', conf: 0.9, why: [['admin-panel', 15, 'Port zarządzania WinBox dostępny z sieci']] },
  nginxDefault: { port: 80, name: 'http', product: 'nginx', version: '1.24.0', title: 'Welcome to nginx!', status: 200, server: 'nginx/1.24.0', classes: ['default-page'], conf: 0.97,
    techs: [['nginx', 'web-server', '1.24.0', 0.97, [ev('header', 'header:Server', 'nginx/1.24.0'), ev('title', 'title', 'Welcome to nginx!')]]], why: [['default-page', 5, 'Strona domyślna serwera WWW']] },
  apacheDefault: { port: 80, name: 'http', product: 'Apache httpd', version: '2.4.52', title: 'Apache2 Ubuntu Default Page: It works', status: 200, server: 'Apache/2.4.52 (Ubuntu)', classes: ['default-page'], conf: 0.97,
    techs: [['Apache HTTP Server', 'web-server', '2.4.52', 0.97, [ev('header', 'header:Server', 'Apache/2.4.52 (Ubuntu)'), ev('body', 'body', 'Apache2 Ubuntu Default Page')]]], why: [['default-page', 5, 'Strona domyślna serwera WWW']] },
  iisDefault: { port: 80, name: 'http', product: 'Microsoft IIS httpd', version: '10.0', title: 'IIS Windows Server', status: 200, server: 'Microsoft-IIS/10.0', powered: 'ASP.NET', classes: ['default-page'], conf: 0.97,
    techs: [['Microsoft IIS', 'web-server', '10.0', 0.97, [ev('header', 'header:Server', 'Microsoft-IIS/10.0')]], ['ASP.NET', 'framework', '', 0.6, [ev('header', 'header:X-Powered-By', 'ASP.NET')]]], why: [['default-page', 5, 'Strona domyślna serwera WWW']] },
  wp: { port: 443, name: 'http', tls: true, cert: 'ca', product: 'nginx', version: '1.24.0', title: 'Wydział – Uczelnia', status: 200, server: 'nginx/1.24.0', powered: 'PHP/8.1.27', gen: 'WordPress 6.4.3', conf: 0.97,
    cookies: ['wordpress_test_cookie|S|-|'], headers: { ...SEC_HEADERS, Link: '<https://HOST/wp-json/>; rel="https://api.w.org/"' }, paths: [['/wp-login.php', 200, 'Zaloguj się ‹ Wydział — WordPress']],
    techs: [['WordPress', 'cms', '6.4.3', 0.99, [ev('meta', 'meta:generator', 'WordPress 6.4.3'), ev('path', 'path:/wp-login.php', '200, formularz logowania'), ev('header', 'header:Link', 'rel="https://api.w.org/"'), ev('cookie', 'cookie:wordpress_test_cookie', 'wordpress_test_cookie')]],
      ['PHP', 'language', '8.1.27', 0.6, [ev('header', 'header:X-Powered-By', 'PHP/8.1.27')]], ['nginx', 'web-server', '1.24.0', 0.97, [ev('header', 'header:Server', 'nginx/1.24.0')]]],
    classes: ['login'], why: [['login', 10, 'Strona logowania (/wp-login.php)']] },
  wpOld: { port: 443, name: 'http', tls: true, cert: 'le', product: 'Apache httpd', version: '2.4.41', title: 'Biblioteka Główna – aktualności', status: 200, server: 'Apache/2.4.41 (Ubuntu)', powered: 'PHP/7.4.3', gen: 'WordPress 5.8.2', conf: 0.97,
    cookies: ['wordpress_test_cookie|-|-|'], headers: { Link: '<https://HOST/wp-json/>; rel="https://api.w.org/"' }, paths: [['/wp-login.php', 200, 'Zaloguj się ‹ Biblioteka — WordPress']],
    techs: [['WordPress', 'cms', '5.8.2', 0.99, [ev('meta', 'meta:generator', 'WordPress 5.8.2'), ev('path', 'path:/wp-login.php', '200, formularz logowania'), ev('header', 'header:Link', 'rel="https://api.w.org/"')]],
      ['PHP', 'language', '7.4.3', 0.6, [ev('header', 'header:X-Powered-By', 'PHP/7.4.3')]], ['Apache HTTP Server', 'web-server', '2.4.41', 0.97, [ev('header', 'header:Server', 'Apache/2.4.41 (Ubuntu)')]]],
    classes: ['login'], why: [['login', 10, 'Strona logowania (/wp-login.php)'], ['outdated', 15, 'Przestarzała wersja: WordPress 5.8.2, PHP 7.4'], ['missing-headers', 10, 'Brak nagłówków bezpieczeństwa na stronie logowania']] },
  moodle: { port: 443, name: 'http', tls: true, cert: 'ca', product: 'Apache httpd', version: '2.4.57', title: 'E-learning Uczelni: Zaloguj się', status: 200, server: 'Apache/2.4.57', powered: 'PHP/8.2.15', conf: 0.96, redirect: '/login/index.php',
    cookies: ['MoodleSession|S|H|Lax'], headers: { ...SEC_HEADERS }, paths: [['/login/index.php', 200, 'E-learning Uczelni: Zaloguj się']],
    techs: [['Moodle', 'cms', '4.3', 0.97, [ev('cookie', 'cookie:MoodleSession', 'MoodleSession'), ev('body', 'body', 'M.cfg = {"wwwroot":'), ev('favicon', 'favicon:mmh3', '-438482901')]], ['PHP', 'language', '8.2.15', 0.6, [ev('header', 'header:X-Powered-By', 'PHP/8.2.15')]], ['Apache HTTP Server', 'web-server', '2.4.57', 0.97, [ev('header', 'header:Server', 'Apache/2.4.57')]]],
    classes: ['login'], why: [['login', 10, 'Strona logowania']], favicon: -438482901 },
  jenkins: { port: 8080, name: 'http', product: 'Jetty', version: '10.0.18', title: 'Dashboard [Jenkins]', status: 200, server: 'Jetty(10.0.18)', conf: 0.95,
    cookies: ['JSESSIONID.4f2a91c0|-|H|'], headers: { 'X-Jenkins': '2.426.3', 'X-Jenkins-Session': '5e1b9a2c', 'X-Hudson': '1.395' }, paths: [['/login', 200, 'Sign in [Jenkins]']],
    techs: [['Jenkins', 'devops', '2.426.3', 0.99, [ev('header', 'header:X-Jenkins', '2.426.3'), ev('title', 'title', 'Dashboard [Jenkins]'), ev('favicon', 'favicon:mmh3', '81586312')]], ['Jetty', 'app-server', '10.0.18', 0.9, [ev('header', 'header:Server', 'Jetty(10.0.18)')]]],
    classes: ['dev-tool', 'admin-panel'], why: [['dev-tool', 30, 'Narzędzie CI dostępne z sieci'], ['admin-panel', 25, 'Panel dostępny bez przekierowania do logowania'], ['missing-headers', 10, 'Brak nagłówków bezpieczeństwa']], favicon: 81586312 },
  grafana: { port: 3000, name: 'http', product: 'Grafana', version: '10.2.3', title: 'Grafana', status: 200, conf: 0.95, redirect: '/login',
    cookies: ['grafana_session|-|H|Lax'], headers: { 'X-Frame-Options': 'deny', 'X-Content-Type-Options': 'nosniff' }, paths: [['/login', 200, 'Grafana'], ['/api/health', 200, '']],
    techs: [['Grafana', 'devops', '10.2.3', 0.98, [ev('path', 'path:/api/health', '"version":"10.2.3"'), ev('cookie', 'cookie:grafana_session', 'grafana_session'), ev('title', 'title', 'Grafana')]]],
    classes: ['login', 'dev-tool'], why: [['dev-tool', 20, 'Panel monitoringu dostępny z sieci'], ['login', 10, 'Strona logowania']] },
  prometheus: { port: 9090, name: 'http', product: 'Prometheus', version: '2.48.1', title: 'Prometheus Time Series Collection and Processing Server', status: 200, conf: 0.94,
    paths: [['/version', 404, ''], ['/-/healthy', 200, '']], techs: [['Prometheus', 'devops', '2.48.1', 0.9, [ev('title', 'title', 'Prometheus Time Series Collection and Processing Server'), ev('path', 'path:/-/healthy', 'Prometheus Server is Healthy.')]]],
    classes: ['dev-tool'], why: [['dev-tool', 25, 'Metryki infrastruktury dostępne bez logowania']] },
  gitlab: { port: 443, name: 'http', tls: true, cert: 'ca', product: 'nginx', title: 'Sign in · GitLab', status: 200, server: 'nginx', conf: 0.96, redirect: '/users/sign_in',
    cookies: ['_gitlab_session|S|H|Lax'], headers: { ...SEC_HEADERS, 'X-Gitlab-Meta': '{"correlation_id":"01HV…"}' }, paths: [['/users/sign_in', 200, 'Sign in · GitLab']],
    techs: [['GitLab', 'devops', '16.8', 0.97, [ev('cookie', 'cookie:_gitlab_session', '_gitlab_session'), ev('title', 'title', 'Sign in · GitLab'), ev('header', 'header:X-Gitlab-Meta', 'correlation_id')]], ['nginx', 'web-server', '', 0.9, [ev('header', 'header:Server', 'nginx')]]],
    classes: ['login', 'dev-tool'], why: [['dev-tool', 15, 'Repozytorium kodu dostępne z sieci'], ['login', 10, 'Strona logowania']] },
  pma: { port: 443, name: 'http', tls: true, cert: 'self', product: 'Apache httpd', version: '2.4.52', title: 'phpMyAdmin', status: 200, server: 'Apache/2.4.52 (Ubuntu)', powered: 'PHP/8.1.2', conf: 0.96,
    cookies: ['phpMyAdmin|S|H|Strict', 'pma_lang|S|H|'], headers: { 'X-Frame-Options': 'DENY', 'X-Robots-Tag': 'noindex, nofollow' },
    techs: [['phpMyAdmin', 'panel', '5.2.1', 0.99, [ev('title', 'title', 'phpMyAdmin'), ev('cookie', 'cookie:phpMyAdmin', 'phpMyAdmin'), ev('body', 'body', 'PMA_VERSION:"5.2.1"')]], ['PHP', 'language', '8.1.2', 0.6, [ev('header', 'header:X-Powered-By', 'PHP/8.1.2')]], ['Apache HTTP Server', 'web-server', '2.4.52', 0.97, [ev('header', 'header:Server', 'Apache/2.4.52 (Ubuntu)')]]],
    classes: ['admin-panel', 'login', 'database'], why: [['admin-panel', 25, 'Panel administracyjny bazy danych'], ['login', 10, 'Strona logowania'], ['self-signed-cert', 10, 'Certyfikat samopodpisany']] },
  nextcloud: { port: 443, name: 'http', tls: true, cert: 'le', product: 'nginx', title: 'Chmura Uczelni – Nextcloud', status: 200, server: 'nginx', conf: 0.95, redirect: '/login',
    cookies: ['oc_sessionPassphrase|S|H|Lax', 'nc_sameSiteCookiestrict|S|H|Strict'], headers: { ...SEC_HEADERS, 'X-Robots-Tag': 'noindex, nofollow' }, paths: [['/status.php', 200, '']],
    techs: [['Nextcloud', 'cms', '27.1.5', 0.98, [ev('path', 'path:/status.php', '"versionstring":"27.1.5"'), ev('cookie', 'cookie:oc_sessionPassphrase', 'oc_sessionPassphrase')]]], classes: ['login'], why: [['login', 10, 'Strona logowania']] },
  roundcube: { port: 443, name: 'http', tls: true, cert: 'ca', product: 'nginx', title: 'Poczta Uczelni :: Witamy w Roundcube Webmail', status: 200, server: 'nginx', conf: 0.95,
    cookies: ['roundcube_sessid|S|H|Lax'], headers: { ...SEC_HEADERS }, techs: [['Roundcube', 'cms', '1.6.6', 0.95, [ev('cookie', 'cookie:roundcube_sessid', 'roundcube_sessid'), ev('title', 'title', 'Roundcube Webmail')]]], classes: ['login'], why: [['login', 10, 'Strona logowania']] },
  tomcat: { port: 8080, name: 'http', product: 'Apache Tomcat', version: '9.0.83', title: 'Apache Tomcat/9.0.83', status: 200, conf: 0.97, paths: [['/manager/html', 401, '401 Unauthorized']],
    techs: [['Apache Tomcat', 'app-server', '9.0.83', 0.99, [ev('title', 'title', 'Apache Tomcat/9.0.83'), ev('path', 'path:/manager/html', '401, WWW-Authenticate: Basic realm="Tomcat Manager Application"')]]],
    classes: ['default-page', 'admin-panel'], why: [['admin-panel', 25, 'Panel Tomcat Manager odpowiada (401)'], ['default-page', 5, 'Strona domyślna serwera aplikacyjnego']] },
  staging: { port: 8000, name: 'http', product: 'gunicorn', title: '[STAGING] System rekrutacji', status: 200, server: 'gunicorn', conf: 0.9,
    cookies: ['csrftoken|-|-|Lax', 'sessionid|-|H|Lax'], headers: { 'X-Environment': 'staging', 'X-Robots-Tag': 'noindex', 'X-Frame-Options': 'DENY' }, paths: [['/admin/', 302, ''], ['/admin/login/', 200, 'Zaloguj się | Administracja stroną Django']],
    techs: [['Django', 'framework', '', 0.93, [ev('cookie', 'cookie:csrftoken', 'csrftoken'), ev('path', 'path:/admin/login/', 'Administracja stroną Django')]], ['gunicorn', 'app-server', '', 0.9, [ev('header', 'header:Server', 'gunicorn')]], ['Staging', 'environment', '', 0.96, [ev('title', 'title', '[STAGING]'), ev('header', 'header:X-Environment', 'staging')]]],
    classes: ['staging', 'login', 'admin-panel'], why: [['staging', 30, 'Środowisko testowe (tytuł, nagłówek X-Environment)'], ['admin-panel', 25, 'Panel administracyjny Django (/admin/)'], ['missing-headers', 10, 'Ciasteczko sesji bez flagi Secure']] },
  kibana: { port: 5601, name: 'http', product: 'Kibana', version: '8.11.3', title: 'Elastic', status: 200, conf: 0.93, redirect: '/login', headers: { 'kbn-name': 'logi-kibana', 'kbn-license-sig': hex(24) },
    techs: [['Kibana', 'devops', '8.11.3', 0.95, [ev('header', 'header:kbn-name', 'logi-kibana'), ev('title', 'title', 'Elastic')]]], classes: ['dev-tool', 'login'], why: [['dev-tool', 20, 'Panel logów dostępny z sieci'], ['login', 10, 'Strona logowania']] },
  zabbix: { port: 443, name: 'http', tls: true, cert: 'ca', product: 'nginx', title: 'Zabbix', status: 200, server: 'nginx', conf: 0.94, cookies: ['zbx_session|S|H|'], headers: { ...SEC_HEADERS },
    techs: [['Zabbix', 'panel', '6.4', 0.94, [ev('cookie', 'cookie:zbx_session', 'zbx_session'), ev('title', 'title', 'Zabbix')]]], classes: ['login', 'admin-panel'], why: [['admin-panel', 20, 'Panel monitoringu'], ['login', 10, 'Strona logowania']] },
  proxmox: { port: 8006, name: 'http', tls: true, cert: 'self', product: 'pve-api-daemon', version: '3.0', title: 'pve1 - Proxmox Virtual Environment', status: 200, server: 'pve-api-daemon/3.0', conf: 0.96,
    techs: [['Proxmox VE', 'panel', '8.1', 0.97, [ev('header', 'header:Server', 'pve-api-daemon/3.0'), ev('title', 'title', 'Proxmox Virtual Environment')]]], classes: ['admin-panel', 'login'], why: [['admin-panel', 25, 'Panel wirtualizacji'], ['login', 10, 'Strona logowania'], ['self-signed-cert', 10, 'Certyfikat samopodpisany']] },
  api: { port: 8443, name: 'http', tls: true, cert: 'ca', product: 'uvicorn', title: '', status: 200, server: 'uvicorn', conf: 0.85, headers: { 'Content-Type': 'application/json' }, paths: [['/docs', 200, 'USOS API - Swagger UI'], ['/version', 200, '']],
    techs: [['FastAPI', 'framework', '', 0.8, [ev('path', 'path:/docs', 'Swagger UI'), ev('header', 'header:Server', 'uvicorn')]]], classes: ['api'], why: [['api', 10, 'Publiczna dokumentacja API (/docs)']] },
  dirlist: { port: 80, name: 'http', product: 'Apache httpd', version: '2.4.52', title: 'Index of /pub', status: 200, server: 'Apache/2.4.52 (Ubuntu)', conf: 0.97,
    techs: [['Apache HTTP Server', 'web-server', '2.4.52', 0.97, [ev('header', 'header:Server', 'Apache/2.4.52 (Ubuntu)')]]], classes: ['directory-listing'], why: [['directory-listing', 20, 'Listing katalogu /pub']] },
  printerHp: { port: 80, name: 'http', product: 'HP LaserJet http config', title: 'HP LaserJet Pro M404dn', status: 200, server: 'HP HTTP Server; HP LaserJet Pro M404dn - W1A53A', conf: 0.95,
    techs: [['HP LaserJet', 'iot', 'M404dn', 0.97, [ev('header', 'header:Server', 'HP HTTP Server; HP LaserJet Pro M404dn'), ev('title', 'title', 'HP LaserJet Pro M404dn')]]], classes: ['iot', 'admin-panel'], why: [['iot', 15, 'Urządzenie IoT (drukarka)'], ['admin-panel', 10, 'Panel konfiguracji bez logowania']] },
  printerKy: { port: 443, name: 'http', tls: true, cert: 'self', product: 'KM-MFP-http', title: 'Kyocera Command Center RX', status: 200, server: 'KM-MFP-http/V0.0.1', conf: 0.95,
    techs: [['Kyocera Command Center', 'iot', 'RX', 0.95, [ev('header', 'header:Server', 'KM-MFP-http/V0.0.1'), ev('title', 'title', 'Kyocera Command Center RX')]]], classes: ['iot', 'admin-panel', 'login'], why: [['iot', 15, 'Urządzenie IoT (drukarka)'], ['admin-panel', 10, 'Panel konfiguracji urządzenia']] },
  camHik: { port: 80, name: 'http', product: 'Hikvision webs', title: '', status: 200, server: 'App-webs/', conf: 0.9, redirect: '/doc/page/login.asp', favicon: 999357577,
    techs: [['Hikvision IP Camera', 'iot', '', 0.96, [ev('favicon', 'favicon:mmh3', '999357577'), ev('header', 'header:Server', 'App-webs/'), ev('path', 'path:/doc/page/login.asp', '200')]]], classes: ['iot', 'login'], why: [['iot', 15, 'Urządzenie IoT (kamera)'], ['login', 10, 'Strona logowania']] },
  camAxis: { port: 443, name: 'http', tls: true, cert: 'self', product: 'Apache httpd', title: 'AXIS P3245-V Network Camera', status: 200, server: 'Apache', conf: 0.9,
    techs: [['AXIS Network Camera', 'iot', 'P3245-V', 0.94, [ev('title', 'title', 'AXIS P3245-V Network Camera')]]], classes: ['iot', 'login'], why: [['iot', 15, 'Urządzenie IoT (kamera)'], ['self-signed-cert', 10, 'Certyfikat samopodpisany']] },
  mikrotik: { port: 80, name: 'http', product: 'MikroTik router config httpd', title: 'RouterOS router configuration page', status: 200, conf: 0.95, favicon: 1924358485,
    techs: [['MikroTik RouterOS', 'iot', '6.49.10', 0.97, [ev('title', 'title', 'RouterOS router configuration page'), ev('favicon', 'favicon:mmh3', '1924358485'), ev('body', 'body', 'RouterOS v6.49.10')]]],
    classes: ['iot', 'admin-panel', 'login'], why: [['iot', 15, 'Urządzenie sieciowe'], ['admin-panel', 20, 'Panel konfiguracji routera'], ['outdated', 15, 'RouterOS 6.49.10 (gałąź bez wsparcia)']] },
  tplink: { port: 80, name: 'http', product: 'TP-LINK router http config', title: 'TL-WR841N', status: 200, server: 'Router Webserver', conf: 0.9,
    techs: [['TP-Link Router', 'iot', 'TL-WR841N', 0.9, [ev('title', 'title', 'TL-WR841N'), ev('header', 'header:Server', 'Router Webserver')]]], classes: ['iot', 'admin-panel', 'login'], why: [['iot', 15, 'Urządzenie sieciowe'], ['admin-panel', 20, 'Panel konfiguracji routera']] },
  synology: { port: 5001, name: 'http', tls: true, cert: 'self', product: 'nginx', title: 'Synology DiskStation', status: 200, server: 'nginx', conf: 0.93,
    techs: [['Synology DSM', 'iot', '7.2', 0.95, [ev('title', 'title', 'Synology DiskStation'), ev('body', 'body', 'SYNO.SDS.Session')]]], classes: ['iot', 'login', 'admin-panel'], why: [['iot', 15, 'Urządzenie NAS'], ['admin-panel', 15, 'Panel DSM'], ['self-signed-cert', 10, 'Certyfikat samopodpisany']] },
  unifi: { port: 8443, name: 'http', tls: true, cert: 'self', product: 'UniFi', title: 'UniFi Network', status: 200, conf: 0.92, redirect: '/manage/account/login',
    techs: [['UniFi Network', 'iot', '8.0', 0.92, [ev('title', 'title', 'UniFi Network')]]], classes: ['iot', 'login', 'admin-panel'], why: [['iot', 15, 'Kontroler sieci Wi-Fi'], ['admin-panel', 15, 'Panel zarządzania']] },
  switchWeb: { port: 80, name: 'http', product: 'HP ProCurve http config', title: 'HP 2530-48G Switch', status: 200, server: 'eHTTP v2.0', conf: 0.9,
    techs: [['HP ProCurve', 'iot', '2530', 0.9, [ev('header', 'header:Server', 'eHTTP v2.0'), ev('title', 'title', 'HP 2530-48G Switch')]]], classes: ['iot', 'admin-panel', 'login'], why: [['iot', 15, 'Urządzenie sieciowe'], ['admin-panel', 20, 'Panel zarządzania przełącznikiem']] },
};

// ---------- Hosts ----------
interface Arch { svcs: string[]; os: string; vendor?: string; label: string; tags: string[]; avail: 'always' | 'office' | 'evening' | 'flappy'; owner: string; crit: number }
const ARCH: Record<string, Arch> = {
  printerHp: { svcs: ['printerHp', 'ipp'], os: 'HP JetDirect', vendor: 'Hewlett Packard', label: 'Drukarka', tags: ['drukarka'], avail: 'always', owner: 'Dział Sieci', crit: 1 },
  printerKy: { svcs: ['printerKy', 'ipp'], os: 'Kyocera embedded', vendor: 'KYOCERA Display', label: 'Drukarka', tags: ['drukarka'], avail: 'always', owner: 'Dział Sieci', crit: 1 },
  camHik: { svcs: ['camHik', 'rtsp'], os: 'Linux 3.x (embedded)', vendor: 'Hangzhou Hikvision', label: 'Kamera', tags: ['kamera', 'monitoring'], avail: 'always', owner: 'Straż Uczelni', crit: 2 },
  camAxis: { svcs: ['camAxis'], os: 'Linux 4.x (embedded)', vendor: 'Axis Communications', label: 'Kamera', tags: ['kamera', 'monitoring'], avail: 'always', owner: 'Straż Uczelni', crit: 2 },
  switch: { svcs: ['switchWeb', 'sshOld'], os: 'HP ProCurve', vendor: 'Hewlett Packard', label: 'Przełącznik', tags: ['sieć'], avail: 'always', owner: 'Dział Sieci', crit: 4 },
  switchTelnet: { svcs: ['switchWeb', 'telnet'], os: 'Cisco IOS 12.x', vendor: 'Cisco Systems', label: 'Przełącznik', tags: ['sieć'], avail: 'always', owner: 'Dział Sieci', crit: 4 },
  workstation: { svcs: ['rdp', 'smb'], os: 'Microsoft Windows 11', vendor: 'Dell', label: 'Stacja robocza', tags: ['biuro'], avail: 'office', owner: '', crit: 2 },
  labLinux: { svcs: ['ssh'], os: 'Linux 6.x', vendor: 'Dell', label: 'Komputer laboratoryjny', tags: ['laboratorium'], avail: 'office', owner: '', crit: 2 },
  labWeb: { svcs: ['ssh', 'apacheDefault'], os: 'Linux 5.x', label: 'Serwer laboratoryjny', tags: ['laboratorium'], avail: 'always', owner: '', crit: 2 },
  nas: { svcs: ['synology', 'smb'], os: 'Synology DSM 7', vendor: 'Synology', label: 'NAS', tags: ['nas'], avail: 'always', owner: '', crit: 3 },
  unifi: { svcs: ['unifi', 'ssh'], os: 'Linux 5.x', vendor: 'Ubiquiti', label: 'Kontroler Wi-Fi', tags: ['sieć', 'wifi'], avail: 'always', owner: 'Dział Sieci', crit: 3 },
  dormRouterMt: { svcs: ['mikrotik', 'winbox'], os: 'MikroTik RouterOS 6.49', vendor: 'Routerboard.com', label: '', tags: ['akademik', 'router'], avail: 'always', owner: '', crit: 1 },
  dormRouterTp: { svcs: ['tplink'], os: 'TP-Link embedded', vendor: 'TP-Link Technologies', label: '', tags: ['akademik', 'router'], avail: 'evening', owner: '', crit: 1 },
  dormPc: { svcs: ['smb', 'rdp'], os: 'Microsoft Windows 10', label: '', tags: ['akademik'], avail: 'evening', owner: '', crit: 1 },
  dormVnc: { svcs: ['vnc'], os: 'Linux 6.x', label: '', tags: ['akademik'], avail: 'flappy', owner: '', crit: 1 },
  dormWeb: { svcs: ['nginxDefault', 'ssh'], os: 'Linux 6.x', label: '', tags: ['akademik'], avail: 'flappy', owner: '', crit: 1 },
  deptWp: { svcs: ['wp', 'ssh'], os: 'Linux 5.15', label: 'Strona wydziałowa', tags: ['www'], avail: 'always', owner: 'Centrum Informatyki', crit: 3 },
  deptNginx: { svcs: ['nginxDefault', 'ssh'], os: 'Linux 5.15', label: 'Serwer WWW', tags: ['www'], avail: 'always', owner: 'Centrum Informatyki', crit: 2 },
  deptIis: { svcs: ['iisDefault', 'rdp'], os: 'Microsoft Windows Server 2019', label: 'Serwer aplikacji', tags: ['www'], avail: 'always', owner: 'Centrum Informatyki', crit: 3 },
};

export interface FxHost extends Host { _avail: Arch['avail']; _block: number }
export const hosts: FxHost[] = [];
export const services: Service[] = [];
export const latest = new Map<number, ServiceResult>();
let hostId = 100;
let svcId = 1000;
const usedIp = new Set<string>();
const DEPTS = ['wggios', 'wimir', 'weaiib', 'wiet', 'wimic', 'wo', 'wmn', 'wgig', 'wz', 'wh', 'wfiis', 'wms', 'wnig', 'weip', 'bg', 'cok', 'swfis', 'sjo'];
const OWNERS = ['Centrum Informatyki', 'Dział Sieci', 'WIET — administratorzy', 'WIMiR — pracownia', 'Biblioteka Główna', 'Dział Rekrutacji', ''];

function certFor(kind: 'ca' | 'le' | 'self', cn: string, daysLeft: number): TLSInfo {
  const expired = daysLeft < 0;
  const issuer = kind === 'ca' ? 'GEANT OV RSA CA 4' : kind === 'le' ? "Let's Encrypt R11" : cn;
  const span = kind === 'le' ? 90 : kind === 'ca' ? 365 : 3650;
  return {
    version: kind === 'self' && chance(0.3) ? 'TLS 1.2' : 'TLS 1.3', cipher: 'TLS_AES_256_GCM_SHA384', subject_cn: cn, subject_org: kind === 'ca' ? 'Uczelnia' : '',
    sans: kind === 'self' ? [cn] : [cn, 'www.' + cn.replace(/^www\./, '')], issuer, not_before: iso(NOW + (daysLeft - span) * D), not_after: iso(NOW + daysLeft * D),
    serial: hex(32), sha256: hex(64), self_signed: kind === 'self', expired, days_left: daysLeft, host_mismatch: false, key_type: kind === 'self' ? 'RSA' : 'ECDSA', key_bits: kind === 'self' ? 2048 : 256,
  };
}

function addService(h: FxHost, key: string, o: Partial<Tpl> & { daysLeft?: number; firstSeenDays?: number } = {}): Service {
  const t0: Tpl = { ...TPL[key], ...o };
  const hostname = h.hostnames?.[0] ?? '';
  const isHttp = t0.name === 'http';
  const scheme = t0.tls ? 'https' : 'http';
  const defaultPort = (t0.tls && t0.port === 443) || (!t0.tls && t0.port === 80);
  const url = isHttp ? scheme + '://' + (hostname || h.ip) + (defaultPort ? '' : ':' + t0.port) + '/' : '';
  const techs: Technology[] = (t0.techs ?? []).map(([name, category, version, confidence, evidence]) => ({ name, category, version, confidence, sources: evidence.map((e) => e.where.split(':')[0] === 'banner' ? 'nmap' : 'sig:' + name.toLowerCase().replace(/[^a-z0-9]+/g, '-')), cpe: '' }));
  const tls = t0.tls ? certFor(t0.cert ?? 'ca', hostname || h.ip, o.daysLeft ?? (t0.cert === 'le' ? int(18, 80) : t0.cert === 'self' ? int(400, 3000) : int(40, 330))) : null;
  const why: InterestReason[] = (t0.why ?? []).map(([code, points, text]) => ({ code, points, text }));
  if (tls?.expired) why.push({ code: 'expired-cert', points: 20, text: 'Certyfikat TLS wygasł ' + Math.abs(tls.days_left) + ' dni temu' });
  else if (tls && tls.days_left <= 14) why.push({ code: 'expiring-cert', points: 10, text: 'Certyfikat TLS wygasa za ' + tls.days_left + ' dni' });
  const scopeCrit = h._block >= 100 ? 5 : h._block >= 32 ? 2 : 3;
  if (scopeCrit >= 5 && why.length) why.push({ code: 'scope-criticality', points: 10, text: 'Zakres o krytyczności 5 (Serwerownia / DMZ)' });
  const cookies: Cookie[] = (t0.cookies ?? []).map((c) => {
    const [name, s, ho, ss] = c.split('|');
    return { name, domain: hostname || h.ip, path: '/', secure: s === 'S', http_only: ho === 'H', same_site: ss || '', value_len: int(26, 64), value_hash: hex(16) };
  });
  const headers: Record<string, string[]> = {};
  if (isHttp) {
    headers['Content-Type'] = ['text/html; charset=utf-8'];
    if (t0.server) headers['Server'] = [t0.server];
    if (t0.powered) headers['X-Powered-By'] = [t0.powered];
    for (const [k, v] of Object.entries(t0.headers ?? {})) headers[k] = [v.replace('HOST', hostname || h.ip)];
    if (cookies.length) headers['Set-Cookie'] = cookies.map((c) => c.name + '=…; Path=/' + (c.secure ? '; Secure' : '') + (c.http_only ? '; HttpOnly' : '') + (c.same_site ? '; SameSite=' + c.same_site : ''));
    headers['Date'] = [new Date(NOW - 9 * H).toUTCString()];
  }
  const matches: SigMatch[] = (t0.techs ?? []).filter((x) => x[4].some((e) => e.matcher !== 'banner')).map(([name, category, version, confidence, evidence]) => ({
    signature: name.toLowerCase().replace(/[^a-z0-9]+/g, '-'), name, category, version, confidence, interest: 0, classes: null, tags: null, evidence,
  }));
  const title = (t0.title ?? '').replace('Wydział – Uczelnia', (h.label || 'Wydział') + ' – Uczelnia');
  const first = NOW - (o.firstSeenDays ?? int(20, 190)) * D;
  const s: Service = {
    id: ++svcId, host_id: h.id, ip: h.ip, hostname, port: t0.port, proto: 'tcp', state: 'open', name: t0.name, product: t0.product ?? '', version: t0.version ?? '',
    banner: t0.banner ?? '', confidence: t0.conf ?? 0.9, tls: Boolean(t0.tls), title, http_status: isHttp ? t0.status ?? 200 : 0, url, technologies: techs,
    classes: t0.classes ?? [], interest: 0, interest_why: why, group_key: hashStr(key + '|' + (t0.title ?? '') + '|' + (t0.product ?? '')), group_size: 1, note: '', tags: [],
    first_seen: iso(first), last_seen: iso(lastRunAt), last_changed: null, overrides: {},
  };
  s.interest = Math.min(100, why.reduce((a, r) => a + r.points, 0));
  services.push(s);
  latest.set(s.id, {
    port: s.port, proto: 'tcp', state: 'open', name: s.name, product: s.product, version: s.version, extra_info: '', cpe: [], banner: s.banner, tunnel: s.tls ? 'ssl' : '', confidence: s.confidence,
    http: isHttp ? {
      scheme, url, final_url: t0.redirect ? url.replace(/\/$/, '') + t0.redirect : url, host: hostname || h.ip, status: s.http_status, title, headers, cookies,
      redirects: t0.redirect ? [{ from: url, to: url.replace(/\/$/, '') + t0.redirect, status: 302 }] : (t0.tls && t0.port === 443 ? [{ from: url.replace('https:', 'http:'), to: url, status: 301 }] : []),
      server: t0.server ?? '', powered_by: t0.powered ?? '', meta_generator: t0.gen ?? '', body_length: int(1800, 96000), body_sha256: hex(64), body_simhash: hex(16),
      body_excerpt: '<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"><title>' + title + '</title>' + (t0.gen ? '<meta name="generator" content="' + t0.gen + '">' : ''),
      favicon_mmh3: t0.favicon ?? null, favicon_sha256: t0.favicon ? hex(64) : '',
      paths: (t0.paths ?? []).map(([path, status, ptitle]) => ({ path, status, title: ptitle, length: int(300, 9000), body_sha256: hex(64), excerpt: '', headers: null, location: status === 302 ? path + 'login/' : '' })),
      response_ms: int(18, 420), error: '',
    } : null,
    tls, matches, technologies: techs, classes: s.classes,
  });
  return s;
}

const PATTERN: Record<Arch['avail'], string> = {
  always: 'aktywny całą dobę', office: 'zwykle aktywny pn–pt 07–17', evening: 'zwykle aktywny codziennie 16–02', flappy: 'odpowiada nieregularnie',
};
const lastRunAt = lastAt(22, 1) + 72 * 60_000;

function addHost(ip: string, block: number, archKey: string | null, o: { hostname?: string; label?: string; owner?: string; crit?: number; tags?: string[]; status?: HostStatus; svcs?: [string, (Partial<Tpl> & { daysLeft?: number; firstSeenDays?: number })?][]; os?: string; avail?: Arch['avail']; firstSeenDays?: number; note?: string } = {}): FxHost {
  usedIp.add(ip);
  const a: Arch = archKey ? ARCH[archKey] : { svcs: [], os: o.os ?? 'Linux 5.15', label: '', tags: [], avail: 'always', owner: 'Centrum Informatyki', crit: 3 };
  const avail = o.avail ?? a.avail;
  let status: HostStatus = o.status ?? 'up';
  if (!o.status) {
    if (avail === 'office') status = chance(0.16) ? 'expected-offline' : chance(0.04) ? 'unstable' : 'up';
    else if (avail === 'evening') status = chance(0.12) ? 'expected-offline' : chance(0.1) ? 'unstable' : chance(0.05) ? 'down' : 'up';
    else if (avail === 'flappy') status = chance(0.45) ? 'unstable' : chance(0.12) ? 'down' : 'up';
    else status = chance(0.012) ? 'down' : chance(0.01) ? 'unstable' : 'up';
  }
  const stability = avail === 'always' ? 0.97 + rnd() * 0.03 : avail === 'office' ? 0.34 + rnd() * 0.1 : avail === 'evening' ? 0.4 + rnd() * 0.12 : 0.35 + rnd() * 0.3;
  const misses = status === 'up' ? 0 : status === 'down' ? int(2, 6) : int(1, 3);
  const pAlive = status === 'up' ? 0.99 : status === 'down' ? 0.03 + rnd() * 0.14 : status === 'expected-offline' ? 0.86 + rnd() * 0.1 : 0.32 + rnd() * 0.4;
  const first = NOW - (o.firstSeenDays ?? int(25, 195)) * D;
  const h: FxHost = {
    id: ++hostId, ip, hostnames: o.hostname ? [o.hostname] : [], scope_ids: [block >= 100 ? 3 : block >= 32 ? 2 : 1], status, p_alive: pAlive, stability,
    consecutive_misses: misses, pattern: avail === 'flappy' ? 'odpowiada nieregularnie (' + Math.round(stability * 100) + '% prób)' : PATTERN[avail],
    first_seen: iso(first), last_seen: iso(lastRunAt), last_up: iso(status === 'up' ? lastRunAt : lastRunAt - misses * D), os_guess: o.os ?? a.os, mac: '', vendor: a.vendor ?? '',
    label: o.label ?? a.label, owner: o.owner ?? (a.owner || (block < 32 ? pick(OWNERS) : '')), criticality: o.crit ?? a.crit, note: o.note ?? '', tags: o.tags ?? [...a.tags], interest: 0, service_count: 0,
    open_ports: [], technologies: [], overrides: {}, source: 'scan', _avail: avail, _block: block,
  };
  hosts.push(h);
  const list: [string, (Partial<Tpl> & { daysLeft?: number; firstSeenDays?: number })?][] = o.svcs ?? a.svcs.map((k) => [k]);
  for (const [k, so] of list) addService(h, k, so);
  return h;
}

// DMZ: hand-written notable hosts (block index 100 = 10.30.4.0/24, 101 = 10.30.5.0/24)
addHost('10.30.4.10', 100, null, { hostname: 'www.uczelnia.example', label: 'Strona główna uczelni', crit: 5, tags: ['www', 'publiczne'], svcs: [['wp', { title: 'Uczelnia – strona główna' }], ['ssh']] });
addHost('10.30.4.11', 100, null, { hostname: 'moodle.uczelnia.example', label: 'Platforma e-learningowa', crit: 5, tags: ['e-learning', 'publiczne'], svcs: [['moodle'], ['ssh']] });
const hJenkins = addHost('10.30.4.20', 100, null, { hostname: 'jenkins.ci.uczelnia.example', label: 'Jenkins CI', owner: 'WIET — administratorzy', crit: 4, tags: ['ci', 'devops'], svcs: [['jenkins'], ['ssh']], note: 'Zgłoszone administratorom WIET 18.11, czekamy na ograniczenie dostępu do VPN.' });
addHost('10.30.4.21', 100, null, { hostname: 'gitlab.uczelnia.example', label: 'GitLab', crit: 4, tags: ['devops'], svcs: [['gitlab'], ['ssh']] });
addHost('10.30.4.30', 100, null, { hostname: 'grafana.noc.uczelnia.example', label: 'Monitoring NOC', owner: 'Dział Sieci', crit: 3, tags: ['monitoring'], svcs: [['grafana'], ['prometheus'], ['ssh']] });
const hStaging = addHost('10.30.4.42', 100, null, { hostname: 'staging.rekrutacja.uczelnia.example', label: 'Rekrutacja — środowisko testowe', owner: 'Dział Rekrutacji', crit: 4, tags: ['staging'], svcs: [['staging'], ['postgres', { firstSeenDays: 0 }], ['ssh']] });
addHost('10.30.4.50', 100, null, { hostname: 'poczta.uczelnia.example', label: 'Poczta', crit: 5, tags: ['poczta', 'publiczne'], svcs: [['roundcube'], ['smtp'], ['imaps']] });
addHost('10.30.4.53', 100, null, { hostname: 'ns1.uczelnia.example', label: 'DNS podstawowy', owner: 'Dział Sieci', crit: 5, tags: ['dns'], svcs: [['dns'], ['ssh']] });
addHost('10.30.4.54', 100, null, { hostname: 'ns2.uczelnia.example', label: 'DNS zapasowy', owner: 'Dział Sieci', crit: 5, tags: ['dns'], svcs: [['dns'], ['ssh']] });
const hPma = addHost('10.30.4.60', 100, null, { hostname: 'db-admin.wggios.uczelnia.example', label: 'Baza wydziałowa WGGiOŚ', owner: 'WGGiOŚ', crit: 4, tags: ['baza'], svcs: [['pma'], ['mysql'], ['sshOld']] });
addHost('10.30.4.70', 100, null, { hostname: 'chmura.uczelnia.example', label: 'Nextcloud', crit: 4, tags: ['publiczne'], svcs: [['nextcloud', { daysLeft: 9 }], ['ssh']] });
addHost('10.30.4.80', 100, null, { hostname: 'usos-api.uczelnia.example', label: 'USOS API', crit: 5, tags: ['api', 'publiczne'], svcs: [['api'], ['ssh']] });
const hBg = addHost('10.30.4.90', 100, null, { hostname: 'bg.uczelnia.example', label: 'Biblioteka Główna', owner: 'Biblioteka Główna', crit: 3, tags: ['www', 'publiczne'], svcs: [['wpOld', { daysLeft: 3 }], ['sshOld']] });
const hDziekanat = addHost('10.30.4.95', 100, null, { hostname: 'stary-dziekanat.uczelnia.example', label: 'Dziekanat (stary system)', crit: 3, tags: ['legacy'], svcs: [['tomcat'], ['apacheDefault'], ['sshOld']], os: 'Linux 3.10 (CentOS 7)' });
addHost('10.30.5.10', 101, null, { hostname: 'logi.uczelnia.example', label: 'Logi (Kibana)', owner: 'Dział Sieci', crit: 4, tags: ['monitoring'], svcs: [['kibana'], ['ssh']] });
addHost('10.30.5.20', 101, null, { hostname: 'zabbix.uczelnia.example', label: 'Zabbix', owner: 'Dział Sieci', crit: 4, tags: ['monitoring'], svcs: [['zabbix'], ['ssh']] });
addHost('10.30.5.30', 101, null, { hostname: 'pve1.uczelnia.example', label: 'Proxmox — węzeł 1', crit: 5, tags: ['wirtualizacja'], svcs: [['proxmox'], ['ssh']] });
addHost('10.30.5.31', 101, null, { hostname: 'pve2.uczelnia.example', label: 'Proxmox — węzeł 2', crit: 5, tags: ['wirtualizacja'], svcs: [['proxmox', { title: 'pve2 - Proxmox Virtual Environment' }], ['ssh']] });
addHost('10.30.5.40', 101, null, { hostname: 'ldap.uczelnia.example', label: 'Katalog LDAP', crit: 5, tags: ['tożsamość'], svcs: [['ldap'], ['ssh']] });
const hFtp = addHost('10.30.5.60', 101, null, { hostname: 'ftp.uczelnia.example', label: 'Publiczne FTP', crit: 2, tags: ['legacy', 'publiczne'], svcs: [['ftp'], ['dirlist'], ['ssh']] });
const hRedis = addHost('10.30.5.77', 101, null, { hostname: 'cache-usos.uczelnia.example', label: 'Cache USOS', crit: 4, tags: ['baza'], svcs: [['redis', { firstSeenDays: 0 }], ['ssh']], firstSeenDays: 40 });
const hOldCert = addHost('10.30.5.88', 101, null, { hostname: 'konferencje.uczelnia.example', label: 'Serwis konferencyjny', crit: 2, tags: ['www'], svcs: [['wp', { title: 'Konferencje Uczelni', cert: 'le', daysLeft: -12 }], ['ssh']] });

function freeIp(prefix: string): string {
  for (;;) {
    const ip = prefix + '.' + int(2, 250);
    if (!usedIp.has(ip)) return ip;
  }
}
// DMZ: departmental sites
for (let i = 0; i < DEPTS.length; i++) {
  const dept = DEPTS[i];
  const block = i % 2 === 0 ? 100 : 101;
  const kind = i % 5 === 3 ? 'deptNginx' : i % 7 === 5 ? 'deptIis' : 'deptWp';
  addHost(freeIp(block === 100 ? '10.30.4' : '10.30.5'), block, kind, { hostname: (kind === 'deptWp' ? 'www.' : 'srv.') + dept + '.uczelnia.example', label: (kind === 'deptWp' ? 'Strona ' : 'Serwer ') + dept.toUpperCase() });
}
// Campus: 32 blocks 10.20.0-31.x. Some blocks are dense, some empty.
const campusDensity = [22, 18, 4, 0, 16, 12, 0, 9, 20, 14, 3, 0, 0, 11, 7, 0, 15, 19, 8, 0, 2, 0, 13, 6, 10, 17, 0, 5, 0, 9, 4, 0];
const campusMix: [string, number][] = [['printerHp', 14], ['printerKy', 6], ['camHik', 9], ['camAxis', 4], ['switch', 7], ['switchTelnet', 2], ['workstation', 26], ['labLinux', 15], ['labWeb', 7], ['nas', 3], ['unifi', 2], ['deptNginx', 3]];
function weighted(mix: [string, number][]): string {
  const total = mix.reduce((a, m) => a + m[1], 0);
  let r = rnd() * total;
  for (const [k, w] of mix) { r -= w; if (r <= 0) return k; }
  return mix[0][0];
}
const BUILD = ['A1', 'A2', 'B1', 'B4', 'C2', 'C5', 'D8', 'D17', 'U2', 'S1'];
for (let b = 0; b < 32; b++) {
  for (let i = 0; i < campusDensity[b]; i++) {
    const k = weighted(campusMix);
    const ip = freeIp('10.20.' + b);
    const room = pick(BUILD) + '-' + int(1, 420);
    const hn = k.startsWith('printer') ? 'drukarka-' + room.toLowerCase() : k.startsWith('cam') ? 'kam-' + room.toLowerCase() : k.startsWith('switch') ? 'sw-' + room.toLowerCase() : k === 'workstation' ? 'pc-' + room.toLowerCase() : k === 'labLinux' ? 'lab-' + room.toLowerCase() : '';
    addHost(ip, b, k, { hostname: hn ? hn + '.kampus.uczelnia.example' : undefined, label: ARCH[k].label + (hn ? ' ' + room : '') });
  }
}
// Dorms: 16 blocks 10.20.32-47.x
const dormDensity = [9, 12, 7, 0, 10, 8, 11, 6, 0, 9, 13, 5, 8, 0, 7, 10];
const dormMix: [string, number][] = [['dormRouterMt', 20], ['dormRouterTp', 22], ['dormPc', 28], ['dormVnc', 8], ['dormWeb', 12], ['nas', 6]];
for (let b = 0; b < 16; b++) {
  for (let i = 0; i < dormDensity[b]; i++) {
    const k = weighted(dormMix);
    addHost(freeIp('10.20.' + (32 + b)), 32 + b, k, { label: '', tags: ['akademik', 'ds-' + (b + 1)] });
  }
}
// A few fixed cases the demo refers to
const hCamDown = hosts.find((h) => h.tags?.includes('kamera') && h.status === 'up')!;
hCamDown.status = 'down'; hCamDown.p_alive = 0.06; hCamDown.consecutive_misses = 2; hCamDown.last_up = iso(lastRunAt - 2 * D);

// Derived host fields and group sizes
const groupCount = new Map<string, number>();
for (const s of services) groupCount.set(s.group_key, (groupCount.get(s.group_key) ?? 0) + 1);
for (const s of services) {
  s.group_size = groupCount.get(s.group_key) ?? 1;
  if (s.group_size <= 2 && s.name === 'http' && s.interest_why) {
    s.interest_why.push({ code: 'rare-tech', points: 10, text: 'Rzadka w tej sieci (grupa ' + s.group_size + ' ' + (s.group_size === 1 ? 'usługi' : 'usług') + ')' });
    s.interest = Math.min(100, s.interest + 10);
  }
}
const newPg = services.find((s) => s.host_id === hStaging.id && s.port === 5432)!;
newPg.interest_why!.unshift({ code: 'new-exposure', points: 20, text: 'Nowa ekspozycja: port otwarty od ostatniego skanu' });
newPg.interest = Math.min(100, newPg.interest + 20);
const newRedis = services.find((s) => s.host_id === hRedis.id && s.port === 6379)!;
newRedis.interest_why!.unshift({ code: 'new-exposure', points: 20, text: 'Nowa ekspozycja: port otwarty od ostatniego skanu' });
newRedis.interest = Math.min(100, newRedis.interest + 20);
// One analyst override to show "observed X, analyst set Y"
const svcJenkins = services.find((s) => s.host_id === hJenkins.id && s.port === 8080)!;
svcJenkins.overrides = { product: { value: 'Jenkins', observed: 'Jetty', by: 'analyst@cbi.example', at: iso(NOW - 3 * D) } };
svcJenkins.product = 'Jenkins';
svcJenkins.tags = ['zgłoszone', 'wiet'];
svcJenkins.note = 'Panel widoczny bez logowania. Właściciel potwierdził, że to środowisko produkcyjne CI.';
hJenkins.overrides = { os_guess: { value: 'Ubuntu 22.04 LTS', observed: 'Linux 5.15', by: 'analyst@cbi.example', at: iso(NOW - 3 * D) } };
hJenkins.os_guess = 'Ubuntu 22.04 LTS';

export function recomputeHost(h: Host) {
  const list = services.filter((s) => s.host_id === h.id && s.state === 'open');
  h.service_count = list.length;
  h.open_ports = list.map((s) => s.port).sort((a, b) => a - b);
  h.technologies = [...new Set(list.flatMap((s) => (s.technologies ?? []).map((x) => x.name)))];
  h.interest = Math.min(100, Math.max(0, ...list.map((s) => s.interest)) + (h.status === 'unstable' ? 5 : 0));
}
for (const h of hosts) {
  recomputeHost(h);
  if (h.status === 'down') for (const s of services) if (s.host_id === h.id) s.state = 'unknown';
}

// ---------- Blocks ----------
export interface FxBlock { cidr: string; idx: number; hosts: number }
export const blocks: FxBlock[] = [];
for (let b = 0; b < 48; b++) blocks.push({ cidr: '10.20.' + b + '.0/24', idx: b, hosts: 0 });
blocks.push({ cidr: '10.30.4.0/24', idx: 100, hosts: 0 }, { cidr: '10.30.5.0/24', idx: 101, hosts: 0 });
for (const b of blocks) b.hosts = hosts.filter((h) => h._block === b.idx && (h.status === 'up' || h.status === 'unstable')).length;

// ---------- Runs ----------
const zeroStats = (): RunStats => ({ addresses_total: 0, addresses_done: 0, chunks_total: 0, chunks_done: 0, hosts_up: 0, services_open: 0, http_services: 0, packets_sent: 0, http_requests: 0, current_pps: 0, avg_pps: 0, elapsed_sec: 0, eta_sec: 0, retried: 0, errors: 0 });
const upHosts = hosts.filter((h) => h.status === 'up' || h.status === 'unstable').length;
const openSvcs = services.filter((s) => s.state === 'open').length;
const httpSvcs = services.filter((s) => s.state === 'open' && s.name === 'http').length;

export const runs: ScanRun[] = [];
function completedRun(id: number, profile: ScanProfile, startMs: number, durMin: number, addr: number, scale: number, summary: ScanRun['summary'], trigger = 'schedule'): ScanRun {
  const r: ScanRun = {
    id, profile_id: profile.id, profile_name: profile.name, status: 'completed', pause_reason: '', trigger, created_by: trigger === 'manual' ? 3 : null, created_at: iso(startMs - 2000),
    started_at: iso(startMs), finished_at: iso(startMs + durMin * 60_000), window_end: null, resume_at: null,
    stats: { ...zeroStats(), addresses_total: addr, addresses_done: addr, chunks_total: Math.round(addr / 640) + 2, chunks_done: Math.round(addr / 640) + 2, hosts_up: Math.round(upHosts * scale), services_open: Math.round(openSvcs * scale),
      http_services: Math.round(httpSvcs * scale), packets_sent: Math.round(addr * 61.4), http_requests: Math.round(httpSvcs * scale * 5.2), current_pps: 0, avg_pps: Math.round((addr * 61.4) / (durMin * 60)), elapsed_sec: durMin * 60, eta_sec: 0, retried: int(6, 19), errors: 0 },
    summary, error: '', import_file: '',
  };
  runs.push(r);
  return r;
}
const sum = (prev: number | null, a: number[]): ScanRun['summary'] => ({ prev_run_id: prev, hosts_new: a[0], hosts_gone: a[1], hosts_back: a[2], hosts_unstable: a[3], services_new: a[4], services_gone: a[5], services_changed: a[6], by_kind: null, findings_new: a[7] });
const ADDR = 12800;
// Older nightly runs for the trend
const nightly: number[] = [];
{
  let id = 20;
  for (let d = 13; d >= 3; d--) {
    const start = lastAt(22, 1, d - 1);
    completedRun(id, profiles[0], start, int(66, 78), ADDR, 0.9 + (13 - d) * 0.008 + rnd() * 0.01, sum(id === 20 ? null : nightly[nightly.length - 1], [int(0, 5), int(0, 4), int(0, 3), int(0, 3), int(1, 9), int(0, 5), int(2, 12), int(0, 4)]));
    nightly.push(id);
    id += d % 3 === 0 ? 2 : 1;
  }
}
completedRun(36, profiles[1], NOW - 62 * H, 6, 518, 0.16, sum(34, [0, 0, 0, 0, 1, 0, 2, 0]));
runs.push({ id: 37, profile_id: null, profile_name: 'Import: dmz-audyt-2026-11.xml', status: 'completed', pause_reason: '', trigger: 'import', created_by: 2, created_at: iso(NOW - 58 * H), started_at: iso(NOW - 58 * H), finished_at: iso(NOW - 58 * H + 4000), window_end: null, resume_at: null,
  stats: { ...zeroStats(), addresses_total: 512, addresses_done: 512, hosts_up: 61, services_open: 148, http_services: 52 }, summary: sum(36, [2, 0, 0, 0, 5, 0, 3, 1]), error: '', import_file: 'dmz-audyt-2026-11.xml' });
completedRun(38, profiles[0], lastAt(22, 1, 1), 71, ADDR, 0.985, sum(nightly[nightly.length - 1], [2, 3, 1, 2, 4, 2, 9, 2]));
nightly.push(38);
completedRun(39, profiles[1], NOW - 30 * H, 6, 518, 0.16, sum(36, [0, 0, 0, 0, 0, 1, 1, 0]));
// #40: a weekend run of the dorms cut by its window. Half of the chunks are deferred.
runs.push({ id: 40, profile_id: 3, profile_name: profiles[2].name, status: 'paused', pause_reason: 'window_closed', trigger: 'schedule', created_by: null, created_at: iso(NOW - 4 * D), started_at: iso(NOW - 4 * D), finished_at: null,
  window_end: iso(NOW - 4 * D + 6 * H), resume_at: iso(NOW + 5 * D),
  stats: { ...zeroStats(), addresses_total: 4096, addresses_done: 2304, chunks_total: 9, chunks_done: 5, hosts_up: 71, services_open: 143, http_services: 58, packets_sent: 23_100_000, http_requests: 301, current_pps: 0, avg_pps: 1071, elapsed_sec: 6 * 3600 - 140, eta_sec: 4 * 3600 + 900, retried: 12, errors: 0 },
  summary: null, error: '', import_file: '' });
completedRun(41, profiles[0], lastAt(22, 1, 0), 72, ADDR, 1, sum(38, [4, 3, 2, 3, 6, 3, 19, 5]));
nightly.push(41);
runs.push({ id: 35, profile_id: 2, profile_name: profiles[1].name, status: 'failed', pause_reason: '', trigger: 'schedule', created_by: null, created_at: iso(NOW - 66 * H), started_at: iso(NOW - 66 * H), finished_at: iso(NOW - 66 * H + 9000), window_end: null, resume_at: null,
  stats: { ...zeroStats(), addresses_total: 518, chunks_total: 2, errors: 1 }, summary: null, error: 'nmap: zakończył się kodem 1: "You requested a scan type which requires root privileges." Uruchom czujkę z CAP_NET_RAW albo wyłącz skan SYN w profilu.', import_file: '' });
runs.push({ id: 34, profile_id: 2, profile_name: profiles[1].name, status: 'cancelled', pause_reason: '', trigger: 'manual', created_by: 2, created_at: iso(NOW - 70 * H), started_at: iso(NOW - 70 * H), finished_at: iso(NOW - 70 * H + 95_000), window_end: null, resume_at: null,
  stats: { ...zeroStats(), addresses_total: 518, addresses_done: 256, chunks_total: 2, chunks_done: 1, hosts_up: 31, services_open: 77, http_services: 30, packets_sent: 21000, avg_pps: 221, elapsed_sec: 95 }, summary: null, error: '', import_file: '' });

// #42: the live run. Chunks are planned density-first with adaptive sizes.
export const chunksByRun = new Map<number, Chunk[]>();
export const mapByRun = new Map<number, MapBlock[]>();
let chunkId = 5000;
function planChunks(runId: number, list: FxBlock[], sizes: number[]): Chunk[] {
  const ordered = [...list].sort((a, b) => b.hosts - a.hosts || a.idx - b.idx);
  const out: Chunk[] = [];
  let i = 0, seq = 0;
  while (i < ordered.length) {
    const n = Math.max(1, Math.round(sizes[Math.min(seq, sizes.length - 1)] / 256));
    const part = ordered.slice(i, i + n);
    i += n;
    out.push({ id: ++chunkId, run_id: runId, seq: ++seq, spec: part.map((b) => b.cidr), size: part.length * 256, priority: Math.max(...part.map((b) => b.hosts)) > 0 ? 100 - seq : 10, status: 'pending', started_at: null, finished_at: null, duration_ms: 0, hosts_up: 0, pps: 0, error: '' });
  }
  return out;
}
const hostsIn = (c: Chunk) => c.spec.reduce((a, cidr) => a + (blocks.find((b) => b.cidr === cidr)?.hosts ?? 0), 0);

export const liveRun: ScanRun = {
  id: 42, profile_id: 1, profile_name: profiles[0].name, status: 'running', pause_reason: '', trigger: 'manual', created_by: 3, created_at: iso(NOW - 19 * 60_000), started_at: iso(NOW - 19 * 60_000 + 3000),
  finished_at: null, window_end: null, resume_at: null, stats: { ...zeroStats(), addresses_total: ADDR, chunks_total: 0 }, summary: null, error: '', import_file: '',
};
runs.push(liveRun);
{
  const cs = planChunks(42, blocks, [256, 256, 256, 512, 512, 512, 768, 768, 1024, 1024, 1024, 1024, 1280]);
  chunksByRun.set(42, cs);
  liveRun.stats.chunks_total = cs.length;
  let t0 = NOW - 19 * 60_000 + 3000;
  const doneN = Math.floor(cs.length * 0.36);
  for (let i = 0; i < cs.length; i++) {
    const c = cs[i];
    if (i < doneN) {
      const dur = int(62, 118) * 1000;
      c.status = 'done'; c.started_at = iso(t0); c.finished_at = iso(t0 + dur); c.duration_ms = dur; c.hosts_up = hostsIn(c); c.pps = int(690, 800);
      t0 += Math.round(dur / 2);
    } else if (i < doneN + 2) {
      c.status = 'running'; c.started_at = iso(NOW - int(20, 60) * 1000); c.pps = int(350, 400);
    }
  }
}
// #40 chunks: dorm blocks, the second half deferred
{
  const cs = planChunks(40, blocks.filter((b) => b.idx >= 32 && b.idx < 48), [256, 256, 512, 512, 512, 512, 512, 512, 512]);
  cs.forEach((c, i) => {
    if (i < 5) { c.status = 'done'; c.duration_ms = int(3600, 4700) * 1000; c.hosts_up = hostsIn(c); c.pps = int(1000, 1120); c.started_at = iso(NOW - 4 * D + i * 70 * 60_000); c.finished_at = iso(NOW - 4 * D + (i + 1) * 70 * 60_000); }
    else c.status = 'deferred';
  });
  chunksByRun.set(40, cs);
}
function doneChunks(runId: number, list: FxBlock[], start: string | null) {
  const cs = planChunks(runId, list, [256, 256, 512, 512, 768, 1024, 1024, 1280, 1280]);
  let t0 = start ? new Date(start).getTime() : NOW;
  for (const c of cs) {
    const dur = Math.round((c.size / 256) * int(74, 96) * 1000 * 0.92);
    c.status = 'done'; c.duration_ms = dur; c.started_at = iso(t0); c.finished_at = iso(t0 + dur); c.hosts_up = hostsIn(c); c.pps = int(700, 800);
    t0 += Math.round(dur / 2);
  }
  chunksByRun.set(runId, cs);
}
doneChunks(41, blocks, runs.find((r) => r.id === 41)!.started_at);
doneChunks(38, blocks, runs.find((r) => r.id === 38)!.started_at);
doneChunks(39, blocks.filter((b) => b.idx >= 100), runs.find((r) => r.id === 39)!.started_at);

export function mapFor(runId: number): MapBlock[] {
  if (runId === 9001) return scaleMap();
  const cs = chunksByRun.get(runId);
  if (!cs) {
    const run = runs.find((r) => r.id === runId);
    const list = run?.profile_id === 2 ? blocks.filter((b) => b.idx >= 100) : run?.profile_id === 3 ? blocks.filter((b) => b.idx >= 32 && b.idx < 48) : blocks;
    return list.map((b) => ({ cidr: b.cidr, size: 256, status: run?.status === 'completed' ? 'done' : 'pending', hosts_up: run?.status === 'completed' ? b.hosts : 0 }));
  }
  const out: MapBlock[] = [];
  for (const c of cs) for (const cidr of c.spec) out.push({ cidr, size: 256, status: c.status, hosts_up: c.status === 'done' ? blocks.find((b) => b.cidr === cidr)?.hosts ?? 0 : 0 });
  return out;
}
// Synthetic scale check for the map (three /16 networks, 768 blocks). Reachable only by URL /runs/9001.
let scaleCache: MapBlock[] | null = null;
function scaleMap(): MapBlock[] {
  if (scaleCache) return scaleCache;
  const r = mulberry32(7);
  const out: MapBlock[] = [];
  for (const net of ['172.16', '172.17', '172.18']) {
    for (let b = 0; b < 256; b++) {
      const done = net === '172.16' ? true : net === '172.17' ? b < 150 : false;
      const dense = Math.sin(b / 9) > 0.2;
      out.push({ cidr: net + '.' + b + '.0/24', size: 256, status: done ? 'done' : net === '172.17' && b < 156 ? 'running' : net === '172.18' && b > 200 ? 'deferred' : 'pending', hosts_up: done ? (dense ? Math.floor(r() * 40) : r() < 0.3 ? Math.floor(r() * 4) : 0) : 0 });
    }
  }
  scaleCache = out;
  return out;
}
export const scaleRun: ScanRun = { ...liveRun, id: 9001, profile_name: 'Test skali mapy (dane syntetyczne, 3 × /16)', status: 'paused', pause_reason: 'manual', stats: { ...zeroStats(), addresses_total: 196608, addresses_done: 104000, chunks_total: 96, chunks_done: 51, hosts_up: 3120, avg_pps: 4800, elapsed_sec: 5400, eta_sec: 4700 } };

// ---------- Changes ----------
export const changes: Change[] = [];
let changeId = 9000;
function chg(runId: number, prev: number, kind: ChangeKind, severity: Severity, h: Host, s: Service | null, summary: string, field = '', before: unknown = null, after: unknown = null, expected = false, acked = false): Change {
  const run = runs.find((r) => r.id === runId)!;
  const c: Change = { id: ++changeId, run_id: runId, prev_run_id: prev, at: run.finished_at ?? run.started_at ?? iso(NOW), kind, severity, host_id: h.id, ip: h.ip, service_id: s?.id ?? null, port: s?.port ?? 0, summary, field, before, after, expected,
    acked_by: acked ? 'm.kowal@cbi.example' : '', acked_at: acked ? iso(NOW - int(2, 30) * H) : null };
  changes.push(c);
  return c;
}
const svcOf = (h: Host, port?: number) => services.find((s) => s.host_id === h.id && (port === undefined || s.port === port)) ?? null;
const byArch = (pred: (h: FxHost) => boolean) => hosts.filter(pred);
function seedChanges(runId: number, prev: number, scale: number, acked: boolean) {
  const office = byArch((h) => h._avail === 'office');
  const evening = byArch((h) => h._avail === 'evening');
  const flappy = byArch((h) => h._avail === 'flappy' || h.status === 'unstable');
  const wps = hosts.filter((h) => h.technologies?.includes('WordPress'));
  const n = (x: number) => Math.max(1, Math.round(x * scale));
  if (runId === 41) {
    chg(runId, prev, 'service_new', 'high', hStaging, newPg, 'Nowy otwarty port 5432/tcp (PostgreSQL 14) na środowisku testowym rekrutacji', 'state', null, 'open');
    chg(runId, prev, 'service_new', 'high', hRedis, newRedis, 'Nowy otwarty port 6379/tcp (Redis 6.2.6)', 'state', null, 'open');
    chg(runId, prev, 'class_changed', 'high', hDziekanat, svcOf(hDziekanat, 8080), 'Usługa zaczęła odpowiadać jako panel administracyjny (Tomcat Manager, 401)', 'classes', ['default-page'], ['default-page', 'admin-panel']);
    chg(runId, prev, 'host_gone', 'medium', hCamDown, null, 'Kamera nie odpowiada w 2 kolejnych skanach; profil mówi, że działa całą dobę (p_alive 0,06)', 'status', 'up', 'down');
    chg(runId, prev, 'headers_changed', 'medium', hBg, svcOf(hBg, 443), 'Zniknął nagłówek Strict-Transport-Security', 'headers', 'Strict-Transport-Security: max-age=31536000', null);
    chg(runId, prev, 'status_changed', 'medium', hOldCert, svcOf(hOldCert, 443), 'Kod odpowiedzi zmienił się z 200 na 503', 'http_status', 200, 503);
    chg(runId, prev, 'tech_version', 'low', hJenkins, svcJenkins, 'Jenkins 2.426.2 → 2.426.3', 'version', '2.426.2', '2.426.3');
    chg(runId, prev, 'cookies_changed', 'low', hStaging, svcOf(hStaging, 8000), 'Ciasteczko sessionid utraciło flagę Secure', 'cookies', 'sessionid; Secure; HttpOnly', 'sessionid; HttpOnly');
    chg(runId, prev, 'redirect_changed', 'low', hFtp, svcOf(hFtp, 80), 'Przekierowanie / → /pub/ zostało usunięte', 'redirects', '/ → /pub/', null);
  }
  for (const h of wps.slice(0, n(5))) chg(runId, prev, 'tech_version', 'info', h, svcOf(h, 443), 'WordPress 6.4.2 → 6.4.3', 'version', '6.4.2', '6.4.3', false, acked);
  for (const h of wps.slice(5, 5 + n(2))) chg(runId, prev, 'cert_changed', 'info', h, svcOf(h, 443), 'Odnowiony certyfikat TLS (nowy numer seryjny, ten sam wystawca)', 'tls.serial', hex(16), hex(16), false, acked);
  for (const h of wps.slice(8, 8 + n(2))) chg(runId, prev, 'title_changed', 'low', h, svcOf(h, 443), 'Zmiana tytułu strony', 'title', 'Strona w przebudowie', svcOf(h, 443)?.title ?? '', false, acked);
  for (const h of evening.slice(0, n(3))) chg(runId, prev, 'host_new', 'low', h, null, 'Nowy host w sieci akademików (' + (h.vendor || h.os_guess) + ')', 'status', null, 'up', false, acked);
  for (const h of evening.slice(3, 3 + n(3))) chg(runId, prev, 'service_new', 'low', h, svcOf(h), 'Nowa usługa ' + (svcOf(h)?.port ?? '') + '/tcp', 'state', null, 'open', false, acked);
  for (const h of office.slice(0, n(9))) chg(runId, prev, 'host_gone', 'info', h, null, 'Host nie odpowiada; profil: ' + h.pattern + ', skan o 22:40', 'status', 'up', 'expected-offline', true, acked);
  for (const h of evening.slice(8, 8 + n(4))) chg(runId, prev, 'service_gone', 'info', h, svcOf(h), 'Usługa niewidoczna, host poza zwykłymi godzinami aktywności', 'state', 'open', 'unknown', true, acked);
  for (const h of flappy.slice(0, n(3))) chg(runId, prev, 'host_unstable', 'low', h, null, 'Host odpowiada nieregularnie: ' + Math.round(h.stability * 100) + '% prób w ostatnich 14 dniach', 'status', 'up', 'unstable', false, acked);
  for (const h of flappy.slice(4, 4 + n(2))) chg(runId, prev, 'host_back', 'info', h, null, 'Host znów odpowiada po ' + int(2, 5) + ' nieudanych próbach', 'status', 'down', 'up', false, acked);
  for (const h of byArch((x) => x.tags?.includes('drukarka') ?? false).slice(0, n(2))) chg(runId, prev, 'service_gone', 'low', h, svcOf(h, 631), 'Port 631/tcp (IPP) zamknięty', 'state', 'open', 'gone', false, acked);
  for (const h of byArch((x) => x._avail === 'always' && x._block < 32).slice(3, 3 + n(2))) chg(runId, prev, 'content_changed', 'info', h, svcOf(h), 'Treść strony różni się istotnie (odległość simhash 19)', 'body_simhash', hex(16), hex(16), false, acked);
  for (const h of byArch((x) => x.tags?.includes('sieć') ?? false).slice(0, n(2))) chg(runId, prev, 'service_changed', 'low', h, svcOf(h, 22), 'Zmiana banera SSH', 'banner', 'SSH-2.0-OpenSSH_7.2', 'SSH-2.0-OpenSSH_7.4', false, acked);
}
seedChanges(38, nightly[nightly.length - 3], 0.7, true);
seedChanges(39, 36, 0.2, true);
seedChanges(41, 38, 1, false);
changes.sort((a, b) => b.id - a.id);
for (const r of runs) {
  if (!r.summary) continue;
  const list = changes.filter((c) => c.run_id === r.id);
  if (list.length === 0) continue;
  const by: Record<string, number> = {};
  for (const c of list) by[c.kind] = (by[c.kind] ?? 0) + 1;
  const cnt = (k: ChangeKind, exp = false) => list.filter((c) => c.kind === k && c.expected === exp).length;
  r.summary = { ...r.summary, by_kind: by, hosts_new: cnt('host_new'), hosts_gone: cnt('host_gone'), hosts_back: cnt('host_back'), hosts_unstable: cnt('host_unstable'), services_new: cnt('service_new'), services_gone: cnt('service_gone'),
    services_changed: list.filter((c) => !['host_new', 'host_gone', 'host_back', 'host_unstable', 'service_new', 'service_gone'].includes(c.kind)).length };
}

// ---------- Findings ----------
export const findings: Finding[] = [];
let findingId = 300;
function fnd(type: string, severity: Severity, title: string, description: string, s: Service | null, h: Host, o: Partial<Finding> = {}): Finding {
  const lr = latest.get(s?.id ?? -1);
  const evidence: Evidence[] = o.evidence ?? (lr?.matches?.[0]?.evidence ?? []).slice(0, 3);
  const f: Finding = {
    id: ++findingId, key: type + ':' + h.ip + ':' + (s?.port ?? 0), type, title, description, severity, status: 'new', interest: s?.interest ?? h.interest, host_id: h.id, ip: h.ip, service_id: s?.id ?? null, port: s?.port ?? 0,
    url: s?.url ?? '', signature: lr?.matches?.[0]?.signature ?? '', evidence, note: '', tags: [], assignee: '', first_seen: s?.first_seen ?? h.first_seen, last_seen: iso(lastRunAt), first_run_id: 38, last_run_id: 41,
    overrides: {}, dojo_id: null, dojo_url: '', manual: false, ...o,
  };
  findings.push(f);
  return f;
}
fnd('admin-panel', 'high', 'Jenkins: panel dostępny bez logowania', 'Strona główna Jenkinsa odpowiada kodem 200 i tytułem „Dashboard [Jenkins]” bez przekierowania na /login. Czujka nie próbowała logowania ani żadnej akcji.', svcJenkins, hJenkins,
  { status: 'triaged', assignee: 'analyst@cbi.example', tags: ['zgłoszone', 'wiet'], note: 'Zgłoszone 18.11, ticket SOC-2291.', dojo_id: 1184, dojo_url: 'https://defectdojo.cbi.example/finding/1184', first_run_id: 29 });
fnd('new-exposure', 'high', 'Nowo wystawiony PostgreSQL na środowisku testowym', 'Port 5432/tcp jest otwarty od skanu #41. Host jest oznaczony jako środowisko testowe systemu rekrutacji.', newPg, hStaging, { first_run_id: 41, first_seen: iso(lastRunAt) });
fnd('new-exposure', 'high', 'Nowo wystawiony Redis', 'Port 6379/tcp jest otwarty od skanu #41. Baner wskazuje Redis 6.2.6.', newRedis, hRedis, { first_run_id: 41, first_seen: iso(lastRunAt) });
fnd('staging', 'high', 'Środowisko testowe widoczne z sieci kampusowej', 'Tytuł strony zaczyna się od [STAGING], nagłówek X-Environment ma wartość staging, a /admin/ prowadzi do panelu Django.', svcOf(hStaging, 8000), hStaging, { assignee: 'm.kowal@cbi.example', status: 'triaged' });
fnd('admin-panel', 'high', 'phpMyAdmin dostępny z sieci', 'Panel phpMyAdmin 5.2.1 z certyfikatem samopodpisanym. Na tym samym hoście otwarty port MySQL 3306.', svcOf(hPma, 443), hPma);
fnd('expired-cert', 'medium', 'Wygasły certyfikat TLS', 'Certyfikat dla konferencje.uczelnia.example wygasł 12 dni temu.', svcOf(hOldCert, 443), hOldCert, { evidence: [ev('tls', 'tls:not_after', 'wygasł 12 dni temu'), ev('tls', 'tls:issuer', "Let's Encrypt R11")] });
fnd('outdated', 'medium', 'Przestarzały WordPress 5.8.2 na PHP 7.4', 'Wersja odczytana z meta generator. Gałąź 5.8 nie otrzymuje poprawek bezpieczeństwa.', svcOf(hBg, 443), hBg, { tags: ['biblioteka'] });
fnd('admin-panel', 'medium', 'Tomcat Manager odpowiada na starym systemie dziekanatu', 'Ścieżka /manager/html zwraca 401 z realm „Tomcat Manager Application”. Strona główna to domyślna strona Tomcat 9.0.83.', svcOf(hDziekanat, 8080), hDziekanat);
fnd('interesting-cookie', 'medium', 'Ciasteczko sesji bez flagi Secure', 'Ciasteczko sessionid jest ustawiane bez flagi Secure na usłudze z formularzem logowania.', svcOf(hStaging, 8000), hStaging, { evidence: [ev('cookie', 'cookie:sessionid', 'sessionid=…; HttpOnly; SameSite=Lax')] });
fnd('directory-listing', 'medium', 'Listing katalogu /pub', 'Serwer zwraca „Index of /pub” z listą plików.', svcOf(hFtp, 80), hFtp, { evidence: [ev('title', 'title', 'Index of /pub')], status: 'accepted', note: 'Publiczne repozytorium materiałów, zaakceptowane przez właściciela.', assignee: 'm.kowal@cbi.example' });
for (const s of services.filter((x) => x.classes?.includes('dev-tool') && x.host_id !== hJenkins.id)) {
  const h = hosts.find((x) => x.id === s.host_id)!;
  fnd('dev-tool', s.interest >= 40 ? 'medium' : 'low', (s.technologies?.[0]?.name ?? s.product) + ': narzędzie deweloperskie dostępne z sieci', 'Usługa rozpoznana po sygnaturze. Dostęp do niej warto ograniczyć do sieci administracyjnej.', s, h);
}
for (const s of services.filter((x) => x.tls && (latest.get(x.id)?.tls?.days_left ?? 99) <= 14 && (latest.get(x.id)?.tls?.days_left ?? 99) >= 0)) {
  const h = hosts.find((x) => x.id === s.host_id)!;
  const d = latest.get(s.id)!.tls!.days_left;
  fnd('expiring-cert', d <= 5 ? 'medium' : 'low', 'Certyfikat TLS wygasa za ' + d + ' dni', 'Certyfikat dla ' + (s.hostname || s.ip) + ' wygasa ' + new Date(latest.get(s.id)!.tls!.not_after).toLocaleDateString('pl-PL') + '.', s, h, { evidence: [ev('tls', 'tls:not_after', 'za ' + d + ' dni')] });
}
for (const s of services.filter((x) => x.port === 23)) {
  const h = hosts.find((x) => x.id === s.host_id)!;
  fnd('remote-access', 'medium', 'Telnet na przełączniku', 'Zarządzanie urządzeniem przez nieszyfrowany telnet.', s, h, { evidence: [ev('banner', 'banner', 'User Access Verification')] });
}
{
  const mt = services.filter((x) => x.technologies?.some((tc) => tc.name === 'MikroTik RouterOS')).slice(0, 9);
  for (const s of mt) fnd('outdated', 'low', 'MikroTik RouterOS 6.49.10 z panelem WWW', 'Router w sieci akademików z panelem konfiguracji i gałęzią RouterOS bez wsparcia.', s, hosts.find((x) => x.id === s.host_id)!, { status: chance(0.3) ? 'accepted' : 'new' });
  const cams = services.filter((x) => x.technologies?.some((tc) => tc.category === 'iot' && /Camera/.test(tc.name))).slice(0, 7);
  for (const s of cams) fnd('iot', 'low', 'Panel WWW kamery dostępny z sieci kampusowej', 'Kamera rozpoznana po hashu favicony i nagłówku Server.', s, hosts.find((x) => x.id === s.host_id)!, { status: chance(0.25) ? 'false_positive' : 'new' });
  const defaults = services.filter((x) => x.classes?.includes('default-page') && x.port === 80).slice(0, 6);
  for (const s of defaults) fnd('default-page', 'info', 'Domyślna strona serwera WWW', 'Serwer odpowiada stroną instalacyjną. Zwykle oznacza zapomniany lub nieskonfigurowany host.', s, hosts.find((x) => x.id === s.host_id)!, { status: chance(0.3) ? 'resolved' : 'new' });
  const vnc = services.filter((x) => x.port === 5900).slice(0, 4);
  for (const s of vnc) fnd('remote-access', 'low', 'VNC wystawione w sieci akademików', 'Baner RFB 003.008. Bez prób logowania.', s, hosts.find((x) => x.id === s.host_id)!);
}
fnd('manual', 'medium', 'Nieudokumentowany serwer w pawilonie C-2', 'Znaleziony podczas przeglądu szaf. Brak właściciela w ewidencji.', null, hosts.find((h) => h._block === 4)!, { manual: true, assignee: 'analyst@cbi.example', tags: ['inwentaryzacja'], status: 'triaged', first_run_id: 0, last_run_id: 0 });
findings.sort((a, b) => b.interest - a.interest || a.id - b.id);

// ---------- Signatures ----------
export const signatures: Signature[] = [];
let sigId = 0;
function yamlFor(slug: string, name: string, category: string, matchers: string[], extra = ''): string {
  return ['id: ' + slug, 'name: ' + name, 'category: ' + category, 'author: czujka', 'safe: true', extra, 'match:', '  any:', ...matchers.map((m) => '    - ' + m.split('\n').join('\n      '))].filter(Boolean).join('\n') + '\n';
}
function sig(slug: string, name: string, category: string, description: string, matchers: string[], o: Partial<Signature> & { extra?: string } = {}) {
  const count = services.filter((s) => s.technologies?.some((tc) => tc.name.toLowerCase() === name.toLowerCase())).length;
  signatures.push({ id: ++sigId, slug, name, category, description, yaml: yamlFor(slug, name, category, matchers, o.extra), enabled: true, builtin: true, author: 'czujka', tags: [category], interest: 0, match_count: count,
    created_at: iso(NOW - 200 * D), updated_at: iso(NOW - int(5, 90) * D), ...o });
}
sig('wordpress', 'WordPress', 'cms', 'CMS WordPress: meta generator, /wp-login.php, nagłówek Link, ciasteczko testowe', ["type: meta\nname: generator\nregex: 'WordPress ?([0-9.]+)?'\nversion: 1\nweight: 0.9", "type: path\npath: /wp-login.php\nstatus: 200\nbody_contains: 'user_login'\nweight: 0.8", "type: header\nname: Link\nregex: 'rel=\"https://api\\.w\\.org/\"'\nweight: 0.6", "type: cookie\nname: wordpress_test_cookie\nweight: 0.7"], { extra: 'classes: [login]\npaths: [/wp-login.php]' });
sig('moodle', 'Moodle', 'cms', 'Platforma e-learningowa Moodle', ["type: cookie\nname: MoodleSession\nweight: 0.8", "type: body\nregex: 'M\\.cfg = \\{\"wwwroot\"'\nweight: 0.7", "type: favicon\nmmh3: -438482901\nweight: 0.9"], { extra: 'classes: [login]' });
sig('jenkins', 'Jenkins', 'devops', 'Serwer CI Jenkins: nagłówek X-Jenkins z wersją', ["type: header\nname: X-Jenkins\nregex: '([0-9.]+)'\nversion: 1\nweight: 0.95", "type: title\nregex: '\\[Jenkins\\]$'\nweight: 0.6", "type: favicon\nmmh3: 81586312\nweight: 0.9"], { extra: 'classes: [dev-tool]\ninterest: 30' , interest: 30 });
sig('grafana', 'Grafana', 'devops', 'Panel Grafana: /api/health, ciasteczko grafana_session', ["type: path\npath: /api/health\nstatus: 200\nregex: '\"version\":\"([0-9.]+)\"'\nversion: 1\nweight: 0.9", "type: cookie\nname: grafana_session\nweight: 0.7"], { extra: 'classes: [dev-tool, login]\npaths: [/api/health]\ninterest: 20', interest: 20 });
sig('gitlab', 'GitLab', 'devops', 'GitLab: ciasteczko sesji i tytuł strony logowania', ["type: cookie\nname: _gitlab_session\nweight: 0.8", "type: title\nregex: 'GitLab$'\nweight: 0.5"], { extra: 'classes: [dev-tool, login]' });
sig('phpmyadmin', 'phpMyAdmin', 'panel', 'Panel administracyjny baz MySQL', ["type: title\nregex: '^phpMyAdmin'\nweight: 0.8", "type: cookie\nname: phpMyAdmin\nweight: 0.8", "type: body\nregex: 'PMA_VERSION:\"([0-9.]+)\"'\nversion: 1\nweight: 0.9"], { extra: 'classes: [admin-panel, login, database]\ninterest: 25', interest: 25 });
sig('nextcloud', 'Nextcloud', 'cms', 'Nextcloud: /status.php z wersją', ["type: path\npath: /status.php\nstatus: 200\nregex: '\"versionstring\":\"([0-9.]+)\"'\nversion: 1\nweight: 0.95"], { extra: 'paths: [/status.php]' });
sig('roundcube', 'Roundcube', 'cms', 'Poczta przez WWW Roundcube', ["type: cookie\nname: roundcube_sessid\nweight: 0.8", "type: title\nregex: 'Roundcube Webmail'\nweight: 0.7"]);
sig('apache-tomcat', 'Apache Tomcat', 'app-server', 'Domyślna strona Tomcat i odpowiedź /manager/html', ["type: title\nregex: '^Apache Tomcat/([0-9.]+)'\nversion: 1\nweight: 0.95", "type: path\npath: /manager/html\nstatus: 401\nheader: 'WWW-Authenticate'\nheader_contains: 'Tomcat Manager'\nweight: 0.9"], { extra: 'classes: [default-page]\npaths: [/manager/html]' });
sig('django-admin', 'Django', 'framework', 'Panel administracyjny Django pod /admin/', ["type: path\npath: /admin/login/\nstatus: 200\nbody_contains: 'csrfmiddlewaretoken'\nweight: 0.85", "type: cookie\nname: csrftoken\nweight: 0.4"], { extra: 'classes: [admin-panel, login]\npaths: [/admin/login/]' });
sig('staging-env', 'Staging', 'environment', 'Środowisko testowe: tytuł, nagłówek lub nazwa hosta', ["type: title\nregex: '(?i)\\[?(staging|test|dev|uat)\\]?'\nweight: 0.7", "type: header\nname: X-Environment\nregex: '(?i)staging|test|dev'\nweight: 0.8", "type: host\nregex: '(?i)^(staging|test|dev|uat)[.-]'\nweight: 0.6"], { extra: 'classes: [staging]\ninterest: 30', interest: 30 });
sig('kibana', 'Kibana', 'devops', 'Kibana: nagłówek kbn-name', ["type: header\nname: kbn-name\nweight: 0.9"], { extra: 'classes: [dev-tool]' });
sig('prometheus', 'Prometheus', 'devops', 'Prometheus: tytuł i /-/healthy', ["type: title\nregex: '^Prometheus Time Series'\nweight: 0.8", "type: path\npath: /-/healthy\nstatus: 200\nbody_contains: 'Prometheus'\nweight: 0.7"], { extra: 'classes: [dev-tool]\npaths: [/-/healthy]' });
sig('zabbix', 'Zabbix', 'panel', 'Zabbix: ciasteczko zbx_session', ["type: cookie\nname: zbx_session\nweight: 0.8", "type: title\nregex: '^Zabbix'\nweight: 0.5"], { extra: 'classes: [admin-panel, login]' });
sig('proxmox-ve', 'Proxmox VE', 'panel', 'Proxmox Virtual Environment', ["type: header\nname: Server\nregex: '^pve-api-daemon/([0-9.]+)'\nweight: 0.9", "type: title\nregex: 'Proxmox Virtual Environment'\nweight: 0.8"], { extra: 'classes: [admin-panel, login]' });
sig('hikvision-ip-camera', 'Hikvision IP Camera', 'iot', 'Kamera Hikvision: hash favicony i nagłówek Server', ["type: favicon\nmmh3: 999357577\nweight: 0.9", "type: header\nname: Server\nregex: '^App-webs/'\nweight: 0.6"], { extra: 'classes: [iot, login]\ninterest: 15', interest: 15 });
sig('axis-network-camera', 'AXIS Network Camera', 'iot', 'Kamera AXIS: tytuł strony', ["type: title\nregex: '^AXIS (\\S+) Network Camera'\nversion: 1\nweight: 0.9"], { extra: 'classes: [iot]' });
sig('mikrotik-routeros', 'MikroTik RouterOS', 'iot', 'Router MikroTik: strona konfiguracji i favicon', ["type: title\nregex: '^RouterOS router configuration page'\nweight: 0.8", "type: favicon\nmmh3: 1924358485\nweight: 0.9", "type: body\nregex: 'RouterOS v([0-9.]+)'\nversion: 1\nweight: 0.7"], { extra: 'classes: [iot, admin-panel]' });
sig('hp-laserjet', 'HP LaserJet', 'iot', 'Drukarka HP LaserJet: nagłówek Server', ["type: header\nname: Server\nregex: 'HP HTTP Server; HP LaserJet (?:Pro )?(\\S+)'\nversion: 1\nweight: 0.9"], { extra: 'classes: [iot]' });
sig('kyocera-command-center', 'Kyocera Command Center', 'iot', 'Drukarka Kyocera', ["type: header\nname: Server\nregex: '^KM-MFP-http'\nweight: 0.9"], { extra: 'classes: [iot]' });
sig('synology-dsm', 'Synology DSM', 'iot', 'NAS Synology DiskStation', ["type: title\nregex: 'Synology DiskStation'\nweight: 0.8", "type: body\nregex: 'SYNO\\.SDS\\.Session'\nweight: 0.7"], { extra: 'classes: [iot, login]' });
sig('unifi-network', 'UniFi Network', 'iot', 'Kontroler UniFi', ["type: title\nregex: '^UniFi Network'\nweight: 0.9"], { extra: 'classes: [iot, login]' });
sig('tp-link-router', 'TP-Link Router', 'iot', 'Router TP-Link', ["type: header\nname: Server\nregex: '^Router Webserver'\nweight: 0.6", "type: title\nregex: '^TL-[A-Z0-9]+'\nweight: 0.7"], { extra: 'classes: [iot, admin-panel]' });
sig('hp-procurve', 'HP ProCurve', 'iot', 'Przełącznik HP ProCurve', ["type: header\nname: Server\nregex: '^eHTTP v'\nweight: 0.7"], { extra: 'classes: [iot, admin-panel]' });
sig('nginx', 'nginx', 'web-server', 'Serwer WWW nginx', ["type: header\nname: Server\nregex: '^nginx(?:/([0-9.]+))?'\nversion: 1\nweight: 0.95"]);
sig('apache-http-server', 'Apache HTTP Server', 'web-server', 'Serwer WWW Apache', ["type: header\nname: Server\nregex: '^Apache(?:/([0-9.]+))?'\nversion: 1\nweight: 0.95"]);
sig('microsoft-iis', 'Microsoft IIS', 'web-server', 'Serwer WWW IIS', ["type: header\nname: Server\nregex: '^Microsoft-IIS/([0-9.]+)'\nversion: 1\nweight: 0.95"]);
sig('php', 'PHP', 'language', 'Wersja PHP z nagłówka X-Powered-By', ["type: header\nname: X-Powered-By\nregex: '^PHP/([0-9.]+)'\nversion: 1\nweight: 0.6"]);
sig('fastapi', 'FastAPI', 'framework', 'Dokumentacja Swagger pod /docs', ["type: path\npath: /docs\nstatus: 200\nbody_contains: 'swagger-ui'\nweight: 0.7"], { extra: 'classes: [api]\npaths: [/docs]' });
sig('header-missing-hsts', 'Brak HSTS', 'header', 'Strona HTTPS bez nagłówka Strict-Transport-Security', ["type: header_absent\nname: Strict-Transport-Security\nweight: 0.9"], { match_count: 61, enabled: true });
sig('cookie-no-secure', 'Ciasteczko sesji bez Secure', 'cookie', 'Ciasteczko o nazwie sesyjnej bez flagi Secure', ["type: cookie\nname_regex: '(?i)sess|sid|token'\nflag_absent: secure\nweight: 0.8"], { match_count: 23 });
sig('directory-listing', 'Listing katalogu', 'other', 'Tytuł „Index of /”', ["type: title\nregex: '^Index of /'\nweight: 0.9"], { extra: 'classes: [directory-listing]', match_count: 1 });
sig('drupal', 'Drupal', 'cms', 'CMS Drupal: nagłówek X-Generator', ["type: header\nname: X-Generator\nregex: '^Drupal ([0-9]+)'\nversion: 1\nweight: 0.9"], { enabled: false });
sig('joomla', 'Joomla', 'cms', 'CMS Joomla: meta generator', ["type: meta\nname: generator\nregex: '^Joomla'\nweight: 0.9"], { enabled: false });
signatures.push({ id: ++sigId, slug: 'usos-footer-version', name: 'USOSweb (wersja w stopce)', category: 'cms', description: 'Własna sygnatura CBI: wersja USOSweb w stopce strony', builtin: false, enabled: true, author: 'analyst@cbi.example', tags: ['cms', 'cbi'], interest: 5, match_count: 0,
  yaml: "id: usos-footer-version\nname: USOSweb\ncategory: cms\nauthor: analyst@cbi.example\nsafe: true\nmatch:\n  any:\n    - type: body\n      regex: 'USOSweb ([0-9.]+-[0-9]+)'\n      version: 1\n      weight: 0.9\n    - type: cookie\n      name: PHPSESSID\n      weight: 0.2\n", created_at: iso(NOW - 12 * D), updated_at: iso(NOW - 12 * D) });

// ---------- Audit log ----------
export const audit: AuditEntry[] = [];
let auditId = 70000;
export function addAudit(user: User | null, action: string, entity: string, entityId: string | number, detail: Record<string, unknown> = {}, at = Date.now()) {
  audit.unshift({ id: ++auditId, at: iso(at), user_id: user?.id ?? null, user_email: user?.email ?? '', action, entity, entity_id: String(entityId), detail, ip: '10.30.4.' + (200 + (user?.id ?? 0)) });
}
{
  const acts: [number, string, string, string, Record<string, unknown>][] = [
    [3, 'run.start', 'run', '42', { profile_id: 1 }], [3, 'auth.login', 'session', '', {}], [5, 'change.ack', 'change', 'bulk', { count: 14 }], [5, 'finding.update', 'finding', '304', { status: ['new', 'triaged'], assignee: 'm.kowal@cbi.example' }],
    [1, 'safety.update', 'safety', '', { max_pps: [1500, 1000] }], [2, 'import.results', 'run', '37', { file: 'dmz-audyt-2026-11.xml', hosts: 61 }], [3, 'service.update', 'service', String(svcJenkins.id), { product: ['Jetty', 'Jenkins'] }],
    [3, 'finding.export', 'defectdojo', '77', { exported: 1 }], [0, 'auth.login_failed', 'session', '', { email: 'admin@cbi.example' }], [2, 'target.create', 'scope', '3', { added: 3, source: 'json' }],
    [1, 'user.create', 'user', '6', { email: 'audyt@partner.example', role: 'audytor-zewnetrzny' }], [1, 'role.create', 'role', '5', { name: 'Audytor zewnętrzny' }], [3, 'signature.create', 'signature', 'usos-footer-version', {}],
    [2, 'profile.update', 'profile', '2', { 'rate.max_pps': [500, 300] }], [4, 'auth.login', 'session', '', {}], [1, 'user.update', 'user', '6', { disabled: [false, true] }], [2, 'run.cancel', 'run', '34', {}],
    [3, 'host.update', 'host', String(hJenkins.id), { os_guess: ['Linux 5.15', 'Ubuntu 22.04 LTS'] }], [5, 'export.run', 'export', 'findings.csv', { rows: 46 }], [1, 'defectdojo.test', 'settings', '', { ok: true }],
  ];
  acts.forEach(([uid, action, entity, id, detail], i) => addAudit(users.find((u) => u.id === uid) ?? null, action, entity, id, detail, NOW - (i * 2.7 + 0.3) * H));
  audit.reverse();
  audit.sort((a, b) => (a.at < b.at ? 1 : -1));
}

export const dojo: DefectDojoSettings = { enabled: true, url: 'https://defectdojo.cbi.example', api_key_set: true, product_name: 'Sieć uczelni', engagement_name: 'Czujka — skany cykliczne', product_type_name: 'Infrastruktura', verify_tls: true, auto_export: false, min_interest: 60 };

// ---------- Availability profiles ----------
export function availability(h: FxHost): AvailabilityProfile {
  const r = mulberry32(h.id * 7919);
  const buckets = [];
  for (let wd = 0; wd < 7; wd++) {
    for (let hr = 0; hr < 24; hr++) {
      let p = 0.97;
      if (h._avail === 'office') p = wd >= 1 && wd <= 5 && hr >= 7 && hr < 17 ? 0.93 : wd >= 1 && wd <= 5 && (hr === 6 || hr === 17) ? 0.4 : 0.03;
      else if (h._avail === 'evening') p = hr >= 16 || hr < 2 ? 0.88 : hr >= 12 ? 0.35 : 0.06;
      else if (h._avail === 'flappy') p = 0.25 + 0.5 * r();
      const n = h._avail === 'always' ? 6 + Math.floor(r() * 4) : r() < 0.08 ? 0 : 4 + Math.floor(r() * 6);
      let up = 0;
      for (let i = 0; i < n; i++) if (r() < p) up++;
      buckets.push({ up, down: n - up });
    }
  }
  const recent = [];
  for (let i = 0; i < 14; i++) {
    const missed = i < h.consecutive_misses || (h._avail !== 'always' && r() < 1 - h.stability);
    recent.push({ run_id: 41 - i, at: iso(lastRunAt - i * 12 * H), up: !missed, rtt_ms: missed ? 0 : Math.round((0.4 + r() * 18) * 10) / 10, attempts: missed ? 3 : r() < 0.1 ? 2 : 1, reason: missed ? 'no-response' : pick(['echo-reply', 'syn-ack', 'reset']) });
  }
  const need = h._avail === 'always' ? 2 : h._avail === 'flappy' ? 5 : h._avail === 'office' ? 4 : 4;
  return { host_id: h.id, buckets, recent, pattern: h.pattern, p_alive: h.p_alive, down_after_misses: Math.max(1, need - (h.status === 'down' ? need : h.consecutive_misses)) || need };
}

export function observations(s: Service): ServiceObservation[] {
  const base = latest.get(s.id)!;
  const ids = [41, 38, 33, 31, 30, 29, 27, 26, 24, 23];
  const firstMs = new Date(s.first_seen).getTime();
  const out: ServiceObservation[] = [];
  ids.forEach((rid, i) => {
    const run = runs.find((x) => x.id === rid);
    const at = run?.finished_at ? new Date(run.finished_at).getTime() : lastRunAt - i * D;
    if (at < firstMs - D) return;
    let result = base;
    if (i >= 2 && base.matches?.some((m) => m.name === 'WordPress' && m.version === '6.4.3')) {
      result = { ...base, technologies: base.technologies?.map((x) => (x.name === 'WordPress' ? { ...x, version: '6.4.2' } : x)) ?? null, http: base.http ? { ...base.http, meta_generator: 'WordPress 6.4.2' } : null };
    }
    if (i >= 1 && s.id === svcJenkins.id) result = { ...base, technologies: base.technologies?.map((x) => (x.name === 'Jenkins' ? { ...x, version: '2.426.2' } : x)) ?? null };
    out.push({ id: s.id * 100 + i, service_id: s.id, run_id: rid, at: iso(at), result });
  });
  return out;
}

export const meta = { lastRunAt, upHosts, nightly };
