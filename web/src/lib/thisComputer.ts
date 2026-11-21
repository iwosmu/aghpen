// "Ten komputer": scan the machine Czujka runs on in one click.
// The UI always sends the target text 'localhost'. The server maps a loopback
// target to the docker host when Czujka runs in a container (Target.maps_to,
// /healthz host_gateway); the UI only shows that mapping, it never rewrites it.
import { get, post, ApiError } from '../api/client';
import type { Page, ScanProfile, ScanRun, Scope, TargetPreview } from '../api/types';
import { t } from '../i18n';

export const THIS_COMPUTER = 'localhost';

export function isLoopback(v: string): boolean {
  const s = v.trim().toLowerCase();
  return s === 'localhost' || s === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s);
}

/**
 * One plain line about what a loopback target is scanned as.
 * mapsTo: Target.maps_to from the server; gateway: /healthz host_gateway
 * (undefined: the server does not say; '': no mapping, loopback is this machine).
 */
export function loopbackLine(value: string, mapsTo?: string | null, gateway?: string | null): string | null {
  if (!isLoopback(value)) return null;
  if (mapsTo) return value + ' = ' + t('host Dockera', 'the Docker host') + ' ' + mapsTo;
  if (gateway === '') return value + ' = ' + t('ten komputer, na którym działa Czujka', 'this computer, where Czujka runs');
  if (gateway) return value + ' = ' + t('host Dockera', 'the Docker host') + ' ' + gateway;
  return null;
}

export const THIS_COMPUTER_SCOPE = () => t('Ten komputer', 'This computer');

/** The seeded default profile: the oldest one. */
export function defaultProfile(items: ScanProfile[]): ScanProfile | undefined {
  return [...items].sort((a, b) => a.id - b.id)[0];
}

/**
 * Creates (or reuses) the scope "Ten komputer" with the target 'localhost', a copy of the
 * seeded default profile for it, and starts a run. Returns the run id.
 */
export async function startThisComputer(): Promise<number> {
  const name = THIS_COMPUTER_SCOPE();
  const scopes = await get<Page<Scope>>('/scopes', { limit: 200 });
  let scope = scopes.items.find((s) => s.name === name);
  if (!scope) scope = await post<Scope>('/scopes', { name, description: t('Komputer, na którym działa Czujka', 'The computer Czujka runs on'), owner: '', criticality: 3, tags: [] });
  if (!scope.target_count) await post<TargetPreview>('/scopes/' + scope.id + '/targets', { text: THIS_COMPUTER });
  const profiles = await get<Page<ScanProfile>>('/profiles', { limit: 200 });
  let profile = profiles.items.find((p) => p.scope_ids.length === 1 && p.scope_ids[0] === scope!.id);
  if (!profile) {
    const base = defaultProfile(profiles.items);
    if (!base) throw new ApiError(409, 'no_profile', t('Brak profilu domyślnego. Utwórz profil.', 'No default profile. Create a profile.'));
    const { id: _i, next_run_at: _n, last_run_id: _l, created_at: _c, updated_at: _u, ...rest } = base;
    void _i; void _n; void _l; void _c; void _u;
    profile = await post<ScanProfile>('/profiles', {
      ...rest, name: name + ': ' + base.name, scope_ids: [scope.id],
      schedule: { ...base.schedule, enabled: false, cron: '', interval_minutes: 0, windows: [] },
    });
  }
  try {
    const run = await post<ScanRun>('/runs', { profile_id: profile.id });
    return run.id;
  } catch (e) {
    // The profile already has a scan in progress: open that one.
    const id = e instanceof ApiError && e.code === 'run_active' ? (e.details as { run_id?: number } | undefined)?.run_id : undefined;
    if (id) return id;
    throw e;
  }
}
