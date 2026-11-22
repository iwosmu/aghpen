/**
 * A tab that was open during an upgrade still runs the old entry script, and
 * the page chunks that script names are gone from the server. The first
 * navigation to a page not yet loaded then fails with a chunk-load error.
 * The new build is one reload away, so reload once instead of showing the
 * fault. The time guard stops a loop when the chunk is missing for another
 * reason.
 */
const KEY = 'czujka.staleReloadAt';
const MIN_GAP_MS = 30_000;

const PATTERNS = [
  /importing a module script failed/i, // Safari
  /failed to fetch dynamically imported module/i, // Chromium
  /error loading dynamically imported module/i, // Firefox
  /unable to preload css/i, // Vite
  /is not a valid javascript mime type/i, // index.html served for a missing chunk
];

export function isStaleBuildError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : typeof err === 'string' ? err : '';
  return PATTERNS.some((p) => p.test(msg));
}

/** Reloads the page unless it already did so a moment ago. Returns true when a reload was started. */
export function reloadForNewBuild(now: number = Date.now(), store: Pick<Storage, 'getItem' | 'setItem'> = sessionStorage, reload: () => void = () => window.location.reload()): boolean {
  try {
    const last = Number(store.getItem(KEY)) || 0;
    if (now - last < MIN_GAP_MS) return false;
    store.setItem(KEY, String(now));
  } catch {
    return false; // no storage: cannot guard against a loop, so show the fault
  }
  reload();
  return true;
}

/** Vite fires this on window when a preloaded chunk or stylesheet of a dynamic import fails. */
export function installStaleBuildReload(): void {
  window.addEventListener('vite:preloadError', (e) => {
    if (reloadForNewBuild()) e.preventDefault();
  });
}
