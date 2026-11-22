import { describe, expect, it } from 'vitest';
import { isStaleBuildError, reloadForNewBuild } from './staleBuild';

function fakeStore() {
  const m = new Map<string, string>();
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) };
}

describe('stale build after an upgrade', () => {
  it('recognises the chunk-load errors of Safari, Chromium, Firefox and Vite', () => {
    expect(isStaleBuildError(new Error('Importing a module script failed.'))).toBe(true);
    expect(isStaleBuildError(new TypeError('Failed to fetch dynamically imported module: https://x/assets/Changes-abc.js'))).toBe(true);
    expect(isStaleBuildError(new TypeError('error loading dynamically imported module'))).toBe(true);
    expect(isStaleBuildError(new Error('Unable to preload CSS for /assets/Changes-abc.css'))).toBe(true);
    expect(isStaleBuildError(new Error("Cannot read properties of undefined (reading 'items')"))).toBe(false);
    expect(isStaleBuildError(undefined)).toBe(false);
  });

  it('reloads once, then shows the fault instead of looping', () => {
    const store = fakeStore();
    let reloads = 0;
    const reload = () => void reloads++;
    expect(reloadForNewBuild(1_000_000, store, reload)).toBe(true);
    expect(reloadForNewBuild(1_005_000, store, reload)).toBe(false);
    expect(reloads).toBe(1);
    expect(reloadForNewBuild(1_040_000, store, reload)).toBe(true);
    expect(reloads).toBe(2);
  });

  it('does not reload when storage is unavailable', () => {
    let reloads = 0;
    const broken = { getItem: () => { throw new Error('denied'); }, setItem: () => {} };
    expect(reloadForNewBuild(1, broken, () => void reloads++)).toBe(false);
    expect(reloads).toBe(0);
  });
});
