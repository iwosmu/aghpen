import type { Technology } from '../api/types';

/** Signature categories that name the application itself (not the web server, the language, a header or cookie rule). */
const APP_CATEGORIES = new Set(['panel', 'cms', 'devops', 'iot', 'security', 'database']);

export interface ShownProduct { product: string; version: string; fromSignature: boolean }

/**
 * The product to display for a service. The stored product wins; when it is
 * empty, the best application a signature recognised fills in (display only,
 * never written back). Highest confidence first, then the shortest name, so
 * "Jenkins" beats "Jenkins bez logowania".
 */
export function shownProduct(s: { product: string; version: string; technologies: Technology[] | null }): ShownProduct {
  if (s.product) return { product: s.product, version: s.version, fromSignature: false };
  const apps = (s.technologies ?? []).filter((t) => APP_CATEGORIES.has(t.category) && t.name);
  if (apps.length === 0) return { product: '', version: s.version, fromSignature: false };
  apps.sort((a, b) => b.confidence - a.confidence || a.name.length - b.name.length || a.name.localeCompare(b.name));
  const best = apps[0];
  return { product: best.name, version: best.version || s.version, fromSignature: true };
}

/** "Adminer 4.17.1", or "" when nothing is known. */
export function productLine(p: ShownProduct): string {
  return [p.product, p.version].filter(Boolean).join(' ');
}
