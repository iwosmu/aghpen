import type { Service } from '../api/types';
import { t } from '../i18n';

/** Czujka's own UI on the scanned host carries this tag (the server adds it). */
export const SELF_TAG = 'czujka';

export function isSelf(s: { tags?: string[] | null }): boolean {
  return (s.tags ?? []).includes(SELF_TAG);
}

/**
 * The name a person reads for a service, never empty: the nmap service name, else the
 * product, else "nierozpoznana". short: product without version (for one-line stories).
 */
export function serviceName(s: Pick<Service, 'name' | 'product' | 'version'> & { tags?: string[] | null }, opts?: { short?: boolean }): string {
  const prod = s.product ? (opts?.short ? s.product : [s.product, s.version].filter(Boolean).join(' ')) : '';
  if (opts?.short) return prod || s.name || t('usługa nierozpoznana', 'unidentified service');
  return s.name || prod || t('nierozpoznana', 'unidentified');
}
