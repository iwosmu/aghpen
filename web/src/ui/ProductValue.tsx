import type { Technology } from '../api/types';
import { t } from '../i18n';
import { productLine, shownProduct } from '../lib/shownProduct';

/** The small mark after a product a signature recognised. */
export function FromSignature() {
  return <span className="ml-1.5 whitespace-nowrap font-sans text-2xs text-ink-3" data-testid="product-from-signature">{t('z sygnatury', 'from signature')}</span>;
}

/** Product and version for a table cell; a signature fills an empty product. */
export function ProductValue({ s, empty = '–' }: { s: { product: string; version: string; technologies: Technology[] | null }; empty?: string }) {
  const p = shownProduct(s);
  const line = productLine(p);
  if (!line) return <>{empty}</>;
  return <>{line}{p.fromSignature ? <FromSignature /> : null}</>;
}
