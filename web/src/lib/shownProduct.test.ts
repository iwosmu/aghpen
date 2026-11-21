import { describe, expect, it } from 'vitest';
import type { Technology } from '../api/types';
import { productLine, shownProduct } from './shownProduct';

const tech = (name: string, category: string, version = '', confidence = 99): Technology => ({ name, category, version, confidence, sources: null, cpe: '' });

describe('shownProduct', () => {
  it('keeps the stored product', () => {
    const p = shownProduct({ product: 'nginx', version: '1.26', technologies: [tech('Adminer', 'panel', '4.17.1')] });
    expect(p).toEqual({ product: 'nginx', version: '1.26', fromSignature: false });
  });

  it('fills an empty product from an application signature', () => {
    const p = shownProduct({ product: '', version: '', technologies: [tech('PHP', 'language', '8.4.24'), tech('X-Powered-By', 'header'), tech('Adminer', 'panel', '4.17.1')] });
    expect(p).toEqual({ product: 'Adminer', version: '4.17.1', fromSignature: true });
    expect(productLine(p)).toBe('Adminer 4.17.1');
  });

  it('ignores the web server, the language and header rules', () => {
    const p = shownProduct({ product: '', version: '', technologies: [tech('nginx', 'web-server', '1.26'), tech('PHP', 'language'), tech('HSTS', 'header')] });
    expect(p.fromSignature).toBe(false);
    expect(productLine(p)).toBe('');
  });

  it('prefers higher confidence, then the shorter name', () => {
    const p = shownProduct({ product: '', version: '', technologies: [tech('Jenkins bez logowania', 'devops'), tech('Jenkins', 'devops', '2.4'), tech('GitLab', 'devops', '', 60)] });
    expect(p.product).toBe('Jenkins');
  });
});
