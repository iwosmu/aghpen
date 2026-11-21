import type { RunPass } from '../api/types';
import { t, plural } from '../i18n';
import { cx, fmtInt, fmtPct } from '../lib/format';
import { Glyph } from './marks';

export function passLabel(p: RunPass): string {
  if (p.name === 'top_ports') return t('najczęstsze porty', 'top ports');
  if (p.name === 'full_range') return t('pełny zakres 1-65535', 'full range 1-65535');
  if (p.name === 'dense') return t('porty 1-10000 na ' + fmtInt(p.hosts) + ' ' + plural(p.hosts, ['hoście', 'hostach', 'hostach'], ['', '']), 'ports 1-10000 on ' + fmtInt(p.hosts) + ' ' + (p.hosts === 1 ? 'host' : 'hosts'));
  return p.name;
}

export function passState(p: RunPass): string {
  switch (p.state) {
    case 'done': return t('gotowe', 'done');
    case 'skipped': return t('pominięty', 'skipped');
    case 'pending': return t('czeka', 'waiting');
    default: return p.ports_total > 0 ? fmtPct(Math.min(1, p.ports_done / p.ports_total)) : t('w toku', 'running');
  }
}

/** "najczęstsze porty: gotowe · pełny zakres 1-65535: 32%": the port passes of a staged run. */
export function RunPasses({ passes, className }: { passes?: RunPass[] | null; className?: string }) {
  if (!passes || passes.length < 2) return null;
  return (
    <p className={cx('flex flex-wrap items-center gap-x-3 gap-y-1 text-sm', className)} data-testid="run-passes">
      {passes.map((p, i) => (
        <span key={p.name + i} className={cx('inline-flex items-center gap-1.5', p.state === 'pending' || p.state === 'skipped' ? 'text-ink-3' : 'text-ink')}>
          {i ? <span className="mr-1.5 text-ink-3" aria-hidden="true">·</span> : null}
          {p.state === 'done' ? <Glyph name="check" tone="new" size={12} /> : p.state === 'running' ? <span className="bar-active inline-block h-1.5 w-4" aria-hidden="true" /> : <Glyph name="ring" tone="expected" size={12} />}
          <span>{passLabel(p)}:</span><span className="num">{passState(p)}</span>
        </span>
      ))}
    </p>
  );
}
