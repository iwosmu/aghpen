import type { RunPass, ScanRun } from '../api/types';
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
    case 'done': return t('gotowy', 'done');
    case 'skipped': return t('pominięty', 'skipped');
    case 'pending': return t('oczekuje', 'pending');
    default: return p.ports_total > 0 ? fmtPct(Math.min(1, p.ports_done / p.ports_total)) : t('w toku', 'running');
  }
}

/**
 * While a staged run is still in a later pass, the result on screen is not
 * final: "Skan trwa: sprawdzono najczęstsze porty, pełny zakres w toku".
 * Changes and gone services come only when the run ends.
 */
export function partialText(run: Pick<ScanRun, 'status' | 'stats'>): string | null {
  const ps = run.stats.passes;
  if (!ps || ps.length < 2 || !['running', 'paused', 'queued'].includes(run.status)) return null;
  const done = ps.filter((p) => p.state === 'done' || p.state === 'skipped');
  const rest = ps.filter((p) => p.state === 'running' || p.state === 'pending');
  if (!done.some((p) => p.state === 'done') || rest.length === 0) return null;
  const cur = rest[0];
  const pct = cur.state === 'running' && cur.ports_total > 0 ? ' (' + fmtPct(Math.min(1, cur.ports_done / cur.ports_total)) + ')' : '';
  const doneText = done.filter((p) => p.state === 'done').map(passLabel).join(t(' i ', ' and '));
  return t('Skan trwa: sprawdzono ' + doneText + ', ' + passLabel(cur) + ' w toku' + pct + '.',
    'Scan in progress: ' + doneText + ' checked, ' + passLabel(cur) + ' running' + pct + '.');
}

export function PartialNote({ run, className }: { run: Pick<ScanRun, 'status' | 'stats'>; className?: string }) {
  const text = partialText(run);
  if (!text) return null;
  return <p className={cx('flex items-start gap-2 border-l-2 border-st-changed bg-raised px-2.5 py-1.5 text-sm text-ink', className)} data-testid="run-partial" role="status"><Glyph name="half" tone="changed" size={12} />{text}</p>;
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
