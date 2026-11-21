import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { useAction, useItem } from '../api/hooks';
import { put } from '../api/client';
import type { ReprobePlan, ReprobeSettings } from '../api/types';
import { t } from '../i18n';
import { cx, fmtDateTime, fmtInt, fmtRelative } from '../lib/format';
import { routeMissing } from '../lib/route';
import { Button, Check, ErrorState, Field, InlineError, Panel, SkeletonRows, Unavailable } from '../ui/kit';
import { Icon } from '../ui/Icon';
import { useCan } from '../session';

function ports(p: number[] | string | null): string {
  if (!p) return '';
  return Array.isArray(p) ? p.slice(0, 6).join(',') + (p.length > 6 ? '…' : '') : p;
}

function SettingsForm({ s, onDone }: { s: ReprobeSettings; onDone: () => void }) {
  const [f, setF] = useState(s);
  const [steps, setSteps] = useState((s.backoff_minutes ?? []).join(', '));
  useEffect(() => { setF(s); setSteps((s.backoff_minutes ?? []).join(', ')); }, [s]);
  const parsed = steps.split(/[\s,]+/).filter(Boolean).map(Number);
  const ok = parsed.length > 0 && parsed.every((x) => Number.isFinite(x) && x > 0) && f.budget_per_hour > 0;
  const save = useAction(() => put<ReprobeSettings>('/settings/reprobe', { enabled: f.enabled, budget_per_hour: f.budget_per_hour, backoff_minutes: parsed }), {
    invalidate: ['/reprobe/plan', '/settings/reprobe', '/audit'], silent: true, success: t('Ustawienia zapisane', 'Settings saved'), onSuccess: onDone,
  });
  return (
    <div className="mt-3 space-y-3 border-t border-rule pt-3" data-testid="reprobe-settings">
      <Check checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} label={t('Ponowne sprawdzenia włączone', 'Re-probing enabled')} />
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label={t('Budżet na godzinę', 'Budget per hour')} hint={t('najwięcej adresów sprawdzanych w ciągu godziny', 'at most this many addresses per hour')}><input type="number" min={1} className="field num" value={f.budget_per_hour} onChange={(e) => setF({ ...f, budget_per_hour: Number(e.target.value) })} /></Field>
        <Field label={t('Kroki potwierdzania (minuty)', 'Confirmation steps (minutes)')} hint={t('po ilu minutach od pierwszego braku odpowiedzi', 'minutes after the first miss')} error={!ok && steps ? t('wpisz dodatnie liczby, np. 10, 30, 90', 'enter positive numbers, for example 10, 30, 90') : undefined}><input className="field mono" value={steps} onChange={(e) => setSteps(e.target.value)} /></Field>
      </div>
      <Button size="sm" variant="primary" icon="check" busy={save.isPending} disabled={!ok} onClick={() => save.mutate(undefined)}>{t('Zapisz', 'Save')}</Button>
      <InlineError error={save.error} />
    </div>
  );
}

/** "Plan ponownych sprawdzeń": what Czujka probes next, when and why (GET /reprobe/plan). With hostId it shows only that host. */
export function ReprobePanel({ hostId, limit = 8 }: { hostId?: number; limit?: number }) {
  const q = useItem<ReprobePlan>('/reprobe/plan', undefined, { refetchInterval: 60_000 });
  const canConfigure = useCan('scans:configure');
  const [edit, setEdit] = useState(false);
  const title = t('Plan ponownych sprawdzeń', 'Re-probe plan');
  if (q.error && routeMissing(q.error)) return <Panel title={title}><Unavailable what={t('Plan pojawi się, gdy serwer udostępni GET /reprobe/plan. Czujka sprawdzi wtedy ponownie hosty, które przestały odpowiadać, w godzinach, w których model spodziewa się odpowiedzi.', 'The plan appears when the server serves GET /reprobe/plan. Czujka then re-probes hosts that went silent, in the hours when the model expects an answer.')} /></Panel>;
  if (q.error) return <Panel title={title}><ErrorState error={q.error} retry={() => q.refetch()} /></Panel>;
  if (!q.data) return <Panel title={title}><SkeletonRows rows={3} /></Panel>;
  const p = q.data;
  const probes = (p.probes ?? []).filter((x) => !hostId || x.host_id === hostId);
  const skipped = (p.skipped ?? []).filter((x) => !hostId || x.host_id === hostId);
  return (
    <Panel title={title} actions={!hostId && canConfigure ? <button type="button" className="link text-xs" onClick={() => setEdit((v) => !v)}>{edit ? t('Zamknij ustawienia', 'Close the settings') : t('Ustawienia', 'Settings')}</button> : undefined}>
      <div data-testid="reprobe-plan">
        {p.blocked && p.enabled ? <p className="mb-2 flex items-start gap-2 text-sm text-danger"><Icon name="stop" size={14} className="mt-0.5" />{p.blocked}</p> : null}
        {!p.enabled ? <p className="text-sm text-ink-2">{t('Ponowne sprawdzenia są wyłączone. Po włączeniu Czujka sprawdzi pojedyncze hosty, które przestały odpowiadać, zamiast czekać na następny pełny skan.', 'Re-probing is off. When it is on, Czujka checks single hosts that went silent instead of waiting for the next full scan.')}</p> : !hostId ? (
          <p className="mb-2 text-xs text-ink-3"><span className="num text-ink">{fmtInt(p.due_now)}</span> {t('do sprawdzenia teraz', 'due now')} · <span className="num text-ink">{fmtInt(p.used_last_hour)}</span> / <span className="num">{fmtInt(p.budget_per_hour)}</span> {t('adresów w ostatniej godzinie', 'addresses in the last hour')}</p>
        ) : null}
        {p.enabled && probes.length === 0 && skipped.length === 0 ? <p className="text-sm text-ink-2">{hostId ? t('Ten host nie czeka na ponowne sprawdzenie.', 'This host is not waiting for a re-probe.') : t('Nic nie czeka na ponowne sprawdzenie. Każdy host odpowiada albo czeka na pełny skan.', 'Nothing waits for a re-probe. Every host answers or waits for the full scan.')}</p> : null}
        {probes.length ? (
          <ul className="divide-y divide-rule">
            {probes.slice(0, limit).map((x, i) => (
              <li key={x.host_id + ':' + i} className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 py-1.5 text-sm">
                <span className="min-w-0">
                  {!hostId ? <Link to={'/hosts/' + x.host_id} className="mono link mr-2">{x.ip}</Link> : null}
                  <span className={cx('mr-2 text-2xs uppercase tracking-wide', x.kind === 'confirm' ? 'text-st-changed' : 'text-accent')}>{x.kind === 'confirm' ? t('potwierdzenie', 'confirm') + ' ' + x.step + '/' + x.steps : t('spodziewana odpowiedź', 'likely up')}</span>
                  <span className="text-ink-2">{x.reason}</span>
                  {ports(x.ports) ? <span className="mono ml-1.5 text-2xs text-ink-3">{ports(x.ports)}</span> : null}
                </span>
                <span className="num text-xs text-ink-2" title={fmtDateTime(x.not_before)}>{new Date(x.not_before).getTime() <= Date.now() ? t('teraz', 'now') : fmtRelative(x.not_before)}</span>
              </li>
            ))}
          </ul>
        ) : null}
        {probes.length > limit ? <p className="mt-1 text-xs text-ink-3">{t('i ' + (probes.length - limit) + ' kolejnych', 'and ' + (probes.length - limit) + ' more')}</p> : null}
        {skipped.length ? (
          <details className="mt-2 text-xs text-ink-2">
            <summary className="cursor-pointer text-ink-3">{t('Pominięte: ' + skipped.length, 'Skipped: ' + skipped.length)}</summary>
            <ul className="mt-1 space-y-0.5">{skipped.slice(0, 20).map((x, i) => <li key={i}>{!hostId ? <span className="mono mr-1.5">{x.ip}</span> : null}{x.reason}</li>)}</ul>
          </details>
        ) : null}
        {edit && !hostId ? <SettingsForm s={p.settings} onDone={() => setEdit(false)} /> : null}
      </div>
    </Panel>
  );
}
