import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { useAction, useItem, usePage } from '../api/hooks';
import { del, patch, post } from '../api/client';
import type { ExposureRule, Finding, RuleDryRun } from '../api/types';
import { plural, t } from '../i18n';
import { cx, fmtInt, fmtRelative } from '../lib/format';
import { useUrlState } from '../lib/hooks';
import { routeMissing } from '../lib/route';
import { Button, ErrorState, InlineError, PageHeader, Panel, SkeletonRows, Unavailable } from '../ui/kit';
import { FindingStatusMark, Sev } from '../ui/marks';
import { useCan } from '../session';
import { Switch } from './Signatures';

const RULE_TEMPLATE = `id: moja-regula
name: 'Panel administracyjny poza siecią zarządzania'
severity: high
description: 'Panele administracyjne powinny być dostępne tylko z sieci zarządzania.'
match:
  class: [admin-panel]
unless:
  cidr: [10.66.1.0/24]
`;

function useDebounced<T>(v: T, ms: number): T {
  const [d, setD] = useState(v);
  useEffect(() => { const h = setTimeout(() => setD(v), ms); return () => clearTimeout(h); }, [v, ms]);
  return d;
}

function Editor({ rule, onSaved }: { rule: ExposureRule | null; onSaved: (r: ExposureRule) => void }) {
  const canCreate = useCan('signatures:create');
  const canUpdate = useCan('signatures:update');
  const canDelete = useCan('signatures:delete');
  const [yaml, setYaml] = useState(rule?.yaml ?? RULE_TEMPLATE);
  useEffect(() => { setYaml(rule?.yaml ?? RULE_TEMPLATE); }, [rule?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  const d = useDebounced(yaml, 400);
  const dry = useQuery<RuleDryRun>({ queryKey: ['/rules/dry-run', d], queryFn: () => post<RuleDryRun>('/rules/dry-run', { yaml: d, limit: 200 }), enabled: d.trim().length > 0, placeholderData: (p) => p, staleTime: 30_000 });
  const save = useAction(() => (rule ? patch<{ rule: ExposureRule }>('/rules/' + rule.id, { yaml }) : post<{ rule: ExposureRule }>('/rules', { yaml, enabled: true })), {
    invalidate: ['/rules', '/findings'], silent: true, success: t('Reguła zapisana', 'Rule saved'), onSuccess: (r) => onSaved(r.rule),
  });
  const remove = useAction(() => del('/rules/' + rule!.id), { invalidate: ['/rules', '/findings'], success: t('Reguła usunięta', 'Rule deleted'), onSuccess: () => onSaved(null as unknown as ExposureRule) });
  const violations = usePage<Finding>('/rules/' + rule?.id + '/violations', { limit: 20 }, Boolean(rule));
  const v = dry.data?.validation;
  const pending = dry.isFetching || d !== yaml;
  const editable = rule ? canUpdate && !rule.builtin : canCreate;
  return (
    <div className="space-y-4">
      <Panel title={rule ? rule.name : t('Nowa reguła', 'New rule')} actions={editable ? (
        <span className="flex gap-2">
          {rule && !rule.builtin && canDelete ? <Button size="sm" variant="danger" icon="trash" busy={remove.isPending} onClick={() => remove.mutate(undefined)}>{t('Usuń', 'Delete')}</Button> : null}
          <Button size="sm" variant="primary" icon="check" busy={save.isPending} disabled={!v?.ok || pending} onClick={() => save.mutate(undefined)}>{t('Zapisz regułę', 'Save the rule')}</Button>
        </span>
      ) : undefined}>
        {rule?.builtin ? <p className="mb-2 text-xs text-ink-3">{t('Reguła wbudowana: tekst jest stały, możesz ją tylko włączyć albo wyłączyć. Skopiuj ją do nowej reguły, aby zmienić warunki.', 'A built-in rule: the text is fixed, you can only switch it on or off. Copy it into a new rule to change the conditions.')}</p> : null}
        <textarea className="field mono min-h-[260px] text-xs leading-5" spellCheck={false} value={yaml} readOnly={!editable} onChange={(e) => setYaml(e.target.value)} data-testid="rule-yaml" aria-label={t('Treść reguły (YAML)', 'Rule text (YAML)')} />
        <div className="mt-2 min-h-[44px]" data-testid="rule-dryrun" aria-live="polite">
          {dry.error ? (routeMissing(dry.error) ? <Unavailable what={t('Walidacja i próba na sucho wymagają POST /rules/dry-run.', 'Validation and the dry run need POST /rules/dry-run.')} /> : <InlineError error={dry.error} />) : null}
          {v && !v.ok ? <ul className="space-y-0.5 text-sm text-danger">{v.issues.map((x, i) => <li key={i}><span className="mono text-xs text-ink-3">{x.path}</span> {x.message}</li>)}</ul> : null}
          {v?.ok && dry.data ? (
            <p className={cx('text-sm', pending && 'opacity-60')}><span className="font-medium">{dry.data.message}</span>{dry.data.condition ? <span className="ml-2 text-xs text-ink-3">{dry.data.condition}</span> : null}<span className="num ml-2 text-2xs text-ink-3">{dry.data.took_ms} ms</span></p>
          ) : null}
          {v?.ok && (dry.data?.violations ?? []).length ? (
            <ul className="mt-2 max-h-[220px] divide-y divide-rule overflow-auto border-t border-rule">
              {(dry.data?.violations ?? []).slice(0, 50).map((x) => (
                <li key={x.key} className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 py-1 text-sm">
                  <span className="min-w-0 truncate">{x.service_id ? <Link to={'/services/' + x.service_id} className="mono link">{x.ip}:{x.port}/{x.proto}</Link> : <Link to={'/hosts/' + x.host_id} className="mono link">{x.ip}</Link>} <span className="text-ink-2">{x.title}</span></span>
                  <Sev level={x.severity} compact />
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      </Panel>
      {rule ? (
        <Panel title={t('Bieżące naruszenia', 'Current violations')} count={violations.data?.total} flush>
          {violations.error ? <ErrorState error={violations.error} retry={() => violations.refetch()} /> : !violations.data ? <SkeletonRows rows={3} /> : violations.data.items.length === 0 ? <p className="px-3 py-3 text-sm text-ink-2 sm:px-4">{t('Ta reguła nie ma teraz naruszeń.', 'This rule has no violation now.')}</p> : (
            <ul className="divide-y divide-rule">
              {violations.data.items.map((f) => (
                <li key={f.id} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 px-3 py-1.5 text-sm sm:px-4">
                  <Link to={'/findings?host_id=' + f.host_id + '&type=policy-violation'} className="link truncate">{f.title}</Link>
                  <FindingStatusMark status={f.status} />
                </li>
              ))}
            </ul>
          )}
        </Panel>
      ) : null}
    </div>
  );
}

export default function Rules() {
  const u = useUrlState();
  const q = usePage<ExposureRule>('/rules', { limit: 200 });
  const canUpdate = useCan('signatures:update');
  const canEvaluate = useCan('results:update');
  const canCreate = useCan('signatures:create');
  const items = q.data?.items ?? [];
  const sel = u.get('rule');
  const bySlug = u.get('slug');
  const rule = sel === 'new' ? null : items.find((r) => String(r.id) === sel || (bySlug && r.slug === bySlug)) ?? items[0] ?? null;
  const one = useItem<ExposureRule>('/rules/' + rule?.id, undefined, { enabled: Boolean(rule) });
  const toggle = useAction((r: ExposureRule) => patch('/rules/' + r.id, { enabled: !r.enabled }), { invalidate: ['/rules', '/findings'], silent: true });
  const evaluate = useAction(() => post<{ violations: number; took_ms: number }>('/rules/evaluate'), { invalidate: ['/rules', '/findings'], success: (r) => t('Sprawdzono reguły: ' + r.violations + ' naruszeń (' + r.took_ms + ' ms)', 'Rules checked: ' + r.violations + ' violations (' + r.took_ms + ' ms)') });
  const header = <PageHeader title={t('Reguły ekspozycji', 'Exposure rules')} sub={t('Zasady, które sieć ma spełniać, np. „panel administracyjny tylko z sieci zarządzania”. Każde naruszenie staje się znaleziskiem z odnośnikiem do reguły.', 'Rules the network must follow, for example "an admin panel only from the management network". Each violation becomes a finding that links to its rule.')}
    actions={<>{canEvaluate && items.length ? <Button icon="refresh" busy={evaluate.isPending} onClick={() => evaluate.mutate(undefined)}>{t('Sprawdź teraz', 'Check now')}</Button> : null}{canCreate ? <Button variant="primary" icon="plus" onClick={() => u.set({ rule: 'new', slug: null })}>{t('Nowa reguła', 'New rule')}</Button> : null}</>} />;
  if (q.error) return <div>{header}<div className="p-4 sm:p-6">{routeMissing(q.error) ? <Unavailable what={t('Serwer nie udostępnia jeszcze reguł (GET /rules). Gdy integrator podłączy moduł, zobaczysz tu reguły wbudowane, ich naruszenia i edytor z próbą na sucho.', 'The server does not serve rules yet (GET /rules). When the integrator wires the module, this page shows the built-in rules, their violations and an editor with a dry run.')} /> : <ErrorState error={q.error} retry={() => q.refetch()} />}</div></div>;
  if (!q.data) return <div>{header}<SkeletonRows rows={8} /></div>;
  return (
    <div>
      {header}
      <div className="grid gap-4 p-4 sm:p-6 xl:grid-cols-[400px_minmax(0,1fr)]">
        <Panel title={t('Reguły', 'Rules')} count={items.length} flush>
          <ul className="divide-y divide-rule" data-testid="rule-list">
            {items.map((r) => (
              <li key={r.id} className={cx('grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 px-3 py-2 sm:px-4', rule?.id === r.id && sel !== 'new' && 'bg-accent-wash')}>
                <button type="button" className="min-w-0 text-left" onClick={() => u.set({ rule: r.id, slug: null })}>
                  <span className={cx('block truncate text-sm', !r.enabled && 'text-ink-3')}>{r.name}</span>
                  <span className="flex items-center gap-2 text-xs text-ink-3"><Sev level={r.severity} compact /><span className={cx('num', r.violations > 0 && r.enabled ? 'text-ink' : '')}>{fmtInt(r.violations)} {plural(r.violations, ['naruszenie', 'naruszenia', 'naruszeń'], ['violation', 'violations'])}</span>{r.builtin ? <span>{t('wbudowana', 'built-in')}</span> : null}{r.last_eval_at ? <span>{fmtRelative(r.last_eval_at)}</span> : null}</span>
                </button>
                <Switch checked={r.enabled} disabled={!canUpdate || toggle.isPending} onChange={() => toggle.mutate(r)} label={t('Reguła włączona', 'Rule enabled')} />
              </li>
            ))}
          </ul>
          {items.length === 0 ? <p className="p-4 text-sm text-ink-2">{t('Brak reguł.', 'No rule yet.')}</p> : null}
        </Panel>
        <Editor rule={sel === 'new' ? null : one.data ?? rule} onSaved={(r) => u.set({ rule: r ? r.id : null })} />
      </div>
    </div>
  );
}
