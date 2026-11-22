import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { useAction, useItem, usePage } from '../api/hooks';
import { del, patch, post } from '../api/client';
import type { ExposureRule, RuleDryRun } from '../api/types';
import { plural, t } from '../i18n';
import { cx, fmtInt } from '../lib/format';
import { useUrlState } from '../lib/hooks';
import { routeMissing } from '../lib/route';
import { Button, ErrorState, InlineError, PageHeader, Panel, SkeletonRows, Unavailable } from '../ui/kit';
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
  const v = dry.data?.validation;
  const pending = dry.isFetching || d !== yaml;
  const editable = rule ? canUpdate && !rule.builtin : canCreate;
  const list = v?.ok ? dry.data?.violations ?? [] : [];
  return (
    <Panel title={<span className="text-base text-ink">{rule ? rule.name : t('Nowa reguła', 'New rule')}</span>} actions={editable ? (
      <span className="flex gap-2">
        {rule && !rule.builtin && canDelete ? <Button size="sm" variant="danger" icon="trash" busy={remove.isPending} onClick={() => remove.mutate(undefined)}>{t('Usuń', 'Delete')}</Button> : null}
        <Button size="sm" variant="primary" icon="check" busy={save.isPending} disabled={!v?.ok || pending} onClick={() => save.mutate(undefined)}>{t('Zapisz regułę', 'Save rule')}</Button>
      </span>
    ) : undefined}>
      {rule?.description ? <p className="mb-4 text-sm text-ink-2">{rule.description}</p> : null}
      <details key={(rule?.id ?? 'new') + String(editable)} open={editable} className="group mb-4" data-testid="rule-definition">
        <summary className="caps cursor-pointer select-none hover:text-ink">{t('Definicja', 'Definition')}</summary>
        <textarea className="field mono mt-2 min-h-[240px] text-xs leading-5" spellCheck={false} value={yaml} readOnly={!editable} onChange={(e) => setYaml(e.target.value)} data-testid="rule-yaml" aria-label={t('Treść reguły (YAML)', 'Rule text (YAML)')} />
        {v && !v.ok ? <ul className="mt-2 space-y-0.5 text-sm text-danger">{v.issues.map((x, i) => <li key={i}><span className="mono text-xs text-ink-3">{x.path}</span> {x.message}</li>)}</ul> : null}
      </details>
      <div data-testid="rule-dryrun" aria-live="polite" className={cx(pending && 'opacity-60')}>
        <h3 className="caps mb-1">{t('Naruszenia', 'Violations')}{v?.ok && dry.data ? <span className="num"> · {fmtInt(dry.data.total)}</span> : null}</h3>
        {dry.error ? (routeMissing(dry.error) ? <Unavailable /> : <InlineError error={dry.error} />) : null}
        {list.length ? (
          <ul className="divide-y divide-rule">
            {list.slice(0, 50).map((x) => (
              <li key={x.key} className="flex h-[34px] min-w-0 items-center gap-3 text-sm">
                {x.service_id ? <Link to={'/services/' + x.service_id} className="mono link flex-none">{x.ip}:{x.port}</Link> : <Link to={'/hosts/' + x.host_id} className="mono link flex-none">{x.ip}</Link>}
                <span className="min-w-0 truncate text-ink-2" title={x.title}>{x.title}</span>
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </Panel>
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
  const evaluate = useAction(() => post<{ violations: number; took_ms: number }>('/rules/evaluate'), { invalidate: ['/rules', '/findings'], success: (r) => t('Naruszenia: ' + r.violations, 'Violations: ' + r.violations) });
  const header = <PageHeader title={t('Reguły ekspozycji', 'Exposure rules')}    actions={<>{canEvaluate && items.length ? <Button icon="refresh" busy={evaluate.isPending} onClick={() => evaluate.mutate(undefined)}>{t('Sprawdź teraz', 'Check now')}</Button> : null}{canCreate ? <Button variant="primary" icon="plus" onClick={() => u.set({ rule: 'new', slug: null })}>{t('Nowa reguła', 'New rule')}</Button> : null}</>} />;
  if (q.error) return <div>{header}<div className="px-4 pb-6 sm:px-6 lg:px-8">{routeMissing(q.error) ? <Unavailable /> : <ErrorState error={q.error} retry={() => q.refetch()} />}</div></div>;
  if (!q.data) return <div>{header}<SkeletonRows rows={8} /></div>;
  return (
    <div>
      {header}
      <div className="grid gap-4 px-4 pb-6 sm:px-6 lg:px-8 xl:grid-cols-[400px_minmax(0,1fr)]">
        <Panel title={t('Reguły', 'Rules')} count={items.length} flush>
          <ul className="divide-y divide-rule" data-testid="rule-list">
            {items.map((r) => (
              <li key={r.id} className={cx('grid h-[44px] grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 px-3 sm:px-4', rule?.id === r.id && sel !== 'new' && 'bg-raised')}>
                <button type="button" className="flex min-w-0 items-center gap-3 text-left" onClick={() => u.set({ rule: r.id, slug: null })}>
                  <span className={cx('min-w-0 flex-1 truncate text-sm', !r.enabled && 'text-ink-3')}>{r.name}</span>
                  {r.violations > 0 ? <span className={cx('num flex-none text-sm', r.enabled ? 'text-ink' : 'text-ink-3')} title={plural(r.violations, ['naruszenie', 'naruszenia', 'naruszeń'], ['violation', 'violations'])}>{fmtInt(r.violations)}</span> : null}
                </button>
                <Switch checked={r.enabled} disabled={!canUpdate || toggle.isPending} onChange={() => toggle.mutate(r)} label={t('Reguła włączona', 'Rule enabled')} />
              </li>
            ))}
          </ul>
          {items.length === 0 ? <p className="p-4 text-sm text-ink-2">{t('Brak reguł', 'No rules yet')}</p> : null}
        </Panel>
        <Editor rule={sel === 'new' ? null : one.data ?? rule} onSaved={(r) => u.set({ rule: r ? r.id : null })} />
      </div>
    </div>
  );
}
