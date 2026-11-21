import { Link, useParams } from 'react-router';
import { useAction, useItem, usePage } from '../api/hooks';
import { patch } from '../api/client';
import type { AvailabilityProfile, Change, Host, Scope, Service } from '../api/types';
import { t, plural } from '../i18n';
import { fmtDateTime, fmtDec, fmtRelative } from '../lib/format';
import { ErrorState, KV, PageHeader, Panel, Select, SkeletonRows, TagInput, Tags, useTip } from '../ui/kit';
import { DataTable, type Col } from '../ui/table';
import { ChangeMark, ClassChips, Crit, HostStatusMark, InterestScore, ServiceStateMark, Sev } from '../ui/marks';
import { InlineText, OverrideNote } from '../ui/edit';
import { WeekHeatmap } from '../viz/WeekHeatmap';
import { useCan } from '../session';
import { ReprobePanel } from './Reprobe';
import { HostLifePanel } from './TimeMachine';
import { isLocalMac } from '../lib/mac';
import { serviceName, isSelf } from '../lib/serviceName';
import { ResponseCell, SelfTag } from '../ui/serviceBits';
import { changeSummary } from '../lib/changeText';
import { ProductValue } from '../ui/ProductValue';
import { productLine, shownProduct } from '../lib/shownProduct';

/** Fewer observations than the model needs: the probes as a strip and when the weekly pattern appears. */
const MIN_OBS = 8;
function FewObservations({ a, n }: { a: AvailabilityProfile; n: number }) {
  const recent = [...(a.recent ?? [])].slice(0, MIN_OBS).reverse();
  return (
    <div data-testid="few-observations">
      <p className="text-sm text-ink">{t('Za mało obserwacji: ' + n + ' z ' + MIN_OBS + '.', 'Too few observations: ' + n + ' of ' + MIN_OBS + '.')}</p>
      <ol className="mt-3 grid grid-cols-8 gap-1.5" data-testid="probe-strip">
        {recent.map((o, i) => {
          const label = fmtDateTime(o.at) + ': ' + (o.up ? t('odpowiedź', 'response') : t('brak odpowiedzi', 'no response'));
          return <li key={i} className="block h-[22px] min-w-0" style={o.up ? { background: 'var(--seq-4)' } : { boxShadow: 'inset 0 0 0 1px var(--rule-strong)' }} title={label} aria-label={label} />;
        })}
        {Array.from({ length: Math.max(0, MIN_OBS - recent.length) }).map((_, i) => (
          <li key={'f' + i} className="block h-[22px] min-w-0 border border-dashed border-rule" aria-hidden="true" />
        ))}
      </ol>
      <div className="mt-1.5 flex flex-wrap items-center justify-between gap-x-4 gap-y-1 text-2xs text-ink-3" data-testid="probe-legend">
        <span className="num">{recent.length ? fmtDateTime(recent[0].at) + (recent.length > 1 ? ' → ' + fmtDateTime(recent[recent.length - 1].at) : '') : ''}</span>
        <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="inline-flex items-center gap-1"><span className="inline-block h-2.5 w-2.5" style={{ background: 'var(--seq-4)' }} aria-hidden="true" />{t('odpowiedź', 'response')}</span>
          <span className="inline-flex items-center gap-1"><span className="inline-block h-2.5 w-2.5" style={{ boxShadow: 'inset 0 0 0 1px var(--rule-strong)' }} aria-hidden="true" />{t('brak odpowiedzi', 'no response')}</span>
          {recent.length < MIN_OBS ? <span className="inline-flex items-center gap-1"><span className="inline-block h-2.5 w-2.5 border border-dashed border-rule" aria-hidden="true" />{t('kolejne skany', 'next scans')}</span> : null}
        </span>
      </div>
    </div>
  );
}

function ModelOutput({ h, a, compact }: { h: Host; a: AvailabilityProfile; compact?: boolean }) {
  const left = Math.max(0, a.down_after_misses - h.consecutive_misses);
  const tip = useTip();
  const recent = [...(a.recent ?? [])].slice(0, 28).reverse();
  return (
    <div className="space-y-3">
      <dl className="border-t border-rule">
        <div className="grid grid-cols-[72px_minmax(0,1fr)] items-baseline gap-x-3 border-b border-rule py-1.5">
          <dt className="num text-lg font-semibold">{fmtDec(a.p_alive)}</dt>
          <dd className="text-sm text-ink-2">{t('prawdopodobieństwo, że host nadal istnieje', 'probability that the host still exists')} <span className="mono text-xs text-ink-3">p_alive</span></dd>
        </div>
        <div className="grid grid-cols-[72px_minmax(0,1fr)] items-baseline gap-x-3 border-b border-rule py-1.5">
          <dt className="num text-lg font-semibold">{a.down_after_misses > 0 ? a.down_after_misses : '–'}</dt>
          <dd className="text-sm text-ink-2">{a.down_after_misses > 0
            ? <>{plural(a.down_after_misses, ['brak odpowiedzi z rzędu', 'braki odpowiedzi z rzędu', 'braków odpowiedzi z rzędu'], ['miss in a row', 'misses in a row'])} {t('i host zostaje uznany za nieaktywny', 'and the host is reported down')}</>
            : t('próg braków odpowiedzi nieznany', 'miss threshold unknown')}</dd>
        </div>
        <div className="grid grid-cols-[72px_minmax(0,1fr)] items-baseline gap-x-3 border-b border-rule py-1.5">
          <dt className="num text-lg font-semibold">{h.consecutive_misses}</dt>
          <dd className="text-sm text-ink-2">
            {plural(h.consecutive_misses, ['brak z rzędu teraz', 'braki z rzędu teraz', 'braków z rzędu teraz'], ['miss in a row now', 'misses in a row now'])}
            {h.status !== 'down' && h.consecutive_misses > 0 ? <span className="text-ink-3"> · {t('jeszcze ' + left + ' do „nieaktywny”', left + ' more to "down"')}</span> : null}
          </dd>
        </div>
      </dl>
      {compact ? null : <p className="border-l border-rule-strong pl-3 text-sm text-ink">{a.pattern || t('Za mało obserwacji, aby opisać wzorzec.', 'Too few observations to describe a pattern.')}</p>}
      {h.status === 'expected-offline' || h.status === 'unstable' || h.status === 'down' ? (
        <p className="text-xs text-ink-2">
          {h.status === 'expected-offline' ? t('O tej porze host zwykle nie odpowiada.', 'The host usually does not respond at this hour.')
            : h.status === 'unstable' ? t('Host odpowiada nieregularnie.', 'The host responds irregularly.')
            : t('Braków odpowiedzi z rzędu jest więcej niż próg.', 'More misses in a row than the threshold.')}
        </p>
      ) : null}
      {recent.length && !compact ? (
        <div>
          <div className="mb-1 text-xs text-ink-3">{t('Ostatnie próby (najnowsza po prawej)', 'Recent probes (latest on the right)')}</div>
          <div className="flex flex-wrap gap-[3px]">
            {recent.map((o, i) => (
              <span key={i} tabIndex={0}
                onPointerEnter={(e) => tip.show(e, <div><div className="num text-ink">#{o.run_id} · {fmtDateTime(o.at)}</div><div className="text-ink-2">{o.up ? t('odpowiedź', 'response') + (o.rtt_ms ? ', ' + fmtDec(o.rtt_ms, 1) + ' ms' : '') : t('brak odpowiedzi', 'no response')} · {o.attempts} {plural(o.attempts, ['próba', 'próby', 'prób'], ['probe', 'probes'])}{o.reason ? ' · ' + o.reason : ''}</div></div>)}
                onPointerLeave={tip.hide} onFocus={(e) => tip.showAt(e.currentTarget, <span className="num">#{o.run_id} · {o.up ? t('odpowiedź', 'response') : t('brak odpowiedzi', 'no response')}</span>)} onBlur={tip.hide}
                className="block h-[14px] w-[10px]" style={o.up ? { background: 'var(--seq-4)' } : { boxShadow: 'inset 0 0 0 1px var(--rule-strong)' }}
                aria-label={'#' + o.run_id + ' ' + (o.up ? t('odpowiedź', 'response') : t('brak odpowiedzi', 'no response'))} />
            ))}
          </div>
        </div>
      ) : null}
      {tip.node}
    </div>
  );
}

export default function HostDetail() {
  const id = Number(useParams().id);
  const canEdit = useCan('results:update');
  const q = useItem<Host>('/hosts/' + id);
  const services = useItem<Service[]>('/hosts/' + id + '/services');
  const avail = useItem<AvailabilityProfile>('/hosts/' + id + '/availability');
  const changes = usePage<Change>('/hosts/' + id + '/changes', { limit: 50 });
  const scopes = usePage<Scope>('/scopes', { limit: 200 });
  const save = useAction((body: Record<string, unknown>) => patch<Host>('/hosts/' + id, body), { invalidate: ['/hosts'], success: t('Zapisano', 'Saved') });
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!q.data) return <SkeletonRows rows={12} />;
  const h = q.data;
  const now = new Date();
  const svcCols: Col<Service>[] = [
    { id: 'port', header: t('Port', 'Port'), width: 90, cell: (s) => <Link to={'/services/' + s.id} className="mono link">{s.port}/{s.proto}</Link> },
    { id: 'state', header: t('Stan', 'Status'), cell: (s) => <ServiceStateMark state={s.state} /> },
    { id: 'name', header: t('Usługa', 'Service'), cell: (s) => <span>{serviceName(s)}{s.tls ? <span className="ml-1.5 text-2xs text-ink-3">TLS</span> : null}{isSelf(s) ? <SelfTag /> : null}</span> },
    { id: 'product', header: t('Produkt', 'Product'), hide: 'md', cell: (s) => <span className="text-ink-2"><ProductValue s={s} /></span> },
    { id: 'title', header: t('Tytuł / technologie', 'Title / technologies'), wrap: true, cell: (s) => <span className="block min-w-[160px] max-w-[420px] truncate text-ink-2">{s.title || (s.technologies ?? []).map((x) => x.name).join(', ') || '–'}</span> },
    { id: 'class', header: t('Klasy', 'Classes'), hide: 'lg', cell: (s) => <ClassChips classes={s.classes} max={2} /> },
    ...((services.data ?? []).some((s) => s.response_ms !== undefined) ? [{ id: 'rt', header: t('Czas odpowiedzi', 'Response time'), align: 'right' as const, hide: 'md' as const, cell: (s: Service) => <ResponseCell s={s} /> }] : []),
    { id: 'interest', header: t('Ciekawość', 'Interest'), align: 'right', cell: (s) => <InterestScore value={s.interest} reasons={s.interest_why} /> },
  ];
  return (
    <div>
      <PageHeader
        back={{ to: '/hosts', label: t('Hosty', 'Hosts') }}
        title={<span className="flex flex-wrap items-center gap-x-3 gap-y-1"><span className="mono text-[26px] font-medium tracking-[-0.01em] sm:text-[30px]">{h.ip}</span><span className="font-sans text-base font-normal"><HostStatusMark status={h.status} /></span></span>}
        sub={<>{h.label ? <span className="text-ink">{h.label} · </span> : null}<span className="mono">{(h.hostnames ?? []).join(', ') || t('bez nazwy DNS', 'no DNS name')}</span></>}
        readOnly={!canEdit}
        actions={<span className="flex items-center gap-2 text-sm text-ink-2">{t('Ciekawość', 'Interest')} <InterestScore value={h.interest} /></span>}
      />
      <div className="grid gap-4 p-4 sm:p-6 xl:grid-cols-[minmax(0,380px)_minmax(0,1fr)]">
        <div className="space-y-4">
          <Panel title={t('Opis analityka', 'Analyst notes')}>
            <dl>
              <KV k={t('Etykieta', 'Label')}><InlineText label={t('Etykieta', 'Label')} value={h.label} canEdit={canEdit} busy={save.isPending} placeholder={t('brak etykiety', 'no label')} onSave={(v) => save.mutate({ label: v })} /></KV>
              <KV k={t('Właściciel', 'Owner')}><InlineText label={t('Właściciel', 'Owner')} value={h.owner} canEdit={canEdit} busy={save.isPending} placeholder={t('nieprzypisany', 'not assigned')} onSave={(v) => save.mutate({ owner: v })} /></KV>
              <KV k={t('Krytyczność', 'Criticality')}>
                {canEdit ? (
                  <span className="flex items-center gap-2"><span className="w-[150px]"><Select label={t('Krytyczność', 'Criticality')} value={String(h.criticality)} onChange={(v) => save.mutate({ criticality: Number(v) })} options={[1, 2, 3, 4, 5].map((n) => ({ value: String(n), label: n + ' · ' + [t('znikoma', 'negligible'), t('niska', 'low'), t('średnia', 'medium'), t('wysoka', 'high'), t('krytyczna', 'critical')][n - 1] }))} /></span><Crit value={h.criticality} /></span>
                ) : <Crit value={h.criticality} />}
              </KV>
              <KV k={t('Tagi', 'Tags')}>{canEdit ? <TagInput value={h.tags ?? []} onChange={(v) => save.mutate({ tags: v })} placeholder={t('dodaj tag', 'add a tag')} /> : <Tags tags={h.tags} max={12} />}</KV>
              <KV k={t('Notatka', 'Note')}><InlineText label={t('Notatka', 'Note')} multiline value={h.note} canEdit={canEdit} busy={save.isPending} placeholder={t('brak notatki', 'no note')} onSave={(v) => save.mutate({ note: v })} /></KV>
            </dl>
          </Panel>
          <Panel title={t('Dane ze skanów', 'Scan data')}>
            <dl>
              <KV k={t('System', 'OS')}>
                <InlineText label={t('System', 'OS')} value={h.os_guess} canEdit={canEdit} placeholder={t('nie rozpoznano', 'not recognised')} onSave={(v) => save.mutate({ os_guess: v })} />
                <OverrideNote o={h.overrides?.os_guess} canEdit={canEdit} onRevert={() => save.mutate({ os_guess: null })} />
              </KV>
              <KV k={t('Nazwy DNS', 'DNS names')} mono>
                {(h.hostnames ?? []).join(', ') || '–'}
                <OverrideNote o={h.overrides?.hostnames} canEdit={canEdit} onRevert={() => save.mutate({ hostnames: null })} />
              </KV>
              {h.mac ? <KV k="MAC" mono>{h.mac}{isLocalMac(h.mac) ? <span className="ml-2 font-sans text-ink-3" title={t('Adres MAC nadany lokalnie (kontener, maszyna wirtualna).', 'A locally assigned MAC address (container, virtual machine).')} data-testid="mac-local">{t('adres lokalny', 'local address')}</span> : h.vendor ? <span className="ml-2 font-sans text-ink-3">{h.vendor}</span> : null}</KV> : null}
              <KV k={t('Zakresy', 'Scopes')}>{(h.scope_ids ?? []).map((sid) => scopes.data?.items.find((s) => s.id === sid)?.name ?? '#' + sid).join(', ') || '–'}</KV>
              <KV k={t('Pierwsza obserwacja', 'First seen')}><span className="num">{fmtDateTime(h.first_seen)}</span></KV>
              <KV k={t('Ostatnia obserwacja', 'Last seen')}><span className="num">{fmtDateTime(h.last_seen)}</span> <span className="text-ink-3">{fmtRelative(h.last_seen)}</span></KV>
              <KV k={t('Ostatnia odpowiedź', 'Last response')}><span className="num">{h.last_up ? fmtDateTime(h.last_up) : '–'}</span></KV>
              <KV k={t('Stabilność', 'Stability')}><span className="num">{fmtDec(h.stability)}</span> <span className="text-xs text-ink-3">{t('udział prób z odpowiedzią', 'share of probes with a response')}</span></KV>
              <KV k={t('Źródło', 'Source')}>{h.source === 'import' ? t('import pliku', 'file import') : t('skan', 'scan')}</KV>
            </dl>
          </Panel>
        </div>

        <div className="min-w-0 space-y-4">
          <Panel title={t('Usługi', 'Services')} count={services.data?.length} flush>
            <DataTable inPanel rows={services.data} cols={svcCols} rowKey={(s) => s.id} rowHref={(s) => '/services/' + s.id} loading={services.isPending} error={services.error} retry={() => services.refetch()}
              rowClass={(s) => (s.state === 'gone' ? 'text-ink-3' : undefined)}
              empty={<p className="p-3 text-sm text-ink-2">{t('Brak otwartych usług.', 'No open services.')}</p>}
              mobile={(s) => (
                <div>
                  <div className="flex items-center justify-between gap-2"><span className="mono text-sm">{s.port}/{s.proto} <span className="font-sans text-ink-2">{serviceName(s)}</span></span><InterestScore value={s.interest} /></div>
                  <div className="mt-0.5 truncate text-xs text-ink-3">{s.title || productLine(shownProduct(s)) || '–'}</div>
                </div>
              )} />
          </Panel>

          <Panel title={t('Dostępność w tygodniu', 'Availability over the week')}>
            {avail.error ? <ErrorState error={avail.error} retry={() => avail.refetch()} /> : !avail.data ? <div className="skeleton h-[220px]" /> : obsCount(avail.data) < MIN_OBS ? (
              <div className="grid gap-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
                <FewObservations a={avail.data} n={obsCount(avail.data)} />
                <ModelOutput h={h} a={avail.data} compact />
              </div>
            ) : (
              <div className="grid gap-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
                <WeekHeatmap buckets={avail.data.buckets} nowIndex={now.getDay() * 24 + now.getHours()} />
                <ModelOutput h={h} a={avail.data} />
              </div>
            )}
          </Panel>
          <ReprobePanel hostId={h.id} />
          <HostLifePanel hostId={h.id} />

          <Panel title={t('Historia zmian', 'Change history')} count={changes.data?.total} flush>
            {changes.error ? <ErrorState error={changes.error} retry={() => changes.refetch()} /> : !changes.data ? <SkeletonRows rows={4} /> : changes.data.items.length === 0 ? (
              <p className="p-3 text-sm text-ink-2">{t('Brak zmian.', 'No changes.')}</p>
            ) : (
              <ol>
                {changes.data.items.map((c) => (
                  <li key={c.id} className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 border-b border-rule px-3 py-2 last:border-b-0 sm:grid-cols-[150px_190px_minmax(0,1fr)_auto]">
                    <span className="num hidden text-xs text-ink-3 sm:block" title={fmtDateTime(c.at)}>{fmtDateTime(c.at)}</span>
                    <span><ChangeMark kind={c.kind} expected={c.expected} /></span>
                    <span className="col-span-2 min-w-0 text-sm sm:col-span-1">
                      {changeSummary(c)}
                      {c.port ? <Link to={'/services/' + c.service_id} className="mono link ml-2 text-xs">:{c.port}</Link> : null}
                      <span className="num ml-2 text-xs text-ink-3 sm:hidden">{fmtRelative(c.at)}</span>
                    </span>
                    <span className="hidden items-center gap-3 sm:flex">{c.expected ? <span className="text-xs text-ink-3">{t('oczekiwana', 'expected')}</span> : <Sev level={c.severity} />}<Link to={'/runs/' + c.run_id} className="num link text-xs">#{c.run_id}</Link></span>
                  </li>
                ))}
              </ol>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function obsCount(a: AvailabilityProfile): number {
  return (a.buckets ?? []).reduce((n, b) => n + b.up + b.down, 0);
}
