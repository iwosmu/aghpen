import { useState, type ReactNode } from 'react';
import { Link, Navigate } from 'react-router';
import { SETUP_DONE_KEY } from './Setup';
import { useItem, usePage } from '../api/hooks';
import type { Change, Dashboard as Dash, Page, RunMap, ScanProfile, ScanRun, Scope, Service } from '../api/types';
import { t, plural, getLang } from '../i18n';
import { cx, fmtDateTime, fmtDuration, fmtInt, fmtPct, fmtRelative, fmtSigned } from '../lib/format';
import { useLiveRun, useNow } from '../lib/hooks';
import { ErrorState, Panel, SkeletonRows } from '../ui/kit';
import { Icon } from '../ui/Icon';
import { ClassChips, Glyph, InterestScore, RunStatusMark, Sev, changeKindInfo, type GlyphName, type Tone } from '../ui/marks';
import { AddressMap } from '../viz/AddressMap';
import { BarList, PacketCount, ProgressBar, RateGauge, TrendRows } from '../viz/charts';
import { useSession } from '../session';
import { RunStory } from '../ui/RunStory';
import { PartialNote, RunPasses } from '../ui/RunPasses';
import { useArrivalOrder } from '../ui/arrivalOrder';
import { SMALL_RUN } from './RunDetail';
import { serviceName } from '../lib/serviceName';
import { ReprobePanel } from './Reprobe';
import { ATTENTION_INTEREST, adminPanelNames, adminPanelServiceNames, changeParts, isFullRun, lastFullPair, partialRunPhrase } from '../lib/headline';
import { changeSummary } from '../lib/changeText';

function Count({ n, glyph, tone, label, to }: { n: number; glyph: GlyphName; tone: Tone; label: string; to: string }) {
  const zero = n === 0;
  return (
    <Link to={to} className={cx('group inline-flex items-center gap-1.5 whitespace-nowrap py-0.5', zero ? 'text-ink-3' : 'text-ink hover:underline')}>
      <Glyph name={glyph} tone={zero ? 'expected' : tone} />
      <span className="num text-base font-medium">{n}</span>
      <span className="text-sm text-ink-2 group-hover:text-ink">{label}</span>
    </Link>
  );
}

/** The handover report: what changed and, from the data, what needs attention. */
function Handover({ d, full }: { d: Dash; full?: ScanRun | null }) {
  const h = d.headline;
  // The headline compares the last two full runs of one profile; a partial run
  // (ad hoc, re-probe, import, manual entry) only gets its own short line.
  const last = d.last_run;
  const partial = last && !isFullRun(last) ? last : null;
  const run = full === undefined ? (partial ? null : last) : full;
  const s = run?.summary;
  const expected = (d.recent_changes ?? []).filter((c) => c.expected).length;
  if (!run && partial) {
    return (
      <div>
        <p className="text-xl font-semibold tracking-[-0.015em]" data-testid="handover">{t('Nie ma jeszcze pełnego skanu profilu do porównania.', 'No full profile scan to compare yet.')}</p>
        <p className="mt-2 text-sm text-ink-2" data-testid="handover-partial">{t('Ostatnio', 'Last')}: {partialRunPhrase(partial)} (<Link to={'/runs/' + partial.id} className="num link">#{partial.id}</Link>, {fmtRelative(partial.finished_at)}).</p>
      </div>
    );
  }
  if (!run) {
    return (
      <div>
        <p className="text-xl font-semibold tracking-[-0.015em]">{t('Nie ma jeszcze zakończonego skanu.', 'No scan has completed yet.')}</p>
        <p className="mt-2 text-base text-ink-2">{t('Dodaj cele, przygotuj profil i uruchom pierwszy przebieg. Pulpit pokaże wtedy, co działa w sieci.', 'Add targets, prepare a profile and start the first run. The dashboard then shows what is on the network.')}</p>
        <Link to="/targets" className="link mt-3 inline-block text-sm">{t('Dodaj cele', 'Add targets')}</Link>
      </div>
    );
  }
  const baseline = Boolean(s) && !s!.prev_run_id;
  const changed = s ? s.services_changed : 0;
  const missing = s?.hosts_missing ?? 0;
  const unreachable = s?.services_unreachable ?? 0;
  const added = s ? s.hosts_new + s.services_new : 0;
  const gone = s ? s.hosts_gone + s.services_gone : 0;
  const returned = s?.services_returned ?? 0;
  const slower = s?.responses_slower ?? 0;
  const recovered = s?.by_kind?.response_recovered ?? 0;
  const quiet = s ? added + gone + changed + s.hosts_unstable + missing + returned + slower + recovered === 0 : true;
  const open = (d.top_findings ?? []).filter((f) => f.status === 'new' || f.status === 'triaged');
  const important = open.filter((f) => f.severity === 'high' || f.interest >= ATTENTION_INTEREST);
  const panels = adminPanelNames(open);
  const attention = h.admin_panels > 0 || h.findings_high > 0 || important.length > 0;
  const named = (panels.length ? panels : adminPanelServiceNames(d.top_services ?? [])).slice(0, 2);
  const parts = s ? changeParts({ added, gone, changed, missing, unstable: s.hosts_unstable, returned, slower, recovered }, getLang(), plural) : [];
  const headline = baseline
    ? t('Pierwszy obraz sieci: ' + fmtInt(h.hosts_up) + ' ' + plural(h.hosts_up, ['aktywny host', 'aktywne hosty', 'aktywnych hostów'], ['', '']) + ', ' + fmtInt(h.services_open) + ' ' + plural(h.services_open, ['otwarta usługa', 'otwarte usługi', 'otwartych usług'], ['', '']) + '.',
      'First picture of the network: ' + fmtInt(h.hosts_up) + ' ' + (h.hosts_up === 1 ? 'host' : 'hosts') + ' up, ' + fmtInt(h.services_open) + ' open ' + (h.services_open === 1 ? 'service' : 'services') + '.')
    : quiet
      ? t('Bez zmian od poprzedniego skanu.', 'No change since the previous scan.')
      : t('Od poprzedniego skanu: ', 'Since the previous scan: ') + parts.join(', ') + '.';
  return (
    <div>
      <p className="max-w-[30ch] text-xl font-semibold tracking-[-0.015em] text-ink sm:max-w-none" data-testid="handover">{headline}</p>
      <p className={cx('mt-2 flex items-start gap-2 text-base', attention ? 'text-ink' : 'text-ink-2')} data-testid="handover-attention">
        {attention ? <Icon name="alert" className="mt-[3px] flex-none text-st-gone" /> : <Icon name="check" className="mt-[3px] flex-none text-st-new" />}
        <span>
          {h.admin_panels > 0 ? (
            <>
              <Link to="/services?class=admin-panel" className="font-medium underline decoration-[var(--st-gone)] decoration-2 underline-offset-4 hover:decoration-[var(--ink)]">
                {fmtInt(h.admin_panels)} {plural(h.admin_panels, ['panel administracyjny dostępny', 'panele administracyjne dostępne', 'paneli administracyjnych dostępnych'], ['admin panel reachable', 'admin panels reachable'])} {t('z sieci', 'from the network')}
              </Link>
              {named.length ? <>{t(', w tym ', ', including ')}{named.join(t(' i ', ' and '))}</> : null}.
              {h.findings_high > 0 ? <> <Link to="/findings?severity=high&status=new,triaged" className="link">{h.findings_high} {plural(h.findings_high, ['znalezisko wysokiej wagi', 'znaleziska wysokiej wagi', 'znalezisk wysokiej wagi'], ['high-severity finding', 'high-severity findings'])}</Link>.</> : null}
            </>
          ) : h.findings_high > 0 ? (
            <>
              <Link to="/findings?severity=high&status=new,triaged" className="font-medium underline decoration-[var(--st-gone)] decoration-2 underline-offset-4 hover:decoration-[var(--ink)]">
                {h.findings_high} {plural(h.findings_high, ['znalezisko wysokiej wagi', 'znaleziska wysokiej wagi', 'znalezisk wysokiej wagi'], ['high-severity finding', 'high-severity findings'])}
              </Link>
              {' '}{t(plural(h.findings_high, ['wymaga', 'wymagają', 'wymaga'], ['', '']) + ' uwagi.', (h.findings_high === 1 ? 'needs' : 'need') + ' attention.')}
            </>
          ) : important.length ? (
            <>{t('Najważniejsze: ', 'Most important: ')}<Link to={'/findings?status=new,triaged'} className="font-medium link">{important[0].title}</Link>{important.length > 1 ? t(' i ' + (important.length - 1) + ' innych.', ' and ' + (important.length - 1) + ' more.') : '.'}</>
          ) : t('Nic nie wymaga uwagi: żadne otwarte znalezisko nie ma wysokiej wagi ani ciekawości od ' + ATTENTION_INTEREST + '.', 'Nothing needs attention: no open finding has high severity or interest from ' + ATTENTION_INTEREST + '.')}
          {' '}
          <span className="text-ink-2">
            {t('Skan', 'Run')} <Link to={'/runs/' + run.id} className="num link">#{run.id}</Link>{run.profile_name ? <> ({run.profile_name})</> : null} {t('zakończony', 'finished')} {fmtRelative(run.finished_at)}.
            {baseline ? ' ' + t('To punkt odniesienia: kolejne skany pokażą, co się zmieniło.', 'This is the baseline: the next scans show what changed.') : null}
          </span>
        </span>
      </p>
      {partial ? (
        <p className="mt-1.5 text-sm text-ink-2" data-testid="handover-partial" title={t('Przebieg częściowy widzi tylko część sieci, więc nie porównujemy go z pełnym skanem.', 'A partial run sees only part of the network, so it is not compared with a full scan.')}>
          {t('Ostatnio', 'Last')}: {partialRunPhrase(partial)} (<Link to={'/runs/' + partial.id} className="num link">#{partial.id}</Link>, {fmtRelative(partial.finished_at)}); {t('przebieg częściowy, bez porównania.', 'a partial run, not compared.')}
        </p>
      ) : null}
      {s && !baseline ? <RunStory runId={run.id} className="mt-3 space-y-1" testId="handover-story" /> : null}
      {s && !baseline ? (
        <div className="mt-3 flex flex-wrap gap-x-5 gap-y-0.5 border-t border-rule pt-2.5">
          <Count n={s.hosts_new} glyph="plus" tone="new" label={plural(s.hosts_new, ['nowy host', 'nowe hosty', 'nowych hostów'], ['new host', 'new hosts'])} to={'/changes?run_id=' + run.id + '&kind=host_new'} />
          <Count n={s.services_new} glyph="plus" tone="new" label={plural(s.services_new, ['nowa usługa', 'nowe usługi', 'nowych usług'], ['new service', 'new services'])} to={'/changes?run_id=' + run.id + '&kind=service_new'} />
          <Count n={s.hosts_gone} glyph="minus" tone="gone" label={plural(s.hosts_gone, ['host nieaktywny', 'hosty nieaktywne', 'hostów nieaktywnych'], ['host inactive', 'hosts inactive'])} to={'/changes?run_id=' + run.id + '&kind=host_gone&expected=false'} />
          <Count n={s.services_gone} glyph="minus" tone="gone" label={plural(s.services_gone, ['usługa zniknęła', 'usługi zniknęły', 'usług zniknęło'], ['service gone', 'services gone'])} to={'/changes?run_id=' + run.id + '&kind=service_gone&expected=false'} />
          {s.services_returned ? <Count n={s.services_returned} glyph="returned" tone="new" label={plural(s.services_returned, ['usługa wróciła', 'usługi wróciły', 'usług wróciło'], ['service back', 'services back'])} to={'/changes?run_id=' + run.id + '&kind=service_returned'} /> : null}
          {s.responses_slower ? <Count n={s.responses_slower} glyph="slow" tone="changed" label={plural(s.responses_slower, ['wolniejsza odpowiedź', 'wolniejsze odpowiedzi', 'wolniejszych odpowiedzi'], ['slower response', 'slower responses'])} to={'/changes?run_id=' + run.id + '&kind=response_slower'} /> : null}
          <Count n={changed} glyph="delta" tone="changed" label={plural(changed, ['zmiana', 'zmiany', 'zmian'], ['change', 'changes'])} to={'/changes?run_id=' + run.id} />
          <Count n={s.hosts_unstable} glyph="wave" tone="unstable" label={plural(s.hosts_unstable, ['host niestabilny', 'hosty niestabilne', 'hostów niestabilnych'], ['unstable host', 'unstable hosts'])} to={'/hosts?status=unstable'} />
          <Count n={missing} glyph="half" tone="expected" label={plural(missing, ['host bez odpowiedzi', 'hosty bez odpowiedzi', 'hostów bez odpowiedzi'], ['host missing', 'hosts missing'])} to={'/changes?run_id=' + run.id + '&kind=host_missing'} />
          {unreachable ? <span className="inline-flex items-center gap-1.5 whitespace-nowrap py-0.5 text-sm text-ink-3" title={t('Usługi hostów, które milczą, ale nie są jeszcze uznane za nieaktywne: stan nieznany, nie zamknięte.', 'Services of silent hosts that are not reported inactive yet: unknown, not closed.')}><span className="num text-base font-medium text-ink-2">{unreachable}</span>{plural(unreachable, ['usługa nieosiągalna', 'usługi nieosiągalne', 'usług nieosiągalnych'], ['service unreachable', 'services unreachable'])}</span> : null}
          <Count n={expected} glyph="dashring" tone="expected" label={plural(expected, ['zmiana oczekiwana', 'zmiany oczekiwane', 'zmian oczekiwanych'], ['expected change', 'expected changes'])} to={'/changes?run_id=' + run.id + '&expected=true'} />
        </div>
      ) : null}
    </div>
  );
}

function Stat({ label, value, delta, deltaTitle, to, mono = true }: { label: string; value: ReactNode; delta?: number | null; deltaTitle?: string; to?: string; mono?: boolean }) {
  const inner = (
    <>
      <dt className="text-xs text-ink-3">{label}</dt>
      <dd className="flex items-baseline gap-2">
        <span className={cx('text-base font-medium text-ink', mono && 'num')}>{value}</span>
        {delta !== undefined && delta !== null ? (
          <span className="num text-xs text-ink-3" title={deltaTitle ?? t('zmiana względem poprzedniego skanu', 'change against the previous scan')}>{delta === 0 ? '±0' : fmtSigned(delta)}</span>
        ) : null}
      </dd>
    </>
  );
  return to
    ? <Link to={to} className="flex items-baseline justify-between gap-3 border-b border-rule py-1.5 hover:bg-raised">{inner}</Link>
    : <div className="flex items-baseline justify-between gap-3 border-b border-rule py-1.5">{inner}</div>;
}

function Inventory({ d, pair }: { d: Dash; pair?: { full?: ScanRun; prev?: ScanRun } }) {
  const h = d.headline;
  // Deltas only between two full runs of the same profile, never across a partial run.
  const full = pair?.full, prev = pair?.prev;
  const dHosts = full && prev ? full.stats.hosts_up - prev.stats.hosts_up : null;
  const dServices = full && prev ? full.stats.services_open - prev.stats.services_open : null;
  const deltaTitle = full && prev ? t('zmiana między pełnymi skanami #' + prev.id + ' i #' + full.id + (full.profile_name ? ' (' + full.profile_name + ')' : ''), 'change between the full scans #' + prev.id + ' and #' + full.id + (full.profile_name ? ' (' + full.profile_name + ')' : '')) : undefined;
  return (
    <dl className="grid grid-cols-1 gap-x-6 sm:grid-cols-2">
      <Stat label={t('Adresy w zakresie', 'Addresses in scope')} value={fmtInt(h.addresses_in_scope)} to="/targets" />
      <Stat label={t('Aktywne hosty', 'Hosts up')} value={fmtInt(h.hosts_up)} delta={dHosts} deltaTitle={deltaTitle} to="/hosts?status=up" />
      <Stat label={t('Otwarte usługi', 'Open services')} value={fmtInt(h.services_open)} delta={dServices} deltaTitle={deltaTitle} to="/services?state=open" />
      <Stat label={t('Usługi WWW', 'Web services')} value={fmtInt(h.web_services)} to="/services?name=http" />
      <Stat label={t('Otwarte znaleziska', 'Open findings')} value={fmtInt(h.findings_open)} to="/findings?status=new,triaged" />
      <Stat label={t('Niepotwierdzone zmiany', 'Unacknowledged changes')} value={fmtInt(h.changes_unacked)} to="/changes?acked=false&expected=false" />
      <Stat label={t('Panele administracyjne', 'Admin panels')} value={fmtInt(h.admin_panels)} to="/services?class=admin-panel" />
      <Stat label={t('Środowiska testowe', 'Staging environments')} value={fmtInt(h.staging_envs)} to="/services?class=staging" />
    </dl>
  );
}

/** The open ports a one-machine run has found so far (polled), instead of the address map. */
function LivePorts({ runId }: { runId: number }) {
  const q = useItem<Page<Service>>('/services', { run_id: runId, limit: 500 }, { refetchInterval: 1500 });
  const byPort = (a: Service, b: Service) => a.port - b.port;
  const { rows: items } = useArrivalOrder('live-ports-' + runId, q.data?.items ?? [], true, byPort, byPort);
  return (
    <div data-testid="live-ports">
      <p className="text-xs text-ink-3">{t('Otwarte porty do tej pory', 'Open ports so far')} <span className="num text-ink-2">{items.length}</span></p>
      {items.length ? (
        <ul className="mt-1.5 flex flex-wrap gap-1">
          {items.slice(0, 40).map((s) => <li key={s.id}><Link to={'/services/' + s.id} className="mono inline-block border border-rule-strong px-1.5 py-0.5 text-xs hover:border-accent" title={serviceName(s)}>{s.port}</Link></li>)}
        </ul>
      ) : <p className="mt-1.5 text-xs text-ink-2">{t('Czekam na pierwsze odpowiedzi…', 'Waiting for the first answers…')}</p>}
    </div>
  );
}

function ActiveRun({ initial, d }: { initial: ScanRun; d: Dash }) {
  const { can } = useSession();
  const live = useLiveRun(initial.id);
  const run = live.run.data ?? initial;
  const map = useItem<RunMap>('/runs/' + run.id + '/map', undefined, { enabled: can('scans:read') });
  const profile = useItem<ScanProfile>('/profiles/' + run.profile_id, undefined, { enabled: Boolean(run.profile_id) && can('scans:read') });
  const s = run.stats;
  const pct = s.addresses_total ? s.addresses_done / s.addresses_total : 0;
  const small = s.addresses_total > 0 && s.addresses_total <= SMALL_RUN;
  return (
    <Panel
      title={<><RunStatusMark status={run.status} pauseReason={run.pause_reason} /> <span className="font-normal text-ink-2">· {t('skan', 'run')} <span className="num">#{run.id}</span> · {run.profile_name}</span></>}
      actions={<Link to={'/runs/' + run.id} className="link inline-flex items-center gap-1 whitespace-nowrap">{t('Otwórz przebieg', 'Open the run')}<Icon name="arrowRight" size={12} /></Link>}
    >
      <div className="grid gap-x-8 gap-y-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
        <div>
          <div className="flex items-baseline justify-between gap-3">
            {small
              ? <span><span className="num text-lg font-semibold">{fmtInt(s.services_open)}</span> <span className="text-xs text-ink-3">{plural(s.services_open, ['otwarta usługa', 'otwarte usługi', 'otwartych usług'], ['open service', 'open services'])} {t('do tej pory', 'so far')}</span></span>
              : <span><span className="num text-lg font-semibold">{fmtPct(pct)}</span> <span className="text-xs text-ink-3">{t('adresów', 'of addresses')}</span></span>}
            <span className="text-xs text-ink-2">{run.status === 'analyzing' ? t('analiza zmian…', 'analysing changes…') : s.eta_sec > 0 ? <>{t('pozostało', 'remaining')} <span className="num text-ink">{fmtDuration(s.eta_sec)}</span></> : null}</span>
          </div>
          <div className="mt-1.5"><ProgressBar value={s.addresses_done} max={s.addresses_total} active={(map.data?.blocks ?? []).filter((b) => b.status === 'running').reduce((a, b) => a + b.size, 0)} label={t('Postęp skanu', 'Scan progress')} /></div>
          <RunPasses passes={s.passes} className="mt-1.5" />
          <PartialNote run={run} className="mt-2" />
          <div className="mt-1 flex justify-between text-2xs text-ink-3">
            <span className="num">{fmtInt(s.addresses_done)} / {fmtInt(s.addresses_total)}</span>
            <span>{t('podgrupy', 'chunks')} <span className="num text-ink-2">{s.chunks_done}/{s.chunks_total}</span></span>
          </div>
          <dl className="mt-3 flex gap-6 text-xs text-ink-2">
            <div><dt className="text-ink-3">{t('aktywne hosty', 'hosts up')}</dt><dd className="num text-sm text-ink">{fmtInt(s.hosts_up)}</dd></div>
            <div><dt className="text-ink-3">{t('usługi', 'services')}</dt><dd className="num text-sm text-ink">{fmtInt(s.services_open)}</dd></div>
            <div><dt className="text-ink-3">{t('czas', 'elapsed')}</dt><dd className="num text-sm text-ink">{fmtDuration(s.elapsed_sec)}</dd></div>
            <div><dt className="text-ink-3">{t('pakiety prób', 'probe packets')}</dt><dd className="text-sm text-ink"><PacketCount sent={s.packets_sent} estimated={s.packets_estimated} /></dd></div>
          </dl>
        </div>
        <RateGauge current={s.current_pps} cap={Math.min(profile.data?.rate.max_pps ?? d.safety.max_pps, d.safety.max_pps)} policyCap={d.safety.max_pps} basis={s.current_pps_basis} />
        <div className="min-w-[150px] max-w-[320px]">
          {small ? <LivePorts runId={run.id} /> : map.data ? <AddressMap blocks={map.data.blocks} compact /> : <div className="skeleton h-[104px] w-[220px]" />}
        </div>
      </div>
    </Panel>
  );
}

function IdleRun({ d }: { d: Dash }) {
  const run = d.last_run;
  return (
    <Panel title={t('Skanowanie', 'Scanning')} actions={<Link to="/runs" className="link">{t('Wszystkie przebiegi', 'All runs')}</Link>}>
      <div className="flex flex-wrap gap-x-10 gap-y-2 text-sm">
        <span className="text-ink-2">{t('Żaden skan teraz nie działa.', 'No scan is running now.')}</span>
        {run ? <span>{t('Ostatni:', 'Last:')} <Link className="link num" to={'/runs/' + run.id}>#{run.id}</Link> · {fmtDateTime(run.finished_at)} · {fmtDuration(run.stats.elapsed_sec)}</span> : null}
        <span>{t('Następny:', 'Next:')} {d.next_run_at ? <><span className="num text-ink">{fmtDateTime(d.next_run_at)}</span> <span className="text-ink-3">({fmtRelative(d.next_run_at)})</span></> : t('brak harmonogramu', 'not scheduled')}</span>
      </div>
    </Panel>
  );
}

function Row({ to, children }: { to: string; children: ReactNode }) {
  return <li><Link to={to} className="flex min-h-[44px] items-start gap-3 border-b border-rule px-3 py-2 hover:bg-raised">{children}</Link></li>;
}

function RecentChanges({ changes }: { changes: Change[] }) {
  const [showExpected, setShowExpected] = useState(false);
  const real = changes.filter((c) => !c.expected);
  const expected = changes.filter((c) => c.expected);
  const list = (showExpected ? [...real.slice(0, 7), ...expected] : real.slice(0, 7));
  return (
    <Panel title={t('Najnowsze zmiany', 'Recent changes')} count={real.length} flush actions={<Link to="/changes" className="link">{t('Dziennik zmian', 'Change log')}</Link>}>
      {real.length === 0 && expected.length === 0 ? <p className="p-3 text-sm text-ink-2">{t('Ostatni skan nie wykrył zmian.', 'The last scan found no change.')}</p> : null}
      <ul>
        {list.map((c) => (
          <Row key={c.id} to={c.service_id ? '/services/' + c.service_id : '/hosts/' + c.host_id}>
            <span className="mt-0.5"><Glyph name={c.expected ? 'dashring' : changeKindInfo(c.kind).glyph} tone={c.expected ? 'expected' : changeKindInfo(c.kind).tone} /></span>
            <span className="min-w-0 flex-1">
              <span className={cx('block text-sm', c.expected ? 'text-ink-2' : 'text-ink')}>{changeSummary(c)}</span>
              <span className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-ink-3">
                <span className="mono">{c.ip}{c.port ? ':' + c.port : ''}</span>
                {c.expected ? <span>{t('oczekiwana', 'expected')}</span> : <Sev level={c.severity} />}
              </span>
            </span>
          </Row>
        ))}
      </ul>
      {expected.length > 0 ? (
        <button type="button" onClick={() => setShowExpected((v) => !v)} aria-expanded={showExpected} className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs text-ink-2 hover:bg-raised hover:text-ink">
          <Glyph name="dashring" tone="expected" />
          {showExpected
            ? t('Zwiń zmiany oczekiwane', 'Fold the expected changes')
            : <>{expected.length} {plural(expected.length, ['zmiana zgodna', 'zmiany zgodne', 'zmian zgodnych'], ['change that fits', 'changes that fit'])} {t('z profilem dostępności hostów. Pokaż', 'the availability profile of the hosts. Show')}</>}
          <Icon name={showExpected ? 'chevronDown' : 'chevronRight'} size={12} />
        </button>
      ) : null}
    </Panel>
  );
}

function SafetyPanel({ st }: { st: Dash['safety'] }) {
  const { can } = useSession();
  return (
    <Panel title={t('Bezpieczeństwo skanowania', 'Scan safety')} actions={<Link to="/admin?tab=safety" className="link">{can('safety:manage') ? t('Polityka', 'Policy') : t('Podgląd polityki', 'View the policy')}</Link>}>
      <p className={cx('mb-2 flex items-center gap-2 text-sm font-medium', st.emergency_stop ? 'text-danger' : 'text-ink')}>
        <Icon name={st.emergency_stop ? 'stop' : 'shield'} className={st.emergency_stop ? '' : 'text-st-new'} />
        {st.emergency_stop ? t('Stop awaryjny aktywny', 'Emergency stop is active') : t('Skaner działa w trybie bezpiecznej detekcji', 'The scanner runs in safe-detection mode')}
      </p>
      <dl>
        <Stat label={t('Limit pakietów', 'Packet cap')} value={<>{fmtInt(st.max_pps)} <span className="font-sans text-xs font-normal text-ink-3">pps</span></>} />
        <Stat label={t('Limit żądań HTTP', 'HTTP request cap')} value={<>{st.max_http_rps} <span className="font-sans text-xs font-normal text-ink-3">{t('na s, ', 'per s, ')}{st.max_per_host_rps} {t('na host', 'per host')}</span></>} />
        <Stat label={t('Metody HTTP', 'HTTP methods')} value={(st.allowed_methods ?? []).join(', ')} />
        <Stat label={t('Wykluczenia', 'Exclusions')} value={(st.exclusions ?? []).length} />
        <Stat label={t('Stop awaryjny', 'Emergency stop')} value={<HostlessState on={st.emergency_stop} />} mono={false} />
      </dl>
    </Panel>
  );
}

interface Step { done: boolean; title: string; text: string; state?: string; to?: string; cta?: string; blocked?: string }

/** A fresh installation: no scan and no imported result yet. Says what to do next, in order. */
function FirstRun({ d }: { d: Dash }) {
  const { can } = useSession();
  const scopes = usePage<Scope>('/scopes', { limit: 1 }, can('targets:read'));
  const profiles = usePage<ScanProfile>('/profiles', { limit: 50 }, can('scans:read'));
  const health = useItem<{ engine?: boolean }>('/healthz', undefined, { staleTime: 60_000 });
  const addresses = d.headline.addresses_in_scope;
  const hasTargets = addresses > 0;
  const list = profiles.data?.items ?? [];
  const ready = list.find((p) => p.enabled && (p.scope_ids ?? []).length > 0);
  const first = list[0];
  const engineOff = health.data?.engine === false;
  const steps: Step[] = [
    {
      done: hasTargets,
      title: t('Dodaj cele', 'Add targets'),
      text: t('Utwórz zakres i wpisz sieci, które wolno skanować. Skaner nigdy nie wychodzi poza tę listę.', 'Create a scope and enter the networks that may be scanned. The scanner never leaves this list.'),
      state: hasTargets ? fmtInt(addresses) + ' ' + plural(addresses, ['adres w zakresie', 'adresy w zakresie', 'adresów w zakresie'], ['address in scope', 'addresses in scope']) : (scopes.data?.total ? t('zakres istnieje, brakuje w nim celów', 'a scope exists, it has no target yet') : undefined),
      to: '/targets', cta: can('targets:create') ? t('Otwórz cele', 'Open targets') : t('Zobacz cele', 'View targets'),
    },
    {
      done: Boolean(ready),
      title: t('Przygotuj profil skanu', 'Prepare a scan profile'),
      text: first && !ready
        ? t('Profil „' + first.name + '” jest gotowy. Przypisz mu zakres, ustaw tempo i okna czasowe.', 'The profile "' + first.name + '" is ready. Give it a scope, then set the rate and the time windows.')
        : t('Profil łączy zakresy z portami, tempem i oknami czasowymi.', 'A profile joins scopes with ports, rate and time windows.'),
      state: ready ? t('profil „' + ready.name + '” ma przypisany zakres', 'the profile "' + ready.name + '" has a scope') : undefined,
      to: can('scans:configure') ? (first ? '/profiles/' + first.id : '/profiles/new') : '/profiles',
      cta: can('scans:configure') ? t('Otwórz profil', 'Open the profile') : t('Zobacz profile', 'View profiles'),
    },
    {
      done: false,
      title: t('Uruchom pierwszy skan', 'Start the first scan'),
      text: t('Przebieg pokaże postęp na mapie przestrzeni adresowej. Po nim pulpit powie, co działa w sieci i co się zmieniło.', 'The run shows its progress on the address-space map. After it the dashboard says what is on the network and what changed.'),
      blocked: engineOff ? t('Silnik skanowania nie jest podłączony w tej instalacji. Zaimportuj wyniki z pliku.', 'The scan engine is not connected in this installation. Import results from a file.') : undefined,
      to: '/profiles', cta: can('scans:run') ? t('Przejdź do uruchomienia', 'Go to start') : undefined,
    },
  ];
  const next = steps.findIndex((s) => !s.done);
  return (
    <section aria-labelledby="first-run-title" data-testid="first-run">
      <h2 id="first-run-title" className="text-xl font-semibold tracking-[-0.015em]">{t('Czujka nie ma jeszcze danych o sieci.', 'Czujka has no data about the network yet.')}</h2>
      <p className="mt-2 max-w-[70ch] text-base text-ink-2">{t('Trzy kroki dzielą tę instalację od pierwszego obchodu. Każdy krok można wykonać teraz albo wrócić do niego później.', 'Three steps stand between this installation and its first watch. Do each step now or come back to it later.')}</p>
      {can('targets:create') && can('scans:configure') ? <p className="mt-2 text-sm"><Link to="/setup" className="link">{t('Albo przejdź wszystko w jednym kreatorze (około 2 minuty)', 'Or go through everything in one wizard (about 2 minutes)')}</Link></p> : null}
      <ol className="mt-4 border-y border-rule">
        {steps.map((s, i) => (
          <li key={s.title} className="grid grid-cols-[28px_minmax(0,1fr)] items-start gap-x-3 gap-y-2 border-b border-rule py-3 last:border-b-0 sm:grid-cols-[28px_minmax(0,1fr)_auto]">
            <span className={cx('num mt-px flex h-[22px] w-[22px] items-center justify-center border text-xs', s.done ? 'border-st-new text-st-new' : i === next ? 'border-accent text-ink' : 'border-rule-strong text-ink-3')} aria-hidden="true">
              {s.done ? <Icon name="check" size={12} /> : i + 1}
            </span>
            <div className="min-w-0">
              <p className={cx('text-sm font-medium', s.done ? 'text-ink-2' : 'text-ink')}>{s.title}<span className="sr-only">{s.done ? ' (' + t('zrobione', 'done') + ')' : ''}</span></p>
              <p className="mt-0.5 max-w-[72ch] text-sm text-ink-2">{s.text}</p>
              {s.state ? <p className="mt-1 text-xs text-ink-3">{s.state}</p> : null}
              {s.blocked ? <p className="mt-1 flex items-start gap-1.5 text-xs text-ink-2"><Icon name="info" size={12} className="mt-0.5 flex-none text-ink-3" />{s.blocked}</p> : null}
            </div>
            {s.cta && s.to ? (
              <Link to={s.to} className={cx('col-start-2 inline-flex h-[30px] items-center gap-1.5 justify-self-start whitespace-nowrap border px-3 text-sm sm:col-start-3 sm:justify-self-end', i === next && !s.blocked ? 'border-accent bg-accent font-medium text-accent-ink hover:bg-accent-strong' : 'border-rule-strong text-ink hover:bg-raised')}>
                {s.cta}<Icon name="arrowRight" size={12} />
              </Link>
            ) : null}
          </li>
        ))}
      </ol>
      {can('results:create') ? (
        <p className="mt-3 flex flex-wrap items-center gap-x-2 text-sm text-ink-2">
          <Icon name="upload" size={14} className="text-ink-3" />
          {t('Masz już wyniki z nmap? Nie potrzebujesz skanu:', 'You already have nmap results? No scan is needed:')}
          <Link to="/transfer" className="link">{t('zaimportuj plik XML', 'import the XML file')}</Link>
        </p>
      ) : null}
    </section>
  );
}

export default function Dashboard() {
  const { can } = useSession();
  const q = useItem<Dash>('/dashboard', undefined, { refetchInterval: 60_000 });
  const runs = usePage<ScanRun>('/runs', { limit: 100, status: 'completed', sort: '-id' }, can('scans:read'));
  const now = useNow();
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!q.data) return <div className="p-4 sm:p-6"><div className="skeleton mb-3 h-8 w-[min(520px,80%)]" /><div className="skeleton mb-6 h-4 w-[min(380px,60%)]" /><SkeletonRows rows={10} /></div>;
  const d = q.data;
  const pair = lastFullPair(runs.data?.items ?? []);
  void now;
  const st = d.safety;
  const h0 = d.headline;
  const fresh = !d.last_run && !d.active_run && h0.hosts_up + h0.hosts_down + h0.hosts_unstable + h0.services_open + h0.findings_open + h0.changes_unacked === 0;
  // A fresh installation with nothing configured leads the administrator into the first-run wizard once.
  const setupDone = (() => { try { return Boolean(localStorage.getItem(SETUP_DONE_KEY)); } catch { return true; } })();
  if (fresh && h0.addresses_in_scope === 0 && can('targets:create') && can('scans:configure') && !setupDone) return <Navigate to="/setup" replace />;
  if (fresh) {
    return (
      <div className="mx-auto max-w-[1480px] space-y-5 p-4 sm:p-6">
        <h1 className="sr-only">{t('Pulpit', 'Dashboard')}</h1>
        <div className="grid gap-x-10 gap-y-6 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
          <FirstRun d={d} />
          <div className="space-y-4">
            <SafetyPanel st={st} />
            <IdleRun d={d} />
          </div>
        </div>
        <p className="pb-2 text-2xs text-ink-3">{t('Stan na', 'As of')} {fmtDateTime(d.generated_at)}</p>
      </div>
    );
  }
  return (
    <div className="mx-auto max-w-[1480px] space-y-4 p-4 sm:p-6">
      <h1 className="sr-only">{t('Pulpit', 'Dashboard')}</h1>
      <div className="grid gap-x-10 gap-y-5 xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
        <Handover d={d} full={runs.data ? (pair.full ?? null) : undefined} />
        <Inventory d={d} pair={runs.data ? pair : undefined} />
      </div>

      {d.active_run ? <ActiveRun initial={d.active_run} d={d} /> : <IdleRun d={d} />}

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title={t('Najważniejsze znaleziska', 'Top findings')} flush actions={<Link to="/findings" className="link">{t('Wszystkie', 'All')}</Link>}>
          {(d.top_findings ?? []).length === 0 ? <p className="p-3 text-sm text-ink-2">{t('Brak otwartych znalezisk.', 'No open finding.')}</p> : null}
          <ul>
            {(d.top_findings ?? []).slice(0, 7).map((f) => (
              <Row key={f.id} to={'/findings?open=' + f.id}>
                <span className="mt-0.5"><Sev level={f.severity} compact /></span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm text-ink">{f.title}</span>
                  <span className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-ink-3">
                    <span className="mono">{f.ip}{f.port ? ':' + f.port : ''}</span>
                    {f.first_run_id === d.last_run?.id ? <span className="inline-flex items-center gap-1 text-ink-2"><Glyph name="plus" tone="new" size={10} />{t('od ostatniego skanu', 'since the last scan')}</span> : <span>{t('od', 'since')} {fmtRelative(f.first_seen)}</span>}
                  </span>
                </span>
                <span className="mt-0.5 flex-none"><InterestScore value={f.interest} /></span>
              </Row>
            ))}
          </ul>
        </Panel>

        <RecentChanges changes={d.recent_changes ?? []} />

        <Panel title={t('Najciekawsze usługi', 'Most interesting services')} flush actions={<Link to="/services?sort=-interest" className="link">{t('Eksplorator', 'Explorer')}</Link>}>
          <ul>
            {(d.top_services ?? []).slice(0, 7).map((s) => (
              <Row key={s.id} to={'/services/' + s.id}>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-ink">{s.title || s.product || serviceName(s)}</span>
                  <span className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-ink-3">
                    <span className="mono">{s.hostname || s.ip}:{s.port}</span>
                    <ClassChips classes={s.classes} max={2} />
                  </span>
                  {s.interest_why && s.interest_why.length ? <span className="mt-1 block truncate text-xs text-ink-2">{s.interest_why.slice(0, 2).map((r) => '+' + r.points + ' ' + r.text).join(' · ')}</span> : null}
                </span>
                <span className="mt-0.5 flex-none"><InterestScore value={s.interest} reasons={s.interest_why} /></span>
              </Row>
            ))}
          </ul>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title={t('Technologie', 'Technologies')} actions={<span className="text-ink-3">{t('liczba usług', 'services')}</span>}>
          <BarList items={(d.technologies ?? []).slice(0, 10)} href={(i) => '/services?tech=' + encodeURIComponent(i.name)} labelWidth={150} />
        </Panel>
        <Panel title={t('Otwarte porty', 'Open ports')} actions={<span className="text-ink-3">{t('liczba usług', 'services')}</span>}>
          <BarList items={(d.ports ?? []).slice(0, 10)} mono href={(i) => '/services?port=' + i.name} labelWidth={150} extra={(i) => i.extra} />
        </Panel>
        <Panel title={t('Trend w kolejnych skanach', 'Trend over runs')}>
          <TrendRows points={d.trend ?? []} series={[
            { key: 'hosts', label: t('aktywne hosty', 'hosts up') },
            { key: 'services', label: t('otwarte usługi', 'open services') },
            { key: 'changes', label: t('zmiany', 'changes') },
          ]} />
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="min-w-0 space-y-4">
        <Panel title={t('Hosty niestabilne', 'Unstable hosts')} count={d.headline.hosts_unstable} flush actions={<Link to="/hosts?status=unstable" className="link">{t('Wszystkie', 'All')}</Link>}>
          {(d.unstable_hosts ?? []).length === 0 ? <p className="p-3 text-sm text-ink-2">{t('Każdy znany host odpowiada zgodnie ze swoim profilem.', 'Every known host answers as its profile predicts.')}</p> : null}
          <ul>
            {(d.unstable_hosts ?? []).slice(0, 6).map((h) => (
              <li key={h.id}>
                <Link to={'/hosts/' + h.id} className="flex min-h-[30px] items-center gap-3 border-b border-rule px-3 py-1.5 hover:bg-raised">
                  <span className="mono w-[104px] flex-none text-sm">{h.ip}</span>
                  <span className="min-w-0 flex-1 truncate text-xs text-ink-2">{h.pattern}</span>
                  <span className="num flex-none text-xs text-ink-2" title={t('Prawdopodobieństwo, że host nadal istnieje', 'Probability that the host still exists')}>p {h.p_alive.toFixed(2)}</span>
                </Link>
              </li>
            ))}
          </ul>
        </Panel>
        <ReprobePanel limit={5} />
        </div>
        <Panel title={t('Wygasające certyfikaty', 'Expiring certificates')} count={(d.certs_expiring ?? []).length} flush>
          {(d.certs_expiring ?? []).length === 0 ? <p className="p-3 text-sm text-ink-2">{t('Żaden certyfikat nie wygasa w ciągu 30 dni.', 'No certificate expires within 30 days.')}</p> : null}
          <ul>
            {(d.certs_expiring ?? []).slice(0, 6).map((s) => {
              const days = s.latest?.result.tls?.days_left ?? 0;
              return (
                <li key={s.id}>
                  <Link to={'/services/' + s.id} className="flex min-h-[30px] items-center gap-3 border-b border-rule px-3 py-1.5 hover:bg-raised">
                    <span className="mono min-w-0 flex-1 truncate text-sm">{s.hostname || s.ip}:{s.port}</span>
                    <span className="inline-flex flex-none items-center gap-1.5 text-xs">
                      <Glyph name={days < 0 ? 'x' : 'delta'} tone={days < 0 ? 'gone' : days <= 7 ? 'changed' : 'expected'} size={12} />
                      <span className={days <= 7 ? 'text-ink' : 'text-ink-2'}>{days < 0 ? t('wygasł ' + Math.abs(days) + ' dni temu', 'expired ' + Math.abs(days) + ' days ago') : t('za ' + days + ' dni', 'in ' + days + ' days')}</span>
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </Panel>
        <SafetyPanel st={st} />
      </div>
      <p className="pb-2 text-2xs text-ink-3">{t('Stan na', 'As of')} {fmtDateTime(d.generated_at)}</p>
    </div>
  );
}

function HostlessState({ on }: { on: boolean }) {
  return on
    ? <span className="inline-flex items-center gap-1.5 text-sm"><Glyph name="x" tone="danger" />{t('aktywny', 'active')}</span>
    : <span className="inline-flex items-center gap-1.5 text-sm font-normal text-ink-2"><Glyph name="ring" tone="expected" />{t('nieaktywny', 'off')}</span>;
}

