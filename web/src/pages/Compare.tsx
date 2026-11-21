import { Link } from 'react-router';
import { useItem, usePage } from '../api/hooks';
import type { Change, DiffReport, ScanRun } from '../api/types';
import { t, plural } from '../i18n';
import { fmtDateTime, fmtDuration, fmtInt, fmtSigned } from '../lib/format';
import { useUrlState } from '../lib/hooks';
import { Check, Empty, ErrorState, PageHeader, Select, SkeletonRows } from '../ui/kit';
import { Icon } from '../ui/Icon';
import { Glyph, Sev, changeKindInfo, type GlyphName, type Tone } from '../ui/marks';
import { BeforeAfter } from './Changes';

function RunCard({ run, side }: { run: ScanRun; side: string }) {
  return (
    <div className="min-w-0 flex-1 border border-rule bg-panel px-3 py-2">
      <div className="text-xs text-ink-3">{side}</div>
      <div className="mt-0.5 flex flex-wrap items-baseline gap-x-2"><Link to={'/runs/' + run.id} className="num link text-base font-medium">#{run.id}</Link><span className="truncate text-sm text-ink-2">{run.profile_name}</span></div>
      <div className="num mt-0.5 text-xs text-ink-2">{fmtDateTime(run.finished_at ?? run.started_at)} · {fmtDuration(run.stats.elapsed_sec)}</div>
      <div className="mt-1 text-xs text-ink-2"><span className="num text-ink">{fmtInt(run.stats.hosts_up)}</span> {t('hostów', 'hosts')} · <span className="num text-ink">{fmtInt(run.stats.services_open)}</span> {t('usług', 'services')}</div>
    </div>
  );
}

function Column({ title, glyph, tone, items, showExpected }: { title: string; glyph: GlyphName; tone: Tone; items: Change[]; showExpected: boolean }) {
  const real = items.filter((c) => !c.expected);
  const expected = items.filter((c) => c.expected);
  const list = showExpected ? [...real, ...expected] : real;
  return (
    <section className="min-w-0 border border-rule bg-panel">
      <h2 className="flex h-[36px] items-center gap-2 border-b border-rule-strong px-3 text-sm font-semibold">
        <Glyph name={glyph} tone={tone} />{title}<span className="num font-normal text-ink-2">{real.length}</span>
        {expected.length ? <span className="ml-auto inline-flex items-center gap-1 text-xs font-normal text-ink-3"><Glyph name="dashring" tone="expected" size={11} />{expected.length} {t('oczekiw.', 'expected')}</span> : null}
      </h2>
      {list.length === 0 ? <p className="p-3 text-sm text-ink-3">{expected.length ? t('Tylko zmiany oczekiwane.', 'Expected changes only.') : t('Brak.', 'None.')}</p> : (
        <ul className="max-h-[560px] overflow-auto">
          {list.map((c) => (
            <li key={c.id} className="border-b border-rule px-3 py-2 last:border-b-0">
              <div className="flex items-start justify-between gap-2">
                <Link to={c.service_id ? '/services/' + c.service_id : '/hosts/' + c.host_id} className="mono link text-sm">{c.ip}{c.port ? ':' + c.port : ''}</Link>
                {c.expected ? <span className="inline-flex flex-none items-center gap-1 text-xs text-ink-3"><Glyph name="dashring" tone="expected" size={11} />{t('oczekiwana', 'expected')}</span> : <span className="flex-none"><Sev level={c.severity} /></span>}
              </div>
              <div className={c.expected ? 'mt-0.5 text-sm text-ink-2' : 'mt-0.5 text-sm'}>{c.summary}</div>
              <div className="text-xs text-ink-3">{changeKindInfo(c.kind).label}</div>
              <BeforeAfter c={c} />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export default function Compare() {
  const u = useUrlState();
  const runs = usePage<ScanRun>('/runs', { limit: 100, status: 'completed', sort: '-id' });
  const list = runs.data?.items ?? [];
  const to = u.get('to') || (list[0] ? String(list[0].id) : '');
  const toRun = list.find((r) => String(r.id) === to);
  const prevId = toRun?.summary?.prev_run_id;
  const from = u.get('from') || (prevId ? String(prevId) : list.find((r) => String(r.id) !== to) ? String(list.find((r) => String(r.id) !== to)!.id) : '');
  const showExpected = u.get('expected') === '1';
  const ready = Boolean(from && to && from !== to);
  const diff = useItem<DiffReport>('/diff', { from, to }, { enabled: ready });
  const opts = list.map((r) => ({ value: String(r.id), label: '#' + r.id + ' · ' + fmtDateTime(r.finished_at) + ' · ' + r.profile_name }));
  const d = diff.data;
  const all = d?.changes ?? [];
  const group = (g: string) => all.filter((c) => changeKindInfo(c.kind).group === g || (g === 'changed' && changeKindInfo(c.kind).group === 'unstable'));
  return (
    <div>
      <PageHeader back={{ to: '/changes', label: t('Zmiany', 'Changes') }} title={t('Porównanie dwóch skanów', 'Compare two runs')} sub={t('Co pojawiło się, zniknęło i zmieniło między dowolnymi dwoma zakończonymi przebiegami.', 'What appeared, disappeared and changed between any two completed runs.')} />
      <div className="space-y-4 p-4 sm:p-6">
        <div className="flex flex-wrap items-end gap-3">
          <label className="block min-w-[240px] flex-1"><span className="label mb-1 block">{t('Starszy skan (przed)', 'Older run (before)')}</span><Select value={from} onChange={(v) => u.set({ from: v })} options={opts} /></label>
          <button type="button" className="mb-0.5 inline-flex h-[30px] w-[30px] items-center justify-center border border-rule-strong hover:bg-raised" aria-label={t('Zamień skany miejscami', 'Swap the runs')} onClick={() => u.set({ from: to, to: from })}><Icon name="compare" /></button>
          <label className="block min-w-[240px] flex-1"><span className="label mb-1 block">{t('Nowszy skan (po)', 'Newer run (after)')}</span><Select value={to} onChange={(v) => u.set({ to: v })} options={opts} /></label>
          <div className="pb-1.5"><Check checked={showExpected} onChange={(v) => u.set({ expected: v ? '1' : null })} label={t('Pokaż zmiany oczekiwane', 'Show expected changes')} /></div>
        </div>
        {runs.isPending ? <SkeletonRows rows={6} /> : list.length < 2 ? (
          <Empty icon="compare" title={t('Do porównania potrzeba dwóch zakończonych skanów', 'A comparison needs two completed runs')} hint={t('Uruchom kolejny skan albo zaimportuj wyniki z pliku.', 'Start another scan or import results from a file.')} />
        ) : !ready ? (
          <Empty icon="compare" title={t('Wybierz dwa różne skany', 'Choose two different runs')} />
        ) : diff.error ? <ErrorState error={diff.error} retry={() => diff.refetch()} /> : !d ? <SkeletonRows rows={8} /> : (
          <>
            <div className="flex flex-col items-stretch gap-3 sm:flex-row sm:items-center">
              <RunCard run={d.from} side={t('Przed', 'Before')} />
              <div className="flex flex-none flex-col items-center px-1 text-xs text-ink-2">
                <Icon name="arrowRight" className="hidden text-ink-3 sm:block" />
                <span className="num">{fmtSigned(d.to.stats.hosts_up - d.from.stats.hosts_up)} {t('hostów', 'hosts')}</span>
                <span className="num">{fmtSigned(d.to.stats.services_open - d.from.stats.services_open)} {t('usług', 'services')}</span>
              </div>
              <RunCard run={d.to} side={t('Po', 'After')} />
            </div>
            <div className="flex flex-col text-sm text-ink-2">
              {all.length === 0 ? t('Między tymi skanami nie zapisano żadnej zmiany.', 'No change was recorded between these runs.') : (
                <span><span className="num text-ink">{all.filter((c) => !c.expected).length}</span> {plural(all.filter((c) => !c.expected).length, ['zmiana wymaga', 'zmiany wymagają', 'zmian wymaga'], ['change needs', 'changes need'])} {t('przeglądu', 'review')}, <span className="num text-ink">{all.filter((c) => c.expected).length}</span> {t('oczekiwanych', 'expected')}. {t('Nowych znalezisk:', 'New findings:')} <span className="num text-ink">{d.summary.findings_new}</span>.</span>
              )}
              {d.summary.hosts_missing ? (
                <span className="mt-1 flex items-start gap-1.5 text-ink-2" data-testid="compare-missing">
                  <Glyph name="half" tone="expected" />
                  <span><span className="num text-ink">{d.summary.hosts_missing}</span> {plural(d.summary.hosts_missing, ['host nie odpowiedział', 'hosty nie odpowiedziały', 'hostów nie odpowiedziało'], ['host did not answer', 'hosts did not answer'])}{t(', ale nie jest jeszcze uznany za nieaktywny', ' but is not reported inactive yet')}{d.summary.services_unreachable ? <>{t('; ich ', '; their ')}<span className="num text-ink">{d.summary.services_unreachable}</span> {plural(d.summary.services_unreachable, ['usługa jest nieosiągalna', 'usługi są nieosiągalne', 'usług jest nieosiągalnych'], ['service is unreachable', 'services are unreachable'])}{t(' (stan nieznany, nie zamknięte)', ' (unknown, not closed)')}</> : null}. {t('Lista w kolumnie „Zmienione”.', 'They are listed under "Changed".')}</span>
                </span>
              ) : null}
            </div>
            <div className="grid gap-4 lg:grid-cols-3">
              <Column title={t('Nowe', 'New')} glyph="plus" tone="new" items={group('new')} showExpected={showExpected} />
              <Column title={t('Zniknęły', 'Gone')} glyph="minus" tone="gone" items={group('gone')} showExpected={showExpected} />
              <Column title={t('Zmienione', 'Changed')} glyph="delta" tone="changed" items={group('changed')} showExpected={showExpected} />
            </div>
          </>
        )}
      </div>
    </div>
  );
}
