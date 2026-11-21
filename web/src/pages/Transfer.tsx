import { useRef, useState } from 'react';
import { Link } from 'react-router';
import { useAction, usePage } from '../api/hooks';
import { download, qs, upload, type Query } from '../api/client';
import type { ImportReport, ScanRun } from '../api/types';
import { t } from '../i18n';
import { fmtBytes, fmtDateTime, fmtInt } from '../lib/format';
import { Button, Field, InlineError, KV, PageHeader, Panel, Select, toast, toastError } from '../ui/kit';
import { FINDING_STATUSES, Glyph, HOST_STATUSES, findingStatusInfo, hostStatusInfo } from '../ui/marks';
import { useSession } from '../session';
import { NoAccess } from '../shell/Layout';

type Kind = 'hosts' | 'services' | 'findings' | 'changes';

function ExportRow({ kind, title, hint, filter, runs }: { kind: Kind; title: string; hint: string; filter: { key: string; label: string; options: { value: string; label: string }[] }; runs?: boolean }) {
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState('');
  void runs;
  const run = async (fmt: 'csv' | 'json') => {
    setBusy(fmt);
    try {
      const q: Query = value ? { [filter.key]: value } : {};
      const size = await download('/export/' + kind + '.' + fmt + qs(q), 'czujka-' + kind + '.' + fmt);
      toast(t('Pobrano czujka-' + kind + '.' + fmt + ' (' + fmtBytes(size) + ')', 'Downloaded czujka-' + kind + '.' + fmt + ' (' + fmtBytes(size) + ')'));
    } catch (e) { toastError(e); }
    setBusy('');
  };
  return (
    <li className="grid gap-x-4 gap-y-2 border-b border-rule py-3 last:border-b-0 md:grid-cols-[minmax(0,1fr)_200px_auto] md:items-end">
      <div>
        <div className="text-sm font-medium">{title}</div>
        <div className="text-xs text-ink-3">{hint} <Link to={'/' + kind} className="link">{t('Więcej filtrów na liście', 'More filters on the list')}</Link></div>
      </div>
      <label className="block"><span className="label mb-1 block">{filter.label}</span><Select value={value} onChange={setValue} options={[{ value: '', label: t('wszystko', 'everything') }, ...filter.options]} /></label>
      <div className="flex gap-1.5">
        <Button icon="download" busy={busy === 'csv'} onClick={() => run('csv')}>CSV</Button>
        <Button icon="download" busy={busy === 'json'} onClick={() => run('json')}>JSON</Button>
      </div>
    </li>
  );
}

export default function Transfer() {
  const { can } = useSession();
  const canImport = can('results:create');
  const canExport = can('export:run');
  const runs = usePage<ScanRun>('/runs', { limit: 100, status: 'completed' }, canExport);
  const [file, setFile] = useState<File | null>(null);
  const [report, setReport] = useState<ImportReport | null>(null);
  const [runId, setRunId] = useState('');
  const [xmlBusy, setXmlBusy] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const imp = useAction((f: File) => { const fd = new FormData(); fd.append('file', f); return upload<ImportReport>('/import/results', fd); }, {
    invalidate: ['/runs', '/hosts', '/services', '/dashboard'], silent: true,
    onSuccess: (r) => { setReport(r); setFile(null); if (input.current) input.current.value = ''; },
  });
  if (!canImport && !canExport) return <NoAccess />;
  const runOpts = (runs.data?.items ?? []).map((r) => ({ value: String(r.id), label: '#' + r.id + ' · ' + fmtDateTime(r.finished_at) }));
  const chosenRun = runId || runOpts[0]?.value || '';
  const nmapXml = async () => {
    setXmlBusy(true);
    try { const size = await download('/export/runs/' + chosenRun + '.xml', 'czujka-run-' + chosenRun + '.xml'); toast(t('Pobrano plik nmap XML (' + fmtBytes(size) + ')', 'Downloaded the nmap XML file (' + fmtBytes(size) + ')')); } catch (e) { toastError(e); }
    setXmlBusy(false);
  };
  return (
    <div>
      <PageHeader title={t('Import i eksport', 'Import and export')} sub={t('Wczytaj wyniki z innego skanera albo wynieś dane Czujki do arkusza, skryptu lub DefectDojo.', 'Load results of another scanner, or take Czujka data to a spreadsheet, a script or DefectDojo.')} readOnly={!canImport} />
      <div className="grid gap-4 p-4 sm:p-6 xl:grid-cols-2">
        <Panel title={t('Import wyników', 'Import results')}>
          {canImport ? (
            <div className="space-y-3">
              <Field label={t('Plik z wynikami', 'Result file')} hint={t('nmap XML (-oX), JSON Czujki albo CSV z kolumnami ip, port, proto, usługa. Import tworzy osobny przebieg i przechodzi przez tę samą analizę zmian co skan.', 'nmap XML (-oX), Czujka JSON or a CSV with the columns ip, port, proto, service. An import makes its own run and goes through the same change analysis as a scan.')}>
                <input ref={input} type="file" accept=".xml,.json,.csv,text/xml,application/json,text/csv" className="field py-1" onChange={(e) => { setFile(e.target.files?.[0] ?? null); setReport(null); }} />
              </Field>
              <Button variant="primary" icon="upload" busy={imp.isPending} disabled={!file} onClick={() => file && imp.mutate(file)}>{t('Importuj wyniki', 'Import the results')}</Button>
              <InlineError error={imp.error} />
              {report ? (
                <div className="border border-rule p-3" data-testid="import-report">
                  <p className="flex items-center gap-2 text-sm font-medium"><Glyph name={report.skipped ? 'delta' : 'check'} tone={report.skipped ? 'changed' : 'new'} />{report.skipped ? t('Import zakończony, część wierszy pominięto', 'The import finished, some rows were skipped') : t('Import zakończony', 'The import finished')}</p>
                  <dl className="mt-2">
                    <KV k={t('Rozpoznany format', 'Detected format')} mono>{report.format}</KV>
                    <KV k={t('Hosty', 'Hosts')}><span className="num">{fmtInt(report.hosts)}</span></KV>
                    <KV k={t('Usługi', 'Services')}><span className="num">{fmtInt(report.services)}</span></KV>
                    <KV k={t('Pominięte wiersze', 'Skipped rows')}><span className="num">{fmtInt(report.skipped)}</span></KV>
                    {report.run_id ? <KV k={t('Przebieg', 'Run')}><Link className="num link" to={'/runs/' + report.run_id}>#{report.run_id}</Link></KV> : null}
                  </dl>
                  {(report.invalid ?? []).length ? (
                    <ul className="mt-2 max-h-[140px] overflow-auto border-t border-rule">
                      {(report.invalid ?? []).map((l) => <li key={l.line} className="grid grid-cols-[64px_minmax(0,1fr)] gap-x-2 border-b border-rule py-1 text-xs"><span className="num text-ink-3">{t('wiersz', 'line')} {l.line}</span><span><span className="mono">{l.value}</span> <span className="text-danger">{l.reason}</span></span></li>)}
                    </ul>
                  ) : null}
                </div>
              ) : null}
            </div>
          ) : <p className="text-sm text-ink-2">{t('Twoja rola nie może importować wyników (uprawnienie results:create).', 'Your role cannot import results (the results:create permission).')}</p>}
        </Panel>

        <Panel title={t('Eksport danych', 'Export data')}>
          {canExport ? (
            <>
              <ul>
                <ExportRow kind="hosts" title={t('Hosty', 'Hosts')} hint={t('Inwentarz z etykietami, właścicielami i stanem.', 'The inventory with labels, owners and status.')} filter={{ key: 'status', label: t('Stan', 'Status'), options: HOST_STATUSES.map((s) => ({ value: s, label: hostStatusInfo(s).label })) }} />
                <ExportRow kind="services" title={t('Usługi', 'Services')} hint={t('Porty, produkty, technologie, klasy, ciekawość.', 'Ports, products, technologies, classes, interest.')} filter={{ key: 'state', label: t('Stan', 'State'), options: [{ value: 'open', label: t('otwarte', 'open') }, { value: 'gone', label: t('zniknęły', 'gone') }] }} />
                <ExportRow kind="findings" title={t('Znaleziska', 'Findings')} hint={t('Ze statusem, wagą, notatkami i odnośnikiem do DefectDojo.', 'With status, severity, notes and the DefectDojo link.')} filter={{ key: 'status', label: t('Status', 'Status'), options: FINDING_STATUSES.map((s) => ({ value: s, label: findingStatusInfo(s).label })) }} />
                <ExportRow kind="changes" title={t('Zmiany', 'Changes')} hint={t('Dziennik różnic między skanami.', 'The log of differences between runs.')} filter={{ key: 'run_id', label: t('Skan', 'Run'), options: runOpts }} />
              </ul>
              <div className="mt-3 grid gap-x-4 gap-y-2 border-t border-rule-strong pt-3 md:grid-cols-[minmax(0,1fr)_200px_auto] md:items-end">
                <div>
                  <div className="text-sm font-medium">{t('Przebieg jako nmap XML', 'A run as nmap XML')}</div>
                  <div className="text-xs text-ink-3">{t('Format, który DefectDojo przyjmuje jako „Nmap Scan”.', 'The format that DefectDojo accepts as "Nmap Scan".')}</div>
                </div>
                <label className="block"><span className="label mb-1 block">{t('Skan', 'Run')}</span><Select value={chosenRun} onChange={setRunId} options={runOpts} /></label>
                <Button icon="download" busy={xmlBusy} disabled={!chosenRun} onClick={nmapXml}>XML</Button>
              </div>
            </>
          ) : <p className="text-sm text-ink-2">{t('Twoja rola nie może eksportować danych (uprawnienie export:run).', 'Your role cannot export data (the export:run permission).')}</p>}
        </Panel>
      </div>
    </div>
  );
}
