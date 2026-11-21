import { useState, type ReactNode } from 'react';
import { Link, useParams } from 'react-router';
import { useAction, useItem, usePage } from '../api/hooks';
import { patch } from '../api/client';
import type { HTTPFingerprint, Service, ServiceObservation, SigMatch, TLSInfo } from '../api/types';
import { t, plural } from '../i18n';
import { cx, fmtBytes, fmtDate, fmtDateTime, fmtRelative, shortHash } from '../lib/format';
import { Button, Check, CopyText, ErrorState, KV, PageHeader, Panel, SkeletonRows, TagInput, Tags } from '../ui/kit';
import { Icon } from '../ui/Icon';
import { ClassChips, Confidence, Glyph, InterestBreakdown, InterestScore, SERVICE_CLASSES, ServiceStateMark, categoryLabel, classLabel } from '../ui/marks';
import { InlineText, OverrideNote } from '../ui/edit';
import { useCan } from '../session';
import { SuggestButton } from './Suggest';
import { ServiceHistoryPanel } from './TimeMachine';
import { ServiceStory, ResponseTimeChart } from '../ui/ServiceStory';
import { serviceName, isSelf } from '../lib/serviceName';
import { SelfTag } from '../ui/serviceBits';

function Flag({ on, label, bad }: { on: boolean; label: string; bad?: boolean }) {
  return (
    <span className={cx('inline-flex items-center gap-1 whitespace-nowrap text-xs', on ? 'text-ink' : bad ? 'text-ink' : 'text-ink-3')}>
      <Glyph name={on ? 'check' : bad ? 'x' : 'ring'} tone={on ? 'new' : bad ? 'gone' : 'expected'} size={11} />{on ? label : t('brak ', 'no ') + label}
    </span>
  );
}

function HttpPanel({ h, tls }: { h: HTTPFingerprint; tls: boolean }) {
  const [allHeaders, setAllHeaders] = useState(false);
  const headers = Object.entries(h.headers ?? {}).sort(([a], [b]) => a.localeCompare(b));
  const shown = allHeaders ? headers : headers.slice(0, 8);
  return (
    <div className="space-y-4">
      <dl className="grid gap-x-8 sm:grid-cols-2">
        <div>
          <KV k={t('Kod HTTP', 'Kod HTTP')}><span className="num font-medium">{h.status || '–'}</span>{h.error ? <span className="ml-2 text-xs text-danger">{h.error}</span> : null}</KV>
          <KV k={t('Tytuł', 'Title')}>{h.title || '–'}</KV>
          <KV k="URL" mono><span className="break-all">{h.final_url || h.url}</span></KV>
          <KV k="Server" mono>{h.server || '–'}</KV>
          {h.powered_by ? <KV k="X-Powered-By" mono>{h.powered_by}</KV> : null}
          {h.meta_generator ? <KV k="meta generator" mono>{h.meta_generator}</KV> : null}
        </div>
        <div>
          <KV k={t('Czas odpowiedzi', 'Response time')}><span className="num">{h.response_ms} ms</span></KV>
          <KV k={t('Rozmiar treści', 'Body size')}><span className="num">{fmtBytes(h.body_length)}</span></KV>
          <KV k="SHA-256" mono><CopyText text={h.body_sha256} className="text-xs" /></KV>
          <KV k="simhash" mono>{h.body_simhash || '–'}</KV>
          <KV k={t('Favicon (mmh3)', 'Favicon (mmh3)')} mono>{h.favicon_mmh3 ?? '–'}</KV>
        </div>
      </dl>

      {(h.redirects ?? []).length ? (
        <div>
          <h3 className="label mb-1.5">{t('Łańcuch przekierowań', 'Redirect chain')}</h3>
          <ol className="space-y-1">
            {(h.redirects ?? []).map((r, i) => (
              <li key={i} className="flex flex-wrap items-center gap-x-2 text-sm">
                <span className="num w-[34px] text-ink-2">{r.status}</span>
                <span className="mono break-all text-ink-2">{r.from}</span>
                <Icon name="arrowRight" size={12} className="text-ink-3" />
                <span className="mono break-all">{r.to}</span>
              </li>
            ))}
          </ol>
        </div>
      ) : null}

      <div>
        <h3 className="label mb-1.5">{t('Nagłówki odpowiedzi', 'Response headers')} <span className="num text-ink-3">{headers.length}</span></h3>
        {headers.length === 0 ? <p className="text-sm text-ink-3">–</p> : (
          <dl className="border-t border-rule">
            {shown.map(([k, v]) => (
              <div key={k} className="grid grid-cols-1 gap-x-4 border-b border-rule py-1 sm:grid-cols-[220px_minmax(0,1fr)]">
                <dt className="mono text-xs text-ink-2">{k}</dt>
                <dd className="mono break-all text-xs text-ink">{v.join(', ')}</dd>
              </div>
            ))}
          </dl>
        )}
        {headers.length > 8 ? <button type="button" className="link mt-1.5 text-xs" onClick={() => setAllHeaders((x) => !x)}>{allHeaders ? t('Pokaż mniej', 'Show less') : t('Pokaż wszystkie ' + headers.length, 'Show all ' + headers.length)}</button> : null}
      </div>

      <div>
        <h3 className="label mb-1.5">{t('Ciasteczka', 'Cookies')} <span className="num text-ink-3">{(h.cookies ?? []).length}</span></h3>
        {(h.cookies ?? []).length === 0 ? <p className="text-sm text-ink-3">{t('Brak ciasteczek.', 'No cookies.')}</p> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-rule-strong text-left text-xs text-ink-3"><th className="h-[26px] pr-4 font-medium">{t('Nazwa', 'Name')}</th><th className="pr-4 font-medium">{t('Flagi', 'Flags')}</th><th className="pr-4 font-medium">{t('Ścieżka', 'Path')}</th><th className="font-medium">{t('Wartość', 'Value')}</th></tr></thead>
              <tbody>
                {(h.cookies ?? []).map((c) => (
                  <tr key={c.name} className="border-b border-rule">
                    <td className="mono h-[30px] whitespace-nowrap pr-4">{c.name}</td>
                    <td className="pr-4"><span className="flex flex-wrap gap-x-3"><Flag on={c.secure} label="Secure" bad={tls} /><Flag on={c.http_only} label="HttpOnly" bad /><span className="whitespace-nowrap text-xs text-ink-2">SameSite={c.same_site || t('brak', 'none')}</span></span></td>
                    <td className="mono pr-4 text-xs text-ink-2">{c.path || '/'}</td>
                    <td className="mono whitespace-nowrap text-xs text-ink-2">{c.value !== undefined ? <span className="text-ink">{c.value.slice(0, 24)}{c.value.length > 24 ? '…' : ''}</span> : <span title={t('Wartości widzi rola z uprawnieniem do edycji wyników', 'A role that may edit results sees the values')}>{c.value_len} {t('zn.', 'chars')} · {shortHash(c.value_hash, 10)}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {(h.paths ?? []).length ? (
        <div>
          <h3 className="label mb-1.5">{t('Ścieżki sprawdzone dla sygnatur (GET)', 'Paths probed for signatures (GET)')}</h3>
          <ul className="border-t border-rule">
            {(h.paths ?? []).map((p) => (
              <li key={p.path} className="flex flex-wrap items-center gap-x-3 border-b border-rule py-1 text-sm">
                <span className="num w-[34px]" style={{ color: 'var(--ink-2)' }}>{p.status}</span>
                <span className="mono">{p.path}</span>
                <span className="truncate text-xs text-ink-3">{p.title || p.location}</span>
                <span className="num ml-auto text-xs text-ink-3">{fmtBytes(p.length)}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function TlsPanel({ c }: { c: TLSInfo }) {
  const state: [ReactNode, 'gone' | 'changed' | 'new'] = c.expired ? [t('wygasł ' + Math.abs(c.days_left) + ' dni temu', 'expired ' + Math.abs(c.days_left) + ' days ago'), 'gone'] : c.days_left <= 14 ? [t('wygasa za ' + c.days_left + ' dni', 'expires in ' + c.days_left + ' days'), 'changed'] : [t('ważny jeszcze ' + c.days_left + ' dni', 'valid for ' + c.days_left + ' more days'), 'new'];
  return (
    <div>
      <div className="mb-2 flex flex-wrap gap-x-5 gap-y-1 text-sm">
        <span className="inline-flex items-center gap-1.5"><Glyph name={state[1] === 'new' ? 'check' : state[1] === 'gone' ? 'x' : 'delta'} tone={state[1]} />{state[0]}</span>
        {c.self_signed ? <span className="inline-flex items-center gap-1.5"><Glyph name="delta" tone="changed" />{t('samopodpisany', 'self-signed')}</span> : null}
        {c.host_mismatch ? <span className="inline-flex items-center gap-1.5"><Glyph name="x" tone="gone" />{t('nazwa hosta nie pasuje do certyfikatu', 'the host name does not match the certificate')}</span> : null}
      </div>
      <dl className="grid gap-x-8 sm:grid-cols-2">
        <div>
          <KV k={t('Podmiot (CN)', 'Subject (CN)')} mono>{c.subject_cn}{c.subject_org ? <span className="ml-2 font-sans text-ink-3">{c.subject_org}</span> : null}</KV>
          <KV k={t('Wystawca', 'Issuer')}>{c.issuer}</KV>
          <KV k="SAN" mono><span className="break-all">{(c.sans ?? []).join(', ') || '–'}</span></KV>
          <KV k={t('Ważny', 'Valid')}><span className="num">{fmtDate(c.not_before)} – {fmtDate(c.not_after)}</span></KV>
        </div>
        <div>
          <KV k={t('Protokół', 'Protocol')} mono>{c.version}</KV>
          <KV k={t('Szyfr', 'Cipher')} mono><span className="break-all">{c.cipher}</span></KV>
          <KV k={t('Klucz', 'Key')} mono>{c.key_type} {c.key_bits}</KV>
          <KV k="SHA-256" mono><CopyText text={c.sha256} className="text-xs" /></KV>
        </div>
      </dl>
    </div>
  );
}

function TechList({ s, matches }: { s: Service; matches: SigMatch[] }) {
  const techs = s.technologies ?? [];
  if (techs.length === 0 && matches.length === 0) return <p className="text-sm text-ink-2">{t('Brak rozpoznanych technologii.', 'No technologies recognised.')}</p>;
  const rest = matches.filter((m) => !techs.some((x) => x.name === m.name));
  const row = (name: string, category: string, version: string, confidence: number, ms: SigMatch[], sources: string[] | null, cpe: string) => (
    <li key={name} className="border-b border-rule py-2 last:border-b-0">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="text-sm font-medium">{name}{version ? <span className="num ml-1.5 font-normal text-ink-2">{version}</span> : null}</span>
        <span className="text-xs text-ink-3">{categoryLabel(category)}</span>
        <span className="ml-auto flex items-center gap-2 text-xs text-ink-2">{t('pewność', 'confidence')} <Confidence value={confidence} width={48} /></span>
      </div>
      <ul className="mt-1 space-y-0.5">
        {ms.flatMap((m) => (m.evidence ?? []).map((e, i) => (
          <li key={m.signature + i} className="grid grid-cols-[64px_minmax(0,1fr)] gap-x-2 text-xs">
            <span className="text-ink-3">{e.matcher}</span>
            <span className="mono break-words"><span className="text-ink-2">{e.where}</span> <span className="text-ink">{e.snippet}</span></span>
          </li>
        )))}
        {ms.length === 0 ? <li className="text-xs text-ink-3">{t('źródło:', 'source:')} {(sources ?? []).join(', ') || 'nmap'}{cpe ? ' · ' + cpe : ''}</li> : null}
      </ul>
      {ms.length ? <div className="mt-1 text-2xs text-ink-3">{plural(ms.length, ['sygnatura', 'sygnatury', 'sygnatury'], ['signature', 'signatures'])}: {ms.map((m) => m.signature).join(', ')}{ms.length > 1 || (ms[0].evidence ?? []).length > 1 ? t(' · pewność łączona ze wszystkich dowodów', ' · confidence combined over all evidence') : ''}</div> : null}
    </li>
  );
  return (
    <ul>
      {techs.map((x) => row(x.name, x.category, x.version, x.confidence, matches.filter((m) => m.name === x.name), x.sources, x.cpe))}
      {rest.map((m) => row(m.name, m.category, m.version, m.confidence, [m], null, ''))}
    </ul>
  );
}

function ClassEditor({ s, onSave, onClose }: { s: Service; onSave: (c: string[]) => void; onClose: () => void }) {
  const [sel, setSel] = useState<string[]>(s.classes ?? []);
  return (
    <div className="mt-2 border border-rule p-2">
      <div className="grid grid-cols-2 gap-x-4 gap-y-1">
        {SERVICE_CLASSES.map((c) => <Check key={c} checked={sel.includes(c)} onChange={(v) => setSel(v ? [...sel, c] : sel.filter((x) => x !== c))} label={classLabel(c)} />)}
      </div>
      <div className="mt-2 flex gap-1.5"><Button size="sm" variant="primary" onClick={() => { onSave(sel); onClose(); }}>{t('Zapisz klasy', 'Save classes')}</Button><Button size="sm" variant="ghost" onClick={onClose}>{t('Anuluj', 'Cancel')}</Button></div>
    </div>
  );
}

export default function ServiceDetail() {
  const id = Number(useParams().id);
  const canEdit = useCan('results:update');
  const canSuggest = useCan('signatures:read');
  const q = useItem<Service>('/services/' + id);
  const obs = usePage<ServiceObservation>('/services/' + id + '/observations', { limit: 30 });
  const save = useAction((body: Record<string, unknown>) => patch<Service>('/services/' + id, body), { invalidate: ['/services', '/service-groups', '/hosts/'], success: t('Zapisano', 'Saved') });
  const [editClasses, setEditClasses] = useState(false);
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!q.data) return <SkeletonRows rows={12} />;
  const s = q.data;
  const r = s.latest?.result;
  const ov = s.overrides ?? {};
  return (
    <div>
      <PageHeader
        back={{ to: '/services', label: t('Usługi', 'Services') }}
        title={<span className="flex flex-wrap items-center gap-x-3 gap-y-1"><span className="mono text-[26px] font-medium tracking-[-0.01em] sm:text-[30px]">{s.ip}:{s.port}</span><span className="font-sans text-base font-normal"><ServiceStateMark state={s.state} /></span></span>}
        sub={<><Link to={'/hosts/' + s.host_id} className="link">{t('host', 'host')} <span className="mono">{s.hostname || s.ip}</span></Link> · {serviceName(s)}{isSelf(s) ? <SelfTag /> : null}{s.tls ? ' · TLS' : ''}{s.url ? <> · <a className="link mono inline-flex items-center gap-1" href={s.url} target="_blank" rel="noreferrer noopener">{s.url}<Icon name="external" size={11} /></a></> : null}</>}
        readOnly={!canEdit}
        actions={<span className="flex items-center gap-3 text-sm text-ink-2">{canSuggest ? <SuggestButton serviceId={s.id} /> : null}<span className="flex items-center gap-2">{t('Ciekawość', 'Interest')} <InterestScore value={s.interest} /></span></span>}
      />
      <div className="grid gap-4 p-4 sm:p-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,400px)]">
        <div className="min-w-0 space-y-4">
          <ServiceStory s={s} />
          {r?.http || s.name === 'http' || s.name === 'https' ? <ResponseTimeChart serviceId={s.id} /> : null}
          <Panel title={t('Identyfikacja', 'Identification')} actions={<span className="flex items-center gap-2 text-ink-2">{t('pewność', 'confidence')} <Confidence value={s.confidence} width={48} /></span>}>
            <dl>
              <KV k={t('Usługa', 'Service')}>
                <InlineText label={t('Usługa', 'Service')} mono value={s.name} canEdit={canEdit} onSave={(v) => save.mutate({ name: v })} />
                <OverrideNote o={ov.name} canEdit={canEdit} onRevert={() => save.mutate({ name: null })} />
              </KV>
              <KV k={t('Produkt', 'Product')}>
                <InlineText label={t('Produkt', 'Product')} value={s.product} canEdit={canEdit} placeholder={t('nie rozpoznano', 'not recognised')} onSave={(v) => save.mutate({ product: v })} />
                <OverrideNote o={ov.product} canEdit={canEdit} onRevert={() => save.mutate({ product: null })} />
              </KV>
              <KV k={t('Wersja', 'Version')}>
                <InlineText label={t('Wersja', 'Version')} mono value={s.version} canEdit={canEdit} placeholder="–" onSave={(v) => save.mutate({ version: v })} />
                <OverrideNote o={ov.version} canEdit={canEdit} onRevert={() => save.mutate({ version: null })} />
              </KV>
              <KV k={t('Klasy', 'Classes')}>
                <span className="flex flex-wrap items-center gap-2"><ClassChips classes={s.classes} max={8} />{(s.classes ?? []).length === 0 ? <span className="text-ink-3">–</span> : null}
                  {canEdit && !editClasses ? <button type="button" className="link text-xs" onClick={() => setEditClasses(true)}>{t('Zmień', 'Change')}</button> : null}</span>
                {editClasses ? <ClassEditor s={s} onSave={(c) => save.mutate({ classes: c })} onClose={() => setEditClasses(false)} /> : null}
                <OverrideNote o={ov.classes} canEdit={canEdit} onRevert={() => save.mutate({ classes: null })} />
              </KV>
              {s.banner ? <KV k={t('Baner', 'Banner')} mono><span className="break-all text-xs">{s.banner}</span></KV> : null}
              {r?.cpe?.length ? <KV k="CPE" mono><span className="break-all text-xs">{r.cpe.join(', ')}</span></KV> : null}
              <KV k={t('Pierwsza obserwacja', 'First seen')}><span className="num">{fmtDateTime(s.first_seen)}</span></KV>
              <KV k={t('Ostatnia obserwacja', 'Last seen')}><span className="num">{fmtDateTime(s.last_seen)}</span> <span className="text-ink-3">{fmtRelative(s.last_seen)}</span></KV>
              {s.last_changed ? <KV k={t('Ostatnia zmiana', 'Last change')}><span className="num">{fmtDateTime(s.last_changed)}</span></KV> : null}
            </dl>
          </Panel>

          {r?.http ? <Panel title="HTTP"><HttpPanel h={r.http} tls={s.tls} /></Panel> : s.name === 'http' ? <Panel title="HTTP"><p className="text-sm text-ink-2">{t('Brak danych HTTP z ostatniego skanu.', 'No HTTP data from the last scan.')}</p></Panel> : null}
          {r?.tls ? <Panel title={t('Certyfikat TLS', 'TLS certificate')}><TlsPanel c={r.tls} /></Panel> : null}

          <ServiceHistoryPanel serviceId={s.id} />
          <Panel title={t('Historia obserwacji', 'Observation history')} count={obs.data?.total} flush>
            {obs.error ? <ErrorState error={obs.error} retry={() => obs.refetch()} /> : !obs.data ? <SkeletonRows rows={4} /> : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-rule-strong text-left text-xs text-ink-3"><th className="h-[30px] px-3 font-medium">{t('Skan', 'Scan')}</th><th className="px-3 font-medium">{t('Czas', 'Time')}</th><th className="px-3 font-medium">{t('Stan', 'Status')}</th><th className="px-3 font-medium">HTTP</th><th className="px-3 font-medium">{t('Tytuł', 'Title')}</th><th className="px-3 font-medium">{t('Produkt', 'Product')}</th><th className="px-3 font-medium">{t('Treść', 'Body')}</th></tr></thead>
                  <tbody>
                    {obs.data.items.map((o, i) => {
                      const prev = obs.data!.items[i + 1]?.result;
                      const ch = (a: unknown, b: unknown) => prev !== undefined && a !== b;
                      const hi = 'bg-st-changed-wash';
                      return (
                        <tr key={o.id} className="border-b border-rule last:border-b-0">
                          <td className="h-[30px] px-3"><Link to={'/runs/' + o.run_id} className="num link">#{o.run_id}</Link></td>
                          <td className="num whitespace-nowrap px-3 text-ink-2">{fmtDateTime(o.at)}</td>
                          <td className={cx('px-3', ch(o.result.state, prev?.state) && hi)}>{o.result.state}</td>
                          <td className={cx('num px-3', ch(o.result.http?.status, prev?.http?.status) && hi)}>{o.result.http?.status ?? '–'}</td>
                          <td className={cx('max-w-[260px] truncate px-3', ch(o.result.http?.title, prev?.http?.title) && hi)}>{o.result.http?.title ?? '–'}</td>
                          <td className={cx('whitespace-nowrap px-3 text-ink-2', ch(o.result.product + o.result.version, (prev?.product ?? '') + (prev?.version ?? '')) && hi)}>{[o.result.product, o.result.version].filter(Boolean).join(' ') || '–'}</td>
                          <td className={cx('mono px-3 text-xs text-ink-3', ch(o.result.http?.body_sha256, prev?.http?.body_sha256) && hi)}>{shortHash(o.result.http?.body_sha256, 8) || '–'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            {obs.data && obs.data.items.length > 1 ? <p className="border-t border-rule px-3 py-1.5 text-2xs text-ink-3"><span className="mr-1.5 inline-block h-[9px] w-[9px] bg-st-changed-wash align-middle" style={{ boxShadow: 'inset 0 0 0 1px var(--st-changed)' }} />{t('pole różni się od starszej obserwacji', 'the field differs from the older observation')}</p> : null}
          </Panel>
        </div>

        <div className="min-w-0 space-y-4">
          <Panel title={t('Ocena ciekawości', 'Interest score')}><InterestBreakdown value={s.interest} reasons={s.interest_why} /></Panel>
          <Panel title={t('Technologie i dowody', 'Technologies and evidence')} count={(s.technologies ?? []).length}><TechList s={s} matches={r?.matches ?? []} /></Panel>
          <Panel title={t('Opis analityka', 'Analyst notes')}>
            <dl>
              <KV k={t('Tagi', 'Tags')}>{canEdit ? <TagInput value={s.tags ?? []} onChange={(v) => save.mutate({ tags: v })} placeholder={t('dodaj tag', 'add a tag')} /> : <Tags tags={s.tags} max={12} />}</KV>
              <KV k={t('Notatka', 'Note')}><InlineText label={t('Notatka', 'Note')} multiline value={s.note} canEdit={canEdit} placeholder={t('brak notatki', 'no note')} onSave={(v) => save.mutate({ note: v })} /></KV>
            </dl>
          </Panel>
          {s.group_size > 1 ? (
            <Panel title={t('Podobne usługi', 'Similar services')}>
              <p className="text-sm text-ink-2">{t('Ta sama treść strony i zestaw technologii na ', 'The same page content and technology set on ')}<span className="num text-ink">{s.group_size}</span> {plural(s.group_size, ['usłudze', 'usługach', 'usługach'], ['service', 'services'])}.</p>
              <Link to={'/services?group_key=' + encodeURIComponent(s.group_key)} className="link mt-1 inline-block text-sm">{t('Pokaż całą grupę', 'Show the group')}</Link>
            </Panel>
          ) : null}
        </div>
      </div>
    </div>
  );
}
