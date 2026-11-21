import { useEffect, useState, type ReactNode } from 'react';
import { useNavigate, useParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { useAction, useItem, usePage } from '../api/hooks';
import { del, patch, post } from '../api/client';
import type { DiscoveryMode, Health, SafetyPolicy, ScanEstimate, ScanProfile, Scope } from '../api/types';
import { t } from '../i18n';
import { cx, fmtCompact, fmtDuration, fmtInt, fmtPct } from '../lib/format';
import { Button, Check, Dialog, ErrorState, Field, InlineError, PageHeader, SkeletonRows } from '../ui/kit';
import { Icon } from '../ui/Icon';
import { Glyph } from '../ui/marks';
import { WindowPicker } from '../viz/WindowPicker';
import { useCan } from '../session';

/** The traffic budget of a saved profile: what a run will send, how long it takes and whether it fits the window. */
export function EstimateBox({ profileId, stale }: { profileId: number; stale?: boolean }) {
  const q = useQuery<ScanEstimate>({ queryKey: ['/profiles/' + profileId + '/estimate'], queryFn: () => post<ScanEstimate>('/profiles/' + profileId + '/estimate'), staleTime: 5_000 });
  const profile = useItem<ScanProfile>('/profiles/' + profileId);
  if (q.error) return <InlineError error={q.error} />;
  if (!q.data) return <div className="skeleton h-[120px]" />;
  const e = q.data;
  const asked = profile.data?.rate.max_pps ?? e.effective_pps;
  const capped = asked > e.effective_pps;
  const hasWindow = e.window_sec > 0;
  // The server gives window_sec 0 when it is called outside the window; the profile still has windows.
  const windowsSet = (profile.data?.schedule.windows ?? []).length > 0;
  const ratio = hasWindow ? e.est_duration_sec / e.window_sec : 0;
  return (
    <div className={cx('border border-rule', stale && 'opacity-60')} data-testid="estimate">
      <div className={cx('flex items-start gap-2 border-b border-rule px-3 py-2 text-sm', hasWindow && !e.fits_window && 'bg-st-changed-wash')}>
        <Glyph name={!hasWindow || e.fits_window ? 'check' : 'delta'} tone={!hasWindow || e.fits_window ? 'new' : 'changed'} />
        <span>
          {!hasWindow
            ? windowsSet ? t('Okno czasowe jest teraz zamknięte. Skan potrwa około ', 'The time window is closed now. A scan takes about ') : t('Profil nie ma okna czasowego. Skan potrwa około ', 'The profile has no time window. A scan takes about ')
            : e.fits_window ? t('Skan mieści się w oknie: około ', 'The scan fits the window: about ') : t('Skan nie mieści się w jednym oknie: około ', 'The scan does not fit one window: about ')}
          <span className="num font-medium">{fmtDuration(e.est_duration_sec)}</span>
          {hasWindow ? <>{t('\u00a0z\u00a0', '\u00a0of\u00a0')}<span className="num">{fmtDuration(e.window_sec)}</span>{t('\u00a0okna', '\u00a0window')}</> : null}.
          {hasWindow && !e.fits_window ? ' ' + t('Zostanie wstrzymany na końcu okna i dokończony w następnym.', 'It is paused at the end of the window and finished in the next one.') : ''}
        </span>
      </div>
      {hasWindow ? (
        <div className="border-b border-rule px-3 py-2">
          <div className="relative h-[8px] bg-raised" aria-hidden="true">
            <div className="h-full" style={{ width: Math.min(100, (ratio / Math.max(1, ratio)) * 100) + '%', background: e.fits_window ? 'var(--accent)' : 'var(--st-changed)' }} />
            <div className="absolute -bottom-1 -top-1 w-[2px] bg-ink" style={{ left: 'calc(' + Math.min(100, (1 / Math.max(1, ratio)) * 100) + '% - 1px)' }} />
          </div>
          <div className="mt-1 flex justify-between text-2xs text-ink-3"><span>{t('czas skanu', 'scan time')}</span><span>{t('kreska: koniec okna', 'tick: end of the window')}</span></div>
        </div>
      ) : null}
      <dl className="grid grid-cols-2 gap-x-4 px-3 py-1 sm:grid-cols-3">
        {([
          [t('Adresy', 'Addresses'), fmtInt(e.addresses)],
          [t('Podgrupy', 'Chunks'), fmtInt(e.chunks)],
          [t('Pakiety (szac.)', 'Packets (est.)'), fmtCompact(e.est_packets)],
          [t('Efektywne tempo', 'Effective rate'), fmtInt(e.effective_pps) + ' pps'],
          [t('Oczekiwane hosty', 'Expected live'), fmtPct(e.expected_live_rate, 1)],
          [t('Podstawa', 'Basis'), e.based_on_history ? t('pomiar z poprzednich skanów', 'measured in earlier runs') : t('model, brak historii', 'model, no history')],
        ] as [string, string][]).map(([k, v]) => (
          <div key={k} className="border-b border-rule py-1.5 last:border-b-0">
            <dt className="text-2xs text-ink-3">{k}</dt>
            <dd className="num text-sm text-ink">{v}</dd>
          </div>
        ))}
      </dl>
      <FullRangeNote e={e} ports={profile.data?.ports ?? ''} />
      {capped ? <p className="flex items-start gap-1.5 border-t border-rule px-3 py-2 text-xs text-ink-2"><Icon name="shield" size={14} className="mt-px text-st-new" />{t('Profil prosi o ' + fmtInt(asked) + ' pps. Polityka bezpieczeństwa ogranicza tempo do ' + fmtInt(e.effective_pps) + ' pps.', 'The profile asks for ' + fmtInt(asked) + ' pps. The safety policy holds the rate at ' + fmtInt(e.effective_pps) + ' pps.')}</p> : null}
      {stale ? <p className="border-t border-rule px-3 py-2 text-xs text-ink-3">{t('Budżet dotyczy zapisanej wersji profilu. Zapisz zmiany, aby go przeliczyć.', 'The budget describes the saved profile. Save the changes to recompute it.')}</p> : null}
    </div>
  );
}

/** A ranked port list (top-N) or 1-65535: the engine may add the full range on a small scope. */
const rankedPorts = (spec: string) => /top-\d+/i.test(spec) || /(^|[\s,])1-65535($|[\s,])/.test(spec);

/**
 * The automatic full port range, described only from what the estimate says:
 * full_range_max_hosts (> 0: the run gets it), full_range_max_addresses (the
 * scope-size trigger), full_range_ports and est_full_range_sec_per_host.
 * Without a per-host time from the API the note shows no time.
 */
function FullRangeNote({ e, ports }: { e: ScanEstimate; ports: string }) {
  const maxHosts = e.full_range_max_hosts ?? 0;
  const maxAddr = e.full_range_max_addresses;
  const perHost = e.est_full_range_sec_per_host;
  if (maxHosts <= 0) {
    if (maxAddr && e.addresses > maxAddr && rankedPorts(ports)) {
      return <p className="border-t border-rule px-3 py-2 text-xs text-ink-2" data-testid="full-range-note">{t('Pełny zakres portów 1-65535 nie obejmie tego zakresu: ma ' + fmtInt(e.addresses) + ' adresów, a działa do ' + fmtInt(maxAddr) + '. Skan sprawdzi tylko porty z listy.', 'The full port range 1-65535 does not apply here: the scope has ' + fmtInt(e.addresses) + ' addresses and it works up to ' + fmtInt(maxAddr) + '. The scan checks only the listed ports.')}</p>;
    }
    return null;
  }
  const portsText = e.full_range_ports ? t(' (' + fmtInt(e.full_range_ports) + ' portów na host)', ' (' + fmtInt(e.full_range_ports) + ' ports per host)') : '';
  const scopeText = maxAddr ? t(' Dotyczy zakresów do ' + fmtInt(maxAddr) + ' adresów.', ' It applies to scopes of up to ' + fmtInt(maxAddr) + ' addresses.') : '';
  return (
    <div className="border-t border-rule px-3 py-2 text-xs text-ink-2" data-testid="full-range-note">
      <p><span className="font-medium text-ink">{t('Pełny zakres portów, automatycznie.', 'Full port range, automatic.')}</span> {t('Najpierw porty z listy: ich usługi pojawiają się w trakcie skanu. Potem Czujka sprawdza resztę 1-65535' + portsText + ' na aktywnych hostach, najwyżej na ' + fmtInt(maxHosts) + '. Wynik jest ostateczny dopiero po drugim etapie.', 'First the listed ports: their services show while the scan runs. Then Czujka checks the rest of 1-65535' + portsText + ' on the live hosts, at most ' + fmtInt(maxHosts) + '. The result is final only after the second pass.')}{scopeText}</p>
      {perHost && perHost > 0 ? (
        <p className="mt-1">{t('Drugi etap trwa około ', 'The second pass takes about ')}<span className="num text-ink">{fmtDuration(perHost)}</span>{t(' dla 1 hosta i około ', ' for 1 host and about ')}<span className="num text-ink">{fmtDuration(perHost * maxHosts)}</span>{t(' dla ' + fmtInt(maxHosts) + ' hostów, przy tempie ' + fmtInt(e.effective_pps) + ' pps. Czas skanu powyżej już go wlicza.', ' for ' + fmtInt(maxHosts) + ' hosts, at ' + fmtInt(e.effective_pps) + ' pps. The scan time above already counts it.')}</p>
      ) : null}
    </div>
  );
}

function Num({ value, onChange, min = 0, max, step = 1, suffix, disabled }: { value: number; onChange: (v: number) => void; min?: number; max?: number; step?: number; suffix?: string; disabled?: boolean }) {
  return (
    <span className="relative block">
      <input type="number" className={cx('field num', suffix && 'pr-12')} value={Number.isFinite(value) ? value : 0} min={min} max={max} step={step} disabled={disabled} onChange={(e) => onChange(e.target.value === '' ? 0 : Number(e.target.value))} />
      {suffix ? <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-xs text-ink-3">{suffix}</span> : null}
    </span>
  );
}
const portList = (v: number[]) => v.join(', ');
const parsePorts = (s: string) => s.split(/[\s,]+/).map(Number).filter((n) => n > 0 && n < 65536);

function blank(): ScanProfile {
  return {
    id: 0, name: '', description: '', scope_ids: [], ports: 'top-1000',
    discovery: { icmp_echo: true, icmp_timestamp: false, tcp_syn_ports: [22, 80, 443], tcp_ack_ports: [80], arp: false, skip_discovery: false, mode: 'balanced' },
    service_detection: true, version_intensity: 5,
    udp: { enabled: false, ports: '' },
    http: { enabled: true, max_redirects: 5, signature_paths: true, max_body_bytes: 262144, timeout_ms: 8000, favicon: true },
    rate: { max_pps: 500, max_parallel_chunks: 2, max_parallel_hosts: 16, http_rps: 10, per_host_concurrency: 2, per_host_delay_ms: 250 },
    chunking: { adaptive: true, initial_size: 256, min_size: 64, max_size: 2048, target_seconds: 90 },
    retry: { unstable_retries: 2, backoff_ms: 1500, down_after_misses: 0 },
    schedule: { enabled: false, cron: '0 22 * * *', interval_minutes: 0, windows: [], timezone: 'Europe/Warsaw' },
    enabled: true, next_run_at: null, last_run_id: null, created_at: '', updated_at: '',
  };
}

/** Fields that older profiles or older servers leave out get the server defaults. */
function withDefaults(p: ScanProfile): ScanProfile {
  p.discovery = { ...p.discovery, mode: p.discovery.mode || 'balanced' };
  p.udp = { enabled: p.udp?.enabled ?? false, ports: p.udp?.ports ?? '' };
  p.retry = { ...p.retry, down_after_misses: p.retry.down_after_misses ?? 0 };
  return p;
}

const UDP_ALLOW = '53,123,137,161,500,1900,5353';

/** The request body. UDP off with no ports is the server default, so it is left out: a server that does not know the field yet still saves the profile. */
function profileBody(p: ScanProfile): Partial<ScanProfile> {
  return p;
}

function discoveryModes(): { id: DiscoveryMode; label: string; text: string }[] {
  return [
    { id: 'fast', label: t('Szybki', 'Fast'), text: t('Jedna tania próba (ICMP echo i SYN do portów WWW) na każdy adres; pełny zestaw prób tylko do hostów znanych z inwentarza. Najkrótszy czas. Przy wysokim tempie może przeoczyć nowe hosty, które nie odpowiadają na te próby.', 'One cheap probe pass (ICMP echo and SYN to the web ports) to every address; the full probe set only to hosts the inventory knows. Shortest time. At high rates it can miss new hosts that do not answer these probes.') },
    { id: 'balanced', label: t('Zrównoważony', 'Balanced'), text: t('Ta sama pierwsza próba na każdy adres, potem pełny zestaw prób do cichych adresów każdego bloku /24, w którym coś odpowiedziało albo inwentarz zna host. Domyślny.', 'The same first pass to every address, then the full probe set to the silent addresses of every /24 block where a host answered or the inventory knows one. The default.') },
    { id: 'thorough', label: t('Dokładny', 'Thorough'), text: t('Pełny zestaw prób na każdy adres. Najdłuższy czas i najwięcej pakietów; nie przeoczy hosta, który odpowiada na którąkolwiek próbę.', 'The full probe set to every address. Longest time and the most packets; it does not miss a host that answers any probe.') },
  ];
}

function Section({ title, hint, children }: { title: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <section className="grid gap-x-8 gap-y-3 border-b border-rule py-5 lg:grid-cols-[220px_minmax(0,1fr)]">
      <div>
        <h2 className="text-sm font-semibold">{title}</h2>
        {hint ? <p className="mt-1 text-xs text-ink-3">{hint}</p> : null}
      </div>
      <div className="min-w-0">{children}</div>
    </section>
  );
}

export default function ProfileEdit() {
  const params = useParams();
  const isNew = !params.id;
  const id = Number(params.id ?? 0);
  const navigate = useNavigate();
  const canEdit = useCan('scans:configure');
  const q = useItem<ScanProfile>('/profiles/' + id, undefined, { enabled: !isNew });
  const scopes = usePage<Scope>('/scopes', { limit: 200 });
  const safety = useItem<SafetyPolicy>('/settings/safety');
  const health = useItem<Health>('/healthz', undefined, { staleTime: 60_000 });
  const [p, setP] = useState<ScanProfile | null>(isNew ? blank() : null);
  const [dirty, setDirty] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  useEffect(() => { if (q.data && !dirty) setP(withDefaults(structuredClone(q.data))); }, [q.data]); // eslint-disable-line react-hooks/exhaustive-deps
  const save = useAction((p: ScanProfile) => { const body = profileBody(p); return isNew ? post<ScanProfile>('/profiles', body) : patch<ScanProfile>('/profiles/' + id, body); }, {
    invalidate: ['/profiles'], silent: true, success: t('Profil zapisany', 'Profile saved'),
    onSuccess: (saved) => { setDirty(false); if (isNew) navigate('/profiles/' + saved.id, { replace: true }); },
  });
  const remove = useAction(() => del('/profiles/' + id), { invalidate: ['/profiles'], success: t('Profil usunięty', 'Profile deleted'), onSuccess: () => navigate('/profiles') });

  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!p) return <SkeletonRows rows={12} />;
  const ro = !canEdit;
  const up = (fn: (d: ScanProfile) => void) => { const next = structuredClone(p); fn(next); setP(next); setDirty(true); };
  const policyCap = safety.data?.max_pps ?? 0;
  const mode = p.schedule.interval_minutes > 0 ? 'interval' : 'cron';
  const invalid = !p.name.trim() ? t('Podaj nazwę profilu.', 'Give the profile a name.') : p.scope_ids.length === 0 ? t('Wybierz co najmniej jeden zakres.', 'Choose at least one scope.') : !p.ports.trim() ? t('Podaj porty.', 'Give the ports.') : p.chunking.min_size > p.chunking.max_size ? t('Najmniejsza podgrupa jest większa od największej.', 'The smallest chunk is larger than the largest.') : policyCap && p.rate.max_pps > policyCap ? t('Tempo ' + fmtInt(p.rate.max_pps) + ' pps przekracza limit polityki bezpieczeństwa (' + fmtInt(policyCap) + ' pps).', 'The rate of ' + fmtInt(p.rate.max_pps) + ' pps is above the safety policy cap (' + fmtInt(policyCap) + ' pps).') : '';

  return (
    <div>
      <PageHeader
        back={{ to: '/profiles', label: t('Profile skanów', 'Scan profiles') }}
        title={isNew ? t('Nowy profil skanu', 'New scan profile') : p.name || t('Profil', 'Profile')}
        sub={t('Profil mówi, co skanować, jak szybko i kiedy. Może być tylko ostrzejszy niż polityka bezpieczeństwa.', 'A profile says what to scan, how fast and when. It can only be stricter than the safety policy.')}
        readOnly={ro}
        actions={ro ? null : (
          <>
            {!isNew ? <Button variant="danger" icon="trash" onClick={() => setConfirmDelete(true)}>{t('Usuń', 'Delete')}</Button> : null}
            <Button variant="primary" icon="check" busy={save.isPending} disabled={Boolean(invalid) || (!dirty && !isNew)} onClick={() => save.mutate(p)}>{t('Zapisz profil', 'Save the profile')}</Button>
          </>
        )}
      />
      <fieldset disabled={ro} className="min-w-0 px-4 pb-10 sm:px-6">
        {invalid && dirty ? <p className="mt-3 text-xs text-danger">{invalid}</p> : null}
        <div className="mt-1"><InlineError error={save.error} /></div>

        <Section title={t('Zakres', 'Scope')} hint={t('Skan obejmuje włączone cele wybranych zakresów.', 'A scan covers the enabled targets of the chosen scopes.')}>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label={t('Nazwa', 'Name')}><input className="field" value={p.name} onChange={(e) => up((d) => { d.name = e.target.value; })} /></Field>
            <Field label={t('Opis', 'Description')}><input className="field" value={p.description} onChange={(e) => up((d) => { d.description = e.target.value; })} /></Field>
          </div>
          <div className="mt-3 space-y-1.5">
            <span className="label block">{t('Zakresy', 'Scopes')}</span>
            {(scopes.data?.items ?? []).map((s) => (
              <Check key={s.id} checked={p.scope_ids.includes(s.id)} disabled={ro} onChange={(v) => up((d) => { d.scope_ids = v ? [...d.scope_ids, s.id] : d.scope_ids.filter((x) => x !== s.id); })}
                label={<span>{s.name} <span className="num text-xs text-ink-3">{fmtInt(s.address_count)} {t('adresów', 'addresses')}</span></span>} />
            ))}
          </div>
          <div className="mt-3"><Check checked={p.enabled} disabled={ro} onChange={(v) => up((d) => { d.enabled = v; })} label={t('Profil aktywny', 'Profile enabled')} /></div>
        </Section>

        <Section title={t('Porty i wykrywanie', 'Ports and discovery')} hint={t('Wykrywanie hostów działa przed skanem portów. Port spoza listy dozwolonych w polityce jest pomijany.', 'Host discovery runs before the port scan. A port outside the policy allow-list is skipped.')}>
          <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto]">
            <Field label={t('Porty (składnia nmap)', 'Ports (nmap syntax)')} hint={t('np. top-1000 albo 22,80,443,8000-8100. Lista top-N albo 1-65535 na małym zakresie: najpierw najczęstsze porty, potem reszta 1-65535 na aktywnych hostach (szczegóły w budżecie ruchu). Jawna lista portów jest skanowana dokładnie tak, jak wpisana.', 'for example top-1000 or 22,80,443,8000-8100. A top-N list or 1-65535 on a small scope: the top ports first, then the rest of 1-65535 on the live hosts (details in the traffic budget). An explicit port list is scanned exactly as written.')}>
              <input className="field mono" value={p.ports} onChange={(e) => up((d) => { d.ports = e.target.value; })} />
            </Field>
            <div className="flex items-end gap-1.5 pb-[22px]">
              {['top-100', 'top-1000', '1-65535'].map((x) => <Button key={x} size="sm" onClick={() => up((d) => { d.ports = x; })} className={p.ports === x ? 'border-accent' : ''}><span className="mono">{x}</span></Button>)}
            </div>
          </div>
          <div className="mt-4" role="radiogroup" aria-label={t('Tryb wykrywania hostów', 'Host discovery mode')} data-testid="discovery-mode">
            <span className="label mb-1.5 block">{t('Tryb wykrywania hostów', 'Host discovery mode')}</span>
            <div className="grid gap-px border border-rule bg-rule sm:grid-cols-3">
              {discoveryModes().map((m) => {
                const on = (p.discovery.mode || 'balanced') === m.id;
                return (
                  <button key={m.id} type="button" role="radio" aria-checked={on} disabled={ro}
                    onClick={() => up((d) => { d.discovery.mode = m.id; })}
                    className={cx('relative bg-panel px-3 py-2 text-left outline-offset-[-2px]', on ? 'bg-raised' : 'hover:bg-raised/60')}>
                    {on ? <span className="absolute inset-x-0 top-0 h-[2px] bg-accent" aria-hidden="true" /> : null}
                    <span className="flex items-center gap-1.5 text-sm font-medium"><span className={cx('inline-block size-2 rounded-full border', on ? 'border-accent bg-accent' : 'border-ink-3')} aria-hidden="true" />{m.label}</span>
                    <span className="mt-1 block text-xs text-ink-3">{m.text}</span>
                  </button>
                );
              })}
            </div>
            {p.discovery.mode === 'fast' && p.rate.max_pps > 1000 ? <p className="mt-1.5 flex items-start gap-1.5 text-xs text-st-changed"><Glyph name="delta" tone="changed" size={12} />{t('Tryb szybki przy ' + fmtInt(p.rate.max_pps) + ' pps: przy tak wysokim tempie część hostów może nie odpowiedzieć na jedyną próbę. Dla pierwszego skanu sieci wybierz tryb zrównoważony.', 'Fast mode at ' + fmtInt(p.rate.max_pps) + ' pps: at a rate this high some hosts may not answer the single probe. For the first scan of a network choose balanced.')}</p> : null}
          </div>
          <div className="mt-3 grid gap-x-6 gap-y-2 sm:grid-cols-2">
            <Check checked={p.discovery.icmp_echo} disabled={ro} onChange={(v) => up((d) => { d.discovery.icmp_echo = v; })} label="ICMP echo" />
            <Check checked={p.discovery.icmp_timestamp} disabled={ro} onChange={(v) => up((d) => { d.discovery.icmp_timestamp = v; })} label="ICMP timestamp" />
            <Check checked={p.discovery.arp} disabled={ro} onChange={(v) => up((d) => { d.discovery.arp = v; })} label={t('ARP (tylko sieć lokalna)', 'ARP (local network only)')} />
            <Check checked={p.discovery.skip_discovery} disabled={ro} onChange={(v) => up((d) => { d.discovery.skip_discovery = v; })} label={t('Pomiń wykrywanie (-Pn)', 'Skip discovery (-Pn)')} hint={t('każdy adres traktowany jak aktywny; wolne', 'every address is treated as up; slow')} />
          </div>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <Field label={t('Porty TCP SYN do wykrywania', 'TCP SYN discovery ports')}><input className="field mono" defaultValue={portList(p.discovery.tcp_syn_ports)} key={'syn' + q.dataUpdatedAt} onBlur={(e) => up((d) => { d.discovery.tcp_syn_ports = parsePorts(e.target.value); })} /></Field>
            <Field label={t('Porty TCP ACK do wykrywania', 'TCP ACK discovery ports')}><input className="field mono" defaultValue={portList(p.discovery.tcp_ack_ports)} key={'ack' + q.dataUpdatedAt} onBlur={(e) => up((d) => { d.discovery.tcp_ack_ports = parsePorts(e.target.value); })} /></Field>
          </div>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <Check checked={p.service_detection} disabled={ro} onChange={(v) => up((d) => { d.service_detection = v; })} label={t('Identyfikacja usług (nmap -sV)', 'Service detection (nmap -sV)')} />
            <Field label={t('Intensywność wersji (0–9)', 'Version intensity (0–9)')}><Num value={p.version_intensity} min={0} max={9} disabled={!p.service_detection} onChange={(v) => up((d) => { d.version_intensity = Math.max(0, Math.min(9, v)); })} /></Field>
          </div>
        </Section>

        <Section title="UDP" hint={t('Opcjonalny skan UDP wysyła tylko nieszkodliwe zapytania protokołów z krótkiej listy (DNS, NTP, NetBIOS, SNMP, IKE, SSDP, mDNS). Wymaga nmap z surowymi gniazdami.', 'The optional UDP scan sends only harmless protocol queries from a short list (DNS, NTP, NetBIOS, SNMP, IKE, SSDP, mDNS). It needs nmap with raw sockets.')}>
          <Check checked={p.udp.enabled} disabled={ro} onChange={(v) => up((d) => { d.udp.enabled = v; })} label={t('Skanuj wybrane usługi UDP', 'Scan the selected UDP services')} />
          <div className={cx('mt-3 grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto]', !p.udp.enabled && 'opacity-60')}>
            <Field label={t('Porty UDP (podzbiór listy)', 'UDP ports (a subset of the list)')} hint={<>{t('puste: cała lista ', 'empty: the whole list ')}<span className="mono">{UDP_ALLOW}</span></>}>
              <input className="field mono" value={p.udp.ports} placeholder={UDP_ALLOW} disabled={!p.udp.enabled} onChange={(e) => up((d) => { d.udp.ports = e.target.value; })} />
            </Field>
          </div>
          {p.udp.enabled && health.data?.probe && !health.data.probe.raw_sockets ? (
            <p className="mt-2 flex items-start gap-1.5 text-xs text-st-changed"><Glyph name="delta" tone="changed" size={12} />{t('Ta instalacja skanuje bez surowych gniazd (tryb ' + health.data.probe.mode + '). Skan UDP zostanie pominięty.', 'This installation scans without raw sockets (mode ' + health.data.probe.mode + '). The UDP scan will be skipped.')}</p>
          ) : null}
        </Section>

        <Section title="HTTP / TLS" hint={t('Kolektor wysyła wyłącznie GET i HEAD. Nie loguje się i nie wysyła danych.', 'The collector sends GET and HEAD only. It never logs in and never sends data.')}>
          <div className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
            <Check checked={p.http.enabled} disabled={ro} onChange={(v) => up((d) => { d.http.enabled = v; })} label={t('Zbieraj dane HTTP i TLS', 'Collect HTTP and TLS data')} />
            <Check checked={p.http.signature_paths} disabled={ro || !p.http.enabled} onChange={(v) => up((d) => { d.http.signature_paths = v; })} label={t('Pobieraj ścieżki z sygnatur', 'Fetch the paths that signatures ask for')} hint={safety.data ? t('najwyżej ' + safety.data.max_paths_per_host + ' na usługę (polityka)', 'at most ' + safety.data.max_paths_per_host + ' per service (policy)') : undefined} />
            <Check checked={p.http.favicon} disabled={ro || !p.http.enabled} onChange={(v) => up((d) => { d.http.favicon = v; })} label={t('Pobieraj faviconę (hash)', 'Fetch the favicon (hash)')} />
          </div>
          <div className="mt-3 grid gap-3 sm:grid-cols-3">
            <Field label={t('Przekierowania', 'Redirects')}><Num value={p.http.max_redirects} max={20} disabled={!p.http.enabled} onChange={(v) => up((d) => { d.http.max_redirects = v; })} /></Field>
            <Field label={t('Limit treści', 'Body limit')}><Num value={Math.round(p.http.max_body_bytes / 1024)} suffix="kB" disabled={!p.http.enabled} onChange={(v) => up((d) => { d.http.max_body_bytes = v * 1024; })} /></Field>
            <Field label={t('Limit czasu', 'Timeout')}><Num value={p.http.timeout_ms} step={500} suffix="ms" disabled={!p.http.enabled} onChange={(v) => up((d) => { d.http.timeout_ms = v; })} /></Field>
          </div>
        </Section>

        <Section title={t('Tempo', 'Rate')} hint={policyCap ? t('Twardy limit polityki bezpieczeństwa: ' + fmtInt(policyCap) + ' pps. Profil nie może go przekroczyć.', 'Hard cap of the safety policy: ' + fmtInt(policyCap) + ' pps. A profile cannot go above it.') : undefined}>
          <div className="grid gap-3 sm:grid-cols-3">
            <Field label={t('Pakiety na sekundę', 'Packets per second')} hint={policyCap && p.rate.max_pps > policyCap ? <span className="text-danger">{t('powyżej limitu polityki: ' + fmtInt(policyCap) + ' pps', 'above the policy cap: ' + fmtInt(policyCap) + ' pps')}</span> : undefined}><Num value={p.rate.max_pps} min={1} suffix="pps" onChange={(v) => up((d) => { d.rate.max_pps = v; })} /></Field>
            <Field label={t('Równoległe podgrupy', 'Parallel chunks')}><Num value={p.rate.max_parallel_chunks} min={1} max={32} onChange={(v) => up((d) => { d.rate.max_parallel_chunks = v; })} /></Field>
            <Field label={t('Równoległe hosty (usługi, HTTP)', 'Parallel hosts (services, HTTP)')}><Num value={p.rate.max_parallel_hosts} min={1} onChange={(v) => up((d) => { d.rate.max_parallel_hosts = v; })} /></Field>
            <Field label={t('Żądania HTTP na sekundę', 'HTTP requests per second')}><Num value={p.rate.http_rps} min={0.1} step={0.5} suffix="rps" onChange={(v) => up((d) => { d.rate.http_rps = v; })} /></Field>
            <Field label={t('Połączenia na host', 'Connections per host')}><Num value={p.rate.per_host_concurrency} min={1} max={8} onChange={(v) => up((d) => { d.rate.per_host_concurrency = v; })} /></Field>
            <Field label={t('Odstęp na host', 'Delay per host')}><Num value={p.rate.per_host_delay_ms} step={50} suffix="ms" onChange={(v) => up((d) => { d.rate.per_host_delay_ms = v; })} /></Field>
          </div>
        </Section>

        <Section title={t('Podgrupy adresów', 'Address chunks')} hint={t('Rozmiar kolejnej podgrupy wynika ze zmierzonego czasu poprzedniej: celem jest stały czas jednej podgrupy.', 'The size of the next chunk follows the measured time of the previous one: the aim is a steady time per chunk.')}>
          <Check checked={p.chunking.adaptive} disabled={ro} onChange={(v) => up((d) => { d.chunking.adaptive = v; })} label={t('Rozmiar adaptacyjny', 'Adaptive size')} />
          <div className="mt-3 grid gap-3 sm:grid-cols-4">
            <Field label={t('Pierwsze podgrupy', 'First chunks')}><Num value={p.chunking.initial_size} min={1} suffix={t('adr.', 'addr.')} onChange={(v) => up((d) => { d.chunking.initial_size = v; })} /></Field>
            <Field label={t('Najmniejsza', 'Smallest')}><Num value={p.chunking.min_size} min={1} suffix={t('adr.', 'addr.')} disabled={!p.chunking.adaptive} onChange={(v) => up((d) => { d.chunking.min_size = v; })} /></Field>
            <Field label={t('Największa', 'Largest')}><Num value={p.chunking.max_size} min={1} suffix={t('adr.', 'addr.')} disabled={!p.chunking.adaptive} onChange={(v) => up((d) => { d.chunking.max_size = v; })} /></Field>
            <Field label={t('Docelowy czas', 'Target time')}><Num value={p.chunking.target_seconds} min={5} suffix="s" disabled={!p.chunking.adaptive} onChange={(v) => up((d) => { d.chunking.target_seconds = v; })} /></Field>
          </div>
        </Section>

        <Section title={t('Hosty niestabilne', 'Unstable hosts')} hint={t('Znany host, który nie odpowiada, dostaje dodatkowe próby, zanim skan zapisze brak odpowiedzi.', 'A known host that does not answer gets extra probes before the scan records a miss.')}>
          <div className="grid gap-3 sm:grid-cols-3">
            <Field label={t('Dodatkowe próby', 'Extra probes')}><Num value={p.retry.unstable_retries} max={10} onChange={(v) => up((d) => { d.retry.unstable_retries = v; })} /></Field>
            <Field label={t('Odstęp między próbami', 'Backoff')}><Num value={p.retry.backoff_ms} step={250} suffix="ms" onChange={(v) => up((d) => { d.retry.backoff_ms = v; })} /></Field>
            <Field label={t('Zgłoś nieaktywność po N brakach odpowiedzi', 'Report inactive after N misses')} hint={p.retry.down_after_misses === 0 ? t('0: decyduje model dostępności hosta', '0: the host availability model decides') : t('host zgłoszony jako nieaktywny po ' + p.retry.down_after_misses + ' brakach z rzędu, niezależnie od modelu', 'the host is reported inactive after ' + p.retry.down_after_misses + ' misses in a row, whatever the model says')}>
              <Num value={p.retry.down_after_misses} min={0} max={50} onChange={(v) => up((d) => { d.retry.down_after_misses = Math.max(0, v); })} />
            </Field>
          </div>
          <p className="mt-2 text-xs text-ink-3">{t('Host, który odpowiadał w poprzednim skanie i milczy teraz, trafia najpierw do „brak odpowiedzi”. Jego usługi są wtedy nieosiągalne, nie zamknięte. Zniknięcie hosta zgłaszamy dopiero według tej reguły.', 'A host that answered in the previous run and is silent now first goes to "missing". Its services are then unreachable, not closed. We report the host gone only under this rule.')}</p>
        </Section>

        <Section title={t('Harmonogram i okna czasowe', 'Schedule and time windows')} hint={t('Skan, który nie zmieści się w oknie, zostaje wstrzymany na jego końcu i wznowiony w następnym.', 'A scan that does not fit its window is paused at the end and resumed in the next one.')}>
          <Check checked={p.schedule.enabled} disabled={ro} onChange={(v) => up((d) => { d.schedule.enabled = v; })} label={t('Uruchamiaj cyklicznie', 'Run on a schedule')} />
          <div className={cx('mt-3 grid gap-3 sm:grid-cols-3', !p.schedule.enabled && 'opacity-60')}>
            <Field label={t('Częstotliwość', 'Frequency')}>
              <select className="field" value={mode} disabled={!p.schedule.enabled} onChange={(e) => up((d) => { if (e.target.value === 'interval') { d.schedule.interval_minutes = 240; d.schedule.cron = ''; } else { d.schedule.interval_minutes = 0; d.schedule.cron = '0 22 * * *'; } })}>
                <option value="cron">{t('wyrażenie cron', 'cron expression')}</option>
                <option value="interval">{t('co N minut w oknach', 'every N minutes inside the windows')}</option>
              </select>
            </Field>
            {mode === 'cron' ? (
              <Field label="Cron" hint={t('min godz dzień mies dzień_tyg', 'min hour day month weekday')}>
                <input className="field mono" value={p.schedule.cron} disabled={!p.schedule.enabled} onChange={(e) => up((d) => { d.schedule.cron = e.target.value; })} />
              </Field>
            ) : (
              <Field label={t('Odstęp', 'Interval')}><Num value={p.schedule.interval_minutes} min={5} step={15} suffix="min" disabled={!p.schedule.enabled} onChange={(v) => up((d) => { d.schedule.interval_minutes = v; })} /></Field>
            )}
            <Field label={t('Strefa czasowa', 'Timezone')}><input className="field mono" value={p.schedule.timezone} disabled={!p.schedule.enabled} onChange={(e) => up((d) => { d.schedule.timezone = e.target.value; })} /></Field>
          </div>
          {mode === 'cron' && p.schedule.enabled && !ro ? (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {([['0 22 * * *', t('codziennie 22:00', 'daily 22:00')], ['0 1 * * 1-5', t('dni robocze 01:00', 'weekdays 01:00')], ['0 0 * * 6', t('sobota 00:00', 'Saturday 00:00')], ['0 */6 * * *', t('co 6 godzin', 'every 6 hours')]] as const).map(([c, label]) => (
                <Button key={c} size="sm" onClick={() => up((d) => { d.schedule.cron = c; })}>{label}</Button>
              ))}
            </div>
          ) : null}
          <div className="mt-4">
            <p className="label mb-1.5">{t('Dozwolone okna czasowe: zamaluj godziny, w których wolno skanować', 'Allowed time windows: paint the hours in which scanning is allowed')}</p>
            <WindowPicker value={p.schedule.windows} disabled={ro} onChange={(w) => up((d) => { d.schedule.windows = w; })} />
          </div>
        </Section>

        <Section title={t('Budżet ruchu', 'Traffic budget')} hint={t('Policzony bez wysłania żadnego pakietu.', 'Computed without sending a single packet.')}>
          {isNew ? <p className="text-sm text-ink-2">{t('Zapisz profil, aby policzyć budżet ruchu: liczbę adresów, pakietów, czas skanu i to, czy zmieści się w oknie.', 'Save the profile to compute the traffic budget: addresses, packets, scan time and whether it fits the window.')}</p> : <EstimateBox profileId={id} stale={dirty} />}
        </Section>
      </fieldset>
      <Dialog open={confirmDelete} onClose={() => setConfirmDelete(false)} title={t('Usunąć profil?', 'Delete the profile?')} width={420}
        footer={<><Button onClick={() => setConfirmDelete(false)}>{t('Anuluj', 'Cancel')}</Button><Button variant="dangerSolid" busy={remove.isPending} onClick={() => remove.mutate(undefined)}>{t('Usuń profil', 'Delete the profile')}</Button></>}>
        <p className="text-sm">{t('Harmonogram profilu przestanie działać. Wyniki dotychczasowych przebiegów zostają.', 'The schedule of the profile stops. Results of past runs stay.')}</p>
      </Dialog>
    </div>
  );
}
