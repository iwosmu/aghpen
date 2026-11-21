import { Fragment, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router';
import { useAction, useItem, usePage } from '../api/hooks';
import { ApiError, del, patch, post, put } from '../api/client';
import type { WebhookSettings, WebhookTestResult, AuditEntry, DefectDojoSettings, DojoPullResult, DojoScopeMapping, DojoSyncResult, DojoTestResult, Permission, PermissionInfo, Role, SafetyPolicy, Scope, User } from '../api/types';
import { t, getLang, plural } from '../i18n';
import { routeMissing } from '../lib/route';

/** The heading of a permission group ("targets" → "Cele"). */
function permGroupLabel(g: string): string {
  const m: Record<string, [string, string]> = {
    targets: ['Cele i zakresy', 'Targets and scopes'], scans: ['Skany i profile', 'Scans and profiles'], results: ['Wyniki i znaleziska', 'Results and findings'],
    signatures: ['Sygnatury i reguły', 'Signatures and rules'], export: ['Eksport', 'Export'], users: ['Użytkownicy', 'Users'], roles: ['Role', 'Roles'],
    audit: ['Dziennik audytu', 'Audit log'], safety: ['Bezpieczeństwo', 'Safety'], integrations: ['Integracje', 'Integrations'], admin: ['Administracja', 'Administration'],
  };
  const v = m[g];
  return v ? t(v[0], v[1]) : g;
}
import { cx, fmtDateTime, fmtInt, fmtRelative } from '../lib/format';
import { useUrlState } from '../lib/hooks';
import { lockMessage, outsideLock } from '../lib/lock';
import { Button, Check, Dialog, ErrorState, Field, IconButton, InlineError, PageHeader, Panel, ReadOnlyNote, Select, SkeletonRows, Tabs } from '../ui/kit';
import { Icon } from '../ui/Icon';
import { DataTable, FilterBar, FilterField, Pager, SearchField, type Col } from '../ui/table';
import { FindingStatusMark, Glyph } from '../ui/marks';
import { useDraft } from '../ui/edit';
import { roleLabel, useSession } from '../session';
import { NoAccess } from '../shell/Layout';
import { Switch } from './Signatures';

// ---------- users ----------
function UserDialog({ roles, onClose }: { roles: Role[]; onClose: () => void }) {
  const [f, setF] = useState({ email: '', name: '', role_id: roles.find((r) => r.slug === 'viewer')?.id ?? roles[0]?.id ?? 0, password: '' });
  const create = useAction(() => post<User>('/users', f), { invalidate: ['/users', '/roles', '/audit'], silent: true, success: t('Użytkownik dodany', 'User added'), onSuccess: onClose });
  const emailOk = /^\S+@\S+\.\S+$/.test(f.email);
  return (
    <Dialog open onClose={onClose} width={480} title={t('Nowy użytkownik', 'New user')}
      footer={<><Button onClick={onClose}>{t('Anuluj', 'Cancel')}</Button><Button variant="primary" icon="plus" busy={create.isPending} disabled={!emailOk || f.password.length < 10} onClick={() => create.mutate(undefined)}>{t('Dodaj użytkownika', 'Add user')}</Button></>}>
      <div className="space-y-3">
        <Field label="E-mail" error={f.email && !emailOk ? t('błędny adres e-mail', 'invalid e-mail address') : undefined}><input className="field" type="email" autoFocus autoComplete="off" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value.trim() })} /></Field>
        <Field label={t('Imię i nazwisko', 'Full name')}><input className="field" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        <Field label={t('Rola', 'Role')}><Select value={String(f.role_id)} onChange={(v) => setF({ ...f, role_id: Number(v) })} options={roles.map((r) => ({ value: String(r.id), label: roleLabel(r.slug, r.name) }))} /></Field>
        <Field label={t('Hasło początkowe', 'Initial password')} hint={t('co najmniej 10 znaków', 'at least 10 characters')}><input className="field mono" type="password" autoComplete="new-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></Field>
        <InlineError error={create.error} />
      </div>
    </Dialog>
  );
}

function UsersTab() {
  const { session } = useSession();
  const users = usePage<User>('/users', { limit: 200 });
  const roles = useItem<Role[]>('/roles');
  const [add, setAdd] = useState(false);
  const [confirm, setConfirm] = useState<User | null>(null);
  const update = useAction((v: { id: number; body: Record<string, unknown> }) => patch<User>('/users/' + v.id, v.body), { invalidate: ['/users', '/roles', '/audit'], success: t('Zapisano', 'Saved') });
  const remove = useAction((id: number) => del('/users/' + id), { invalidate: ['/users', '/roles', '/audit'], success: t('Użytkownik usunięty', 'User deleted'), onSuccess: () => setConfirm(null) });
  const me = session.user.id;
  const cols: Col<User>[] = [
    { id: 'name', header: t('Użytkownik', 'User'), wrap: true, cell: (x) => (
      <div className="min-w-[180px] py-1"><div className={x.disabled ? 'text-ink-3' : 'text-ink'}>{x.name || x.email.split('@')[0]}{x.id === me ? <span className="ml-1.5 text-2xs text-ink-3">{t('to Ty', 'you')}</span> : null}</div><div className="mono text-xs text-ink-3">{x.email}</div></div>
    ) },
    { id: 'role', header: t('Rola', 'Role'), width: 220, cell: (x) => x.id === me ? <span>{roleLabel(x.role_slug, x.role_name)}</span> : <Select label={t('Rola użytkownika ', 'Role of ') + x.email} value={String(x.role_id)} onChange={(v) => update.mutate({ id: x.id, body: { role_id: Number(v) } })} options={(roles.data ?? []).map((r) => ({ value: String(r.id), label: roleLabel(r.slug, r.name) }))} /> },
    { id: 'login', header: t('Ostatnie logowanie', 'Last login'), hide: 'md', cell: (x) => <span className="num text-ink-2" title={fmtDateTime(x.last_login_at)}>{x.last_login_at ? fmtRelative(x.last_login_at) : t('nigdy', 'never')}</span> },
    { id: 'state', header: t('Konto włączone', 'Account enabled'), cell: (x) => <Switch checked={!x.disabled} disabled={x.id === me || update.isPending} onChange={(v) => update.mutate({ id: x.id, body: { disabled: !v } })} label={t('Konto włączone: ', 'Account enabled: ') + x.email} /> },
    { id: 'del', header: '', align: 'right', width: 44, cell: (x) => x.id === me ? null : <IconButton icon="trash" label={t('Usuń użytkownika ', 'Delete user ') + x.email} onClick={() => setConfirm(x)} /> },
  ];
  return (
    <div>
      <div className="flex items-center justify-between gap-3 px-4 py-2 sm:px-6">
        <p className="text-sm text-ink-2">{users.data ? <><span className="num text-ink">{users.data.total}</span> {plural(users.data.total, ['konto', 'konta', 'kont'], ['account', 'accounts'])}</> : null}</p>
        <Button variant="primary" icon="plus" onClick={() => setAdd(true)}>{t('Nowy użytkownik', 'New user')}</Button>
      </div>
      <DataTable rows={users.data?.items} cols={cols} rowKey={(x) => x.id} loading={users.isPending} error={users.error} retry={() => users.refetch()}
        mobile={(x) => <div><div className="text-sm">{x.name || x.email}</div><div className="text-xs text-ink-3">{x.email} · {roleLabel(x.role_slug, x.role_name)}{x.disabled ? ' · ' + t('wyłączone', 'disabled') : ''}</div></div>} />
      {add && roles.data ? <UserDialog roles={roles.data} onClose={() => setAdd(false)} /> : null}
      <Dialog open={confirm !== null} onClose={() => setConfirm(null)} width={420} title={t('Usunąć użytkownika?', 'Delete user?')}
        footer={<><Button onClick={() => setConfirm(null)}>{t('Anuluj', 'Cancel')}</Button><Button variant="dangerSolid" busy={remove.isPending} onClick={() => confirm && remove.mutate(confirm.id)}>{t('Usuń konto', 'Delete account')}</Button></>}>
        <p className="text-sm"><span className="mono">{confirm?.email}</span>{t('. Konto zostanie usunięte, wpisy w dzienniku audytu zostaną.', '. The account is deleted. Its audit entries stay.')}</p>
      </Dialog>
    </div>
  );
}

// ---------- roles ----------
function RolesTab({ canManage }: { canManage: boolean }) {
  const roles = useItem<Role[]>('/roles');
  const perms = useItem<PermissionInfo[]>('/permissions');
  const [draft, setDraft] = useState<Record<number, Permission[]>>({});
  const [add, setAdd] = useState(false);
  const [name, setName] = useState('');
  const [copyFrom, setCopyFrom] = useState('');
  const save = useAction((r: Role) => patch<Role>('/roles/' + r.id, { permissions: draft[r.id] }), { invalidate: ['/roles', '/audit'], success: t('Rola zapisana', 'Role saved'), onSuccess: (r) => setDraft((d) => { const n = { ...d }; delete n[r.id]; return n; }) });
  const create = useAction(() => post<Role>('/roles', { name, description: '', permissions: (roles.data ?? []).find((r) => String(r.id) === copyFrom)?.permissions ?? [] }), { invalidate: ['/roles', '/audit'], silent: true, success: t('Rola dodana', 'Role added'), onSuccess: () => { setAdd(false); setName(''); } });
  const remove = useAction((id: number) => del('/roles/' + id), { invalidate: ['/roles', '/audit'], success: t('Rola usunięta', 'Role deleted') });
  const groups = useMemo(() => {
    const m = new Map<string, PermissionInfo[]>();
    for (const p of perms.data ?? []) { const g = m.get(p.group) ?? []; g.push(p); m.set(p.group, g); }
    return [...m.entries()];
  }, [perms.data]);
  if (roles.error) return <ErrorState error={roles.error} retry={() => roles.refetch()} />;
  if (!roles.data || !perms.data) return <SkeletonRows rows={10} />;
  const list = roles.data;
  const en = getLang() === 'en';
  return (
    <div className="p-4 sm:p-6">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                {canManage ? <Button variant="primary" icon="plus" onClick={() => setAdd(true)}>{t('Nowa rola', 'New role')}</Button> : null}
      </div>
      <div className="overflow-x-auto border border-rule bg-panel">
        <table className="w-full text-sm" data-testid="permission-matrix">
          <thead>
            <tr className="border-b border-rule-strong">
              <th className="sticky left-0 z-10 min-w-[230px] bg-panel px-3 py-2 text-left text-xs font-medium text-ink-3">{t('Uprawnienie', 'Permission')}</th>
              {list.map((r) => (
                <th key={r.id} className="min-w-[104px] px-2 py-2 text-left align-bottom font-medium">
                  <div className="text-sm text-ink">{roleLabel(r.slug, r.name)}</div>
                  <div className="text-2xs font-normal text-ink-3">{r.builtin ? t('wbudowana', 'built-in') : t('własna', 'custom')} · {r.user_count} {getLang() === 'pl' ? 'os.' : plural(r.user_count, ['', '', ''], ['user', 'users'])}</div>
                  {!r.builtin && canManage ? (
                    <div className="mt-1 flex gap-1">
                      {draft[r.id] ? <Button size="sm" variant="primary" busy={save.isPending} onClick={() => save.mutate(r)}>{t('Zapisz', 'Save')}</Button> : null}
                      {draft[r.id] ? <Button size="sm" variant="ghost" onClick={() => setDraft((d) => { const n = { ...d }; delete n[r.id]; return n; })}>{t('Cofnij', 'Undo')}</Button> : r.user_count === 0 ? <IconButton icon="trash" label={t('Usuń rolę ', 'Delete role ') + r.name} onClick={() => remove.mutate(r.id)} /> : null}
                    </div>
                  ) : null}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {groups.map(([group, items]) => (
              <Fragment key={group}>
                <tr className="border-b border-rule bg-raised"><th colSpan={list.length + 1} className="sticky left-0 px-3 py-1 text-left text-xs font-semibold text-ink-2">{permGroupLabel(group)}</th></tr>
                {items.map((p) => (
                  <tr key={p.permission} className="border-b border-rule last:border-b-0 hover:bg-raised">
                    <th scope="row" className="sticky left-0 z-10 bg-panel px-3 py-1 text-left font-normal"><div className="text-sm text-ink">{en ? p.label_en : p.label_pl}</div><div className="mono text-2xs text-ink-3">{p.permission}</div></th>
                    {list.map((r) => {
                      const cur = draft[r.id] ?? r.permissions;
                      const on = cur.includes(p.permission);
                      const label = (en ? p.label_en : p.label_pl) + ', ' + roleLabel(r.slug, r.name);
                      return (
                        <td key={r.id} className="px-2 py-1">
                          {r.builtin || !canManage
                            ? on ? <span className="inline-flex items-center" title={label}><Glyph name="check" tone="neutral" size={13} /><span className="sr-only">{t('tak', 'yes')}</span></span> : <span className="text-ink-3" title={label}>·<span className="sr-only">{t('nie', 'no')}</span></span>
                            : <input type="checkbox" className="h-[15px] w-[15px] accent-[var(--accent)]" checked={on} aria-label={label} onChange={(e) => setDraft((d) => ({ ...d, [r.id]: e.target.checked ? [...cur, p.permission] : cur.filter((x) => x !== p.permission) }))} />}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      <Dialog open={add} onClose={() => setAdd(false)} width={440} title={t('Nowa rola', 'New role')}
        footer={<><Button onClick={() => setAdd(false)}>{t('Anuluj', 'Cancel')}</Button><Button variant="primary" busy={create.isPending} disabled={!name.trim()} onClick={() => create.mutate(undefined)}>{t('Dodaj rolę', 'Add role')}</Button></>}>
        <div className="space-y-3">
          <Field label={t('Nazwa', 'Name')}><input className="field" autoFocus value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label={t('Skopiuj uprawnienia z', 'Copy permissions from')}><Select value={copyFrom} onChange={setCopyFrom} options={[{ value: '', label: t('żadnej', 'none') }, ...list.map((r) => ({ value: String(r.id), label: roleLabel(r.slug, r.name) }))]} /></Field>
          <InlineError error={create.error} />
        </div>
      </Dialog>
    </div>
  );
}

// ---------- audit ----------
function AuditTab() {
  const u = useUrlState();
  const limit = 50;
  const offset = Number(u.get('offset', '0'));
  const q = usePage<AuditEntry>('/audit', { q: u.get('q'), action: u.get('action'), entity: u.get('entity'), sort: '-at', limit, offset });
  const [text, setText] = useDraft(u.get('q'), (v) => u.set({ q: v }));
  const cols: Col<AuditEntry>[] = [
    { id: 'at', header: t('Czas', 'Time'), width: 170, cell: (a) => <span className="num text-ink-2">{fmtDateTime(a.at)}</span> },
    { id: 'user', header: t('Kto', 'Who'), cell: (a) => <span className="mono text-xs">{a.user_email || t('(system)', '(system)')}</span> },
    { id: 'action', header: t('Akcja', 'Action'), cell: (a) => <span className={cx('mono text-xs', /delete|emergency|failed/.test(a.action) ? 'text-danger' : 'text-ink')}>{a.action}</span> },
    { id: 'entity', header: t('Obiekt', 'Object'), hide: 'md', cell: (a) => <span className="text-ink-2">{a.entity}{a.entity_id ? <span className="mono ml-1 text-xs">{a.entity_id}</span> : null}</span> },
    { id: 'detail', header: t('Szczegóły', 'Details'), hide: 'lg', cell: (a) => <span className="mono block max-w-[360px] truncate text-xs text-ink-3" title={JSON.stringify(a.detail)}>{a.detail && Object.keys(a.detail).length ? JSON.stringify(a.detail) : '–'}</span> },
    { id: 'ip', header: 'IP', hide: 'xl', cell: (a) => <span className="mono text-xs text-ink-3">{a.ip}</span> },
  ];
  return (
    <div>
      <FilterBar onClear={() => u.clear(['q', 'action', 'entity'])} active={['q', 'action', 'entity'].filter((k) => u.get(k)).length}>
        <SearchField value={text} onChange={setText} placeholder={t('akcja, użytkownik, obiekt', 'action, user, object')} />
        <FilterField label={t('Rodzaj akcji', 'Action type')} width={170}>
          <Select value={u.get('action')} onChange={(v) => u.set({ action: v })} options={[{ value: '', label: t('wszystkie', 'all') }, ...['auth', 'run', 'target', 'scope', 'profile', 'signature', 'finding', 'change', 'host', 'service', 'user', 'role', 'safety', 'export', 'import', 'defectdojo'].map((x) => ({ value: x, label: x }))]} />
        </FilterField>
      </FilterBar>
      <DataTable rows={q.data?.items} cols={cols} rowKey={(a) => a.id} loading={q.isPending} error={q.error} retry={() => q.refetch()} dim={q.isPlaceholderData}
        empty={<p className="p-4 text-sm text-ink-2 sm:px-6">{t('Brak wpisów dla tych filtrów.', 'No entries for these filters.')}</p>}
        mobile={(a) => <div><div className="mono text-xs">{a.action}</div><div className="text-xs text-ink-3">{a.user_email} · {fmtDateTime(a.at)}</div></div>} />
      {q.data ? <Pager total={q.data.total} limit={limit} offset={offset} onOffset={(o) => u.set({ offset: o || null })} /> : null}
    </div>
  );
}

// ---------- safety ----------
function SafetyTab() {
  const { can } = useSession();
  const canManage = can('safety:manage');
  const q = useItem<SafetyPolicy>('/settings/safety');
  const [f, setF] = useState<SafetyPolicy | null>(null);
  const [excl, setExcl] = useState('');
  const [nets, setNets] = useState('');
  const [confirmStop, setConfirmStop] = useState(false);
  useEffect(() => { if (q.data) { setF(q.data); setExcl((q.data.exclusions ?? []).join('\n')); setNets((q.data.allowed_networks ?? []).join('\n')); } }, [q.data]);
  const lines = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
  const save = useAction(() => put<SafetyPolicy>('/settings/safety', { ...f, exclusions: lines(excl), allowed_networks: lines(nets) }), { invalidate: ['/settings/safety', '/dashboard', '/audit'], silent: true, success: t('Polityka zapisana', 'Policy saved') });
  const stop = useAction(() => post<SafetyPolicy>('/emergency-stop'), { invalidate: ['/settings/safety', '/dashboard', '/runs', '/audit'], onSuccess: () => setConfirmStop(false) });
  const release = useAction(() => post<SafetyPolicy>('/emergency-stop/release'), { invalidate: ['/settings/safety', '/dashboard', '/audit'], success: t('Stop awaryjny wyłączony', 'Emergency stop is off') });
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!f || !q.data) return <SkeletonRows rows={8} />;
  const num = (k: 'max_pps' | 'max_http_rps' | 'max_per_host_rps' | 'max_paths_per_host', label: string, suffix: string, hint?: string) => (
    <Field label={label} hint={hint}>
      <span className="relative block"><input type="number" min={1} className="field num pr-14" disabled={!canManage} value={f[k]} onChange={(e) => setF({ ...f, [k]: Number(e.target.value) })} /><span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-xs text-ink-3">{suffix}</span></span>
    </Field>
  );
  const op = q.data.operator_networks ?? [];
  const outside = outsideLock(lines(nets), op);
  const lockErr = save.error instanceof ApiError && save.error.status === 422 ? lockMessage(save.error.message, getLang()) : null;
  const dirty = JSON.stringify(lines(excl)) !== JSON.stringify(q.data.exclusions ?? []) || JSON.stringify(lines(nets)) !== JSON.stringify(q.data.allowed_networks ?? [])
    || JSON.stringify({ ...f, exclusions: null, allowed_networks: null }) !== JSON.stringify({ ...q.data, exclusions: null, allowed_networks: null });
  return (
    <div className="grid gap-4 p-4 sm:p-6 xl:grid-cols-[minmax(0,1fr)_360px]">
      <Panel title={t('Polityka bezpieczeństwa', 'Safety policy')} actions={canManage ? <Button size="sm" variant="primary" icon="check" busy={save.isPending} disabled={!dirty} onClick={() => save.mutate(undefined)}>{t('Zapisz politykę', 'Save policy')}</Button> : undefined}>
        {!canManage ? <div className="mb-3"><ReadOnlyNote text={t('Tylko do odczytu.', 'Read only.')} /></div> : null}
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {num('max_pps', t('Pakiety na sekundę', 'Packets per second'), 'pps')}
          {num('max_http_rps', t('Żądania HTTP na sekundę', 'HTTP requests per second'), 'rps')}
          {num('max_per_host_rps', t('Żądania na host', 'Requests per host'), 'rps')}
          {num('max_paths_per_host', t('Ścieżki na usługę', 'Paths per service'), t('maks.', 'max'))}
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <Field label={t('Dozwolone porty', 'Allowed ports')} hint={t('puste: wszystkie', 'empty: all')}><input className="field mono" disabled={!canManage} value={f.allowed_ports} onChange={(e) => setF({ ...f, allowed_ports: e.target.value })} /></Field>
          <Field label={t('Zabronione porty', 'Denied ports')} hint={t('np. 9100 (drukarki)', 'for example 9100 (printers)')}><input className="field mono" disabled={!canManage} value={f.denied_ports} onChange={(e) => setF({ ...f, denied_ports: e.target.value })} /></Field>
        </div>
        <div className="mt-3">
          {op.length ? (
            <div className="mb-3 border border-rule bg-sunk px-3 py-2.5" data-testid="operator-lock">
              <p className="flex items-center gap-1.5 text-sm font-medium text-ink"><Icon name="lock" size={14} className="text-ink-2" />{t('Blokada operatora', 'Operator lock')}</p>
              <p className="mt-1.5 flex flex-wrap gap-1.5">{op.map((n) => <span key={n} className="mono border border-rule-strong px-1.5 py-0.5 text-sm text-ink">{n}</span>)}</p>
              <p className="mt-1.5 max-w-[72ch] text-xs text-ink-2">{t('Ustawia ją zmienna CZUJKA_ALLOWED_NETWORKS. W Czujce można ją tylko zawęzić.', 'Set by the CZUJKA_ALLOWED_NETWORKS variable. Czujka can only narrow it.')}</p>
            </div>
          ) : null}
          <Field label={t('Dozwolone sieci', 'Allowed networks')} hint={op.length && !nets.trim() ? t('Puste: cała sieć z blokady operatora.', 'Empty: the whole network of the operator lock.') : nets.trim() ? t('Czujka skanuje tylko adresy z tych sieci.', 'Czujka scans only addresses in these networks.') : t('Puste: bez ograniczenia. CIDR, jeden w wierszu.', 'Empty: no limit. CIDR, one per line.')}>
            <textarea className="field mono" rows={3} disabled={!canManage} value={nets} onChange={(e) => setNets(e.target.value)} placeholder={'10.66.0.0/16\n149.156.0.0/16'} data-testid="allowed-networks" aria-invalid={outside.length > 0 || Boolean(lockErr)} />
          </Field>
          {lockErr ? (
            <p role="alert" className="mt-1.5 flex items-start gap-1.5 text-xs text-danger" data-testid="allowed-lock-error"><Icon name="lock" size={14} className="mt-px flex-none" /><span>{lockErr}</span></p>
          ) : outside.length ? (
            <p className="mt-1.5 flex items-start gap-1.5 text-xs text-st-changed" data-testid="allowed-outside-lock"><Icon name="lock" size={14} className="mt-px flex-none" /><span>{t('Poza blokadą operatora: ', 'Outside the operator lock: ')}<span className="mono">{outside.join(', ')}</span>{t('. Usuń te wpisy.', '. Remove these entries.')}</span></p>
          ) : null}
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <Field label={t('Wykluczenia', 'Exclusions')} hint={t('adres albo CIDR, jeden w wierszu', 'an address or a CIDR, one per line')}><textarea className="field mono" rows={5} disabled={!canManage} value={excl} onChange={(e) => setExcl(e.target.value)} /></Field>
          <div className="space-y-3">
            <Field label="User-Agent"><input className="field mono" disabled={!canManage} value={f.user_agent} onChange={(e) => setF({ ...f, user_agent: e.target.value })} /></Field>
            <div>
              <span className="label mb-1 block">{t('Metody HTTP', 'HTTP methods')}</span>
              <p className="flex flex-wrap items-center gap-2 text-sm">
                {(f.allowed_methods ?? []).map((m) => <span key={m} className="mono border border-rule-strong px-1.5 py-0.5 text-xs">{m}</span>)}
                <span className="inline-flex items-center gap-1 text-xs text-ink-3"><Icon name="lock" size={12} />{t('stałe', 'fixed')}</span>
              </p>
            </div>
          </div>
        </div>
        <div className="mt-3">{lockErr ? <p className="text-xs text-danger">{t('Popraw dozwolone sieci.', 'Fix the allowed networks.')}</p> : <InlineError error={save.error} />}</div>
        <p className="mt-3 text-2xs text-ink-3">{t('Ostatnia zmiana:', 'Last change:')} <span className="num">{fmtDateTime(q.data.updated_at)}</span></p>
      </Panel>

      <Panel title={t('Stop awaryjny', 'Emergency stop')}>
        <p className={cx('flex items-center gap-2 text-base font-medium', q.data.emergency_stop ? 'text-danger' : 'text-ink')}>
          <Icon name={q.data.emergency_stop ? 'stop' : 'shield'} className={q.data.emergency_stop ? '' : 'text-st-new'} />
          {q.data.emergency_stop ? t('Włączony', 'On') : t('Wyłączony', 'Off')}
        </p>
        <p className="mt-2 text-sm text-ink-2">{t('Stop wstrzymuje wszystkie trwające skany i blokuje nowe, także z harmonogramu, dopóki administrator go nie wyłączy.', 'The stop pauses all running scans and blocks new ones, scheduled ones too, until an administrator turns it off.')}</p>
        <div className="mt-3 flex flex-wrap gap-2">
          {!q.data.emergency_stop && can('safety:stop') ? <Button variant="dangerSolid" icon="stop" onClick={() => setConfirmStop(true)}>{t('Zatrzymaj wszystkie skany', 'Stop all scans')}</Button> : null}
          {q.data.emergency_stop && canManage ? <Button variant="primary" icon="play" busy={release.isPending} onClick={() => release.mutate(undefined)}>{t('Wyłącz stop', 'Turn off the stop')}</Button> : null}
          {q.data.emergency_stop && !canManage ? <ReadOnlyNote text={t('Stop wyłącza administrator.', 'An administrator turns the stop off.')} /> : null}
        </div>
      </Panel>
      <Dialog open={confirmStop} onClose={() => setConfirmStop(false)} width={440} title={t('Zatrzymać wszystkie skany?', 'Stop all scans?')}
        footer={<><Button onClick={() => setConfirmStop(false)}>{t('Anuluj', 'Cancel')}</Button><Button variant="dangerSolid" icon="stop" busy={stop.isPending} onClick={() => stop.mutate(undefined)}>{t('Zatrzymaj wszystkie skany', 'Stop all scans')}</Button></>}>
        <p className="text-sm">{t('Wszystkie trwające skany zostaną wstrzymane. Nowe nie ruszą.', 'All running scans pause. No new scan starts.')}</p>
      </Dialog>
    </div>
  );
}

// ---------- Alert webhook ----------
const SEV_OPTS = () => [
  { value: 'info', label: t('informacyjna i wyżej', 'info and above') },
  { value: 'low', label: t('niska i wyżej', 'low and above') },
  { value: 'medium', label: t('średnia i wyżej', 'medium and above') },
  { value: 'high', label: t('tylko wysoka', 'high only') },
];
function WebhookPanel() {
  const q = useItem<WebhookSettings>('/settings/webhook');
  const [f, setF] = useState<WebhookSettings | null>(null);
  const [secret, setSecret] = useState('');
  const [clear, setClear] = useState(false);
  const [test, setTest] = useState<WebhookTestResult | null>(null);
  useEffect(() => { if (q.data) setF(q.data); }, [q.data]);
  const save = useAction(() => put<WebhookSettings>('/settings/webhook', { enabled: f?.enabled, url: f?.url, min_severity: f?.min_severity, ui_url: f?.ui_url ?? '', ...(secret ? { secret } : {}), ...(clear ? { clear_secret: true } : {}) }),
    { invalidate: ['/settings/webhook', '/audit'], silent: true, success: t('Ustawienia zapisane', 'Settings saved'), onSuccess: () => { setSecret(''); setClear(false); } });
  const run = useAction(() => post<WebhookTestResult>('/settings/webhook/test', { url: f?.url, ...(secret ? { secret } : {}) }), { silent: true, onSuccess: setTest });
  if (q.error && routeMissing(q.error)) return null;
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!f || !q.data) return <SkeletonRows rows={4} />;
  const dirty = secret !== '' || clear || JSON.stringify(f) !== JSON.stringify(q.data);
  return (
    <Panel title={t('Webhook alertów', 'Alert webhook')} className="mt-4" actions={<Button size="sm" variant="primary" icon="check" busy={save.isPending} disabled={!dirty} onClick={() => save.mutate(undefined)} data-testid="webhook-save">{t('Zapisz ustawienia', 'Save settings')}</Button>}>
      <div data-testid="webhook">
                <Check checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} label={t('Webhook włączony', 'Webhook enabled')} />
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <Field label={t('Adres (URL)', 'Address (URL)')}><input className="field mono" value={f.url} onChange={(e) => { setF({ ...f, url: e.target.value }); setTest(null); }} placeholder="https://hooks.slack.com/services/…" data-testid="webhook-url" /></Field>
          <Field label={t('Minimalna waga', 'Minimum severity')}><Select value={f.min_severity} onChange={(v) => setF({ ...f, min_severity: v as WebhookSettings['min_severity'] })} options={SEV_OPTS()} /></Field>
          <Field label={t('Sekret HMAC (opcjonalnie)', 'HMAC secret (optional)')} hint={f.secret_set && !clear ? t('Zapisany. Wpisz nowy, aby go zmienić. Podpis w nagłówku X-Czujka-Signature.', 'Stored. Type a new one to replace it. Signature in the X-Czujka-Signature header.') : undefined}>
            <input className="field mono" type="password" autoComplete="off" value={secret} disabled={clear} onChange={(e) => { setSecret(e.target.value); setTest(null); }} placeholder={f.secret_set ? '••••••••••••••••' : ''} data-testid="webhook-secret" />
          </Field>
          <Field label={t('Adres Czujki w odnośnikach', 'Czujka address in the links')} hint={t('Puste: adres, z którego zapisano ustawienia.', 'Empty: the address the settings were saved from.')}><input className="field mono" value={f.ui_url} onChange={(e) => setF({ ...f, ui_url: e.target.value })} placeholder={typeof window !== 'undefined' ? window.location.origin : ''} /></Field>
        </div>
        {f.secret_set ? <div className="mt-2"><Check checked={clear} onChange={(v) => { setClear(v); if (v) setSecret(''); }} label={t('Usuń zapisany sekret', 'Remove stored secret')} /></div> : null}
        <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-rule pt-3">
          <Button icon="link" busy={run.isPending} disabled={!f.url} onClick={() => run.mutate(undefined)} data-testid="webhook-test-button">{t('Wyślij test', 'Send test')}</Button>
          {test ? (
            <span className="inline-flex items-start gap-2 text-sm" role="status" data-testid="webhook-test">
              <span className="mt-0.5"><Glyph name={test.ok ? 'check' : 'x'} tone={test.ok ? 'new' : 'gone'} /></span>
              <span>{test.ok ? t('Test dostarczony: ', 'Test delivered: ') : t('Test nieudany: ', 'Test failed: ')}<span className="mono">{test.status ? 'HTTP ' + test.status : t('brak odpowiedzi', 'no response')} · {fmtInt(test.ms)} ms</span>{test.error ? <span className="block text-xs text-ink-2">{test.error}</span> : null}</span>
            </span>
          ) : null}
        </div>
        <div className="mt-2"><InlineError error={save.error ?? run.error} /></div>
      </div>
    </Panel>
  );
}

// ---------- DefectDojo ----------
function DojoTab() {
  const q = useItem<DefectDojoSettings>('/settings/defectdojo');
  const [f, setF] = useState<DefectDojoSettings | null>(null);
  const [key, setKey] = useState('');
  const [test, setTest] = useState<DojoTestResult | null>(null);
  useEffect(() => { if (q.data) setF(q.data); }, [q.data]);
  const save = useAction(() => put<DefectDojoSettings>('/settings/defectdojo', { ...f, ...(key ? { api_key: key } : {}) }), { invalidate: ['/settings/defectdojo', '/audit'], silent: true, success: t('Ustawienia zapisane', 'Settings saved'), onSuccess: () => setKey('') });
  const run = useAction(() => post<DojoTestResult>('/settings/defectdojo/test', { url: f?.url, verify_tls: f?.verify_tls, ...(key ? { api_key: key } : {}) }), { silent: true, onSuccess: setTest });
  const scopes = usePage<Scope>('/scopes', { limit: 200 });
  const [pull, setPull] = useState<DojoPullResult | null>(null);
  const [sync, setSync] = useState<DojoSyncResult | null>(null);
  const pullRun = useAction((apply: boolean) => post<DojoPullResult>('/defectdojo/pull' + (apply ? '?apply=true' : '')), { silent: true, invalidate: ['/findings'], onSuccess: setPull });
  const syncRun = useAction(() => post<DojoSyncResult>('/defectdojo/sync'), { silent: true, invalidate: ['/findings'], onSuccess: setSync });
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!f || !q.data) return <SkeletonRows rows={8} />;
  const dirty = key !== '' || JSON.stringify(f) !== JSON.stringify(q.data);
  const maps = f.scope_mappings ?? [];
  const setMap = (i: number, m: Partial<DojoScopeMapping>) => setF({ ...f, scope_mappings: maps.map((x, j) => (j === i ? { ...x, ...m } : x)) });
  const scopeOpts = (scopes.data?.items ?? []).map((s) => ({ value: String(s.id), label: s.name }));
  const freeScope = (scopes.data?.items ?? []).find((s) => !maps.some((m) => m.scope_id === s.id));
  const count = (x: unknown) => (Array.isArray(x) ? x.length : typeof x === 'number' ? x : 0);
  return (
    <div className="max-w-[860px] p-4 sm:p-6">
      <Panel title="DefectDojo" actions={<Button size="sm" variant="primary" icon="check" busy={save.isPending} disabled={!dirty} onClick={() => save.mutate(undefined)}>{t('Zapisz ustawienia', 'Save settings')}</Button>}>
                <Check checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} label={t('Integracja włączona', 'Integration enabled')} />
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <Field label={t('Adres DefectDojo', 'DefectDojo URL')}><input className="field mono" value={f.url} onChange={(e) => { setF({ ...f, url: e.target.value }); setTest(null); }} placeholder="https://defectdojo.example" /></Field>
          {'link_url' in q.data ? (
            <Field label={t('Adres do odnośników (publiczny)', 'Link address (public)')} hint={t('Adres DefectDojo dla przeglądarki. Puste: adres wyżej.', 'The DefectDojo URL for the browser. Empty: the URL above.')}>
              <input className="field mono" value={f.link_url ?? ''} onChange={(e) => setF({ ...f, link_url: e.target.value })} placeholder="http://127.0.0.1:18080" data-testid="dojo-link-url" />
            </Field>
          ) : null}
          <Field label={t('Klucz API', 'API key')} hint={f.api_key_set ? t('Zapisany. Wpisz nowy, aby go zmienić.', 'Stored. Type a new one to replace it.') : t('Brak klucza.', 'No key set.')}>
            <input className="field mono" type="password" autoComplete="off" value={key} onChange={(e) => { setKey(e.target.value); setTest(null); }} placeholder={f.api_key_set ? '••••••••••••••••' : ''} />
          </Field>
          <Field label={t('Typ produktu', 'Product type')}><input className="field" value={f.product_type_name} onChange={(e) => setF({ ...f, product_type_name: e.target.value })} /></Field>
          <Field label={t('Produkt', 'Product')}><input className="field" value={f.product_name} onChange={(e) => setF({ ...f, product_name: e.target.value })} /></Field>
          <Field label={t('Zaangażowanie', 'Engagement')}><input className="field" value={f.engagement_name} onChange={(e) => setF({ ...f, engagement_name: e.target.value })} /></Field>
          <Field label={t('Automatyczny eksport od ciekawości', 'Auto-export from interest')}><input type="number" min={0} max={100} className="field num" disabled={!f.auto_export} value={f.min_interest} onChange={(e) => setF({ ...f, min_interest: Number(e.target.value) })} /></Field>
        </div>
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          <Check checked={f.verify_tls} onChange={(v) => setF({ ...f, verify_tls: v })} label={t('Sprawdzaj certyfikat TLS serwera', 'Verify the server TLS certificate')} />
          <Check checked={f.auto_export} onChange={(v) => setF({ ...f, auto_export: v })} label={t('Eksportuj nowe znaleziska po każdym skanie', 'Export new findings after each scan')} />
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-rule pt-3">
          <Button icon="link" busy={run.isPending} disabled={!f.url} onClick={() => run.mutate(undefined)}>{t('Sprawdź połączenie', 'Test connection')}</Button>
          {test ? (
            <span className="inline-flex items-start gap-2 text-sm" role="status" data-testid="dojo-test">
              <span className="mt-0.5"><Glyph name={test.ok ? 'check' : 'x'} tone={test.ok ? 'new' : 'gone'} /></span>
              <span>{test.message}{test.version ? <span className="mono ml-2 text-xs text-ink-3">v{test.version}</span> : null}</span>
            </span>
          ) : null}
        </div>
        <div className="mt-2"><InlineError error={save.error ?? run.error} /></div>

        <div className="mt-4 border-t border-rule pt-3" data-testid="dojo-mappings">
          <p className="text-sm font-medium">{t('Produkt DefectDojo dla zakresu', 'DefectDojo product per scope')}</p>
          <p className="mb-2 text-xs text-ink-3">{t('Puste pole przyjmuje wartość ogólną.', 'An empty field takes the general value.')}</p>
          {maps.length ? (
            <ul className="space-y-2">
              {maps.map((m, i) => (
                <li key={i} className="grid items-end gap-2 sm:grid-cols-[180px_repeat(3,minmax(0,1fr))_auto]">
                  <Field label={t('Zakres', 'Scope')}><Select value={String(m.scope_id)} onChange={(v) => setMap(i, { scope_id: Number(v) })} options={scopeOpts} /></Field>
                  <Field label={t('Typ produktu', 'Product type')}><input className="field" value={m.product_type_name} placeholder={f.product_type_name} onChange={(e) => setMap(i, { product_type_name: e.target.value })} /></Field>
                  <Field label={t('Produkt', 'Product')}><input className="field" value={m.product_name} placeholder={f.product_name} onChange={(e) => setMap(i, { product_name: e.target.value })} /></Field>
                  <Field label={t('Zaangażowanie', 'Engagement')}><input className="field" value={m.engagement_name} placeholder={f.engagement_name} onChange={(e) => setMap(i, { engagement_name: e.target.value })} /></Field>
                  <IconButton icon="x" label={t('Usuń mapowanie', 'Remove mapping')} onClick={() => setF({ ...f, scope_mappings: maps.filter((_, j) => j !== i) })} />
                </li>
              ))}
            </ul>
          ) : null}
          <Button size="sm" icon="plus" className="mt-2" disabled={!freeScope} onClick={() => freeScope && setF({ ...f, scope_mappings: [...maps, { scope_id: freeScope.id, product_type_name: '', product_name: '', engagement_name: '' }] })}>{t('Dodaj mapowanie', 'Add mapping')}</Button>
        </div>

        <div className="mt-4 border-t border-rule pt-3">
          <p className="text-sm font-medium">{t('Synchronizacja statusów', 'Status sync')}</p>
          <Check checked={Boolean(f.status_sync)} onChange={(v) => setF({ ...f, status_sync: v })} label={t('Synchronizuj statusy z DefectDojo po każdym skanie', 'Sync statuses with DefectDojo after each scan')} />
          <p className="mt-1 text-xs text-ink-3">{t('Przy konflikcie zostaje status z Czujki.', 'On a conflict the Czujka status stays.')}</p>
          <div className="mt-2 flex flex-wrap gap-2">
            <Button size="sm" icon="download" busy={pullRun.isPending && !pullRun.variables} disabled={!q.data.api_key_set} onClick={() => pullRun.mutate(false)} data-testid="dojo-pull">{t('Sprawdź statusy w DefectDojo', 'Check statuses in DefectDojo')}</Button>
            {pull && (pull.updates ?? []).length && !pull.applied ? <Button size="sm" variant="primary" icon="check" busy={pullRun.isPending && pullRun.variables === true} onClick={() => pullRun.mutate(true)}>{t('Zastosuj ' + (pull.updates ?? []).length + ' ' + plural((pull.updates ?? []).length, ['zmianę', 'zmiany', 'zmian'], ['change', 'changes']), 'Apply ' + (pull.updates ?? []).length + ' ' + plural((pull.updates ?? []).length, ['zmianę', 'zmiany', 'zmian'], ['change', 'changes']))}</Button> : null}
            <Button size="sm" icon="upload" busy={syncRun.isPending} disabled={!q.data.api_key_set} onClick={() => syncRun.mutate(undefined)}>{t('Wyślij statusy do DefectDojo', 'Send statuses to DefectDojo')}</Button>
          </div>
          {!q.data.api_key_set ? <p className="mt-1 text-xs text-ink-3">{t('Najpierw zapisz adres i klucz API.', 'Save the URL and API key first.')}</p> : null}
          <InlineError error={pullRun.error ?? syncRun.error} />
          {pull ? (
            <div className="mt-2 border border-rule p-2 text-sm" data-testid="dojo-pull-result">
              <p>{t('Sprawdzone znaleziska: ' + fmtInt(pull.checked) + '. Zmiany do przyjęcia: ' + (pull.updates ?? []).length + '. Konflikty: ' + count(pull.conflicts) + '. Brak w DefectDojo: ' + count(pull.missing) + '.', 'Findings checked: ' + fmtInt(pull.checked) + '. Changes to apply: ' + (pull.updates ?? []).length + '. Conflicts: ' + count(pull.conflicts) + '. Missing in DefectDojo: ' + count(pull.missing) + '.')}{pull.applied ? ' ' + t('Zastosowano: ' + pull.applied + '.', 'Applied: ' + pull.applied + '.') : ''}</p>
              {pull.linked ? <p className="mt-1 flex items-center gap-1.5 text-xs text-ink" data-testid="dojo-pull-linked"><Icon name="link" size={12} className="text-ink-2" />{t('Połączone znaleziska z niepotwierdzonego eksportu: ' + pull.linked + '.', 'Findings linked from an unconfirmed export: ' + pull.linked + '.')}</p> : null}
              {(pull.updates ?? []).length ? (
                <ul className="mt-2 max-h-[220px] overflow-auto border-t border-rule">
                  {(pull.updates ?? []).map((x) => (
                    <li key={x.finding_id} className="grid gap-x-3 border-b border-rule py-1.5 text-xs last:border-b-0 sm:grid-cols-[250px_minmax(0,1fr)]" data-testid="dojo-pull-update">
                      <span><Link className="link num" to={'/findings?open=' + x.finding_id}>#{x.finding_id}</Link> <FindingStatusMark status={x.from} /> → <FindingStatusMark status={x.to} /></span>
                      <span className="text-ink-2">{x.reason}</span>
                    </li>
                  ))}
                </ul>
              ) : null}
              {Array.isArray(pull.conflicts) && pull.conflicts.length ? (
                <div className="mt-2 border-t border-rule pt-2" data-testid="dojo-pull-conflicts">
                  <p className="text-xs font-medium text-ink">{t('Konflikty', 'Conflicts')}</p>
                  <ul>
                    {pull.conflicts.map((x) => (
                      <li key={x.finding_id} className="grid gap-x-3 border-b border-rule py-1.5 text-xs last:border-b-0 sm:grid-cols-[250px_minmax(0,1fr)]">
                        <span><Link className="link num" to={'/findings?open=' + x.finding_id}>#{x.finding_id}</Link> <span className="text-ink-3">{t('Czujka', 'Czujka')}</span> <FindingStatusMark status={x.local} /></span>
                        <span className="text-ink-2">{t('DefectDojo: ', 'DefectDojo: ')}<span className="mono">{x.remote}</span> · {x.reason}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : null}
          {sync ? <p className="mt-2 text-sm" data-testid="dojo-sync-result">{t('Zamknięte: ' + sync.closed + ', ponownie otwarte: ' + sync.reopened + ', pominięte: ' + sync.skipped + (count(sync.errors) ? ', błędy: ' + count(sync.errors) : '') + '.', 'Closed: ' + sync.closed + ', reopened: ' + sync.reopened + ', skipped: ' + sync.skipped + (count(sync.errors) ? ', errors: ' + count(sync.errors) : '') + '.')}</p> : null}
        </div>
      </Panel>
      <WebhookPanel />
    </div>
  );
}

export default function Admin() {
  const u = useUrlState();
  const { can } = useSession();
  const tabs = [
    can('users:manage') ? { id: 'users', label: t('Użytkownicy', 'Users') } : null,
    { id: 'roles', label: t('Role i uprawnienia', 'Roles and permissions') },
    can('audit:read') ? { id: 'audit', label: t('Dziennik audytu', 'Audit log') } : null,
    can('scans:read') ? { id: 'safety', label: t('Bezpieczeństwo', 'Safety') } : null,
    can('integrations:manage') ? { id: 'defectdojo', label: t('DefectDojo i webhook', 'DefectDojo and webhook') } : null,
  ].filter((x): x is { id: string; label: string } => x !== null);
  const tab = tabs.some((x) => x.id === u.get('tab')) ? u.get('tab') : tabs[0]?.id;
  if (!tab) return <NoAccess />;
  const readOnly = (tab === 'roles' && !can('roles:manage')) || (tab === 'safety' && !can('safety:manage'));
  return (
    <div>
      <PageHeader title={t('Administracja', 'Administration')} readOnly={readOnly} />
      <div className="px-4 pt-2 sm:px-6"><Tabs tabs={tabs} value={tab} onChange={(id) => u.set({ tab: id, q: null, action: null, entity: null })} /></div>
      {tab === 'users' ? <UsersTab /> : null}
      {tab === 'roles' ? <RolesTab canManage={can('roles:manage')} /> : null}
      {tab === 'audit' ? <AuditTab /> : null}
      {tab === 'safety' ? <SafetyTab /> : null}
      {tab === 'defectdojo' ? <DojoTab /> : null}
          </div>
  );
}
