import { useEffect, useRef, useState, type ButtonHTMLAttributes, type ReactNode, type Ref } from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router';
import { cx } from '../lib/format';
import { t, getLang } from '../i18n';
import { lockMessage } from '../lib/lock';
import { Icon } from './Icon';
import { ApiError, isUnavailable } from '../api/client';

// ---------- Button ----------
type BtnVariant = 'primary' | 'default' | 'ghost' | 'danger' | 'dangerSolid';
const BTN: Record<BtnVariant, string> = {
  primary: 'bg-primary text-primary-ink border-primary hover:bg-primary-hover hover:border-primary-hover active:bg-primary-press font-semibold shadow-[0_1px_0_rgb(255_255_255/0.35)_inset]',
  default: 'bg-raised text-ink border-rule-strong hover:border-ink-3 hover:bg-[color-mix(in_oklch,var(--raised),var(--ink)_6%)]',
  ghost: 'bg-transparent text-ink-2 border-transparent hover:bg-raised hover:text-ink',
  danger: 'bg-transparent text-danger border-danger/60 hover:bg-st-gone-wash',
  dangerSolid: 'bg-danger-solid text-danger-ink border-danger-solid hover:brightness-110 font-semibold',
};

export function Button({
  variant = 'default', size = 'md', icon, busy, children, className, ...rest
}: { variant?: BtnVariant; size?: 'sm' | 'md'; icon?: string; busy?: boolean } & ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      type="button"
      {...rest}
      disabled={rest.disabled || busy}
      className={cx(
        'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-sm border transition-colors duration-150',
        'disabled:opacity-50 disabled:pointer-events-none active:translate-y-px',
        size === 'sm' ? 'h-[28px] px-2.5 text-xs' : 'h-[34px] px-3.5 text-sm',
        BTN[variant], className,
      )}
    >
      {busy ? <Spinner /> : icon ? <Icon name={icon} size={size === 'sm' ? 14 : 16} /> : null}
      {children}
    </button>
  );
}

export function LinkButton({ to, icon, children, variant = 'default', size = 'md' }: { to: string; icon?: string; children: ReactNode; variant?: BtnVariant; size?: 'sm' | 'md' }) {
  return (
    <Link
      to={to}
      className={cx(
        'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-sm border transition-colors duration-150',
        size === 'sm' ? 'h-[28px] px-2.5 text-xs' : 'h-[34px] px-3.5 text-sm', BTN[variant],
      )}
    >
      {icon ? <Icon name={icon} size={size === 'sm' ? 14 : 16} /> : null}
      {children}
    </Link>
  );
}

export function IconButton({ icon, label, className, ...rest }: { icon: string; label: string } & ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      type="button" aria-label={label} title={label} {...rest}
      className={cx('inline-flex h-[34px] w-[34px] items-center justify-center rounded-sm border border-transparent text-ink-2 hover:bg-raised hover:text-ink disabled:opacity-50', className)}
    >
      <Icon name={icon} />
    </button>
  );
}

export function Spinner() {
  return <span className="inline-block h-3 w-3 animate-spin rounded-full border-[1.5px] border-current border-t-transparent" aria-hidden="true" />;
}

// ---------- Layout pieces ----------
export function PageHeader({ title, sub, actions, readOnly, back }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode; readOnly?: boolean; back?: { to: string; label: string } }) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3 border-b border-rule/70 px-4 pb-4 pt-5 sm:px-6 lg:px-8">
      <div className="min-w-0">
        {back ? (
          <Link to={back.to} className="mb-1 inline-flex items-center gap-1 text-xs text-ink-3 hover:text-ink">
            <Icon name="chevronLeft" size={12} />{back.label}
          </Link>
        ) : null}
        <h1 className="font-display text-[30px] font-normal leading-[1.05] tracking-[-0.005em] text-ink sm:text-[36px]">{title}</h1>
        {sub ? <p className="mt-0.5 max-w-[80ch] text-sm text-ink-2">{sub}</p> : null}
        {readOnly ? <ReadOnlyNote /> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}

export function ReadOnlyNote({ text }: { text?: string }) {
  return (
    <p className="mt-1.5 inline-flex items-center gap-1.5 text-xs text-ink-3" data-testid="read-only-note">
      <Icon name="lock" size={12} />
      {text ?? t('Tylko odczyt. Twoja rola nie pozwala na zmiany na tej stronie.', 'Read only. Your role does not allow changes on this page.')}
    </p>
  );
}

export function Panel({ title, count, actions, children, className, flush }: { title?: ReactNode; count?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; flush?: boolean }) {
  return (
    <section className={cx('card min-w-0', className)}>
      {title ? (
        <div className="flex min-h-[40px] items-center justify-between gap-3 border-b border-rule/70 px-4">
          <h2 className="flex items-baseline gap-2 text-sm font-semibold text-ink">
            {title}
            {count !== undefined ? <span className="num text-xs font-normal text-ink-3">{count}</span> : null}
          </h2>
          {actions ? <div className="flex items-center gap-2 text-xs">{actions}</div> : null}
        </div>
      ) : null}
      <div className={flush ? '' : 'p-4'}>{children}</div>
    </section>
  );
}

export function Field({ label, hint, error, children, className }: { label: ReactNode; hint?: ReactNode; error?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <label className={cx('block min-w-0', className)}>
      <span className="label mb-1 block">{label}</span>
      {children}
      {error ? <span className="mt-1 block text-xs text-danger">{error}</span> : hint ? <span className="mt-1 block text-xs text-ink-3">{hint}</span> : null}
    </label>
  );
}

export function Check({ label, checked, onChange, disabled, hint }: { label: ReactNode; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; hint?: ReactNode }) {
  return (
    <label className={cx('flex items-start gap-2 text-sm', disabled && 'opacity-60')}>
      <input type="checkbox" className="mt-0.5" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>
        {label}
        {hint ? <span className="block text-xs text-ink-3">{hint}</span> : null}
      </span>
    </label>
  );
}

export function KV({ k, children, mono }: { k: ReactNode; children: ReactNode; mono?: boolean }) {
  return (
    <div className="flex min-h-[30px] items-baseline gap-3 border-b border-rule py-1.5 last:border-b-0">
      <dt className="w-[38%] max-w-[180px] flex-none text-xs text-ink-3">{k}</dt>
      <dd className={cx('min-w-0 flex-1 break-words text-sm text-ink', mono && 'mono')}>{children}</dd>
    </div>
  );
}

export function Tabs({ tabs, value, onChange }: { tabs: { id: string; label: ReactNode; count?: number }[]; value: string; onChange: (id: string) => void }) {
  return (
    <div role="tablist" className="flex gap-0 overflow-x-auto border-b border-rule px-4 sm:px-6">
      {tabs.map((tab) => (
        <button
          key={tab.id} role="tab" type="button" aria-selected={value === tab.id} onClick={() => onChange(tab.id)}
          className={cx(
            '-mb-px flex h-[40px] items-center gap-1.5 whitespace-nowrap border-b-2 px-3 text-sm',
            value === tab.id ? 'border-primary font-medium text-ink' : 'border-transparent text-ink-2 hover:text-ink',
          )}
        >
          {tab.label}
          {tab.count !== undefined ? <span className="num text-xs text-ink-3">{tab.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

export function Chip({ children, onRemove, tone = 'plain', title }: { children: ReactNode; onRemove?: () => void; tone?: 'plain' | 'accent'; title?: string }) {
  return (
    <span title={title} className={cx('inline-flex h-[22px] max-w-full items-center gap-1 rounded-sm border px-2 text-xs', tone === 'accent' ? 'border-accent/50 bg-accent-wash text-ink' : 'border-rule-strong text-ink-2')}>
      <span className="truncate">{children}</span>
      {onRemove ? (
        <button type="button" onClick={onRemove} aria-label={t('Usuń', 'Remove')} className="-mr-0.5 text-ink-3 hover:text-ink"><Icon name="x" size={10} /></button>
      ) : null}
    </span>
  );
}

// ---------- States ----------
export function Empty({ title, hint, action, icon = 'ring' }: { title: ReactNode; hint?: ReactNode; action?: ReactNode; icon?: string }) {
  return (
    <div className="flex flex-col items-start gap-1.5 px-4 py-8 sm:px-6">
      <Icon name={icon} className="text-ink-3" size={18} />
      <p className="text-sm font-medium text-ink">{title}</p>
      {hint ? <p className="max-w-[62ch] text-sm text-ink-2">{hint}</p> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

export interface Explained { title: string; detail: string; code: string; calm: boolean; icon: string; retryable: boolean }

/** Turns an error into text for the analyst. The server message is English and technical, so the title comes from the code. */
export function explainError(error: unknown): Explained {
  const e = error as ApiError | Error | null;
  const msg = e?.message ?? String(error ?? '');
  if (!(e instanceof ApiError)) return { title: t('Wystąpił błąd', 'Something went wrong'), detail: msg, code: 'error', calm: false, icon: 'alert', retryable: true };
  const base = { code: e.code, calm: false, icon: 'alert', retryable: false };
  if (e.status === 0) return { ...base, title: t('Brak połączenia z serwerem', 'Cannot reach the server'), detail: t('Sprawdź połączenie i spróbuj ponownie.', 'Check the connection and try again.'), retryable: true };
  if (e.status === 501 || e.code === 'not_wired') return { ...base, calm: true, icon: 'info', title: t('Funkcja niedostępna w tej instalacji', 'Not available in this installation'), detail: t('Ten moduł nie jest podłączony do serwera. Pozostałe funkcje działają normalnie.', 'This module is not connected to the server. Everything else works as usual.') + ' (' + msg + ')' };
  if (e.status === 401) return { ...base, icon: 'lock', title: t('Sesja wygasła', 'Session expired'), detail: t('Zaloguj się ponownie.', 'Sign in again.') };
  if (e.status === 403 && /csrf/i.test(msg)) return { ...base, icon: 'lock', title: t('Odśwież stronę', 'Reload the page'), detail: t('Potem powtórz operację.', 'Then repeat the operation.') };
  if (e.status === 403) return { ...base, icon: 'lock', title: t('Brak uprawnień', 'No permission'), detail: t('Twoja rola nie pozwala na tę operację.', 'Your role does not allow this operation.') + ' (' + msg + ')' };
  if (e.status === 404) return { ...base, title: t('Nie znaleziono', 'Not found'), detail: t('Ten obiekt nie istnieje albo został usunięty.', 'This object does not exist or was deleted.') };
  if (e.code === 'emergency_stop') return { ...base, icon: 'stop', title: t('Stop awaryjny jest włączony', 'The emergency stop is on'), detail: t('Najpierw wyłącz stop awaryjny.', 'Turn off the emergency stop first.') };
  if (e.status === 409) return { ...base, title: t('Tej operacji nie można teraz wykonać', 'This operation is not possible now'), detail: msg };
  if (e.code === 'dojo_unconfirmed') return { ...base, icon: 'alert', retryable: true, title: t('Wysłano, nie potwierdzono', 'Sent, not confirmed'), detail: getLang() === 'pl' ? msg.replace(/^Wysłano, nie potwierdzono:\s*(\S)/, (_m, c: string) => c.toUpperCase()) : 'Repeat the export. DefectDojo accepted the data but stopped answering before it confirmed it. Repeating the export, or pulling the statuses, links these findings by key, without duplicates.' };
  const locked = e.status === 422 ? lockMessage(msg, getLang()) : null;
  if (locked) return { ...base, icon: 'lock', title: t('Blokada operatora', 'Operator lock'), detail: locked };
  if (e.status === 422 || e.code === 'validation') return { ...base, title: t('Błędne dane', 'Invalid data'), detail: msg };
  if (e.status === 429) return { ...base, icon: 'clock', title: t('Zbyt wiele prób', 'Too many attempts'), detail: t('Spróbuj ponownie za kilka minut.', 'Try again in a few minutes.') + ' (' + msg + ')' };
  if (e.status === 400) return { ...base, title: t('Nieprawidłowe żądanie', 'Bad request'), detail: msg };
  if (e.status === 502 || e.status === 503 || e.status === 504) return { ...base, title: t('Usługa zewnętrzna nie odpowiada', 'An external service is not responding'), detail: msg, retryable: true };
  return { ...base, title: t('Błąd serwera', 'Server error'), detail: msg, retryable: true };
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  const x = explainError(error);
  return (
    <div role={x.calm ? 'status' : 'alert'} data-testid={x.calm ? 'unavailable' : 'error-state'} className="flex flex-col items-start gap-1.5 px-4 py-8 sm:px-6">
      <Icon name={x.icon} className={x.calm ? 'text-ink-3' : 'text-danger'} size={18} />
      <p className="text-sm font-medium text-ink">{x.title}</p>
      <p className="max-w-[70ch] text-sm text-ink-2">{x.detail} <span className="mono text-xs text-ink-3">{x.code}</span></p>
      {retry && x.retryable ? <Button size="sm" icon="refresh" onClick={retry} className="mt-2">{t('Spróbuj ponownie', 'Try again')}</Button> : null}
    </div>
  );
}

/** A calm note for a function whose server module is missing (HTTP 501). */
export function Unavailable({ what, error }: { what?: ReactNode; error?: unknown }) {
  const msg = (error as Error | undefined)?.message;
  return (
    <div role="status" data-testid="unavailable" className="flex items-start gap-2 border border-rule bg-sunk px-3 py-2.5 text-sm">
      <Icon name="info" className="mt-0.5 flex-none text-ink-3" size={14} />
      <div className="min-w-0">
        <p className="font-medium text-ink">{t('Funkcja niedostępna w tej instalacji', 'Not available in this installation')}</p>
        <p className="text-xs text-ink-2">{what ?? t('Ten moduł nie jest podłączony do serwera. Pozostałe funkcje działają normalnie.', 'This module is not connected to the server. Everything else works as usual.')}</p>
        {msg ? <p className="mono mt-0.5 break-words text-2xs text-ink-3">{msg}</p> : null}
      </div>
    </div>
  );
}

export function SkeletonRows({ rows = 6 }: { rows?: number }) {
  return (
    <div className="px-3 py-2" aria-busy="true" aria-label={t('Wczytywanie', 'Loading')}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex h-[30px] items-center gap-3 border-b border-rule last:border-b-0">
          <div className="skeleton h-2.5" style={{ width: 60 + ((i * 37) % 80) }} />
          <div className="skeleton h-2.5 flex-1" style={{ maxWidth: 180 + ((i * 53) % 220) }} />
          <div className="skeleton h-2.5 w-12" />
        </div>
      ))}
    </div>
  );
}

export function InlineError({ error }: { error: unknown }) {
  if (!error) return null;
  if (isUnavailable(error)) return <Unavailable error={error} />;
  const x = explainError(error);
  const plain = !(error instanceof ApiError);
  return (
    <p role="alert" className="flex items-start gap-1.5 text-xs text-danger">
      <Icon name={x.icon} size={14} className="mt-px flex-none" />
      <span>{plain ? x.detail : <><span className="font-medium">{x.title}.</span> {x.detail}</>}</span>
    </p>
  );
}

// ---------- Dialog (native <dialog>: focus trap and Esc come from the platform) ----------
export function Dialog({ open, onClose, title, children, footer, width = 520 }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode; width?: number }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  if (!open) return null;
  return createPortal(
    <dialog
      ref={ref}
      onClose={onClose}
      onClick={(e) => { if (e.target === ref.current) onClose(); }}
      className="m-auto max-h-[88dvh] w-[calc(100vw-24px)] overflow-visible border border-rule-strong bg-panel p-0 text-ink shadow-[var(--shadow)] backdrop:bg-black/55"
      style={{ maxWidth: width }}
    >
      <div className="flex max-h-[88dvh] flex-col">
        <div className="flex h-[40px] flex-none items-center justify-between border-b border-rule px-4">
          <h2 className="text-sm font-semibold">{title}</h2>
          <IconButton icon="x" label={t('Zamknij', 'Close')} onClick={onClose} className="-mr-2" />
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-4">{children}</div>
        {footer ? <div className="flex flex-none flex-wrap items-center justify-end gap-2 border-t border-rule px-4 py-3">{footer}</div> : null}
      </div>
    </dialog>,
    document.body,
  );
}

// ---------- Toasts ----------
type Toast = { id: number; text: ReactNode; tone: 'ok' | 'error' | 'info' };
let pushToast: ((t: Omit<Toast, 'id'>) => void) | null = null;
export function toast(text: ReactNode, tone: 'ok' | 'error' | 'info' = 'ok') { pushToast?.({ text, tone }); }
export function toastError(e: unknown) {
  const x = explainError(e);
  toast(<span data-testid={x.calm ? 'toast-unavailable' : 'toast-error'}><span className="font-medium">{x.title}.</span> <span className="text-ink-2">{x.detail}</span></span>, x.calm ? 'info' : 'error');
}

export function Toaster() {
  const [items, setItems] = useState<Toast[]>([]);
  useEffect(() => {
    pushToast = (x) => {
      const id = Date.now() + Math.random();
      setItems((cur) => [...cur.slice(-3), { ...x, id }]);
      setTimeout(() => setItems((cur) => cur.filter((i) => i.id !== id)), x.tone === 'ok' ? 3500 : 7000);
    };
    return () => { pushToast = null; };
  }, []);
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-[min(380px,calc(100vw-32px))] flex-col gap-2" aria-live="polite">
      {items.map((i) => (
        <div
          key={i.id}
          className={cx('pointer-events-auto flex items-start gap-2 border bg-raised px-3 py-2 text-sm shadow-[var(--shadow)]', i.tone === 'error' ? 'border-danger/70' : 'border-rule-strong')}
          style={{ animation: 'rise-in 200ms var(--ease-out-expo)' }}
        >
          <Icon name={i.tone === 'error' ? 'alert' : i.tone === 'info' ? 'info' : 'check'} className={i.tone === 'error' ? 'mt-0.5 text-danger' : i.tone === 'info' ? 'mt-0.5 text-ink-3' : 'mt-0.5 text-st-new'} size={14} />
          <div className="min-w-0 flex-1">{i.text}</div>
        </div>
      ))}
    </div>
  );
}

// ---------- Floating tooltip for charts ----------
export function useTip() {
  const [tip, setTip] = useState<{ x: number; y: number; body: ReactNode } | null>(null);
  const show = (e: { clientX: number; clientY: number }, body: ReactNode) => setTip({ x: e.clientX, y: e.clientY, body });
  const showAt = (el: Element, body: ReactNode) => {
    const r = el.getBoundingClientRect();
    setTip({ x: r.left + r.width / 2, y: r.top, body });
  };
  const hide = () => setTip(null);
  const node = tip
    ? createPortal(
        <div
          role="tooltip"
          className="pointer-events-none fixed z-[60] max-w-[280px] border border-rule-strong bg-raised px-2.5 py-1.5 text-xs text-ink shadow-[var(--shadow)]"
          style={{
            left: Math.max(8, Math.min(tip.x + 12, (typeof window !== 'undefined' ? window.innerWidth : 1200) - 292)),
            top: Math.max(8, tip.y + 14),
          }}
        >
          {tip.body}
        </div>,
        document.body,
      )
    : null;
  return { show, showAt, hide, node };
}

// ---------- Small data pieces ----------
export function Meter({ value, max, cap, tone = 'accent', height = 6, label }: { value: number; max: number; cap?: number; tone?: 'accent' | 'danger' | 'changed'; height?: number; label?: string }) {
  const pct = max > 0 ? Math.max(0, Math.min(1, value / max)) : 0;
  const color = tone === 'danger' ? 'var(--danger)' : tone === 'changed' ? 'var(--st-changed)' : 'var(--accent)';
  return (
    <div
      className="relative w-full bg-[color-mix(in_oklch,var(--accent)_14%,var(--raised))]" style={{ height }}
      role="meter" aria-valuemin={0} aria-valuemax={max} aria-valuenow={value} aria-label={label}
    >
      <div className="h-full transition-[width] duration-500" style={{ width: pct * 100 + '%', background: color }} />
      {cap !== undefined && max > 0 ? <div className="absolute -bottom-1 -top-1 w-px bg-ink" style={{ left: Math.min(100, (cap / max) * 100) + '%' }} /> : null}
    </div>
  );
}

export function Tags({ tags, max = 4 }: { tags: string[] | null | undefined; max?: number }) {
  if (!tags || tags.length === 0) return null;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {tags.slice(0, max).map((x) => <Chip key={x}>{x}</Chip>)}
      {tags.length > max ? <span className="text-xs text-ink-3">+{tags.length - max}</span> : null}
    </span>
  );
}

export function CopyText({ text, className }: { text: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button" title={t('Kopiuj', 'Copy')}
      onClick={() => { navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); }); }}
      className={cx('group inline-flex max-w-full items-center gap-1 text-left', className)}
    >
      <span className="mono truncate">{text}</span>
      <Icon name={done ? 'check' : 'copy'} size={12} className={cx('flex-none', done ? 'text-st-new' : 'text-ink-3 opacity-0 group-hover:opacity-100 group-focus-visible:opacity-100')} />
    </button>
  );
}

export function Select({ value, onChange, options, label, className }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; label?: string; className?: string }) {
  return (
    <select aria-label={label} className={cx('field', className)} value={value} onChange={(e) => onChange(e.target.value)}>
      {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
}

export function TagInput({ value, onChange, placeholder }: { value: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [draft, setDraft] = useState('');
  const add = () => {
    const v = draft.trim().toLowerCase();
    if (v && !value.includes(v)) onChange([...value, v]);
    setDraft('');
  };
  return (
    <div className="flex min-h-[34px] flex-wrap items-center gap-1 rounded-sm border border-rule-strong bg-sunk px-1.5 py-1 focus-within:border-transparent focus-within:outline focus-within:outline-[1.5px] focus-within:outline-offset-1 focus-within:outline-focus">
      {value.map((x) => <Chip key={x} onRemove={() => onChange(value.filter((y) => y !== x))}>{x}</Chip>)}
      <input
        className="h-[20px] min-w-[90px] flex-1 bg-transparent text-sm outline-none placeholder:text-ink-3"
        value={draft} placeholder={placeholder ?? t('dodaj tag', 'add a tag')}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add(); }
          if (e.key === 'Backspace' && !draft && value.length) onChange(value.slice(0, -1));
        }}
        onBlur={add}
      />
    </div>
  );
}

/** A file picker with a translated button and the chosen name; the native input stays in the DOM (sr-only) for tests and the keyboard. */
export function FileInput({ accept, file, onFile, inputRef, testId }: { accept?: string; file: File | null; onFile: (f: File | null) => void; inputRef?: Ref<HTMLInputElement>; testId?: string }) {
  return (
    <span className="field flex cursor-pointer items-center gap-3 overflow-hidden pl-0 pr-3 focus-within:border-transparent focus-within:outline focus-within:outline-[1.5px] focus-within:outline-offset-1 focus-within:outline-focus">
      <input ref={inputRef} type="file" accept={accept} data-testid={testId} className="sr-only" onChange={(e) => onFile(e.target.files?.[0] ?? null)} />
      <span className="flex h-full flex-none items-center border-r border-rule-strong bg-raised px-3 text-sm font-medium text-ink">{t('Wybierz plik', 'Choose a file')}</span>
      <span className={'min-w-0 truncate text-sm ' + (file ? 'mono text-ink' : 'text-ink-3')}>{file ? file.name : t('nie wybrano pliku', 'no file chosen')}</span>
    </span>
  );
}
