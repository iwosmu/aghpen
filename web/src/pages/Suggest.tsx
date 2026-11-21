import { useState } from 'react';
import { useNavigate } from 'react-router';
import { useAction } from '../api/hooks';
import { post } from '../api/client';
import type { Suggestion } from '../api/types';
import { t } from '../i18n';
import { routeMissing } from '../lib/route';
import { Button, Dialog, InlineError, Unavailable } from '../ui/kit';
import { Glyph } from '../ui/marks';

export const SUGGEST_KEY = 'czujka.suggest.yaml';

/** "Zaproponuj sygnaturę": POST /signatures/suggest for one service, then open the proposal in the editor. */
export function SuggestButton({ serviceId }: { serviceId: number }) {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const run = useAction(() => post<Suggestion>('/signatures/suggest', { service_id: serviceId }), { silent: true });
  const s = run.data;
  const go = () => { if (s?.yaml) { sessionStorage.setItem(SUGGEST_KEY, s.yaml); navigate('/signatures/new?suggest=1'); } };
  return (
    <>
      <Button icon="signatures" onClick={() => { setOpen(true); run.mutate(undefined); }} data-testid="suggest-signature">{t('Zaproponuj sygnaturę', 'Suggest signature')}</Button>
      <Dialog open={open} onClose={() => setOpen(false)} width={720} title={t('Propozycja sygnatury', 'Suggested signature')}
        footer={<><Button onClick={() => setOpen(false)}>{t('Zamknij', 'Close')}</Button>{s?.ok && s.yaml ? <Button variant="primary" icon="edit" onClick={go}>{t('Otwórz w edytorze', 'Open in editor')}</Button> : null}</>}>
        <div className="space-y-3" data-testid="suggest-result">
          {run.isPending ? <p className="text-sm text-ink-2">{t('Szukanie cech tej usługi…', 'Looking for distinctive features…')}</p> : null}
          {run.error ? (routeMissing(run.error) ? <Unavailable what={t('Propozycje sygnatur wymagają POST /signatures/suggest. Moduł nie jest jeszcze podłączony.', 'Signature suggestions need POST /signatures/suggest. The module is not wired yet.')} /> : <InlineError error={run.error} />) : null}
          {s ? (
            <>
              <p className="flex items-start gap-2 text-sm font-medium"><span className="mt-0.5"><Glyph name={s.ok ? 'check' : 'x'} tone={s.ok ? 'new' : 'neutral'} /></span>{s.message}</p>
              {s.ok ? (
                <>
                  {(s.rules ?? []).length ? (
                    <div>
                      <p className="label mb-1">{t('Uzasadnienie', 'Reasons')}</p>
                      <ul className="space-y-1 text-sm">{(s.rules ?? []).map((r, i) => <li key={i} className="grid grid-cols-[90px_minmax(0,1fr)] gap-x-2"><span className="mono text-xs text-ink-3">{r.kind}</span><span>{r.explanation}</span></li>)}</ul>
                    </div>
                  ) : null}
                  {s.retro_hunt ? (
                    <p className="text-sm text-ink-2">{t('Test wsteczny: ', 'Retro-hunt: ')}{s.matches_target ? t('pasuje do przykładu', 'matches the example') : t('nie pasuje do przykładu', 'does not match the example')}{' · '}{t(s.other_matches + ' innych usług pasuje', s.other_matches + ' other services match')}{' · '}{t('sprawdzono ' + s.retro_hunt.scanned + ' usług, wysłano ' + s.retro_hunt.packets_sent + ' pakietów', s.retro_hunt.scanned + ' services checked, ' + s.retro_hunt.packets_sent + ' packets sent')}</p>
                  ) : null}
                  <pre className="mono max-h-[260px] overflow-auto border border-rule bg-sunk p-2 text-xs leading-5">{s.yaml}</pre>
                  {(s.rejected ?? []).length ? (
                    <details className="text-xs text-ink-2"><summary className="cursor-pointer text-ink-3">{t('Odrzucone cechy: ' + (s.rejected ?? []).length, 'Rejected features: ' + (s.rejected ?? []).length)}</summary>
                      <ul className="mt-1 space-y-0.5">{(s.rejected ?? []).map((r, i) => <li key={i}><span className="mono">{r.value}</span> · {r.reason}</li>)}</ul>
                    </details>
                  ) : null}
                </>
              ) : null}
            </>
          ) : null}
        </div>
      </Dialog>
    </>
  );
}
