import { Link } from 'react-router';
import { usePage } from '../api/hooks';
import type { Change, Service } from '../api/types';
import { t, plural } from '../i18n';
import { awayText, responseDelta } from '../lib/changeText';
import { serviceName } from '../lib/serviceName';
import { Glyph, changeKindInfo } from './marks';
import { MissingHostLines } from './MissingHosts';

/** The change kinds a person reads as the story of a run, in reading order. */
const STORY: { kind: string; one: [string, string]; few: [string, string]; many: [string, string]; en: [string, string] }[] = [
  { kind: 'service_gone', one: ['usługa zniknęła', ''], few: ['usługi zniknęły', ''], many: ['usług zniknęło', ''], en: ['service gone', 'services gone'] },
  { kind: 'service_returned', one: ['usługa wróciła', ''], few: ['usługi wróciły', ''], many: ['usług wróciło', ''], en: ['service is back', 'services are back'] },
  { kind: 'service_new', one: ['nowa usługa', ''], few: ['nowe usługi', ''], many: ['nowych usług', ''], en: ['new service', 'new services'] },
  { kind: 'response_slower', one: ['usługa odpowiada wolniej', ''], few: ['usługi odpowiadają wolniej', ''], many: ['usług odpowiada wolniej', ''], en: ['service responds slower', 'services respond slower'] },
  { kind: 'response_recovered', one: ['usługa znów odpowiada szybko', ''], few: ['usługi znów odpowiadają szybko', ''], many: ['usług znów odpowiada szybko', ''], en: ['service fast again', 'services fast again'] },
  { kind: 'host_new', one: ['nowy host', ''], few: ['nowe hosty', ''], many: ['nowych hostów', ''], en: ['new host', 'new hosts'] },
  { kind: 'host_back', one: ['host wrócił', ''], few: ['hosty wróciły', ''], many: ['hostów wróciło', ''], en: ['host is back', 'hosts are back'] },
  { kind: 'host_gone', one: ['host nieaktywny', ''], few: ['hosty nieaktywne', ''], many: ['hostów nieaktywnych', ''], en: ['host down', 'hosts down'] },
];

function itemLabel(c: Change, svc: Map<string, Service>, showIp: boolean): string {
  const s = (c.service_id ? [...svc.values()].find((x) => x.id === c.service_id) : undefined) ?? svc.get(c.host_id + ':' + c.port);
  const where = c.port ? (showIp ? c.ip : '') + ':' + c.port : c.ip;
  const name = s ? serviceName(s, { short: true }) : '';
  return where + (name ? ' ' + name : '');
}

/**
 * The named changes of a run at the top of a page: "1 usługa zniknęła: :8787 nginx".
 * Shows nothing when the run changed nothing a person reads as a story.
 */
export function RunStory({ runId, className, testId = 'run-story' }: { runId: number; className?: string; testId?: string }) {
  const q = usePage<Change>('/changes', { run_id: runId, expected: false, limit: 200 });
  return <StoryList changes={q.data?.items ?? []} runId={runId} className={className} testId={testId} />;
}

/** The story lines for a list of changes (a run, or the diff of two runs). */
export function StoryList({ changes, runId, className, testId = 'run-story' }: { changes: Change[]; runId?: number; className?: string; testId?: string }) {
  const items = changes.filter((c) => !c.expected && STORY.some((s) => s.kind === c.kind));
  const anyMissing = changes.some((c) => c.kind === 'host_missing' && !c.expected);
  const hosts = [...new Set(items.map((c) => c.host_id))];
  const oneHost = hosts.length === 1 ? hosts[0] : 0;
  const svcQ = usePage<Service>('/services', { host_id: oneHost || undefined, limit: 500 }, oneHost > 0);
  if (!items.length && !anyMissing) return null;
  const svc = new Map<string, Service>();
  for (const s of svcQ.data?.items ?? []) svc.set(s.host_id + ':' + s.port, s);
  const showIp = hosts.length > 1;
  return (
    <ul className={className ?? 'space-y-1'} data-testid={testId}>
      <MissingHostLines changes={changes} />
      {STORY.map((st) => {
        const list = items.filter((c) => c.kind === st.kind);
        if (!list.length) return null;
        const info = changeKindInfo(st.kind);
        const n = list.length;
        const head = n + ' ' + plural(n, [st.one[0], st.few[0], st.many[0]], st.en);
        return (
          <li key={st.kind} className="flex items-start gap-2 text-base" data-kind={st.kind}>
            <span className="mt-[5px]"><Glyph name={info.glyph} tone={info.tone} /></span>
            <span className="min-w-0">
              {runId ? <Link to={'/changes?run_id=' + runId + '&kind=' + st.kind} className="font-medium hover:underline">{head}</Link> : <span className="font-medium">{head}</span>}:{' '}
              {list.slice(0, 6).map((c, i) => {
                const extra = st.kind === 'service_returned' ? (awayText(c) ? ', ' + awayText(c) : '')
                  : st.kind === 'response_slower' || st.kind === 'response_recovered' ? (responseDelta(c) ? ' ' + responseDelta(c) : '') : '';
                const to = c.service_id ? '/services/' + c.service_id : svc.get(c.host_id + ':' + c.port) ? '/services/' + svc.get(c.host_id + ':' + c.port)!.id : '/hosts/' + c.host_id;
                return <span key={c.id}>{i ? ', ' : ''}<Link to={to} className="mono link">{itemLabel(c, svc, showIp)}</Link>{extra ? <span className="num text-ink-2">{extra}</span> : null}</span>;
              })}
              {n > 6 ? <span className="text-ink-2">{t(' i ' + (n - 6) + ' więcej', ' and ' + (n - 6) + ' more')}</span> : null}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
