# Czujka REST API: time machine and re-probing

Routes of `internal/timeline` and `internal/reprobe`. Base path `/api/v1`, the same conventions as `docs/API.md` (JSON, snake_case, `Page<T>` lists with `limit` (default 50, max 1000) and `offset`, errors `{"error":{"code","message"}}`, RFC 3339 times). The integrator folds this table into `docs/API.md`.

| Method and path | Permission | Query / body → answer |
| --- | --- | --- |
| GET `/timeline` | results:read | optional `from`, `to` (RFC 3339) → `{runs: RunPoint[], from, to, took_ms}`: every analysed run, oldest first |
| GET `/timeline/at` | results:read | `run_id` or `at` (RFC 3339: the last analysed run at or before it; neither: the last run), plus the filters of the three lists below → `Snapshot` `{run, summary, hosts: Page<AtHost>, services: Page<AtService>, findings: Page<AtFinding>, took_ms}`; `limit`/`offset` apply to each list |
| GET `/timeline/at/hosts` | results:read | `run_id` or `at`; filters `status` (up, unstable, expected-offline, down, unknown, `missing` = every silent status but down), `cidr`, `q`, `scope_id`, `port`; `sort` `ip` (default), `-ip`, `observed_at`, `-observed_at`, `status` → `Page<AtHost>` |
| GET `/timeline/at/services` | results:read | `run_id` or `at`; filters `host_id`, `port`, `name`, `tech`, `class`, `state` (open, unknown, gone, `all`; default open and unknown), `tls`, `cidr`, `q`; `sort` `ip` (default), `port`, `-port`, `observed_at`, `-observed_at` → `Page<AtService>` |
| GET `/timeline/at/findings` | results:read | `run_id` or `at`; filters `severity`, `type`, `host_id` → `Page<AtFinding>`, most interesting first |
| GET `/timeline/hosts/{id}` | results:read | → `HostLife` `{host_id, ip, status_now, first_seen, last_seen, host: Interval[], services: ServiceLane[]}` (swim lanes) |
| GET `/timeline/services/{id}` | results:read | → `ServiceHistory` `{service_id, host_id, ip, port, proto, observations, changed: FieldHistory[], unchanged: {field: value}}` |
| GET `/reprobe/plan` | scans:read | → `Plan` `{generated_at, enabled, blocked, budget_per_hour, used_last_hour, due_now, active_reprobe, probes: Probe[], skipped: Skip[], settings}` |
| GET `/settings/reprobe` | scans:read | → `Settings` |
| PUT `/settings/reprobe` | scans:configure | partial `Settings` `{enabled, budget_per_hour, backoff_minutes, likely_up_rate, max_ports_per_host}` → `Settings`; 422 `validation` on a bad value |

## Definitions

- **Runs on the time line**: analysed runs (`runs.summary IS NOT NULL`), ordered by id. "As of run R" means every observation of a run with id ≤ R. A run's time is `finished_at`, else `started_at`, else `created_at`.
- **Host as of R**: the state of its latest observation as of R: `up`, or the status the availability model gave it then (`unstable`, `expected-offline`, `down`, `unknown`).
- **Service as of R**: its latest observation as of R (product, version, title, HTTP status, TLS, technologies and classes from that observation). It is `gone` when its host answered in a later run (≤ R) that did not see it, `unknown` when its host was silent in every later run, `open` otherwise. A service not probed in R keeps its last earlier observation. `changed_since` is true when product, version or title differ today.
- **Finding open at R**: first seen in a run ≤ R and before R's time, and not resolved before R (a resolved finding keeps its `last_run_id`). The past triage status is not stored; `status_now` is today's.

## Types

```text
RunPoint     {run_id, at, trigger, status, profile_name,
              hosts_up, hosts_missing, hosts_down, services_open, services_unknown, findings_open,   // state as of the run
              probed, probed_up, changes, changes_expected, changes_by_kind}                        // what the run did
AtHost       {id, ip, hostnames, label, status, up, observed_at, run_id, status_now, open_ports}
AtService    {id, host_id, ip, port, proto, state, name, product, version, title, http_status, tls,
              technologies, classes, observed_at, run_id, state_now, changed_since}
AtFinding    {id, key, type, title, severity, interest, host_id, ip, port, first_seen, last_seen,
              first_run_id, last_run_id, status_now}
summary      {hosts_up, hosts_missing, hosts_down, services_open, services_unknown, findings_open,
              findings_by_severity, diff_to_now: {services_gone_since, services_new_since, services_changed,
              hosts_down_since, hosts_up_since, hosts_new_since, findings_opened_since, findings_closed_since,
              sentences: ["270 usług, które wtedy istniały, dziś nie odpowiada.", ...]}}
Interval     {state, status, from, to, from_run, to_run, observations, ongoing}
             host lane: state up | missing | down, status = model status; service lane: state open | unknown
             "to" is the first observation after the interval (the last one when ongoing)
ServiceLane  {service_id, port, proto, name, state_now, intervals: Interval[], versions: [{at, run_id, before, after}]}
FieldHistory {field, values: [{value, from, to, from_run, to_run, observations}]}
             fields: name, version (product + version), title, status (HTTP), certificate (sha256 prefix + expiry day),
             headers (stable header names; Date, Content-Length, ETag ... ignored), technologies
Probe        {host_id, ip, ports, not_before, kind: confirm | likely-up, step, steps, reason (Polish), profile_id}
Skip         {host_id, ip, reason (Polish)}
Settings     {enabled: true, budget_per_hour: 200, backoff_minutes: [10, 30, 90], likely_up_rate: 0.6, max_ports_per_host: 32}
```

## Re-probing rules (`reprobe.Build`, a pure function)

- Candidates: hosts with status `unstable` or `expected-offline` whose latest observation is a miss. `down` hosts wait for the next full scan.
- **Confirm**: a host that went `host_missing` (status `unstable`, answered before) gets probes at `first miss + backoff_minutes[k]`, k = reprobes already recorded since the first miss. An overdue step is due now. A miss streak older than the last step plus 12 hours is not confirmed any more.
- **Likely up**: other candidates (and confirm hosts after the last step) are probed 5 minutes into the next hour whose model up-rate (`analyze.UpRates`) is at least `likely_up_rate`, where the host really answered on the same type of day (weekday or weekend, hour ±1), after its latest observation or reprobe. It needs at least 8 observations (`analyze.MinObsForExpected`).
- **Safety**: never when `enabled` is false or the emergency stop is set; never an address in the policy exclusions (IP, CIDR, range); the time moves to the next open window of the host's profile (`sched.NextAllowed`), and a likely-up hour without an open window is skipped; at most `budget_per_hour` addresses per hour, counting the reprobes of the last hour (`reprobe_log`); later probes move to the next hour with a note. The engine applies the safety policy again (ports, rates, exclusions).
- The executor (`reprobe.Executor`) runs every minute, starts the due probes as one targeted run per profile with trigger `reprobe`, records them in `reprobe_log`, and starts nothing while a reprobe run is still queued, running or analysing.

## Wiring (lines for `internal/wire` / `cmd/czujka` and `internal/api`)

```go
// startup, after st.Migrate:
tl := timeline.New(st, logger)
if err := tl.Start(ctx); err != nil { return err }           // creates the 2 timeline indexes
rb := reprobe.NewStoreBackend(st, histLoc, nil, logger)        // histLoc = store.Options.Location
if err := rb.Init(ctx); err != nil { return err }             // creates reprobe_log (tde_heap like hosts)
rb.SetStarter(func(ctx context.Context, req reprobe.Request) (model.ScanRun, error) {
	return mgr.StartTargeted(ctx, req.ProfileID, req.Targets, req.Trigger, req.Reason) // runner capability, below
})
go (&reprobe.Executor{B: rb, Log: logger}).Run(ctx)

// internal/api routes(), inside r.Route("/api/v1", ...), where "can" exists:
tl.Register(r, timeline.Middleware(can))
(&reprobe.Service{B: rb}).Register(r, reprobe.Middleware(can))
```

`api.Deps` needs two optional fields (`Timeline *timeline.Timeline`, `Reprobe *reprobe.Service`) or a generic `Extra func(r chi.Router, can func(model.Permission) func(http.Handler) http.Handler)` hook; registered routes go through the existing audit and session middleware, so PUT `/settings/reprobe` is audited.

### Runner capability needed: `StartTargeted`

A run on an ad-hoc list of addresses and ports that goes through the normal engine, sink and analysis:

1. Refuse with `ErrEmergencyStop` when the policy has the emergency stop set.
2. Create the run with `profile_id = NULL` (the unique index allows one active run per profile; a reprobe must not collide with a full run), `profile_name = "reprobe"`, `trigger = "reprobe"`.
3. Plan: `Targets` = one `ip` target per address; `Profile` = a copy of `req.ProfileID`'s profile (else the default profile) with `Ports` = the union of the targets' ports (empty: the profile's ports) and the same service detection and HTTP options, so the analysis sees the same fields and does not report spurious title or version changes; `Hints` = every target address with its ports, so the engine emits an observation (`up = false`) for a silent address; `Policy` = the current policy; `WindowEnd` from the profile windows.
4. Sink: `store.NewSink(SinkOptions{Source: "scan", MarkMissing: true})`; then the normal analysis (`AnalyzeRun`) and the normal events.

The integration test `TestReprobeConfirmationRun` drives exactly this path with a fake engine.

## Indexes

`timeline.Start` creates two indexes. `EXPLAIN ANALYZE` of a page of services as of a run (2 000 hosts, 30 runs, 57 500 host and 109 809 service observations) before and after:

| | stock indexes | with the timeline indexes |
| --- | --- | --- |
| plan of the latest observation per service | Bitmap Heap Scan on `service_obs_service_idx` (service_id only) + filter run_id + sort, 4 077 loops, 109 809 heap blocks | Index Scan on `timeline_svc_obs_run_idx (service_id, run_id DESC)`, 2 rows per loop |
| execution time of the statement | 68 ms | 30 ms |
| GET `/timeline/at?run_id=…` (summary + 3 pages) | 0.57–5.3 s (cold cache: 3.9–5.3 s) | 88–139 ms |
| GET `/timeline/at/services?tech=Jenkins` | 168–223 ms | 19–29 ms |
| GET `/timeline/at/hosts?status=up&cidr=…` | 6–62 ms | 2.6–4.9 ms |

- `timeline_svc_obs_run_idx ON service_observations (service_id, run_id DESC)`
- `timeline_host_obs_run_idx ON host_observations (host_id, run_id DESC)`

`reprobe` adds the table `reprobe_log (id, at, run_id, host_id, ip, kind, step, reason)` with indexes `(host_id, at DESC)` and `(at DESC)`. Its access method follows the `hosts` table (`tde_heap` when pg_tde is active).

## Limits

- Run order is run id. A reprobe run created while a long full run is still active gets a higher id than that run even though it finished first.
- "Gone" as of a run assumes the later run looked at the port. A full run with a narrower port list than an earlier one can mark a service `gone` in the time machine while the live inventory keeps it (the live analysis checks the profile's port scope).
- The scrubber result is cached per process until a run is analysed again or a new observation or change arrives; the findings counts are computed on every call.
- `analyze.Diff` emits no `host_back` when an `unstable` host (after `host_missing`) answers again; the host returns to `up` silently. `host_back` comes only after `down` or `expected-offline` (proposed change for `internal/analyze` in the report).
