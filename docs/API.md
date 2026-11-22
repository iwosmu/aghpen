# Czujka REST API (v1)

Base path `/api/v1`. JSON bodies use the types of `internal/model/types.go` (their JSON tags are the wire format). `web/src/api/types.ts` mirrors them.

- Auth: session cookie `czujka_session` (HttpOnly, SameSite=Strict). Mutating requests send `X-CSRF-Token` from `Session.csrf_token`.
- Lists: query `limit` (default 50, max 1000), `offset`, `sort` (field, `-field` for descending), `q` (free text) plus the filters named below. Answer: `Page<T>`.
- Errors: `{"error":{"code":"forbidden","message":"..."}}`. Codes: `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`, `validation`, `unsafe_signature`, `emergency_stop`, `internal`.
- JSON answers: a list field is always an array (`[]`, never `null`). A time that is not set is `null` (or left out with `omitempty`), never `0001-01-01T00:00:00Z`. One encoder in `internal/api/jsonout.go` does both for every answer and every SSE event.
- PATCH bodies are partial objects. A PATCH on a scanner-observed field of a host, service or finding stores an override; sending `null` for that field removes the override.

| Method and path | Permission | Body → answer |
| --- | --- | --- |
| POST `/auth/login` | public | `{email,password}` → `Session` |
| POST `/auth/logout` | any | → 204 |
| POST `/auth/password` | any (session + CSRF) | `{current_password, new_password}` → 204. Self-service change of the own password (10–256 characters). A wrong `current_password` is 422 `validation` and counts as a failed login (lockout rules apply); a short new password is 422. The session that made the change stays; every other session of the user ends. Audit: `auth.password_change` (no password in the entry) |
| GET `/me` | any | → `Session` |
| GET `/permissions` | any | → `[{permission, group, label_pl, label_en}]` |
| GET `/users` · POST `/users` | users:manage | `{email,name,password,role_id}` → `User` |
| PATCH · DELETE `/users/{id}` | users:manage | partial `User` (+ `password`) |
| GET `/roles` | any | → `Role[]` |
| POST `/roles` · PATCH · DELETE `/roles/{id}` | roles:manage | `Role` (built-in roles: read only) |
| GET `/audit` | audit:read | filters `user_id, action, entity, from, to` → `Page<AuditEntry>` |
| GET `/scopes` · GET `/scopes/{id}` | targets:read | → `Page<Scope>` / `Scope` |
| POST `/scopes` | targets:create | `Scope` |
| PATCH `/scopes/{id}` | targets:update | |
| DELETE `/scopes/{id}` | targets:delete | |
| GET `/scopes/{id}/targets` | targets:read | → `Page<Target>` |
| POST `/scopes/{id}/targets` | targets:create | `{text}` (one target per line: IP, CIDR, range, domain) or `Target[]` → `TargetPreview` (saved) |
| POST `/scopes/{id}/targets/import` | targets:create | multipart `file` (CSV or JSON), `dry_run` → `TargetPreview` |
| POST `/targets/preview` | targets:read | `{text}` or `[Target]` → `TargetPreview` (nothing saved). Every `invalid` entry has the real line of the text (from 1; for an array, the item number), also an entry that the safety policy or the operator lock drops. The same holds for `POST /scopes/{id}/targets` and the file import |
| PATCH `/targets/{id}` | targets:update | `{value?, note?, tags?, enabled?}`. A new `value`, or `enabled: true`, takes the same allowed-networks and operator-lock check as creation; a refusal is 422 `validation` |
| DELETE `/targets/{id}` | targets:delete | |
| GET `/profiles` · GET `/profiles/{id}` | scans:read | → `ScanProfile` |
| POST `/profiles` · PATCH · DELETE `/profiles/{id}` | scans:configure | `ScanProfile` |
| POST `/profiles/{id}/estimate` | scans:read | → `ScanEstimate`. `in_window`: a window of the profile is open now (or it has none). Outside the windows `next_window_at` is the start of the next window, `window_sec` its length and `fits_window` compares `est_duration_sec` with it. `prev_run_id`, `prev_finished_at`, `prev_duration_sec` (active time), `prev_hosts_up`, `prev_addresses`: the last completed run of the profile, measured. `deep_max_hosts` > 0: a scope over 256 addresses with a top-N list gets the rotating deep pass (the rest of 1-65535 for up to that many live hosts, counted in the packets); `deep_waiting_hosts`: known live hosts it will not reach in this run |
| GET `/runs` · GET `/runs/{id}` | scans:read | filters `profile_id, status` → `ScanRun` |
| POST `/runs` | scans:run | `{profile_id}` → `ScanRun`; 409 `emergency_stop` while the emergency stop is active (also when the engine is not wired); 409 `run_active` with `details: {run_id}` when the profile already has a queued, running or paused run; 409 `kernel_cap` when `CZUJKA_KERNEL_CAP=require` and the kernel packet cap is not installed (also for resume and ad-hoc runs). When the kernel dropped probe packets during a run, `stats.notes` gets `jądro odrzuciło N pakietów ponad limit` |
| POST `/runs/adhoc` | scans:run | `AdHocScope` `{profile_id, addresses, ports, reason}` → `ScanRun` with `trigger: "reprobe"`, `ad_hoc` set and `profile_id: null`. Probes only the given addresses (IP or CIDR up to /16, at most 65 536 addresses) and ports (nmap list; empty = the profile ports) through the normal engine, sink and analysis, with the rate, discovery and HTTP settings of the profile (`profile_id` 0 = the first profile). Every address (or CIDR) must lie wholly inside one enabled target of any scope (a loopback address counts as the docker host address, a domain target as its IPv4 addresses): an analyst with scans:run cannot reach an address that nobody with targets:create entered; otherwise 422 `validation` "… adres nie leży w całości w żadnym włączonym celu …". The allowed networks, exclusions and safety policy apply as well; a refusal is 422 `validation` with a Polish message (for example "każdy cel leży poza dozwolonymi sieciami polityki bezpieczeństwa albo blokadą operatora (CZUJKA_ALLOWED_NETWORKS: …); <address>: <reason>"). An ad-hoc run never marks hosts or services of other addresses as missing and does not change the speed history of the profile |
| PATCH `/runs/{id}` | scans:run | `{note, label}` → `ScanRun`; note up to 4000 characters, label one line up to 100; the `q` filter of `GET /runs` searches both |
| POST `/runs/{id}/pause` · `/resume` · `/cancel` | scans:run | → `ScanRun` |
| GET `/runs/{id}/chunks` | scans:read | → `Chunk[]` |
| GET `/runs/{id}/map` | scans:read | → `{blocks:[{cidr, size, status, hosts_up}]}` (/24 blocks for the address-space map) |
| GET `/runs/{id}/events` | scans:read | SSE: events `progress` (`ScanRun`), `chunk` (`Chunk`), `host` (`{ip, up, services}`), then one final event: `done` (`ScanRun`; the run ended: `completed`, `failed` or `cancelled`) or `paused` (`ScanRun`; the run stopped and can be resumed: `pause_reason` is `user`, `window` (`resume_at` set), `emergency_stop` or `shutdown`). The stream closes after the final event. A client that connects to a run that is already paused gets `paused` at once |
| GET `/events` | results:read | SSE: global events `run` (`ScanRun`), `change` (`Change`), `finding` (`Finding`) |
| POST `/hosts` | results:create | manual entry: `{ip, hostnames, up (default true), os_guess, mac, observed_at, services: [{port, proto (tcp), state (open), name, product, version, banner, tls, title, url, http_status, technologies}]}` → 201 `{run, host}`. Stored through the same ingest and analysis as a scan, as a run with `trigger: "manual-entry"` and reason `manual`. Manual entry is partial data: services that it does not name stay as they are |
| POST `/hosts/{id}/services` | results:create | one service (fields as above) or `{services: [...]}` for a known host → 201 `{run, host}` |
| GET `/hosts` | results:read | filters `status, tag, scope_id, cidr, tech, port, min_interest, unstable` → `Page<Host>`. Default order: interest, highest first, where a `down` host counts as interest 0, so live hosts come first (the same with `sort=-interest`; the returned `interest` is unchanged). No default status filter |
| GET `/hosts/{id}` | results:read | → `Host` |
| PATCH `/hosts/{id}` | results:update | `label, owner, criticality, note, tags, hostnames, os_guess` |
| DELETE `/hosts/{id}` | results:delete | |
| GET `/hosts/{id}/services` | results:read | → `Service[]` |
| GET `/hosts/{id}/availability` | results:read | → `AvailabilityProfile` |
| GET `/hosts/{id}/changes` | results:read | → `Page<Change>` |
| GET `/services` | results:read | filters `host_id, port, state, name, tech, class, tag, group_key, min_interest, tls, run_id` → `Page<Service>`. With `run_id`, each item also has `carried: true` when that run did not scan the service's port (see Port coverage). Default order: interest, highest first, where a service that is not `open` (gone, unknown, filtered) counts as interest 0, so open services come first (the same with `sort=-interest`; the returned `interest` is unchanged). No default state filter |
| GET `/services/{id}` | results:read | → `Service` with `latest` |
| PATCH `/services/{id}` | results:update | `name, product, version, note, tags, classes` |
| DELETE `/services/{id}` | results:delete | |
| GET `/services/{id}/observations` | results:read | → `Page<ServiceObservation>` |
| GET `/services/{id}/response-times` | results:read | `?limit=` (1–500, default 50) → `{service_id, rule: {baseline_n, slow_factor, slow_min_ms}, points: [{run_id, at, ms, baseline_ms, slow}]}`, oldest first, one point per run; `ms: null` = the port was open and HTTP did not answer; `baseline_ms: null` = no baseline yet |
| GET `/service-groups` | results:read | → `Page<ServiceGroup>` |
| GET `/technologies` | results:read | → `NameCount[]` (name, count, extra = category) |
| GET `/changes` | results:read | filters `run_id, kind, severity, host_id, acked, expected, from, to` → `Page<Change>`. `deep_pass`: the change concerns a service that the run's deep pass scanned ("found by the deeper pass") |
| GET `/changes/{id}` | results:read | → `Change` |
| POST `/changes/{id}/ack` · POST `/changes/ack` | results:update | `{ids}` |
| GET `/diff?from={runId}&to={runId}` | results:read | → `DiffReport` |
| GET `/findings` · GET `/findings/{id}` | results:read | filters `status, severity, type, host_id, tag, min_interest, exported` → `Finding` |
| POST `/findings` | results:create | manual `Finding` |
| PATCH `/findings/{id}` | results:update | `title, description, severity, status, note, tags, assignee`. Reopen rule (engine findings and policy findings alike): a scan or a rule evaluation never changes `accepted` or `false_positive` (set by an analyst or by the DefectDojo pull). A `resolved` finding goes back to `new` only when its cause is observed after the resolution (the observation time of the host or service is later than the time the finding became resolved): once per resolution, with an audit entry `finding.reopen` (by `system`, detail `{from, to, resolved_at, seen_at, run_id, reason}`). An evaluation over unchanged data does not reopen it. With `status_sync` the reopen goes to DefectDojo through `/defectdojo/sync` |
| DELETE `/findings/{id}` | results:delete | |
| POST `/findings/export/defectdojo` | export:run | `{ids}` or `{filter}` → `DojoExportResult`; writes `dojo_id` and `dojo_url` back to each finding; a second export updates and does not duplicate. When DefectDojo accepts the import and then stops answering before the read that confirms it: 502 code `dojo_unconfirmed`, message "Wysłano, nie potwierdzono: powtórz eksport. …" (details: the `DojoExportResult`). Repeating the export, or `POST /defectdojo/pull`, links those findings by key (`unique_id_from_tool`) without duplicates. With `scope_mappings` in the settings, the findings of a host in a mapped scope go to the product and engagement of that scope (first matching mapping by scope id), the rest to the default target |
| POST `/defectdojo/pull` | results:update | `?apply=true` → `{checked, updates: [{finding_id, key, dojo_id, from, to, dojo_changed_at, reason}], conflicts, missing, errors, applied, linked}`. First links by key the findings that an unconfirmed export sent (`linked`: `dojo_id` and `dojo_url` written; nothing is created in DefectDojo). Then reads the DefectDojo state of every exported finding and proposes Czujka status changes (DefectDojo mitigated → resolved, false positive → false_positive, risk accepted → accepted, active again → new). Without `apply` nothing changes. A status that a Czujka analyst set wins: it is reported as a conflict, not applied. Applied changes are edits by `defectdojo` in the audit log. 409 `not_configured` without URL and API key |
| POST `/defectdojo/sync` | export:run | → `{closed, reopened, skipped, errors}`: closes in DefectDojo the exported findings that Czujka resolved (mitigated) and reopens the ones Czujka sees again |
| POST `/import/findings` | results:create | multipart `file` (+ optional `format`, `source`): DefectDojo Generic Findings JSON or CSV, a DefectDojo API findings list, or the Czujka findings export (`/export/findings.{json,csv}`, `/export/findings.dojo.{json,csv}`); the format is detected → 201 `{format, findings, skipped, invalid, created, updated, hosts_created, run_id}`. A finding is matched by its key (a Czujka key, `unique_id_from_tool`, or title + host + port), so a second import updates and does not duplicate. A host that the file names and the inventory does not know is entered by hand (one `manual-entry` run, the finding ports as open services); a finding without a host address is skipped with a Polish reason |
| GET `/export/findings.dojo.json` · `.dojo.csv` | export:run | the findings (list filters apply) in DefectDojo Generic Findings format: upload in DefectDojo as "Generic Findings Import"; imports again through `/import/findings` |
| POST `/runs/{id}/export/defectdojo` | export:run | uploads the nmap XML of the run as an "Nmap Scan" import → `{test_id, test_url, reimport, mode, title, created, closed, reactivated, untouched, total}`. The test is keyed by the profile and the engagement: title `Czujka nmap: profil <profile_id>` (a run without a profile: `Czujka nmap: przebieg <run_id>`). The first upload of a profile imports a new test (`mode: "import"`); every later run of that profile re-imports into the same test with `close_old_findings=true` (`mode: "reimport"`, `closed` = what the new XML no longer has). Upload runs in time order: an older run uploaded after a newer one closes what only the newer one saw |
| GET `/signatures` · GET `/signatures/{id}` | signatures:read | filters `category, enabled, builtin, tag` → `Signature` |
| POST `/signatures` | signatures:create | `{yaml, enabled}` → `Signature` (rejected with `unsafe_signature` when the validator finds a safety issue) |
| PATCH `/signatures/{id}` | signatures:update | `{yaml, enabled}` |
| DELETE `/signatures/{id}` | signatures:delete | |
| POST `/signatures/validate` | signatures:read | `{yaml}` → `SignatureValidation` |
| POST `/signatures/retrohunt` | signatures:read | `{yaml}` or `{id}`, optional `{latest_only}` → `RetroHuntResult` Without results:update the stored cookie values are blanked before matching: a cookie rule then matches on name and flags only, so retro-hunt cannot be used to guess a hidden value |
| POST `/signatures/import` | signatures:create | a whole signature file in any accepted format (Czujka YAML, a YAML or JSON list, a map keyed by name, passive nuclei templates): multipart `file` or `text`, JSON `{text}`, or the raw body → `{created, updated, skipped: [{slug, reason}], validation}`. 201 when at least one signature was stored; 422 `validation` with the same report in `details` when none was. A rejected signature is not stored; its reasons are in `validation.issues`. Built-in signatures are never replaced |
| GET `/runs/{id}/report.html` · GET `/runs/{id}/report.md` | results:read | the report of one run (summary, changes, top findings and services, unstable hosts, parameters, traffic, safety policy) as a self-contained HTML page or Markdown; `?download=1` sends it as an attachment |
| POST `/passive/import` | targets:create | multipart `file`: DNS zone, CSV, JSON or JSONL with hostnames and addresses → `PassiveResult` `{facts, out_of_scope, candidates: [{kind, value, hostnames, ports, sources, last_seen, reason}], hints, sources, file}`. Nothing is saved; facts outside every scope are listed, never candidates |
| POST `/passive/ptr` | results:update | reverse DNS (system resolver, at most 5 lookups/s) of the known live hosts; the names are added to those hosts (not to a host whose hostnames an analyst set) → `PassiveResult` with `hosts_updated` |
| POST `/passive/crtsh` | targets:create | asks crt.sh (an external service) for the certificates of the scope domains → `PassiveResult`. 409 `disabled` until an administrator sets `crtsh_enabled` |
| POST `/passive/confirm` | targets:create | `{scope_id, candidates: [{value, sources, note}]}` → `TargetPreview` (saved); the targets get `source: "passive"` and the tag `passive` |
| GET `/settings/passive` · PUT | integrations:manage | `{crtsh_enabled}` (default false) |
| GET `/tags` | results:read | → `NameCount[]` |
| POST `/import/results` | results:create | multipart `file` (nmap XML, Czujka JSON, CSV; the format is detected), optional `scope_id` → `ImportReport`. Imported hosts take the same ingest and analysis as scanned ones (run with `trigger: "import"`). `hosts` counts answering hosts, `hosts_down` the hosts that the file reports as down (a known one is a miss for the availability model, an unknown one is not stored); `skipped` counts only unusable rows. A known host that the file does not name is not a miss. With `scope_id` the caller also needs targets:create (otherwise 403): the answering hosts that the scope does not cover become IP targets of that scope (`source: "import"`, allowed networks apply; their count is `targets`) |
| GET `/export/{kind}.{fmt}` | export:run | kind `hosts, services, findings, changes, signatures`; fmt `json, csv`; list filters apply; `/export/runs/{id}.{json,csv,xml}`: json = Czujka JSON (lossless `HostResult` records), csv = one row per service, xml = nmap XML (for DefectDojo "Nmap Scan"); all three are written by `internal/interchange` (one CSV dialect) and import again through `/import/results`. A service the run did not scan is marked: JSON `carried: true`, CSV column `carried` = `true`, nmap XML port `reason="czujka-not-scanned"`; an import skips such services (they were not observed) |
| GET `/dashboard` | results:read | → `Dashboard`. `last_run`, `headline.new_since_last_run`, `gone_since_last_run`, `hosts_missing` and `trend` come only from full runs: completed runs of a profile over its whole scope (trigger `manual` or `schedule`; not ad hoc, `reprobe`, `import` or `manual-entry`). `trend` holds the full runs of the profile of the last full run, so the deltas of two neighbouring points compare two full runs of one profile. `headline.last_partial` = `{run_id, trigger, addresses, at}` of the newest completed partial run when it is newer than the last full run, else `null`; show it on its own line. The counts (`hosts_up`, `services_open`, …) are the current inventory |
| GET `/settings/safety` | scans:read | → `SafetyPolicy` plus `kernel_cap: {mode, active, pps, burst, policy_pps, dropped, reason}` (read only, not stored): the kernel packet cap (internal/kcap). `mode` is `auto`, `require` or `off`; `pps` and `burst` are the kernel limit (`policy_pps` × 1.1, a tenth of a second of it), 0 when not active; `dropped` counts probe packets the kernel dropped since the start; `reason` says why the cap is not active, e.g. `unavailable: host network (…)` |
| PUT `/settings/safety` | safety:manage | `SafetyPolicy` (a partial body keeps the other fields). The answer carries `kernel_cap` as GET does; a new `max_pps` replaces the kernel rule at once, and every save retries a failed install. Only the fields the request changes are validated, so a value stored before a rule (or before the lock) does not block other edits. 422 messages are Polish, code `validation`. `allowed_networks` (IP or CIDR list; empty = no limit): a target outside it is refused at entry (`/scopes/{id}/targets`, `/targets/preview`, imports, ad-hoc runs) with a Polish reason in `invalid`; a domain is allowed only when every address it resolves to is inside; the runner checks again when it builds the plan and drops what is outside. `operator_networks` is read only: the operator lock from `CZUJKA_ALLOWED_NETWORKS`. Every new entry of `allowed_networks` must lie inside it (else 422); targets, ad-hoc runs and re-probes outside it are refused. At start, the stored `allowed_networks` are intersected with the lock: a network inside stays, a wider one is replaced by the lock networks inside it, one with nothing in common is dropped; a change is logged and audited (action `safety.lock_clamp`, by `system`, detail `{lock, before, after, dropped, narrowed}`) |
| POST `/emergency-stop` | safety:stop | → `SafetyPolicy` (sets the flag; every running run stops at once and becomes `paused` with `pause_reason: "emergency_stop"`; its SSE stream sends `paused`, not `done`: the run is not finished and can be resumed after the release; new runs, ad-hoc runs and resumes answer 409 `emergency_stop`) |
| POST `/emergency-stop/release` | safety:manage | → `SafetyPolicy` (clears the flag; paused runs stay paused until someone calls `/runs/{id}/resume`) |
| GET `/settings/defectdojo` · PUT · POST `/settings/defectdojo/test` | integrations:manage | `DefectDojoSettings` → `{ok, message, version}`. `link_url`: the public base of every DefectDojo link that Czujka stores and shows (`dojo_url` of findings, `test_url`, product and engagement links); empty = `url`. Set it when Czujka reaches DefectDojo at an address a browser cannot open (for example `url: http://host.docker.internal:18080`, `link_url: https://dojo.example.org`). It must be an http or https address with a host (else 422). `scope_mappings: [{scope_id, product_type_name, product_name, engagement_name}]` (each scope at most once; the scope must exist). `status_sync`: after every analysed run, close resolved findings in DefectDojo, reopen observed ones and apply the status pull (result in the audit log, action `finding.sync.defectdojo`). The stored API key goes only to the stored address (scheme, host, port): a test or a save with another `url` and no `api_key` is 422 |
| GET `/settings/webhook` · PUT · POST `/settings/webhook/test` | integrations:manage | `WebhookSettings` `{enabled, url, min_severity, secret (write-only), secret_set, ui_url}`; PUT also takes `clear_secret: true`. `url` must be http or https with a host (else 422); it is stored encrypted together with `secret`. An empty `secret` keeps the stored one. `min_severity`: `info`, `low`, `medium` (default) or `high`. `ui_url`: the public address of Czujka for the links; empty = the address the settings were saved from. The test sends one message with `event: "test"` and answers `{ok, status, ms, error}` (always 200; `ok: false` on failure). It uses the stored settings; `url` and `secret` in the body override them, so a form can test before saving. See "Alert webhook" below |
| GET `/healthz` | public | Without a session (also at the root `/healthz`) → only `{status, version}` (503 with `status: "error"` when the database does not answer). With a session → `{status, version, db, tde, tde_detail, field_encryption, engine, probe: {prober, mode, raw_sockets}}`; `kernel_cap` (as in `/settings/safety`) only for a session with `safety:manage`; `host_gateway`: the IPv4 address loopback targets are scanned as (empty when the mapping is off); `probe.mode` is `nmap-raw` (SYN scan, ICMP/ARP discovery), `nmap-connect` (no raw sockets: `-sT`) or `native` (Go TCP connect, no nmap) |
| GET `/doctor` | safety:manage | → `{ok, version, checks: [{name, title, status: ok|warn|fail, detail, fix}]}`: the installation check of `czujka doctor` (database, pg_tde, master key, nmap version, raw sockets, DNS, free disk, pg_dump/pg_restore, routes to the scan networks of enabled scopes; no packet is sent). `fix` is a Polish instruction |

## Notes

- **Change summaries and language.** `Change.summary` is rendered when the change is read, from its stored fields (`kind`, `ip`, `port`, `field`, `before`, `after`, `expected`, `detail`), by one function (`analyze.RenderSummary`). The language comes from `?lang=en|pl`; without it, from the first tag of `Accept-Language` (`en`, `en-*` → English); default Polish. This holds for `/changes`, `/changes/{id}`, `/hosts/{id}/changes`, `POST /changes/{id}/ack`, `/diff`, `/dashboard` (`recent_changes`) and `/export/changes.{json,csv}`. The run report, the webhook and the live SSE stream use Polish. `Change.detail` (object, optional) holds the values behind the sentence and the internal measures: `rule`, `p_alive`, `misses_to_down`, `open_services`, `services`, `ports`, `product`, `name`, `expired`, `self_signed`, `values`, `flags`, `simhash_distance`, `pattern`, `stability_pct`. Changes stored before migration 0007 have no `detail`: the server reads the missing values from their stored text, so they also render in the current wording and in both languages. For an unknown kind the stored text is returned. The change search (`q`) matches the stored Polish text. Host-state values in `before`/`after` (field `status`): `up`, `missing` (not responding, unconfirmed), `down`, `unstable`, `expected-offline` (outside usual hours).
- **Language of the other server texts.** Every API response carries `Content-Language: en|pl` (and `Vary: Accept-Language`), chosen like the change summaries (`?lang=`, then `Accept-Language`, default Polish). The store keeps Polish; English is rendered when the answer is written, from stable fields (finding type, rule id, signature slug, reason code, counts) and the data parts of the stored text, so rows of every earlier build render in both languages and Polish output is the stored text. In English: `Finding.title`, `description` and `evidence[].snippet` (`/findings`, `/findings/{id}`, PATCH `/findings/{id}`, `/dashboard` `top_findings`, `/rules/{id}/violations`); `Service.interest_why[].text`, `technologies[].name` and the match and technology names of `latest` (`/services`, `/services/{id}`, `/hosts/{id}/services`, `/dashboard` `top_services`, `certs_expiring`); built-in signature `name` and `description` while unedited (`/signatures`; YAML key `name_en`, `description_en`); built-in rule `name` and `description` while unedited (`/rules`, `/rules/{id}`), the dry-run `message`, `condition` and violation `summary`; `ScanRun.profile_name` "wpis ręczny" (manual entry) and the default profile "Domyślny" (`/runs`, `/profiles`, `/dashboard`); the time machine's `diff_to_now.sentences` (from the counts), finding titles, technology names and run profile name; built-in role `name` and `description` (`/roles`); `RunStats.warnings` and `notes`, `ad_hoc.reason` and `error` of runs; passive candidate `reason`; retro-hunt `notes`; the re-probe plan (`blocked`, probe and skip `reason`); the webhook test `error`; `error.message` of the known messages (`internal/i18n`). `/export/findings.{csv,json}?lang=en` writes findings in English. Manual and imported findings, rule YAML and analyst-written text stay as written. Exports and run reports read only `?lang=` (default Polish); the DefectDojo export always keeps Polish. No new response field.
- **host_missing.** A host that answered in the previous run and is silent now, but is not yet reported inactive, gets the change `host_missing` (severity medium). Its open services count in `summary.services_unreachable`; they are not gone. `Headline.hosts_missing` on the dashboard counts these hosts of the last run; the global SSE stream sends the change as `change`. `host_gone` follows when the model (or the profile rule `retry.down_after_misses`) reports the host inactive.
- **Services of a host that went down.** When a scan reports a known host as down, its open and filtered services become `unknown` (not gone: the port was not checked). A service becomes `gone` (change `service_gone`) only when a full scan finds the host up and the port not open.
- **down_after_misses** in `AvailabilityProfile`: how many misses in a row, counted from now, would report the host inactive. For a host that is already down it is the rule value of the profile (`retry.down_after_misses`, or the model threshold), never 0.
- **Partial data.** Runs with `trigger` `import`, `manual-entry` and `reprobe` do not mark services that they do not name as gone, and `manual-entry` does not resolve stale findings.
- **Per-run dedup.** The sink stores at most one observation per host per run: a later "up" of the same run corrects an earlier "down", a later "down" never hides an earlier "up".
- **Schedules.** Saving a profile never starts a run. A schedule that never ran is first due one interval after the save (interval schedule without windows), at the first window start after the save (interval schedule with windows), or at the first cron time after the save. After a run, the next one is due one interval after its start, moved to the next window when it falls outside the windows.
- **Profile fields.** `discovery.mode` is `balanced` (default), `fast` or `thorough`. `udp: {enabled, ports}`: UDP ports are limited to the allow-list of harmless protocol queries (53, 123, 137, 161, 500, 1900, 5353) and to the allowed and denied ports of the policy; a list that leaves none answers 422.
- **Loopback targets and the docker host.** In a container with a host gateway (`CZUJKA_HOST_GATEWAY`, default the IPv4 address of `host.docker.internal`), the targets `localhost`, a single `127.x` and `::1` are scanned as the gateway. `Target.maps_to` (preview, target list, save, PATCH) gives that address; it is absent when the target is scanned as itself. Exclusions and the operator lock apply to the mapped address. The host is stored under the gateway address with the hostname `localhost` and the label "Host dockera (ten komputer)" (only when it has no label). Czujka's own UI on that host (`CZUJKA_PUBLISHED_PORT`, title "Czujka") gets the tag `czujka` and produces no findings; the same holds for `127.0.0.1` in host-network mode.
- **service_returned.** A service (same host, port, protocol) that was open in an earlier run, not open in the previous one, and is open now: kind `service_returned` (low; medium for sensitive classes), `field: "state"`, `before: {state: "gone", last_open_run_id, last_open_at, away_seconds, runs_away}`, `after: "open"`. A service seen open before is never `service_new`. `summary.services_returned` counts them.
- **Response time.** Every service observation keeps the time of the first HTTP request (`result.http.response_ms`). Baseline: the median of the last 5 answered observations that were not slow themselves (one is enough). `response_slower` (low) when the time is at least 2× the baseline and at least 300 ms above it, or when the port is open and HTTP no longer answers; `response_recovered` (info) when a slow service is back to normal. Reported on the transition only. `field: "http.response_ms"`, `before: {baseline_ms, ms}`, `after: {ms}` or `{ms: null, error: "no_answer"}`. `summary.responses_slower` counts them. Service items carry `response_ms` (latest observation, null without an HTTP answer) and `response_slow` (that observation was slow).
- **Port coverage.** The engine reports, per host, the ports a run covered: the profile's list, plus the full-range or dense pass when it finished for that host, plus the UDP ports. A complete run marks a service `gone` (and reports `service_gone`) only on a covered port. A service on a port outside the coverage (full range skipped: more than 16 hosts, stopped, timed out) keeps its state, and the run stores a copy of its last observation with `result.carried = true`; no change is reported, the next run compares with that copy, and the response-time series skips copies. `RunStats.services_open` and `http_services` count only the services the run saw (no carried ones); the run report prints the carried count next to that figure and marks carried rows "nie skanowana w tym przebiegu". The time machine's `services_open` is the inventory as of the run, carried services included.
- **Sub-routers.** Other packages can mount routes under `/api/v1` through `Deps.Mounts` (`api.Mount{Pattern, Router func(guard api.Guard) http.Handler}`). `api.Guard` is the permission middleware of this router (`guard(model.PermResultsRead)`); `api.WriteJSON` and `api.WriteError` write answers in the format above.

## API with curl

There are no API tokens. A script logs in like the browser: a session cookie, and the CSRF token from the login answer in the `X-CSRF-Token` header of every request that changes data (POST, PUT, PATCH, DELETE). A missing or wrong token answers 403; no session answers 401. Checked against a running server on 21.11.2026.

```sh
# 1. Log in. The session cookie goes to the jar; the answer carries the CSRF token.
C=http://127.0.0.1:8080/api/v1
CSRF=$(curl -s -c jar.txt -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.org","password":"..."}' $C/auth/login | jq -r .csrf_token)

# 2. Read: only the cookie.
curl -s -b jar.txt "$C/profiles" | jq '.items[] | {id, name}'

# 3. Change: the cookie and the X-CSRF-Token header. Start a run of profile 1.
RUN=$(curl -s -b jar.txt -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"profile_id":1}' $C/runs | jq -r .id)
curl -s -b jar.txt "$C/runs/$RUN" | jq '{id, status, stats}'

# 4. Export the run and the findings.
curl -s -b jar.txt -o run-$RUN.json "$C/export/runs/$RUN.json"
curl -s -b jar.txt -o findings.csv "$C/export/findings.csv"

# 5. Log out.
curl -s -b jar.txt -H "X-CSRF-Token: $CSRF" -X POST $C/auth/logout
```

- The profile needs a scope: a profile without one answers 422 `profil nie ma zakresu`. „Ten komputer” in the UI creates a profile with a scope.
- The session lasts `CZUJKA_SESSION_TTL` (default 12 h). Logins are rate limited per address (`CZUJKA_LOGIN_RATE_PER_MIN`, 429) and an account is locked for `CZUJKA_LOGIN_LOCKOUT` after `CZUJKA_LOGIN_MAX_FAILURES` failures; the counter starts again when a lock expires. A locked account answers exactly like an unknown account or a wrong password (401 `unauthorized`, "invalid e-mail or password"); only the audit entry says `reason: locked`. `czujka user unlock EMAIL` clears a lock. The login body is at most 8 KiB and the audited e-mail at most 254 characters. Requests without a session (failed logins, rejected calls) are audited within a budget (a burst of 60, then 1 per second); the next written entry carries `dropped_before` with the count of dropped ones.
- Use an account with only the permissions the script needs (for example a custom role with `scans:run` and `export:run`).

## Alert webhook

After every analysed run (scan, re-probe, import, manual entry), Czujka sends one `POST` to the configured URL, when the webhook is enabled and the run has at least one change or new finding at `min_severity` or above. Otherwise it sends nothing.

- Headers: `Content-Type: application/json`, `User-Agent: Czujka/1.0 (webhook)`, `X-Czujka-Event: run.analyzed` (or `test`), and with a secret `X-Czujka-Signature: sha256=<hex HMAC-SHA256(secret, raw body)>`.
- One attempt, 10 s timeout, no retry, redirects not followed. A status outside 2xx is a failure. Every delivery (and every test) writes an audit entry `integration.webhook.send` with `{run_id, status, ms, changes, findings, error}`.
- Body:

```json
{
  "event": "run.analyzed",
  "run_id": 12,
  "run_url": "https://czujka.example/runs/12",
  "trigger": "manual",
  "scope": "profil dmz",
  "finished_at": "2026-11-21T18:00:00Z",
  "counts": {"service_new": 1, "service_gone": 1, "host_missing": 1, "findings_new": 1},
  "changes": [{"kind": "service_new", "severity": "medium", "ip": "10.0.0.1", "port": 8080,
               "summary": "Nowa usługa 10.0.0.1:8080 (Jenkins)", "url": "https://czujka.example/services/9"}],
  "findings": [{"kind": "finding", "severity": "high", "ip": "10.0.0.1", "port": 8080,
                "summary": "Panel administracyjny: Jenkins", "interest": 80, "url": "https://czujka.example/hosts/1"}],
  "text": "*Czujka: przebieg #12 przeanalizowany* (profil dmz)\nnowe usługi: 1, ...\n• [wysoka] Panel administracyjny: Jenkins (10.0.0.1:8080) https://czujka.example/hosts/1\n...\nPrzebieg: https://czujka.example/runs/12"
}
```

- `counts` is `summary.by_kind` of the run plus `findings_new`. `changes` (at most 10, highest severity first) holds the kinds `host_new`, `service_new`, `host_gone`, `service_gone`, `host_missing`, `service_unreachable`, `host_back`, `service_returned` and `response_slower` at `min_severity` or above; expected changes are left out. `findings` (at most 5) are the findings first seen in this run, by severity and interest.
- `text` is a Polish plain-text message with bare URLs. Slack and Mattermost incoming webhooks render it as is; other receivers read the JSON fields.

## Exposure rules and signature from an example

Routes of `internal/rules` (mounted at `/rules`) and `internal/sigsuggest`. Read, validate and dry-run need `results:read` (rules are a view on the results). Writing a rule needs the signature permissions (`signatures:create`, `signatures:update`, `signatures:delete`): a rule is detection content, edited by the same roles. A manual evaluation stores findings, so it needs `results:update`. A signature suggestion only reads: `signatures:read`.

| Method and path | Permission | Body → answer |
| --- | --- | --- |
| GET `/rules` | results:read | → `Page<Rule>` (built-in first, then by `slug`) |
| GET `/rules/{id}` | results:read | → `Rule` |
| POST `/rules` | signatures:create | `{yaml, enabled?}` → 201 `{rule, validation}`; 422 `validation` with `details: Validation`; 409 when the `id` is taken |
| PATCH `/rules/{id}` | signatures:update | `{yaml?, enabled?}` → `{rule, validation}`; 409 when the text of a built-in rule changes |
| DELETE `/rules/{id}` | signatures:delete | 204; 409 for a built-in rule (it can only be disabled) |
| POST `/rules/validate` | results:read | `{yaml}` → `Validation` |
| POST `/rules/dry-run` | results:read | `{yaml, limit?: 500}` → `DryRunResult` (nothing stored) |
| POST `/rules/evaluate` | results:update | → `Report` (evaluates every enabled rule now) |
| GET `/rules/{id}/violations` | results:read | `status=new,triaged`, `limit`, `offset` → `Page<Finding>` |
| POST `/signatures/suggest` | signatures:read | `{service_id}` → `Suggestion`; 404 when the service has no observation |

A create, update or delete starts a full evaluation in the background. The rules are also evaluated after the analysis of every run, import, manual entry and re-probe run (before the DefectDojo step).

```text
Rule          {id, slug, name, severity, description, yaml, enabled, builtin, author, violations (at the last evaluation), last_eval_at, created_at, updated_at}
Validation    {ok, issues: [{level: error | warning, path, message (Polish), safety}]}   // SignatureValidation without "paths"
DryRunResult  {validation, total, truncated, hosts, services, took_ms, condition, message (Polish),
               violations: [{rule, rule_name, severity, subject: service | host | scope, key, host_id, ip, service_id, port, proto,
                             url, title, summary, evidence: Evidence[], interest, storable}]}
Report        {run_id, rules, rejected, hosts, services, violations, stored, created, resolved, by_rule, eval_ms, store_ms, took_ms}
Suggestion    {ok, message (Polish), service_id, target, slug, name, yaml,
               rules: [{kind, feature, rule, weight, df, others, explanation}], rejected: [{kind, value, reason}],
               validation, retro_hunt: {scanned, total_hits, packets_sent, hits (at most 50)}, matches_target, other_matches,
               candidates, others_http, others_tls, look_alikes, history, took_ms}
```

- `storable: false` only for a `per: scope` assertion on an empty scope (a finding needs a host). `rejected` in `Report` lists stored rules that the validator no longer accepts (not evaluated).
- A violation is a normal `Finding`: `type: "policy-violation"`, `signature: "policy:<slug>"`, key `policy-violation|<slug>|<IP>|<port>/<proto>`; filter `GET /findings?type=policy-violation`. The analyst fields (status, note, tags, assignee, edited severity and title) are never overwritten. The run analysis never resolves these findings; the rule evaluation resolves them when the cause is gone.
- A suggestion stores nothing. With no distinctive feature it answers `ok: false`, `yaml: ""` and says why in `message`. The analyst saves the YAML through `POST /signatures`.

## Time machine

Routes of `internal/timeline`. `Page<T>` lists take `limit` (default 50, max 1000) and `offset`; times are RFC 3339.

| Method and path | Permission | Query → answer |
| --- | --- | --- |
| GET `/timeline` | results:read | optional `from`, `to` → `{runs: RunPoint[], from, to, took_ms}`: every analysed run, oldest first |
| GET `/timeline/at` | results:read | `run_id` or `at` (the last analysed run at or before it; neither: the last run), plus the filters of the three lists below → `{run, summary, hosts: Page<AtHost>, services: Page<AtService>, findings: Page<AtFinding>, took_ms}` |
| GET `/timeline/at/hosts` | results:read | `run_id` or `at`; `status` (up, unstable, expected-offline, down, unknown, `missing` = every silent status but down), `cidr`, `q`, `scope_id`, `port`; `sort` `ip`, `-ip`, `observed_at`, `-observed_at`, `status` → `Page<AtHost>` |
| GET `/timeline/at/services` | results:read | `run_id` or `at`; `host_id`, `port`, `name`, `tech`, `class`, `state` (open, unknown, gone, `all`; default open and unknown), `tls`, `cidr`, `q`; `sort` `ip`, `port`, `-port`, `observed_at`, `-observed_at` → `Page<AtService>` |
| GET `/timeline/at/findings` | results:read | `run_id` or `at`; `severity`, `type`, `host_id` → `Page<AtFinding>`, most interesting first |
| GET `/timeline/hosts/{id}` | results:read | → `HostLife` `{host_id, ip, status_now, first_seen, last_seen, host: Interval[], services: ServiceLane[]}` (swim lanes) |
| GET `/timeline/services/{id}` | results:read | → `ServiceHistory` `{service_id, host_id, ip, port, proto, observations, changed: FieldHistory[], unchanged: {field: value}}` |

## Re-probing

Model-driven confirmation probes (`internal/reprobe`). When a host goes `host_missing`, Czujka probes only that address and its known ports again after 10, 30 and 90 minutes (configurable), so a host that really went away becomes `host_gone` without a full scan, and a host that was only briefly silent returns to `up`. Hosts that answer irregularly get a probe in an hour when the availability model expects them up.

**On by default.** A fresh installation stores `enabled: true`. Re-probing sends the profile's own safe probes to single addresses that a scan already found, within the hourly budget, the scan windows, the safety policy and the emergency stop. `PUT /settings/reprobe {"enabled": false}` turns it off.

| Method and path | Permission | Body → answer |
| --- | --- | --- |
| GET `/reprobe/plan` | scans:read | → `Plan` `{generated_at, enabled, blocked, budget_per_hour, used_last_hour, due_now, active_reprobe, probes: Probe[], skipped: Skip[], settings}` |
| GET `/settings/reprobe` | scans:read | → `Settings` |
| PUT `/settings/reprobe` | scans:configure | partial `Settings` `{enabled, budget_per_hour, backoff_minutes, likely_up_rate, max_ports_per_host}` → `Settings`; 422 `validation` on a bad value |

A re-probe is a normal run: `trigger: "reprobe"`, `profile_id: null`, `ad_hoc` = the addresses and the union of their known ports (empty: the profile ports), with the rates, detection and HTTP options of the host's profile. Only addresses inside an enabled target are probed; a host that only an import or a manual entry knows is skipped. It goes through the same engine (safety policy, exclusions, allowed networks, rate limits, emergency stop), sink, analysis and rule evaluation as `POST /runs/adhoc`. Every requested address that the inventory knows is a hint of the plan, so a silent one gets a down observation. Services of the probed hosts outside the probed ports are not touched; a probed port that no longer answers on a live host becomes `gone`.

### Time machine: definitions

- **Runs on the time line**: analysed runs (`runs.summary IS NOT NULL`), ordered by id. "As of run R" means every observation of a run with id ≤ R. A run's time is `finished_at`, else `started_at`, else `created_at`.
- **Host as of R**: the state of its latest observation as of R: `up`, or the status the availability model gave it then (`unstable`, `expected-offline`, `down`, `unknown`).
- **Service as of R**: its latest observation as of R (product, version, title, HTTP status, TLS, technologies and classes from that observation). It is `gone` when its host answered in a later run (≤ R) that did not see it, `unknown` when its host was silent in every later run, `open` otherwise. A run that did not cover the service's port stores a carried copy, so the service stays `open` and `carried` is true when that copy is the observation used. A service not probed in R keeps its last earlier observation. `changed_since` is true when product, version or title differ today.
- **Finding open at R**: first seen in a run ≤ R and before R's time, and not resolved before R (a resolved finding keeps its `last_run_id`). The past triage status is not stored; `status_now` is today's.

### Time machine and re-probing: types

```text
RunPoint     {run_id, at, trigger, status, profile_name,
              hosts_up, hosts_missing, hosts_down, services_open, services_unknown, findings_open,   // state as of the run
              probed, probed_up, changes, changes_expected, changes_by_kind}                        // what the run did
AtHost       {id, ip, hostnames, label, status, up, observed_at, run_id, status_now, open_ports}
AtService    {id, host_id, ip, port, proto, state, name, product, version, title, http_status, tls,
              technologies, classes, observed_at, run_id, state_now, changed_since, carried}
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
Settings     {enabled: false (fresh installation), budget_per_hour: 200, backoff_minutes: [10, 30, 90], likely_up_rate: 0.6, max_ports_per_host: 32}
```

### Re-probing rules (`reprobe.Build`, a pure function)

- Candidates: hosts with status `unstable` or `expected-offline` whose latest observation is a miss. `down` hosts wait for the next full scan.
- **Confirm**: a host that went `host_missing` (status `unstable`, answered before) gets probes at `first miss + backoff_minutes[k]`, k = reprobes already recorded since the first miss. An overdue step is due now. A miss streak older than the last step plus 12 hours is not confirmed any more. A host with fewer than 8 observations (no rhythm learned yet) uses the steps 1, 3 and 10 minutes instead (`reprobe.YoungBackoffMinutes`), so a host seen in one scan and silent in the next is confirmed inactive about a minute later.
- **Likely up**: other candidates (and confirm hosts after the last step) are probed 5 minutes into the next hour whose model up-rate (`analyze.UpRates`) is at least `likely_up_rate`, where the host really answered on the same type of day (weekday or weekend, hour ±1), after its latest observation or reprobe. It needs at least 8 observations (`analyze.MinObsForExpected`).
- **Safety**: never when `enabled` is false or the emergency stop is set; never an address in the policy exclusions (IP, CIDR, range); the time moves to the next open window of the host's profile (`sched.NextAllowed`), and a likely-up hour without an open window is skipped; at most `budget_per_hour` addresses per hour, counting the reprobes of the last hour (`reprobe_log`); later probes move to the next hour with a note. The engine applies the safety policy again (ports, rates, exclusions).
- The executor (`reprobe.Executor`) runs every minute, starts the due probes as one targeted run per profile with trigger `reprobe`, records them in `reprobe_log`, and starts nothing while a reprobe run is still queued, running or analysing.


### Time machine indexes

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

### Time machine limits

- Run order is run id. A reprobe run created while a long full run is still active gets a higher id than that run even though it finished first.
- "Gone" as of a run assumes the later run looked at the port. A full run with a narrower port list than an earlier one can mark a service `gone` in the time machine while the live inventory keeps it (the live analysis checks the profile's port scope).
- The scrubber result is cached per process until a run is analysed again or a new observation or change arrives; the findings counts are computed on every call.
- `analyze.Diff` emits no `host_back` when an `unstable` host (after `host_missing`) answers again; the host returns to `up` silently. `host_back` comes only after `down` or `expected-offline` (proposed change for `internal/analyze` in the report).
