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
| POST `/targets/preview` | targets:read | `{text}` → `TargetPreview` (nothing saved) |
| PATCH `/targets/{id}` | targets:update | |
| DELETE `/targets/{id}` | targets:delete | |
| GET `/profiles` · GET `/profiles/{id}` | scans:read | → `ScanProfile` |
| POST `/profiles` · PATCH · DELETE `/profiles/{id}` | scans:configure | `ScanProfile` |
| POST `/profiles/{id}/estimate` | scans:read | → `ScanEstimate` |
| GET `/runs` · GET `/runs/{id}` | scans:read | filters `profile_id, status` → `ScanRun` |
| POST `/runs` | scans:run | `{profile_id}` → `ScanRun`; 409 `emergency_stop` while the emergency stop is active (also when the engine is not wired) |
| POST `/runs/adhoc` | scans:run | `AdHocScope` `{profile_id, addresses, ports, reason}` → `ScanRun` with `trigger: "reprobe"`, `ad_hoc` set and `profile_id: null`. Probes only the given addresses (IP or CIDR up to /16, at most 65 536 addresses) and ports (nmap list; empty = the profile ports) through the normal engine, sink and analysis, with the rate, discovery and HTTP settings of the profile (`profile_id` 0 = the first profile). The allowed networks, exclusions and safety policy apply. An ad-hoc run never marks hosts or services of other addresses as missing and does not change the speed history of the profile |
| PATCH `/runs/{id}` | scans:run | `{note, label}` → `ScanRun`; note up to 4000 characters, label one line up to 100; the `q` filter of `GET /runs` searches both |
| POST `/runs/{id}/pause` · `/resume` · `/cancel` | scans:run | → `ScanRun` |
| GET `/runs/{id}/chunks` | scans:read | → `Chunk[]` |
| GET `/runs/{id}/map` | scans:read | → `{blocks:[{cidr, size, status, hosts_up}]}` (/24 blocks for the address-space map) |
| GET `/runs/{id}/events` | scans:read | SSE: events `progress` (`ScanRun`), `chunk` (`Chunk`), `host` (`{ip, up, services}`), then one final event: `done` (`ScanRun`; the run ended: `completed`, `failed` or `cancelled`) or `paused` (`ScanRun`; the run stopped and can be resumed: `pause_reason` is `user`, `window` (`resume_at` set), `emergency_stop` or `shutdown`). The stream closes after the final event. A client that connects to a run that is already paused gets `paused` at once |
| GET `/events` | results:read | SSE: global events `run` (`ScanRun`), `change` (`Change`), `finding` (`Finding`) |
| POST `/hosts` | results:create | manual entry: `{ip, hostnames, up (default true), os_guess, mac, observed_at, services: [{port, proto (tcp), state (open), name, product, version, banner, tls, title, url, http_status, technologies}]}` → 201 `{run, host}`. Stored through the same ingest and analysis as a scan, as a run with `trigger: "manual-entry"` and reason `manual`. Manual entry is partial data: services that it does not name stay as they are |
| POST `/hosts/{id}/services` | results:create | one service (fields as above) or `{services: [...]}` for a known host → 201 `{run, host}` |
| GET `/hosts` | results:read | filters `status, tag, scope_id, cidr, tech, port, min_interest, unstable` → `Page<Host>` |
| GET `/hosts/{id}` | results:read | → `Host` |
| PATCH `/hosts/{id}` | results:update | `label, owner, criticality, note, tags, hostnames, os_guess` |
| DELETE `/hosts/{id}` | results:delete | |
| GET `/hosts/{id}/services` | results:read | → `Service[]` |
| GET `/hosts/{id}/availability` | results:read | → `AvailabilityProfile` |
| GET `/hosts/{id}/changes` | results:read | → `Page<Change>` |
| GET `/services` | results:read | filters `host_id, port, state, name, tech, class, tag, group_key, min_interest, tls, run_id` → `Page<Service>` |
| GET `/services/{id}` | results:read | → `Service` with `latest` |
| PATCH `/services/{id}` | results:update | `name, product, version, note, tags, classes` |
| DELETE `/services/{id}` | results:delete | |
| GET `/services/{id}/observations` | results:read | → `Page<ServiceObservation>` |
| GET `/service-groups` | results:read | → `Page<ServiceGroup>` |
| GET `/technologies` | results:read | → `NameCount[]` (name, count, extra = category) |
| GET `/changes` | results:read | filters `run_id, kind, severity, host_id, acked, expected, from, to` → `Page<Change>` |
| POST `/changes/{id}/ack` · POST `/changes/ack` | results:update | `{ids}` |
| GET `/diff?from={runId}&to={runId}` | results:read | → `DiffReport` |
| GET `/findings` · GET `/findings/{id}` | results:read | filters `status, severity, type, host_id, tag, min_interest, exported` → `Finding` |
| POST `/findings` | results:create | manual `Finding` |
| PATCH `/findings/{id}` | results:update | `title, description, severity, status, note, tags, assignee` |
| DELETE `/findings/{id}` | results:delete | |
| POST `/findings/export/defectdojo` | export:run | `{ids}` or `{filter}` → `DojoExportResult`; writes `dojo_id` and `dojo_url` back to each finding; a second export updates and does not duplicate. With `scope_mappings` in the settings, the findings of a host in a mapped scope go to the product and engagement of that scope (first matching mapping by scope id), the rest to the default target |
| POST `/defectdojo/pull` | results:update | `?apply=true` → `{checked, updates: [{finding_id, key, dojo_id, from, to, dojo_changed_at, reason}], conflicts, missing, errors, applied}`. Reads the DefectDojo state of every exported finding and proposes Czujka status changes (DefectDojo mitigated → resolved, false positive → false_positive, risk accepted → accepted, active again → new). Without `apply` nothing changes. A status that a Czujka analyst set wins: it is reported as a conflict, not applied. Applied changes are edits by `defectdojo` in the audit log. 409 `not_configured` without URL and API key |
| POST `/defectdojo/sync` | export:run | → `{closed, reopened, skipped, errors}`: closes in DefectDojo the exported findings that Czujka resolved (mitigated) and reopens the ones Czujka sees again |
| POST `/import/findings` | results:create | multipart `file` (+ optional `format`, `source`): DefectDojo Generic Findings JSON or CSV, a DefectDojo API findings list, or the Czujka findings export (`/export/findings.{json,csv}`, `/export/findings.dojo.{json,csv}`); the format is detected → 201 `{format, findings, skipped, invalid, created, updated, hosts_created, run_id}`. A finding is matched by its key (a Czujka key, `unique_id_from_tool`, or title + host + port), so a second import updates and does not duplicate. A host that the file names and the inventory does not know is entered by hand (one `manual-entry` run, the finding ports as open services); a finding without a host address is skipped with a Polish reason |
| GET `/export/findings.dojo.json` · `.dojo.csv` | export:run | the findings (list filters apply) in DefectDojo Generic Findings format: upload in DefectDojo as "Generic Findings Import"; imports again through `/import/findings` |
| POST `/runs/{id}/export/defectdojo` | export:run | uploads the nmap XML of the run as an "Nmap Scan" import → `{test_id, test_url, reimport, created, closed, reactivated, untouched, total}`; a second upload of the same run re-imports into the same test |
| GET `/signatures` · GET `/signatures/{id}` | signatures:read | filters `category, enabled, builtin, tag` → `Signature` |
| POST `/signatures` | signatures:create | `{yaml, enabled}` → `Signature` (rejected with `unsafe_signature` when the validator finds a safety issue) |
| PATCH `/signatures/{id}` | signatures:update | `{yaml, enabled}` |
| DELETE `/signatures/{id}` | signatures:delete | |
| POST `/signatures/validate` | signatures:read | `{yaml}` → `SignatureValidation` |
| POST `/signatures/retrohunt` | signatures:read | `{yaml}` or `{id}`, optional `{latest_only}` → `RetroHuntResult` |
| POST `/signatures/import` | signatures:create | a whole signature file in any accepted format (Czujka YAML, a YAML or JSON list, a map keyed by name, passive nuclei templates): multipart `file` or `text`, JSON `{text}`, or the raw body → `{created, updated, skipped: [{slug, reason}], validation}`. 201 when at least one signature was stored; 422 `validation` with the same report in `details` when none was. A rejected signature is not stored; its reasons are in `validation.issues`. Built-in signatures are never replaced |
| GET `/runs/{id}/report.html` · GET `/runs/{id}/report.md` | results:read | the report of one run (summary, changes, top findings and services, unstable hosts, parameters, traffic, safety policy) as a self-contained HTML page or Markdown; `?download=1` sends it as an attachment |
| POST `/passive/import` | targets:create | multipart `file`: DNS zone, CSV, JSON or JSONL with hostnames and addresses → `PassiveResult` `{facts, out_of_scope, candidates: [{kind, value, hostnames, ports, sources, last_seen, reason}], hints, sources, file}`. Nothing is saved; facts outside every scope are listed, never candidates |
| POST `/passive/ptr` | results:update | reverse DNS (system resolver, at most 5 lookups/s) of the known live hosts; the names are added to those hosts (not to a host whose hostnames an analyst set) → `PassiveResult` with `hosts_updated` |
| POST `/passive/crtsh` | targets:create | asks crt.sh (an external service) for the certificates of the scope domains → `PassiveResult`. 409 `disabled` until an administrator sets `crtsh_enabled` |
| POST `/passive/confirm` | targets:create | `{scope_id, candidates: [{value, sources, note}]}` → `TargetPreview` (saved); the targets get `source: "passive"` and the tag `passive` |
| GET `/settings/passive` · PUT | integrations:manage | `{crtsh_enabled}` (default false) |
| GET `/tags` | results:read | → `NameCount[]` |
| POST `/import/results` | results:create | multipart `file` (nmap XML, Czujka JSON, CSV; the format is detected), optional `scope_id` → `ImportReport`. Imported hosts take the same ingest and analysis as scanned ones (run with `trigger: "import"`). `hosts` counts answering hosts, `hosts_down` the hosts that the file reports as down (a known one is a miss for the availability model, an unknown one is not stored); `skipped` counts only unusable rows. A known host that the file does not name is not a miss. With `scope_id`, the answering hosts that the scope does not cover become IP targets of that scope (`source: "import"`, allowed networks apply; their count is `targets`) |
| GET `/export/{kind}.{fmt}` | export:run | kind `hosts, services, findings, changes, signatures`; fmt `json, csv`; list filters apply; `/export/runs/{id}.{json,csv,xml}`: json = Czujka JSON (lossless `HostResult` records), csv = one row per service, xml = nmap XML (for DefectDojo "Nmap Scan"); all three are written by `internal/interchange` (one CSV dialect) and import again through `/import/results` |
| GET `/dashboard` | results:read | → `Dashboard` |
| GET `/settings/safety` | scans:read | → `SafetyPolicy` |
| PUT `/settings/safety` | safety:manage | `SafetyPolicy`. `allowed_networks` (IP or CIDR list; empty = no limit): a target outside it is refused at entry (`/scopes/{id}/targets`, `/targets/preview`, imports, ad-hoc runs) with a Polish reason in `invalid`; a domain is allowed only when every address it resolves to is inside; the runner checks again when it builds the plan and drops what is outside |
| POST `/emergency-stop` | safety:stop | → `SafetyPolicy` (sets the flag; every running run stops at once and becomes `paused` with `pause_reason: "emergency_stop"`; its SSE stream sends `paused`, not `done`: the run is not finished and can be resumed after the release; new runs, ad-hoc runs and resumes answer 409 `emergency_stop`) |
| POST `/emergency-stop/release` | safety:manage | → `SafetyPolicy` (clears the flag; paused runs stay paused until someone calls `/runs/{id}/resume`) |
| GET `/settings/defectdojo` · PUT · POST `/settings/defectdojo/test` | integrations:manage | `DefectDojoSettings` → `{ok, message, version}`. `scope_mappings: [{scope_id, product_type_name, product_name, engagement_name}]` (each scope at most once; the scope must exist). `status_sync`: after every analysed run, close resolved findings in DefectDojo, reopen observed ones and apply the status pull (result in the audit log, action `finding.sync.defectdojo`) |
| GET `/healthz` | public | → `{status, version, db, tde, tde_detail, field_encryption, engine, probe: {prober, mode, raw_sockets}}`; `probe.mode` is `nmap-raw` (SYN scan, ICMP/ARP discovery), `nmap-connect` (no raw sockets: `-sT`) or `native` (Go TCP connect, no nmap) |

## Notes

- **host_missing.** A host that answered in the previous run and is silent now, but is not yet reported inactive, gets the change `host_missing` (severity medium). Its open services count in `summary.services_unreachable`; they are not gone. `Headline.hosts_missing` on the dashboard counts these hosts of the last run; the global SSE stream sends the change as `change`. `host_gone` follows when the model (or the profile rule `retry.down_after_misses`) reports the host inactive.
- **Services of a host that went down.** When a scan reports a known host as down, its open and filtered services become `unknown` (not gone: the port was not checked). A service becomes `gone` (change `service_gone`) only when a full scan finds the host up and the port not open.
- **down_after_misses** in `AvailabilityProfile`: how many misses in a row, counted from now, would report the host inactive. For a host that is already down it is the rule value of the profile (`retry.down_after_misses`, or the model threshold), never 0.
- **Partial data.** Runs with `trigger` `import`, `manual-entry` and `reprobe` do not mark services that they do not name as gone, and `manual-entry` does not resolve stale findings.
- **Per-run dedup.** The sink stores at most one observation per host per run: a later "up" of the same run corrects an earlier "down", a later "down" never hides an earlier "up".
- **Profile fields.** `discovery.mode` is `balanced` (default), `fast` or `thorough`. `udp: {enabled, ports}`: UDP ports are limited to the allow-list of harmless protocol queries (53, 123, 137, 161, 500, 1900, 5353) and to the allowed and denied ports of the policy; a list that leaves none answers 422.
- **Sub-routers.** Other packages can mount routes under `/api/v1` through `Deps.Mounts` (`api.Mount{Pattern, Router func(guard api.Guard) http.Handler}`). `api.Guard` is the permission middleware of this router (`guard(model.PermResultsRead)`); `api.WriteJSON` and `api.WriteError` write answers in the format above.
