# Czujka REST API (v1)

Base path `/api/v1`. JSON bodies use the types of `internal/model/types.go` (their JSON tags are the wire format). `web/src/api/types.ts` mirrors them.

- Auth: session cookie `czujka_session` (HttpOnly, SameSite=Strict). Mutating requests send `X-CSRF-Token` from `Session.csrf_token`.
- Lists: query `limit` (default 50, max 1000), `offset`, `sort` (field, `-field` for descending), `q` (free text) plus the filters named below. Answer: `Page<T>`.
- Errors: `{"error":{"code":"forbidden","message":"..."}}`. Codes: `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`, `validation`, `unsafe_signature`, `emergency_stop`, `internal`.
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
| POST `/runs` | scans:run | `{profile_id}` → `ScanRun` |
| POST `/runs/{id}/pause` · `/resume` · `/cancel` | scans:run | → `ScanRun` |
| GET `/runs/{id}/chunks` | scans:read | → `Chunk[]` |
| GET `/runs/{id}/map` | scans:read | → `{blocks:[{cidr, size, status, hosts_up}]}` (/24 blocks for the address-space map) |
| GET `/runs/{id}/events` | scans:read | SSE: events `progress` (`ScanRun`), `chunk` (`Chunk`), `host` (`{ip, up, services}`), `done` |
| GET `/events` | results:read | SSE: global events `run` (`ScanRun`), `change` (`Change`), `finding` (`Finding`) |
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
| POST `/findings/export/defectdojo` | export:run | `{ids}` or `{filter}` → `DojoExportResult` |
| GET `/signatures` · GET `/signatures/{id}` | signatures:read | filters `category, enabled, builtin, tag` → `Signature` |
| POST `/signatures` | signatures:create | `{yaml, enabled}` → `Signature` (rejected with `unsafe_signature` when the validator finds a safety issue) |
| PATCH `/signatures/{id}` | signatures:update | `{yaml, enabled}` |
| DELETE `/signatures/{id}` | signatures:delete | |
| POST `/signatures/validate` | signatures:read | `{yaml}` → `SignatureValidation` |
| POST `/signatures/retrohunt` | signatures:read | `{yaml}` or `{id}`, optional `{latest_only}` → `RetroHuntResult` |
| GET `/tags` | results:read | → `NameCount[]` |
| POST `/import/results` | results:create | multipart `file` (nmap XML, Czujka JSON, CSV), optional `scope_id` → `ImportReport` |
| GET `/export/{kind}.{fmt}` | export:run | kind `hosts, services, findings, changes, signatures`; fmt `json, csv`; list filters apply; `/export/runs/{id}.{json,csv,xml}` (xml = nmap XML for DefectDojo "Nmap Scan") |
| GET `/dashboard` | results:read | → `Dashboard` |
| GET `/settings/safety` | scans:read | → `SafetyPolicy` |
| PUT `/settings/safety` | safety:manage | `SafetyPolicy` |
| POST `/emergency-stop` | safety:stop | → `SafetyPolicy` (sets the flag, cancels running runs) |
| POST `/emergency-stop/release` | safety:manage | → `SafetyPolicy` |
| GET `/settings/defectdojo` · PUT · POST `/settings/defectdojo/test` | integrations:manage | `DefectDojoSettings` → `{ok, message, version}` |
| GET `/healthz` | public | → `{status, version, db, tde}` |
