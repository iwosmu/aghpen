# Czujka core: worker report

Task `task_9c76d3c21933`. Branch `iwosmu/czujka-core`. Last code commit `f97e7c8` (this report is the commit after it).
All output below is real output from this machine (Apple Silicon, Docker 29.6, Go 1.27.4), 2026-11-21.

## 1. What was built

| Package | Content |
| --- | --- |
| `internal/config` | `CZUJKA_*` configuration with validation and defaults. |
| `internal/crypto` | AES-256-GCM envelope encryption. One data key per record, wrapped by the master key. Token `czk1.<keyid>.<wrapped key>.<ciphertext>`. AAD binds a ciphertext to its row. Keyring with old keys for rotation. |
| `internal/store` | PostgreSQL 17 through pgx v5. Embedded migration, applied at start under an advisory lock. 21 tables, every one `tde_heap`. Batch ingest through `jsonb_to_recordset` (about 8 statements for 250 hosts, no N+1). Store-backed `model.ResultSink`. List filters with indexes, streaming readers for exports, dashboard, key rotation, TDE status probe. |
| `internal/auth` | argon2id passwords, 256-bit session tokens stored as SHA-256 hashes, HttpOnly + SameSite=Strict cookie, CSRF token per session, login rate limit and account lockout, four built-in roles as ARCHITECTURE section 6, custom roles, admin seed. Rules: an actor cannot grant a permission it does not hold; the last admin cannot be removed, disabled or demoted. |
| `internal/runner` | Run lifecycle around `model.Engine`: start, pause, resume, cancel, emergency stop, recovery after a restart, import, event bus for SSE. Tested with a fake engine. |
| `internal/api` | Every route of `docs/API.md` with chi. Permission check per route, validation, list envelope, error format, audit of every mutating request (also the rejected ones) and every login attempt, SSE for runs and global events, security headers, UI from `CZUJKA_WEB_DIR` or an embedded FS, streaming JSON and CSV export with the list filters. Seams for other workers are in `internal/api/deps.go`; a nil seam answers `501 not_wired`. Built-in basic target parser. |
| `cmd/czujka` | `serve`, `migrate`, `user create`, `rotate-key`, `version`, plus `genkey` and `healthcheck`. `cmd/czujka/wire.go` is the one place where the integration step connects the other packages. |
| `deploy/`, `Makefile` | `deploy/db` (Percona PostgreSQL 17 + pg_tde), `deploy/Dockerfile` (multi-stage, static binary, Alpine + nmap, non-root), `deploy/docker-compose.yml`, `deploy/.env.example`, `deploy/README.md` (Polish). `make dev`, `test`, `test-integration`, `bench`, `build`, `up`, `down`, `logs`. |

Decisions that differ from, or add to, the documents:

- **Emergency stop pauses running runs** (reason `emergency_stop`, resumable after release). ARCHITECTURE 4.2 says "cancels". New runs are blocked with `409 emergency_stop`. Change `Manager.EmergencyStop` if a hard cancel is wanted.
- An actor can change or delete a user only when the actor holds every permission of that user's role (stops a takeover through a password reset).
- Extra error codes: `not_wired` (501), `rate_limited` (429). The error object can carry `details`.
- Service ingest keeps the old product and version when a new observation has them empty.
- Exports are written to the audit log although they are reads.

## 2. Evidence

### 2.1 Tests

Start the test database, then run all tests:

```sh
make test-integration
# which is:
docker build -t czujka-db:17 deploy/db
docker run -d --name czujka-dev-pg -e POSTGRES_USER=czujka -e POSTGRES_PASSWORD=czujka -e POSTGRES_DB=czujka \
  -p 127.0.0.1:55432:5432 -v czujka-dev-pg-keys:/tde-keys czujka-db:17
CZUJKA_TEST_DB_URL='postgres://czujka:czujka@127.0.0.1:55432/czujka?sslmode=disable' CZUJKA_TEST_REQUIRE_TDE=1 go test -count=1 ./...
```

```
ok  	github.com/iwosmu/aghpen/cmd/czujka	0.146s
ok  	github.com/iwosmu/aghpen/internal/api	6.191s
ok  	github.com/iwosmu/aghpen/internal/auth	4.363s
ok  	github.com/iwosmu/aghpen/internal/config	0.179s
ok  	github.com/iwosmu/aghpen/internal/crypto	0.180s
?   	github.com/iwosmu/aghpen/internal/model	[no test files]
ok  	github.com/iwosmu/aghpen/internal/runner	5.381s
ok  	github.com/iwosmu/aghpen/internal/store	4.915s
```

`gofmt -l .` is empty. `go build ./... && go vet ./... && go test ./...` pass (without a database the integration tests skip).

### 2.2 Compose from a clean state

Command (project name and port changed so that workers do not collide):
`CZUJKA_PORT=18080 docker compose -p czcore-e2e -f deploy/docker-compose.yml up -d --build --wait`

```
 Container czcore-e2e-db-1 Healthy
 Container czcore-e2e-czujka-1 Healthy
NAME                  IMAGE               STATUS                    PORTS
czcore-e2e-czujka-1   czujka:czcore-e2e   Up 5 seconds (healthy)    127.0.0.1:18080->8080/tcp
czcore-e2e-db-1       czujka-db:17        Up 11 seconds (healthy)   5432/tcp
$ curl -s http://127.0.0.1:18080/healthz
{"db":"ok","engine":false,"field_encryption":{"algorithm":"AES-256-GCM envelope","key_id":"250da4315bfd"},"status":"ok","tde":true,"tde_detail":{"active":true,"available":true,"tables":21,"encrypted":21,"wal_encrypted":true},"version":"czcore-e2e"}
```

Runtime image:

```
user: uid=10001(czujka) gid=10001(czujka) groups=10001(czujka)
CapPrm: 0000000000000000 CapEff: 0000000000000000 CapBnd: 0000000000003000      (bounding set = NET_ADMIN + NET_RAW only)
cap_add=[CAP_NET_ADMIN CAP_NET_RAW] cap_drop=[ALL] read_only=true user=czujka:czujka
Nmap version 7.97
$ nmap --privileged -sS -n -p 8080 127.0.0.1      (inside the container, its own loopback; a SYN scan needs raw sockets)
8080/tcp open  http-proxy
ldd /usr/local/bin/czujka: Not a valid dynamic program      (static binary)
```

### 2.3 RBAC with curl (against the compose stack)

The three extra users were created with `czujka user create` inside the container. Script: log in with `curl -c`, then send each request with the cookie and `X-CSRF-Token`.

```
== login as each role ==
POST /auth/login viewer@czujka.local -> 200 role=viewer permissions=4
POST /auth/login analyst@czujka.local -> 200 role=analyst permissions=9
POST /auth/login editor@czujka.local -> 200 role=editor permissions=16
POST /auth/login admin@czujka.local -> 200 role=admin permissions=22
POST /auth/login admin@czujka.local wrong password -> 401
cookie flags (curl jar): #HttpOnly_127.0.0.1 name=czujka_session
Set-Cookie: czujka_session=<redacted>; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict

== allow / deny matrix (HTTP status) ==
request                                              viewer   analyst  editor   admin   
GET    /scopes (read)                                200      200      200      200     
GET    /hosts (read)                                 200      200      200      200     
GET    /dashboard (read)                             200      200      200      200     
PATCH  /scopes/{id}                                  403      200      200      200     
PATCH  /targets/{id}                                 403      200      200      200     
POST   /scopes                                       403      403      201      201     
POST   /scopes/{id}/targets                          403      403      201      201     
DELETE /targets/{id}                                 403      403      204      204     
POST   /profiles                                     403      403      201      201     
POST   /runs (engine not wired: 501)                 403      501      501      501     
POST   /emergency-stop                               403      403      403      200     
POST   /emergency-stop/release                       403      403      403      200     
GET    /export/hosts.csv                             403      200      200      200     
GET    /users                                        403      403      403      200     
POST   /users                                        403      403      403      201     
POST   /roles                                        403      403      403      201     
PUT    /settings/safety                              403      403      403      200     
PUT    /settings/defectdojo                          403      403      403      200     
GET    /audit                                        403      403      403      200     

== privilege escalation is refused ==
editor creates a role (no roles:manage) -> 403
admin deletes the last admin -> {"error":{"code":"conflict","message":"the last administrator cannot be removed, disabled or demoted"}}
admin demotes the last admin -> {"error":{"code":"conflict","message":"the last administrator cannot be removed, disabled or demoted"}}

== CSRF: a mutation with the session cookie but no X-CSRF-Token ==
HTTP/1.1 403 Forbidden
{"error":{"code":"forbidden","message":"missing or wrong CSRF token: send the csrf_token of the session in the X-CSRF-Token header"}}
with a wrong token -> 403
no session at all  -> {"error":{"code":"unauthorized","message":"sign in first"}}
 401

== security headers ==
Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

Read: viewer gets 403 on every mutation. Analyst can PATCH but cannot POST or DELETE targets. Editor can create and delete but cannot manage users, roles, safety or integrations. Admin can do all. `POST /runs` answers 501 for allowed roles because no engine is wired in this branch; it answers 403 for the viewer.

```
== audit log excerpt (GET /audit as admin, oldest first) ==
entries: 71
12:28:24	viewer@czujka.local	auth.login	2	status=200	
12:28:24	analyst@czujka.local	auth.login	3	status=200	
12:28:24	editor@czujka.local	auth.login	4	status=200	
12:28:24	admin@czujka.local	auth.login	1	status=200	
12:28:24		auth.login_failed		status=401	invalid_credentials
12:28:24	viewer@czujka.local	auth.login	2	status=200	
12:28:25	admin@czujka.local	scope.create		status=403	csrf
12:28:25	admin@czujka.local	scope.create		status=403	csrf
12:28:24	viewer@czujka.local	auth.login	2	status=200	
12:28:24	viewer@czujka.local	auth.login	2	status=200	
12:28:25	viewer@czujka.local	scope.update	1	status=403	
12:28:25	viewer@czujka.local	target.update	1	status=403	
12:28:25	viewer@czujka.local	scope.create		status=403	
12:28:25	viewer@czujka.local	scope.target.create	1	status=403	
12:28:25	analyst@czujka.local	target.update	2	status=200	
12:28:25	editor@czujka.local	target.update	3	status=200	
12:28:25	analyst@czujka.local	scope.target.create	1	status=403	
12:28:25	editor@czujka.local	scope.target.create	1	status=201	
12:28:25	analyst@czujka.local	target.delete	2	status=403	
12:28:25	editor@czujka.local	target.delete	3	status=204	
12:28:25	analyst@czujka.local	safety.emergency_stop		status=403	
12:28:25	editor@czujka.local	safety.emergency_stop		status=403	
12:28:25	admin@czujka.local	safety.emergency_stop		status=200	
12:28:25	admin@czujka.local	safety.emergency_stop_release		status=200	
12:28:25	admin@czujka.local	safety.update		status=200	
12:28:25	admin@czujka.local	integration.defectdojo.update	defectdojo	status=200	
12:28:25	admin@czujka.local	user.delete	1	status=409	
12:28:25	admin@czujka.local	user.update	1	status=409	
secrets in the audit log: 0
```

Columns: time, user, action, entity id, HTTP status, reason. The failed login entry keeps the attempted e-mail in `detail.email`.

### 2.4 Encryption at rest

```
== layer 1: pg_tde ==
        table         | access_method | encrypted 
----------------------+---------------+-----------
 audit_log            | tde_heap      | t
 changes              | tde_heap      | t
 chunks               | tde_heap      | t
 findings             | tde_heap      | t
 host_availability    | tde_heap      | t
 host_observations    | tde_heap      | t
 hosts                | tde_heap      | t
 roles                | tde_heap      | t
 runs                 | tde_heap      | t
 scan_profiles        | tde_heap      | t
 schema_migrations    | tde_heap      | t
 scopes               | tde_heap      | t
 service_observations | tde_heap      | t
 services             | tde_heap      | t
 sessions             | tde_heap      | t
 settings             | tde_heap      | t
 signatures           | tde_heap      | t
 tags                 | tde_heap      | t
 targets              | tde_heap      | t
 technologies         | tde_heap      | t
 users                | tde_heap      | t
(21 rows)

tables=21 tde_heap=21 encrypted=21
pg_tde 2.2
on
tde_heap
czujka-principal-key|czujka-keyring

== layer 2: field-level ciphertext (the DefectDojo API key was set to PLAINTEXT-MARKER-czcore-7391 over the API) ==
    key     |                                                                                                    value                                                                                                     |                                     secret                                      | len 
------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------+-----
 defectdojo | {"url": "https://dojo.example.org", "enabled": false, "verify_tls": true, "api_key_set": false, "auto_export": false, "min_interest": 0, "product_name": "", "engagement_name": "", "product_type_name": ""} | czk1.250da4315bfd.DzzMQMlAACD6y3iyG0Xm82QS1OR61DrwtssX5B3kwZc1nwBWSRzsR9FS5W... | 174
(1 row)

GET /settings/defectdojo as admin (the key is write-only):
{"enabled":false,"url":"https://dojo.example.org","api_key_set":true,"product_name":"","engagement_name":"","product_type_name":"","verify_tls":true,"auto_export":false,"min_interest":0}


== raw data directory: grep for plaintext markers ==
in SQL: TDE-ONLY-MARKER-czcore-5582
data_directory=/data/db
grep -r -a -l PLAINTEXT-MARKER-czcore-7391 /data/db -> files with a match: 0 
grep -r -a -l TDE-ONLY-MARKER-czcore-5582 /data/db -> files with a match: 0 
grep -r -a -l CONTROL-MARKER-czcore-9914 /data/db -> files with a match: 1 /data/db/base/16384/16972
```

The control row shows that the grep finds data in a plain `heap` table. The two product markers are not in any file of the data directory.

Key rotation, end to end on the compose stack (`czujka rotate-key`):

```
key id in the stored ciphertext before: 250da4315bfd
current master key id: fed80f7b0f81
  re-wrapped findings.evidence_enc            0
  re-wrapped findings.note_enc                0
  re-wrapped hosts.note_enc                   0
  re-wrapped service_observations.secret      0
  re-wrapped services.note_enc                0
  re-wrapped settings.secret                  2
ciphertexts per key id before: map[250da4315bfd:2]
ciphertexts per key id after:  map[fed80f7b0f81:2]
done: remove CZUJKA_MASTER_KEY_OLD and restart czujka with the new key
key id in the stored ciphertext after:  fed80f7b0f81
-- restart czujka with the new key only --
 Container czcore-e2e-db-1 Healthy 
 Container czcore-e2e-czujka-1 Healthy 
{"status":"ok","tde":true,"field_encryption":{"algorithm":"AES-256-GCM envelope","key_id":"fed80f7b0f81"}}
-- a start with the old key only must refuse --
czujka: the master key does not match this database (data was encrypted with key id fed80f7b0f81, the keyring has [250da4315bfd]): crypto: master key of this ciphertext is not in the keyring (key id fed80f7b0f81)
```

### 2.5 Edits survive scans

`CZUJKA_TEST_DB_URL=... go test -count=1 -run TestEditsSurviveScans -v ./internal/store/`

The test ingests a scan, edits the host, the service and the finding as an analyst, then ingests a second scan with different observed values.

```
=== RUN   TestEditsSurviveScans
    store_integration_test.go:125: service.product  = "OpenResty (potwierdzone z adminem)"  (override: observed=nginx by=analityk@example.org)
    store_integration_test.go:126: service.version  = "1.26.2"  (not overridden, follows the scan)
    store_integration_test.go:127: service.note     = "nie ruszać do audytu"  tags=[audyt]
    store_integration_test.go:128: host.os_guess    = "Debian 12"  (override: observed=Linux 6.1)  label="Serwer WWW dziekanatu" owner="DSI" criticality=4
    store_integration_test.go:129: finding.status   = "accepted"  note="ryzyko zaakceptowane do 2027-01" assignee="jan"
    store_integration_test.go:130: finding.severity = "low"  (override: observed=high)  title="Panel administracyjny (nowy tytuł ze skanu)" interest=75 last_run=2
--- PASS: TestEditsSurviveScans (0.18s)
PASS
ok  	github.com/iwosmu/aghpen/internal/store	0.403s
```

### 2.6 Performance at 10 000 hosts

`make bench` (10 000 synthetic `HostResult` x 3 services through the store sink, real PostgreSQL with pg_tde, then real HTTP requests; median of 10).

Store level (`TestIngestBenchmark`): first ingest 6587.5 ms (1518 hosts/s, 4554 observations/s); second ingest of the same hosts 2217.8 ms (4509 hosts/s, 13527 observations/s). Rows after two runs: hosts=10000, services=30000, service_observations=60000.

HTTP level (`TestHTTPBenchmark`):

```
ingest: 10000 hosts x 3 services in 1.292s
GET /api/v1/hosts                                        median     6.3 ms  min     5.3  max     7.8  body 22977 bytes
GET /api/v1/hosts?limit=200&sort=-interest               median     7.3 ms  min     6.8  max     9.2  body 91833 bytes
GET /api/v1/hosts?port=443&cidr=10.100.8.0/22&sort=ip    median     1.9 ms  min     1.8  max     2.4  body 23038 bytes
GET /api/v1/hosts?q=10.100.39                            median     6.1 ms  min     5.6  max     6.4  body 23087 bytes
GET /api/v1/services?limit=50                            median    14.1 ms  min    13.8  max    15.3  body 22880 bytes
GET /api/v1/services?port=443&name=https&limit=100       median     7.8 ms  min     7.3  max     8.9  body 45619 bytes
GET /api/v1/dashboard                                    median     8.0 ms  min     6.6  max     8.9  body 1565 bytes
GET /api/v1/export/hosts.csv                             median    42.0 ms  min    40.7  max    44.7  body 1212245 bytes
GET /api/v1/export/services.json                         median   208.4 ms  min   193.7  max   216.5  body 13914008 bytes
```

## 3. Changes to `internal/model`

None. No field, type or JSON tag was added or changed.

Files outside the owned paths: none. (`go.mod` and `go.sum` gained chi, pgx v5, x/crypto, x/time.)

## 4. Known gaps and next steps

- **Not wired in this branch** (each answers `501 not_wired`, nothing is faked): scan engine, post-run analyzer and run diff, result importer, nmap XML exporter, DefectDojo client, signature validator, retro-hunt. Connect them in `cmd/czujka/wire.go`. So signature create/update, `/diff`, `/import/results`, DefectDojo export and a real scan are tested only up to the seam.
- **Scheduler**: `store.NextScheduledRun`, `Manager.ResumeDue` and the `WindowFunc` seam exist. No loop calls them here; `internal/sched` owns that.
- **UI**: `web/` is not in this branch. The Dockerfile builds it when present, but that stage ran only in its "no web" path. The image serves `CZUJKA_WEB_DIR=/app/web`. An embedded UI needs a small `embed` package in `web/` assigned to `Deps.WebFS`. Without a UI the server shows an honest placeholder page.
- **Emergency stop** pauses instead of cancels (see section 1).
- **Result import** does not apply a `scope_id` to imported hosts.
- **pg_tde limits**: system catalogs, `pg_statistic` and temporary files are not encrypted. The key provider is a file on its own volume; production needs Vault or KMIP.
- **Compose without `deploy/.env`** uses a default database password. The database has no published port and sits on an internal network. Set a real password for production.
- `make up` was not run by name; the same compose command ran with a project prefix and port 18080. `make test` and `make build` ran.
- The scanner container joins only the `scan` network. The integration step must attach it to the lab networks.
- Only nmap has file capabilities. If the engine opens raw sockets in Go, add `setcap` for the `czujka` binary in the Dockerfile.
- The login rate limiter is in memory (one instance). The CSP allows inline styles (`style-src 'unsafe-inline'`).
- Benchmarks are single runs on a laptop. The first ingest is about 3 times slower than a re-scan; not investigated.

## 5. Branch and commit

Branch `iwosmu/czujka-core`. Not pushed, not merged. Commits:

```
f97e7c8 test(api): HTTP benchmark after a 10k host ingest; docs(deploy): run and encryption guide
ed6dc40 feat(deploy): product Dockerfile, compose stack with pg_tde database, Makefile; API audit names and tests
a852e27 feat(api,cmd): REST API with RBAC, audit log, SSE and streaming exports; czujka subcommands
980caae feat(auth,runner): argon2id sessions with RBAC rules, run manager with pause, resume, recovery and event bus
2dce167 feat(store): PostgreSQL store with pg_tde, field-level encryption, batch ingest and key rotation
```

Docker cleanup: containers, networks and volumes with the prefixes `czcore-` are removed. The image `czujka-db:17` is kept as a build cache.
