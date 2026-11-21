# Integration report: analysis, import/export, DefectDojo, scheduler seam (task_776132ae89c2)

Branch `iwosmu/czujka-core`. Base: merge of `iwosmu/agh-orchestrated-kickoff` (fast-forward).
Commits of this task: `529fd8c` (adapters, runner, store, API, docs) and the two commits after it (e2e flow, tests, this report).

## What was built

### 1. Post-run analysis (`internal/wire/analysis.go`, implements `runner.Analyzer` and `api.Analyzer`)

- Runs after each completed scan run, after each import, and after a run that its window paused.
- Stability: for each host with an observation in the run it calls `analyze.Assess` on the stored histogram and stores status (`up`, `expected-offline`, `unstable`, `down`), `p_alive`, pattern text and consecutive misses.
- Diff: `analyze.Diff` against a per-host baseline (the newest earlier observation of the host; a silent host keeps the services of its last answer). Changes and the `RunDiffSummary` are stored. A repeated analysis of the same run replaces its changes (idempotent).
- Interest and groups: `analyze.AssignGroupKeys`, `analyze.Interest` with reasons, `analyze.HostInterest`, effective classes. An analyst override of `classes` is not touched.
- Findings: `analyze.DeriveFindings`, upsert by `Key`. A finding with status `new` that the run did not see again on an answering host becomes `resolved`. Status, note, assignee and overrides set by an analyst are never changed.
- Partial runs: the analysis reads only hosts that have an observation row for the run. An address that the run did not reach has no row, so it is not a miss. Test: `TestPartialRunsAndStability`.
- Events: the runner publishes `change` and `finding` events on the bus after the analysis (also for a window-paused run).
- New column `host_observations.status` (migration `0002_analysis.sql`): the model status at each observation, so a later diff knows that a host was already down.

### 2. API seams (`internal/wire`, `internal/api`)

- `Analyzer`: `GET /diff?from=&to=` for any two runs; `DownAfterMisses` for the availability route.
- `Importer`: `POST /import/results`, format auto-detected by `internal/interchange`. Imported hosts take the same ingest and the same analysis as scanned hosts. A host that the file reports as down is kept only when the inventory knows it.
- `Exporter`: `/export/runs/{id}.{json,csv,xml}` through `interchange.NewWriter` (Czujka JSON, CSV, nmap XML). Each of the three imports again.
- `DojoClient`: settings with the API key field-encrypted, connection test, export of selected findings with `dojo_id` and `dojo_url` written back, automatic export after a run for findings at or above `min_interest`, and the new route `POST /runs/{id}/export/defectdojo` (nmap XML of a run as "Nmap Scan"; a second upload re-imports into the same test). Permission `export:run`, audit action `run.export.defectdojo`.
- Go interface changes in `internal/api/deps.go` (HTTP contract unchanged): `Importer.ParseResults(ctx, filename, data) (hosts, model.ImportReport, error)`, `Exporter.RunWriter(w, format, run) (ResultWriter, error)`, `DojoClient.UploadNmap(...)`, type `DojoUpload`.

### 3. Emergency stop

- Behaviour kept: runs become `paused` with reason `emergency_stop` and are resumable after the release.
- `Manager.EmergencyStop` now cancels the context of every engine first, before any database call.
- `docs/ARCHITECTURE.md` §4.2 and `docs/API.md` now describe pause-and-resume.

### 4. Scheduler seam

- Store: `ScheduledProfiles`, `DueProfiles(now)`, `LastRunStart(profileID)`, `WindowPausedRuns` (ordered by `resume_at`), existing `SetProfileNextRun`, `NextScheduledRun`.
- Runner: existing `Start(ctx, profileID, nil, "schedule")`, `Resume`, `ResumeDue(now)`, `SetWindow`.
- `internal/wire/sched.go`: `SchedBackend{Store, Runner}` with `Profiles`, `DueProfiles`, `LastRunStart`, `SetNextRun`, `StartRun`, `PausedByWindow`, `ResumeRun`. It should satisfy the `Backend` of `internal/sched` with a rename of methods at most.

### 5. Seed for the first start

- `store.SeedDefaults` runs once (guard key `seed` in settings): the default safety policy and one profile "Domyślny (bezpieczne rozpoznanie)" (`top-100`, 300 pps, no scope, schedule off). Nothing else. A deleted default profile does not come back.

### 6. `make e2e-core`

- `deploy/e2e-core.sh` and `deploy/e2e/modify-nmap.pl`. Real stack (PostgreSQL with pg_tde + czujka on `127.0.0.1:18090`), real nmap XML, real local DefectDojo. No scan runs. 24 checks; exit code 1 when one fails.
- The script removes its stack, its volumes and the two DefectDojo products it creates.

### Wiring left ready (`internal/wire/wire.go`, `Build`)

Nil today, 501 `not_wired` in the API, nothing faked: `Engine` (`internal/scan`), `Window` (`internal/sched`), `API.Signatures` and `API.RetroHunter` (`internal/sig`, `internal/httpfp`), `API.WebFS` (`web/`), `API.Hooks`. The comment in `Build` names the line for each. `cmd/czujka` only calls `wire.Build`.

## Evidence

### Checks

```
$ gofmt -l .
$ go build ./... && go vet ./... && echo BUILD_VET_OK
$ CZUJKA_TEST_DB_URL=postgres://czujka:...@127.0.0.1:55432/czujka CZUJKA_TEST_REQUIRE_TDE=1 go test -count=1 ./...
BUILD_VET_OK
ok  	github.com/iwosmu/aghpen/cmd/czujka	0.130s
?   	github.com/iwosmu/aghpen/cmd/dojoprobe	[no test files]
ok  	github.com/iwosmu/aghpen/internal/analyze	0.103s
ok  	github.com/iwosmu/aghpen/internal/api	5.351s
ok  	github.com/iwosmu/aghpen/internal/auth	3.673s
ok  	github.com/iwosmu/aghpen/internal/config	0.070s
ok  	github.com/iwosmu/aghpen/internal/crypto	0.069s
ok  	github.com/iwosmu/aghpen/internal/defectdojo	0.485s
ok  	github.com/iwosmu/aghpen/internal/interchange	0.081s
?   	github.com/iwosmu/aghpen/internal/model	[no test files]
ok  	github.com/iwosmu/aghpen/internal/runner	4.439s
ok  	github.com/iwosmu/aghpen/internal/store	4.613s
?   	github.com/iwosmu/aghpen/internal/store/storetest	[no test files]
ok  	github.com/iwosmu/aghpen/internal/wire	2.589s
```

The database is PostgreSQL 17 with pg_tde in docker (`make dev-db`), not a fake.

### Selected test output (real database)

```
    wire_integration_test.go:194: silent host: p_alive=0.458, reported inactive after 3 more misses
    wire_integration_test.go:238: json export: 3350 bytes, 4 hosts; diff against the source run: 0 changes map[]
    wire_integration_test.go:238: xml  export: 3124 bytes, 4 hosts; diff against the source run: 0 changes map[]
    wire_integration_test.go:238: csv  export: 1358 bytes, 4 hosts; diff against the source run: 0 changes map[]
--- PASS: TestImportAnalysisDiffAndRoundTrip (0.43s)
    wire_integration_test.go:326: a host that answered in 5 runs then stops:
          miss 1: status=unstable p_alive=0.398
          miss 2: status=unstable p_alive=0.242
          miss 3: status=down p_alive=0.162
--- PASS: TestPartialRunsAndStability (0.48s)
ok  	github.com/iwosmu/aghpen/internal/wire	1.064s
    runner_test.go:321: emergency stop: engine context cancelled after 6.778ms, call returned after 7.763542ms
--- PASS: TestEmergencyStop (0.43s)
--- PASS: TestWindowClosedFailureAndNotWired (0.46s)
ok  	github.com/iwosmu/aghpen/internal/runner	1.046s
--- PASS: TestSeedDefaultsRunsOnce (0.46s)
--- PASS: TestSchedulerSeam (0.45s)
ok  	github.com/iwosmu/aghpen/internal/store	1.037s
--- PASS: TestWiring (0.00s)
ok  	github.com/iwosmu/aghpen/cmd/czujka	0.127s
```

- `TestEmergencyStop`: the engine saw its cancelled context after about 7 ms. The fake engine was inside a database write of the previous chunk; the cancel itself is the first statement of `EmergencyStop`.
- `TestPartialRunsAndStability`: a host that the run did not reach keeps status `up` with 0 misses; the first miss gives `host_unstable`, `host_gone` comes once after three misses, later misses give no change, a return gives `host_back` and no "new service" noise.

### E2E transcript (`make e2e-core`, also in `deploy/e2e/transcript.txt`)

```

=== 0. Preconditions ===
DefectDojo answers at http://127.0.0.1:18080 (user admin)

=== 1. Start the stack from a clean state ===
 Container czcore-e2e-db-1 Healthy 
 Container czcore-e2e-db-1 Healthy 
 Container czcore-e2e-czujka-1 Healthy 
{"status":"ok","db":"ok","tde":true,"tables":21,"encrypted":21,"engine":false}
  OK    healthz: ok tde=true engine=false

=== 2. Log in; the first start seeded a safety policy and one profile, nothing else ===
{"user":"admin@czujka.local","role":"admin","permissions":22}
{"max_pps":1000,"max_http_rps":50,"max_per_host_rps":2,"allowed_methods":["GET","HEAD"],"emergency_stop":false}
{"name":"Domyślny (bezpieczne rozpoznanie)","ports":"top-100","max_pps":300,"scope_ids":[],"schedule_enabled":false}
  OK    seed: profiles=1 hosts=0 findings=0 scopes=0

=== 3. Create a scope ===
{"valid":1,"address_count":256,"invalid":0}

=== 4. Import a real nmap XML file (lab/defectdojo/sample-nmap.xml) ===
{"format":"nmap-xml","run_id":1,"hosts":4,"services":12,"targets":0,"skipped":0,"invalid":[]}
{"id":1,"status":"completed","trigger":"import","import_file":"sample-nmap.xml","hosts_up":4,"services_open":3,"summary":{"prev_run_id":null,"hosts_new":0,"hosts_gone":0,"hosts_back":0,"hosts_unstable":0,"services_new":0,"services_gone":0,"services_changed":0,"by_kind":{},"findings_new":4}}
  OK    run 1: completed changes=0
-- services with their interest score and reasons:
  172.31.250.4:6379 Redis key-value store 7.4.12  interest=30  classes=database  why=database+25 scope-criticality+5
  172.31.250.2:80 nginx 1.31.9  interest=15  classes=default-page  why=default-page+5 sensitive-header+5 scope-criticality+5
  172.31.250.3:80 Apache httpd 2.4.71  interest=10  classes=  why=sensitive-header+5 scope-criticality+5
-- findings derived from the import:
  #4 [new] database-exposed 172.31.250.4:6379 interest=30  Baza danych dostępna z sieci: Redis key-value store 7.4.12 (172.31.250.4:6379)
  #2 [new] interesting-header 172.31.250.2:80 interest=15  Nagłówki ujawniają szczegóły oprogramowania: Server (172.31.250.2:80)
  #1 [new] default-page 172.31.250.2:80 interest=15  Strona domyślna serwera: Welcome to nginx! (172.31.250.2:80)
  #3 [new] interesting-header 172.31.250.3:80 interest=10  Nagłówki ujawniają szczegóły oprogramowania: Server (172.31.250.3:80)
  OK    scope match: 4

=== 5. Analyst edits ===
{"id":1,"product":"nginx (reverse proxy dziekanatu)","version":"1.31.9","note":"zgloszone do DSI","tags":["dziekanat"],"override":{"value":"nginx (reverse proxy dziekanatu)","observed":"nginx","by":"admin@czujka.local","at":"2026-11-21T12:49:32.808348792Z"}}
{"id":4,"type":"database-exposed","status":"accepted","note":"baza testowa, ryzyko zaakceptowane","assignee":"ola"}

=== 6. Import a second, modified file (new nginx version, SSH opened, Apache closed, one host silent) ===
  changed XML tokens: 10
{"format":"nmap-xml","run_id":2,"hosts":4,"services":12,"targets":0,"skipped":0,"invalid":[]}
{"id":2,"status":"completed","summary":{"prev_run_id":1,"hosts_new":0,"hosts_gone":0,"hosts_back":0,"hosts_unstable":1,"services_new":1,"services_gone":1,"services_changed":1,"by_kind":{"headers_changed":1,"host_unstable":1,"service_changed":1,"service_gone":1,"service_new":1,"tech_version":1},"findings_new":2}}
-- changes of run 2:
  service_changed [low] Zmiana wersji 172.31.250.2:80: nginx 1.31.9 → nginx 1.33.0
  tech_version [low] Zmiana wersji nginx na 172.31.250.2:80: 1.31.9 → 1.33.0
  headers_changed [info] Zmiana nagłówków 172.31.250.2:80: Server: nginx/1.31.9 → nginx/1.33.0
  service_gone [low] Usługa 172.31.250.3:80 zniknęła (Apache httpd 2.4.71)
  service_new [medium] Nowa usługa 172.31.250.4:22 (OpenSSH 9.9)
  host_unstable [low] Host 172.31.250.5 nie odpowiedział w porze, w której zwykle odpowiada; jeszcze nie jest zgłoszony jako nieaktywny
  OK    changes: headers_changed,host_unstable,service_changed,service_gone,service_new,tech_version
-- hosts after run 2 (stability model):
  172.31.250.2 status=up p_alive=1 misses=0 interest=15 open_ports=80
  172.31.250.3 status=up p_alive=1 misses=0 interest=0 open_ports=
  172.31.250.4 status=up p_alive=1 misses=0 interest=30 open_ports=22,6379
  172.31.250.5 status=unstable p_alive=0.3581018086891665 misses=1 interest=0 open_ports=
{"p_alive":0.3581018086891665,"down_after_misses":1,"recent":[{"run_id":1,"up":true},{"run_id":2,"up":false}]}
  OK    silent host: unstable
-- findings after run 2:
  #1 [new] default-page 172.31.250.2:80 first_run=1 last_run=2
  #2 [new] interesting-header 172.31.250.2:80 first_run=1 last_run=2
  #3 [resolved] interesting-header 172.31.250.3:80 first_run=1 last_run=1
  #4 [accepted] database-exposed 172.31.250.4:6379 first_run=1 last_run=2
  #8 [new] remote-access-exposed 172.31.250.4:22 first_run=2 last_run=2
  #9 [new] new-exposure 172.31.250.4:22 first_run=2 last_run=2
  OK    new findings from the new SSH service: 2
  OK    finding of the closed Apache port: resolved
-- the edits survive the second import:
{"product":"nginx (reverse proxy dziekanatu)","version":"1.33.0","note":"zgloszone do DSI","tags":["dziekanat"],"observed_product":"nginx","by":"admin@czujka.local"}
  OK    service override: nginx (reverse proxy dziekanatu) / 1.33.0 / zgloszone do DSI
  OK    finding triage: accepted / baza testowa, ryzyko zaakceptowane / last_run=2

=== 7. Diff of the two runs (GET /diff?from=1&to=2) ===
{"from":1,"to":2,"summary":{"prev_run_id":1,"hosts_new":0,"hosts_gone":0,"hosts_back":0,"hosts_unstable":1,"services_new":1,"services_gone":1,"services_changed":1,"by_kind":{"headers_changed":1,"host_unstable":1,"service_changed":1,"service_gone":1,"service_new":1,"tech_version":1},"findings_new":0},"changes":["service_changed 172.31.250.2:80","tech_version 172.31.250.2:80","headers_changed 172.31.250.2:80","service_gone 172.31.250.3:80","service_new 172.31.250.4:22","host_unstable 172.31.250.5:0"]}
  OK    diff: new=1 gone=1 changed=1

=== 8. DefectDojo: settings, connection test, export of findings (twice), nmap XML of the run (twice) ===
{"enabled":true,"url":"http://host.docker.internal:18080","api_key_set":true,"product_name":"Czujka e2e 20261121-134914","engagement_name":"e2e 20261121-134914","product_type_name":"","verify_tls":true,"auto_export":false,"min_interest":0}
  OK    the API key is not returned: absent set=true
stored as: czk1.e809fccf7510.6pIROT9kEH6xR_pyobWQm8... (190 chars)
  OK    the API key is not in the database in clear text: 0
{"message":"Połączono z DefectDojo 3.5.202 jako admin","ok":true,"version":"3.5.202"}
first export:  {"exported":5,"updated":0,"failed":0,"test_id":15,"test_url":"http://host.docker.internal:18080/test/15","errors":[]}
second export: {"exported":0,"updated":5,"failed":0,"test_id":15,"test_url":"http://host.docker.internal:18080/test/15","errors":[]}
  OK    first export creates: exported=5 updated=0 failed=0
  OK    second export updates, no duplicates: exported=0 updated=5 failed=0
  OK    findings in the DefectDojo test after export 1 and 2: 5 5
-- dojo_id and dojo_url written back:
  #1 default-page -> dojo_id=58 http://host.docker.internal:18080/finding/58
  #2 interesting-header -> dojo_id=57 http://host.docker.internal:18080/finding/57
  #4 database-exposed -> dojo_id=54 http://host.docker.internal:18080/finding/54
  #8 remote-access-exposed -> dojo_id=56 http://host.docker.internal:18080/finding/56
  #9 new-exposure -> dojo_id=55 http://host.docker.internal:18080/finding/55
-- the same findings as DefectDojo holds them:
  dojo #54 [Low] Baza Danych Dostępna Z Sieci: Redis Key-Value Store 7.4.12 (172.31.250.4:6379)  unique_id=database-exposed/172.31.250.4/tcp-6379
  dojo #55 [Info] Nowa Ekspozycja: OpenSSH 9.9 (172.31.250.4:22)  unique_id=new-exposure/172.31.250.4/tcp-22
  dojo #56 [Info] Usługa Zdalnego Dostępu: OpenSSH 9.9 (172.31.250.4:22)  unique_id=remote-access-exposed/172.31.250.4/tcp-22
  dojo #57 [Info] Nagłówki Ujawniają Szczegóły Oprogramowania: Server (172.31.250.2:80)  unique_id=interesting-header/172.31.250.2/tcp-80
  dojo #58 [Info] Strona Domyślna Serwera: Welcome to Nginx! (172.31.250.2:80)  unique_id=default-page/172.31.250.2/tcp-80
nmap XML upload 1: {"test_id":16,"test_url":"http://host.docker.internal:18080/test/16","reimport":false,"created":3,"closed":0,"reactivated":0,"untouched":0,"total":3}
nmap XML upload 2: {"test_id":16,"test_url":"http://host.docker.internal:18080/test/16","reimport":true,"created":0,"closed":0,"reactivated":0,"untouched":3,"total":3}
  OK    nmap upload: first imports, second re-imports into the same test: false true same-test

=== 9. JSON, CSV and XML exports of run 2 import again without a change ===
  json: 3350 bytes -> {"format":"czujka-json","run_id":3,"hosts":4,"services":6,"skipped":0,"invalid":0}
       against run 2: service changes: 0; host status changes: host_gone 172.31.250.5
  OK    json round trip: hosts=4 services=6 invalid=0 service_changes=0
  csv: 1358 bytes -> {"format":"csv","run_id":4,"hosts":4,"services":6,"skipped":0,"invalid":0}
       against run 2: service changes: 0; host status changes: none
  OK    csv round trip: hosts=4 services=6 invalid=0 service_changes=0
  xml: 3124 bytes -> {"format":"nmap-xml","run_id":5,"hosts":4,"services":6,"skipped":0,"invalid":0}
       against run 2: service changes: 0; host status changes: none
  OK    xml round trip: hosts=4 services=6 invalid=0 service_changes=0
  OK    Czujka JSON is lossless (export -> import -> export): identical
-- first lines of the Czujka JSON export:
{"format":"czujka-json","version":1,"generated_at":"2026-11-21T12:49:32.861183Z","run_id":2,"hosts":[
{"run_id":2,"ip":"172.31.250.2","hostnames":["czujka-an-nginx.czujka-an-net"],"up":true,"reason":"arp-response","rtt_ms":0.01,"attempts":1,"mac":"72:F8:25:39:A1:2E","vendor":"","os_guess":"","observed_at":"2026-11-21T12:05:49Z","services":[{"port":80,"proto":"tcp","state":"open","name":"http","product":"nginx","versi ...
-- CSV export:
ip,hostname,up,port,proto,state,service,product,version,extra_info,banner,tls,url,status,title,server,redirect,technologies,classes,cert_cn,cert_issuer,cert_not_after,cert_sha256,cookies,cpe,os,mac,ve
172.31.250.2,czujka-an-nginx.czujka-an-net,true,80,tcp,open,http,nginx,1.33.0,,,,http://172.31.250.2:80/,,Welcome to nginx!,nginx/1.33.0,,nginx:1.33.0,,,,,,,cpe:/a:igor_sysoev:nginx:1.33.0,,72:F8:25:3
172.31.250.3,czujka-an-httpd.czujka-an-net,true,,,,,,,,,,,,,,,,,,,,,,,,6A:ED:52:6D:D6:DB,,0.044,arp-response,,2026-11-21T12:05:49Z
  OK    inventory after the re-imports: hosts=4 open_services=3

=== 10. Automatic export after a run (auto_export with min_interest 25) ===
{"product_name":"Czujka e2e auto 20261121-134914","auto_export":true,"min_interest":25}
  dojo #62 [Low] Baza Danych Dostępna Z Sieci: Redis Key-Value Store 7.4.12 (172.31.250.4:6379)
{"user_email":"system","action":"finding.export.defectdojo","detail":{"auto":true,"exported":1,"failed":0,"run_id":6,"selected":1,"updated":0}}
  OK    run 6 exported its findings with interest >= 25 by itself: 1
  OK    at least one finding passed the threshold: yes

=== 11. Audit log of this flow ===
  12:49:32 admin@czujka.local result.import 1 status=201
  12:49:32 admin@czujka.local service.update 1 status=200
  12:49:32 admin@czujka.local finding.update 4 status=200
  12:49:32 admin@czujka.local result.import 2 status=201
  12:49:33 admin@czujka.local integration.defectdojo.update defectdojo status=200
  12:49:33 admin@czujka.local integration.defectdojo.test defectdojo status=200
  12:49:33 admin@czujka.local finding.export.defectdojo  status=200
  12:49:34 admin@czujka.local finding.export.defectdojo  status=200
  12:49:34 admin@czujka.local run.export.defectdojo 2 status=200
  12:49:34 admin@czujka.local run.export.defectdojo 2 status=200
  12:49:34 admin@czujka.local export.run 2 status=200
  12:49:34 admin@czujka.local export.run 2 status=200
  12:49:34 admin@czujka.local result.import 3 status=201
  12:49:34 admin@czujka.local export.run 2 status=200
  12:49:34 admin@czujka.local result.import 4 status=201
  12:49:34 admin@czujka.local export.run 2 status=200
  12:49:34 admin@czujka.local result.import 5 status=201
  12:49:34 admin@czujka.local export.run 3 status=200
  12:49:34 admin@czujka.local integration.defectdojo.update defectdojo status=200
  12:49:34 system finding.export.defectdojo 6 status=null
  12:49:34 admin@czujka.local result.import 6 status=201

E2E OK: every check passed
```

## `internal/model`

Nothing added and nothing changed by me.

## Edits outside my packages

- `internal/analyze`, `internal/interchange`, `internal/defectdojo`: no edits.
- `docs/ARCHITECTURE.md` §4.2 and `docs/API.md`: the edits that the brief asked for (emergency stop wording, the new route, run export formats, import wording).
- `deploy/docker-compose.yml`: `extra_hosts: host.docker.internal:host-gateway` on the `czujka` service, so the container reaches a DefectDojo on the docker host.

## Known gaps and notes

1. Port scope of the diff: a profile with an explicit port list limits "service gone" to that list. A `top-N` spec is treated as "all ports in scope", because the list behind `top-N` belongs to the engine. When the engine is wired, it should give the real port set.
2. An imported file is a full view of the hosts it lists: a service that the file does not show as open becomes `gone`. An import of a partial scan (few ports) of a known host will report the other services gone.
3. A re-import of the same file is a new run and a new observation. For a host that the file reports as down it is one more miss (see step 9 of the transcript: `host_gone 172.31.250.5` on the third observation).
4. Ports that a file lists as closed and that were never open are not stored (12 services in the sample, 6 kept). The exports contain what the store holds.
5. Host-level `Scripts` (added to `model.HostResult` by the analysis worker) are not stored by `internal/store`, so they are lost in an export. Service-level scripts are kept. The sample file has no host scripts.
6. The automatic DefectDojo export runs synchronously after the analysis, with a 5-minute limit and at most 5000 findings. An error goes to the log and the audit log; it does not fail the run.
7. `dojo_url` uses the URL from the settings. In the e2e stack this is `http://host.docker.internal:18080`, which a browser on the host cannot open.
8. Group keys: above 60 000 open services the analysis uses the per-service `GroupKey` and skips the near-duplicate pass of `AssignGroupKeys`.
9. `SchedBackend` was written against the description in the brief. I have not seen `internal/sched`; method names may need a rename.
10. Not wired because not merged: engine, targets, sched, httpfp, sig, web.

## Docker resources

- Removed: `czcore-e2e` stack with volumes and network, test database `czcore-pg` with its volume, image tag `czujka:e2e`.
- The DefectDojo lab (`lab/defectdojo`, containers `czujka-dojo-*`): I started it for the e2e flow and stopped it at the end (`docker compose stop`; volumes and data kept). I deleted only the products that my e2e runs created (names `Czujka e2e ...`).
