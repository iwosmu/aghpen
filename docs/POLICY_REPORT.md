# Policy worker: report

Branch `iwosmu/czujka-policy`. Date 2026-11-21. Worker report (English); the analyst documentation is [REGULY.md](REGULY.md) (Polish), the routes are in [API.md](API.md#exposure-rules-and-signature-from-an-example).

## 1. What was built

### `internal/rules`: exposure rules ("attack surface as code")

- `dsl.go`, `cond.go`: YAML rule DSL (`id, name, severity, description, remediation, enabled, subject: service|host, expect: absent|present, per: host|scope, where, match`). `where`: scope names/tags, `cidr`, `not_cidr`, `tags`, `not_tags`, `state` (default `open`), `host_status`. Conditions: `class, tech` (with version comparison, `WordPress < 6.5`), `port` (ranges), `proto, service, product, banner, state, host_status, tls` (`present, expired, self_signed, host_mismatch, days_left_below, issuer, subject, version`), `scheme, redirects_to_https, http_status` (`2xx`), `header` (present/absent/regex), `cookie` (name/regex + `secure, http_only, same_site`), `title, url, hostname` (RE2), `new_within_days, tags, min_interest`, combined with `all / any / not`. "No data is not absence": header-absent, no-redirect and no-TLS conditions never match a service without an HTTP answer.
- Validator: Polish messages, YAML paths (`match.any[0].tls.expird`), line numbers, RE2 only (back-references and look-arounds are syntax errors), unknown top-level fields are warnings.
- `eval.go`: streaming evaluator, host by host; memory holds only violations and one flag per scope-level assertion. Stable keys `policy-violation|<rule>|<ip>|<port>/<proto>` (service), `…|<ip>` (host), `…|scope`. Evidence names every matched field (`class: admin-panel`, `port: 8080/tcp`, `not: nie zachodzi: etykieta approved`).
- `service.go`: own table `policy_rules` created at start with the access method of the `findings` table (tde_heap when the store uses pg_tde, verified in the test: `findings=tde_heap policy_rules=tde_heap`), advisory-locked `CREATE TABLE IF NOT EXISTS`. Seed of the starter pack (built-in text refreshed, the analyst's enabled flag kept, retired built-ins removed). CRUD (built-ins can only be switched on/off). `Evaluate(ctx, runID)`: one exported call for the integrator; reads hosts with `store.EachHost`, streams services with their newest observation in one SQL query (`LEFT JOIN LATERAL`, no secrets read), stores findings through `store.UpsertFindings` (analyst-owned fields never overwritten), resolves vanished violations through `store.ResolveFindings` (only status `new`), updates per-rule counters. `DryRun` stores nothing and returns "Ta reguła zgłosiłaby dziś N naruszeń". `Violations` lists the findings of one rule. A rule change triggers a background re-evaluation.
- `builtin/university.yaml`: 14 rules, 11 enabled by default (admin panel outside `mgmt`, login over plain HTTP, expired cert, cert < 14 days, database port, telnet/FTP, RDP/VNC, staging/dev-tool without `approved`, default page, directory listing, outdated CMS major), 3 disabled (new service without `approved`, self-signed, web without HTTPS redirect).
- `http.go`: chi sub-router `Router(can)` that takes the permission middleware.
- Incremental evaluation: not done. A full evaluation of 2 000 hosts takes under 100 ms, so it re-checks everything after every run; this also catches time-dependent conditions (certificate days left, `new_within_days`) without a scan.

### `internal/sigsuggest`: a signature from an example

- `features.go`: candidate features of one observation: non-standard header names, product header values without version (`Server`, `X-Powered-By`, …), cookie names (generic session names weakened), favicon mmh3, title up to its first word with a digit, meta generator, asset paths (other hosts and libraries skipped), distinctive CSS class/id names, HTML comments, visible "Product v1.2.3" text, TLS CN/org, titles of fetched paths. Volatile values are rejected with a reason (dates, long hex, UUID, long digit runs, base64-like tokens, csrf/nonce/token names). Every emitted rule is tested to be valid DSL and to match the example (`TestEmittedRulesMatchTheExample`), and every version rule to extract a version.
- `suggest.go`: stability over the last 5 observations of the example; document frequency over the newest observation of every other service, streamed one observation at a time (`store.EachObservation`, LatestOnly); look-alike detection (another service sharing at least half, and at least 2, of the example's structural features is an instance of the same product and does not count against rarity); features in more than 5 % of the remaining services are rejected as common; up to 6 rules (at most 3 body rules), weights from feature strength (lowered when the feature occurs elsewhere), `min_confidence: 0.6`, version extractors; free slug (built-in and stored signatures checked); safe-mode validator (`sig.Validate`) and retro-hunt (`sig.NewHunter`) over stored data; Polish explanation per rule; "no distinctive features" answer instead of a weak signature.
- `http.go`: `Handler` for `POST /signatures/suggest {service_id}`.

## 2. Evidence

Test database: `docker run -d --name czpol-pg … -p 127.0.0.1:55491:5432 czujka-db:17` (PostgreSQL 17 + pg_tde, own name and port).

```
$ gofmt -l . | wc -l
0
$ go build ./... && go vet ./... && go test ./...      # exit 0
$ CZUJKA_TEST_DB_URL='postgres://czujka:czujka@127.0.0.1:55491/czujka?sslmode=disable' go test -count=1 -v ./internal/rules ./internal/sigsuggest
--- PASS: TestValidatorPolishMessagesAndPaths
--- PASS: TestBuiltinPackIsValid
--- PASS: TestCompareVersions
--- PASS: TestLeaves
--- PASS: TestEvidenceNamesMatchedFields
--- PASS: TestPresentPerHostAndScope
--- PASS: TestHostSubjectAndScopes
--- PASS: TestNoDataIsNotAbsence
--- PASS: TestDryRunMessage
--- PASS: TestEvaluateStoresAndResolvesViolations   (triaged finding keeps status, note and severity; vanished ones resolved; returning one reopened; disabled rule resolves its findings)
--- PASS: TestHTTPRoutes                            (dry run stores nothing; 422 / 409 / 201 / 204; every permission checked)
    ingest of 2000 hosts x 3 services: 311ms
    dry run: 200 violations, 2000 hosts, 6000 services, took 47 ms; Ta reguła zgłosiłaby dziś 200 naruszeń (sprawdzono 2000 hostów i 6000 usług).
    first evaluation (all inserts): rules=11 violations=1160 created=1160 eval=45 ms store=48 ms total=94 ms
    second evaluation (no change): violations=1160 created=0 resolved=0 eval=54 ms store=43 ms total=97 ms
--- PASS: TestScale2000Hosts
ok   github.com/iwosmu/aghpen/internal/rules
--- PASS: TestExtract
--- PASS: TestEmittedRulesMatchTheExample
--- PASS: TestTitlePrefixAndVolatile
--- PASS: TestSuggestFromStoredInventory            (kiosk with 40 nginx defaults: 1 look-alike, history 1; nginx default page: "nie ma cech wyróżniających")
ok   github.com/iwosmu/aghpen/internal/sigsuggest
```

### Suggested signatures on real data

19 lab imitation hosts started from the lab image (`docker run -d --name czpol-<host> -e LABSIM_HOST=<host> -p 127.0.0.1:181xx:<port> czujka-lab/labsim:1`), 30 HTTP/TLS services. `TestProofOnLiveServices` fingerprints each with the product's collector (`httpfp`, GET/HEAD only, second pass with the safe signature paths as the scanner does), matches the built-in signature engine, stores everything through `store.IngestHosts`, then calls `Suggest`:

```
$ CZUJKA_TEST_DB_URL=… SIGSUGGEST_PROOF='kiosk-1:80=127.0.0.1:18100,…' SIGSUGGEST_PROOF_TARGETS='kiosk-1:80,cam-1:80,printer-1:80,nas-1:5000,staging-portal:80,news-site:80' \
  go test -count=1 -v -run TestProofOnLiveServices ./internal/sigsuggest
=== kiosk-1:80 (service 1, 127.0.0.1:18100) ok=true matches_target=true other_matches=1 took=7ms
Sygnatura „InfoKiosk” pasuje do przykładu i do 1 innych z 29 zapisanych usług (podobne instancje).
--- retro-hunt hits: [127.0.0.1:18100 v=4.2.1 127.0.0.1:18101 v=4.2.1]
=== cam-1:80 (service 3, 127.0.0.1:18102) ok=true matches_target=true other_matches=2 took=7ms
Sygnatura „App-webs” pasuje do przykładu i do 2 innych z 29 zapisanych usług (podobne instancje).
--- retro-hunt hits: [127.0.0.1:18102 v= 127.0.0.1:18103 v= 127.0.0.1:18104 v=]
=== printer-1:80 (service 6, 127.0.0.1:18105) ok=true matches_target=true other_matches=5 took=7ms
Sygnatura „HP LaserJet Pro” pasuje do przykładu i do 5 innych z 29 zapisanych usług (podobne instancje).
--- retro-hunt hits: [127.0.0.1:18105 v= 127.0.0.1:18106 v= 127.0.0.1:18107 v= 127.0.0.1:18108 v= 127.0.0.1:18109 v= 127.0.0.1:18110 v=]
=== nas-1:5000 (service 15, 127.0.0.1:18114) ok=true matches_target=true other_matches=1 took=6ms
Sygnatura „Synology DSM” pasuje do przykładu i do 1 innych z 29 zapisanych usług (podobne instancje).
--- retro-hunt hits: [127.0.0.1:18114 v=6.2 127.0.0.1:18115 v=6.2]
=== staging-portal:80 (service 17, 127.0.0.1:18116) ok=false matches_target=false other_matches=0 took=4ms
Ta usługa nie ma cech wyróżniających: z 2 kandydatów żaden nie jest jednocześnie rzadki i stały (porównano z 29 innymi usługami HTTP). Słaba sygnatura dawałaby fałszywe trafienia, więc jej nie proponuję.
--- retro-hunt hits: []
=== news-site:80 (service 20, 127.0.0.1:18119) ok=true matches_target=true other_matches=0 took=6ms
Sygnatura „Aktualności Koła Naukowego” pasuje do przykładu i do żadnej innej z 29 zapisanych usług.
--- retro-hunt hits: [127.0.0.1:18119 v=1.26.2]
proof_integration_test.go:143: policy evaluation on the live inventory: rules=11 hosts=1 services=30 violations=20 by_rule=map[admin-panel-outside-mgmt:4 login-over-plain-http:9 staging-or-debug-exposed:7] took=9ms
```

```
=== kiosk-1:80 (service 1, 127.0.0.1:18100) ok=true matches_target=true other_matches=1 took=7ms
Sygnatura „InfoKiosk” pasuje do przykładu i do 1 innych z 29 zapisanych usług (podobne instancje).
--- YAML ---
id: infokiosk
name: 'InfoKiosk'
category: other
description: 'Sygnatura zaproponowana z przykładu 127.0.0.1:18100 (Informator — kiosk k-7f3a). 6 z 6 cech nie występuje w żadnej usłudze spoza grupy podobnych instancji.'
tags: [sugerowana]
interest: 20
match:
  condition: any
  min_confidence: 0.6
  rules:
    - {type: favicon, mmh3: [1990289189], weight: 0.9}
    - {type: header, name: 'X-Infokiosk-Node', weight: 0.7}
    - {type: cookie, name: 'infokiosk_sid', weight: 0.7}
    - {type: header, name: 'Server', regex: '^ik-httpd', weight: 0.6}
    - {type: body, regex: 'InfoKiosk[ /]v?[0-9]+\.[0-9]+', weight: 0.6}
    - {type: title, regex: '^Informator — kiosk', weight: 0.55}
version:
  - {type: body, regex: 'InfoKiosk[ /]v?([0-9]+(?:\.[0-9]+)+)'}
  - {type: body, regex: 'InfoKiosk build v?([0-9]+(?:\.[0-9]+)+)'}
--- why ---
  - ikona (favicon mmh3 1990289189) występuje tylko w tej usłudze i w 1 podobnych instancjach (0 z 28 pozostałych usług) (waga 0.90)
  - nagłówek X-Infokiosk-Node występuje tylko w tej usłudze i w 1 podobnych instancjach (0 z 28 pozostałych usług) (waga 0.70)
  - ciasteczko infokiosk_sid występuje tylko w tej usłudze i w 1 podobnych instancjach (0 z 28 pozostałych usług) (waga 0.70)
  - nagłówek Server: ik-httpd występuje tylko w tej usłudze i w 1 podobnych instancjach (0 z 28 pozostałych usług) (waga 0.60)
  - napis „InfoKiosk 4.2.1” z numerem wersji występuje tylko w tej usłudze i w 1 podobnych instancjach (0 z 28 pozostałych usług) (waga 0.60)
  - tytuł zaczyna się od „Informator — kiosk” występuje tylko w tej usłudze i w 1 podobnych instancjach (0 z 28 pozostałych usług) (waga 0.55)
--- retro-hunt hits: [127.0.0.1:18100 v=4.2.1 127.0.0.1:18101 v=4.2.1]
```

```
=== printer-1:80 (service 6, 127.0.0.1:18105) ok=true matches_target=true other_matches=5 took=7ms
Sygnatura „HP LaserJet Pro” pasuje do przykładu i do 5 innych z 29 zapisanych usług (podobne instancje).
--- YAML ---
id: hp-laserjet-pro
name: 'HP LaserJet Pro'
category: iot
description: 'Sygnatura zaproponowana z przykładu 127.0.0.1:18105 (HP LaserJet Pro M404dn 10.66.30.20). 5 z 5 cech nie występuje w żadnej usłudze spoza grupy podobnych instancji.'
tags: [sugerowana]
interest: 20
classes: [iot]
match:
  condition: any
  min_confidence: 0.6
  rules:
    - {type: favicon, mmh3: [1299514437], weight: 0.9}
    - {type: title, regex: '^HP LaserJet Pro', weight: 0.55}
    - {type: body, contains: '/hp/device/DeviceStatus/Index', weight: 0.5}
    - {type: body, contains: '/hp/device/SuppliesStatus', weight: 0.5}
    - {type: body, contains: '/hp/device/NetworkSummary', weight: 0.5}
--- why ---
  - ikona (favicon mmh3 1299514437) występuje tylko w tej usłudze i w 5 podobnych instancjach (0 z 24 pozostałych usług) (waga 0.90)
  - tytuł zaczyna się od „HP LaserJet Pro” występuje tylko w tej usłudze i w 5 podobnych instancjach (0 z 24 pozostałych usług) (waga 0.55)
  - zasób /hp/device/DeviceStatus/Index w treści strony występuje tylko w tej usłudze i w 5 podobnych instancjach (0 z 24 pozostałych usług) (waga 0.50)
  - zasób /hp/device/SuppliesStatus w treści strony występuje tylko w tej usłudze i w 5 podobnych instancjach (0 z 24 pozostałych usług) (waga 0.50)
  - zasób /hp/device/NetworkSummary w treści strony występuje tylko w tej usłudze i w 5 podobnych instancjach (0 z 24 pozostałych usług) (waga 0.50)
--- retro-hunt hits: [127.0.0.1:18105 v= 127.0.0.1:18106 v= 127.0.0.1:18107 v= 127.0.0.1:18108 v= 127.0.0.1:18109 v= 127.0.0.1:18110 v=]
```

```
=== nas-1:5000 (service 15, 127.0.0.1:18114) ok=true matches_target=true other_matches=1 took=6ms
Sygnatura „Synology DSM” pasuje do przykładu i do 1 innych z 29 zapisanych usług (podobne instancje).
--- YAML ---
id: synology-dsm
name: 'Synology DSM'
category: panel
description: 'Sygnatura zaproponowana z przykładu 127.0.0.1:18114 (nas-wimiip - Synology DiskStation). 5 z 5 cech nie występuje w żadnej usłudze spoza grupy podobnych instancji.'
tags: [sugerowana]
interest: 20
classes: [admin-panel, iot, login]
match:
  condition: any
  min_confidence: 0.6
  rules:
    - {type: favicon, mmh3: [233021496], weight: 0.9}
    - {type: title, equals: 'nas-wimiip - Synology DiskStation', weight: 0.6}
    - {type: body, regex: 'Synology DSM[ /]v?[0-9]+\.[0-9]+', weight: 0.6}
    - {type: body, contains: 'webman/resources/css/desktop.css', weight: 0.5}
    - {type: body, contains: 'webapi/entry.cgi', weight: 0.5}
version:
  - {type: body, regex: 'Synology DSM[ /]v?([0-9]+(?:\.[0-9]+)+)'}
--- why ---
  - ikona (favicon mmh3 233021496) występuje tylko w tej usłudze i w 1 podobnych instancjach (0 z 28 pozostałych usług) (waga 0.90)
  - tytuł „nas-wimiip - Synology DiskStation” występuje tylko w tej usłudze i w 1 podobnych instancjach (0 z 28 pozostałych usług) (waga 0.60)
  - napis „Synology DSM 6.2” z numerem wersji występuje tylko w tej usłudze i w 1 podobnych instancjach (0 z 28 pozostałych usług) (waga 0.60)
  - zasób webman/resources/css/desktop.css w treści strony występuje tylko w tej usłudze i w 1 podobnych instancjach (0 z 28 pozostałych usług) (waga 0.50)
  - zasób webapi/entry.cgi w treści strony występuje tylko w tej usłudze i w 1 podobnych instancjach (0 z 28 pozostałych usług) (waga 0.50)
--- retro-hunt hits: [127.0.0.1:18114 v=6.2 127.0.0.1:18115 v=6.2]
```

```
=== cam-1:80 (service 3, 127.0.0.1:18102) ok=true matches_target=true other_matches=2 took=7ms
Sygnatura „App-webs” pasuje do przykładu i do 2 innych z 29 zapisanych usług (podobne instancje).
--- YAML ---
id: app-webs
name: 'App-webs'
category: iot
description: 'Sygnatura zaproponowana z przykładu 127.0.0.1:18102 (bez tytułu). 3 z 3 cech nie występuje w żadnej usłudze spoza grupy podobnych instancji.'
tags: [sugerowana]
interest: 20
classes: [iot, login]
match:
  condition: any
  min_confidence: 0.6
  rules:
    - {type: favicon, mmh3: [-2069091689], weight: 0.9}
    - {type: header, name: 'Server', regex: '^App-webs', weight: 0.6}
    - {type: body, contains: '/doc/page/login.asp', weight: 0.5}
--- why ---
  - ikona (favicon mmh3 -2069091689) występuje tylko w tej usłudze i w 2 podobnych instancjach (0 z 27 pozostałych usług) (waga 0.90)
  - nagłówek Server: App-webs występuje tylko w tej usłudze i w 2 podobnych instancjach (0 z 27 pozostałych usług) (waga 0.60)
  - zasób /doc/page/login.asp w treści strony występuje tylko w tej usłudze i w 2 podobnych instancjach (0 z 27 pozostałych usług) (waga 0.50)
--- retro-hunt hits: [127.0.0.1:18102 v= 127.0.0.1:18103 v= 127.0.0.1:18104 v=]
```

`staging-portal:80` is a bare nginx redirect: the answer is "nie ma cech wyróżniających" and no YAML, as intended. All retro-hunts report `packets_sent: 0`.

The first proof run exposed a flaw: sibling instances (the second kiosk, the other cameras, the other printer ports) counted against rarity, so every weight was lowered and the cameras and printers were rejected as "common". Look-alike detection fixed it (commit `c28f692`); a second flaw (two weak features, `Server: nginx` and a title, made every nginx service a look-alike) is fixed by deciding look-alikes on structural features only.

## 3. `internal/model`

Nothing added or changed. Rule issues reuse `model.SignatureIssue`; violations are `model.Finding` with `Type: "policy-violation"`.

## 4. Lines to add to wire (integrator)

```go
import (
	"github.com/iwosmu/aghpen/internal/rules"
	"github.com/iwosmu/aghpen/internal/sigsuggest"
)

// at start, after st.Migrate:
pol := rules.New(st, logger)
if err := pol.Start(ctx); err != nil { return err } // creates policy_rules, seeds the starter pack
sugg := sigsuggest.New(st, logger)

// internal/api/server.go routes(), inside r.Route("/api/v1", …):
r.Mount("/rules", pol.Router(can))
r.With(can(model.PermSignaturesRead)).Post("/signatures/suggest", sugg.Handler)

// after the analysis of every run AND every import (runner post-run hook, import handler):
if rep, err := pol.Evaluate(ctx, runID); err != nil { log.Error("policy evaluation failed", "run", runID, "error", err) } else { _ = rep }
```

Required one-line change in `internal/wire/analysis.go` (`AnalyzeRun`, stale-finding loop): skip policy findings, or `AnalyzeRun` resolves them and `pol.Evaluate` reopens them in the same cycle:

```go
if f.Manual || derived[f.Key] || f.LastRunID >= runID || f.Type == rules.FindingType {
```

UI (`web/`): a "Reguły" page (list, YAML editor calling `/rules/validate` and `/rules/dry-run` on edit, enable switch, violations per rule) and a "Zaproponuj sygnaturę" button on the service page that posts `/signatures/suggest` and opens the YAML in the signature editor. Wire format in API.md.

## 5. Known gaps and next steps

- Evaluation is full, not incremental (measured under 100 ms for 2 000 hosts; a 50 000-host inventory should be measured).
- Rule conditions do not read the body excerpt (it is stored encrypted and is not loaded by the evaluator); body checks belong in signatures, whose classes and technologies rules can then use.
- `sigsuggest`: a title that contains a per-device name without digits (`nas-wimiip - Synology DiskStation`) is kept whole; harmless under `condition: any`, but a smarter title split would generalise better. Look-alike threshold (half of the structural features) is a heuristic tuned on the lab.
- Proof data is on 127.0.0.1 (one host, 30 ports) because Docker Desktop on macOS does not route to container IPs; the same code path stores data for any address.
