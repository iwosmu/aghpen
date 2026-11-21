# Worker report: UI on the lab /16

Task `task_af8038eedd3a`, branch `iwosmu/czujka-web`, 2026-11-21. All edits are in `web/`. No Go file and no `internal/model` field was changed.

Stack: `deploy/docker-compose.yml` + `deploy/docker-compose.scan-network.yml`, project `czui`, port 18610, scanner at 10.66.0.2 on `czujka-lab` (10.66.0.0/16, 70 hosts). `/healthz` → `probe.mode = nmap-raw`. Vite dev on 15610 proxies to it. Wizard stack: project `czuiw`, port 18611, fresh volume.

## 1. Live flows (point 1)

| Flow | Result | Evidence |
| --- | --- | --- |
| Traffic budget on the profile and in the start dialog | PASS | `01`, `30` |
| Run page: map of 256 /24 blocks, chunk table with work groups (`Chunk.group`), hover highlights the group | PASS (run #2: 108 groups, 78 merged) | `02`, `03`, `47-run-completed-*` |
| Live pps against the cap (run page gauge, top strip, dashboard panel) | PASS | `02`, `40` |
| Pause / resume / cancel | PASS (0.27 s / 0.26 s / cancel) | `04`–`06` |
| Time window closes mid-run → paused `window_closed`, resumed by the scheduler | PASS (run #3 paused 15:33:01, resumed 15:35:08 by the scheduler) | `32`, `33` |
| Scheduled run | PASS (runs with trigger `schedule` from cron `*/2 * * * *`) | runs list |
| Emergency stop during a scan, resume refused (409), release, manual resume | PASS (paused in 0.4 s) | `11`–`15` |
| Dashboard and lists fill with the lab hosts | PASS (66–68 hosts up, 74 services, 140+ findings) | `40`–`46` |

## 2. Point 2 features

Discovery mode cards with the fast-mode warning; UDP section (allow-list 53, 123, 137, 161, 500, 1900, 5353; raw-socket warning from `/healthz`); `retry.down_after_misses`; `host_missing` / `hosts_missing` / `services_unreachable` in the dashboard headline, change log, compare view and run summary; scanner mode in the safety chip; per-run report (open and print); signature import with the per-signature result; retro-hunt `total_hits`, `truncated`, `missing_paths`, `notes`; passive sources (zone file, reverse DNS, confirm candidates, crt.sh off by default with the external-service warning). Screenshots `50`–`55`.

## 3. Point 3 (routes live since 468754e)

| Feature | Result | Evidence |
| --- | --- | --- |
| Manual host entry (POST /hosts, services as `port/proto name product version` lines) | PASS: host 10.66.250.15 created, run `manual-entry`, 3 changes | `60`, `61` |
| Findings export in DefectDojo Generic Findings (JSON, CSV) | PASS: 274.5 kB JSON | `63` |
| Findings import (format detected) | PASS: re-import of the export → 180 updated, 0 created, 0 duplicates | `63` |
| DefectDojo per-scope mapping, `status_sync`, pull (dry run + apply), sync | UI built; not run end to end: no DefectDojo instance in the lab | `65` |
| Allowed networks in the safety policy | PASS: saved `10.66.0.0/16`, `127.0.0.0/8` | `64` |
| Run note and label (PATCH /runs/{id}) | PASS | `62` |
| SSE final event `paused` | handled: the run stream closes and the cache takes the paused run | code |
| UDP workaround removed | PASS: PATCH /profiles with `udp` → 200 | API |

## 4. Follow-up screens (routes not mounted yet: calm "funkcja niedostępna" state)

Built against `docs/API-time.md` and `docs/API-policy.md`; not verified on real data yet.

- **Wehikuł czasu** (`/time`, nav "Obserwacja"): scrubber over `GET /timeline` (mark height by changes, re-probe runs thin), ← → step, drag with 140 ms debounce, `?run=` in the URL; headline counts with the difference to today; Polish `diff_to_now.sentences`; Hilbert map of that run (colour = hosts up then, outline = block where a host from then is silent today); paged host, service and finding lists with filters.
- **Host detail**: swim lanes from `GET /timeline/hosts/{id}` (host up/missing/down, one lane per service, version ticks) and the re-probe plan for the host, next to the heatmap.
- **Service detail**: field history from `GET /timeline/services/{id}`; button "Zaproponuj sygnaturę" (`POST /signatures/suggest`) with YAML, Polish explanations, retro-hunt result and "Otwórz w edytorze".
- **Plan ponownych sprawdzeń**: dashboard (next to unstable hosts) and host detail; settings (enabled, budget, backoff steps); `blocked` reason; wizard step 5 offers it as a checked option; runs with trigger `reprobe` get their own label.
- **Reguły ekspozycji** (`/rules`): list with severity, switch, violation count; YAML editor with debounced `/rules/dry-run` ("Ta reguła zgłosiłaby dziś N naruszeń" + matching services); violations per rule; "Sprawdź teraz". Findings of type `policy-violation` have a label, a filter and a link to their rule.
- `POST /signatures/suggest` answers 405 today (the path matches `GET /signatures/{id}`); the UI treats 404 "no such route", 405 and 501 as "not available".

Screenshots `70`–`73`.

## 5. First-run wizard (point 4)

Login with the generated password → running first scan: **19.9 s** (Playwright, typing at 45 ms per character, 1.5 s pause per step, fresh `czuiw` stack; 5 steps, about 10 fields). The setup page shows 0.8 s after login. Screenshots `20`–`25`.

## 6. Polish (point 5)

Tour in PL/EN, dark/light, 1440×900 and 390×844: `40`–`47` with suffixes `-pl-dark-1440`, `-en-dark-1440`, `-pl-light-1440`, `-pl-dark-390`, `-en-light-390`. Fixes from the review: estimate text with a closed window, live cap on the dashboard run panel, resume disabled during the emergency stop, start dialog picks a profile with a scope, headline names the profile of the last run. The Impeccable critique ran in reduced form (detector: 0 findings, plus my own screenshot review), because the full critique needs sub-agents, which this task forbids.

## 7. Backend problems for the integrator

1. `POST /profiles/{id}/estimate` outside the window returns `window_sec: 0`, `fits_window: false` for a profile with windows; it should give the next window's length. The UI words it as "the window is closed now".
2. Engine speed (accuracy owner): an empty /24 chunk takes about 19 s at about 80 pps, far under the cap; a /16 needs about 27 min with 3 parallel chunks, about 6–7 min with 8. Early ETA is far off (3 h, then 3 min). Adaptive chunking never grew chunks above /24.
3. The estimate assumes a 5 % live rate (4 M packets, 50 min) for a sparse /16.
4. A profile with `schedule.enabled` and `interval_minutes: 1440` starts at once on creation; a manual start then fails with "already active" and no clearer message.
5. ~~`POST /signatures/suggest` → 405~~ fixed in f7d69c9 (route mounted, answers 200).
6. ~~Time machine, re-probe, rules and suggest routes: 404~~ live since f7d69c9 (see section 8).

## 8. Round 4: mounted feature routes on real lab data

All four screens run against the czui stack (lab /16, 11+ runs). No mismatch with `docs/API.md` that needed a UI change; fixes were on the UI side.

| Screen | Evidence | Screenshot |
| --- | --- | --- |
| Time machine | 11 runs on the scrubber, 5–8 ms per step; the map frame is the widest completed run (full /16 Hilbert map); blocks with hosts or services silent today are outlined | `90-time-machine-latest`, `91-time-machine-first-run` |
| Host swim lanes | 10.66.70.22 (lab flapper): up / missing / down intervals and the service lane | `92-host-swim-lanes` |
| Field history | 10.66.70.15:80: `version` flips between `nginx` and `–` | `95-service-field-history` |
| Rules | after `POST /rules/evaluate`: 57 violations across 11 rules; dry run of "admin panel outside management network" gives 11 | `93-rule-dry-run` |
| Signature suggest | service 1: 6 suggested rules and a retro-hunt over saved results | `94-suggest-signature` |
| Re-probe plan | re-probing enabled in settings; real entries for the flappers 10.66.70.22 and 10.66.70.20: "Potwierdzenie 1 z 3, 10 min po pierwszym braku" | `96-reprobe-plan-dashboard`, `97-reprobe-plan-host` |

UI fixes in this round: time machine map frame and density-only legend (`AddressMap snapshot`), Count grid borders, re-probe "blocked" text shown only when re-probing is on, duplicate React key on `/changes/compare` (unsaved diff rows have `id: 0`).

Backend observations:

1. Field history treats "no version probe" as a change: profile 4 runs without `-sV`, so `version` alternates `nginx` / `–` between profiles. The engine should keep the last known version when the run did not probe versions.
2. Interest values: every top service and top finding reads 100 (review point 5). The UI is unchanged; check again after the accuracy worker recalibrates the score.

## 9. Round 4: review fixes

| Point | Change | Before → after |
| --- | --- | --- |
| 1. Headline | The sentence comes from data. Baseline run: "Pierwszy obraz sieci: N aktywnych hostów, M otwartych usług. To punkt odniesienia…". Later runs list only non-zero counts ("Od poprzedniego skanu: 2 zniknięcia."). The attention line names the main risk: "11 paneli administracyjnych dostępnych z sieci, w tym phpMyAdmin i Adminer." "Nic nie wymaga uwagi" only when no open finding has high severity or interest ≥ 70 (`lib/headline.ts`, tested). | `80-before-dashboard` → `80-after-dashboard` |
| 2. Rate over cap | The effective cap is min(profile, policy). Over the cap by more than 5 %: red number with an alert icon, striped red fill, `role="alert"` text in the gauge (run page and dashboard), and red "current / cap pps" in the top strip. Shown live with profile 2 capped to 400 while the engine reported 792–800 pps. | `81b-before-dashboard-live-gauge` → `81c-after-dashboard-over-cap`, `81d-after-run-over-cap` |
| 3. Progress at 0 % | Running chunks draw a striped moving segment on the progress bar (off with reduced motion). The phase is in words: "Wykrywanie hostów w 64 podgrupach (16 127 adresów). Postęp rośnie po zakończeniu każdej podgrupy." | `81-before-run-progress` → `81-after-run-progress` |
| 4. Few observations | Under 8 observations the 7 × 24 map is replaced by a strip of the probes (filled = answer) plus empty slots, and the text says how many more scans the weekly pattern needs. | `82-before-host-one-observation` → `82-after-host-one-observation` |
| 5. Interest | No change: waiting for the recalibration. | – |
| 6. Login, empty product, viewer | Login: one line under the heading: what Czujka does and that it only detects (GET and HEAD, never tries to log in). Empty product checked as `viewer` on a fresh stack. Every page crawled as `viewer` on the lab stack: 0 responses 401/403, 0 toasts; edit forms show "Tylko odczyt…"; `/setup` now redirects a role without create/configure/run rights to the dashboard. | `83-before-login-*` → `83-after-login-1440/390`; `84-after-empty-product-viewer-1440/390`; `viewer_*` |
| 7. Demo mode | `?present=1` (or Shift+P) zooms the UI one step (×1.125) for 1080p; `?present=0` turns it off. The safety strip stays. There is no dev chrome to hide. At 1920 × 1080 the normal UI already records cleanly; present mode fills the width better. | `98-normal-1920-dashboard`, `98-present-1920-dashboard`, `98-present-1920-time` |

## 10. Operator lock (CZUJKA_ALLOWED_NETWORKS, b89755f)

Checked on the czui stack restarted with `CZUJKA_ALLOWED_NETWORKS=10.66.0.0/16`.

| Place | What the UI shows | Screenshot |
| --- | --- | --- |
| Safety page | A locked block "Zablokowane przez operatora wdrożenia" with the lock networks above the editable allowed networks, and one sentence: no user, an administrator included, can widen it. A live warning names entries outside the lock before saving. A refused save (422) shows the reason next to the field, in Polish. | `lock-1-safety-refused` |
| Top safety strip | Lock icon and `10.66.0.0/16` in the chip; the tooltip names the lock and says no user can widen it. | visible in every screenshot |
| Wizard, network step | One line about the lock under the ranges; the live preview counts and marks entries outside the lock ("blokada"). | `lock-2-wizard-preview` |
| Target preview (Cele) | Same lock line and marking in `PreviewReport`. | `lock-3-targets-preview` |
| Ad-hoc run | New dialog "Skan wybranych adresów" on Przebiegi (`POST /runs/adhoc`; there was no UI for it). It marks addresses outside the lock as you type, and shows the 422 refusal as "Zablokowane przez operatora wdrożenia" plus the per-address reason. | `lock-4-adhoc-refused` |

Backend observations:

1. A policy saved before the lock keeps `allowed_networks` outside it (here `127.0.0.0/8`). Every later `PUT /settings/safety` answers 422 until an administrator removes that entry, even a change of `max_pps` only; the wizard's limits step also sends the whole policy and gets the same 422. The UI warns about such entries, but the server could flag or drop them at start.
2. `/targets/preview` gives `line: 0` for entries dropped by the policy or the lock. The UI used the line as a React key; fixed in the UI, and it shows "–" instead of "wiersz 0".
3. The 422 texts of `PUT /settings/safety` and `POST /runs/adhoc` are English; the UI translates the lock cases (`lib/lock.ts`, tested).

## 11. DefectDojo end to end through the UI (local DefectDojo 3.5.202)

Czujka (czui stack, lab data) talks to DefectDojo at `http://host.docker.internal:18080` (from the container). New product type objects were not needed: the type `Czujka` existed. Products created: `Czujka UI e2e` (default) and `Czujka UI e2e – hosty niestabilne` (scope mapping for the scope "Laboratorium: hosty niestabilne").

| # | Step | Result | Evidence |
| --- | --- | --- | --- |
| 1 | Settings: URL, API key, test with version, product type / product / engagement, scope mapping, `status_sync` | PASS: "Połączono z DefectDojo 3.5.202 jako admin", settings saved and read back | `dojo-1-settings` |
| 2 | Export selected findings and a filtered set; links; fields in DefectDojo | PASS: 3 selected findings of a host in the mapped scope went to the mapped product (test #25), 2 selected + the filter "waga: wysoka" (33) to the default product (test #26). In DefectDojo: title, severity, description with evidence, endpoint `http://10.66.70.14:49152`, `unique_id_from_tool` = the Czujka key. Links: see step 9 | `dojo-2a`…`dojo-2e`, `dojo-pair-*` |
| 3 | Export again | PASS: "Nowe w DefectDojo 0, Zaktualizowane 33"; no duplicate `unique_id_from_tool` in the test | `dojo-3-export-again` |
| 4 | DefectDojo: false positive, risk accepted, mitigated; Czujka: dry run, conflict, apply | PASS: dry run proposed #719 → fałszywy alarm, #718 → zaakceptowane, #717 → rozwiązane; #716 (status "w analizie" set by an analyst in Czujka, mitigated in DefectDojo) listed as a conflict and kept; "Zastosowano: 3" | `dojo-4a-pull-dry-run`, `dojo-4b-pull-applied` |
| 5 | One reopen rule: resolve in Czujka and sync; reappear and sync; accepted and false positive stay | PASS (rule), FAIL (frequent profile still flips, backend 4): #1658 set to "rozwiązane" in the UI, sync "Zamknięte: 3" (DefectDojo #705: Inactive, Mitigated); run #144 saw it again → one `finding.reopen` (by `system`, resolved 16:09:26, seen 16:10:05), run #145 → no second reopen; sync "ponownie otwarte: 1" (DefectDojo #705: Active). #1598 "zaakceptowane" and #1599 "fałszywy alarm" kept their status through runs #141, #143, #144, #145 although both were observed in each | `dojo-5a`…`dojo-5d` |
| 6 | Run as "Nmap Scan", then the next runs of the profile into the same test | PASS: run #129 → "Pierwszy import", mode `import`, test #30 "Czujka nmap: profil 4" (5 new); run #130 → mode `reimport` into #30 (4 closed, 1 unchanged: the unstable hosts were gone); run #132 → mode `reimport` into #30 (4 reactivated, 1 unchanged). The run dialog shows the mode and the test title | `dojo-6a-nmap-run-129`, `dojo-6b-nmap-run-130`, `dojo-6c-nmap-run-132` |
| 7 | Generic Findings file route both ways | PASS: `czujka-findings.dojo.json` from Import / eksport, uploaded by hand in the DefectDojo UI as "Generic Findings Import": "processed a total of 301 findings" with the same severity split (33 / 18 / 33 / 217). A DefectDojo API findings list (test #28) imported into Czujka: format `dojo-api-json`, 3 created | `dojo-7b`, `dojo-7c`, `dojo-7d` |
| 8 | Errors: wrong key, unreachable URL, DefectDojo down during an export | PASS: wrong key → "DefectDojo odrzucił token API… HTTP 403"; unreachable → "brak połączenia z DefectDojo… connection refused"; nginx of DefectDojo stopped 2 s into an export of 265 findings → the dialog shows "Usługa zewnętrzna nie odpowiada…" and a retry hint; after the restart the same export gave 40 new + 225 updated and 0 duplicates (backend 3) | `dojo-8a`…`dojo-8d` |
| 9 | `link_url` (public base of every DefectDojo link) | PASS: "Adres do odnośników (publiczny)" = `http://127.0.0.1:18080` saved and read back; after the next export finding #70 links to `http://127.0.0.1:18080/finding/618` and the link opens the finding in DefectDojo (before: `host.docker.internal`, ERR_NAME_NOT_RESOLVED). Stored links change only when a finding is exported again. The URL hint under "Adres DefectDojo" now shows only while `link_url` is empty | `dojo-9a-link-url-setting`, `dojo-9b-czujka-link`, `dojo-9c-link-opens-defectdojo` |
| 10 | Outage after the import: 502 `dojo_unconfirmed`, then linking | PASS: a local proxy in front of DefectDojo dropped every request for 40 s right after `/reimport-scan/` answered 201. Export of 2 new manual findings → the dialog shows "Wysłano, nie potwierdzono. Powtórz eksport…" (no raw Go error, no second retry hint). Path A: `POST /defectdojo/pull` from the UI → "Połączono 2 znaleziska wysłane w niepotwierdzonym eksporcie" (`linked: 2`, #2191 → DefectDojo #711, #2192 → #710). Path B: two more findings, same outage, then the same export again → "Nowe 0, Zaktualizowane 2" (#2311 → #712, #2312 → #713). No duplicates in test #26 | `dojo-10a-unconfirmed-502`, `dojo-10b-pull-linked`, `dojo-10c-export-again-links` |

UI changes for this flow: export of the filtered set (button "Pasujące do DefectDojo" / "Wszystkie do DefectDojo" with a confirmation that says existing findings are updated), "Do DefectDojo" on a completed run (Nmap Scan import, result with the test link and re-import counts), the status pull lists every proposed change and every conflict (Czujka status vs DefectDojo state, reason), the apply button disappears after applying, one error after a failed export (no duplicate toast) plus a retry hint, and a hint under the URL when it is a container-only address.

Backend problems (exact). Round 1 items 1 (`link_url`), 2 (test per profile) and 3 (`dojo_unconfirmed`, linking) are fixed and verified above. Open:

4. The reopen rule works (once per resolution), but findings on the frequent profile still alternate between "nowe" and "rozwiązane", now through the automatic resolution: `internal/wire/analysis.go` (after `UpsertFindings`) resolves every `new` finding of an answering host that the run no longer derives. On the unstable hosts of profile 4 a service is missing in one run and back in the next, so 11 findings on 10.66.70.x went resolved → new twice in 15 minutes (runs #132 and #139; for example #155 "Serwer plików (10.66.70.10:80)", #1594…#1600 on 10.66.70.11), and each change is a DefectDojo close/reopen with `status_sync` on. Suggestion: resolve automatically only after the service is gone by the stability model (N misses in a row, or not for services marked unstable).
5. `accepted` does not reach DefectDojo: exporting #1598 (accepted) leaves DefectDojo #703 `active: true, risk_accepted: false` without an error (product without simple risk acceptance). In the product with simple risk acceptance enabled the export fails for #90: HTTP 400 "Active findings cannot be risk accepted." (the PATCH sets `risk_accepted` without `active: false`). `false_positive` works (#704: `false_p: true`, inactive).
6. Severity: "Panel administracyjny: phpMyAdmin (10.66.10.10:80)" is `info` (interest 75) in Czujka and DefectDojo; for the accuracy owner.

Left in DefectDojo (the README does not call them disposable): products `Czujka UI e2e` (tests #26 API findings, #27 and #28 Nmap Scan of round 1, #30 "Czujka nmap: profil 4", #29 the manual Generic Findings import, which duplicates the API findings in the same product; simple risk acceptance enabled for step 4) and `Czujka UI e2e – hosty niestabilne` (test #25). In Czujka: 3 findings imported from DefectDojo test #28 ("Open Port: …/TCP") and 4 manual findings "Ręczny wpis analityka 1…4" on 10.66.10.10 (step 10), exported to test #26.

Also in this round: the two lock refusals are translated again in the EN view (`lockMessage()` matches the new Polish server texts as well as the old English ones; test added), and the target preview shows the real line number for entries that the policy or the lock drops (the "–" workaround is gone; the lock icon stays).

## 12. Live rate basis and estimated packets (engine rate fix, 74b332b)

`RunStats.current_pps_basis` and `RunStats.packets_estimated` are shown in the three places with a live rate. Checked on run #126 (lab /16, profile cap 2000 pps), where the engine reported `current_pps_basis: "pace"` and `packets_estimated: 40`.

| Place | When the basis is `pace` | Screenshot |
| --- | --- | --- |
| Top strip | "tempo zadane ≈1 380 / 2 000 pps"; the tooltip says it is the nmap pace (--min-rate/--max-rate) of running stages, not a measurement | `rate-3-strip-pace` |
| Run page gauge | "≈ 1 840 pps" with a "tempo zadane" tag (same tooltip); with `measured` the tag reads "zmierzone". "Pakiety prób ≈ 102 958" with a tooltip that names the estimated part | `rate-1-run-page-pace` |
| Dashboard run panel | same gauge, plus "pakiety prób ≈ 126 510" | `rate-2-dashboard-pace` |

The over-cap warning stays (more than 5 % above the run cap); with the basis `pace` its text says "Tempo zadane przekracza limit…", with `measured` "Zmierzone tempo przekracza limit…". The label "Wysłane pakiety" is now "Pakiety prób", because `packets_sent` counts probe packets only.

Contract note: the task named `packets_estimated` a bool; in `internal/model` it is an `int64` (the estimated part of `packets_sent`). The UI shows "≈" when it is above 0.

`DefectDojoSettings.link_url` is now served; section 11, row 9 has the check and the screenshots.

## 13. Juror's-eye review (nine fixes, feature freeze)

Stacks: `czui` (real lab data: full runs of profile 4 and profile 2, re-probes #131, #142, #148, #149, gone services) and a fresh `czuiv` stack for the time machine (full runs #1, #2, #4, ad-hoc run #3 on 10.66.10.10-11). "Before" shots come from a worktree at `ea8f5c7` served against the same API. All shots are in `web/screenshots/lab/jury-*`.

| # | Point | What changed | Shots (before → after) |
| --- | --- | --- | --- |
| 1 | Dashboard compares full runs | The headline and the deltas use the last two **full** runs of one profile (`lib/headline.ts`: `isFullRun`, `lastFullPair`). A partial run (reprobe, ad-hoc, manual entry, import) gets its own line: "Ostatnio: sprawdzenie 512 adresów (#148, …); przebieg częściowy, bez porównania." The delta tooltip names the two runs. Data comes from the real `GET /runs` list and run `stats`; no API change was needed. Compare and the runs list follow the same rule: Compare defaults to the last full pair and marks partial runs; the runs list shows "sprawdzenie N adresów · opcje profilu …" for partial runs. | jury-1-dashboard, jury-9a-compare, jury-9b-runs |
| 2 | Live first | Services default to "otwarte"; "wszystkie" sorts live above gone (`-state,` prefix), gone rows stay muted. Hosts default to "bez nieaktywnych" (`up,unstable,expected-offline,unknown`). "Najciekawsze usługi" already reads open services only. | jury-2-services, jury-6b-hosts |
| 3 | Findings grouped | Default status "otwarte" (new, triaged). Default view "Według rodzaju": one row per kind ("… · 18 usług", status summary, top severity, max interest), expandable to the addresses; a row opens the drawer. "Lista" keeps the old table with bulk actions. Resolved ones sit behind the status filter. | jury-3-findings, jury-3b-findings-open-group (after only), jury-m-findings |
| 4 | Probe strip legend | Cells carry only colour plus title and aria-label; one legend row below (date range, "odpowiedź / brak odpowiedzi / kolejne skany"). Checked with 1 and 3 observations (few-observations strip), and 8+ and 60 observations (weekly map plus recent-probe bar, unchanged and already label-free). | jury-4-host-1obs, jury-4-host-3obs, jury-m-host-strip |
| 5 | Translated fields | `lib/fields.ts` (`fieldLabel`, `fieldValue`) used by Changes, Compare, service field history and the time machine: "stan: brak → otwarta", "stan hosta: aktywny → bez odpowiedzi", "wersja nginx". The raw field stays in the title attribute. | jury-5-changes, jury-9a-compare |
| 6 | Hosts without open ports | The ports column says "brak otwartych portów" (title: "odpowiada, brak otwartych portów w profilu"); technology stays blank. | jury-6-hosts-noports |
| 7 | Time machine | One run: "Wehikuł czasu potrzebuje co najmniej dwóch przebiegów" with a link to the run. Up to 5 runs: the diff panel first, the lists directly under it, the map last. Partial runs are thin marks; ← → step over them, Shift + ← → includes them. On the newest run the diff says "Od tamtej pory inwentarz się nie zmienił." | jury-7a-time-one-run, jury-7b-time-few-runs, jury-7c-time-earlier-run (after only) |
| 8 | Local MAC | `lib/mac.ts` `isLocalMac` (second hex digit 2/6/A/E): the UI shows "adres lokalny" instead of the vendor. | jury-8-mac |
| 9 | Crawl as viewer and analyst, PL and EN | 21 pages, no console errors. Fixed: "p_alive" column header → "Obecność"; "(host_missing)/(host_gone)" in profile help; Hosts subtitle; plurals ("1 naruszenie", "1 wiersz", "1 user"); permission group headings ("targets" → "Cele i zakresy"); Compare default pair; partial runs in the runs list. | jury-9a-compare, jury-9b-runs, jury-9c-roles |

Backend items (not changed, UI only):

- The MAC vendor comes from the API as is. The lookup gives local addresses a vendor (e.g. `66:21:C4:…` on host 192 → "Applicon", the OUI of `00:00:40`). It should skip locally administered addresses.
- Finding, signature and rule titles and descriptions are Polish in the EN view (server data).
- The host tag filter lists the internal tag "new-exposure".
- A dashboard field `last_full_run` / `prev_full_run` would save the extra `GET /runs` call; the UI does not need it.
- Auto-resolve flapping on the frequent profile (section 11, item 4) is still open.
