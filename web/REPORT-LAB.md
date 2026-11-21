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
