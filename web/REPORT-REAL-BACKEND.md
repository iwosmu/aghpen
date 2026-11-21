# Worker report: web UI against the real backend

Task `task_ba5d4b9c9519`, branch `iwosmu/czujka-web`, 2026-11-21. All edits are in `web/`. No Go file and no `internal/model` field was changed.

## 1. Stack I ran

| Part | Value |
| --- | --- |
| Database | container `czweb-pg` (image `czujka-db:17`), 127.0.0.1:55472 |
| Server | `czujka serve` on 127.0.0.1:18300, UI served from `web/dist` through `CZUJKA_WEB_DIR` |
| Dev server | Vite on 127.0.0.1:15173 with `CZUJKA_DEV_API=http://127.0.0.1:18300` (`npm run dev:api`) |
| Lab | docker network `czweb-net` (10.213.77.0/24): nginx, Grafana, phpMyAdmin, WordPress, Redis, later adminer and a second nginx |
| DefectDojo | the shared lab instance on 127.0.0.1:18080. It was stopped by its owner during my run, so I started it again and stopped it at the end |

Backend builds. The coordinator branch at my first merge had an empty `wire()`, so import, export and DefectDojo answered 501. I did not edit Go code. I built the server from the integrator branch instead:

- `iwosmu/czujka-core@529fd8c`: every flow in section 3 except the live run. Engine not wired in this build.
- `iwosmu/czujka-core@69919c4`: the live run and SSE checks in section 4. Engine wired (`/healthz` gives `engine:true`, nmap connect mode).

## 2. Real data, product paths only

- Users for editor, analyst and viewer, one custom role and two more users: created in the Admin UI.
- Scope "Laboratorium docker czweb" with targets as text (CIDR, range, domain, two bad lines) and as a CSV file (dry run, then import).
- Five imports of real `nmap -sV -oX` output of my docker network, run from a container on that network. Between the scans I stopped Redis and phpMyAdmin and started adminer and a second nginx. Result: host_new, service_new, host_unstable, host_gone changes and findings.
- Two engine runs of `127.0.0.1` only (own scope and profile, 8 ports). Result: 3 HTTP services with fingerprints, 7 findings from signatures.
- 4 findings exported to the live DefectDojo (ids 63 to 66).

## 3. Flows against the real API

Playwright, real forms, server on 18300. "pass" means the UI did the action and the API state or the next page confirmed it.

| # | Flow | Result |
| --- | --- | --- |
| 1 | Login with the real form, wrong password message | pass |
| 2 | Lockout: 4 wrong passwords give the normal message, the 5th and later give the lockout message (429), the right password stays blocked, login works after the lockout time | pass |
| 3 | Logout, then a protected URL goes to /login | pass |
| 4 | Session expiry (cookie removed): next click goes to /login with the notice, login returns to the same page | pass after fix (the UI looped on `/me` before) |
| 5 | CSRF: request without a token gets 403 with a clear message; stale token (login in a second tab) is refreshed and the edit is repeated once (403 then 200) | pass |
| 6 | Hosts: search, port filter, CIDR filter, sort | pass |
| 7 | Services: search, port filter, sort, groups view | pass |
| 8 | Changes: kind filter, acked filter, acknowledge one, acknowledge two in bulk | pass |
| 9 | Findings: manual finding, detail drawer, status edit, bulk assign, delete | pass after fix (a refetch of the deleted finding gave 404) |
| 10 | Host edit: label, owner, note; OS override shown as "scanner observed / analyst set" with author and time; revert | pass |
| 11 | Service edit: version override, survives reload, revert | pass |
| 12 | Targets: text preview with valid, invalid and excluded counts; CSV dry run; import | pass |
| 13 | Profile create and edit, window preset in the window picker, save | pass |
| 14 | Estimate | pass on 69919c4; calm "funkcja niedostępna" on 529fd8c |
| 15 | Results import (nmap XML), import report | pass |
| 16 | Exports: hosts, services, findings, changes as CSV and JSON, run as nmap XML, view export from a list. 10 files downloaded and opened | pass |
| 17 | Users: create, role select | pass |
| 18 | Roles: custom role in the permission matrix, add a permission, save, log in with it | pass |
| 19 | Audit log: search filter, paging | pass |
| 20 | Safety policy: change pps and exclusions, top bar shows the new limit, target preview counts the excluded address | pass |
| 21 | Emergency stop and release, banner | pass. Start of a scan during the stop was only seen with the engine not wired (501) |
| 22 | DefectDojo: settings save, stored key is never shown again, test with a wrong address, test with the live instance ("Połączono z DefectDojo 3.5.202 jako admin") | pass |
| 23 | DefectDojo export: 4 new findings, links in the list; calm message when DefectDojo is down (502) | pass |
| 24 | Signature editor validation | pass on 69919c4; calm 501 state on 529fd8c |
| 25 | Start a scan from the UI, live run page | pass on 69919c4, see section 4 |
| 26 | Vite dev server through the proxy: login, pages, SSE | pass |

Roles. For each role I compared what the UI shows with direct API calls made from the same session.

| Role | UI | API made anyway |
| --- | --- | --- |
| viewer | no edit, ack, add, start, import or export control; no Import/eksport nav item; Admin shows roles and safety read-only | 403 on users, audit, export, PATCH host, ack, findings, scopes, profiles, runs, safety, signatures |
| analyst | edits hosts, services, findings; can start a scan and export; no add finding, no targets, no profile edit, no import | 200 on export and PATCH host; 403 on findings create and delete, scopes, profiles, users, safety |
| editor | everything except users, roles, audit, safety | 403 only on users and safety |
| custom "Dyżurny zmian" (viewer + results:update) | edit controls on hosts, no add finding, no targets | consistent |

Forbidden request made anyway: while the custom-role user had the host page open, the admin removed `results:update`. The next save showed the toast "Brak uprawnień. Twoja rola nie pozwala na tę operację." and the value did not change. Screenshot `4-role-custom-forbidden-message.png`.

No page crashed in any role. No console error in any run after the fixes.

## 4. SSE

The event names and payloads in `internal/runner/bus.go` and `internal/api` match the client. Verified at runtime:

- `/events`: `run` (analyzing, completed), `change` and `finding` during imports; `run` during engine runs.
- `/runs/{id}/events` on a finished import run: `progress`, then `done`, then the server closes.
- `/runs/{id}/events` on a real engine run of 127.0.0.1 (44 s): 49 `progress`, 1 `host` (`{ip, up, services}`), 1 `chunk`, 1 `done`. The run page went from "w toku" to "zakończony" with no reload: `22-live-run-a.png`, `22-live-run-finished-no-reload.png`.
- Both streams also work through the Vite proxy.

Client change: the run stream closes on `done`. The server closes it too, and a native EventSource would reconnect every 3 s.

Not verified: pause, resume and cancel of a live run from the UI; a run that waits for a time window; a run with many chunks on the Hilbert map; a scheduled run; emergency stop while a scan runs.

## 5. Backend mismatches

Format: route, what it returns, what the contract says.

1. backend: any route with a slice field, for example `GET /profiles` of the seeded default profile. Returns `"windows": null`. The contract type is an array. The UI now turns `null` into `[]` for known array fields (`src/api/normalize.ts`). Before that `/profiles` and `/profiles/1` crashed.
2. backend: `GET /settings/safety` and `GET /dashboard`. Return `updated_at: "0001-01-01T00:00:00Z"` when the policy was never saved. The contract says a timestamp; an absent value should be omitted or null. The UI shows no date for a year before 1971.
3. backend: `GET /hosts/{id}/availability`. Returns `down_after_misses: 0` for a host that is already `down` (2 for other hosts). The contract says the threshold of the model. The UI shows "–" for 0.
4. backend: `POST /roles` with the name "Dyżurny zmian". Returns slug `dy-urny-zmian`. Polish letters should be transliterated.
5. backend: `POST /runs` with the emergency stop active on 529fd8c. Returns 501 `not_wired`. The contract says 409 `emergency_stop`. Not checked again on 69919c4.
6. backend: `POST /import/results` with nmap XML. A known host that is absent from the file does not count as a miss, so a plain second import never produces host_gone. Only `nmap -v` output with explicit `state="down"` hosts does. Those down hosts are also counted as "skipped rows" in the import report (8 skipped), although the analysis uses them.
7. backend: `GET /services` after a host went `down`. The service of that host stays `state: open` (10.213.77.12:80). The contract has `closed`/gone states for this.
8. backend: `GET /runs/{id}/events` for a paused run (code reading, not runtime). Sends `done` and closes. The UI follows the global `run` event to notice the resume.
9. backend: emergency stop pauses runs (CORE_REPORT), the UI dialog says scans are stopped. Wording, not verified at runtime.
10. backend, 529fd8c only: `POST /signatures/validate`, `/signatures/retrohunt`, `POST /signatures`, `POST /profiles/{id}/estimate`, `POST /runs` answered 501. Validate, estimate and runs work on 69919c4. Retro-hunt and signature save were not checked again.

## 6. UI fixes in this task

- Fixture layer: `__CZUJKA_FIXTURES__` is a compile-time constant, true only in the dev server with `VITE_FIXTURES=1`. `vite build` with `VITE_FIXTURES=1` fails. `scripts/check-bundle.mjs` fails the build when a fixture marker is in `dist`. Nothing was removed from `src/fixtures`.
- CSP: the inline theme script moved to `public/boot.js` (the server CSP forbids inline scripts).
- `null` arrays normalised; Go zero time treated as "no date".
- 501 `not_wired`: calm "Funkcja niedostępna w tej instalacji" state in pages, panels and toasts, no retry loop.
- Error messages by status and code: 401, 403, CSRF, 404, 409, emergency stop, 422, 429, 502-504, network.
- Session expiry: no `/me` loop, notice on the login page, return to the same page. Stale CSRF token: one refresh and one retry.
- Login: lockout message for 429.
- Error boundary around each page.
- First run: dashboard with three steps (targets, profile, first scan) and the import alternative; empty lists of hosts, services, changes and findings link to scans and to the import.
- Small: plural for excluded addresses, no "0 wierszy" footer under an empty list, threshold display for a down host.

## 7. Screenshots

`web/screenshots/real/`, 81 files, all from the real server, 1440x900 unless the name starts with `m-` (390x844). I looked at the main pages: dashboard (empty, with data, light, English, mobile), runs, live run, run detail, hosts, host detail (active and gone), services, service detail with HTTP fingerprint, changes, compare, findings, DefectDojo export, targets, profiles, transfer, admin tabs, emergency stop, role views, login states.

Groups: `00*` login states, `01`-`15-empty*` fresh database, `08`-`17` configuration and admin, `20`-`31` real data, `4-role-*` per role, `m-*` mobile.

## 8. Checks

| Check | Result |
| --- | --- |
| `npm run typecheck` | pass |
| `npm run lint` | pass |
| `npm test` | 16 tests pass |
| `npm run build` (tsc, vite build, check-bundle) | pass |
| `VITE_FIXTURES=1 vite build` | fails as designed |
| `go build ./...`, `go vet ./...`, `go test ./...`, `go build -tags embedui ./...` | pass |

## 9. Left

- The flows listed as not verified in section 4.
- English copy was checked on the dashboard only. Mobile was checked on five pages.
- The ten backend items in section 5.
