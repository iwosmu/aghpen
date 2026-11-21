# Worker report: Czujka web UI

Task `task_e6a0f7c686b3`, dispatch `ctx_487adf6d9725`. Branch `iwosmu/czujka-web`. Feature commit `d01a276`. Not pushed, not merged.

**Read this first:** every screenshot and every runtime check below ran on the dev fixture layer (`VITE_FIXTURES=1`). No real backend existed, so the UI has not run against the real API.

## 1. What I built (all in `web/`)

| Path | Content |
| --- | --- |
| `src/api` | `types.ts` (mirror of `internal/model/types.go`), typed HTTP client, SSE client, TanStack Query hooks |
| `src/session.tsx`, `src/shell` | session, permission checks, layout with navigation rail, top bar with the live run, safety limits and the emergency stop |
| `src/pages` | Login, Dashboard, Runs, RunDetail, Hosts, HostDetail, Services, ServiceDetail, Changes, Compare, Findings, Signatures, SignatureEditor, Targets, Profiles, ProfileEdit, Transfer, Admin |
| `src/viz` | AddressMap (Hilbert curve, one cell per /24), WeekHeatmap (7x24), WindowPicker (paintable 7x24), BarList, TrendRows, ProgressBar, RateGauge. Hand-made SVG |
| `src/ui` | DataTable and FilterBar, Panel/Dialog/Tabs kit, state marks, inline edit, override note with revert, export buttons |
| `src/i18n.ts` | Polish default, English toggle, all strings through `t()` / `plural()` |
| `src/fixtures` | dev-only stand-in for the backend: every endpoint of `docs/API.md`, SSE simulation of a running scan, a university network (399 hosts, 717 services, 6 users) |
| `src/**/*.test.ts` | 14 unit tests: Hilbert layout, time-window conversion, formatters |
| `embed.go`, `noembed.go` | `//go:embed all:dist` behind the `embedui` build tag |
| `README.md` (Polish), `DESIGN.md`, `PRODUCT.md` | run instructions, design system, product context |

## 2. Evidence

Commands ran in `web/` unless a different directory is given.

| Command | Key output |
| --- | --- |
| `npm run typecheck` | `tsc --noEmit`, exit 0 |
| `npm run lint` | `eslint .`, exit 0, no findings |
| `npm test` | `Test Files 3 passed (3)`, `Tests 14 passed (14)` |
| `npm run build` | `181 modules transformed`, `built in 119ms` |
| `grep -rlE "cbi\.example|czujka\.fx|mulberry" dist | wc -l` | `0` (fixtures are absent from the production bundle) |
| repo root: `go build ./... && go vet ./... && go test ./...` | `BUILD_OK`, `VET_OK`, no test files in `cmd/czujka`, `internal/model`, `web` |
| repo root: `go build -tags embedui ./...` | `EMBED_BUILD_OK` |
| `impeccable detect --json src` | `[]` |

Production bundle: main chunk `index-*.js` 353.88 kB (111.04 kB gzip), CSS 43.41 kB (9.16 kB gzip). Largest lazy chunks: Hosts 43.80 kB, Admin 25.14 kB, ProfileEdit 24.82 kB, Dashboard 20.87 kB. All JavaScript: 634.9 kB raw, about 191 kB gzip. `dist` is 908 kB with 10 woff2 font files.

### Screenshots (`web/screenshots/`, 59 files, Playwright, fixture data)

The scripted runs reported no console error and no page error. Document width at 390 px equals the viewport width (no horizontal page scroll).

- Desktop 1440x900, admin: `01-login`, `02-dashboard`, `02b-dashboard-lower`, `03-runs`, `04-run-live`, `05-run-paused-window`, `06-run-map-3x16`, `07-hosts`, `08-host-detail`, `09-host-unstable`, `10-services`, `11-services-groups`, `12-service-detail`, `12b-service-detail-lower`, `13-changes`, `14-compare`, `15-findings`, `16-signatures`, `17-signature-editor`, `18-targets`, `19-profiles`, `20-profile-edit`, `20b-profile-schedule`, `21-transfer`, `22-admin-users`, `23-admin-roles`, `24-admin-audit`, `25-admin-safety`, `26-admin-defectdojo` (each with the suffix `-1440.png`).
- Flows clicked in the browser: `12c-service-override-reverted` (override notes 1 -> 0), `15b-findings-bulk`, `15c-finding-detail`, `15d-findings-defectdojo-export` (2 created, link to test #77), `17b-signature-unsafe` (POST and payload rejected), `17c-signature-retrohunt` (16 matches, 0 packets), `18b-targets-preview`, `18c-targets-file-dry-run` (2 valid, 1 invalid, 1 duplicate), `19b-start-run-estimate`, `20c-profile-window-weekend`, `26b-admin-defectdojo-test`, `27-emergency-stop-confirm`, `27b-emergency-stop-active`.
- Role-aware rendering, same pages as viewer: `40-viewer-dashboard`, `41-viewer-findings`, `42-viewer-host-detail`, `43-viewer-run-live`, `44-viewer-signatures`, `45-viewer-admin-roles`, `46-viewer-targets`. Compare `15-findings` with `41-viewer-findings`, `08-host-detail` with `42-viewer-host-detail`, `23-admin-roles` with `45-viewer-admin-roles`: the viewer has no emergency stop, no checkboxes, no edit controls, fewer navigation entries and admin tabs, and a "read only" line.
- Themes and language: `28-dashboard-light`, `29-run-live-light`, `30-dashboard-en`.
- Mobile 390x844: `50-dashboard-390`, `50b-dashboard-lower-390`, `51-hosts-390`, `52-service-detail-390`, `52b-service-detail-lower-390`, `53-findings-390`, `54-run-live-390`.

I looked at each image. Fixed after inspection: a render loop on the findings page, table cells out of line with the page gutter, overflow in the services, changes, findings and chunk tables, wrapped cron text, grid tracks that widened on mobile.

## 3. Changes to `internal/model`

None. I touched no file outside `web/`.

## 4. Screen status, gaps, next steps

Complete on fixture data (rendered, inspected at 1440x900): all twelve areas of the brief.

Partial or not verified:

- **No real backend.** Field names follow `docs/API.md` and `internal/model/types.go`, but no request reached a real server. SSE event names and payloads are the most likely place for a mismatch.
- Written but not clicked in the scripted pass: login form submit (the script set the fixture session directly), run pause/resume/cancel, change acknowledge (single and bulk), manual finding form submit, results import upload, profile save, user and role edits, safety policy save.
- Mobile: the four required pages and the run detail are inspected. The other pages use the same table-to-list pattern but I did not inspect them. Wide tables inside panels (cookies, observation history) scroll sideways at 390 px.
- Light theme: two pages inspected. English: one page inspected. Fixture content stays Polish in English mode.
- Accessibility: focus rings, keyboard handlers and ARIA labels are in the code. I ran no axe audit and did not walk every keyboard path.
- The traffic budget on the profile form reflects the saved profile, not unsaved edits. The UI says so.
- Small visual defects left: two class chips stack in the host services table and break the 30 px row; the compare view shows one duplicated row that comes from fixture data.
- Tests cover pure logic only. There are no component or end-to-end tests.
- `package.json` has a `postinstall` step that writes `node_modules/go.mod`. Reason: the npm package `flatted` ships Go sources, and without the file `go build ./...` and `go test ./...` walk into `web/node_modules`.
- Impeccable v4.10.0 is available (`npx impeccable update`). I did not run the update.

Next steps: run the UI against the real server and fix contract mismatches; add an e2e smoke test in `e2e/`; run an axe audit; inspect the remaining pages at 390 px.

## 5. Branch and commit

Branch `iwosmu/czujka-web`. Feature commit `d01a276`. This report is the next commit on the same branch.
