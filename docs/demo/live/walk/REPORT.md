# Juror walk-through, Part 2 (internal report for the coordinator)

Machine: czlive (dind), state from `live.sh full` (4 template stacks, 2 scans, 2 imports).
Tool: docs/demo/live/walk.mjs (Playwright Chromium, one context at a time).
Roles: viewer, analyst, editor, admin (admin2@czujka.local). Modes: PL 1440 with clicks and forms, EN 1440, PL 390.
Raw records: 178 (scratchpad issues.jsonl). Screenshots below are in docs/demo/live/walk/ and docs/demo/live/proof/.

Good: no visible control answered 403 for any role. Read-only pages show "Tylko odczyt". Forms with wrong input keep the submit button disabled (hosts, findings, scopes, users). No page error and no 5xx.

Ordered by how bad it looks in front of the jury.

1. BACKEND. A manual host entry is diffed like a full scan. Page /hosts, role editor or admin. Steps: "Dodaj host ręcznie", host 172.18.0.1, port 8080, save. Result: run #4 "wpis ręczny" has 31 changes: 30 "Usługa 172.18.0.1:… zniknęła" (all other services of the host) and 1 false "Usługa 172.18.0.1:8080: port otwarty, ale HTTP nie odpowiedział w czasie (zwykle 38 ms)". The dashboard "Recent changes" then lists only these false gone services. A second identical entry (run #5) adds none. Screenshot docs/demo/live/walk/manual-entry-false-gone.png. API: GET /changes?run_id=4.
2. Findings, "Wszystkie do DefectDojo", roles analyst, editor, admin. The dialog says "Do DefectDojo trafią wszystkie znaleziska (78)" and the button says "Eksportuj 0". DefectDojo is not configured; the dialog does not say so. Screenshot docs/demo/live/walk/dojo-export-78-vs-0.png.
3. BACKEND. Disabling a target fails. Page /targets, roles analyst, editor, admin. Steps: switch "Wyłącz cel localhost". Result: 422 "value: not an IP address, CIDR, range or domain". Reproduced with curl: PATCH /api/v1/targets/1 {"enabled":false}. The PATCH validates the value field when it is absent.
4. Profiles, all roles, 1440 px. The table is 2688 px wide in a 1223 px box: the default profile's port list is one line with no break. Tempo, Harmonogram, Ostatni and Uruchom are off screen. Screenshot docs/demo/live/walk/profiles-table-2688px.png.
5. EN mode, all roles: Polish text stays. Finding titles ("Baza danych dostępna z sieci: …", "Panel administracyjny: Gitea – niedokończona instalacja"), the dashboard headline ("including Gitea – niedokończona instalacja"), interest reasons ("+40 Sygnatura: … · +30 Panel administracyjny …"), rule names on /rules ("Panel administracyjny poza siecią zarządzania", "Telnet albo FTP dostępny w sieci"), the default profile name, and "wpis ręczny · manual entry" (both languages side by side) on /runs and /time. Screenshots docs/demo/live/walk/manual-entry-false-gone.png, en-rules-polish.png, en-runs-wpis-reczny.png, en-time-wpis-reczny.png.
6. Administracja at 390 px, all roles: the page is 567 px wide; the tab row runs off screen (the fifth tab shows as "B"). Screenshot docs/demo/live/walk/admin-390-overflow.png.
7. Administracja, users, role admin: the "Konto aktywne" switch disables an account with one click and no confirmation. The walker disabled admin@czujka.local, viewer, analyst and editor this way. The list then shows only "wyłączone". The admin's own switch is disabled with no reason shown. Screenshot docs/demo/live/walk/admin-users-disabled-one-click.png.
8. Hosts, all roles: "Inwentarz jest pusty. Hosty pojawią się po pierwszym skanie" when the only host is inactive and the default filter "bez nieaktywnych" hides it. The text is untrue. Screenshot docs/demo/live/proof/2-hosty.png.
9. Dashboard vs Changes: the dashboard says "nie było jej 1 min 48 s", the change says "wróciła po 1 min". Screenshots proof/1-pulpit.png and proof/1-zmiany.png.
10. Dashboard, same service named two ways: "localhost:8081" in "Most interesting services", "172.18.0.1:8081" in "Top findings". Screenshot docs/demo/live/walk/manual-entry-false-gone.png.
11. Findings: one issue in two rows with different severity. "Panel administracyjny: Gitea – niedokończona instalacja" is "informacyjna"; "Niedokończona instalacja aplikacji · 3 usługi" is "wysoka". Screenshot docs/demo/live/walk/findings-severity-split.png.
12. Host state words differ between two changes of one host: "aktywny → bez odpowiedzi" (host_missing), then "niestabilny → nieaktywny" (host_gone). Screenshot proof/2-zmiany.png.
13. Targets, "Nowy zakres" with an existing name, roles editor, admin: the error shows the database constraint: "Operacja jest sprzeczna z bieżącym stanem. conflict: scopes_name_key". Screenshot docs/demo/live/walk/scope-conflict-raw.png.
14. Polish plural: "1 adresów · 1 cel" and "Razem 1 adresów w 1 zakresie" (web/src/pages/Targets.tsx:242 has no plural()). Screenshot docs/demo/live/walk/targets-1-adresow.png.
15. Import / eksport, role analyst: "Twoja rola nie może importować wyników (uprawnienie results:create)" shows a raw permission slug. Screenshot docs/demo/live/walk/transfer-analyst-permission-slug.png.
16. Native file inputs read "Choose File / No file chosen" on PL pages (/targets, /transfer), also with browser locale pl-PL in Playwright. Screenshot docs/demo/live/walk/targets-1-adresow.png, proof/7-import.png.
17. Profiles, opening the default profile (no scope): POST /profiles/1/estimate answers 422 "profil nie ma zakresu" and the console logs an error. The dialog itself explains it well ("Ten profil nie ma przypisanego zakresu …"). Only console noise.
18. Disabled buttons with no reason: "Dodaj cele", "Wczytaj", "Importuj wyniki", "Importuj znaleziska" (empty input), "Reguła włączona" switch for viewer. Low: the input or the read-only banner explains it.

Not checked: the walker did not submit "Skan wybranych adresów" (it did not find the "Uruchom" button there), and EN at 390 px. "Lista" (/services) and "Według rodzaju" (/findings) showed no effect because they are the active tab: not a bug.
