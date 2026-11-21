# Zgodność z treścią zadania

Macierz śledzenia wymagań z `docs/PROBLEM_DEFINITION.md`. Dokument mówi, co działa w scalonym kodzie, a co jeszcze nie.

| | |
| --- | --- |
| Stan na | 2026-11-21, gałąź `iwosmu/agh-orchestrated-kickoff`, commit `6886182` |
| Metoda | czytanie kodu, `go test ./...`, testy integracyjne na PostgreSQL z `pg_tde`, uruchomienie `docker compose` i wywołania `curl`, jeden przebieg `scanprobe` na `127.0.0.1` |
| Nie jest źródłem | raporty autorów modułów i inne dokumenty; każde twierdzenie sprawdzono w kodzie albo w działającym programie |

## Statusy

| Status | Znaczenie |
| --- | --- |
| **gotowe** | Kod jest scalony. Działanie sprawdzone testem albo wywołaniem na działającym programie. |
| **w integracji** | Biblioteka jest scalona i ma testy. Binarka `czujka` jeszcze jej nie wywołuje: odpowiednia trasa API odpowiada `501 not_wired` albo nie istnieje. |
| **brak** | W scalonym kodzie nie ma nic. |

## Najważniejszy fakt

Wszystkie moduły skanowania i analizy istnieją jako przetestowane biblioteki. Funkcja `wire` w `cmd/czujka/wire.go` zwraca jednak pustą strukturę. Dlatego w binarce produktu **nie działa jeszcze**: start skanu, estymata, harmonogram, import wyników, eksport nmap XML, porównanie przebiegów, analiza po przebiegu, walidacja i dodawanie sygnatur, retro-hunt, DefectDojo. Sprawdzone na działającym stosie:

```text
POST /api/v1/runs                     -> 501 {"code":"not_wired","message":"the scan engine is not wired"}
POST /api/v1/profiles/1/estimate      -> 501 not_wired
POST /api/v1/import/results           -> 501 not_wired
POST /api/v1/signatures/validate      -> 501 not_wired
POST /api/v1/settings/defectdojo/test -> 501 not_wired
GET  /api/v1/signatures?limit=1       -> 200 {"items":[],"total":0}
GET  /healthz                         -> {"engine":false,"tde":true,...}
```

Test `TestNotWiredRoutesAnswer501` (`internal/api`) pilnuje, że niepodłączony moduł odpowiada 501, a nie udaje wyniku.

W binarce produktu działa dziś: logowanie, role i użytkownicy, zakresy i cele (formularz i plik), profile skanów, polityka bezpieczeństwa i awaryjne zatrzymanie (flaga), edycja hostów, usług i obserwacji, eksport CSV/JSON, dziennik audytu, szyfrowanie, interfejs WWW (serwowany z obrazu).

## 1. Wymagania z rozdziału 2 zadania

| Nr | Wymaganie | Co robi Czujka | Gdzie | Dowód | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Wczytanie listy adresów IP, zakresów CIDR lub domen | Tekst (jeden cel na wiersz albo lista po przecinku) i plik CSV/JSON. Rozpoznaje IPv4, IPv6 (pojedynczy adres), CIDR, zakres `a-b` i `a.b.c.d-N`, domenę. Podgląd przed zapisem: poprawne, błędne z numerem wiersza i powodem, duplikaty, liczba adresów, adresy wyłączone polityką. | `internal/api/targets_parse.go`, `handlers_targets.go`; `POST /scopes/{id}/targets`, `/targets/preview`, `/scopes/{id}/targets/import`; strona „Cele” | `TestParseTarget`, `TestParseTextAndFile`, `TestExcludedAndBlocks`; curl: 6 wartości → 4 poprawne, 3 błędy, 1037 adresów; plik JSON → 4097 adresów | **gotowe** |
| 1 | – domena jako cel skanu | Silnik rozwiązuje domenę na adresy IPv4 (rekordy A) i przekazuje nazwę do kolektora HTTP. Rozwiązuje też domeny z listy wyłączeń. | `internal/targets/expand.go` | `TestExpandResolvesAndExcludes` | **w integracji** |
| 2 | Bezpieczny skan discovery | Silnik: wykrycie hostów → skan portów → wykrycie usług → HTTP/TLS → sygnatury. Nie wysyła skryptów NSE, loginów ani danych aplikacji. Szczegóły: `docs/BEZPIECZENSTWO.md`. | `internal/scan`, `internal/probe`; `POST /runs` | `TestNmapArgs`, `TestRunDiscoversHostsRetriesAndReports`; `scanprobe -targets 127.0.0.1 -ports 18480,22` → 1 host, 1 usługa `http`; w produkcie `POST /runs` → 501 | **w integracji** |
| 2a | Wielowątkowy skan narzędziami jak nmap, które integrują się z DefectDojo | Pula pracowników, równoległe procesy nmap z jednym wspólnym budżetem pakietów. Bez nmap: własny prober TCP w Go. Wynik przebiegu można wyeksportować jako nmap XML dla DefectDojo („Nmap Scan”). | `internal/scan/engine.go`, `limits.go`, `internal/probe/nmap.go`, `native.go`; `internal/interchange` | `TestParallelismAndBudget`, `TestBudgetSplit`, `TestNativeProber`; nmap 7.97 w obrazie produktu (sprawdzone); eksport XML w produkcie → 501 | **w integracji** |
| 2b | Sprawdzenie czasu trwania skanu | Estymata przed startem (adresy, pakiety, czas, czy mieści się w oknie). W trakcie: czas aktywny, ETA, średnie tempo, czas każdej części. | `scan.Engine.Estimate`, `internal/scan/stats.go`; `POST /profiles/{id}/estimate`, `GET /runs/{id}`, `/runs/{id}/chunks` | `TestEstimate`, `TestStatsKeeper`; w produkcie estymata → 501 | **w integracji** |
| 2c | Podział adresów na optymalne podgrupy | Bloki /24 łączone w części; bloki ze znanymi hostami idą pierwsze. Rozmiar grupy roboczej dopasowuje się do zmierzonego tempa: `następny = clamp(EWMA(rozmiar × cel / pomiar), min, max)`. | `internal/scan/planner.go`; pola `chunking` profilu | `TestSizerFollowsMeasuredSpeed`, `TestBuildUnitsDensityFirst`, `TestAdaptiveGroupsGrowWithSpeed` | **w integracji** |
| 3 | Wykrycie aktywnych hostów | Z surowymi gniazdami: ICMP echo, ICMP timestamp, TCP SYN, TCP ACK, ARP. Bez nich: połączenie TCP. Host blokujący ICMP jest wykrywany sondą TCP. | `internal/probe/nmap.go` (`DiscoverArgs`), `native.go` | `TestParseXMLDiscovery`, `TestNormalizeDiscovery`; przebieg na 127.0.0.1 | **w integracji** |
| 4 | Identyfikacja podstawowych usług | `nmap -sV` tylko na otwartych portach: usługa, produkt, wersja, CPE, pewność. Tylko TCP. | `internal/probe/nmap.go` (`ServiceArgs`), `nmapxml.go` | `TestParseXMLService`, `TestIdentifyBanner`; 127.0.0.1:18480 → `http`, „Golang net/http server” | **w integracji** |
| 4 | – usługi UDP (DNS, SNMP, NTP) | Brak skanu UDP. | – | `grep -i udp internal/probe internal/scan` nie zwraca nic | **brak** |
| 5 | Informacje o usługach HTTP/HTTPS | Kolektor wysyła `GET /` na adres IP z nagłówkiem `Host` i SNI. | `internal/httpfp`; `cmd/fpprobe` | niżej | **w integracji** |
| 5a | – tytuł strony | `title` | `httpfp/html.go` | `TestBasicFingerprint` | **w integracji** |
| 5b | – kod odpowiedzi HTTP | `status` | `httpfp/collector.go` | `TestBasicFingerprint` | **w integracji** |
| 5c | – nagłówki | do 100 nagłówków, `server`, `powered_by` | `httpfp/fetch.go` (`cleanHeaders`) | `TestBasicFingerprint` | **w integracji** |
| 5d | – ciasteczka | nazwa, domena, ścieżka, flagi `Secure`/`HttpOnly`/`SameSite`, długość i skrót wartości | `httpfp/fetch.go` (`cookiesOf`) | `TestRedirectChainAndCookies` | **w integracji** |
| 5e | – certyfikat TLS | wersja, szyfr, CN, SAN, wystawca, daty, SHA-256, samopodpisany, wygasły, niezgodność nazwy | `httpfp/tls.go` | `TestTLSSelfSigned`, `TestTLSExpiredCertificate` | **w integracji** |
| 5f | – przekierowania | każdy krok zapisany; kolektor idzie dalej tylko w obrębie tego samego hosta i portu | `httpfp/collector.go` (`root`) | `TestRedirectChainAndCookies`, `TestOffHostRedirectNotFollowed`, `TestRedirectLoopStops` | **w integracji** |
| 6 | Proste wykrywanie technologii: CMS, framework, serwer aplikacyjny, IoT | 386 sygnatur wbudowanych. Kategorie: `cms` 66, `framework` 27, `app-server` 19, `web-server` 23, `iot` 40 i inne. Pewność liczona jako noisy-OR. | `internal/sig`, `signatures/*.yaml` | `TestBuiltinLibraryIsValid`, `TestBuiltinDetections`, `TestConfidenceIsNoisyOR`; w produkcie `GET /signatures` → 0 pozycji | **w integracji** |
| 7 | Rozpoznanie: środowisko testowe lub staging, panel administracyjny | Klasy usług `staging` i `admin-panel` (oraz `login`, `dev-tool`, `database` …). Pliki `environment.yaml` (24 sygnatury) i `panels.yaml` (87). | `internal/sig/classify.go` | `TestClassifier`, `TestCategoryGivesClasses` | **w integracji** |
| 8 | Porównanie wyników między przebiegami | Różnica dowolnych dwóch przebiegów: hosty, usługi, technologie, tytuł, status, certyfikat, nagłówki, ciasteczka, treść, przekierowania, klasy. | `internal/analyze/diff.go`; `GET /diff?from=&to=`; strona „Porównanie” | testy `internal/analyze`; w produkcie `GET /diff` → 501 | **w integracji** |
| 9 | Oznaczenie nowych, znikających i zmienionych usług | Zmiany `service_new`, `service_gone`, `service_changed` (i 15 innych rodzajów) z wagą i flagą „oczekiwana”. Lista zmian z potwierdzaniem. | `internal/analyze/diff.go`; tabela `changes`; `GET /changes`, `POST /changes/ack` | `TestChangesSignaturesTags` (zapis i odczyt); nic jeszcze nie wywołuje analizy po przebiegu (`runner.Options.Analyzer` jest `nil`) | **w integracji** |
| 10 | Własne sygnatury detekcyjne | Własny język YAML: 14 typów reguł, walidator trybu bezpiecznego, retro-hunt na zapisanych obserwacjach bez wysyłania pakietów. Edytor w UI. | `internal/sig/dsl.go`, `safety.go`, `retro.go`; `POST /signatures`, `/signatures/validate`, `/signatures/retrohunt` | `TestValidatorRejectsUnsafeSignatures`, `TestBriefExampleIsValid`, `TestRetroHunt`, `TestHotReloadEnableDisable`; w produkcie trasy → 501 | **w integracji** |
| 11 | Formularz do wprowadzania danych | Formularz celów (tekst) z podglądem. Formularz ręcznej obserwacji (`POST /findings`). | strony „Cele”, „Obserwacje”; `handlers_targets.go`, `handlers_inventory.go` (`createFinding`) | curl jak w wierszu 1 | **gotowe** (cele, obserwacje) |
| 11a | – dane z formularza przetwarzane tak samo | Cele z formularza i z pliku idą tą samą ścieżką (`preview` → `saveTargets`) i do tego samego planu skanu. Wyniki z importu wchodzą przez `ResultSink.OnHost`, tak jak wyniki silnika. | `handlers_targets.go`, `runner.Import` | `TestImport` (`internal/runner`) | **gotowe** (cele); **w integracji** (wyniki) |
| 11b | – wprowadzanie ręczne oraz plik CSV i/lub JSON | Cele: ręcznie, CSV, JSON, z próbą na sucho (`dry_run`). Wyniki skanu: plik nmap XML, JSON, CSV. | `/scopes/{id}/targets/import`, `/import/results` | curl: CSV na sucho → 2 poprawne, 1 błąd; JSON → 201; import wyników → 501 | **gotowe** (cele); **w integracji** (wyniki) |
| 11c | – ręczne dodanie hosta lub usługi do wyników | Nie ma formularza ani trasy. Wynik można dodać tylko plikiem. | – | brak `POST /hosts` i `POST /services` w `internal/api/server.go` | **brak** |
| 12 | RBAC z tworzeniem i obsługą różnych ról | 22 uprawnienia. Administrator tworzy własne role z listy uprawnień. Nikt nie nada uprawnienia, którego sam nie ma. Role wbudowane są tylko do odczytu. Ostatniego administratora nie da się usunąć. | `internal/auth`; `/roles`, `/users`, `/permissions`; strona „Administracja” | `TestRBACMatrixCSRFAndAudit`, `TestRBACRules`; curl: `POST /roles` → 201 (rola „Audytor”) | **gotowe** |
| 13 | Cztery konkretne role | `admin` = Administracja; `editor` = Dodawanie, usuwanie, modyfikacja; `analyst` = Modyfikacja i odczyt; `viewer` = Odczyt. Tabela uprawnień: `docs/BEZPIECZENSTWO.md`. | `internal/auth/roles.go` | `TestBuiltinRolesMatchTheArchitecture`; curl jako `viewer`: `POST` celu → 403, eksport → 403, `GET /users` → 403 | **gotowe** |
| 14 | Edycja wprowadzonych wartości niezależnie od stanu skanu, zachowana przy kolejnych skanach | Edycja pola obserwowanego przez skaner zapisuje nadpisanie: wartość analityka, wartość skanera, kto i kiedy. Kolejny skan aktualizuje tylko wartość skanera. `null` cofa nadpisanie. Pola analityka (notatka, tagi, etykieta, właściciel, krytyczność, status obserwacji) nie są nigdy zapisywane przez skan. Edycja działa w osobnej transakcji, także podczas przebiegu. | `internal/store/inventory.go` (`applyPatch`), `ingest.go` (`czujka_observed`); `PATCH /hosts/{id}`, `/services/{id}`, `/findings/{id}`, `/targets/{id}`, `/profiles/{id}` | `TestEditsSurviveScans`, `TestInventoryEditsCookiesAndExport` (na PostgreSQL z `pg_tde`) | **gotowe** |
| 14 | – zakres pól do edycji | Host: nazwy, system, etykieta, właściciel, krytyczność, tagi, notatka. Usługa: nazwa, produkt, wersja, klasy, tagi, notatka. Obserwacja: tytuł, opis, waga, status, tagi, przypisanie, notatka. Nie da się edytować: stanu portu, tytułu strony, listy technologii, rekordu przebiegu. | `hostPatch`, `servicePatch` w `internal/store` | kod | **gotowe** (z ograniczeniem) |
| 15 | Czytelny interfejs dla każdej roli i główny dashboard | 18 stron, polski i angielski, widok zależny od uprawnień. Dashboard: liczby główne, najważniejsze obserwacje, ostatnie zmiany, niestabilne hosty, wygasające certyfikaty. | `web/`; `GET /dashboard` | Obraz serwuje UI (`GET /` → 200 HTML). `GET /dashboard` → 200. Zrzuty w `web/screenshots/` powstały na **danych przykładowych** (`VITE_FIXTURES=1`), nie na prawdziwym serwerze. | **w integracji** |
| 16 | Baza z szyfrowaniem w spoczynku dla pól wrażliwych | Warstwa 1: PostgreSQL 17 z `pg_tde`, wszystkie 21 tabel w `tde_heap`, szyfrowany WAL. Warstwa 2: AES-256-GCM dla 6 kolumn (klucz API DefectDojo, wartości ciasteczek, fragmenty treści, dowody, notatki). | `deploy/db`, `internal/crypto`, `internal/store/rotate.go` | `TestMigrateIsIdempotentAndTablesAreEncrypted`, `TestIngestInventoryAndFieldEncryption`, `TestKeyRotation`; `/healthz`: `tables 21, encrypted 21, wal_encrypted true`; w zrzucie `pg_dump` klucz API jest szyfrogramem | **gotowe** |
| 16 | – wyjątek | Surowy nagłówek `Set-Cookie` jest zapisywany razem z innymi nagłówkami. Chroni go tylko warstwa 1 i widzi go każdy z prawem odczytu wyników. | `httpfp/fetch.go` (`cleanHeaders`), `store/inventory.go` (`splitSecrets`) | kod: `splitSecrets` nie obejmuje nagłówków | **brak** (luka) |

## 2. Akapit o module sygnatur

Wymaganie: sygnatury służą do bezpiecznej detekcji cech, nie do eksploatacji.

| Przykład z zadania | Reguła w Czujce | Dowód | Status |
| --- | --- | --- | --- |
| obecność konkretnego nagłówka | `header` (`exists`, `contains`, `regex`) | `TestEveryRuleType` | **w integracji** |
| konkretna nazwa ciasteczka | `cookie` (nazwa, wzorzec nazwy, flagi); dowód nie zawiera wartości | `TestCookieEvidenceHidesTheValue` | **w integracji** |
| hash favicony | `favicon` (`mmh3` w stylu Shodan, `sha256`) | `TestMurmur3Vectors`, `TestFaviconFallbackAndSoftNotFound` | **w integracji** |
| charakterystyczny fragment HTML | `body`, `title`, `meta` | `TestEveryRuleType` | **w integracji** |
| ścieżka `/login`, `/admin`, `/version` bez prób logowania | `path`: tylko `GET` bez treści i danych logowania; najwyżej 5 ścieżek na sygnaturę | `TestCheckPath`, `TestSafePath`, `TestMethodGuard` | **w integracji** |
| wykrycie wersji w stopce | reguły `version` z grupą wyrażenia regularnego | `TestVersionExtraction`, `TestCleanVersion` | **w integracji** |
| fingerprint popularnego CMS-a | `signatures/cms.yaml` (41 sygnatur) | `TestBuiltinDetections` | **w integracji** |
| ostrożność: brak eksploatacji | Walidator odrzuca: metodę inną niż GET/HEAD, treść żądania, nagłówki, dane logowania, ładunki, inny host, `..`, kodowanie procentowe, pliki ukryte, ścieżki zmieniające stan, kopie i klucze. | `TestValidatorRejectsUnsafeSignatures`, `TestRetroHuntRejectsUnsafeSignature` | **w integracji** |

## 3. Akapit o wielowątkowości, oknach i podgrupach

| Zdanie z zadania | Co robi Czujka | Dowód | Status |
| --- | --- | --- | --- |
| Skan wielowątkowy z użyciem nmap | wiersz 2a | `TestParallelismAndBudget` | **w integracji** |
| Narzędzia integrujące się z DefectDojo | nmap XML → „Nmap Scan”; obserwacje → „Generic Findings Import” | sprawdzone na DefectDojo 3.5.202 (`docs/INTEGRACJE.md` §4); w produkcie → 501 | **w integracji** |
| Sprawdzanie czasu trwania skanu | wiersz 2b | `TestEstimate` | **w integracji** |
| Podział na optymalne podgrupy zależnie od szybkości | wiersz 2c | `TestSizerFollowsMeasuredSpeed` | **w integracji** |
| Ustawianie przedziałów czasowych uruchomienia | Profil ma okna (dni tygodnia, od–do, przez północ, strefa czasowa). Zapis i walidacja działają. | curl: `POST /profiles` z oknem pn–pt 22:00–06:00 → 201; `TestInWindowSimpleAndMidnight`, `TestWindowsAcrossDaylightSaving` | **gotowe** (konfiguracja) |
| Ustawianie częstotliwości | Profil ma cron (5 pól) albo odstęp w minutach. Harmonogram istnieje jako biblioteka, ale nikt go nie uruchamia: `next_run_at` pozostaje `null`. | `TestCron`, `TestSchedulerTick`; curl: profil z cronem → `"next_run_at":null` | **gotowe** (konfiguracja); **w integracji** (uruchamianie) |
| Po przekroczeniu okna skan zatrzymany i wznowiony w kolejnym oknie | Silnik nie zaczyna części, która nie zmieści się przed końcem okna. O końcu okna przerywa i odkłada resztę. Menedżer przebiegów zapisuje `paused / window_closed` i czas wznowienia. Wznowienie (`ResumeDue`) nie ma jeszcze wywołującego. | `TestWindowGuardDoesNotStartWhatCannotFit`, `TestWindowPauseThenResume` (`internal/scan`), `TestWindowClosedFailureAndNotWired` (`internal/runner`) | **w integracji** |

## 4. Minimalny oczekiwany zakres

| Punkt | Co robi Czujka | Dowód | Status |
| --- | --- | --- | --- |
| import listy hostów lub zakresów | wiersz 1 | curl | **gotowe** |
| import wyników skanów w formie JSON lub CSV | Importer nmap XML, JSON (4 kształty), CSV z tabelą nazw kolumn; błędny wiersz nie przerywa importu. | testy `internal/interchange`; w produkcie → 501 | **w integracji** |
| obsługa dużych zakresów, ponad 10 000 IP | Liczenie adresów bez rozwijania listy (/8 w czasie stałym). Plan w blokach /24. Zapis wsadowy po 250 hostów. | `TestCountLargeAndExclusions`; curl: /20 → 4096 adresów; `make bench` (10 000 hostów × 3 usługi) nie był uruchomiony w tym audycie | **w integracji** |
| konfiguracja skanu: okno czasowe i częstotliwość | rozdz. 3 | curl | **gotowe** (konfiguracja) |
| ograniczanie tempa zapytań | Limit = mniejsza z wartości profilu i polityki. Pakiety: jeden budżet dzielony między procesy nmap (`--min-rate` = `--max-rate`). HTTP: limit globalny i na host. | `TestEffectiveLimits`, `TestBudgetSplit`, `TestLimiterRate`, `TestProfilesSafetyAndValidation` | **w integracji** (egzekwowanie); **gotowe** (polityka) |
| wykrywanie aktywnych hostów | wiersz 3 | – | **w integracji** |
| podstawowa identyfikacja usług | wiersz 4 | – | **w integracji** |
| zapis wyników do bazy lub pliku | PostgreSQL: hosty, usługi, obserwacje z historią, zmiany, obserwacje analityczne. | `TestIngestInventoryAndFieldEncryption`, `TestRunsChunksAndProfiles` | **gotowe** |
| porównanie dwóch skanów | wiersz 8 | – | **w integracji** |
| dashboard lub raport pokazujący najważniejsze zmiany | Dashboard: wiersz 15. Raport z przebiegu w HTML (A4) i Markdown: biblioteka bez trasy API. | `docs/samples/raport-przyklad.html`; testy `internal/report` | **w integracji** |
| eksport wyników do JSON lub CSV | `GET /export/{hosts,services,findings,changes,signatures}.{json,csv}` i `/export/runs/{id}.{json,csv}`. Strumieniowo. Ochrona przed formułami w CSV. Każdy eksport trafia do audytu. | `TestInventoryEditsCookiesAndExport`, `TestMergePatchAndCSVSafe`; curl: `/export/hosts.csv` → 200 | **gotowe** |
| rozgraniczenie funkcjonalności na role | wiersze 12–13 | – | **gotowe** |
| edycja danych istniejących skanów, wyników i konfiguracji | Wyniki i konfiguracja: wiersz 14. Rekord przebiegu nie ma pól do edycji (tylko wstrzymaj, wznów, anuluj). | – | **gotowe** (wyniki, konfiguracja); **brak** (rekord przebiegu) |
| ochrona danych z wykonanych skanów (szyfrowanie) | wiersz 16 | – | **gotowe** |

## 5. Mile widziany dodatkowy zakres

| Punkt | Co robi Czujka | Dowód | Status |
| --- | --- | --- | --- |
| harmonogram cyklicznych skanów | Cron i odstęp, okna, `Scheduler.Tick`. Brak adaptera `sched.Backend` w API. | `TestSchedulerTick`, `TestNextRunAndNextStart` | **w integracji** |
| wykrywanie różnic zależnych od pory dnia | Histogram 168 kubełków (godzina tygodnia) na host, zapisywany przy każdym wyniku. Model Bayesa nadaje status `expected-offline`. | `TestHourBucket` (zapis); testy `internal/analyze`; `docs/ALGORYTMY.md` §2 | **gotowe** (zbieranie danych); **w integracji** (model) |
| ocena „ciekawości” | Punkty 0–100 z listą powodów. | testy `internal/analyze`; `docs/ALGORYTMY.md` §5 | **w integracji** |
| powtarzanie pomiarów dla hostów niestabilnych | Znany host, który nie odpowiada, dostaje dodatkowe próby z rosnącą przerwą; ostatnia to połączenie TCP na znane porty. | `TestRunDiscoversHostsRetriesAndReports` | **w integracji** |
| moduł HTTP/HTTPS fingerprinting | wiersz 5 | – | **w integracji** |
| proste wykrywanie CMS-ów lub technologii | wiersz 6 | – | **w integracji** |
| grupowanie podobnych usług | Klucz grupy z ikony, szablonu tytułu, technologii, nazw nagłówków i skrótu treści. | testy `internal/analyze`; `GET /service-groups` | **w integracji** |
| obsługa tagów | Tagi na celach, hostach, usługach, obserwacjach; filtr `tag`; `GET /tags`. | `TestChangesSignaturesTags` | **gotowe** |
| eksport wybranych obserwacji do DefectDojo | Wybrane obserwacje jako findings z endpointami; drugi eksport nie tworzy duplikatów. | `docs/INTEGRACJE.md` §4 (żywa instancja 3.5.202); w produkcie → 501 | **w integracji** |
| wizualizacja zmian w czasie | Trend na dashboardzie, mapa adresów (krzywa Hilberta), mapa cieplna tygodnia. | zrzuty na danych przykładowych | **w integracji** |
| integracja z pasywnymi źródłami danych | Pliki (CSV, JSON, JSON Lines, strefa DNS), odwrotny DNS, crt.sh (domyślnie wyłączone). Bez trasy API i ekranu. | testy `internal/passive`; `docs/INTEGRACJE.md` §3 | **w integracji** |

## 6. Wymagania formalne i techniczne

| Punkt | Stan | Status |
| --- | --- | --- |
| Repozytorium kodu źródłowego | to repozytorium | **gotowe** |
| Dokumentacja techniczna | `docs/DOKUMENTACJA.md` (spis) | **gotowe** |
| Prezentacja do 10 slajdów | W repozytorium nie ma pliku prezentacji. | **brak** |
| Działające demo | Stos startuje jednym poleceniem (sprawdzone). Bez podłączonego silnika demo nie pokaże skanu. Nie ma scenariusza demo. | **w integracji** |
| Technologie bezpłatne i open-source | Go, PostgreSQL (dystrybucja Percona z `pg_tde`), nmap, chi, pgx, React, Vite. Bez płatnych API. | **gotowe** |
| Język o niskim zużyciu zasobów | Go; jedna statyczna binarka; obraz 72 MB; proces `czujka` w spoczynku 42 MiB RAM (pomiar `docker stats`) | **gotowe** |

## 7. Dwanaście punktów weryfikowanych przez jury (rozdz. 6)

| Nr | Punkt | Stan w scalonym kodzie | Status |
| --- | --- | --- | --- |
| 1 | Poprawność wykrycia aktywnych hostów | Silnik jako biblioteka. W scalonym kodzie nie ma pomiaru precyzji i czułości względem wyników referencyjnych. | **w integracji** |
| 2 | Poprawność identyfikacji usług | `nmap -sV`, tylko TCP. Brak UDP. | **w integracji** |
| 3 | Trafność fingerprintingu HTTP/HTTPS | Kolektor z 20 testami na lokalnych serwerach. | **w integracji** |
| 4 | Wykrycie CMS-ów lub technologii | 386 sygnatur; część oparta na dokumentacji produktów, bez sprawdzenia na żywej instancji (`docs/SIGNATURES.md` §12). | **w integracji** |
| 5 | Ciekawe nagłówki i ciasteczka | `headers.yaml` (20), `cookies.yaml` (11), flagi ciasteczek, zmiany `headers_changed` i `cookies_changed`. | **w integracji** |
| 6 | Działanie customowych sygnatur | Język i walidator gotowe; trasy API → 501. Format przykładowych sygnatur organizatora nieznany. | **w integracji** |
| 7 | Porównanie wyników między skanami | wiersz 8 | **w integracji** |
| 8 | Hosty niestabilne lub zmieniające odpowiedź | Powtórki w silniku, model dostępności, flaga „oczekiwana” zmiana. | **w integracji** |
| 9 | Bezpieczeństwo i ostrożność skanera | Polityka i awaryjne zatrzymanie w API: gotowe. Limity w silniku: biblioteka. | **gotowe** (polityka); **w integracji** (silnik) |
| 10 | Czytelność dashboardu lub raportu | UI sprawdzone na danych przykładowych. Raport: przykład w `docs/samples/`. | **w integracji** |
| 11 | Import oraz eksport danych | Import celów i eksport CSV/JSON: gotowe. Import wyników i eksport XML: 501. Import obserwacji z pliku: brak. | **gotowe** (częściowo) |
| 12 | Rozgraniczenie funkcjonalności między role | wiersze 12–13 | **gotowe** |

## 8. Kryteria oceny

| Waga | Kryterium | Ocena stanu |
| --- | --- | --- |
| 30% | Skuteczność discovery i identyfikacji usług | Silnik działa jako biblioteka i narzędzie `scanprobe`. Produkt go nie wywołuje. Brak UDP. |
| 20% | Jakość techniczna, dokumentacja, prezentacja, uruchomienie, import/eksport, DefectDojo | Start jednym poleceniem: sprawdzony. Dokumentacja: jest. Import wyników, XML i DefectDojo: biblioteki, 501 w produkcie. Prezentacja: brak. |
| 15% | Zmiany w czasie, niestabilne hosty, raportowanie | Algorytmy z testami i pomiarami. Analiza po przebiegu niepodłączona. |
| 15% | Bezpieczeństwo, kontrola intensywności, dashboard | Polityka, awaryjne zatrzymanie, tryb bezpieczny sygnatur: gotowe albo przetestowane. Dashboard niesprawdzony na prawdziwych danych. |
| 10% | Fingerprinting, technologie, CMS, nagłówki, ciasteczka, sygnatury | Kolektor i 386 sygnatur jako biblioteka. W produkcie lista sygnatur jest pusta. |
| 10% | Role i zabezpieczenie danych | Gotowe i sprawdzone. Jedna luka: surowy nagłówek `Set-Cookie`. |

## 9. Jak powtórzyć sprawdzenie

```sh
gofmt -l . ; go build ./... && go vet ./... && go test -count=1 ./...
make test-integration                    # testy bazy na PostgreSQL z pg_tde (docker)
docker compose -f deploy/docker-compose.yml up -d --build --wait
curl -s http://127.0.0.1:8080/healthz    # pole "engine" mówi, czy silnik jest podłączony
go run ./cmd/scanprobe -targets 127.0.0.1 -ports 8080 -pps 50
```

Po podłączeniu modułów w `cmd/czujka/wire.go` statusy **w integracji** trzeba sprawdzić ponownie tymi samymi wywołaniami: trasa nie może odpowiadać 501.
