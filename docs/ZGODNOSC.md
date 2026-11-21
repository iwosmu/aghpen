# Zgodność z treścią zadania

Skrót dla jury. Każde wymaganie z `docs/PROBLEM_DEFINITION.md`, każdy z 12 punktów weryfikacji i każde kryterium oceny: co robi Czujka, gdzie to zobaczyć i jaki jest dowód.

| | |
| --- | --- |
| Stan na | 2026-11-21 wieczorem, gałąź `iwosmu/agh-orchestrated-kickoff`, po poprawkach z audytu jury (znikający host, webhook alertów, porty szablonu) |
| Liczby | Jedno źródło: [`docs/WYNIKI.md`](WYNIKI.md). Ten plik je cytuje albo do nich odsyła. |
| Metoda | czytanie kodu i tras API (`internal/api/server.go`, `internal/wire/wire.go`, `cmd/czujka/reprobe.go`), nazwy testów w kodzie, zapis testu e2e `e2e/full/transcript.txt` (100 ze 100), raport interfejsu na laboratorium `web/REPORT-LAB.md` i zrzuty `web/screenshots/lab/` |
| Nie jest źródłem | poprzednia wersja tego pliku; każdy status sprawdzono od nowa |
| Publiczna instancja | `https://czujka.dev` z laboratorium 70 hostów; konto do odczytu dla jury: dane logowania w zgłoszeniu |

Numery zrzutów (`40`, `47` …) to pliki w `web/screenshots/lab/`. „Krok N” to krok w `e2e/full/transcript.txt`.

## Statusy

| Status | Znaczenie | Wierszy |
| --- | --- | --- |
| **udowodnione** | Działa w produkcie. Dowód z działającego produktu: zapis testu e2e, raport z laboratorium, zrzut na prawdziwych danych albo test integracyjny przez REST API na PostgreSQL z `pg_tde`. | 85 |
| **gotowe** | Działa w produkcie i ma testy, ale brak zapisu przebiegu na prawdziwych danych albo dowód jest do powtórzenia. | 9 |
| **częściowe** | Działa tylko część wymagania albo brakuje pomiaru, o który pyta wymaganie. | 2 |
| **brak** | Nie ma tego w kodzie. | 0 |

Razem 96 wierszy.

## Najsłabsze miejsca

1. **Skala (kryterium 30%).** Pomiar trafności i tempa dotyczy laboratorium /16 z 70 hostami (`docs/WYNIKI.md`). Czas dla większej sieci to ekstrapolacja z tego pomiaru, nie pomiar.
2. **Liczby pakietów: zmierzone na łączu.** `e2e/full/transcript.txt` (100 ze 100) przechwytuje ruch z filtrem źródła (`src host <adres Czujki> or arp`), który widzi pakiety wysyłane przez nmapa przez surowe gniazdo; stare liczby z przechwytywania `-Q out` są usunięte. Przebieg 1: 13 147 surowych pakietów nmapa na łączu (licznik silnika 13 246), najwięcej 641 na sekundę przy limicie 800, średnio 234,7/s. Przebieg 2: 13 125 pakietów, najwięcej 641/s, średnio 305,2/s. Wszystkie wysłane pakiety: najwięcej 643/s. Stop awaryjny: wywołanie trwało 0,09 s, po 1 s nie działał żaden proces nmap, po stopie wyszło 5 pakietów IP w ciągu 0,01 s i żaden później niż 1 s. Retro-hunt: 0 pakietów od Czujki. Pozostaje: pomiar dotyczy sieci /22 z 9 hostami; tempo na /16 opisuje `docs/WYNIKI.md`.
3. **IPv6, UDP, tokeny API.** Zakresy CIDR IPv6 są odrzucane, a nazwy domen dają tylko adresy IPv4 (rekordy A). UDP działa bez wykrywania wersji. REST API wymaga sesji i tokenu CSRF; nie ma tokenów API (`docs/API.md`, „API with curl”).

## 1. Wymagania z rozdziału 2 zadania

| Nr | Wymaganie | Co robi Czujka | Gdzie to zobaczyć | Dowód | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Wczytanie listy adresów IP, zakresów CIDR lub domen | Tekst (jeden cel w wierszu) i plik CSV/JSON. IPv4, CIDR, zakres `a-b`, domena, pojedynczy IPv6. Podgląd przed zapisem: poprawne, błędne z numerem wiersza, duplikaty, liczba adresów, adresy wyłączone polityką. | ekran „Cele”; kreator, krok 2 | `TestParseTarget`, `TestParseTextAndFile`; kreator na laboratorium: 4 poprawne, 1 błędny wiersz, 1024 adresy (`web/screenshots/lab/21-wizard-2-network-preview.png`); e2e: zakres /22 → 1022 adresy (`e2e/full/transcript.txt` krok 5) | **udowodnione** |
| 1a | – domena jako cel | Silnik rozwiązuje domenę na adresy IPv4 (rekordy A) i przekazuje nazwę do kolektora HTTP (nagłówek `Host`, SNI). | ekran „Cele”; plik `lab/ground-truth/targets-domains.txt` (73 nazwy) | `TestExpandResolvesAndExcludes` (`internal/targets`); brak zapisu przebiegu z domenami | **gotowe** |
| 1b | – IPv6 | Pojedynczy adres IPv6 tak. Zakres CIDR IPv6 jest odrzucany z komunikatem „zakresy CIDR IPv6 nie są obsługiwane”. | ekran „Cele” (błąd przy `2001:db8::/64`) | `internal/targets/parse.go` | **częściowe** |
| 2 | Bezpieczny skan discovery | Wykrycie hostów → porty → usługi (`nmap -sV`) → HTTP/TLS → sygnatury. Bez skryptów NSE, logowania i danych aplikacji. Szczegóły: `docs/BEZPIECZENSTWO.md`. | „Przebiegi skanów” → przebieg | e2e: dwa pełne przebiegi przez REST API (`e2e/full/transcript.txt` kroki 6 i 11); /16 laboratorium: 65 535 adresów (`web/screenshots/lab/47-run-completed-pl-dark-1440.png`) | **udowodnione** |
| 2a | – wielowątkowo, narzędziami jak nmap, które integrują się z DefectDojo | Równoległe procesy nmap z jednym wspólnym budżetem pakietów. Bez nmap: własny prober TCP. Eksport przebiegu jako nmap XML („Nmap Scan” w DefectDojo). | `/healthz` → `probe.mode: nmap-raw`; „Import / eksport” | `TestParallelismAndBudget`, `TestBudgetSplit`; e2e: XML przebiegu 2 importuje się z powrotem: 10 hostów, 9 usług (krok 13) | **udowodnione** |
| 2b | – sprawdzenie czasu trwania skanu | Estymata przed startem (adresy, pakiety, czas, czy mieści się w oknie). W trakcie: czas aktywny, ETA, tempo, czas każdej podgrupy. | okno „Uruchom skan”, kreator krok 5, strona przebiegu | e2e: estymata 1022 adresy, 122 s (krok 5); /16: czas pełnego skanu w `docs/WYNIKI.md` (bramka laboratorium). Słabość: estymata zakłada 5 % aktywnych adresów, a wczesne ETA bywa dalekie (`web/REPORT-LAB.md` §7) | **udowodnione** |
| 2c | – podział adresów na optymalne podgrupy | Bloki /24 łączone w grupy robocze; rozmiar grupy idzie za zmierzonym tempem (EWMA, cel 30 s); bloki ze znanymi hostami idą pierwsze. | strona przebiegu: tabela „Podgrupy adresów”, mapa | `TestSizerFollowsMeasuredSpeed`, `TestBuildUnitsDensityFirst`; /16: 256 bloków w 108 grupach, 78 łączonych (zrzut `47`) | **udowodnione** |
| 3 | Wykrycie aktywnych hostów | Z surowymi gniazdami: ICMP echo i timestamp, TCP SYN/ACK, ARP. Bez nich: połączenie TCP. Host bez ICMP jest wykrywany sondą TCP albo ARP. | „Hosty” | e2e: 9 z 9 hostów, także host odrzucający ICMP (krok 7); /16: 67 z 67 hostów, bez fałszywych (`docs/WYNIKI.md`). Szczegóły: wiersz 7.1 | **udowodnione** |
| 4 | Identyfikacja podstawowych usług | `nmap -sV` na otwartych portach: usługa, produkt, wersja, CPE. | „Usługi”, szczegóły usługi | e2e: nginx 1.24.0, OpenSSH 9.7, Redis 7.4.12, MariaDB 11.8.9, Grafana (krok 7) | **udowodnione** |
| 4a | – usługi UDP | Profil może włączyć UDP, tylko dla niegroźnych zapytań: 53, 123, 137, 161, 500, 1900, 5353. | „Profile skanów” → sekcja UDP | `TestUDPPorts`, `TestUDPArgsAreSafe`, `TestSNMPProbe` (`internal/probe/udp_test.go`); brak zapisu przebiegu UDP na laboratorium | **gotowe** |
| 5a | Informacje HTTP/HTTPS: tytuł strony | `title` z HTML | szczegóły usługi, sekcja HTTP | e2e: `title=WordPress › Installation`, `Grafana`, `Welcome to nginx!` (krok 7); zrzut `44` | **udowodnione** |
| 5b | – kod odpowiedzi HTTP | `status` | szczegóły usługi | zrzut `44` (Status 200); e2e: zmiana kodu wykrywana jako zmiana (`internal/analyze`) | **udowodnione** |
| 5c | – nagłówki | do 100 nagłówków, `Server`, `X-Powered-By` | szczegóły usługi, „Nagłówki odpowiedzi” | zrzut `44`; e2e: znaleziska `interesting-header` (krok 7) | **udowodnione** |
| 5d | – ciasteczka | nazwa, domena, ścieżka, flagi `Secure`/`HttpOnly`/`SameSite`, długość i skrót wartości; wartość szyfrowana, w zapisanych nagłówkach zamaskowana (`MaskSetCookie`) | szczegóły usługi; test sygnatury | zrzut `51` (`infokiosk_sid`, `Secure=false; HttpOnly=true`); `TestRedirectChainAndCookies`; `internal/httpfp/fetch.go` | **udowodnione** |
| 5e | – certyfikat TLS | wersja, szyfr, CN, SAN, wystawca, daty, SHA-256, samopodpisany, wygasły, niezgodność nazwy | szczegóły usługi, sekcja TLS | e2e: `self-signed-cert` i `cert-expiring` na 10.91.3.50:9443 (krok 7); `TestTLSSelfSigned`, `TestTLSExpiredCertificate` | **udowodnione** |
| 5f | – przekierowania | każdy krok zapisany; kolektor idzie dalej tylko w obrębie tego samego hosta i portu | szczegóły usługi | `TestRedirectChainAndCookies`, `TestOffHostRedirectNotFollowed`, `TestRedirectLoopStops`; hosty `redir-chain`, `redir-ext` w laboratorium bez osobnego zapisu | **gotowe** |
| 6 | Wykrywanie technologii: CMS, framework, serwer aplikacyjny, IoT | 398 sygnatur w YAML: panele 87, IoT 53, serwery 47, CMS 41, usługi 37, frameworki 36, systemy uczelniane 32, staging 24, nagłówki 22, ciasteczka 12, narzędzia laboratoryjne 7. Pewność: noisy-OR dowodów. | „Usługi” → „Technologie i dowody”; „Sygnatury” | e2e: WordPress, Grafana, nginx z wersją, PHP, Apache (krok 7); zrzut `44`: WordPress 6.9.4, Apache 2.4.67, PHP 8.3.31; pulpit: MikroTik RouterOS (zrzut `40`) | **udowodnione** |
| 7 | Rozpoznanie: staging, panel administracyjny | Klasy `staging`, `admin-panel` (oraz `login`, `dev-tool`, `database` …). | pulpit: liczniki „Panele administracyjne”, „Środowiska testowe” | e2e: `staging` na 10.91.3.50, `admin-panel` na WordPress (krok 7); pulpit /16: 9 paneli, 9 środowisk (zrzut `40`) | **udowodnione** |
| 8 | Porównanie wyników między przebiegami | Różnica dowolnych dwóch przebiegów: hosty, usługi, technologie, tytuł, status, certyfikat, nagłówki, ciasteczka, treść, przekierowania. | „Zmiany” → „Porównaj dwa skany”; `GET /diff?from=&to=` | e2e: `GET /diff` przebiegów 1 i 2 → 8 zmian (krok 11) | **udowodnione** |
| 9 | Oznaczenie nowych, znikających i zmienionych usług | 23 rodzaje zmian z wagą i flagą „oczekiwana”, potwierdzanie zmian. Host, który przestał odpowiadać, pokazuje swoje usługi jako „nie odpowiada (niepotwierdzone)”; sonda potwierdzająca rozstrzyga w ciągu minut. | „Zmiany”; zdanie na pulpicie | e2e: `host_new`, `service_new`, `service_changed`, `tech_version`, `title_changed`, `host_unstable` (krok 11); laboratorium `t0`→`t1`: zrzut `45` | **udowodnione** |
| 10 | Własne sygnatury detekcyjne | Język YAML, 14 typów reguł, walidator trybu bezpiecznego, retro-hunt po zapisanych danych, edytor z walidacją na żywo, import pliku, sygnatura z przykładu. | „Sygnatury” → edytor; usługa → „Zaproponuj sygnaturę” | e2e: sygnatura przez API, retro-hunt 3 trafienia, dopasowanie w przebiegu 2, import pliku (kroki 9, 11, 14); zrzut `51` | **udowodnione** |
| 11 | Formularz do wprowadzania danych | Formularz celów, formularz ręcznego hosta z usługami, formularz znaleziska. | „Cele”; „Hosty” → „Dodaj host ręcznie”; „Znaleziska” | `web/REPORT-LAB.md` §3: host 10.66.250.15 utworzony, przebieg „wpis ręczny”, 3 zmiany; zrzuty `60`, `61` | **udowodnione** |
| 11a | – dane z formularza przetwarzane tak samo | Ręczny host i import wyników idą przez ten sam zapis i tę samą analizę co skan, jako osobny przebieg. | „Przebiegi skanów”: przebieg `manual-entry` albo `import` | `internal/wire/analysis.go`; e2e: import JSON/CSV/XML tworzy przebiegi 3–5 (krok 13) | **udowodnione** |
| 11b | – ręcznie oraz plik CSV i/lub JSON | Cele: ręcznie, CSV, JSON, próba na sucho. Wyniki: nmap XML, JSON, CSV. Znaleziska: DefectDojo Generic Findings JSON/CSV i eksport Czujki. | „Import / eksport” | e2e: import trzech formatów (krok 13); ponowny import znalezisk: 180 zaktualizowanych, 0 duplikatów (`web/REPORT-LAB.md` §3, zrzut `63`) | **udowodnione** |
| 12 | RBAC z tworzeniem i obsługą różnych ról | 22 uprawnienia; administrator tworzy własne role; nikt nie nada uprawnienia, którego sam nie ma; ostatniego administratora nie da się usunąć. | „Administracja” → role i użytkownicy | `TestRBACMatrixCSRFAndAudit` (REST API na PostgreSQL z `pg_tde`), `TestRBACRules`; `internal/model/types.go` (22 stałe `Perm…`) | **udowodnione** |
| 13 | Cztery konkretne role | Administrator = Administracja; Edytor = Dodawanie, usuwanie, modyfikacja; Analityk = Modyfikacja i odczyt; Obserwator = Odczyt. | „Administracja”; drugie okno z kontem roli „Obserwator” | `internal/auth/roles.go`; `TestBuiltinRolesMatchTheArchitecture`; konto do odczytu dla jury na `https://czujka.dev` (dane logowania w zgłoszeniu) | **udowodnione** |
| 14 | Edycja niezależna od stanu skanu, zachowana przy kolejnych skanach | Edycja pola skanera zapisuje nadpisanie z wartością skanera obok; pola analityka nigdy nie są nadpisywane; edycja działa także w trakcie przebiegu. Przebieg ma edytowalną notatkę i etykietę. | szczegóły hosta i usługi (ołówek przy polu), „Znaleziska” | e2e: notatka i tagi usługi oraz akceptacja znaleziska przetrwały drugi skan (krok 11); `TestEditsSurviveScans`; notatka przebiegu: `web/REPORT-LAB.md` §3 | **udowodnione** |
| 15 | Czytelny interfejs dla każdej roli i główny dashboard | Pulpit zaczyna się zdaniem „co się zmieniło od ostatniego skanu”, potem liczby, trwający skan, listy. Polski i angielski, motyw ciemny i jasny, telefon i komputer; kontrolki niedostępne dla roli nie są rysowane. | „Pulpit” | zrzuty `40`–`47` na danych laboratorium /16 (`web/REPORT-LAB.md` §6) | **udowodnione** |
| 16 | Szyfrowanie w spoczynku dla pól wrażliwych | Warstwa 1: PostgreSQL 17 z `pg_tde`, wszystkie tabele i WAL. Warstwa 2: AES-256-GCM dla klucza API DefectDojo, adresu i klucza webhooka, wartości ciasteczek, fragmentów treści, dowodów, notatek; rotacja klucza. | `/healthz` → `"tde":true` | e2e: `"tde":true` (krok 2); `TestMigrateIsIdempotentAndTablesAreEncrypted`, `TestIngestInventoryAndFieldEncryption`, `TestKeyRotation` | **udowodnione** |
| 16a | – kopia zapasowa | `czujka backup` zapisuje `pg_dump` w jednym archiwum szyfrowanym AES-256-GCM kluczem pochodnym od klucza głównego; zmienione albo ucięte archiwum się nie otwiera. `czujka restore` odmawia innego klucza i sprawdza liczby wierszy, klucz i `pg_tde`. | `docker compose -f deploy/docker-compose.yml exec czujka czujka backup` | `cmd/czujka/backup.go`; `deploy/e2e/backup-restore.sh` (dwa czyste stosy, dane A odtworzone w B; 11 kontroli według commitu `692f8da`, przebiegu nie powtórzyłem) | **gotowe** |

## 2. Akapit o module sygnatur

| Punkt | Co robi Czujka | Gdzie to zobaczyć | Dowód | Status |
| --- | --- | --- | --- | --- |
| obecność konkretnego nagłówka | reguła `header` (`exists`, `contains`, `regex`) | „Sygnatury” → edytor | sygnatura `lab-infokiosk`: `X-InfoKiosk-Node` (zrzut `51`); `TestEveryRuleType` | **udowodnione** |
| konkretna nazwa ciasteczka | reguła `cookie` (nazwa, wzorzec, flagi); dowód bez wartości | test sygnatury | zrzut `51` (`infokiosk_sid`); `TestCookieEvidenceHidesTheValue` | **udowodnione** |
| hash favicony | reguła `favicon` (`mmh3` jak w Shodan, `sha256`) | szczegóły usługi: „Favicon (mmh3)” | `TestMurmur3Vectors`, `TestFaviconFallbackAndSoftNotFound`; przykład z laboratorium w `docs/REGULY.md` §10 (InfoKiosk, `mmh3: 1990289189`) | **gotowe** |
| charakterystyczny fragment HTML | reguły `body`, `title`, `meta` | edytor sygnatur | e2e: własna sygnatura po treści strony, 3 trafienia (krok 9) | **udowodnione** |
| ścieżka `/login`, `/admin`, `/version` bez logowania | reguła `path`: tylko GET bez treści i danych logowania; najwyżej 5 ścieżek na sygnaturę, 8 na usługę z polityki | test sygnatury: „Dodatkowe żądania GET na usługę” | zrzut `51` (`/kiosk/status`); `TestCheckPath`, `TestSafePath`, `TestMethodGuard` | **udowodnione** |
| wykrycie wersji w stopce | reguły `version` z grupą wyrażenia regularnego | „Technologie i dowody” | zrzut `44`: WordPress 6.9.4 z `meta generator`; `TestVersionExtraction` | **udowodnione** |
| fingerprint popularnego CMS-a | `signatures/cms.yaml` (41 sygnatur) | „Usługi”, filtr technologii | e2e: WordPress (krok 7); zrzut `44` | **udowodnione** |
| ostrożność: brak eksploatacji | Walidator odrzuca: metodę inną niż GET/HEAD, treść żądania, nagłówki, dane logowania, ładunki, inny host, `..`, kodowanie procentowe, ścieżki zmieniające stan. | import pliku sygnatur | e2e: sygnatura z `POST` i `body` odrzucona z numerem wiersza (krok 14); `TestValidatorRejectsUnsafeSignatures` | **udowodnione** |

## 3. Akapit o wielowątkowości, oknach i podgrupach

| Punkt | Co robi Czujka | Gdzie to zobaczyć | Dowód | Status |
| --- | --- | --- | --- | --- |
| Skan wielowątkowy z użyciem nmap | wiersz 2a | strona przebiegu: kilka podgrup „skanowany” naraz | zrzut `03`; `TestParallelismAndBudget` | **udowodnione** |
| Narzędzia integrujące się z DefectDojo | Eksport przebiegu jako nmap XML i znalezisk jako Generic Findings Import; wysyłka przez API z kluczem znaleziska (drugi eksport aktualizuje); synchronizacja statusu. | „Znaleziska” → „Eksport do DefectDojo”; „Integracje” | pliki: e2e krok 13, `web/REPORT-LAB.md` §3 (eksport 274,5 kB, ponowny import bez duplikatów); z ekranu produktu do żywego DefectDojo 3.5.202: eksport zaznaczonych i filtrowanych, ponowny eksport bez duplikatów, mapowanie zakresów, pull statusów, przebieg jako „Nmap Scan” z ponownym importem, błędy i awaria w trakcie (`web/REPORT-LAB.md` §11, zrzuty `dojo-*`). Do tego webhook alertów po każdym przebiegu (Slack, Mattermost, podpis HMAC; `docs/API.md`, „Alert webhook”) | **udowodnione** |
| Sprawdzanie czasu trwania skanu | wiersz 2b | okno „Uruchom skan” | e2e krok 5 | **udowodnione** |
| Podział na optymalne podgrupy zależnie od szybkości | wiersz 2c | tabela „Podgrupy adresów” | zrzut `47` | **udowodnione** |
| Przedziały czasowe uruchomienia | Okna tygodniowe (dni, od–do, przez północ, strefa czasowa), siatka 7 × 24 do malowania. | „Profile skanów” → okna; kreator krok 4 | e2e krok 16; `TestInWindowSimpleAndMidnight`, `TestWindowsAcrossDaylightSaving` | **udowodnione** |
| Częstotliwość | Cron (5 pól) albo odstęp w minutach; harmonogram uruchamia przebiegi sam. | „Przebiegi skanów”: wyzwalacz `schedule` | `web/REPORT-LAB.md` §1: przebiegi z crona `*/2 * * * *`; `TestSchedulerTick` | **udowodnione** |
| Po przekroczeniu okna skan zatrzymany i wznowiony w kolejnym oknie | Silnik nie zaczyna podgrupy, która się nie zmieści; o końcu okna przerywa; harmonogram wznawia w następnym oknie; w przebiegu częściowym nie ma fałszywych „zniknięć”. | strona przebiegu: „wstrzymany · okno”, potem „wznowiony” | e2e krok 16: pauza 15:02:16, wznowienie 15:04:01, zakończony; zrzuty `32`, `33` | **udowodnione** |

## 4. Minimalny oczekiwany zakres

| Punkt | Co robi Czujka | Gdzie to zobaczyć | Dowód | Status |
| --- | --- | --- | --- | --- |
| import listy hostów lub zakresów | wiersz 1 | „Cele” | wiersz 1 | **udowodnione** |
| import wyników skanów JSON lub CSV | nmap XML, JSON (4 kształty), CSV z tabelą nazw kolumn; błędny wiersz nie przerywa importu | „Import / eksport” | e2e krok 13 | **udowodnione** |
| obsługa dużych zakresów, ponad 10 000 IP | Liczenie adresów bez rozwijania listy, plan w blokach /24, zapis wsadowy. | strona przebiegu /16 | 65 535 adresów w jednym przebiegu (zrzut `47`); `TestCountLargeAndExclusions` | **udowodnione** |
| konfiguracja skanu: okno i częstotliwość | rozdz. 3 | „Profile skanów” | e2e krok 16 | **udowodnione** |
| ograniczanie tempa zapytań | Limit = mniejsza z wartości profilu i polityki. Jeden budżet pakietów dla wszystkich procesów nmap; HTTP: limit globalny i na host. | górny pasek: limit pps; wskaźnik tempa | tcpdump na łączu przy pełnym skanie /16: żadnej sekundy ponad limit + 10% (`docs/WYNIKI.md`, „Tempo i bezpieczeństwo skanowania”); tcpdump w `e2e/full/transcript.txt`: surowe pakiety nmapa najwięcej 641/s przy limicie 800 (kroki 6, 11, 18) | **udowodnione** |
| wykrywanie aktywnych hostów | wiersz 3 | „Hosty” | wiersz 3 | **udowodnione** |
| podstawowa identyfikacja usług | wiersz 4 | „Usługi” | wiersz 4 | **udowodnione** |
| zapis wyników do bazy lub pliku | PostgreSQL: hosty, usługi, obserwacje z historią, zmiany, znaleziska; pliki eksportu | „Hosty”, „Import / eksport” | `TestIngestInventoryAndFieldEncryption`; e2e kroki 7 i 13 | **udowodnione** |
| porównanie dwóch skanów | wiersz 8 | „Porównaj dwa skany” | e2e krok 11 | **udowodnione** |
| dashboard lub raport z najważniejszymi zmianami | Pulpit (wiersz 15) i raport przebiegu HTML (A4) i Markdown | „Pulpit”; przebieg → „Raport” | e2e krok 12 (`report.html` 200, `report.md` 200); zrzut `55` | **udowodnione** |
| eksport wyników do JSON lub CSV | `/export/{hosts,services,findings,changes,signatures}.{json,csv}`, `/export/runs/{id}.{json,csv,xml}`; ochrona przed formułami w CSV; każdy eksport w audycie | przyciski „CSV” / „JSON” nad każdą listą | e2e krok 13 | **udowodnione** |
| rozgraniczenie funkcjonalności na role | wiersze 12–13 | „Administracja” | wiersze 12–13 | **udowodnione** |
| edycja danych skanów, wyników i konfiguracji | wiersz 14; profile, cele, polityka; notatka i etykieta przebiegu | szczegóły hosta, usługi, przebiegu | e2e krok 11; `web/REPORT-LAB.md` §3 | **udowodnione** |
| ochrona danych (szyfrowanie) | wiersz 16 | `/healthz` | wiersz 16 | **udowodnione** |

## 5. Mile widziany dodatkowy zakres

| Punkt | Co robi Czujka | Gdzie to zobaczyć | Dowód | Status |
| --- | --- | --- | --- | --- |
| harmonogram cyklicznych skanów | rozdz. 3 | „Profile skanów” | `web/REPORT-LAB.md` §1 | **udowodnione** |
| wykrywanie różnic zależnych od pory dnia | Histogram 168 godzin tygodnia na host i model Bayesa: brak w porze, w której host zwykle milczy, dostaje status `expected-offline` i nie trafia do alarmów. | szczegóły hosta: „Dostępność w tygodniu”, `p_alive` | `TestStabilityScenarios` (`docs/ALGORYTMY.md` §2.6); e2e: `host_unstable` zamiast „zniknął” (krok 11); rytm na prawdziwym zegarze laboratorium czeka na `lab/story.sh` | **gotowe** |
| ocena „ciekawości” | Punkty 0–100, zawsze z listą powodów. | „Usługi” → „Dlaczego ciekawa” | e2e: `interest=98 why=signature+40 staging+20 …` (krok 7); zrzut `44` | **udowodnione** |
| powtarzanie pomiarów dla hostów niestabilnych | W przebiegu: dodatkowe próby znanego hosta. Po przebiegu: plan ponownych sprawdzeń jednego adresu po 10, 30, 90 min (host z mniej niż 8 obserwacjami: 1, 3, 10 min) albo w godzinie, w której model spodziewa się odpowiedzi; budżet 200 adresów na godzinę; domyślnie włączony. | „Pulpit” i szczegóły hosta: „Plan ponownych sprawdzeń” | e2e: przebieg 2 `retried: 1` (krok 11); `internal/reprobe` (`reprobe_integration_test.go`); e2e krok 11b: zatrzymany host dostał `host_gone` przez przebiegi ponownych sprawdzeń, bez pełnego skanu; znikający host w dwóch skanach: `TestVanishedHostInTwoScans` (`internal/wire`); zrzuty `96`, `97` na laboratorium (plan dla hosta niestabilnego 10.66.70.20) | **udowodnione** |
| moduł HTTP/HTTPS fingerprinting | wiersze 5a–5f | szczegóły usługi | wiersze 5a–5f | **udowodnione** |
| proste wykrywanie CMS-ów lub technologii | wiersz 6 | „Usługi” | wiersz 6 | **udowodnione** |
| grupowanie podobnych usług | Klucz grupy z ikony, szablonu tytułu, technologii, nazw nagłówków i skrótu treści. | `GET /service-groups`; „Usługi” | testy `internal/analyze` (`group.go`) | **gotowe** |
| obsługa tagów | Tagi na celach, hostach, usługach, znaleziskach; filtr; `GET /tags`. | pole „Tagi” w szczegółach | e2e: tag `e2e` na usłudze przetrwał skan (krok 11) | **udowodnione** |
| eksport wybranych obserwacji do DefectDojo | rozdz. 3, wiersz „Narzędzia integrujące się z DefectDojo” | „Znaleziska” → zaznacz → „Eksport do DefectDojo” | jak w rozdz. 3 | **udowodnione** |
| wizualizacja zmian w czasie | Mapa cieplna tygodnia, pasma życia hosta i usług, historia pól usługi, wehikuł czasu (suwak przebiegów), trend na pulpicie, mapa adresów. | szczegóły hosta i usługi; „Wehikuł czasu” | `internal/timeline` (`history_integration_test.go`); sprawdzenia wehikułu w `e2e/full/run.sh` krok 11b; zrzuty `90`, `91`, `92`, `95` na danych laboratorium /16 | **udowodnione** |
| integracja z pasywnymi źródłami danych | Pliki (CSV, JSON, JSON Lines, strefa DNS), odwrotny DNS, crt.sh (domyślnie wyłączone). | „Import / eksport” → źródła pasywne | e2e krok 15; zrzuty `52`–`54` | **udowodnione** |
| (własne) reguły ekspozycji | Reguły w YAML: czego w sieci być nie może albo co musi być; sprawdzane po każdym skanie i imporcie, bez pakietów; 16 reguł startowych. | „Reguły ekspozycji”; znaleziska `policy-violation` | `internal/rules` (`rules_integration_test.go`); próba na sucho 55 ms na 2000 hostach (`docs/REGULY.md` §7); sprawdzenia w `e2e/full/run.sh` krok 11b; zrzut `93`: reguła startowa zgłasza 11 naruszeń na 76 hostach i 117 usługach laboratorium | **udowodnione** |
| (własne) sygnatura z przykładu | Usługa → rzadkie i stałe cechy → walidator → retro-hunt. | usługa → „Zaproponuj sygnaturę” | `internal/sigsuggest` (`proof_integration_test.go`); przykład InfoKiosk w `docs/REGULY.md` §10; zrzut `94`: sygnatura z 10.66.1.10:80 pasuje do przykładu i do żadnej z 116 innych usług | **udowodnione** |

## 6. Wymagania formalne i techniczne

| Punkt | Stan | Gdzie | Status |
| --- | --- | --- | --- |
| Repozytorium kodu źródłowego | to repozytorium; `go build ./...` przechodzi | `README.md` | **udowodnione** |
| Dokumentacja techniczna | spis w `docs/DOKUMENTACJA.md`; wdrożenie, bezpieczeństwo, algorytmy, sygnatury, reguły, integracje, API | `docs/` | **gotowe** |
| Prezentacja do 10 slajdów | 10 slajdów, PDF i HTML. Każdy slajd to jeden obraz z podpisem: tytuł do 8 słów i najwyżej 12 słów poza nim; `docs/slides/build.mjs` pilnuje limitu i wypisuje liczbę słów. Szczegóły są w notatkach do slajdów (`docs/DEMO.md` rozdz. 2). 1 miejsce czeka na pomiar (`DO UZUPEŁNIENIA`, slajd 3): czas przebiegu /16 na silniku po zamrożeniu. | `docs/slides/czujka.pdf` | **częściowe** |
| Działające demo, lokalnie lub w środowisku testowym | Stos startuje jednym poleceniem; laboratorium 70 hostów lokalnie; publiczna instancja `https://czujka.dev` z laboratorium i zaplanowanym skanem. Film 2:09 nagrany skryptem z prawdziwego interfejsu (`docs/demo/record.mjs`): kreator na świeżej instalacji, skan /16 na żywo (fragment w ×8, oznaczony), porównanie dwóch skanów, host niestabilny, wehikuł czasu, reguła, sygnatura z przykładu, stop awaryjny. Pierwsza wersja z lokalnego stosu (21.11.2026); wersja końcowa 22.11 rano na danych z nocy, tym samym poleceniem. Głos lektora nagrywa się osobno (`docs/demo/lektor.txt`). | `docs/demo/czujka-demo.mp4`; `docs/DEMO.md`; `https://czujka.dev` | **udowodnione** |
| Technologie bezpłatne i open-source | Go, PostgreSQL (Percona z `pg_tde`), nmap, chi, pgx, React, Vite. Bez płatnych API. | `go.mod`, `web/package.json` | **udowodnione** |
| Język o niskim zużyciu zasobów | Go; obraz 107 MB (`docker images`, 2026-11-21); najwyżej 90,7 MiB pamięci kontenera w czasie skanów | `e2e/full/transcript.txt` krok 18 | **udowodnione** |

## 7. Dwanaście punktów weryfikowanych przez jury (rozdz. 6)

| Nr | Punkt | Stan | Gdzie to zobaczyć | Dowód | Status |
| --- | --- | --- | --- | --- | --- |
| 7.1 | Poprawność wykrycia aktywnych hostów | Wykrywa hosty także bez ICMP. /16: 67 z 67 hostów, precyzja i czułość 1,000. | „Hosty” | e2e 9 z 9 (krok 7); `docs/WYNIKI.md`, „Wykrywanie w sieci /16” | **udowodnione** |
| 7.2 | Poprawność identyfikacji usług | `nmap -sV`, UDP z listy niegroźnych zapytań. /16: otwarte porty 154 ze 155, nazwy usług 153 ze 155, 0 fałszywych; wersje usług 30 z 32. | „Usługi” | e2e krok 7; `docs/WYNIKI.md` | **udowodnione** |
| 7.3 | Trafność fingerprintingu HTTP/HTTPS | Tytuł, kod, nagłówki, ciasteczka, TLS, przekierowania. /16: tytuły 122 ze 122, nagłówki i ciasteczka 68 z 68, flagi ciasteczek 24 z 24, certyfikaty 12 z 12, favicon 14 z 14. | szczegóły usługi | wiersze 5a–5f; `docs/WYNIKI.md` | **udowodnione** |
| 7.4 | Wykrycie CMS-ów lub technologii | 398 sygnatur, wersje z dowodami. /16: technologie precyzja 0,990, czułość 0,981; wersje technologii 55 z 56. | „Technologie i dowody” | wiersz 6; `docs/WYNIKI.md` | **udowodnione** |
| 7.5 | Ciekawe nagłówki i ciasteczka | `headers.yaml` (22), `cookies.yaml` (12), flagi ciasteczek, zmiany `headers_changed` i `cookies_changed`, reguły ekspozycji na nagłówki i ciasteczka. | „Znaleziska”, filtr `interesting-header` | e2e: znaleziska „HTTPS bez HSTS”, „Wersja oprogramowania w Server” (krok 7); zrzut `51` | **udowodnione** |
| 7.6 | Działanie customowych sygnatur | wiersz 10 | „Sygnatury” | e2e kroki 9, 11, 14 | **udowodnione** |
| 7.7 | Porównanie wyników między skanami | wiersze 8–9 | „Zmiany” | e2e krok 11 | **udowodnione** |
| 7.8 | Hosty niestabilne lub zmieniające odpowiedź | Model 168 godzin, `host_unstable` zamiast fałszywego „zniknął”, plan ponownych sprawdzeń, `host_back`. Hosty `flapper`, `tod-office`, `tod-night` w laboratorium. | szczegóły hosta | e2e krok 11 (`host_unstable`), krok 11b (`host_gone` przez ponowne sprawdzenia); `TestStabilityScenarios`; `TestVanishedHostInTwoScans`; `go run ./e2e/watchunstable` | **udowodnione** |
| 7.9 | Bezpieczeństwo i ostrożność skanera | Tylko GET i HEAD, walidator sygnatur, limity polityki ponad profilem, okna, wykluczenia, dozwolone sieci, stop awaryjny, kontener bez roota. | górny pasek: limit, GET/HEAD, „Stop awaryjny” | e2e: wywołanie stopu 0,09 s, brak procesu nmap po 1 s, po stopie 5 pakietów IP w ciągu 0,01 s i żaden później niż 1 s (tcpdump z filtrem źródła), nowy przebieg odrzucony 409 (krok 17); sygnatura z POST odrzucona (krok 14); proces uid 10001 (krok 2) | **udowodnione** |
| 7.10 | Czytelność dashboardu lub raportu | Pulpit ze zdaniem na górze, raport przebiegu A4. | „Pulpit”, „Raport” | zrzuty `40`–`47`, `55`; e2e krok 12 | **udowodnione** |
| 7.11 | Import oraz export danych | Cele, wyniki (XML, JSON, CSV), znaleziska, sygnatury; eksport każdej listy i przebiegu. | „Import / eksport” | e2e kroki 13–14; `web/REPORT-LAB.md` §3 | **udowodnione** |
| 7.12 | Rozgraniczenie funkcjonalności między role | wiersze 12–13 | konto „Obserwator” | `TestRBACMatrixCSRFAndAudit` | **udowodnione** |

## 8. Kryteria oceny

| Waga | Kryterium | Stan | Status |
| --- | --- | --- | --- |
| 30% | Skuteczność discovery i identyfikacji usług w dużej infrastrukturze | /16 (65 535 adresów) w jednym przebiegu przy limicie 1000 pps: hosty 67 z 67, otwarte porty 154 ze 155, technologie precyzja 0,990 i czułość 0,981. Czas skanu i pełne tabele: `docs/WYNIKI.md`. | **udowodnione** |
| 15% | Zmiany w czasie, niestabilne hosty, raportowanie | Zmiany i porównanie udowodnione w e2e. Ponowne sprawdzenia, wehikuł czasu i reguły udowodnione zrzutami na laboratorium (`90`–`97`). Model rytmu: testy i scenariusze w `docs/ALGORYTMY.md` §2.6. Host zatrzymany między dwoma skanami: drugi skan pokazuje go z usługami jako „nie odpowiada (niepotwierdzone)”, sonda potwierdzająca daje „nieaktywny” po około minucie (`docs/ALGORYTMY.md` §3.4). | **udowodnione** |
| 20% | Jakość techniczna, dokumentacja, prezentacja, uruchomienie, import/eksport, DefectDojo | Jedno polecenie (czas: `docs/WYNIKI.md`, „Uruchomienie”); e2e 100 ze 100; czujka.dev działa; import i eksport udowodnione; DefectDojo z ekranu produktu udowodnione (`web/REPORT-LAB.md` §11); webhook alertów; prezentacja z 1 miejscem na czas /16. | **gotowe** |
| 15% | Bezpieczeństwo, kontrola intensywności, przejrzystość dashboardu | Mechanizmy udowodnione (krok 14, 16, 17); pulpit na danych laboratorium. Tempo na łączu zmierzone przy pełnym skanie /16: żadnej sekundy ponad limit + 10% (`docs/WYNIKI.md`); po stopie żaden pakiet IP później niż 1 s. | **udowodnione** |
| 10% | Fingerprinting, technologie, CMS, nagłówki, ciasteczka, sygnatury | 398 sygnatur, wersje z dowodami, własne sygnatury i sygnatura z przykładu; trafność technologii w `docs/WYNIKI.md`. | **udowodnione** |
| 10% | Role i zabezpieczenie danych | 4 role i własne role, 22 uprawnienia, `pg_tde` i AES-256-GCM, audyt. Kopia zapasowa szyfrowana (`czujka backup`). | **udowodnione** |

## 9. Jak powtórzyć sprawdzenie

```sh
go build ./... && go vet ./... && go test -count=1 ./...
make test-integration                    # testy bazy na PostgreSQL z pg_tde (docker)
make e2e-full                            # cały produkt przez REST API, około 15 minut; zapis: e2e/full/transcript.txt
docker compose up -d                     # w katalogu głównym, bez .env
curl -s http://127.0.0.1:8080/healthz    # "engine":true, "tde":true, "probe":{"mode":"nmap-raw"}
```

Laboratorium 70 hostów i stan startowy demo: `docs/DEMO.md` §3. Prawda wzorcowa: `lab/ground-truth/`, ocena: `go run ./e2e/score`.
