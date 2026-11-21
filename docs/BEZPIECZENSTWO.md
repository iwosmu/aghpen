# Bezpieczeństwo Czujki

Dokument ma dwie części: model bezpiecznego skanowania i ochronę danych. Każdy fakt pochodzi z kodu. Stan na 2026-11-22, po poprawkach z przeglądu bezpieczeństwa (rozdz. 4).

Silnik skanu (`internal/scan`, `internal/probe`, `internal/sched`) jest podłączony do binarki `czujka` (`internal/wire`). Tak samo silnik sygnatur i retro-hunt.

## 1. Model bezpiecznego skanowania

Zasada: Czujka wykrywa obecność cech. Nie loguje się, nie wysyła ładunków, nie zgaduje haseł, nie zmienia stanu badanych systemów.

### 1.1 Co skaner wysyła, a czego nigdy

| Etap | Wysyła | Nigdy nie wysyła | Gdzie w kodzie |
| --- | --- | --- | --- |
| Wykrycie hostów | ICMP echo, ICMP timestamp, TCP SYN, TCP ACK, ARP (z surowymi gniazdami) albo połączenie TCP (bez nich) | – | `internal/probe/nmap.go` (`DiscoverArgs`) |
| Skan portów | TCP SYN (`-sS`) albo pełne połączenie TCP (`-sT`) | portów spoza listy dozwolonej polityką | `PortScanArgs`, `probe.EffectivePorts` |
| Skan UDP (opcjonalny, domyślnie wyłączony w profilu) | nieszkodliwe zapytania protokołu tylko na porty z listy: 53 (DNS), 123 (NTP), 137 (NetBIOS), 161 (SNMPv3 engine discovery, własna sonda silnika), 500 (IKE), 1900 (SSDP), 5353 (mDNS). Lista jest dodatkowo filtrowana portami polityki. Wymaga nmap z surowymi gniazdami; bez nich etap jest pomijany z ostrzeżeniem | community string SNMP (sonda nmap dla portu 161 zawiera `public`, dlatego silnik jej nie używa), danych logowania, portów UDP spoza listy | `internal/probe/udp.go` (`UDPServices`, `UDPPorts`), `internal/scan/engine.go` |
| Wykrycie usług | sondy `nmap -sV` tylko na otwarte porty | opcji `--script`, `-sC`, `-A`, `-O` | `ServiceArgs`; test `TestNmapArgs` |
| Wersja brokera AMQP (mały zakres) | 8 bajtów nagłówka protokołu `AMQP 0 0 9 1`, które jako pierwsze wysyła każdy klient AMQP i sonda amqp samego nmap; odczyt ramki `Connection.Start` (produkt, wersja) i zamknięcie połączenia. Tylko na otwarty port 5672 albo port, który tablica portów nmap nazywa `amqp`, i tylko gdy `nmap -sV` nie nazwał go w ciągu 3 s. Wyłączone, gdy profil wyłącza wykrywanie usług | uwierzytelnienia (`Connection.StartOk`), innych ramek, nagłówka na inne porty | `internal/probe/amqp.go` (`AMQPHello`), `internal/scan/pipeline.go` (`quickHost`); testy `TestAMQPHelloReadsTheVersion`, `TestQuickPathReadsTheAMQPVersion` |
| HTTP/TLS | `GET` (i `HEAD`) bez treści | innych metod, treści żądania, danych logowania, ciasteczek z poprzedniej odpowiedzi | `internal/httpfp/fetch.go` (`methodAllowed`, `do`); test `TestMethodGuard` |
| Ścieżki sygnatur | `GET` ścieżek, które przeszły walidator | ścieżek zmieniających stan albo pobierających sekrety (rozdz. 1.5) | `internal/sig/safety.go` (`CheckPath`) |
| Prober zapasowy (bez nmap) | połączenie TCP i bierny odczyt banera | żadnych danych aplikacji | `internal/probe/native.go`; test `TestNativeProber` |

Uwagi:

- `nmap -sV` uruchamia wbudowane skrypty kategorii `version`. Są częścią wykrywania wersji i nmap nie ma przełącznika, który je wyłącza. Czujka nie przekazuje żadnej opcji `--script`.
- Cele trafiają do nmap przez standardowe wejście (`-iL -`) po walidacji wyrażeniem regularnym. Polecenie nie przechodzi przez powłokę.
- Kolektor HTTP łączy się zawsze z adresem IP ze skanu. Nazwa hosta trafia tylko do nagłówka `Host` i SNI (test `TestHostnameIsHostHeaderAndStaysOnTheIP`).
- Kolektor nie odrzuca niepoprawnych certyfikatów (`InsecureSkipVerify`). To celowe: wygasły albo samopodpisany certyfikat jest informacją. Kolektor nie wysyła przy tym żadnych danych.
- Każde żądanie ma nagłówek `User-Agent: Czujka/1.0 (attack surface inventory; safe detection only)`. Administrator badanego hosta widzi, kto pyta. Wartość ustawia polityka.
- **Integracje to nie skanowanie.** Webhook alertów (`POST` z podsumowaniem przebiegu) i eksport do DefectDojo idą tylko na adresy, które administrator wpisał w ustawieniach integracji (uprawnienie `integrations:manage`). Nie trafiają do badanych celów. Reguła „tylko GET i HEAD” dotyczy celów skanowania i się nie zmienia. Webhook: jedna próba, limit 10 s, bez ponowień, bez podążania za przekierowaniem, wynik w dzienniku audytu (`integration.webhook.send`). Adres i klucz HMAC są zaszyfrowane w `settings.secret`. Klient DefectDojo też nie podąża za przekierowaniem. Błąd integracji pokazuje tylko kod odpowiedzi, bez treści odpowiedzi (testy `TestPostFollowsNoRedirectAndEchoesNoBody`, `TestClientFollowsNoRedirectAndEchoesNoBody`). Zapisany klucz API DefectDojo idzie tylko do zapisanego hosta: test połączenia z innym adresem wymaga podania klucza w żądaniu, a zmiana hosta w ustawieniach wymaga nowego klucza (`TestDojoStoredKeyStaysWithItsHost`). Adresy integracji mogą celowo wskazywać sieć wewnętrzną; wpisuje je tylko administrator.

### 1.2 Limity tempa i miejsce egzekwowania

Limit skuteczny to mniejsza z wartości profilu skanu i polityki bezpieczeństwa (`scan.EffectiveLimits`).

| Limit | Profil (domyślnie) | Polityka (domyślnie) | Gdzie egzekwowany |
| --- | --- | --- | --- |
| Pakiety sond na sekundę, wszystkie procesy jednego przebiegu razem | `rate.max_pps` (500) | `max_pps` (1000) | Jeden budżet (`scan.Budget`) na przebieg, dzielony między równoległe procesy nmap tego przebiegu. Każdy proces dostaje udział jako `--min-rate` i `--max-rate`. |
| Żądania HTTP na sekundę, wszystkie hosty razem | `rate.http_rps` (20) | `max_http_rps` (50) | Kubełek żetonów w silniku (`probe.Limiter`). Przed wywołaniem kolektora silnik pobiera tyle żetonów, ile żądań planuje (strona + ścieżki + ikona). |
| Żądania HTTP na sekundę do jednego hosta | – | `max_per_host_rps` (2) | Limiter na host w silniku. |
| Równoległe usługi HTTP na jednym hoście | `rate.per_host_concurrency` (1) | – | Semafor na host. |
| Dodatkowe ścieżki sygnatur na usługę | – | `max_paths_per_host` (8) | Silnik obcina listę ścieżek przed przekazaniem kolektorowi. |
| Przekierowania | `http.max_redirects` (3) | twardy limit 10 | `httpfp` (`root`) |
| Rozmiar pobieranej treści | `http.max_body_bytes` (256 KiB) | – | `httpfp`; limit obejmuje też rozpakowany gzip (test `TestOversizedAndEndlessBodies`) |
| Czas jednego żądania | `http.timeout_ms` (5000) | – | `httpfp` (test `TestSlowServers`) |
| Ikona strony | – | 1 MiB | `httpfp` |

Pomiar z laboratorium silnika (`e2e/engine/REPORT.md`, licznik pakietów interfejsu): przy limicie 500 pakietów na sekundę zmierzono 498–504 w każdej sekundzie. Samo `--max-rate` pilnuje tylko średniej, dlatego silnik ustawia też `--min-rate`. Skutek uboczny: nmap nie zwalnia sam przy utracie pakietów. Tempo trzeba dobrać do sieci.

Znane ograniczenia limitów:

- Sondy wykrywania wersji (`-sV`) idą zwykłymi gniazdami. `--max-rate` ich nie obejmuje; licznik pakietów jest dla nich szacunkiem.
- Limiter HTTP pobiera z góry koszt całego wywołania kolektora (strona, ikona, ścieżki). Żądania wewnątrz jednego wywołania idą bez odstępu między sobą, a przekierowania nie są wliczane.
- Budżet pakietów, limiter HTTP i limiter na host są tworzone dla każdego przebiegu osobno. Kilka przebiegów naraz wysyła razem do N × `max_pps` (przegląd H2, otwarte; należy do silnika).

### 1.3 Polityka bezpieczeństwa

Jedna, globalna. Obowiązuje każdy profil i każdy przebieg. Trasy: `GET /settings/safety` (uprawnienie `scans:read`), `PUT /settings/safety` (`safety:manage`, w rolach wbudowanych tylko administrator).

| Pole | Domyślnie | Walidacja przy zapisie |
| --- | --- | --- |
| `max_pps` | 1000 | 1–100 000 |
| `max_http_rps` | 50 | powyżej 0, najwyżej 10 000 |
| `max_per_host_rps` | 2 | powyżej 0, nie więcej niż `max_http_rps` |
| `max_paths_per_host` | 8 | 0–100 |
| `allowed_ports` | puste = wszystkie | lista portów w składni nmap, bez znaków powłoki |
| `denied_ports` | puste | jak wyżej |
| `exclusions` | puste | każda pozycja musi być adresem, CIDR, zakresem albo domeną |
| `allowed_methods` | `GET`, `HEAD` | **tylko** `GET` i `HEAD`; inna wartość daje błąd 422 |
| `user_agent` | `Czujka/1.0 (…)` | jeden wiersz, najwyżej 300 znaków |
| `emergency_stop` | `false` | zmieniają go tylko trasy awaryjnego zatrzymania |

Sprawdzone na działającym stosie: `PUT` z `"allowed_methods":["GET","POST"]` → `422 allowed_methods can only hold GET and HEAD (safe detection)`. Każda zmiana polityki trafia do dziennika audytu (`safety.update`). Test: `TestProfilesSafetyAndValidation`.

Porty: silnik skanuje część wspólną portów profilu i listy dozwolonej, bez portów zabronionych. Gdy nie zostaje żaden port, przebieg nie startuje (`TestPolicyFiltersPorts`). Sondy wykrywania hostów przechodzą ten sam filtr.

### 1.4 Awaryjne zatrzymanie

| | |
| --- | --- |
| Włączenie | `POST /emergency-stop`, uprawnienie `safety:stop` (role wbudowane: `admin`, `editor`, `analyst`); przycisk w górnym pasku UI. Kto może uruchomić skan, może też zatrzymać wszystkie skany. |
| Skutek | Flaga w bazie, zapisywana atomowo (`jsonb_set`). Zapis polityki (`PUT /settings/safety`) nigdy jej nie zmienia, więc równoległa edycja polityki nie skasuje świeżego zatrzymania. Menedżer przebiegów zatrzymuje wszystkie aktywne przebiegi; dostają stan `paused` z powodem `emergency_stop`. Wyniki zebrane do tej chwili zostają. |
| Blokada | Dopóki flaga jest ustawiona, nie wystartuje nowy przebieg i nie wznowi się wstrzymany. Silnik sprawdza flagę jako pierwszy krok i nie wysyła nic. |
| Zwolnienie | `POST /emergency-stop/release`, uprawnienie `safety:manage` (rola wbudowana: tylko `admin`). Wstrzymane przebiegi czekają na ręczne wznowienie. |
| Audyt | `safety.emergency_stop`, `safety.emergency_stop_release` |
| Testy | `TestEmergencyStop` (`internal/runner`), `TestEmergencyStopRefusesToStart` (`internal/scan`), `TestSafetyEditKeepsTheEmergencyStop` (`internal/store`), `TestSafetyPutNeverClearsTheEmergencyStop` (`internal/api`) |

Sprawdzone na działającym stosie: flaga włącza się i wyłącza; użytkownik z rolą `viewer` dostaje 403. `TestEmergencyStop` mierzy czas od zatrzymania do chwili, w której silnik przestaje pracować.

Zwykłe sterowanie przebiegiem (wstrzymaj, wznów, anuluj) wymaga uprawnienia `scans:run`.

### 1.5 Tryb bezpieczny sygnatur

Sygnatura może tylko czytać odpowiedź i poprosić o `GET` dodatkowej ścieżki. Walidator (`sig.Validate`) odrzuca sygnaturę z błędem `unsafe_signature`, gdy zawiera:

| Reguła | Przykład odrzucony |
| --- | --- |
| metodę inną niż `GET` i `HEAD` | `method: POST` |
| treść żądania, własne nagłówki, ciasteczka, dane logowania, ładunki; każde nieznane pole żądania | `body:`, `headers:`, `auth:`, `payloads:` |
| pełny adres URL albo inny host | `http://10.0.0.1/admin`, `//host/x`, `/a@host/` |
| przejście katalogów albo kodowanie procentowe | `/../etc/hosts`, `/%2e%2e/` |
| znaki spoza listy (ścieżka: litery, cyfry, `/ _ - . ~`; zapytanie: litery, cyfry, `_ - . = &`, do 80 znaków) | `/a;id`, `/s?q=<script>` |
| pliki i katalogi ukryte poza `/.well-known/` | `/.env`, `/.git/config` |
| ścieżki zmieniające stan; słowa są sprawdzane także jako części nazw w notacji camelCase | `/logout`, `/actuator/shutdown`, `/api/users?action=delete`, `/api/resetPassword`, `/cache/flushAll` |
| ścieżki pobierające sekrety, kopie, klucze, konfigurację, zrzuty | `/backup.zip`, `/db.sql`, `/id_rsa`, `/wp-config.php`, `/actuator/env` |
| słowa poleceń | `/cgi-bin/test?cmd=id` |
| więcej niż 5 ścieżek, ścieżkę dłuższą niż 200 znaków, wyrażenie regularne dłuższe niż 500 znaków | – |

Lista zakazów jest w `internal/sig/safety.go`: 55 fragmentów, 69 słów, 46 rozszerzeń plików. Wyrażenia regularne kompiluje silnik RE2 (czas liniowy, bez odwołań wstecznych), więc wzorzec nie zawiesi silnika.

Kolektor sprawdza ścieżkę drugi raz przed wysłaniem (`TestSafePath`). Dla ścieżek dodatkowych nie podąża za przekierowaniami i kończy po 2 kolejnych błędach. Za przekierowaniem w obrębie tego samego hosta (na przykład ze strony głównej) kolektor idzie tylko wtedy, gdy cel przechodzi `sig.CheckRedirect`: ścieżka przez `CheckPath`, zapytanie przez listę zakazanych słów (`TestSameOriginRedirectToAnUnsafePathNotFollowed`).

Retro-hunt dopasowuje sygnaturę do zapisanych obserwacji. Nie wysyła żadnego pakietu (`TestRetroHuntDoesNotChangeObservations`). Użytkownik bez `results:update` dostaje w retro-hunt ciasteczka z pustą wartością, więc wynik dopasowania nie zdradza ukrytej wartości (`TestRetroHuntIsNoCookieValueOracle`).

Testy: `TestValidatorRejectsUnsafeSignatures`, `TestCheckPath`, `TestRetroHuntRejectsUnsafeSignature`. Trasy sygnatur działają w produkcie: zapis przechodzi przez walidator, a zmiana przeładowuje silnik sygnatur.

### 1.6 Trzymanie się zakresu

| Mechanizm | Działanie | Dowód |
| --- | --- | --- |
| Wyłączenia | Adresy, CIDR, zakresy i domeny z polityki są odejmowane od celów przed planowaniem. Przy wznowieniu przebiegu aktualne wyłączenia są stosowane ponownie. Podgląd celów pokazuje liczbę wyłączonych adresów. | `TestCountLargeAndExclusions`, `TestExpandResolvesAndExcludes`, `TestExcludedAndBlocks` |
| Brak przekierowań poza host | Przekierowanie na inny protokół, host albo port jest zapisane, ale kolektor za nim nie idzie. | `TestOffHostRedirectNotFollowed` |
| Ścieżki tylko na badanej usłudze | Sygnatura nie może podać adresu URL ani innego hosta. | `TestCheckPath` |
| Ikona tylko z tego samego hosta | Odnośnik do ikony na innym hoście jest pomijany. | `httpfp/fetch.go` (`iconLinks`) |
| Źródła pasywne | O zakresie decyduje adres. Nazwa organizacji wskazująca na obcy adres nie staje się kandydatem na cel. | `TestCollectCandidatesAndHints` |
| Usługa zewnętrzna crt.sh | Domyślnie wyłączona. Wymaga dwóch zgód naraz. Wysyła tylko nazwę domeny. | `docs/INTEGRACJE.md` §3.1 |
| Okno czasowe | Silnik nie zaczyna części, która nie zmieści się przed końcem okna, a o końcu okna przerywa pracę. | `TestWindowGuardDoesNotStartWhatCannotFit` |
| Blokada operatora | `CZUJKA_ALLOWED_NETWORKS`: sieci, poza które Czujka nie wyjdzie. Nikt, także administrator, nie poszerzy jej w UI ani w API. Cel poza blokadą jest odrzucany przy wpisie, w skanie doraźnym, w ponownym sondowaniu i przy budowie planu. | `docs/WDROZENIE.md`, `TestOperatorLockThroughTheAPI` |
| Dozwolone sieci polityki | `allowed_networks` w polityce bezpieczeństwa zawęża zakres w granicach blokady. Domena przechodzi tylko wtedy, gdy każdy jej adres leży w środku. | `docs/API.md` (`PUT /settings/safety`) |
| Skan doraźny | Każdy adres (albo CIDR) skanu doraźnego (`POST /runs/adhoc`, uprawnienie `scans:run`) musi leżeć w całości w jednym włączonym celu. Analityk nie zeskanuje adresu, którego nikt z `targets:create` nie wpisał. Sprawdzenie działa też przy wznowieniu przebiegu i w ponownym sondowaniu. | `TestAdHocRunStaysInsideEnabledTargets`, `TestAdHocNeedsAnEnabledTarget` |
| Edycja celu | `PATCH /targets/{id}` ze zmianą wartości albo włączeniem celu przechodzi te same sprawdzenia co nowy cel. | `TestTargetUpdateRunsTheAllowedNetworksCheck` |
| Import do zakresu | Import wyników z `scope_id` dodaje cele, więc wymaga też `targets:create`. | `TestImportIntoScopeNeedsTargetsCreate` |

Zakres wyznaczają cele wpisane przez użytkownika z uprawnieniem `targets:create`, ograniczone blokadą operatora i dozwolonymi sieciami, minus wyłączenia.

Otwarte (przegląd M2, należy do silnika): sprawdzenie nazwy domenowej i skan rozwiązują ją osobno, więc nazwa o zmiennych odpowiedziach DNS może wskazać adres spoza dozwolonych sieci. Przy wznowieniu zapisane części planu dostają tylko aktualne wyłączenia, a nie zawężoną blokadę.

### 1.7 Kontener skanera

Sprawdzone na działającym stosie:

| Cecha | Wartość |
| --- | --- |
| Użytkownik procesu | `czujka` (uid 10001), nie root |
| Uprawnienia jądra | `cap_drop: ALL`, `cap_add: NET_RAW, NET_ADMIN`; nmap dostaje surowe gniazda przez `setcap` na pliku. `NET_ADMIN` zostaje celowo (decyzja po przeglądzie, L5). W trybie sieci hosta (`docker-compose.host-network.yml`) dotyczy przestrzeni nazw sieci hosta |
| System plików | tylko do odczytu (`touch /x` → „Read-only file system”); `/tmp` jako tmpfs |
| Baza danych | sieć wewnętrzna bez trasy na zewnątrz, bez opublikowanego portu |
| Interfejs WWW | domyślnie tylko `127.0.0.1:8080` |

Bez `NET_RAW` nmap przechodzi na skan połączeniowy (`-sT`) i nadal działa.

## 2. Ochrona danych

### 2.1 Szyfrowanie w spoczynku, warstwa 1: pg_tde

| | |
| --- | --- |
| Baza | PostgreSQL 17, dystrybucja Percona z rozszerzeniem `pg_tde` (open source) |
| Zakres | Wszystkie tabele Czujki używają metody dostępu `tde_heap`. WAL jest szyfrowany (`pg_tde.wal_encrypt = on`). `default_table_access_method = tde_heap`, więc nowa tabela też jest szyfrowana. |
| Klucze bazy | Plik pęku kluczy w osobnym wolumenie `czujka-tde-keys`. Kopia samego wolumenu danych jest nieczytelna. |
| Kontrola przy starcie | `CZUJKA_TDE=require` (domyślnie w `docker-compose.yml`): Czujka nie wystartuje, gdy `pg_tde` nie działa. `auto`: startuje i ostrzega w logu. |
| Stan | `GET /healthz` z sesją → `"tde":true`, `"tables":21,"encrypted":21,"wal_encrypted":true`. Bez sesji `/healthz` zwraca tylko `{status, version}` (`TestHealthzWithoutSessionIsMinimal`). |

Sprawdzenie w bazie (wynik: 21 wierszy, każdy `tde_heap | t`):

```sh
docker compose -f deploy/docker-compose.yml exec db psql -h 127.0.0.1 -U czujka -d czujka -c \
  "SELECT c.relname, am.amname, pg_tde_is_encrypted(c.oid) FROM pg_class c JOIN pg_am am ON am.oid = c.relam
   WHERE c.relkind = 'r' AND c.relnamespace = 'public'::regnamespace ORDER BY 1"
```

Test: `TestMigrateIsIdempotentAndTablesAreEncrypted`.

Czego `pg_tde` nie szyfruje: katalogów systemowych (nazwy tabel i kolumn), statystyk, plików tymczasowych. Zrzut logiczny (`pg_dump`) zawiera dane odszyfrowane. Dlatego dane najbardziej wrażliwe mają warstwę 2.

### 2.2 Szyfrowanie pól, warstwa 2

AES-256-GCM w schemacie kopertowym (`internal/crypto`):

- Każda wartość ma własny losowy klucz danych (256 bitów).
- Klucz danych jest opakowany kluczem głównym.
- Dane dodatkowe (AAD) wiążą szyfrogram z tabelą, kolumną i wierszem. Szyfrogram skopiowany do innego wiersza nie da się odczytać (`TestRoundTripAndBinding`, `TestTamperDetection`).
- Format w bazie: `czk1.<id klucza głównego>.<dane>`.

| Kolumna | Zawartość |
| --- | --- |
| `settings.secret` | klucz API DefectDojo; adres i klucz HMAC webhooka; wartość kontrolna klucza głównego |
| `service_observations.secret` | wartości ciasteczek, fragment treści odpowiedzi, fragmenty odpowiedzi ze ścieżek sygnatur |
| `findings.evidence_enc` | dowody obserwacji |
| `findings.note_enc` | notatka analityka do obserwacji |
| `hosts.note_enc` | notatka analityka do hosta |
| `services.note_enc` | notatka analityka do usługi |

Lista jest w `internal/store/rotate.go` (`encryptedColumns`). Sprawdzone: po zapisaniu klucza API w ustawieniach kolumna ma wartość `czk1.6f97b2a75ca6.…`, a zrzut `pg_dump` nie zawiera jawnego klucza. API zwraca tylko `"api_key_set":true`. Testy: `TestIngestInventoryAndFieldEncryption`, `TestSplitAndMergeSecrets`.

Tylko warstwa 1 chroni: adresy, nazwy hostów, banery, tytuły stron, nagłówki odpowiedzi, dane użytkowników, dziennik audytu.

Nagłówek `Set-Cookie` w zapisanych nagłówkach nie ma wartości ciasteczka. Kolektor zamienia ją na `nazwa=[masked len=N]` przed zapisem (`httpfp.MaskSetCookie`, test `TestMaskSetCookie`). Sama wartość trafia tylko do `service_observations.secret` (warstwa 2).

### 2.3 Klucz główny i rotacja

| | |
| --- | --- |
| Źródło | `CZUJKA_MASTER_KEY` (32 bajty jako base64 albo hex) albo plik `CZUJKA_MASTER_KEY_FILE`. Zmienna ma pierwszeństwo. |
| Pierwszy start bez klucza | Czujka generuje klucz do pliku z prawami 0600 (wolumen `czujka-keys`) i ostrzega w logu. |
| Identyfikator | Skrót SHA-256 klucza (12 znaków). Jest w każdym szyfrogramie i w `/healthz` dla zalogowanego użytkownika. Nie ujawnia klucza. |
| Kontrola przy starcie | Zły klucz zatrzymuje start z komunikatem: `the master key does not match this database (data was encrypted with key id …, the keyring has […])`. |
| Rotacja | `czujka rotate-key` opakowuje na nowo tylko klucze danych. Jest szybka i można ją powtórzyć. Zapisuje wpis `crypto.rotate_key` w audycie. Procedura: `docs/WDROZENIE.md`. |

Sprawdzone: rotacja przeniosła 2 wartości z klucza `6f97b2a75ca6` na `2a1e32e2d201`; start ze starym kluczem dał komunikat z tabeli; start z nowym kluczem odczytał ustawienia. Testy: `TestRotation`, `TestKeyRotation`.

Rotacja nie zmienia kluczy danych ani szyfrogramów pól. Kto ma stary klucz główny i starą kopię bazy, odczyta pola z tej kopii. Po wycieku klucza trzeba więc obrócić klucz i usunąć stare kopie.

Utrata klucza głównego oznacza utratę pól z warstwy 2. Klucz `pg_tde` w pliku to rozwiązanie dla prototypu; w produkcji należy użyć Vault albo KMIP (`pg_tde` je obsługuje).

### 2.4 Hasła i logowanie

| | |
| --- | --- |
| Skrót hasła | argon2id: pamięć 32 MiB, 2 przebiegi, 1 wątek, sól 16 bajtów, klucz 32 bajty; zapis w formacie PHC |
| Wymagania | 10–256 znaków |
| Pierwszy administrator | Gdy `CZUJKA_ADMIN_PASSWORD` jest puste, losowe hasło pojawia się raz w logu. Baza go nie przechowuje, ale log kontenera trzyma je, dopóki kontener istnieje. Zmień je po pierwszym logowaniu. |
| Zmiana własnego hasła | `POST /auth/password` `{current_password, new_password}` z sesją i tokenem CSRF → 204. Złe obecne hasło liczy się jako nieudane logowanie. Pozostałe sesje użytkownika kończą się. Wpis `auth.password_change` bez hasła (`TestSelfServicePasswordChange`). |
| Blokada konta | 5 nieudanych logowań → blokada na 15 minut (`CZUJKA_LOGIN_MAX_FAILURES`, `CZUJKA_LOGIN_LOCKOUT`). Po wygaśnięciu blokady licznik startuje od zera, więc jedna próba co 15 minut nie trzyma konta zablokowanego. Administrator zdejmuje blokadę poleceniem `czujka user unlock EMAIL`. |
| Brak wyroczni kont | Zablokowane konto, nieznane konto i złe hasło dają tę samą odpowiedź `401 invalid_credentials`. Hasło jest sprawdzane (dla nieznanego i zablokowanego konta: z fikcyjnym skrótem), więc czas odpowiedzi też ich nie rozróżnia. Dziennik audytu zapisuje prawdziwy powód (`locked`). |
| Limit prób | 20 na minutę z jednego adresu (`CZUJKA_LOGIN_RATE_PER_MIN`); licznik w pamięci procesu |
| Rozmiar żądania | treść logowania do 8 KiB; e-mail w dzienniku obcięty do 254 znaków |

Testy: `TestPasswordHash`, `TestLoginSessionAndLockout`, `TestLoginRateLimitPerAddress`, `TestLoginGivesNoAccountOracle`, `TestLoginAuditIsBounded`, `TestLockExpiryResetsTheFailureCounter`, `TestUnlockByEmail`.

### 2.5 Sesje i CSRF

| | |
| --- | --- |
| Token sesji | 256 losowych bitów; w bazie tylko skrót SHA-256 |
| Ciasteczko | `czujka_session`: `HttpOnly`, `SameSite=Strict`, `Secure` przy TLS (`CZUJKA_COOKIE_SECURE=auto`) |
| Ważność | 12 godzin (`CZUJKA_SESSION_TTL`); wygasłe sesje usuwane co 15 minut |
| CSRF | Token na sesję. Każde żądanie zmieniające (poza logowaniem) musi go mieć w nagłówku `X-CSRF-Token`. Porównanie w stałym czasie. |
| Nagłówki odpowiedzi | `Content-Security-Policy` (`default-src 'self'`, `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` dla API, HSTS przy TLS |

Sprawdzone: `POST` bez tokenu → `403 missing or wrong CSRF token`. Testy: `TestPrincipalAndCSRF`, `TestSecurityHeadersAndUI`.

Ograniczenia: CSP dopuszcza style w treści strony (`style-src 'unsafe-inline'`). Czujka nie kończy TLS sama; poza `127.0.0.1` potrzebny jest serwer pośredniczący z TLS (`docs/WDROZENIE.md`).

### 2.6 Dziennik audytu

- Wpis dla każdego żądania zmieniającego, także odrzuconego (brak sesji, brak uprawnienia, zły token CSRF, błąd walidacji).
- Wpis dla każdego eksportu, chociaż eksport jest odczytem.
- Pola: czas, użytkownik, akcja, obiekt, identyfikator, kod odpowiedzi, metoda, ścieżka, adres klienta, szczegóły (na przykład nazwy zmienionych pól).
- Treść żądań nie jest zapisywana. Hasła i klucze nie trafiają do dziennika.
- Żądania bez sesji mają wspólny budżet wpisów: 1 na sekundę, zapas 60. Wpisy ponad budżet są pomijane, a następny wpis ma w szczegółach liczbę pominiętych (`dropped_before`). Zalew żądań z sieci skanowanej nie zapcha więc dziennika.
- Polecenia wiersza poleceń (`user create`, `user unlock`, `rotate-key`) zapisują wpis z użytkownikiem `cli`.
- Odczyt: `GET /audit`, uprawnienie `audit:read`.

Test: `TestRBACMatrixCSRFAndAudit`, `TestDefaultAuditAction`. Ograniczenia: brak retencji i brak ochrony przed zmianą wpisów przez administratora bazy.

### 2.7 Role i uprawnienia

Uprawnienia sprawdza API. Interfejs tylko ukrywa to, czego użytkownik nie może zrobić.

| Uprawnienie | Znaczenie | admin | editor | analyst | viewer |
| --- | --- | :-: | :-: | :-: | :-: |
| `targets:read` | podgląd zakresów i celów | ✓ | ✓ | ✓ | ✓ |
| `targets:create` | dodawanie celów | ✓ | ✓ | – | – |
| `targets:update` | edycja celów | ✓ | ✓ | ✓ | – |
| `targets:delete` | usuwanie celów | ✓ | ✓ | – | – |
| `scans:read` | podgląd skanów i profili | ✓ | ✓ | ✓ | ✓ |
| `scans:run` | start, wstrzymanie, anulowanie skanu | ✓ | ✓ | ✓ | – |
| `scans:configure` | profile i harmonogramy | ✓ | ✓ | – | – |
| `results:read` | podgląd wyników | ✓ | ✓ | ✓ | ✓ |
| `results:update` | edycja wyników, tagów, obserwacji | ✓ | ✓ | ✓ | – |
| `results:create` | dodawanie obserwacji, import wyników | ✓ | ✓ | – | – |
| `results:delete` | usuwanie wyników | ✓ | ✓ | – | – |
| `signatures:read` | podgląd sygnatur | ✓ | ✓ | ✓ | ✓ |
| `signatures:create` | dodawanie sygnatur | ✓ | ✓ | – | – |
| `signatures:update` | edycja sygnatur | ✓ | ✓ | ✓ | – |
| `signatures:delete` | usuwanie sygnatur | ✓ | ✓ | – | – |
| `export:run` | eksport danych, wysyłka do DefectDojo | ✓ | ✓ | ✓ | – |
| `integrations:manage` | ustawienia integracji (DefectDojo, webhook, źródła pasywne) | ✓ | – | – | – |
| `safety:manage` | polityka bezpieczeństwa, zwolnienie blokady | ✓ | – | – | – |
| `safety:stop` | awaryjne zatrzymanie | ✓ | ✓ | ✓ | – |
| `users:manage` | użytkownicy | ✓ | – | – | – |
| `roles:manage` | role | ✓ | – | – | – |
| `audit:read` | dziennik audytu | ✓ | – | – | – |

| Rola | Nazwa w UI | Rola z zadania |
| --- | --- | --- |
| `admin` | Administrator | Administracja |
| `editor` | Edytor | Dodawanie, usuwanie, modyfikacja |
| `analyst` | Analityk | Modyfikacja i odczyt |
| `viewer` | Obserwator | Odczyt |

Reguły:

- Administrator tworzy własne role z dowolnego podzbioru uprawnień (`POST /roles`).
- Nikt nie nada roli z uprawnieniem, którego sam nie ma.
- Role wbudowane są tylko do odczytu.
- Ostatniego administratora nie da się usunąć, wyłączyć ani zdegradować.
- Wartości ciasteczek badanych usług widzi tylko użytkownik z `results:update`. Pozostali dostają nazwy i flagi, także w retro-hunt.
- Import wyników do zakresu wymaga `results:create` i `targets:create`.

Sprawdzone na działającym stosie jako `viewer`: dodanie celu → 403, awaryjne zatrzymanie → 403, eksport → 403, lista użytkowników → 403, odczyt zakresów → 200. Utworzenie własnej roli „Audytor” → 201. Testy: `TestBuiltinRolesMatchTheArchitecture`, `TestRBACMatrixCSRFAndAudit`, `TestRBACRules`, `TestRequireMiddleware`.

## 3. Znane ograniczenia (zbiorczo)

| Obszar | Ograniczenie |
| --- | --- |
| Tempo | Budżet pakietów i limity HTTP działają w obrębie jednego przebiegu. Kilka przebiegów naraz sumuje swoje limity (przegląd H2, otwarte). `--min-rate` = `--max-rate`: stałe tempo, bez samoczynnego zwalniania nmap. Sondy `-sV` poza limitem pakietów. |
| Zakres | Nazwa domenowa jest rozwiązywana osobno przy sprawdzeniu i przy skanie; wznowione części planu nie dostają zawężonej blokady (przegląd M2, otwarte). |
| Kontener | `NET_ADMIN` zostaje obok `NET_RAW` (decyzja po przeglądzie, L5). |
| Kopie | Zrzut `pg_dump` jest jawny poza kolumnami warstwy 2. Trzeba go szyfrować. |
| Klucze | Klucz `pg_tde` w pliku na wolumenie. `rotate-key` opakowuje na nowo tylko klucze danych; stara kopia bazy ze starym kluczem pozostaje czytelna. |
| Logowanie | Limit prób w pamięci jednego procesu. Brak drugiego składnika. Hasło pierwszego administratora zostaje w logu kontenera, dopóki kontener istnieje. Zmiana hasła działa w API (`POST /auth/password`); formularz w UI to osobne zadanie. |
| Audyt | Brak retencji i ochrony integralności. |

## 4. Przegląd bezpieczeństwa

Przegląd kodu z 2026-11-21 (wewnętrzny, jeden recenzent) znalazł 2 problemy wysokie (H), 4 średnie (M) i 7 niskich (L). Każda poprawka ma test, który na kodzie sprzed poprawki nie przechodził, na prawdziwych handlerach i prawdziwej bazie PostgreSQL. Przegląd nie sprawdzał zachowania w działającym stosie.

### 4.1 Co przegląd potwierdził

- Każda trasa API ma strażnika z właściwym uprawnieniem.
- Token CSRF na każdej trasie zmieniającej, także przy wylogowaniu i wysyłce plików.
- Nikt nie nada uprawnienia, którego sam nie ma. Role wbudowane są tylko do odczytu. Ostatni administrator jest chroniony blokadą doradczą w bazie.
- Token sesji: 256 bitów, w bazie skrót SHA-256, ciasteczko `HttpOnly` i `SameSite=Strict`, nowy token przy każdym logowaniu. Z `X-Forwarded-For` liczy się tylko wpis skrajnie prawy.
- argon2id z pamięcią 32 MiB; fikcyjny skrót dla nieznanych kont.
- nmap: bez powłoki, cele na standardowym wejściu po wyrażeniu regularnym, porty odbudowane z mapy bitowej, bez `--script`, nazwy hostów nigdy nie trafiają do nmap.
- Kolektor HTTP: tylko `GET` i `HEAD`, połączenie przypięte do skanowanego adresu IP, bez przekierowań poza host, ograniczona treść i gzip.
- Ścisłe parsowanie adresów (`netip`: zapis dziesiętny i ósemkowy adresu daje błąd). Mapowanie adresu pętli zwrotnej sprawdzane z blokadą operatora. SQL z parametrami i listą dozwolonych kolumn sortowania. Dekoder XML bez encji zewnętrznych. Limity rozmiaru plików.
- UI bez `dangerouslySetInnerHTML`. Raport z `html/template` i CSP `default-src 'none'`.
- Koperta AES-256-GCM z AAD związanym z wierszem. Zły klucz zatrzymuje start. TDE domyślnie `require`.
- Baza bez opublikowanego portu, kontener bez roota, system plików tylko do odczytu.
- Zwolnienie awaryjnego zatrzymania wymaga `safety:manage`.

### 4.2 Poprawki

| Nr | Problem | Poprawka | Commit | Test |
| --- | --- | --- | --- | --- |
| H1 | `scans:run` mógł zeskanować dowolny adres skanem doraźnym; edycja celu omijała sprawdzenie dozwolonych sieci | adres skanu doraźnego musi leżeć we włączonym celu (także przy wznowieniu i ponownym sondowaniu); edycja celu przechodzi sprawdzenie; import do zakresu wymaga `targets:create` | `b90c5de` | `TestAdHocRunStaysInsideEnabledTargets`, `TestTargetUpdateRunsTheAllowedNetworksCheck`, `TestImportIntoScopeNeedsTargetsCreate` |
| H2 | limit pakietów na przebieg, nie globalny | **otwarte**, należy do silnika (`internal/scan`) | – | – |
| M1 | retro-hunt jako wyrocznia ukrytych wartości ciasteczek | puste wartości ciasteczek dla użytkownika bez `results:update` | `03dd94b` | `TestRetroHuntIsNoCookieValueOracle` |
| M2 | DNS rozwiązywany osobno przy sprawdzeniu i przy skanie | **otwarte**, należy do silnika (`internal/scan`) | – | – |
| M3 | wyścig mógł skasować awaryjne zatrzymanie | atomowy `jsonb_set`; zapis polityki nie zmienia flagi | `7aab986` | `TestSafetyEditKeepsTheEmergencyStop`, `TestSafetyPutNeverClearsTheEmergencyStop` |
| M4 | blokada kont i zalew dziennika bez logowania; odpowiedź zdradzała istnienie konta | reset licznika po blokadzie, jedna odpowiedź 401, fikcyjna weryfikacja hasła, limit treści, budżet wpisów bez sesji, `czujka user unlock` | `6899d6c` | `TestLoginGivesNoAccountOracle`, `TestLoginAuditIsBounded`, `TestLockExpiryResetsTheFailureCounter` |
| L1 | test DefectDojo wysyłał zapisany klucz na adres z żądania | klucz idzie tylko do zapisanego hosta | `bcf9f69` | `TestDojoStoredKeyStaysWithItsHost` |
| L2 | integracje podążały za przekierowaniem i zwracały treść odpowiedzi | bez przekierowań, błąd tylko z kodem odpowiedzi | `f78c305` | `TestClientFollowsNoRedirectAndEchoesNoBody`, `TestPostFollowsNoRedirectAndEchoesNoBody` |
| L3 | lista zakazanych ścieżek tylko na całe słowa; przekierowanie w obrębie hosta bez sprawdzenia ścieżki | słowa z notacji camelCase; `sig.CheckRedirect` przed przekierowaniem | `bc0cbff` | `TestCheckPath`, `TestSameOriginRedirectToAnUnsafePathNotFollowed` |
| L4 | `findings.dojo.csv` bez ochrony przed formułami | ochrona każdej komórki | `dbbf298` | `TestDojoGenericCSVFormulaGuard` |
| L5 | stałe hasło bazy dla instalacji ze starszej wersji; `NET_ADMIN` | nowe losowe hasło, Czujka przenosi na nie rolę bazy; `NET_ADMIN` zostaje celowo | `0e53e15` | `TestAdoptLegacyDBPassword` |
| L6 | brak zmiany własnego hasła; `/healthz` bez sesji zdradzał szczegóły | `POST /auth/password`; `/healthz` bez sesji: tylko `{status, version}` | `6345589` | `TestSelfServicePasswordChange`, `TestHealthzWithoutSessionIsMinimal` |
| L7 | ten dokument był nieaktualny | rozdziały 1–3 zgodne z kodem, ten rozdział | ten commit | – |
