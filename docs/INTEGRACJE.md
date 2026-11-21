# Integracje Czujki

Dokument opisuje wymianę danych: import i eksport wyników, pasywne źródła danych, integrację z DefectDojo i lokalne laboratorium DefectDojo.

| Temat | Pakiet |
| --- | --- |
| Import i eksport wyników | `internal/interchange` |
| Pasywne źródła danych | `internal/passive` |
| DefectDojo | `internal/defectdojo` |
| Raport z przebiegu | `internal/report` (opis w `docs/ALGORYTMY.md`, rozdz. 8) |
| Narzędzie testowe | `cmd/dojoprobe` |

Format przykładowych danych od organizatorów nie był znany w chwili pisania. Dlatego każdy importer ma **jedną tabelę nazw pól**. Dopasowanie do nowego formatu to dopisanie nazw kolumn do tej tabeli.

## 1. Import wyników

Punkt API: `POST /import/results` (plik w `multipart`, opcjonalnie `scope_id`). Odpowiedź: `ImportReport`.

Importer zamienia plik na te same rekordy `HostResult`, które emituje silnik skanu. Dane z importu przechodzą więc tę samą analizę: model dostępności, zmiany, ocenę ciekawości, obserwacje.

### 1.1 Formaty

Format jest wykrywany z treści pliku. Rozszerzenie nie ma znaczenia.

| Format | Kiedy | Uwagi |
| --- | --- | --- |
| nmap XML | plik zaczyna się od `<?xml` albo `<nmaprun` | wynik `nmap -oX`; czytany strumieniowo, host po hoście |
| Czujka JSON | plik zaczyna się od `{` albo `[` | własny format bezstratny oraz warianty opisane niżej |
| CSV | pozostałe | jeden wiersz to jedna usługa; separator wykrywany: przecinek, średnik, tabulator, pionowa kreska |

**nmap XML.** Importer czyta: stan hosta i powód, adresy IPv4/IPv6, MAC i producenta, nazwy hostów, porty ze stanem, wynik `-sV` (usługa, produkt, wersja, informacje dodatkowe, tunel TLS, pewność `conf`, CPE), skrypty portów i hosta, dopasowania systemu operacyjnego, czas RTT. Skrypty `http-title`, `http-server-header` i `banner` wypełniają tytuł strony, nagłówek `Server` i baner. Ucięty plik nie przerywa importu: hosty przeczytane do miejsca uszkodzenia zostają.

**JSON.** Akceptowane kształty:

```json
{"format":"czujka-json","version":1,"generated_at":"2026-11-21T12:12:03Z","run_id":1,"hosts":[
  {"ip":"172.31.250.2","hostnames":["www.lab"],"up":true,"observed_at":"2026-11-21T12:05:49Z",
   "services":[{"port":80,"proto":"tcp","state":"open","name":"http","product":"nginx","version":"1.31.9"}]}
]}
```

```json
[{"ip":"10.0.0.9","port":8080,"service":"http","product":"Jenkins","version":"2.440"}]
```

```json
{"results":[{"address":"10.0.0.9","hostname":"ci.lab","ports":[{"port":22,"service":"ssh"},{"port":8080}]}]}
```

```json
{"ip":"10.0.0.9","ports":[22,80,443]}
{"ip":"10.0.0.10","port":3306,"service":"mysql"}
```

Kolejno: koperta Czujki (bezstratna), tablica płaskich rekordów (jeden na usługę), hosty z zagnieżdżoną listą portów, JSON Lines. Klucze płaskich rekordów przechodzą przez tabelę z rozdz. 1.2.

**CSV.** Pierwszy wiersz to nagłówek. Nazwy kolumn są porównywane bez rozróżniania wielkości liter; spacja, myślnik i kropka są równe podkreśleniu (`HTTP Status` = `http_status`). Znak BOM jest pomijany. Nieznane kolumny są ignorowane.

### 1.2 Tabela nazw pól

Źródło: `FieldMapping` w `internal/interchange/mapping.go`. Pierwsza nazwa w wierszu to nazwa kolumny w eksporcie CSV.

| Pole | Akceptowane nazwy kolumn (CSV) i kluczy (płaski JSON) |
| --- | --- |
| `ip` | `ip`, `ip_address`, `ipaddress`, `address`, `addr`, `ipv4`, `ipv6`, `host_ip`, `target`, `adres`, `adres_ip` |
| `host` | `host` |
| `hostname` | `hostname`, `hostnames`, `fqdn`, `domain`, `dns`, `dns_name`, `rdns`, `nazwa`, `nazwa_hosta`, `domena` |
| `up` | `up`, `alive`, `is_up`, `host_up`, `host_state`, `host_status`, `aktywny` |
| `port` | `port`, `portid`, `port_number`, `dst_port`, `dport` |
| `proto` | `proto`, `protocol`, `transport`, `protokol` |
| `state` | `state`, `port_state`, `stan` |
| `service` | `service`, `service_name`, `name`, `svc`, `usluga` |
| `product` | `product`, `software`, `app`, `produkt` |
| `version` | `version`, `product_version`, `wersja` |
| `extra_info` | `extra_info`, `extrainfo`, `info`, `extra` |
| `banner` | `banner`, `raw_banner`, `baner` |
| `tls` | `tls`, `ssl`, `https`, `tunnel` |
| `url` | `url`, `uri`, `link` |
| `status` | `status`, `http_status`, `status_code`, `http_code`, `code`, `response_code`, `kod` |
| `title` | `title`, `http_title`, `page_title`, `tytul` |
| `server` | `server`, `http_server`, `server_header`, `web_server` |
| `redirect` | `redirect`, `final_url`, `location`, `redirect_url`, `przekierowanie` |
| `technologies` | `technologies`, `technology`, `tech`, `techs`, `cms`, `framework`, `technologie` |
| `classes` | `classes`, `class`, `category`, `categories`, `klasy` |
| `cert_cn` | `cert_cn`, `tls_subject_cn`, `ssl_cn`, `cert_subject`, `certificate_cn`, `subject_cn` |
| `cert_issuer` | `cert_issuer`, `tls_issuer`, `ssl_issuer`, `issuer` |
| `cert_not_after` | `cert_not_after`, `tls_not_after`, `cert_expires`, `cert_expiry`, `not_after`, `ssl_expiry` |
| `cert_sha256` | `cert_sha256`, `tls_sha256`, `cert_fingerprint`, `tls_fingerprint` |
| `cookies` | `cookies`, `cookie`, `cookie_names`, `ciasteczka` |
| `cpe` | `cpe`, `cpes` |
| `os` | `os`, `os_guess`, `operating_system`, `system` |
| `mac` | `mac`, `mac_address` |
| `vendor` | `vendor`, `mac_vendor`, `producent` |
| `rtt_ms` | `rtt_ms`, `rtt`, `latency_ms`, `latency` |
| `reason` | `reason`, `host_reason` |
| `confidence` | `confidence`, `conf` |
| `observed_at` | `observed_at`, `timestamp`, `time`, `date`, `datetime`, `scan_time`, `scanned_at`, `last_seen`, `seen_at`, `czas`, `data` |

Kolumna `host` może zawierać adres albo nazwę; importer rozpoznaje to po wartości. Kolumna `status` z wartością `up` albo `down` jest czytana jako stan hosta, a liczba jako kod HTTP.

### 1.3 Błędne wiersze

Jeden zły wiersz nigdy nie przerywa importu. `ImportReport.invalid` wymienia numer wiersza, wartość i powód po polsku, na przykład „niepoprawny adres IP" albo „niepoprawny numer portu". Lista ma limit 500 pozycji. Hosty ze stanem „down" są pomijane i liczone w `skipped`.

Import kończy się błędem tylko wtedy, gdy całego pliku nie da się przeczytać (pusty plik, nieznany format).

## 2. Eksport wyników

Punkt API: `GET /export/runs/{id}.{json,csv,xml}`. Eksport jest strumieniowy: host po hoście, bez trzymania całego przebiegu w pamięci.

| Format | Zawartość | Do czego |
| --- | --- | --- |
| JSON | koperta `czujka-json` z pełnymi rekordami `HostResult` | format bezstratny: kopia, przeniesienie między instancjami |
| CSV | jeden wiersz na usługę, kolumny z rozdz. 1.2 | arkusz kalkulacyjny, szybki przegląd |
| XML | nmap XML | DefectDojo, typ skanu „Nmap Scan"; inne narzędzia czytające nmap |

Stan na 2026-11-21: trasa `/export/runs/{id}.csv` w API używa jeszcze własnego, krótszego nagłówka (18 kolumn: `run_id,ip,hostnames,up,reason,observed_at,port,proto,state,name,product,version,tunnel,http_status,title,url,technologies,classes`). Eksport JSON tej trasy to tablica rekordów `HostResult` bez koperty. Importer czyta oba układy CSV i oba kształty JSON. Poniżej nagłówek eksportera `internal/interchange` (narzędzie `dojoprobe convert -to csv`).

Nagłówek CSV (stała kolejność):

```text
ip,hostname,up,port,proto,state,service,product,version,extra_info,banner,tls,url,status,title,server,redirect,technologies,classes,cert_cn,cert_issuer,cert_not_after,cert_sha256,cookies,cpe,os,mac,vendor,rtt_ms,reason,confidence,observed_at
```

Przykładowy wiersz z prawdziwego skanu:

```text
172.31.250.2,czujka-an-nginx.czujka-an-net,true,80,tcp,open,http,nginx,1.31.9,,,,http://172.31.250.2:80/,,Welcome to nginx!,nginx/1.31.9,,nginx:1.31.9,,,,,,,cpe:/a:igor_sysoev:nginx:1.31.9,,72:F8:25:39:A1:2E,,0.01,arp-response,1,2026-11-21T12:05:49Z
```

Co niesie który format:

| Dane | JSON | XML | CSV |
| --- | --- | --- | --- |
| host, porty, usługa, produkt, wersja, CPE | tak | tak | tak |
| tytuł strony, nagłówek `Server`, baner | tak | tak (skrypty `http-title`, `http-server-header`, `banner`) | tak |
| technologie i klasy Czujki | tak | tak (skrypty `czujka-technologies`, `czujka-classes`) | tak (nazwy) |
| pełne nagłówki HTTP, flagi ciasteczek, dopasowania sygnatur z dowodami | tak | nie | nie |

Bezpieczeństwo CSV: komórka zaczynająca się od `=`, `+`, `-` albo `@` dostaje apostrof na początku. Arkusz kalkulacyjny nie wykona więc formuły z banera obcego serwera. Importer usuwa ten apostrof.

### 2.1 Sprawdzenie w obie strony

Wykonane na prawdziwym wyniku `nmap -sV` (trzy kontenery w prywatnej sieci docker):

```sh
go run ./cmd/dojoprobe convert -in nmap.xml  -to xml  > rt.xml    # 4 hosty, 12 usług, 0 błędnych wierszy
go run ./cmd/dojoprobe convert -in rt.xml    -to json > rt.json
go run ./cmd/dojoprobe convert -in rt.json   -to csv  > rt.csv
go run ./cmd/dojoprobe convert -in rt.csv    -to xml  > rt2.xml
```

Po każdym kroku adresy, porty, stany, usługi, produkty i wersje są identyczne z oryginałem. Test `TestRoundTripRealNmap` powtarza to dla dwóch prawdziwych plików i trzech formatów.

## 3. Pasywne źródła danych

Pakiet `internal/passive` zbiera wiedzę o zakresie **bez wysyłania pakietów do skanowanych adresów**.

| Źródło | Co robi | Ruch sieciowy |
| --- | --- | --- |
| Plik (`FileSource`) | czyta plik przekazany przez właściciela sieci | żaden |
| Odwrotny DNS (`PTRSource`) | pyta o rekordy PTR znanych, aktywnych adresów | zapytania do resolwera systemowego (zwykle własny DNS organizacji); domyślnie 5 na sekundę |
| Certificate Transparency (`CTSource`) | pyta serwis crt.sh o certyfikaty domeny | **usługa zewnętrzna, domyślnie wyłączona** |

### 3.1 Certificate Transparency: usługa zewnętrzna

Zapytanie do crt.sh **wysyła nazwę domeny z zakresu do zewnętrznego serwisu**. Dlatego:

- źródło jest domyślnie wyłączone;
- działa tylko wtedy, gdy administrator włączy je w ustawieniach (`CTSource.Enabled`) i wywołanie dostanie `Options.AllowExternal`. Oba warunki naraz;
- wysyła wyłącznie nazwę domeny: `GET https://crt.sh/?q=%.domena&output=json`. Nie wysyła adresów, listy hostów ani danych logowania;
- między domenami czeka 2 sekundy;
- nazwy z certyfikatów nie mają adresu, więc stają się tylko kandydatami do sprawdzenia przez analityka.

Testy nigdy nie łączą się z crt.sh: używają lokalnego serwera, a klient HTTP w testach odrzuca każdy adres inny niż 127.0.0.1.

### 3.2 Pliki

Format jest wykrywany z treści.

| Format | Przykład źródła |
| --- | --- |
| CSV (przecinek, średnik, tabulator, kreska; z nagłówkiem albo bez) | eksport strefy DNS z panelu, lista hostów z inwentarza |
| JSON (tablica, koperta `results`/`data`/`records`, jeden poziom zagnieżdżenia) | lista certyfikatów w formacie crt.sh, eksport z narzędzia |
| JSON Lines | pasywny DNS w formacie „Passive DNS Common Output Format" (`rrname`, `rrtype`, `rdata`, `time_first`, `time_last`) |
| plik strefy DNS | wynik `dig AXFR`, plik strefy BIND (`$ORIGIN`, `@`, nazwy względne) |

Przykłady (fragmenty plików testowych z `internal/passive/testdata`):

```text
nazwa;typ;wartość;ttl
www.kampus.example.;A;10.66.1.10;3600
poczta.kampus.example;CNAME;mx1.kampus.example.;3600
```

```json
{"rrname":"ci.kampus.example.","rrtype":"A","rdata":"10.66.3.17","time_first":1761465600,"time_last":1763686800,"count":412,"sensor_id":"dns-1"}
```

```json
[{"issuer_name":"C=US, O=Let's Encrypt, CN=R11","common_name":"www.kampus.example","name_value":"www.kampus.example\nkampus.example","not_before":"2026-11-20T08:14:03","not_after":"2027-02-18T08:14:02","serial_number":"04a1…"}]
```

Tabela nazw pól (`FieldMapping` w `internal/passive/mapping.go`). Nazwy są porównywane bez wielkości liter, separatorów i polskich znaków (`Źródło` = `zrodlo`, `Last Seen` = `last_seen`).

| Pole | Akceptowane nazwy |
| --- | --- |
| `ip` | `ip`, `ip_address`, `address`, `addr`, `ipv4`, `ipv6`, `host_ip`, `resolved_ip`, `adres`, `adres_ip` |
| `hostname` | `hostname`, `host`, `name`, `fqdn`, `domain`, `dns_name`, `rrname`, `query`, `qname`, `subdomain`, `record`, `owner`, `domena`, `nazwa`, `nazwa_hosta` |
| `port` | `port`, `dport`, `dst_port`, `dest_port`, `port_number` |
| `first_seen` | `first_seen`, `time_first`, `first`, `first_seen_at`, `seen_first`, `zone_time_first`, `pierwsza_obserwacja`, `pierwszy_raz` |
| `last_seen` | `last_seen`, `time_last`, `last`, `last_seen_at`, `seen_last`, `zone_time_last`, `timestamp`, `entry_timestamp`, `ostatnia_obserwacja`, `ostatni_raz` |
| `source` | `source`, `src`, `sensor`, `sensor_id`, `origin`, `feed`, `zrodlo` |
| `type` | `type`, `rrtype`, `record_type`, `qtype`, `rtype`, `typ` |
| `value` | `value`, `rdata`, `data`, `answer`, `answers`, `target`, `content`, `wartosc`, `dane` |
| `count` | `count`, `hits`, `seen`, `liczba` |
| `cert_cn` | `common_name`, `subject_cn`, `cn`, `subject`, `cert_subject`, `cert_cn` |
| `cert_sans` | `name_value`, `sans`, `san`, `subject_alt_names`, `dns_names`, `alt_names`, `names`, `cert_sans` |
| `cert_issuer` | `issuer`, `issuer_name`, `issuer_cn`, `cert_issuer`, `wystawca` |
| `cert_not_before` | `not_before`, `valid_from`, `cert_not_before`, `wazny_od` |
| `cert_not_after` | `not_after`, `valid_to`, `expires`, `cert_not_after`, `wazny_do` |
| `cert_serial` | `serial`, `serial_number`, `cert_serial` |
| `cert_sha256` | `sha256`, `fingerprint`, `fingerprint_sha256`, `sha256_fingerprint`, `cert_sha256` |

Reguły:

- Typ rekordu `A`/`AAAA` daje parę nazwa–adres, `CNAME` alias, `PTR` parę adres–nazwa. Typy `NS`, `MX`, `TXT`, `SOA` są pomijane i liczone w `skipped`.
- Rekord z polami certyfikatu daje po jednym fakcie na każdą nazwę z certyfikatu. Nazwa `*.domena` jest zapisana jako `domena` z flagą `wildcard`.
- Czas: RFC 3339, format crt.sh bez strefy, sama data, `dd.mm.rrrr`, czas Unix w sekundach albo milisekundach.
- Błędny wiersz trafia do raportu pliku (numer, wartość, powód) i nie przerywa importu.

### 3.3 Wynik: fakty, podpowiedzi, kandydaci

`Collect` łączy źródła i zwraca:

| Element | Znaczenie | Co robi z nim Czujka |
| --- | --- | --- |
| `Facts` | fakty wewnątrz zakresu, bez duplikatów, każdy ze źródłem | historia: skąd znamy nazwę |
| `Hints` | nazwy (i porty z sensora) dla adresu w zakresie | dopisuje nazwy do hosta; kolektor HTTP może zapytać o właściwy wirtualny host |
| `Candidates` | adres w zakresie, którego nie ma w inwentarzu, albo nazwa w domenie zakresu bez znanego adresu | pokazuje analitykowi; **celem staje się dopiero po potwierdzeniu** |
| `OutOfScope` | fakty spoza zakresu | pokazuje jako informację; nigdy nie tworzy kandydata |

Reguła zakresu chroni przed skanowaniem cudzej sieci. Gdy fakt ma adres, **o zakresie decyduje adres**. Nazwa organizacji, która wskazuje na obcy adres (na przykład usługa w chmurze), trafia do `OutOfScope`. Ani ten adres, ani ta nazwa nie zostają kandydatem.

Wynik dla pięciu plików testowych (`go test ./internal/passive -run TestCollectCandidatesAndHints -v`):

```text
5 files -> 22 facts in scope, 4 out of scope, 6 address candidates, 7 name candidates, 9 hints
```

Prawdziwe zapytanie PTR z testu `TestPTRLookupOfLocalhost`:

```text
real PTR lookup: 127.0.0.1 -> localhost (kind=ptr, source=ptr)
```

Stan integracji: pakiet jest gotowy i przetestowany. Podłączenie do bazy i do interfejsu (ekran kandydatów, przycisk „dodaj do celów") należy do warstwy API.

## 4. DefectDojo

### 4.1 Ustawienia

Punkty API: `GET`/`PUT /settings/defectdojo`, `POST /settings/defectdojo/test`, `POST /findings/export/defectdojo`.

| Pole | Znaczenie |
| --- | --- |
| `url` | adres instancji, na przykład `https://dojo.example` |
| `api_key` | token API v2 (tylko do zapisu; odczyt zwraca `api_key_set`) |
| `product_type_name`, `product_name`, `engagement_name` | gdzie zapisać dane; domyślnie `Czujka`, `Czujka – Attack Surface`, `Czujka discovery` |
| `verify_tls` | weryfikacja certyfikatu serwera; wyłącz tylko dla instancji z certyfikatem samopodpisanym |
| `auto_export`, `min_interest` | eksport po każdym przebiegu i próg oceny ciekawości |

Test połączenia zwraca nazwę użytkownika i wersję serwera, na przykład „Połączono z DefectDojo 3.5.202 jako admin". Błędy mają jasne komunikaty: zły token, zły adres, błąd TLS, przekroczony czas, odmowa połączenia. Komunikat podaje tylko status HTTP, bez treści odpowiedzi serwera. Klient nie podąża za przekierowaniem (token poszedłby z nim pod nowy adres): odpowiedź 3xx to błąd z prośbą o właściwy adres. Zapisany token trafia tylko pod zapisany adres; test albo zapis z innym adresem wymaga podania tokenu. Adresy integracji wpisuje administrator i mogą celowo wskazywać sieć wewnętrzną.

### 4.2 Co i jak jest eksportowane

Klient szuka typu produktu, produktu i engagementu po nazwie. Tworzy je tylko wtedy, gdy ich nie ma.

Obserwacje trafiają do testu `Czujka findings`:

| Pole w DefectDojo | Wartość |
| --- | --- |
| `title` | tytuł obserwacji |
| `severity` | `Info`, `Low`, `Medium`, `High` według wagi w Czujce (automatyczne obserwacje mają `Info` albo `Low`) |
| `description` | opis, host, port, URL, typ, ocena ciekawości, daty pierwszej i ostatniej obserwacji, lista dowodów |
| endpoint | adres IP, port i protokół (`http://10.0.0.5`, `tcp://10.0.0.7:6379`) |
| `tags` | `czujka`, typ obserwacji, tagi analityka |
| `unique_id_from_tool` | klucz obserwacji, na przykład `admin-panel/10.66.3.17/tcp-8080/jenkins` |

Status z Czujki ustawia flagi:

| Status w Czujce | DefectDojo |
| --- | --- |
| `triaged` | `verified = true` |
| `false_positive` | `active = false`, `false_p = true` |
| `resolved` | `active = false`, `is_mitigated = true` |
| `accepted` | tag `accepted` |

Wartości ciasteczek i inne sekrety nie występują w dowodach, więc nie mogą trafić do DefectDojo.

### 4.3 Drugi eksport nie tworzy duplikatów

Trasę wybraliśmy przez test na żywej instancji DefectDojo 3.5.202:

- Nowe obserwacje idą przez `/import-scan` (pierwszy eksport) albo `/reimport-scan` (kolejne) z typem skanu „Generic Findings Import". To jedyna trasa, która tworzy endpointy: w wersji 3.x nie ma `POST /endpoints`, a `POST /findings` nie przyjmuje endpointów.
- Obserwacje, które już istnieją, klient znajduje po `unique_id_from_tool` i aktualizuje przez `PATCH /findings/{id}`. Wysyła tylko pola, które się zmieniły.
- Sam `/reimport-scan` nie wystarcza. Dopasowuje po skrócie tytułu i opisu, więc obserwacja ze zmienionym opisem powstałaby drugi raz. W teście dało to 4 duplikaty.

Wyniki z żywej instancji:

| Eksport | Utworzone | Zaktualizowane | Błędy |
| --- | --- | --- | --- |
| pierwszy, 4 obserwacje | 4 | 0 | 0 |
| drugi, te same dane | 0 | 4 | 0 |
| trzeci: jeden zmieniony opis, jeden zmieniony status, jedna nowa obserwacja | 1 | 4 (2 zmienione przez `PATCH`) | 0 |

### 4.4 Plik nmap XML

Eksport XML przebiegu (`POST /runs/{id}/export/defectdojo`) trafia do testu typu „Nmap Scan". Kluczem testu jest profil i engagement: tytuł `Czujka nmap: profil <id>` (przebieg bez profilu: `Czujka nmap: przebieg <id>`). Pierwsze wysłanie dla profilu robi import i tworzy test (`mode: "import"`). Każdy kolejny przebieg tego profilu robi reimport do tego samego testu z `close_old_findings=true` (`mode: "reimport"`): pozycje, których nowy plik już nie ma, DefectDojo zamyka (`closed` w odpowiedzi). Id profilu, nie nazwa, trzyma klucz stały po zmianie nazwy. Przebiegi wysyłaj w kolejności czasu: starszy przebieg wysłany po nowszym zamknie to, co widział tylko nowszy. Parser DefectDojo tworzy jedną pozycję na numer otwartego portu, z endpointem dla każdego hosta.

### 4.4a Adres linków (`link_url`)

Czujka może łączyć się z DefectDojo pod adresem, którego przeglądarka analityka nie otworzy (np. `http://host.docker.internal:18080` z kontenera). Pole `link_url` w ustawieniach DefectDojo to publiczny adres DefectDojo. Z niego Czujka buduje każdy link: `dojo_url` obserwacji, `test_url` oraz linki produktu i engagementu. Puste pole oznacza adres `url`.

### 4.4b Awaria w środku eksportu

Gdy DefectDojo przyjmie `/import-scan`, a potem przestanie odpowiadać przed odczytem kontrolnym, Czujka nie zna id nowych pozycji. Odpowiedź to 502 z kodem `dojo_unconfirmed` i tekstem „Wysłano, nie potwierdzono: powtórz eksport.". Nie ma w niej surowego błędu Go. Ponowny eksport znajduje te pozycje po kluczu (`unique_id_from_tool`) i łączy je bez duplikatów. To samo robi pobranie statusów (`POST /defectdojo/pull`, pole `linked`); ono niczego w DefectDojo nie tworzy. Test `TestUnconfirmedExportIsLinkedByKeyLater` zrywa połączenie po imporcie i sprawdza oba sposoby.

### 4.5 Ograniczenia

- DefectDojo sam zmienia wielkość liter w tytułach („Panel Administracyjny: …"), także po `PATCH`.
- Aktualizacja to jedno żądanie `PATCH` na zmienioną obserwację, po kolei. Niezmienione obserwacje nie kosztują żądania. Pierwszy eksport idzie w paczkach po 500.
- Integracja była sprawdzona z wersjami 3.5.202 (lokalnie, zapis i odczyt) i 3.5.201 (publiczne demo, tylko odczyt, rozdz. 4.10). Ścieżka dla wersji 2.x (odczyt endpointów) jest napisana, ale nie była uruchomiona na prawdziwym serwerze 2.x.
- DefectDojo 3.5 nie zapisuje portu w adresie `ssh://host:22` (zostaje `ssh://host`). Import takiej pozycji do Czujki daje port 0.
- DefectDojo 3.5 odrzuca zmianę znacznika `mitigated` (`EDITABLE_MITIGATED_DATA=false`). Klient ustawia tylko `is_mitigated` i `active`; czas zamknięcia wpisuje DefectDojo.

### 4.6 Format „Generic Findings Import" w plikach

`internal/interchange` czyta i zapisuje obserwacje w formacie DefectDojo „Generic Findings Import". Listę pól wzięliśmy z parsera DefectDojo 3.5.202 (`dojo/tools/generic/json_parser.py`, `csv_parser.py`, odczytane w kontenerze). Parser JSON odrzuca cały plik, gdy obiekt ma pole spoza listy dozwolonych; test `TestDojoGenericJSONOnlyAllowedKeysAndRoundTrip` pilnuje, że Czujka pisze tylko dozwolone pola.

| Funkcja | Działanie |
| --- | --- |
| `WriteDojoGenericJSON(w, findings)` | `{"name","type","findings":[…]}` |
| `WriteDojoGenericCSV(w, findings)` | kolumny `Date, Title, CweId, Url, Severity, Description, Mitigation, Impact, References, Active, Verified, FalsePositive, IsMitigated, Duplicate` |
| `ToDojoGeneric(f)` | jedna obserwacja jako obiekt formatu |
| `ImportFindings(r, FindingsOptions)` | odczyt z wykryciem formatu, wynik `[]model.Finding` i `FindingsReport` |
| `DetectFindings(head)` | nazwa formatu po pierwszych bajtach |
| `FlagsOf(status)`, `StatusFromDojo(flags, tag)` | mapowanie statusów w obie strony |

Pola obiektu JSON, które pisze Czujka:

| Pole | Wartość |
| --- | --- |
| `title`, `description`, `severity`, `date` | tytuł, opis z dowodami, `Info`/`Low`/`Medium`/`High`, data pierwszej obserwacji |
| `cwe`, `mitigation`, `impact` | z tabeli według typu obserwacji (na przykład `expired-cert` → CWE-298, `database-exposed` → CWE-668, `interesting-cookie` → CWE-1004) |
| `references` | URL usługi |
| `active`, `verified`, `false_p`, `is_mitigated` | ze statusu (tabela w 4.8) |
| `unique_id_from_tool`, `vuln_id_from_tool` | klucz i typ obserwacji |
| `service` | `port/tcp` |
| `endpoints` | `[{"protocol","host","port"}]`, host to zawsze adres IP |
| `tags` | `czujka`, typ, tagi analityka |

CSV DefectDojo nie ma kolumny na `unique_id_from_tool` ani na tagi. Klucz jedzie w opisie („Klucz: …"), skąd import Czujki go odczytuje.

Odczyt przyjmuje pięć formatów:

| Format (`FindingsReport.format`) | Rozpoznanie |
| --- | --- |
| `dojo-generic-json` | obiekt z kluczem `findings` |
| `dojo-generic-csv` | nagłówek z kolumnami `Date`, `Title`, `Severity`, `Description` |
| `dojo-api-json` | lista z API DefectDojo (`GET /api/v2/findings/`: `count`, `results`, opcjonalnie `prefetch`), jedna pozycja albo tablica pozycji |
| `czujka-findings-json` | eksport Czujki `GET /api/v1/export/findings.json` (tablica `model.Finding`) |
| `czujka-findings-csv` | eksport Czujki `GET /api/v1/export/findings.csv` (te same kolumny; znak `'` przed formułą jest zdejmowany) |

Host i port obserwacji, w tej kolejności: endpoint (napis URI, obiekt `host/port/protocol`, identyfikator rozwiązany przez `prefetch=endpoints`, także `location_value` z DefectDojo 3.x), kolumna `Url`, wiersz „**Host:** … · **Port:** …" z opisu Czujki, klucz Czujki (`typ/IP/tcp-port/…`). Bez żadnego z nich wiersz jest błędny z powodem „nie można ustalić hosta …".

Klucz i znacznik źródła:

- Pozycja wyeksportowana kiedyś przez Czujkę (klucz w formacie Czujki) wraca z tym samym kluczem i typem. `manual = false`.
- Pozycja innego narzędzia dostaje `type = imported`, `manual = true` (analiza po przebiegu jej nie rozwiązuje), tag `import:<źródło>` (`import:defectdojo`, `import:defectdojo-generic` albo nazwa z `FindingsOptions.Source`) i stały klucz `import/<IP>/tcp-<port>/<skrót>` z `unique_id_from_tool` albo z tytułu, IP i portu. Drugi import tego samego pliku daje te same klucze.
- `Critical` z DefectDojo staje się `high`. CWE, wpływ, zalecenia i odnośniki są dopisywane do opisu.
- Identyfikator DefectDojo trafia do `dojo_id`.

Błędne wiersze nie przerywają importu. Powody po polsku: „brak tytułu", „nieznana waga …", „niepoprawna data …", „nie można ustalić hosta …", „powtórzona obserwacja …", „niepoprawny port …", „niepoprawny CweId …".

Wywołujący (trasa API) zamienia IP na identyfikator hosta i zapisuje obserwacje przez `UpsertFindings` po kluczu.

### 4.7 Status z DefectDojo do Czujki

`Client.PullStatus(ctx, []LocalStatus)` czyta stan wyeksportowanych obserwacji (te z `dojo_id`) przez `GET /findings/{id}/` i zwraca `StatusPull`: propozycje zmian, konflikty, pozycje usunięte w DefectDojo. Niczego nie zapisuje. Czysta funkcja `ProposeStatusUpdates` robi porównanie i ma testy.

| Flagi w DefectDojo (pierwsza pasująca reguła) | Status w Czujce |
| --- | --- |
| `false_p` | `false_positive` |
| `risk_accepted` | `accepted` |
| `out_of_scope` | `accepted` |
| `is_mitigated` | `resolved` |
| `active = false` | `resolved` |
| tag `accepted` | `accepted` |
| `active` i `verified` | `triaged` |
| `active`, bez `verified` | `new` |

Kto wygrywa:

| Status w Czujce | Wynik |
| --- | --- |
| `new` albo `resolved` (ustawił skaner) | wygrywa DefectDojo: propozycja zmiany |
| ustawiony przez analityka, zmiana w DefectDojo (`last_status_update`) nowsza niż edycja (`LocalStatus.ChangedAt` albo `Overrides["status"].At`) | wygrywa DefectDojo: propozycja zmiany |
| ustawiony przez analityka, edycja nowsza albo czas edycji nieznany | wygrywa analityk: wpis w `conflicts` |
| DefectDojo w stanie domyślnym (aktywna, niezweryfikowana) | wygrywa analityk: stan domyślny nie jest decyzją |

Sprawdzone na lokalnym DefectDojo 3.5.202: po `PATCH` w DefectDojo (`false_p`, `verified`, `out_of_scope`) pull zwrócił trzy propozycje: `new → false_positive`, `new → triaged`, `new → accepted`.

### 4.8 Zamykanie i ponowne otwieranie

`Client.SyncLifecycle(ctx, findings, now)`:

- obserwacja Czujki ze statusem `resolved` (już niewidoczna), której pozycja w DefectDojo jest otwarta: `PATCH is_mitigated = true, active = false` i notatka „Czujka: obserwacja … nie jest już widoczna (ostatnio widziana …, przebieg #…). Oznaczona jako usunięta.";
- obserwacja znów widoczna (`new` albo `triaged`), której pozycja jest zamknięta: `PATCH is_mitigated = false, active = true` i notatka „… jest znów widoczna … Ponownie otwarta.";
- pozycje oznaczone w DefectDojo jako fałszywy alarm, zaakceptowane albo poza zakresem nie są otwierane ponownie.

Po stronie Czujki obowiązuje jedna zasada dla ustaleń silnika i ustaleń z reguł polityki. `accepted` i `false_positive` (od analityka albo z pobrania statusów) nie zmienia żaden skan. Ustalenie `resolved` wraca do `new` tylko wtedy, gdy przyczynę zaobserwowano po rozwiązaniu, raz na jedno rozwiązanie, z wpisem `finding.reopen` w dzienniku audytu. Synchronizacja przenosi to otwarcie do DefectDojo. Samo ponowne sprawdzenie reguł na tych samych danych niczego nie otwiera.

Sprawdzone na lokalnej instancji: zamknięcie dało `active: False, is_mitigated: True, mitigated: 2026-11-21T13:15:56Z` i notatkę; ponowne otwarcie `active: True, is_mitigated: False` i drugą notatkę. Pierwsza próba z polem `mitigated` dostała 400 („Editing mitigated timestamp is disabled"), dlatego klient go nie wysyła.

Status przy eksporcie (`FlagsOf`):

| Status w Czujce | `active` | `verified` | `false_p` | `is_mitigated` |
| --- | --- | --- | --- | --- |
| `new` | ✓ | – | – | – |
| `triaged` | ✓ | ✓ | – | – |
| `accepted` | ✓ | – | – | – (tag `accepted`) |
| `false_positive` | – | – | ✓ | – |
| `resolved` | – | – | – | ✓ |

`accepted` jedzie jako tag, bo DefectDojo akceptuje ryzyko tylko przez obiekt Risk Acceptance albo przy włączonej prostej akceptacji w produkcie.

### 4.9 Produkt i engagement według zakresu, załączniki

- `ScopeMapping{scope_id, product_type_name, product_name, engagement_name}`: `TargetFor(scopeIDs, maps, def)` wybiera cel dla obserwacji, `GroupByTarget` dzieli listę na grupy do osobnych eksportów. Puste nazwy biorą wartość domyślną.
- `Client.AttachFile(ctx, "tests"|"findings", id, title, name, data)` wysyła plik przez `POST /api/v2/{tests|findings}/{id}/files/`. `AttachEvidence` dołącza do każdej wyeksportowanej obserwacji plik tekstowy z dowodami (`EvidenceText`), `AttachRunXML` dołącza nmap XML przebiegu do testu. Sprawdzone lokalnie: 4 pliki dowodów i plik XML w teście 19.

### 4.10 Wersje DefectDojo

Test połączenia na publicznym demo `https://demo.defectdojo.org`, tylko odczyt: jedno `POST /api-token-auth/`, potem wyłącznie `GET`.

```text
dojoprobe test (demo)   → {"ok": true, "message": "Połączono z DefectDojo 3.5.201 jako admin", "version": "3.5.201"}
OpenAPI demo 3.5.201 / lokalnie 3.5.202: trasy klienta (user_profile, product_types, products, engagements, tests,
  findings, findings/{id}, findings/{id}/notes, findings/{id}/files, tests/{id}/files, import-scan, reimport-scan,
  location_findings, endpoints/{id}) mają te same metody; schematy Finding, PatchedFinding, ImportScan, Note: bez różnic
```

Pierwsze 400 pozycji na demo to obserwacje SAST bez endpointów (kod, pliki). Import Czujki odrzuca je z powodem „nie można ustalić hosta", bo nie dotyczą adresu w sieci.

### 4.11 Zapis sprawdzenia na lokalnym DefectDojo 3.5.202

```text
$ dojoprobe generic -in lab/defectdojo/sample-findings.json -to json > czujka-generic.json   (i -to csv)
$ curl -X POST /api/v2/import-scan/ -F scan_type="Generic Findings Import" -F file=@czujka-generic.json …
  → test 19: statistics.after.total 4 (3 Info, 1 Low)
$ … -F file=@czujka-generic.csv → test 20: 4 pozycje
$ dojoprobe list -test 19
  #70 Low active=true Baza Danych Dostępna Z Sieci: Redis … endpoints=[tcp://172.31.250.4:6379] key=database-exposed/172.31.250.4/tcp-6379
$ curl /api/v2/findings/?test=19&prefetch=endpoints > dd-api.json; dojoprobe fimport -in dd-api.json
  format dojo-api-json: 4 findings, 0 skipped
  low new 172.31.250.4:6379 manual=false type=database-exposed key=database-exposed/172.31.250.4/tcp-6379 dojo=#70
$ (plik innego narzędzia → DefectDojo test 21 → API) dojoprobe fimport -in dd-api-foreign.json
  medium new 10.66.5.20:3000 manual=true type=imported key=import/10.66.5.20/tcp-3000/df60f976c8ae9a72 dojo=#75
  high   new 10.66.5.21:0    manual=true type=imported key=import/10.66.5.21/tcp-0/0524dba464a72986 dojo=#76
```

Odpowiedzi API z tego sprawdzenia leżą w `internal/interchange/testdata/dojo/` i są danymi testów.

## 5. Lokalne laboratorium DefectDojo

Katalog `lab/defectdojo` uruchamia prawdziwy DefectDojo z oficjalnych obrazów. Instancja słucha tylko na `127.0.0.1:18080`. Hasło i token są jawne, więc instancja służy wyłącznie do testów i demo.

```sh
docker compose -f lab/defectdojo/docker-compose.yml up -d

export DOJO_URL=http://127.0.0.1:18080
export DOJO_TOKEN=c2a1b0f4d7e84c5aa3f29b6e0d1c7f58a4e3b2d1

go run ./cmd/dojoprobe test                                             # połączenie i wersja
go run ./cmd/dojoprobe push -file lab/defectdojo/sample-findings.json   # eksport obserwacji
go run ./cmd/dojoprobe push -file lab/defectdojo/sample-findings.json   # drugi eksport: 0 nowych
go run ./cmd/dojoprobe nmap -file lab/defectdojo/sample-nmap.xml -title "Czujka nmap run 1"
go run ./cmd/dojoprobe list -test <test_id>                             # pozycje z endpointami

docker compose -f lab/defectdojo/docker-compose.yml down                # dane zostają w wolumenach
```

Login, hasło i pełny opis: `lab/defectdojo/README.md`. Pliki przykładowe pochodzą z prawdziwego skanu nmap trzech kontenerów.

`cmd/dojoprobe` to narzędzie deweloperskie. Używa tych samych pakietów co produkt.

| Polecenie | Działanie |
| --- | --- |
| `test` | test połączenia, wersja serwera |
| `derive -in plik` | import wyników i wyprowadzenie obserwacji (JSON na wyjściu) |
| `convert -in plik -to xml\|json\|csv` | import i eksport w innym formacie |
| `push -file obserwacje.json` | eksport obserwacji do DefectDojo |
| `nmap -file skan.xml -title nazwa` | wysłanie nmap XML jako „Nmap Scan" |
| `list -test id` | pozycje testu z endpointami, kluczami i tagami |
| `generic -in obserwacje.json -to json\|csv` | zapis w formacie Generic Findings Import |
| `fimport -in plik` | import obserwacji (Generic JSON/CSV, lista z API DefectDojo, eksport Czujki) |
| `pull -file obserwacje.json` | propozycje statusów z DefectDojo (obserwacje z `dojo_id`) |
| `lifecycle -file obserwacje.json` | zamknięcie rozwiązanych i ponowne otwarcie widocznych |
| `attach -file obserwacje.json [-test id -in skan.xml]` | pliki dowodów i nmap XML |
