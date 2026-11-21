# Sygnatury Czujki

Ten dokument opisuje język sygnatur (DSL), tryb bezpieczny walidatora, sposób liczenia pewności, retro-hunt, wbudowaną bibliotekę i narzędzie `fpprobe`.

Kod: `internal/sig` (silnik), `internal/httpfp` (kolektor HTTP/TLS), `signatures/*.yaml` (biblioteka wbudowana), `internal/sigwire` (połączenie silnika z bazą i API), `cmd/fpprobe` (narzędzie wiersza poleceń).

Szybki start: [rozdział 13](#13-jak-napisać-własną-sygnaturę-w-2-minuty) pokazuje siedem gotowych przykładów. Obce formaty (JSON, mapa po nazwie, szablony nuclei) opisuje [rozdział 14](#14-zgodność-z-innymi-formatami).

## 1. Zasada: tylko bezpieczna detekcja

Sygnatura stwierdza **obecność** cechy. Nigdy nie loguje się, nie wysyła ładunków i nie zgaduje haseł.

- Kolektor wysyła tylko `GET` i `HEAD`. Kod kolektora odrzuca każdą inną metodę (`methodAllowed`).
- Żądanie nie ma treści, własnych nagłówków, ciasteczek ani danych logowania. Kolektor nie odsyła ciasteczek, które dostał.
- Kolektor łączy się zawsze z adresem IP i portem ze skanu. Przekierowanie na inny host, port albo protokół jest zapisane, ale nie jest wykonywane.
- Sygnatura może dodać najwyżej 5 dodatkowych ścieżek. Każda ścieżka przechodzi przez walidator (rozdział 5).
- Dowód dopasowania ciasteczka nie zawiera jego wartości. Zawiera nazwę, długość i flagi.

## 2. Przykład

```yaml
id: wordpress
name: WordPress
category: cms
description: System CMS
tags: [php]
interest: 10
classes: []
cpe: cpe:2.3:a:wordpress:wordpress
implies: [PHP]
requests:
  - path: /wp-login.php
match:
  condition: any
  min_confidence: 0.5
  rules:
    - {type: meta, name: generator, regex: '^WordPress', weight: 0.9}
    - {type: body, contains: 'wp-content/', weight: 0.5}
    - {type: cookie, name_regex: '^wordpress_', weight: 0.7}
    - {type: path, path: /wp-login.php, status: 200, contains: 'user_login', weight: 0.9}
    - {type: favicon, mmh3: [-235701012], weight: 0.9}
version:
  - {type: meta, name: generator, regex: 'WordPress ([0-9.]+)'}
```

Najprostsza poprawna sygnatura ma trzy wiersze (forma skrócona):

```yaml
id: moja-aplikacja
name: Moja aplikacja
body: 'Powered by MojaAplikacja'
```

## 3. Pola sygnatury

| Pole | Znaczenie | Domyślnie |
| --- | --- | --- |
| `id` (alias `slug`) | Identyfikator: małe litery, cyfry, `-`, `_`, `.`. Gdy go brak, powstaje z `name`. | z nazwy |
| `name` | Nazwa technologii albo ustalenia. | wymagane (albo `id`) |
| `category` | `cms, framework, app-server, web-server, iot, panel, database, devops, language, proxy, security, os, library, environment, header, cookie, other` | `other` |
| `description` | Opis dla analityka. | puste |
| `tags` | Lista etykiet. | puste |
| `interest` | Waga 0–100 do oceny „co jest ciekawe”. | 0 |
| `classes` | Klasy usługi: `admin-panel, login, staging, iot, default-page, api, dev-tool, database, remote-access, directory-listing, error-page` | puste |
| `cpe` | CPE 2.3 bez wersji. Silnik dopisuje wykrytą wersję. | puste |
| `implies` | Technologie, które wynikają z tej (np. WordPress → PHP). Pewność × 0,9. | puste |
| `aliases` | Inne nazwy tej samej technologii, np. nazwa produktu z nmap (`Apache httpd`). | puste |
| `technology` | Nazwa technologii, gdy jest inna niż `name` (kilka sygnatur na jedną technologię). `false`: sygnatura jest ustaleniem, nie technologią. | `name` |
| `enabled` | Czy sygnatura jest włączona po załadowaniu. | `true` |
| `requests` | Dodatkowe bezpieczne ścieżki GET (najwyżej 5). Ścieżki z reguł `path` są dodawane same. | puste |
| `match` | `condition` (`any` albo `all`), `min_confidence` (0–1), `rules` (lista reguł). | `any`, 0,3 |
| `version` | Lista reguł, które wyciągają wersję. Pierwsza grupa wyrażenia to wersja. | puste |

Sygnatury kategorii `header`, `cookie` i `environment` bez pola `technology` są ustaleniami: trafiają do listy dopasowań, ale nie do listy technologii.

Jeden plik może mieć wiele sygnatur: jako lista YAML, pod kluczem `signatures:` albo jako kolejne dokumenty (`---`).

## 4. Reguły

### 4.1 Typy reguł

| Typ | Co sprawdza | Dodatkowe pola | Waga domyślna |
| --- | --- | --- | --- |
| `header` | Nagłówek odpowiedzi. | `name`, `name_regex` | 0,6 |
| `cookie` | Ciasteczko: nazwa, wartość i flagi. | `name`, `name_regex`, `secure`, `http_only`, `same_site` | 0,6 |
| `body` | Treść strony głównej (pierwsze 64 KiB). | – | 0,4 |
| `title` | Tytuł strony. | – | 0,5 |
| `meta` | Znacznik `<meta>`. | `name` (domyślnie `generator`) | 0,8 |
| `favicon` | Skrót ikony. | `mmh3` (lista liczb, styl Shodan), `sha256` | 0,9 |
| `path` | Odpowiedź na dodatkową ścieżkę. | `path`, `status`, `field` (`body`, `title`, `header`, `location`) | 0,8 |
| `status` | Kod HTTP strony głównej. | `status` (liczba albo lista) | 0,3 |
| `banner` | Baner usługi (np. SSH, FTP, SMTP). | – | 0,6 |
| `service` | Wynik nmap. | `field`: `name`, `product`, `version`, `extra_info`, `cpe` | 0,7 |
| `tls` | Certyfikat i sesja TLS. | `field`: `subject`, `issuer`, `san`, `org`, `version`, `cipher` | 0,5 |
| `url` | Adres końcowy po przekierowaniach. | – | 0,4 |
| `redirect` | Cele przekierowań i nagłówek `Location`. | – | 0,4 |
| `hostname` | Nazwa hosta (nagłówek Host, rekord PTR, domena celu). | – | 0,3 |

Aliasy typów: `headers`, `cookies`, `html`, `content`, `generator`, `icon`, `request`, `status_code`, `nmap`, `cert`, `ssl`, `location`, `host`, `final_url`.

### 4.2 Dopasowania

| Pole | Znaczenie |
| --- | --- |
| `contains` | Tekst albo lista tekstów. Wystarczy jeden z listy. |
| `contains_all` | Lista tekstów. Muszą wystąpić wszystkie. |
| `regex` | Wyrażenie regularne w składni RE2 (albo lista; wystarczy jedno). |
| `equals` | Cała wartość jest równa tekstowi (albo jednemu z listy). |
| `exists: true` | Nagłówek, ciasteczko albo znacznik istnieje. To domyślne zachowanie reguły bez innego dopasowania. |
| `absent: true` | Rzeczy nie ma. Brak danych (np. ścieżka nigdy nie pobrana, usługa bez HTTP) nie liczy się jako „nie ma”. |
| `case_sensitive: true` | Rozróżnia wielkość liter. Domyślnie dopasowanie nie rozróżnia wielkości liter. |
| `not: true` | Weto. Gdy reguła pasuje, cała sygnatura nie pasuje. |
| `required: true` | Reguła musi pasować, inaczej sygnatura nie pasuje. |
| `weight` | Waga dowodu od 0 do 1. |
| `version_group` | Numer grupy wyrażenia, która zawiera wersję. W regułach `match` trzeba go podać. W liście `version` domyślnie 1. |

Kilka dopasowań w jednej regule łączy się spójnikiem „i”.

### 4.3 Forma skrócona

Klucz najwyższego poziomu o nazwie typu reguły tworzy regułę:

```yaml
id: przyklad
name: Przykład
title: 'Panel administracyjny'            # tekst = contains
header: 'X-Powered-By: Przyklad'          # "Nazwa: tekst"; sama nazwa = nagłówek istnieje
headers: {Server: '^przyklad/([0-9.]+)'}   # styl Wappalyzer: nazwa → wyrażenie; grupa 1 = wersja
cookies: {przyklad_session: ''}           # pusty wzorzec = ciasteczko istnieje
favicon: -235701012
body:
  - 'Powered by Przyklad'
  - {regex: 'przyklad-ui-[0-9]+\.js', weight: 0.7}
```

## 5. Tryb bezpieczny walidatora

`sig.Validate(yaml)` zwraca `model.SignatureValidation`: `ok`, listę problemów i listę ścieżek, które sygnatura by pobrała. Każdy problem ma poziom (`error` albo `warning`), ścieżkę YAML, komunikat po polsku z numerem wiersza i znacznik `safety`. Sygnatura z choć jednym błędem nie jest kompilowana i nie trafia do silnika.

Walidator odrzuca (błąd z `safety: true`):

| Reguła | Przykład odrzucony |
| --- | --- |
| Metoda inna niż GET i HEAD. | `method: POST` |
| Treść żądania, własne nagłówki, ciasteczka, dane logowania, parametry, ładunki. Każde nieznane pole żądania też jest błędem. | `body:`, `headers:`, `auth:`, `payloads:` |
| Ścieżka, która nie zaczyna się od `/`, adres URL, inny host. | `http://10.0.0.1/admin`, `//host/x`, `/a@host/` |
| Przejście katalogów i kodowanie procentowe. | `/../etc/hosts`, `/%2e%2e/`, `/a%00` |
| Znaki spoza listy dozwolonych. Ścieżka: litery, cyfry, `/ _ - . ~`. Parametry zapytania: litery, cyfry, `_ - . = &`, najwyżej 80 znaków. | `/a;id`, `/s?q=<script>` |
| Katalogi i pliki ukryte poza `/.well-known/`. | `/.env`, `/.git/config` |
| Ścieżki, które zmieniają stan. | `/logout`, `/actuator/shutdown`, `/reboot.cgi`, `/api/users?action=delete` |
| Ścieżki, które pobierają dane wrażliwe: kopie, klucze, konfigurację, zrzuty. | `/backup.zip`, `/db.sql`, `/id_rsa`, `/wp-config.php`, `/actuator/env`, `/actuator/heapdump` |
| Ścieżki z poleceniami. | `/cgi-bin/test?cmd=id` |
| Więcej niż 5 ścieżek w sygnaturze, ścieżka dłuższa niż 200 znaków. | – |
| Wyrażenie regularne dłuższe niż 500 znaków. | – |

Wyrażenia regularne są kompilowane silnikiem RE2 (pakiet `regexp` języka Go). RE2 działa w czasie liniowym i nie ma odwołań wstecznych ani asercji. Wzorce typu `(a+)+$` nie mogą zawiesić silnika. Wzorzec z odwołaniem wstecznym albo asercją jest błędem składni.

Ostrzeżenia nie blokują sygnatury: nieznane pole, nieznana kategoria albo klasa, reguła `path` bez sprawdzenia treści (ryzyko fałszywego trafienia na „miękkim 404”), próg `min_confidence` nie do osiągnięcia, ścieżka w `requests`, której nie używa żadna reguła.

Przykład:

```
$ fpprobe -validate evil.yaml
{ "ok": false, "issues": [
  { "level": "error", "path": "requests[0].method", "safety": true,
    "message": "metoda POST jest zabroniona: tryb bezpieczny dopuszcza tylko GET i HEAD (wiersz 5)" },
  { "level": "error", "path": "requests[0].body", "safety": true,
    "message": "pole „body” (treść żądania) jest zabronione: sygnatura może wysłać tylko GET lub HEAD bez treści, nagłówków i danych logowania (wiersz 6)" },
  { "level": "error", "path": "match.rules[0].path", "safety": true,
    "message": "niebezpieczna ścieżka „/../../etc/passwd”: przejście katalogów („..”) jest zabronione" } ] }
```

## 6. Pewność

Pewność dopasowania sygnatury to „noisy-OR” wag reguł pozytywnych, które pasują:

```
pewność = 1 − (1 − w1) · (1 − w2) · … · (1 − wn)
```

Przykład: reguły o wagach 0,5 i 0,7 dają 1 − 0,5 · 0,3 = 0,85. Sygnatura pasuje, gdy pewność jest nie mniejsza niż `min_confidence` (domyślnie 0,3). Reguła `not: true` nie dodaje pewności; jest wetem. Przy `condition: all` muszą pasować wszystkie reguły pozytywne.

### Technologie

`Match` zwraca trzy rzeczy: dopasowania, technologie i klasy.

- Jedna technologia powstaje z wszystkich sygnatur o tej samej nazwie (pole `technology`, `aliases`) i z produktu z nmap. Pewność technologii to noisy-OR pewności źródeł. Jedno źródło liczy się najwyżej jako 0,99.
- Produkt z nmap (`ServiceResult.Product`, `Version`, `Confidence`) jest dowodem o nazwie `nmap`.
- Wersje zgodne (`2.4` i `2.4.57`) łączą się; zostaje dokładniejsza.
- Wersje sprzeczne (`1.24.0` z nagłówka i `1.18.0` z nmap) obniżają pewność technologii: mnożnik 0,85. Zostaje wersja z silniejszym dowodem. Lista źródeł dostaje wpis `version-conflict:<wersja>`.
- Pole `implies` dodaje technologię pochodną ze źródłem `implied:<sygnatura>`.

### Klasy

Klasy pochodzą z pola `classes` dopasowanych sygnatur, z kategorii (`iot`, `database`) i z heurystyk klasyfikatora:

| Klasa | Heurystyka |
| --- | --- |
| `login` | pole hasła w HTML, nagłówek `WWW-Authenticate` |
| `admin-panel` | słowo „admin”, „panel administracyjny” itp. w tytule; ścieżka `/admin`, `/manager`, `/console` w adresie końcowym |
| `staging` | etykieta `dev`, `test`, `staging`, `uat`, `qa`, `preprod`, `sandbox`, `demo`, `beta` w nazwie hosta albo w certyfikacie; tytuł („środowisko testowe”, `[TEST]`); nagłówek `X-Environment` |
| `directory-listing` | „Index of /”, „Directory listing for /” |
| `api` | odpowiedź JSON na stronie głównej, Swagger/OpenAPI, GraphiQL |
| `error-page` | kod 5xx; kod 4xx (poza 401) z tytułem błędu albo krótką treścią |
| `database`, `remote-access` | nazwa usługi z nmap (mysql, postgresql, redis …; ssh, telnet, rdp, vnc …) |

## 7. Silnik

- `sig.NewBuiltinEngine()` ładuje bibliotekę wbudowaną w plik binarny (`go:embed`). `sig.Builtin()` zwraca ją jako `[]model.Signature` – baza danych może z niej zasiać tabelę sygnatur.
- `Engine.Load([]model.Signature)` podmienia cały zestaw (hot reload). Sygnatury błędne albo niebezpieczne są odrzucone i opisane w `LoadReport`; pozostałe działają od razu. Późniejszy rekord o tym samym `slug` zastępuje wcześniejszy, więc sygnatura własna może nadpisać wbudowaną.
- `Engine.SetEnabled(slug, bool)` włącza i wyłącza sygnaturę.
- `Engine.Match(svc)` nie bierze blokady. Zestaw sygnatur jest niezmienny i podmieniany atomowo, więc `Match` można wołać z wielu wątków w trakcie przeładowania.
- `Engine.ExtraPaths()` zwraca ścieżki włączonych sygnatur bez powtórzeń. Kolejność: najpierw ścieżki, których używa najwięcej sygnatur, potem według `interest`. Skaner może wziąć pierwsze N.
- `Engine.PathsFor(svc, limit)` (dodatek) układa ścieżki dla jednej usługi: najpierw te, których sygnatury mają już poparcie na stronie głównej.
- `Engine.MatchHost(svc, nazwy...)` (dodatek) to `Match` z nazwami hosta dla reguł `hostname`.

### Wydajność

Wszystkie teksty reguł `body` i teksty wymagane przez wyrażenia regularne (wyciągnięte z drzewa składni wyrażenia, także z alternatyw) trafiają do jednego automatu Aho-Corasick. Jedno przejście po treści strony mówi, które reguły w ogóle mogą pasować. Wyrażenie regularne uruchamia się tylko wtedy, gdy jego tekst wymagany jest w treści.

Pomiar (`go test ./internal/sig -bench . -benchtime 3s`, Apple M5 Pro, 386 sygnatur, 10 000 różnych usług, treść 4–24 KiB):

| Test | Czas na usługę | 10 000 usług |
| --- | --- | --- |
| `BenchmarkMatch` (1 rdzeń) | 0,89 ms | 8,9 s |
| `BenchmarkMatchParallel` (15 rdzeni) | 0,09 ms | 0,9 s |
| `BenchmarkMatchNoPrefilter` (bez automatu) | 43,9 ms | 439 s |

Automat przyspiesza dopasowanie około 50 razy.

### „Miękkie 404”

Reguła `path` nie pasuje, gdy odpowiedź na ścieżkę jest stroną zbiorczą: ta sama treść (ten sam skrót SHA-256) wróciła dla co najmniej 3 ścieżek albo jest identyczna ze stroną główną.

## 8. Retro-hunt

`sig.RetroHunt(yaml, []model.ServiceObservation)` sprawdza nową sygnaturę na zapisanych obserwacjach. Nie wysyła żadnego pakietu (`packets_sent: 0`): czyta zapisane nagłówki, ciasteczka, tytuł, fragment treści, skróty ikony, dane TLS, banery i odpowiedzi na ścieżki pobrane wcześniej.

Sygnatura najpierw przechodzi przez walidator. Sygnatura odrzucona daje pusty wynik i notatkę z powodem.

Gdy sygnatura potrzebuje ścieżki, której dana obserwacja nigdy nie pobrała, reguły `path` nie mogą tam zadziałać. Wynik mówi to wprost:

- `missing_paths` – brakujące ścieżki,
- `incomplete` – liczba obserwacji HTTP bez co najmniej jednej z nich,
- `notes` – notatka po polsku, np. „Sygnatura potrzebuje ścieżki /wp-login.php, której nie pobrano w 2 z 5 obserwacji. …”.

Te trzy pola dodano do `model.RetroHuntResult`.

W produkcie retro-hunt czyta obserwacje strumieniowo z bazy (`sigwire.RetroHunt`, `sig.Hunter`). W pamięci jest jedna obserwacja naraz, więc zużycie pamięci nie rośnie z liczbą obserwacji. Lista `hits` ma limit 5000 pozycji; `total_hits` podaje pełną liczbę trafień, a `truncated: true` mówi, że listę ucięto. Te dwa pola też dodano do `model.RetroHuntResult`. Pomiar jest w rozdziale 15.

## 9. Biblioteka wbudowana

386 sygnatur w 10 plikach. Test `TestBuiltinLibraryIsValid` ładuje każdy plik i nie przepuszcza żadnego błędu ani ostrzeżenia walidatora.

| Plik | Sygnatury | Zawartość |
| --- | --- | --- |
| `cms.yaml` | 41 | WordPress, Joomla, Drupal, TYPO3, Moodle, MediaWiki, DokuWiki, Ghost, Nextcloud, ownCloud, Roundcube, Zimbra, OWA, Confluence, Jira, instalatory |
| `frameworks.yaml` | 35 | Laravel, Symfony, Django, Rails, Spring Boot, ASP.NET, Express, Next.js, React, Vue, Angular, jQuery, Bootstrap |
| `servers.yaml` | 47 | nginx, Apache, IIS, Caddy, Tomcat, Jetty, WildFly, WebLogic, HAProxy, Traefik, Varnish, Cloudflare, strony domyślne |
| `panels.yaml` | 87 | phpMyAdmin, Adminer, Grafana, Kibana, Jenkins, GitLab, Gitea, Portainer, Keycloak, RabbitMQ, Prometheus, Swagger UI, Docker Registry, cPanel, Webmin, Proxmox |
| `iot.yaml` | 53 | kamery (Hikvision, Dahua, Axis), routery (MikroTik, Ubiquiti, TP-Link), drukarki, NAS (Synology, QNAP), UPS, BMC (iLO, iDRAC, Redfish), zapory |
| `university.yaml` | 32 | USOSweb, USOS API, APD, CAS, Shibboleth, DSpace, OJS, EPrints, dLibra, Omega-PSIR, Koha, EZproxy, BigBlueButton, JupyterHub, Jupyter, RStudio |
| `environment.yaml` | 24 | znaczniki staging/dev/test, Django DEBUG, Laravel Ignition, profiler Symfony, phpinfo, Actuator, debugger Werkzeug, ślady stosu, pprof, lista plików |
| `headers.yaml` | 20 | wersje w nagłówkach, nagłówki debugowania, wyciek serwera zaplecza i adresów prywatnych, błędy CORS, logowanie po HTTP, brak CSP/HSTS na stronie logowania |
| `cookies.yaml` | 11 | sesja bez `Secure`/`HttpOnly`, JWT w ciasteczku, BIG-IP, Shiro `rememberMe`, ciasteczka load balancerów i WAF |
| `services.yaml` | 36 | usługi inne niż HTTP: OpenSSH, Dropbear, Telnet, FTP, SMTP, bazy danych, RDP, VNC, SMB, LDAP, MQTT, protokoły przemysłowe, JDWP |

Skróty ikon (`mmh3`) w bibliotece pochodzą wyłącznie z prawdziwych instancji uruchomionych w laboratorium (tabela w rozdziale 11). Biblioteka nie zawiera skrótów spisanych z pamięci ani z internetu.

## 10. Kolektor HTTP/TLS

`httpfp.Collector` implementuje `model.Fingerprinter`.

- Wybór TLS: najpierw TLS, gdy nmap mówi `ssl`/`https` albo port jest typowy dla TLS (443, 8443, 9443 …). Przy błędzie kolektor próbuje drugiego protokołu. Odpowiedź 400 „plain HTTP request was sent to HTTPS port” też przełącza na TLS.
- `GET /` z ustawionym `User-Agent`, nagłówkiem `Host` i SNI. Połączenie idzie zawsze na adres IP ze skanu.
- Przekierowania są obsługiwane ręcznie, do `MaxRedirects`, tylko w obrębie tego samego protokołu, hosta i portu. Każdy krok jest zapisany w `Redirects`.
- Treść: limit odczytu (domyślnie 256 KiB), ręczne rozpakowanie gzip/deflate z limitem wyjścia (ochrona przed „bombą”), konwersja kodowania znaków na UTF-8, limit czasu na powolne i nieskończone odpowiedzi.
- Wypełnia: status, tytuł, nagłówki, ciasteczka (flagi, długość i skrót wartości), `Server`, `X-Powered-By`, generator, długość, SHA-256, simhash treści, fragment treści, skróty ikony (mmh3 w stylu Shodan i SHA-256), czas odpowiedzi.
- TLS: wersja, szyfr, CN, organizacja, SAN, wystawca, daty, numer seryjny, SHA-256 certyfikatu, samopodpisany, wygasły, dni do końca ważności, niezgodność nazwy, typ i długość klucza. Kolektor nie odrzuca niepoprawnych certyfikatów – zapisuje je.
- Dodatkowe ścieżki trafiają do `Paths` (`PathProbe`). Kolektor nie podąża tam za przekierowaniami i kończy po 2 kolejnych błędach.

## 11. fpprobe i laboratorium

```
fpprobe -addr 127.0.0.1:8080 [-host nazwa] [-tls] [-paths] [-max-paths 20] [-brief] [-full] [-sigs plik.yaml]
fpprobe -validate plik.yaml
fpprobe -convert plik          # obcy format → YAML Czujki (rozdział 14)
fpprobe -list
```

`fpprobe` wypisuje odcisk i dopasowania jako JSON. Z `-paths` robi dwa przejścia: stronę główną, a potem ścieżki wybrane przez `PathsFor`. `-brief` daje krótkie podsumowanie. Bez `-full` wynik nie zawiera fragmentów treści ani wartości ciasteczek.

Laboratorium: `cmd/fpprobe/testlab/docker-compose.yml` uruchamia 27 prawdziwych aplikacji na `127.0.0.1` (projekt `czfp`).

```
docker compose -p czfp -f cmd/fpprobe/testlab/docker-compose.yml up -d
go run ./cmd/fpprobe -addr 127.0.0.1:19105 -paths -brief
docker compose -p czfp -f cmd/fpprobe/testlab/docker-compose.yml down -v
```

Wynik z 2026-11-21 (`fpprobe -addr 127.0.0.1:<port> -paths`, obrazy `latest`):

| Aplikacja | Port | HTTP | Technologie (z wersją) | Klasy | Ikona mmh3 |
| --- | --- | --- | --- | --- | --- |
| wordpress | 19101 | 200 | WordPress 6.9.4, PHP 8.3.31, Apache HTTP Server 2.4.67 | admin-panel, login | – |
| drupal | 19102 | 200 | Drupal 11, PHP 8.5.13, Apache HTTP Server 2.4.71, jQuery | admin-panel | 1015329088 |
| joomla | 19103 | 200 | Joomla, Apache HTTP Server 2.4.71, PHP | admin-panel, login | 1627330242 |
| grafana | 19104 | 200 | Grafana 13.0.2 | login | 2123863676 |
| jenkins | 19105 | 403 | Java, Jenkins 2.580.2, Jetty 12.1.14 | dev-tool, error-page | 81586312 |
| phpmyadmin | 19106 | 200 | PHP 8.3.37, phpMyAdmin 5.2.3, Apache HTTP Server 2.4.71, Bootstrap | admin-panel, database, login | -476231906 |
| tomcat | 19107 | 200 | Apache Tomcat 10.1.62, Java | default-page | -297069493 |
| gitea | 19108 | 200 | Gitea 1.27.3 | admin-panel, dev-tool, login | -1266910437 |
| nginx | 19109 | 200 | nginx 1.30.7 | default-page | – |
| httpd | 19110 | 200 | Apache HTTP Server 2.4.71 | default-page | – |
| moodle | 19111 | 200 | Moodle, Apache HTTP Server, PHP | – | -438482901 |
| nextcloud | 19112 | 200 | Nextcloud 34.0.6, PHP 8.5.13, Apache HTTP Server 2.4.71 | login | 167837543 |
| portainer | 19113 | 200 | Portainer, Angular | admin-panel, dev-tool | -845890009 |
| portainer-tls | 19213 | 200 | Portainer, Angular | admin-panel, dev-tool | -845890009 |
| rabbitmq | 19114 | 200 | RabbitMQ Management, Cowboy, jQuery 3.5.1, Bootstrap | admin-panel, login | -1015107330 |
| prometheus | 19115 | 200 | Prometheus 3.16.0 | dev-tool | -1449038499 |
| traefik | 19116 | 200 | Traefik 3.7.19 | admin-panel, dev-tool | 1752131761 |
| adminer | 19117 | 200 | Adminer 6.3.0, PHP 8.4.28 | admin-panel, database, login | -519503050 |
| keycloak | 19119 | 200 | Keycloak, Java, React | admin-panel, login | -533488376 |
| mediawiki | 19120 | 200 | MediaWiki 1.46.2, PHP 8.3.37, Apache HTTP Server 2.4.71 | – | – |
| ghost | 19121 | 200 | Node.js, Ghost 5.130, Express | – | -927719618 |
| caddy | 19122 | 200 | Caddy | default-page | – |
| jupyterhub | 19123 | 200 | JupyterHub 6.2.0, Python, Tornado 6.6.1, Bootstrap | dev-tool, login | 1248917303 |
| roundcube | 19125 | 200 | PHP 8.4.28, Roundcube Webmail, Apache HTTP Server 2.4.71, Bootstrap | login | -1754690812 |
| swagger | 19126 | 200 | Swagger UI, nginx | api, dev-tool | -1128940573 |
| registry | 19127 | 200 | Docker Registry | api, dev-tool | – |
| dokuwiki | 19128 | 200 | DokuWiki, PHP 8.4.28, Apache HTTP Server | – | -630493013 |

Przykład wyjścia:

```
$ fpprobe -addr 127.0.0.1:19105 -paths -brief
target:   127.0.0.1:19105
http:     http://127.0.0.1:19105/ -> 403 "" (734 B, 2 ms, 23 requests)
server:   "Jetty(12.1.14)" powered-by: "" generator: ""
favicon:  mmh3 81586312 sha256 4fec1ee82f0dc4a8e4e9bb26954cf54cf9bf1e6a009516cb6c49ff16924e8caa
tech:     Java (1.00), Jenkins 2.580.2 (0.99), Jetty 12.1.14 (0.95)
classes:  dev-tool, error-page
findings: header-version-server, cookie-language-framework
```

## 12. Ograniczenia

- Sygnatury oprogramowania, którego nie było w laboratorium (m.in. USOS, DSpace, OJS, Koha, EZproxy, Zimbra, BigBlueButton, urządzenia IoT), opierają się na udokumentowanych cechach produktów. Nie były sprawdzone na żywej instancji i nie mają skrótów ikon.
- Moodle i kilka innych aplikacji nie ujawnia wersji bez logowania. Czujka nie zgaduje wersji.
- Reguły `body` widzą pierwsze 64 KiB strony, a reguły `path` pierwsze 16 KiB odpowiedzi.
- Reguły `banner` i `service` zależą od danych z nmap (`ServiceResult.Banner`, `Product`, `Version`). Kolektor HTTP ich nie zbiera.
- Reguły `hostname` potrzebują nazw hosta. `Match` zna tylko nagłówek Host; pełne nazwy podaje `MatchHost`.
- Strona, która generuje inną treść przy każdym żądaniu (np. token w HTML), omija wykrywanie „miękkiego 404” po skrócie. Dlatego reguły `path` w bibliotece sprawdzają też treść.
- Kolektor nie wykonuje JavaScriptu. Aplikacje, które budują całą stronę w przeglądarce, są rozpoznawane po znacznikach w HTML startowym, nagłówkach i ikonie.

## 13. Jak napisać własną sygnaturę w 2 minuty

1. Obejrzyj usługę: `fpprobe -addr 127.0.0.1:8080 -paths -brief`. Wynik pokazuje nagłówki, nazwy ciasteczek, tytuł i skrót ikony (`favicon: mmh3 …`).
2. Zapisz sygnaturę w pliku `moja.yaml`. Wzory są niżej.
3. Sprawdź ją: `fpprobe -validate moja.yaml`. Walidator podaje błędy po polsku, ze ścieżką pola i numerem wiersza.
4. Wypróbuj na usłudze: `fpprobe -addr 127.0.0.1:8080 -paths -brief -sigs moja.yaml`.
5. Dodaj ją w interfejsie (zakładka sygnatur) albo przez API: `POST /api/v1/signatures` z polem `yaml`. `POST /api/v1/signatures/retrohunt` pokaże, gdzie sygnatura pasuje w danych już zebranych, bez wysłania pakietu.

Każda sygnatura potrzebuje `id`, `name` i co najmniej jednej reguły. Poniższe siedem przykładów to dokładnie lista „bezpiecznych sygnatur” z opisu zadania. Test `TestDocsWalkthroughExamples` wczytuje je z tego pliku i sprawdza, że każdy przechodzi walidację i wykrywa swoją cechę.

**1. Obecność konkretnego nagłówka**

```yaml
id: aplikacjax-naglowek
name: AplikacjaX (nagłówek)
category: framework
match:
  rules:
    - {type: header, name: X-Powered-By, contains: 'AplikacjaX'}
```

Sam fakt istnienia nagłówka: `{type: header, name: X-Debug-Token, exists: true}`.

**2. Konkretna nazwa ciasteczka**

```yaml
id: aplikacjax-ciasteczko
name: AplikacjaX (ciasteczko)
category: framework
match:
  rules:
    - {type: cookie, name: APLIKACJAX_SESSION}
```

Czujka porównuje tylko nazwę i atrybuty ciasteczka. Nie odsyła go do serwera.

**3. Skrót ikony (favicon hash)**

```yaml
id: aplikacjax-ikona
name: AplikacjaX (ikona)
category: panel
match:
  rules:
    - {type: favicon, mmh3: [116323821]}
```

Liczbę podaje `fpprobe -brief` w wierszu `favicon`. To ten sam skrót MurmurHash3, którego używają Shodan i FOFA.

**4. Charakterystyczny fragment HTML**

```yaml
id: aplikacjax-html
name: AplikacjaX (fragment HTML)
category: framework
match:
  rules:
    - {type: body, contains: '<div id="aplikacjax-root">'}
```

**5. Ścieżka typu `/login`, bez próby logowania**

```yaml
id: aplikacjax-logowanie
name: AplikacjaX (strona logowania)
category: panel
classes: [login]
match:
  rules:
    - {type: path, path: /login, status: [200], contains: 'name="aplikacjax_password"'}
```

Czujka wysyła jedno `GET /login` i czyta odpowiedź. Nie wypełnia formularza i nie wysyła hasła. Ścieżki sygnatur własnych mają pierwszeństwo w limicie dodatkowych ścieżek na usługę (`PathsFor`), przed ogólnymi ścieżkami biblioteki wbudowanej. Reguła sprawdza też treść, bo serwer, który na każdą ścieżkę odpowiada 200, dałby fałszywe trafienie.

**6. Wersja w stopce**

```yaml
id: aplikacjax-wersja
name: AplikacjaX
category: framework
match:
  rules:
    - {type: body, regex: 'Powered by AplikacjaX v([0-9]+(\.[0-9]+)+)', version_group: 1}
```

Pierwsza grupa w nawiasach to wersja. Trafia do pola `version` technologii i do CPE, gdy sygnatura ma pole `cpe`.

**7. Odcisk popularnego CMS-a**

```yaml
id: kampuscms
name: KampusCMS
category: cms
cpe: 'cpe:2.3:a:kampus:kampuscms'
implies: [PHP]
match:
  rules:
    - {type: meta, name: generator, regex: '^KampusCMS ?([0-9.]+)?', version_group: 1}
    - {type: header, name: X-Generator, contains: 'KampusCMS'}
    - {type: cookie, name: kampuscms_sid}
    - {type: body, contains: '/kampuscms/assets/'}
    - {type: path, path: /kampuscms/admin/, status: [200, 302], contains: 'KampusCMS'}
```

Wystarczy jedna reguła. Każda następna podnosi pewność (rozdział 6), więc CMS rozpoznany po trzech cechach ma wyższy wynik niż po jednej.

## 14. Zgodność z innymi formatami

Loader przyjmuje pliki, które nie są w formacie Czujki. Każda sygnatura, niezależnie od formatu wejścia, przechodzi przez ten sam kompilator i ten sam tryb bezpieczny (rozdział 5). Walidator jest ostatnią bramką: konwersja niczego nie omija.

### 14.1 Kształt pliku

| Kształt | Przykład |
| --- | --- |
| YAML albo JSON | `{"id": "x", "name": "X", "body": "tekst"}` |
| jedna sygnatura, lista albo kilka dokumentów `---` | `[{...}, {...}]` |
| klucz zbiorczy | `signatures`, `sigs`, `fingerprints`, `technologies`, `apps`, `templates`, `items`, `entries`, `definitions`, a także `rules` z listą całych sygnatur |
| mapa po nazwie | `{"WordPress": {...}, "Drupal": {...}}` – klucz staje się nazwą i id |

### 14.2 Synonimy pól

| Pole Czujki | Przyjmowane nazwy |
| --- | --- |
| `id` | `id`, `slug`, `identifier`, `sid`, `template-id`; gdy brak, id powstaje z nazwy |
| `name` | `name`, `label`, `app`, `software`, `product`, `technology` |
| `category` | `category`, `cat`, `group`, `kind` |
| `description` | `description`, `desc`, `summary`, `details`, `comment`, `notes` |
| `tags` | `tags`, `labels`; lista albo tekst z przecinkami |
| `interest` | `interest`, `priority`, albo `severity` / `risk` (info 10, low 25, medium 50, high 75, critical 90) |
| `match.rules` | `match`, `matchers`, `rules`, `detect`, `detection`, `checks`, `conditions`, `fingerprint(s)`, `patterns`, `indicators` |
| `condition` | `condition`, `mode`, `operator`, `matchers-condition`, `logic` (`and` / `all` → wszystkie reguły) |
| typ reguły | `type` albo `part` / `in` / `where` / `target` / `scope`; gdy `type` to `word` lub `regex`, cel bierze się z `part` |
| tekst | `contains`, `word`, `words`, `text`, `keyword(s)`, `string(s)`, `substring`, `value`, `match` |
| wyrażenie regularne | `regex`, `regexp`, `pattern`, `patterns`, `matches`, `re` |
| nagłówek | `header`, `headers`, `header_name` |
| ciasteczko | `cookie`, `cookies`, `cookie_name` |
| ścieżka | `path`, `paths`, `endpoint`, `uri`, `url` (gdy zaczyna się od `/`) |
| skrót ikony | `favicon_hash`, `favicon`, `mmh3`, `favicon_mmh3`, `icon_hash`, `hash` |
| treść strony | `html`, `body`, `content`, `response`, `text` |
| tytuł | `title` |
| wersja | `version`, `versions`, `version_regex`, `version_pattern`, `version_extract` – reguła albo sam wzorzec z grupą |
| waga | `weight`, `confidence`, `score`; liczba całkowita od 2 do 100 to procent |

Pozostałe reguły zgodności:

- Nazwy pól nie rozróżniają wielkości liter ani znaków `-` i `_` (`matchers-condition` = `matchers_condition`).
- Reguła bez typu dostaje typ z pól, które ma: ścieżka → `path`, skrót → `favicon`, `header` → `header`, `cookie` → `cookie`. Sam tekst oznacza treść strony; walidator zgłasza wtedy ostrzeżenie.
- `condition: and` w regule z listą słów oznacza: wszystkie słowa (`contains_all`).
- Ścieżka na górnym poziomie sygnatury (`endpoint: /login`) razem z listą reguł przenosi reguły treści, tytułu, statusu i nagłówków na tę ścieżkę.
- Id w dowolnej postaci („Old Printer UI”) jest zamieniane na poprawne (`old-printer-ui`) z ostrzeżeniem.
- Nieznane pole daje ostrzeżenie, nie błąd.

### 14.3 Pliki w stylu Wappalyzera

Mapa po nazwie technologii albo wpis z polem `cats` lub `scriptSrc` jest czytany według konwencji Wappalyzera:

- wzorce w `headers`, `cookies`, `meta`, `html`, `url`, `scriptSrc` to wyrażenia regularne; pusty wzorzec oznacza „pole istnieje”;
- znacznik `\;version:\1` ustawia grupę wersji, a `\;confidence:50` wagę reguły;
- `cats` ustawia kategorię, `implies` i `cpe` są przenoszone, `certIssuer` staje się regułą `tls`;
- `js`, `dom`, `dns`, `xhr`, `css`, `robots`, `probe` są pomijane z ostrzeżeniem, bo wymagają przeglądarki albo innego protokołu. Wpis, który ma tylko takie pola, jest odrzucany: nie ma reguły, którą Czujka może sprawdzić.

### 14.4 Szablony nuclei

Konwerter przyjmuje pasywny podzbiór szablonów HTTP nuclei:

| Element nuclei | Wynik w Czujce |
| --- | --- |
| `id`, `info.name`, `author`, `description`, `tags` | te same pola; `severity` → `interest`; `classification.cpe` → `cpe`; tagi `panel` / `login` → kategoria `panel` i klasa `login` |
| `method: GET`, `path: ["{{BaseURL}}/x"]` | `{{BaseURL}}` → reguły strony głównej; inna ścieżka → reguła `path` |
| matcher `word` (`condition: and`, `case-insensitive`), `regex`, `status`, `negative` | `contains` / `contains_all`, `regex`, `status`, `not` |
| `part: body / header / all` | treść albo wiersze „Nazwa: wartość” nagłówków |
| `matchers-condition: and` | jedna reguła łącząca ścieżkę, status i tekst; gdy się nie da – reguły `required` |
| `dsl` z `mmh3(base64_py(body))` i liczbą | reguła `favicon` (jedyne przyjmowane wyrażenie DSL) |
| `extractors` typu `regex` z `group` | reguły `version` |

Konwerter odrzuca, z komunikatem po polsku i oznaczeniem trybu bezpiecznego:

- metodę inną niż GET lub HEAD, treść żądania (`body`), surowe żądania (`raw`);
- `payloads`, `attack`, `fuzzing`, `race`, `threads`, `pipeline`, `unsafe`, własne nagłówki żądania (`headers`), `cookie-reuse`, `self-contained`;
- zmienne i funkcje pomocnicze `{{...}}` w ścieżce albo w dopasowaniu (także `interactsh`), ścieżki do innego hosta, sekcję `variables`;
- wyrażenia DSL inne niż porównanie skrótu ikony;
- protokoły inne niż HTTP: `dns`, `tcp` / `network`, `ssl`, `file`, `headless`, `websocket`, `whois`, `code`, `javascript`, `workflows`, `flow`.

Matchery `binary`, `size`, `xpath` i `kval` są zgłaszane jako zwykły błąd (nieobsługiwane, ale nie groźne). Ekstraktory inne niż `regex` są pomijane z ostrzeżeniem.

Po konwersji działa tryb bezpieczny. Szablon z samym `GET {{BaseURL}}/.git/config` albo `/actuator/shutdown` jest poprawnym szablonem pasywnym dla konwertera, ale walidator odrzuca jego ścieżkę (rozdział 5).

### 14.5 `fpprobe -convert`

`fpprobe -convert plik` wypisuje YAML Czujki na standardowe wyjście, a ostrzeżenia i błędy na wyjście błędów. Kod wyjścia 1 oznacza, że żadna sygnatura z pliku nie przeszła. Pliki przykładowe są w `internal/sig/testdata/foreign/`.

```
$ fpprobe -convert internal/sig/testdata/foreign/nuclei-panel.yaml
id: acme-gateway-detect
name: ACME Gateway - Detect
category: panel
description: ACME Gateway login panel was detected.
author: 'jkowalski, anowak'
cpe: 'cpe:2.3:a:acme:gateway'
tags: [panel, acme, detect]
classes: [login]
interest: 10
match:
  rules:
    - {type: path, path: /gateway/login, status: [200], contains_all: ['<title>ACME Gateway</title>', acme-gateway-login], case_sensitive: true, weight: 0.9}
    - {type: path, path: /login, status: [200], contains_all: ['<title>ACME Gateway</title>', acme-gateway-login], case_sensitive: true, weight: 0.9}
version:
  - {type: path, path: /gateway/login, regex: 'Gateway version ([0-9.]+)'}
  - {type: path, path: /login, regex: 'Gateway version ([0-9.]+)'}

$ fpprobe -convert internal/sig/testdata/foreign/nuclei-active.yaml
error [tryb bezpieczny]: http[0].raw: szablon nuclei używa pola „raw” (surowe żądania (raw)); Czujka konwertuje tylko pasywne żądania GET bez treści, nagłówków i ładunków (wiersz 9)
error [tryb bezpieczny]: http[0].attack: szablon nuclei używa pola „attack” (tryb ataku z ładunkami); Czujka konwertuje tylko pasywne żądania GET bez treści, nagłówków i ładunków (wiersz 15)
error [tryb bezpieczny]: http[0].payloads: szablon nuclei używa pola „payloads” (ładunki (payloads)); Czujka konwertuje tylko pasywne żądania GET bez treści, nagłówków i ładunków (wiersz 17)
fpprobe: plik odrzucony; powody są powyżej
```

Sygnatura w obcym formacie działa też bez konwersji: `POST /api/v1/signatures`, `fpprobe -sigs` i `sigwire.Import` przyjmują ją wprost. `sigwire.Import` zapisuje ją jako kanoniczny YAML Czujki.

### 14.6 Ograniczenia zgodności

- Format zestawu od organizatorów nie był znany w chwili pisania. Loader obsługuje kształty i nazwy z tabel powyżej. Pole o innej nazwie daje ostrzeżenie z nazwą pola; dopisanie synonimu to jeden wiersz w `internal/sig/dsl.go`.
- Konwersja nuclei gubi to, czego Czujka nie ma: `stop-at-first-match`, podążanie za przekierowaniami na dodatkowych ścieżkach, ekstraktory `kval` / `json` / `xpath`.
- Złożony warunek `and` w szablonie z kilkoma żądaniami albo ścieżkami, którego nie da się zapisać jedną regułą, jest odrzucany z prośbą o podział szablonu.
- Z plików Wappalyzera używane są tylko cechy widoczne w odpowiedzi HTTP.

## 15. Połączenie z bazą i API (`internal/sigwire`)

`sigwire.Wire` łączy silnik z tabelą `signatures` i z API. Jeden obiekt spełnia `api.SignatureValidator` i `api.RetroHunter`, a `Engine()` zwraca ten sam `*sig.Engine`, który dostaje silnik skanowania jako `model.SignatureEngine`.

| Funkcja | Działanie |
| --- | --- |
| `Start(ctx)` | `Seed` + `Reload` przy starcie programu |
| `Seed(ctx)` | zapisuje bibliotekę wbudowaną jako wiersze `builtin`; odświeża YAML, gdy wbudowany się zmienił; zachowuje wybór `enabled` analityka; usuwa wiersze wbudowane, których biblioteka już nie ma; nie dotyka sygnatur własnych |
| `Reload(ctx)`, `Changed(ctx)` | czyta wszystkie wiersze i podmienia zestaw silnika jedną operacją atomową; `Changed` to `api.Hooks.SignaturesChanged` |
| `Validate(yaml)` | wynik walidacji i metadane sygnatury; tekst z więcej niż jedną sygnaturą odrzuca (jeden wiersz = jedna sygnatura) |
| `RetroHunt(ctx, yaml, latestOnly)` | strumieniowy retro-hunt po zapisanych obserwacjach (rozdział 8) |
| `Import(ctx, tekst, autor)` | zapisuje wszystkie poprawne sygnatury z pliku (dowolny format z rozdziału 14) jako własne i przeładowuje silnik; sygnatury wbudowanej nie nadpisuje |
| `UpdateMatchCounts(ctx)` | liczy, ile usług pasuje do każdej sygnatury w najnowszych obserwacjach (`match_count`), jednym zapytaniem SQL |

Wiersz, którego walidator nie przyjmie (np. sygnatura własna zapisana przed zaostrzeniem reguł), nie zatrzymuje programu. `Reload` pomija go i zapisuje w logu: `signature rejected; it is not loaded slug=… reason=…`. Gdy bazy nie da się odczytać, silnik zostaje przy poprzednim zestawie.

Pomiar z 2026-11-21 (`TestRetroHuntScale` z `CZUJKA_RETRO_N=100000`, PostgreSQL 17 z pg_tde w kontenerze, laptop):

```
stored 100000 observations (about 4 KiB of encrypted body each) in 17.14s
retro-hunt: 100000 observations, 2000 hits, 5436 ms (18396 observations/s), 0 packets, peak heap 48 MiB (before 18 MiB)
match counts over 100000 services: 183ms
signatures seeded builtin=386 removed=0 took_ms=55
signatures loaded rows=386 loaded=386 enabled=386 rejected=0 paths=45 took_ms=75
```

Testy integracyjne potrzebują bazy (`CZUJKA_TEST_DB_URL`); bez niej są pomijane.
