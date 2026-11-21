# Laboratorium testowe Czujki

Sieć dockerowa, która udaje dużą, różnorodną i zmienną infrastrukturę uczelni. Służy do sprawdzenia, czy Czujka znajduje hosty, usługi, technologie i zmiany. Każdy stan laboratorium ma plik z prawdą wzorcową (ground truth), a narzędzie `e2e/score` liczy precision, recall i F1.

- Sieć: jeden bridge `czujka-lab`, `10.66.0.0/16`, brama `10.66.0.1`.
- 70 hostów w stanie `t0` (75 kontenerów razem ze stanami `t1`/`t2` i skrzynką skanera), 24 bloki /24.
- Strefa DNS `lab.czujka.test` na `10.66.0.53` (dnsmasq, rekordy A i PTR).
- Obrazy działają na `linux/arm64` i `linux/amd64`. Wszystko jest wolnym oprogramowaniem.
- Żaden port laboratorium nie jest wystawiony na hosta. Skaner musi dołączyć do sieci (rozdział 4).

## 1. Jedno źródło prawdy

Całe laboratorium opisuje manifest w Go: `lab/manifest` (`real.go`: prawdziwe oprogramowanie, `sim.go`: imitacje). Generator tworzy z niego wszystkie pozostałe pliki:

```sh
go run ./lab/gen          # zapisuje pliki
go run ./lab/gen -check   # kończy się błędem, gdy plik na dysku jest nieaktualny (to samo robi test w lab/manifest)
```

| Plik generowany | Zawartość |
| --- | --- |
| `lab/docker-compose.yml` | wszystkie kontenery, stałe adresy IP, limity pamięci, healthchecki |
| `lab/labsim/hosts/*.json` | konfiguracja każdej imitacji (wbudowana w binarkę `labsim`) |
| `lab/ground-truth/t0.json`, `t1.json`, `t2.json` | prawda wzorcowa każdego stanu |
| `lab/ground-truth/changes-t0-t1.json`, `changes-t1-t2.json` | oczekiwane zmiany między stanami |
| `lab/ground-truth/targets-cidr.txt`, `targets-domains.txt` | gotowe listy celów do importu (CIDR i 73 nazwy domenowe) |
| `lab/generated/states.sh` | listy kontenerów dla `scenario.sh` |
| tabela adresów w tym pliku | między znacznikami `BEGIN/END ADDRESS PLAN` |

Nie edytuj tych plików ręcznie. Zmień manifest i uruchom generator.

Dwa rodzaje hostów:

- **Prawdziwe oprogramowanie** (WordPress, Joomla, Drupal, Tomcat, Jenkins, Gitea, bazy danych...). Prawda wzorcowa jest wpisana ręcznie i poprawiona według wyników skanu nmap.
- **Imitacje `labsim`** (`lab/labsim`, jedna binarka Go, tylko biblioteka standardowa). Odpowiadają wyłącznie na `GET` i `HEAD` (inna metoda: 405). Prawda wzorcowa jest wyliczana z tej samej konfiguracji, którą dostaje serwer, więc nie może się z nim rozjechać.

## 2. Start, stop, zasoby

```sh
lab/lab.sh up        # buduje obrazy, startuje stan t0, czeka aż wszystkie hosty są healthy
lab/lab.sh status    # podsumowanie stanu kontenerów
lab/lab.sh stats     # pamięć i CPU każdego kontenera, z sumą (docker stats --no-stream)
lab/lab.sh sh        # powłoka w skrzynce skanera (albo: lab/lab.sh sh nmap -sn 10.66.1.0/24)
lab/lab.sh down      # usuwa kontenery, sieć i wolumeny; obrazy zostają
```

Zmierzone na Docker Desktop (aarch64, 15 CPU, 27 GB):

| Pomiar | Wartość |
| --- | --- |
| Start od zera (`lab/lab.sh up`, obrazy już zbudowane) | 31–32 s do stanu „71 kontenerów healthy” (trzy pomiary po `lab/lab.sh down`: 31 s, 31 s, 32 s) |
| Pamięć po starcie (`lab/lab.sh stats`) | 2009–2011 MiB zaraz po starcie, 2248 MiB po 5 minutach i pełnym skanie (71 kontenerów) |
| Pierwsze budowanie i pobranie obrazów | kilka minut (35 obrazów bazowych, 13 własnych) |
| Przejście `t0` → `t1` (`lab/scenario.sh t1`) | 9 s |

Każdy kontener ma `mem_limit`. Budżet zadania to 6 GB; laboratorium zużywa około jednej trzeciej.

## 3. Stany i scenariusze

```sh
lab/scenario.sh t0
lab/scenario.sh t1
lab/scenario.sh t2
```

Wynik nie zależy od stanu wyjściowego. Skrypt zatrzymuje kontenery, których stan nie ma, startuje te, które ma, i zapisuje nazwę stanu na wspólnym wolumenie. Każda imitacja czyta ten plik co sekundę i zmienia porty, treść, nagłówki i certyfikaty. Zmiana wersji prawdziwego oprogramowania to dwa kontenery z tym samym adresem IP w różnych stanach (np. `wp-old` i `wp-new` na `10.66.1.11`).

### t0 → t1 (25 oczekiwanych zmian, `changes-t0-t1.json`)

| Zmiana | Host |
| --- | --- |
| nowy host | `cam-3` 10.66.130.77 (kamera), `shadow-adminer` 10.66.5.5 (zapomniany panel bazy) |
| host znika | `ftp` 10.66.20.20, `legacy-php` 10.66.3.16 |
| zmiana wersji | `blog` 10.66.1.11: WordPress 5.8.3 → 6.9.4, PHP 7.4 → 8.3, Apache 2.4.51 → 2.4.67; `nginx` 10.66.2.10: 1.24.0 → 1.30.7; `kiosk-1` 10.66.60.12: InfoKiosk 4.2.1 → 4.3.0 |
| strona staje się panelem administracyjnym | `news-site` 10.66.2.30: nowy tytuł, formularz logowania, ciasteczko `admin_session` |
| zmiana tytułu | `staging-portal` 10.66.40.10:443 |
| odnowiony certyfikat | `tls-valid` 10.66.50.10:443 |
| zmiana nagłówka i ciasteczek | `hdr-leaky` 10.66.60.10:80 (`X-Powered-By`, `PHPSESSID`, `tracking_id`) |
| port zamknięty i otwarty | `hdr-leaky` 10.66.60.10: 8000 zamknięty, 8081 otwarty |

### t1 → t2 (8 oczekiwanych zmian, `changes-t1-t2.json`)

| Zmiana | Host |
| --- | --- |
| host wraca | `legacy-php` 10.66.3.16 |
| host znika | `shadow-adminer` 10.66.5.5 |
| zmiana kodu HTTP | `dev-api` 10.66.40.11:8080 (200 → 503) |
| wymieniony przeterminowany certyfikat | `tls-expired` 10.66.50.12:443 |
| zmiana celu przekierowania | `redir-ext` 10.66.50.21:80 |
| poprawione flagi ciasteczka JWT | `jwt-app` 10.66.60.11 (porty 80 i 443) |
| port zamknięty | `stealth-high` 10.66.70.11:31337 |

### Hosty niestabilne (bez dostępu do gniazda dockera)

Kontener sam wyłącza i włącza swój interfejs sieciowy (`ip link set eth0 down/up`, uprawnienie `NET_ADMIN` tylko we własnej przestrzeni sieciowej). Dostępność jest czystą funkcją zegara (`lab/labcfg.Avail`), więc prawda wzorcowa i narzędzia oceny liczą ją tak samo jak host.

| Host | Reguła |
| --- | --- |
| `flapper` 10.66.70.20 | każda minuta zegara: w górze, gdy pierwszy bajt `sha256("czujka-flapper\|<numer minuty>")` jest parzysty. Około 50% minut, ciąg pseudolosowy, ale powtarzalny. |
| `tod-office` 10.66.70.21 | „godziny pracy” w skali: okres 6 minut, 3 minuty w górze i 3 w dole (`unix mod 360 < 180`). |
| `tod-night` 10.66.70.22 | „nocny”: okres 10 minut, 4 minuty w dole i 6 w górze (`240 ≤ unix mod 600`). |

Model stabilności Czujki powinien po kilku skanach oznaczyć te trzy hosty jako niestabilne i nie zgłaszać ich zniknięć jako alarmów. `e2e/score` nie wlicza ich do metryk; wypisuje je osobno i porównuje z modelem dostępności. Podgląd na żywo: `go run ./e2e/watchunstable`.

## 4. Jak skaner dołącza do sieci

Host macOS nie ma trasy do adresów kontenerów (Docker Desktop trzyma sieć w maszynie wirtualnej). Skaner musi działać **w kontenerze podłączonym do sieci `czujka-lab`**. Adresy `10.66.0.2`–`10.66.0.49` są wolne dla skanerów (`10.66.0.10` zajmuje skrzynka).

**Skrzynka skanera** (`lab/scanner-box`, `10.66.0.10`): Alpine z nmap, curl, dig, jq i openssl. Startuje razem z laboratorium i używa DNS laboratorium.

```sh
lab/lab.sh sh nmap -sn -n -T4 --min-rate 3000 --max-retries 2 10.66.0.0/16
lab/lab.sh sh curl -si http://www.lab.czujka.test/
lab/lab.sh sh dig +short @10.66.0.53 -x 10.66.30.10
```

**Czujka w compose** (plik produktu, nie laboratorium):

```yaml
services:
  czujka:
    networks:
      default: {}
      lab: {ipv4_address: 10.66.0.20}
    cap_add: [NET_RAW, NET_ADMIN]   # nmap -sS i ARP
    dns: [10.66.0.53]               # strefa lab.czujka.test
networks:
  lab:
    external: true
    name: czujka-lab
```

**Jednorazowo:** `docker run --rm -it --network czujka-lab --ip 10.66.0.20 --cap-add NET_RAW --cap-add NET_ADMIN --dns 10.66.0.53 <obraz>` albo `docker network connect --ip 10.66.0.20 czujka-lab <kontener>`.

Uwagi dla skanera:

- W tej samej sieci L2 nmap wykrywa hosty przez ARP. Domyślne tempo jest za wolne dla /16 (ponad 10 minut). Z `-T4 --min-rate 3000 --max-retries 2` przegląd 65 536 adresów trwa 48 s.
- Skaner pod własnym adresem (np. `10.66.0.20`) widzi też siebie. Podaj go narzędziu oceny: `score -ignore 10.66.0.20`. Brama i skrzynka są pomijane zawsze (pole `ignore` w ground truth).
- Rekordy PTR: wbudowany resolver dockera (`127.0.0.11`) sam odpowiada na zapytania odwrotne nazwą kontenera (`czujka-lab-cam-1-1.czujka-lab`). Nazwy ze strefy laboratorium daje zapytanie wprost do serwera: `dig @10.66.0.53 -x 10.66.30.10` → `kamera-1.lab.czujka.test`. Zapytania w przód (`www.lab.czujka.test`) działają przez oba.
- Skanuj tylko `10.66.0.0/16`. Laboratorium nie wysyła ruchu poza swoją sieć.

## 5. Co jest w laboratorium

Imitacje urządzeń odtwarzają **publiczny odcisk** prawdziwego produktu (nagłówki, tytuł, ścieżki, ciasteczka, układ strony logowania), nie jego kod ani logikę:

| Host | Wzorzec |
| --- | --- |
| `router-1`, `router-2` | MikroTik RouterOS 6.49.10, strona WebFig (tytuł „RouterOS router configuration page”, brak nagłówka `Server`) |
| `cam-1`, `cam-2`, `cam-3` | kamera Hikvision (`Server: App-webs/`, pusty tytuł, przekierowanie w JavaScript na `/doc/page/login.asp`) |
| `printer-1`, `printer-2` | HP LaserJet Pro M404dn, wbudowany serwer WWW (`Server: HP HTTP Server`, porty 80/443/631) |
| `nas-1` | Synology DiskStation DSM 6.2 (przekierowanie 80 → 5000, 5001 z TLS, tytuł „… - Synology DiskStation”, zasoby `webman/`) |

Przypadki trudne (pole `hard` w ground truth; `score` ich nie karze, chyba że z `-strict`):

| Host | Dlaczego trudny |
| --- | --- |
| `no-icmp` 10.66.70.10 | odrzuca ICMP. W tej samej sieci L2 odpowiada na ARP; ping ICMP go nie widzi (`nmap -sn -PE --disable-arp-ping`). |
| `stealth-high` 10.66.70.11 | firewall odrzuca po cichu wszystko poza portami 8888, 18443, 31337 (także ICMP i porty 80/443). Skan domyślnych 1000 portów nmap znajduje 8888 i 31337, ale nie 18443; potrzebny jest pełny zakres portów. |
| `slow` 10.66.70.12 | każda odpowiedź HTTP po 4 s |
| `tarpit` 10.66.70.13 | port 2222 przyjmuje połączenie i wysyła 1 bajt co 10 s; nazwa usługi nie do ustalenia |
| `many-ports` 10.66.70.14 | 64 otwarte porty |
| `volatile` 10.66.70.15 | treść strony i jeden nagłówek zmieniają się przy każdym żądaniu (nie może to być zgłaszane jako zmiana) |
| `vhosts` 10.66.2.20 | różne strony zależnie od nagłówka `Host` (trzy nazwy w DNS: `hosting`, `rekrutacja`, `intranet`) |
| usługi UDP (`dns`, `snmp`, `ntp`) | wymagają skanu UDP |
| adresy `10.66.99.0` i `10.66.99.255` | krawędzie bloku /24 wewnątrz /16: to zwykłe adresy hostów |

Przypadki TLS: `tls-valid` (łańcuch z CA laboratorium), `tls-selfsigned`, `tls-expired`, `tls-mismatch` (certyfikat na inną nazwę), `caddy` (HTTP → HTTPS, wewnętrzne CA Caddy), `redir-chain` (łańcuch przekierowań), `redir-ext` (przekierowanie na inny host). Certyfikaty imitacji powstają przy starcie kontenera względem bieżącej daty, więc „przeterminowany” jest zawsze przeterminowany.

Nagłówki i ciasteczka: `hdr-leaky` (wersje i tryb debug w nagłówkach, CORS `*`, ciasteczka bez `Secure`/`HttpOnly`), `jwt-app` (ciasteczko o kształcie JWT), `kiosk-1`/`kiosk-2` (produkt „InfoKiosk”, który wykrywa tylko **własna sygnatura**: `lab/custom-signatures/infokiosk.yaml`).

## 6. Plan adresów

<!-- BEGIN ADDRESS PLAN (generated by lab/gen) -->

### Usługi sieciowe i bazy danych (nie-HTTP)

| Adres | Kontener | Nazwy DNS | Porty | Stany | Co to jest |
| --- | --- | --- | --- | --- | --- |
| `10.66.0.53` | `dns` | ns1 | 53, 53/udp | t0, t1, t2 | dnsmasq: strefa lab.czujka.test (53/tcp, 53/udp) |
| `10.66.20.10` | `mariadb` | db | 3306 | t0, t1, t2 | MariaDB 11.4.13 (3306), wspólna baza CMS-ów |
| `10.66.20.11` | `postgres` | pg | 5432 | t0, t1, t2 | PostgreSQL 17.12 (5432) |
| `10.66.20.12` | `redis` | cache | 6379 | t0, t1, t2 | Redis 7.4.12 bez hasła (6379) |
| `10.66.20.13` | `memcached` | memcache | 11211 | t0, t1, t2 | memcached 1.6.45 (11211) |
| `10.66.20.20` | `ftp` | ftp | 21 | t0 | vsftpd (21), dostęp anonimowy; znika w t1 |
| `10.66.20.21` | `smtp` | mail | 25 | t0, t1, t2 | Postfix (25) |
| `10.66.20.22` | `mqtt` | mqtt | 1883 | t0, t1, t2 | Eclipse Mosquitto 2.0.23 (1883), dostęp anonimowy |
| `10.66.20.30` | `ssh-new` | bastion | 22 | t0, t1, t2 | OpenSSH 10.3 (Alpine 3.24), port 22 |
| `10.66.20.31` | `ssh-old` | stary-serwer | 22 | t0, t1, t2 | OpenSSH 7.9 (Alpine 3.9, przestarzały), port 22 |
| `10.66.20.40` | `snmp` | ups | 161/udp | t0, t1, t2 | net-snmp (161/udp): host tylko z usługą UDP |
| `10.66.20.41` | `ntp` | ntp | 123/udp | t0, t1, t2 | chrony (123/udp): host tylko z usługą UDP |
| `10.66.20.50` | `vnc` | pracownia-vnc | 5900 | t0, t1, t2 | TigerVNC (5900), wymaga hasła |

### CMS-y

| Adres | Kontener | Nazwy DNS | Porty | Stany | Co to jest |
| --- | --- | --- | --- | --- | --- |
| `10.66.1.10` | `wp-main` | www | 80 | t0, t1, t2 | WordPress 6.9.4, zainstalowany, aktualny |
| `10.66.1.11` | `wp-new` | blog | 80 | t1, t2 | WordPress 6.9.4 po aktualizacji (t1, t2) |
| `10.66.1.11` | `wp-old` | blog | 80 | t0 | WordPress 5.8.3 (przestarzały) w t0; w t1 zastąpiony przez 6.9.4 na tym samym adresie |
| `10.66.1.20` | `joomla` | biblioteka | 80 | t0, t1, t2 | Joomla 5.4.10, zainstalowana |
| `10.66.1.30` | `drupal` | repozytorium | 80 | t0, t1, t2 | Drupal 10.6.22, zainstalowany (SQLite) |
| `10.66.1.40` | `dokuwiki` | wiki | 8080 | t0, t1, t2 | DokuWiki 2026-07-14c |

### Serwery WWW

| Adres | Kontener | Nazwy DNS | Porty | Stany | Co to jest |
| --- | --- | --- | --- | --- | --- |
| `10.66.2.10` | `nginx-new` | static | 80 | t1, t2 | nginx 1.30.7 po aktualizacji (t1, t2) |
| `10.66.2.10` | `nginx-old` | static | 80 | t0 | nginx 1.24.0 (strona domyślna) w t0 |
| `10.66.2.11` | `httpd` | www2 | 80 | t0, t1, t2 | Apache httpd 2.4.71 (strona domyślna „It works!”) |
| `10.66.2.12` | `caddy` | caddy | 80, 443 | t0, t1, t2 | Caddy 2.11.9: HTTP → HTTPS, certyfikat z wewnętrznego CA Caddy |
| `10.66.2.20` | `vhosts` | hosting, rekrutacja, intranet | 80 | t0, t1, t2 | nginx 1.30.7 z wirtualnymi hostami: domyślny, rekrutacja, intranet (logowanie) |
| `10.66.2.30` | `news-site` | kolo | 80 | t0, t1, t2 | strona aktualności, która w t1 staje się panelem administracyjnym |

### Frameworki i serwery aplikacyjne

| Adres | Kontener | Nazwy DNS | Porty | Stany | Co to jest |
| --- | --- | --- | --- | --- | --- |
| `10.66.3.10` | `tomcat` | tomcat | 8080 | t0, t1, t2 | Apache Tomcat 10.1.62: strona domyślna i /manager/html (401) |
| `10.66.3.11` | `spring` | oceny-api | 8080 | t0, t1, t2 | Spring Boot 3.4 z otwartym Actuatorem (/actuator, /actuator/env) |
| `10.66.3.12` | `django` | dev-django | 8000 | t0, t1, t2 | Django 5.2 w trybie DEBUG (runserver), /admin/ |
| `10.66.3.13` | `flask` | sale | 5000 | t0, t1, t2 | Flask 3 za gunicorn 23, ciasteczko sesji o kształcie JWT bez Secure |
| `10.66.3.14` | `express` | status | 3000 | t0, t1, t2 | Node.js 22 + Express 4, connect.sid, CORS * |
| `10.66.3.15` | `laravel` | rekrutacja-app | 8000 | t0, t1, t2 | Laravel 12 (APP_DEBUG=true), ciasteczka XSRF-TOKEN i laravel_session |
| `10.66.3.16` | `legacy-php` | rezerwacje | 80 | t0, t2 | PHP 7.4.33 (koniec wsparcia) na Apache, PHPSESSID bez flag, /info.php; znika w t1, wraca w t2 |

### „Shadow IT”

| Adres | Kontener | Nazwy DNS | Porty | Stany | Co to jest |
| --- | --- | --- | --- | --- | --- |
| `10.66.5.5` | `shadow-adminer` | — | 8080 | t1 | „Shadow IT”: Adminer 4.17.1 postawiony na nowym adresie; pojawia się w t1, znika w t2 |

### Panele administracyjne i narzędzia deweloperskie

| Adres | Kontener | Nazwy DNS | Porty | Stany | Co to jest |
| --- | --- | --- | --- | --- | --- |
| `10.66.10.10` | `phpmyadmin` | pma | 80 | t0, t1, t2 | phpMyAdmin 5.2.3 |
| `10.66.10.11` | `adminer` | adminer | 8080 | t0, t1, t2 | Adminer 5.5.1 |
| `10.66.10.20` | `grafana` | grafana | 3000 | t0, t1, t2 | Grafana 12.4.15 (strona logowania) |
| `10.66.10.21` | `prometheus` | prometheus | 9090 | t0, t1, t2 | Prometheus 3.16.0 bez uwierzytelniania |
| `10.66.10.30` | `jenkins` | ci | 8080, 50000 | t0, t1, t2 | Jenkins 2.580.2 LTS bez logowania (kreator wyłączony) |
| `10.66.10.31` | `gitea` | git | 22, 3000 | t0, t1, t2 | Gitea 1.27.3 (HTTP 3000, SSH 22) |
| `10.66.10.40` | `portainer` | portainer | 8000, 9000, 9443 | t0, t1, t2 | Portainer CE 2.39.9 (HTTP 9000, HTTPS 9443 self-signed, 8000) |
| `10.66.10.41` | `rabbitmq` | mq | 4369, 5672, 15672, 15692, 25672 | t0, t1, t2 | RabbitMQ 4.3.8 z panelem zarządzania (15672) |
| `10.66.10.50` | `pgadmin` | pgadmin | 25, 80 | t0, t1, t2 | pgAdmin 4 9.19 (strona logowania); obraz wystawia też Postfix na porcie 25 |

### IoT i urządzenia sieciowe (imitacje)

| Adres | Kontener | Nazwy DNS | Porty | Stany | Co to jest |
| --- | --- | --- | --- | --- | --- |
| `10.66.30.1` | `router-1` | gw-iot | 80 | t0, t1, t2 | imitacja MikroTik RouterOS 6.49.10 (pierwszy adres bloku) |
| `10.66.30.10` | `cam-1` | kamera-1 | 80 | t0, t1, t2 | imitacja kamery IP Hikvision |
| `10.66.30.11` | `cam-2` | kamera-2 | 80 | t0, t1, t2 | imitacja kamery IP Hikvision (bliźniak cam-1) |
| `10.66.30.20` | `printer-1` | drukarka-1 | 80, 443, 631 | t0, t1, t2 | imitacja HP LaserJet Pro M404dn (80, 443, 631) |
| `10.66.30.30` | `nas-1` | nas | 80, 5000, 5001 | t0, t1, t2 | imitacja Synology DSM 6.2 (80 → 5000, 5001 TLS) |

### Środowiska staging i test

| Adres | Kontener | Nazwy DNS | Porty | Stany | Co to jest |
| --- | --- | --- | --- | --- | --- |
| `10.66.40.10` | `staging-portal` | staging | 80, 443 | t0, t1, t2 | staging: nagłówek X-Environment, baner, certyfikat dla staging.lab.czujka.test; tytuł zmienia się w t1 |
| `10.66.40.11` | `dev-api` | dev-api | 8080 | t0, t1, t2 | API deweloperskie: X-Debug-Token (profiler Symfony), CORS * z poświadczeniami; w t2 odpowiada 503 |
| `10.66.40.12` | `test-shop` | test | 80 | t0, t1, t2 | środowisko TEST za Basic Auth (401, realm „TEST environment”) |

### TLS i przekierowania

| Adres | Kontener | Nazwy DNS | Porty | Stany | Co to jest |
| --- | --- | --- | --- | --- | --- |
| `10.66.50.10` | `tls-valid` | portal | 80, 443 | t0, t1, t2 | poprawny łańcuch (CA laboratorium), HTTP → HTTPS; certyfikat wygasa za 30 dni, odnowiony w t1 |
| `10.66.50.11` | `tls-selfsigned` | selfsigned | 443, 8443 | t0, t1, t2 | certyfikat self-signed (443 i 8443) |
| `10.66.50.12` | `tls-expired` | expired | 443 | t0, t1, t2 | certyfikat wygasły 35 dni temu; odnowiony w t2 |
| `10.66.50.13` | `tls-mismatch` | mismatch | 443 | t0, t1, t2 | certyfikat wystawiony dla innej nazwy (intranet.uczelnia.example) |
| `10.66.50.20` | `redir-chain` | kariera | 80 | t0, t1, t2 | łańcuch przekierowań: / → /start → /pl/ → /pl/home (301, 302, 307) |
| `10.66.50.21` | `redir-ext` | stary-portal | 80 | t0, t1, t2 | przekierowanie na inny host (10.66.50.10); w t2 na 10.66.50.20 |

### Nagłówki, ciasteczka, własna sygnatura

| Adres | Kontener | Nazwy DNS | Porty | Stany | Co to jest |
| --- | --- | --- | --- | --- | --- |
| `10.66.60.10` | `hdr-leaky` | helpdesk | 80, 8000, 8081 | t0, t1, t2 | nagłówki zdradzające wersje i debug, CORS *, PHPSESSID bez flag; w t1 zmiana nagłówka, ciasteczek i portów (8000 → 8081) |
| `10.66.60.11` | `jwt-app` | dziennik | 80, 443 | t0, t1, t2 | ciasteczko-JWT bez HttpOnly/Secure, ASP.NET_SessionId bez Secure, nagłówki IIS/ASP.NET; ciasteczko naprawione w t2 |
| `10.66.60.12` | `kiosk-1` | kiosk-1 | 80 | t0, t1, t2 | InfoKiosk 4.2.1: cel własnej sygnatury (nagłówek, ciasteczko, fragment HTML, favicon, ścieżka, wersja w stopce); 4.3.0 w t1 |

### Trudne przypadki i hosty niestabilne

| Adres | Kontener | Nazwy DNS | Porty | Stany | Co to jest |
| --- | --- | --- | --- | --- | --- |
| `10.66.70.10` | `no-icmp` | pliki | 80 | t0, t1, t2 | host nie odpowiada na ICMP (iptables DROP icmp) |
| `10.66.70.11` | `stealth-high` | serwis | 8888, 18443, 31337 | t0, t1, t2 | usługi tylko na nietypowych portach (8888, 18443, 31337); reszta pakietów jest odrzucana po cichu |
| `10.66.70.12` | `slow` | archiwum | 80 | t0, t1, t2 | serwer odpowiadający po 4 s |
| `10.66.70.13` | `tarpit` | pulapka | 80, 2222 | t0, t1, t2 | port 2222 typu tarpit (1 bajt na 10 s) obok zwykłego HTTP |
| `10.66.70.14` | `many-ports` | multi | 64 portów TCP (81–49152) | t0, t1, t2 | host z 64 otwartymi portami HTTP |
| `10.66.70.15` | `volatile` | ogloszenia | 80 | t0, t1, t2 | treść strony inna przy każdym żądaniu (czas, licznik, losowe tokeny, nagłówek X-Request-Id) |
| `10.66.70.20` | `flapper` | stacja-pomiarowa | 80 | t0, t1, t2 | host niestabilny: osiągalny w pseudolosowych ~50% minut |
| `10.66.70.21` | `tod-office` | dziekanat-pc | 80 | t0, t1, t2 | host „godziny pracy”: 3 minuty włączony, 3 minuty wyłączony |
| `10.66.70.22` | `tod-night` | backup-nocny | 80 | t0, t1, t2 | host „nocny”: w cyklu 10 minut wyłączony przez pierwsze 4, włączony przez 6 |

### Pojedyncze hosty na krawędziach bloków

| Adres | Kontener | Nazwy DNS | Porty | Stany | Co to jest |
| --- | --- | --- | --- | --- | --- |
| `10.66.99.0` | `edge-zero` | zero | 80 | t0, t1, t2 | pojedynczy host na krawędzi bloku (10.66.99.0) |
| `10.66.99.255` | `edge-255` | ff | 80 | t0, t1, t2 | pojedynczy host na krawędzi bloku (10.66.99.255) |
| `10.66.128.1` | `router-2` | gw-akademik | 80 | t0, t1, t2 | imitacja MikroTik RouterOS 6.49.10, samotny host w 10.66.128.0/24 |
| `10.66.130.77` | `cam-3` | kamera-3 | 80 | t1, t2 | nowa kamera Hikvision: pojawia się w t1 |
| `10.66.200.200` | `kiosk-2` | kiosk-2 | 80 | t0, t1, t2 | InfoKiosk 4.2.1, samotny host w 10.66.200.0/24 |
| `10.66.255.254` | `printer-2` | drukarka-2 | 80, 443, 631 | t0, t1, t2 | imitacja HP LaserJet na ostatnim adresie sieci |

### Narzędzia

| Adres | Kontener | Nazwy DNS | Porty | Stany | Co to jest |
| --- | --- | --- | --- | --- | --- |
| `10.66.0.10` | `scanner-box` | — | — | t0, t1, t2 | skrzynka skanera: nmap, curl, dig (nie jest hostem laboratorium) |

<!-- END ADDRESS PLAN -->

## 7. Format prawdy wzorcowej

Typy: `lab/truth/truth.go`. Najważniejsze pola usługi:

| Pole | Znaczenie |
| --- | --- |
| `port`, `proto`, `name`, `name_alt`, `tunnel` | port i nazwa usługi; `name_alt` to inne dopuszczalne nazwy (np. nazwa, którą podaje nmap) |
| `product`, `version` | produkt i wersja tak, jak je widać z sieci |
| `technologies` (`name`, `category`, `version`, `aliases`) | technologie, które skaner musi wykryć |
| `tech_optional`, `class_optional` | poprawne, ale niewymagane: nie liczą się ani jako trafienie, ani jako fałszywy alarm |
| `classes` | klasy usługi (`admin-panel`, `login`, `staging`, `iot`, ...) |
| `http` | kod, tytuł, `Location`, `Server`, nagłówki, ciasteczka z flagami, hash favicony (mmh3 i sha256), `volatile` |
| `tls` | CN, SAN, wystawca, `self_signed`, `expired`, `host_mismatch`, `gen` (numer wydania certyfikatu) |
| `interesting` | nagłówki i ciasteczka, które Czujka powinna zebrać i oznaczyć |
| `signatures` | identyfikatory własnych sygnatur, które muszą trafić |
| `hard` | powód, dla którego usługa jest przypadkiem trudnym |

Host ma dodatkowo `availability` (host niestabilny) i `hard` (lista powodów).

## 8. Bezpieczeństwo

- Laboratorium działa tylko w sieci `czujka-lab`. Nie publikuje portów na hoście.
- Hasła w `docker-compose.yml` są jawne i służą tylko laboratorium. Skaner ich nie używa: Czujka niczego nie loguje.
- Imitacje nie mają żadnej logiki logowania. Strona logowania to statyczny HTML.
