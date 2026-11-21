# Wdrożenie Czujki

Instrukcja dla administratora. Polecenia z tego dokumentu zostały wykonane 2026-11-21 na commicie `6886182` (Docker Engine 29.6.2, Docker Compose 5.3.1, linux/arm64). Miejsca niesprawdzone są oznaczone.

> Silnik skanu nie jest jeszcze podłączony do binarki (`GET /healthz` pokazuje `"engine":false`). Stos startuje i działa: logowanie, cele, profile, role, polityka, eksport. Start skanu odpowiada `501 not_wired`. Stan modułów: `docs/ZGODNOSC.md`.

## 1. Wymagania

| | |
| --- | --- |
| Docker | Docker Engine z wtyczką Compose v2 |
| Architektura | linux/amd64 albo linux/arm64 (obraz bazy istnieje dla obu) |
| Sieć podczas budowania | Docker Hub, `proxy.golang.org`, rejestr npm, repozytorium pakietów Alpine |
| Dysk | obraz `czujka` 72 MB, obraz bazy `czujka-db:17` 1,37 GB, plus dane |
| Pamięć w spoczynku | `czujka` 42 MiB, baza 27 MiB (pomiar `docker stats` na pustej instalacji) |
| Uprawnienia kontenera | `NET_RAW` i `NET_ADMIN` dla nmap; bez nich skan przechodzi na tryb połączeniowy |

## 2. Start

```sh
git clone <adres repozytorium> czujka && cd czujka
cp deploy/.env.example deploy/.env        # opcjonalnie: własne sekrety, patrz rozdz. 3
docker compose -f deploy/docker-compose.yml up -d --build --wait
```

Skrót: `make up`. Pierwsze budowanie pobiera obrazy i zależności. Kolejne starty trwają kilkanaście sekund.

Stos startuje także bez `deploy/.env`. Wtedy:

- hasło roli bazy ma wartość domyślną (baza nie ma portu ani trasy na zewnątrz),
- klucz główny powstaje w wolumenie `czujka-keys`,
- losowe hasło pierwszego administratora pojawia się raz w logu.

Sprawdzenie:

```sh
docker compose -f deploy/docker-compose.yml ps
curl -s http://127.0.0.1:8080/healthz
```

```json
{"db":"ok","engine":false,"field_encryption":{"algorithm":"AES-256-GCM envelope","key_id":"6f97b2a75ca6"},"status":"ok","tde":true,"tde_detail":{"active":true,"available":true,"tables":21,"encrypted":21,"wal_encrypted":true},"version":"dev"}
```

| Usługa | Obraz | Sieć i porty | Wolumeny |
| --- | --- | --- | --- |
| `db` | `deploy/db`: PostgreSQL 17 (Percona) z `pg_tde` | sieć `internal`, bez portu na hoście | `czujka-pgdata` (dane), `czujka-tde-keys` (klucze `pg_tde`) |
| `czujka` | `deploy/Dockerfile`: binarka Go, interfejs WWW, nmap 7.97, Alpine | sieci `internal` i `scan`; `127.0.0.1:8080` | `czujka-keys` (klucz główny) |

Kilka instalacji na jednej maszynie: dodaj `-p <nazwa>` i inny port, na przykład `CZUJKA_PORT=18480 docker compose -p czujka-test -f deploy/docker-compose.yml up -d --build --wait`. Nazwy kontenerów i wolumenów dostają wtedy przedrostek `czujka-test`.

## 3. Zmienne `CZUJKA_*`

### 3.1 Zmienne pliku `deploy/.env` (czyta je `docker-compose.yml`)

| Zmienna | Domyślnie | Znaczenie |
| --- | --- | --- |
| `CZUJKA_DB_PASSWORD` | `czujka-internal-network-only` | hasło roli bazy; ustaw własne przed pierwszym startem |
| `CZUJKA_ADMIN_EMAIL` | `admin@czujka.local` | pierwszy administrator, tworzony przy pierwszym starcie |
| `CZUJKA_ADMIN_PASSWORD` | puste | hasło pierwszego administratora (co najmniej 10 znaków); puste = losowe, pokazane raz w logu |
| `CZUJKA_MASTER_KEY` | puste | klucz główny szyfrowania pól: 32 bajty jako base64 albo hex; puste = klucz w pliku w wolumenie |
| `CZUJKA_MASTER_KEY_OLD` | puste | poprzednie klucze po przecinku; tylko na czas rotacji |
| `CZUJKA_TDE` | `require` | `require`: nie startuj bez `pg_tde`; `auto`: startuj i ostrzeż; `off` |
| `CZUJKA_BIND` | `127.0.0.1` | adres hosta, na którym słucha interfejs |
| `CZUJKA_PORT` | `8080` | port na hoście |
| `CZUJKA_COOKIE_SECURE` | `auto` | flaga `Secure` ciasteczka sesji: `auto` (przy TLS), `true`, `false` |
| `CZUJKA_TRUST_PROXY` | `false` | `true` za serwerem pośredniczącym: adres klienta to ostatni wpis `X-Forwarded-For` (dopisany przez serwer pośredniczący), TLS z `X-Forwarded-Proto` |
| `CZUJKA_ALLOWED_NETWORKS` | puste | blokada operatora: sieci CIDR po przecinku. Czujka nie skanuje nic poza nimi. Żaden użytkownik, także administrator, nie poszerzy jej w interfejsie ani w API |
| `CZUJKA_TZ` | `Europe/Warsaw` | strefa czasowa histogramu dostępności hostów (godzina tygodnia) |
| `CZUJKA_VERSION` | `dev` | etykieta obrazu i wersja w `/healthz` |

### 3.2 Zmienne binarki ustawiane przez obraz albo compose

| Zmienna | Wartość w stosie | Znaczenie |
| --- | --- | --- |
| `CZUJKA_DB_URL` | `postgres://czujka:…@db:5432/czujka?sslmode=disable` | adres bazy; wymagana |
| `CZUJKA_LISTEN` | `:8080` | adres nasłuchu w kontenerze |
| `CZUJKA_WEB_DIR` | `/app/web` | katalog ze zbudowanym interfejsem |
| `CZUJKA_MASTER_KEY_FILE` | `/var/lib/czujka/master.key` | plik klucza głównego; powstaje z prawami 0600, gdy go nie ma i `CZUJKA_MASTER_KEY` jest puste |

### 3.3 Pozostałe zmienne binarki (plik compose ich nie przekazuje)

| Zmienna | Domyślnie | Znaczenie |
| --- | --- | --- |
| `CZUJKA_SESSION_TTL` | `12h` | czas życia sesji |
| `CZUJKA_LOGIN_MAX_FAILURES` | `5` | nieudane logowania przed blokadą konta |
| `CZUJKA_LOGIN_LOCKOUT` | `15m` | czas blokady konta |
| `CZUJKA_LOGIN_RATE_PER_MIN` | `20` | próby logowania na minutę z jednego adresu |
| `CZUJKA_LOG_FORMAT` | `json` | `json` albo `text` |
| `CZUJKA_AUTO_RESUME` | `true` | wznów po starcie przebiegi przerwane restartem |
| `CZUJKA_INGEST_BATCH` | `250` | liczba hostów w jednej paczce zapisu do bazy |
| `CZUJKA_USER_PASSWORD` | – | hasło dla polecenia `czujka user create`, gdy nie ma `--password` |

Żeby je ustawić, dodaj plik `deploy/docker-compose.override.yml` i podaj go drugim `-f`:

```yaml
services:
  czujka:
    environment:
      CZUJKA_SESSION_TTL: 8h
      CZUJKA_LOGIN_MAX_FAILURES: "3"
```

```sh
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.override.yml up -d --wait
```

Zmienne testowe (tylko dla programistów): `CZUJKA_TEST_DB_URL`, `CZUJKA_TEST_REQUIRE_TDE`, `CZUJKA_BENCH`. Obraz bazy czyta `CZUJKA_TDE_KEYRING` (ścieżka pliku kluczy `pg_tde`, domyślnie `/tde-keys/czujka-keyring.per`).

## 4. Pierwsze logowanie i użytkownicy

```sh
docker compose -f deploy/docker-compose.yml logs czujka | grep -A3 "first administrator"
```

```text
  Czujka: first administrator created
    e-mail:   admin@czujka.local
    password: <losowe hasło>
  Change it after the first login.
```

Otwórz `http://127.0.0.1:8080` i zaloguj się. Hasło zmienisz w „Administracja → Użytkownicy” albo poleceniem:

```sh
docker compose -f deploy/docker-compose.yml exec -T czujka \
  czujka user create --email admin@czujka.local --reset --password 'NoweHaslo-2026!'
```

Konta dla pozostałych ról (`admin`, `editor`, `analyst`, `viewer` albo własna rola):

```sh
docker compose -f deploy/docker-compose.yml exec -T czujka \
  czujka user create --email analityk@example.org --role analyst --password 'Haslo-Analityka-1'
# user analityk@example.org created with role analyst (id 3)
```

Bez `--password` polecenie drukuje losowe hasło. Polecenia binarki: `serve`, `migrate`, `user create`, `rotate-key`, `genkey`, `healthcheck`, `version`.

## 5. Dostęp z innych maszyn

Domyślnie interfejs słucha tylko na `127.0.0.1` i bez TLS. Dla dostępu z sieci:

1. Postaw serwer pośredniczący z TLS (nginx, Caddy, Traefik) przed `127.0.0.1:8080`.
2. Ustaw `CZUJKA_TRUST_PROXY=true` i `CZUJKA_COOKIE_SECURE=true`.
3. Nie ustawiaj `CZUJKA_BIND=0.0.0.0` bez TLS: hasła i ciasteczko sesji szłyby jawnie.

### 5.1 Instancja publiczna: zabezpieczenia

- **Blokada operatora.** Ustaw `CZUJKA_ALLOWED_NETWORKS` na sieci, które wolno skanować, np. `10.91.0.0/16,127.0.0.1`. To twarda granica wdrożenia. Cel poza nią jest odrzucany przy wpisie do zakresu, w skanie doraźnym, w ponownym sondowaniu i przy planowaniu przebiegu. Nazwa domenowa przechodzi tylko wtedy, gdy każdy jej adres leży w blokadzie. Administrator może zawęzić `allowed_networks` w polityce bezpieczeństwa, ale nie może jej poszerzyć poza blokadę (odpowiedź 422). Polityka w `GET /settings/safety` pokazuje blokadę w polu `operator_networks`. Skradziona sesja administratora nie skieruje więc skanera w internet.
- **Ograniczenie logowania.** Z jednego adresu klienta: 20 prób na minutę (`CZUJKA_LOGIN_RATE_PER_MIN`), potem 429. Na jedno konto: 5 nieudanych prób (`CZUJKA_LOGIN_MAX_FAILURES`) blokuje konto na 15 minut (`CZUJKA_LOGIN_LOCKOUT`), z każdego adresu. Za serwerem pośredniczącym adres klienta to ostatni wpis `X-Forwarded-For`, więc podrobiony nagłówek od klienta nie omija limitu. Uwaga: blokada konta działa też przeciw atakującemu, który zna adres e-mail. Na instancji publicznej nie używaj domyślnego `admin@czujka.local`.
- **Nagłówki bezpieczeństwa** na każdej odpowiedzi: `Content-Security-Policy` bez skryptów inline i z `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Strict-Transport-Security` przy TLS.

Sprawdzenie na prawdziwym stosie: `./e2e/lock/run.sh` (19 kontroli: blokada operatora, nagłówki, limit logowania za serwerem pośredniczącym, blokada konta, adres klienta w dzienniku audytu). Skrypt niczego nie skanuje.

## 6. Kopia zapasowa i odtwarzanie

Do odtworzenia potrzebne są **dwie rzeczy**: zrzut bazy i klucz główny. Bez klucza głównego pola szyfrowane (notatki, dowody, wartości ciasteczek, klucz API DefectDojo) są stracone.

### 6.1 Kopia

```sh
# 1. zrzut logiczny bazy
docker compose -f deploy/docker-compose.yml exec -T db \
  pg_dump -h 127.0.0.1 -U czujka -d czujka --clean --if-exists > czujka-backup.sql

# 2. klucz główny (gdy jest w pliku; gdy jest w deploy/.env, skopiuj wartość CZUJKA_MASTER_KEY)
docker compose -f deploy/docker-compose.yml exec -T czujka cat /var/lib/czujka/master.key > czujka-master.key
chmod 600 czujka-master.key
```

**Zrzut jest jawny.** `pg_dump` czyta dane już odszyfrowane przez `pg_tde`. Sprawdzone: zrzut zawiera adresy e-mail użytkowników tekstem; kolumny warstwy 2 pozostają szyfrogramami (`czk1.…`). Zaszyfruj plik (na przykład `age` albo `gpg`) i trzymaj klucz główny osobno od zrzutu.

### 6.2 Odtworzenie

```sh
docker compose -f deploy/docker-compose.yml stop czujka
docker compose -f deploy/docker-compose.yml exec -T db \
  psql -h 127.0.0.1 -U czujka -d czujka -v ON_ERROR_STOP=1 -q < czujka-backup.sql
docker compose -f deploy/docker-compose.yml start czujka
curl -s http://127.0.0.1:8080/healthz
```

Sprawdzone: po odtworzeniu `/healthz` pokazuje `"db":"ok"` i 21 zaszyfrowanych tabel, a zakresy i cele są na miejscu. Tabele wracają do `tde_heap`, bo zrzut zapisuje metodę dostępu.

Na nowej maszynie: najpierw uruchom stos (powstanie pusta baza z `pg_tde`), ustaw `CZUJKA_MASTER_KEY` w `deploy/.env` na wartość z kopii, potem wykonaj kroki powyżej. Ten wariant nie był uruchomiony w tym sprawdzeniu.

Kopia wolumenów zamiast zrzutu wymaga wszystkich trzech wolumenów naraz (`czujka-pgdata`, `czujka-tde-keys`, `czujka-keys`) przy zatrzymanym stosie. Nie była sprawdzona.

## 7. Rotacja klucza głównego

```sh
NEW=$(docker compose -f deploy/docker-compose.yml exec -T czujka czujka genkey)
OLD=$(docker compose -f deploy/docker-compose.yml exec -T czujka cat /var/lib/czujka/master.key)   # albo dotychczasowa wartość z deploy/.env
docker compose -f deploy/docker-compose.yml exec -T \
  -e CZUJKA_MASTER_KEY="$NEW" -e CZUJKA_MASTER_KEY_OLD="$OLD" czujka czujka rotate-key
```

```text
current master key id: 2a1e32e2d201
  re-wrapped settings.secret                  2
ciphertexts per key id before: map[6f97b2a75ca6:2]
ciphertexts per key id after:  map[2a1e32e2d201:2]
done: remove CZUJKA_MASTER_KEY_OLD and restart czujka with the new key
```

Potem **koniecznie**:

1. Wpisz `CZUJKA_MASTER_KEY=<nowy klucz>` do `deploy/.env`. Zmienna ma pierwszeństwo przed plikiem w wolumenie, w którym nadal leży stary klucz.
2. `docker compose -f deploy/docker-compose.yml up -d --wait`
3. Sprawdź `key_id` w `/healthz`.
4. Zapisz nowy klucz w kopii zapasowej.

Bez kroku 1 usługa po restarcie nie wystartuje i pokaże w logu: `the master key does not match this database (data was encrypted with key id 2a1e32e2d201, the keyring has [6f97b2a75ca6])`. Sprawdzone oba przypadki.

Rotacja opakowuje na nowo tylko klucze danych, więc jest szybka. Przerwaną rotację można uruchomić ponownie. Rotacja klucza `pg_tde` to osobna operacja po stronie bazy (funkcje `pg_tde`); nie była sprawdzona.

## 8. Aktualizacja

```sh
# najpierw kopia z rozdz. 6
git pull
docker compose -f deploy/docker-compose.yml up -d --build --wait
curl -s http://127.0.0.1:8080/healthz
```

`czujka serve` stosuje migracje bazy przy każdym starcie (`internal/store/migrations`). Migracje są idempotentne (test `TestMigrateIsIdempotentAndTablesAreEncrypted`). Dziś istnieje jedna migracja, więc przejście między wersjami schematu nie było jeszcze ćwiczone. Przebieg przerwany restartem dostaje stan `paused` z powodem `restart` i wznawia się po starcie (`CZUJKA_AUTO_RESUME`).

## 9. Jak skaner dołącza do sieci

Kontener `czujka` jest w sieci `scan` (zwykły most Dockera). Przez nią i przez host dociera do adresów osiągalnych z maszyny.

| Cel skanu | Jak połączyć | Stan |
| --- | --- | --- |
| Kontenery laboratorium w innej sieci Dockera | `docker network connect <sieć_laboratorium> czujka-czujka-1` | Polecenie sprawdzone: kontener dostaje adres w dołączonej sieci. Skan z produktu: do weryfikacji po integracji silnika. |
| To samo na stałe | plik override z siecią zewnętrzną (niżej) | niesprawdzone |
| Sieć fizyczna za hostem | Ruch wychodzi przez NAT hosta. Wykrywanie ARP nie działa przez NAT; działają ICMP i TCP. | do weryfikacji po integracji silnika |
| Ten sam segment L2 z ARP | `network_mode: host` (tylko Linux) | niesprawdzone |

```yaml
# deploy/docker-compose.override.yml
services:
  czujka:
    networks: [internal, scan, lab]
networks:
  lab:
    external: true
    name: <sieć_laboratorium>
```

Nazwę sieci laboratorium pokazuje `docker network ls`. Po odłączeniu: `docker network disconnect <sieć> czujka-czujka-1`.

Kontener ma `NET_RAW` i `NET_ADMIN`, a nmap ma je nadane na pliku. Dzięki temu skan SYN, ICMP i ARP działa bez użytkownika root. Gdy środowisko nie pozwala na te uprawnienia, silnik używa skanu połączeniowego.

Narzędzie `scanprobe` uruchamia sam silnik bez bazy i API:

```sh
go run ./cmd/scanprobe -targets 127.0.0.1 -ports 8080 -pps 50
# COMPLETED: 1/1 addresses, 1 hosts up, 1 open services, 25 packets (avg 1 pps, limit 50)
```

## 10. Rozwiązywanie problemów

| Objaw | Przyczyna | Rozwiązanie |
| --- | --- | --- |
| Budowanie kończy się na `go mod download` z `dial tcp: lookup proxy.golang.org … i/o timeout` | brak DNS albo sieci w kontenerze budującym (wystąpiło raz podczas tego sprawdzenia) | uruchom polecenie ponownie; sprawdź DNS Dockera; w sieci bez internetu zbuduj obraz gdzie indziej i przenieś go przez `docker save` / `docker load` |
| `czujka` restartuje się, log: `the master key does not match this database` | inny klucz główny niż ten, którym zaszyfrowano dane | ustaw właściwy `CZUJKA_MASTER_KEY`; po rotacji patrz rozdz. 7 |
| Start zatrzymany: `CZUJKA_TDE=require but pg_tde is not usable` | baza bez `pg_tde` (na przykład zewnętrzny PostgreSQL) | użyj obrazu `deploy/db` albo świadomie ustaw `CZUJKA_TDE=auto` |
| `/healthz` pokazuje `"tde":false` | nie wszystkie tabele są w `tde_heap` | `tde_detail.reason` podaje liczbę tabel; sprawdź zapytaniem z `docs/BEZPIECZENSTWO.md` §2.1 |
| Port 8080 zajęty | inna usługa na hoście | `CZUJKA_PORT=18080` w `deploy/.env` |
| Nie znam hasła administratora | log został usunięty | `czujka user create --email … --reset --password …` (rozdz. 4) |
| Logowanie: konto zablokowane | 5 nieudanych prób | odczekaj 15 minut albo ustaw nowe hasło poleceniem z rozdz. 4 |
| Odpowiedź `403 missing or wrong CSRF token` przy wywołaniach API | brak nagłówka `X-CSRF-Token` | weź `csrf_token` z `GET /api/v1/me` |
| Odpowiedź `501 not_wired` | moduł nie jest podłączony w tej wersji binarki | `docs/ZGODNOSC.md`; `/healthz` pole `engine` |
| Po zalogowaniu przez HTTP z innej maszyny sesja nie działa | `CZUJKA_COOKIE_SECURE=true` bez TLS | użyj TLS (rozdz. 5) |
| Skan nie widzi hostów laboratorium | kontener nie jest w sieci laboratorium | rozdz. 9 |

Logi: `docker compose -f deploy/docker-compose.yml logs -f czujka` (JSON, jeden wpis na wiersz).

## 11. Zatrzymanie i usunięcie

```sh
docker compose -f deploy/docker-compose.yml down        # dane i klucze zostają w wolumenach
docker compose -f deploy/docker-compose.yml down -v     # usuwa dane, klucze pg_tde i klucz główny: nieodwracalne
```

## 12. Praca programisty

```sh
make dev                # baza w dockerze (127.0.0.1:55432) + czujka na 127.0.0.1:8080
make test               # gofmt, build, vet, testy jednostkowe (testy bazy są pomijane bez bazy)
make test-integration   # wszystkie testy na prawdziwym PostgreSQL z pg_tde
make bench              # zapis 10 000 hostów x 3 usługi i czasy API
```

W tym sprawdzeniu `go test ./...` przeszedł dla wszystkich pakietów, a testy `internal/store`, `internal/api`, `internal/auth` i `internal/runner` przeszły także na PostgreSQL z `pg_tde`. `make bench` nie był uruchomiony.
