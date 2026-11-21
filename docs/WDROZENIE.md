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

W katalogu głównym świeżego klonu, bez żadnego innego kroku:

```sh
git clone <adres repozytorium> czujka && cd czujka
docker compose up -d
docker compose logs czujka | grep -A3 "first administrator"     # login i hasło, pokazane raz
```

Plik `compose.yaml` w katalogu głównym włącza `deploy/docker-compose.yml` (Compose 2.20 lub nowszy). `docker compose up -d` buduje obrazy, gdy ich nie ma; po zmianie kodu: `docker compose up -d --build`. Polecenia `docker compose -f deploy/docker-compose.yml …` i `make up` działają jak dotąd i dają ten sam projekt `czujka`.

Bez `deploy/.env` sekrety powstają przy pierwszym starcie:

- jednorazowa usługa `secrets` (Alpine, bez sieci) zapisuje losowe hasło roli bazy w wolumenie `czujka-secrets`; baza czyta je przez `POSTGRES_PASSWORD_FILE`, a Czujka przez `CZUJKA_DB_PASSWORD_FILE`. W repozytorium nie ma hasła bazy;
- klucz główny powstaje w wolumenie `czujka-keys`;
- losowe hasło pierwszego administratora pojawia się raz w logu.

Własne wartości: `make init` zapisuje `deploy/.env` z losowymi sekretami (`FORCE=1` nadpisuje; stary klucz główny jest wtedy stracony). `docker compose up -d` w katalogu głównym czyta `deploy/.env`. `CZUJKA_DB_PASSWORD` z `deploy/.env` ma pierwszeństwo przed hasłem z wolumenu. Baza utworzona przed wersją z usługą `secrets` zachowuje swoje dotychczasowe hasło. Zrób kopię `deploy/.env` poza maszyną.

Zmierzone na czystej maszynie: `docker:28-dind` na Docker Desktop (arm64), 0 obrazów na starcie, klon z pakietu git gałęzi (zapis: `deploy/e2e/fresh-clone-dind.txt`). Koniec pomiaru to `/api/v1/healthz` z `status: ok` i 21 z 21 tabel zaszyfrowanych.

| Start | Klon | `docker compose up -d` do zdrowego API | Razem |
| --- | --- | --- | --- |
| obrazy pobrane z Docker Hub i zbudowane na maszynie (commit f964d6e) | 1 s | 79 s | **80 s** |
| to samo przez mirror.gcr.io (Docker Hub odrzucał wtedy pobrania anonimowe: `toomanyrequests`), commit d250e29 | 1 s | 115 s | **116 s** |
| to samo przez mirror.gcr.io, gałąź po scaleniu (commit 607c91e, z `pull_policy: build`) | 2 s | 51 s | **53 s** |
| paczka offline (§2.2) zamiast budowy, bez sieci | 3 s (rozpakowanie) | 23 s (`sh install.sh`) | **26 s** |

Dalej, w tej samej instancji: logowanie, „Ten komputer”, „Uruchom skan” w 9 s (przeglądarka sterowana skryptem), skan 41 s. Wynik na tej maszynie: nginx na 8787 (wersja i tytuł), API Dockera z TLS na 2376 i Czujka. Host ma etykietę „Host dockera (ten komputer)”. Czas pobierania obrazów zależy od łącza.

Wcześniejszy pomiar na maszynie z obrazami bazowymi w pamięci (`deploy/e2e/clone-timing.sh`, commit 19d57d8): 32 s z budową bez cache, 14 s z cache.

Sprawdzenie:

```sh
docker compose ps
curl -s http://127.0.0.1:8080/healthz
```

```json
{"db":"ok","engine":false,"field_encryption":{"algorithm":"AES-256-GCM envelope","key_id":"6f97b2a75ca6"},"status":"ok","tde":true,"tde_detail":{"active":true,"available":true,"tables":21,"encrypted":21,"wal_encrypted":true},"version":"dev"}
```

| Usługa | Obraz | Sieć i porty | Wolumeny |
| --- | --- | --- | --- |
| `secrets` | `alpine:3.22`, uruchamiana raz przed bazą | bez sieci | `czujka-secrets` (hasło roli bazy) |
| `db` | `deploy/db`: PostgreSQL 17 (Percona) z `pg_tde` | sieć `internal`, bez portu na hoście | `czujka-pgdata` (dane), `czujka-tde-keys` (klucze `pg_tde`), `czujka-secrets` (tylko odczyt) |
| `czujka` | `deploy/Dockerfile`: binarka Go, interfejs WWW, nmap 7.97, Alpine | sieci `internal` i `scan`; `127.0.0.1:8080` | `czujka-keys` (klucz główny), `czujka-secrets` (tylko odczyt) |

### 2.1 Sprawdzenie instalacji: `czujka doctor`

```sh
docker compose -f deploy/docker-compose.yml exec czujka czujka doctor     # albo --json
```

Polecenie sprawdza: połączenie z bazą, `pg_tde` (zaszyfrowane tabele i WAL), klucz główny (czy pasuje do danych), nmap i jego wersję (co najmniej 7.80), gniazda surowe (SYN, ICMP, ARP), DNS, wolne miejsce na dysku, `pg_dump` i `pg_restore` oraz trasę do sieci włączonych zakresów (bez wysyłania pakietów). Przy każdym błędzie drukuje poprawkę po polsku. Kod wyjścia jest różny od zera, gdy któraś kontrola ma stan `fail`. Administrator widzi ten sam raport w API: `GET /api/v1/doctor`.

### 2.2 Instalacja offline: `make bundle`

`make bundle` tworzy `dist/czujka-bundle-<wersja>.tar.gz`: obrazy `czujka`, `czujka-db:17` i `alpine:3.22` (`docker save`), pliki compose bez sekcji budowania, `.env.example`, `init.sh`, `install.sh` i instrukcję `CZYTAJ.txt`. Na maszynie docelowej wystarczy Docker z wtyczką compose, bez dostępu do rejestru obrazów:

```sh
tar -xzf czujka-bundle-<wersja>.tar.gz && cd czujka-bundle-<wersja>
sh install.sh      # docker load, .env z losowymi sekretami, start stosu, czujka doctor
```

Sprawdzone (`deploy/e2e/bundle-proof.sh`, 9 z 9 kontroli): paczka (350 MiB) trafia do czystego kontenera `docker:28-dind` z `--network none`, czyli bez dostępu do sieci. `install.sh` ładuje obrazy, tworzy `deploy/.env` i uruchamia stos w 29 s. Pomiar 2026-11-21 (commit d250e29, paczka 354 MiB, czysty `docker:28-dind`): 26 s od rozpakowania do zdrowego stosu. Ponownie po scaleniu (commit 607c91e, z obrazem `alpine:3.22` usługi `secrets`): 9 z 9 kontroli, instalacja 29 s. `/healthz` zwraca `ok` z aktywnym `pg_tde`, a administrator loguje się hasłem z instalatora.

### 2.3 Bez kontenerów: `make release`

`make release` buduje statyczne binarki linux/amd64 i linux/arm64 z wbudowanym interfejsem (`dist/release/`). Każde archiwum zawiera jednostkę systemd, plik zmiennych i instrukcję instalacji: [`deploy/systemd/README.md`](../deploy/systemd/README.md).

### 2.4 Ciągła integracja

`.github/workflows/ci.yml`: gofmt, build, vet i testy jednostkowe Go; testy integracyjne na PostgreSQL 17 z `pg_tde` w kontenerze; typecheck, lint, testy i build interfejsu; budowa obrazu produktu.

Kilka instalacji na jednej maszynie: dodaj `-p <nazwa>` i inny port, na przykład `CZUJKA_PORT=18480 docker compose -p czujka-test up -d`. Nazwy kontenerów i wolumenów dostają wtedy przedrostek `czujka-test`.

### 2.5 Test na szablonie organizatorów (`lab/jury`)

Szablon organizatorów to jedna maszyna: usługi w Dockerze na portach hosta (`lab/jury/README.md`). Są dwa tryby.

| Tryb | Kiedy | Co znaczy `localhost` |
| --- | --- | --- |
| domyślny (`deploy/docker-compose.yml`) | Docker Desktop (macOS, Windows) i Linux | host dockera: adres, na który wskazuje `host.docker.internal` (Docker Desktop: 192.168.65.254, Linux: brama mostu, np. 172.17.0.1). Czujka skanuje porty opublikowane przez hosta. |
| sieć hosta (`deploy/docker-compose.host-network.yml`) | tylko Linux | sam `127.0.0.1` maszyny; Czujka widzi też bezpośrednio każdą sieć mostkową Dockera na tej maszynie |

Tryb domyślny, od zera do pierwszego wyniku:

```sh
CZUJKA_PORT=9180 docker compose up -d
docker compose logs czujka | grep -A3 "first administrator"
(cd lab/jury && ./quickstart.sh up)
```

Szablon zajmuje port 8080, dlatego Czujka dostaje 9180. W interfejsie (`http://127.0.0.1:9180`) naciśnij „Ten komputer” i „Uruchom skan”. Profil domyślny (top 1000 i porty infrastruktury) obejmuje też porty szablonu spoza top 1000: `2223,5673,8474,8787,15432,15673,21000-21010`. Na stacji roboczej host dockera to ten sam komputer: pełny zakres portów (`1-65535`, `top-1000`) trafia sondami wykrywania wersji także w lokalne usługi innych programów. Gdy na komputerze działają inne programy, skanuj tylko porty szablonu (`21,80,81,443,2223,3001,5673,6379,8080,8081,8085,8086,8088,8089,8090,8474,8787,8888,15432,15673,21000-21010`) i ustaw tę samą listę w `allowed_ports` polityki bezpieczeństwa. Podgląd celu pokazuje „skanowany jako 192.168.65.254” (pole `maps_to` w API), a `/api/v1/healthz` podaje `host_gateway`. Host trafia do inwentarza raz, pod adresem bramy, z nazwą `localhost` i etykietą „Host dockera (ten komputer)”. Usługa Czujki na porcie `CZUJKA_PORT` tego hosta dostaje tag `czujka` i nie daje znalezisk. Wykluczenia i blokada operatora dotyczą adresu bramy, nie `127.0.0.1`.

Sieć hosta (Linux):

```sh
CZUJKA_PORT=9180 docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.host-network.yml up -d --build --wait
# compose.yaml w katalogu głównym nie łączy się z tym plikiem: podaj oba pliki -f
```

Interfejs słucha wtedy na `CZUJKA_BIND:CZUJKA_PORT` samego hosta (domyślnie `127.0.0.1`). Baza zostaje w swojej sieci i jest dostępna z hosta tylko na `127.0.0.1:CZUJKA_DB_HOST_PORT` (domyślnie 55432). Plik wymaga Docker Compose 2.24 lub nowszego.

Zmierzone 2026-11-21:

- Docker Desktop, tryb domyślny, cel `localhost`, własne kontenery na `127.0.0.1` (nginx i Toxiproxy), porty `18950,28787,28085`: `host_gateway` 192.168.65.254. Przebieg 1: 3 usługi, Czujka z tagiem `czujka`. Przebieg 2 (nginx zatrzymany, Toxiproxy +500 ms): `service_gone` na 28787 i `response_slower` na 28085 (509 ms, baza 5 ms). Przebieg 3: `service_returned` na 28787 (83 s nieobecności, 1 skan) i `response_recovered` (4 ms). Każdy przebieg 39–45 s dla jednego hosta i 3 portów.
- Linux (serwer z Ubuntu 24.04, ufw przepuszcza tylko 22), tryb domyślny, cel `localhost`, własne kontenery nginx opublikowane tylko na adresie mostu `172.17.0.1`, porty `28787,28788`: `host.docker.internal` w kontenerze to `172.17.0.1`, `host_gateway` 172.17.0.1, podgląd `localhost` → `maps_to` 172.17.0.1. Przebieg 1: obie usługi i etykieta „Host dockera (ten komputer)”. Przebieg 2 (nginx na 28787 zatrzymany): `service_gone` na 28787. Przebieg 3: `service_returned` (41 s nieobecności, 1 skan). Każdy przebieg 18–22 s.
  Na Linuksie port opublikowany tylko na `127.0.0.1` hosta (`-p 127.0.0.1:P:P`) nie jest osiągalny z kontenera przez `172.17.0.1`. Szablon publikuje porty na wszystkich adresach, więc tryb domyślny je widzi. Usługę związaną z `127.0.0.1` skanuje tryb sieci hosta.
  Za zaporą, która odrzuca pakiety bez odpowiedzi (ufw), zatrzymana usługa daje stan `filtered`, a nie `closed`. Port otwartej wcześniej usługi w stanie `filtered` na hoście, który odpowiada, to `service_gone`, a nie „usługa nieosiągalna”.
- Linux, sieć hosta, po zmianie sekretów (commit 607c91e, bez `.env`): `up -d --build --wait` 31 s, usługa `secrets` wygenerowała hasło bazy, interfejs i baza słuchają tylko na `127.0.0.1` (18090 i 55491). Cel `127.0.0.1`, porty `18090,28787`: przebieg 1 obie usługi (Czujka z tagiem `czujka`), przebieg 2 `service_gone` na 28787, przebieg 3 `service_returned` (1 min, 1 skan). Każdy przebieg 33–38 s.
- Linux (serwer z Ubuntu 24.04), sieć hosta, cel `127.0.0.1`, porty `18090,28787`: `network_mode=host`, interfejs i baza tylko na `127.0.0.1`, `host_gateway` puste. Przebiegi 1–3: `service_gone`, potem `service_returned` na 28787; usługa Czujki z tagiem `czujka`, bez znalezisk. Każdy przebieg 32–39 s.

Zmiany między skanami (`docs/API.md`, rodzaje zmian):

| Rodzaj | Kiedy |
| --- | --- |
| `service_returned` „Usługa wróciła” | usługa (ten sam host, port i protokół) była otwarta we wcześniejszym przebiegu, w poprzednim nie, teraz znów jest otwarta. Zmiana podaje, kiedy była otwarta ostatnio, ile sekund jej nie było i w ilu skanach. Usługa widziana wcześniej nigdy nie jest „nowa”. |
| `response_slower` „Wolniejsza odpowiedź” | czas odpowiedzi HTTP jest co najmniej 2 razy większy od bazy usługi i większy o co najmniej 300 ms; albo port jest otwarty, a HTTP nie odpowiedział (`"error": "no_answer"`), choć wcześniej odpowiadał. Baza: mediana ostatnich 5 pomiarów, które same nie były wolne; wystarczy jeden pomiar. Zgłaszane raz, przy przejściu. |
| `response_recovered` „Odpowiedź w normie” | wolna usługa znów odpowiada w zwykłym czasie |

Czas odpowiedzi to czas pierwszego żądania `GET` do usługi (`http.response_ms` w zapisie obserwacji). Seria do wykresu: `GET /api/v1/services/{id}/response-times`.

## 3. Zmienne `CZUJKA_*`

### 3.1 Zmienne pliku `deploy/.env` (czyta je `docker-compose.yml`)

| Zmienna | Domyślnie | Znaczenie |
| --- | --- | --- |
| `CZUJKA_DB_PASSWORD` | puste | hasło roli bazy; puste = losowe, zapisane przy pierwszym starcie w wolumenie `czujka-secrets` (usługa `secrets`). Działa przy tworzeniu bazy; zmiana później wymaga też `ALTER ROLE` w bazie |
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
| `CZUJKA_HOST_GATEWAY` | puste | adres, pod którym Czujka w kontenerze skanuje cele `localhost`, `127.x` i `::1`. Puste: adres IPv4 `host.docker.internal` (tylko w kontenerze); `off`: pętla zwrotna zostaje pętlą zwrotną; adres IPv4: ten adres. Odpowiedź tylko IPv6 wyłącza mapowanie (ostrzeżenie w logu) |
| `CZUJKA_DB_HOST_PORT` | `55432` | tylko w trybie sieci hosta: port bazy na `127.0.0.1` hosta |

### 3.2 Zmienne binarki ustawiane przez obraz albo compose

| Zmienna | Wartość w stosie | Znaczenie |
| --- | --- | --- |
| `CZUJKA_DB_URL` | `postgres://czujka:…@db:5432/czujka?sslmode=disable` | adres bazy; wymagana |
| `CZUJKA_DB_PASSWORD_FILE` | puste (w compose: `/run/czujka-secrets/db_password`) | plik z hasłem bazy; hasło trafia do `CZUJKA_DB_URL` w miejsce hasła z adresu |
| `CZUJKA_LISTEN` | `:8080` | adres nasłuchu w kontenerze |
| `CZUJKA_PUBLISHED_PORT` | `CZUJKA_PORT` | port, na którym host publikuje interfejs; usługa Czujki na tym porcie hosta dockera dostaje tag `czujka`. Puste: port z `CZUJKA_LISTEN` |
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

Bez `--password` polecenie drukuje losowe hasło. Polecenia binarki: `serve`, `migrate`, `user create`, `rotate-key`, `genkey`, `healthcheck`, `doctor`, `backup`, `restore`, `version`.

## 5. Dostęp z innych maszyn

Domyślnie interfejs słucha tylko na `127.0.0.1` i bez TLS. Dla dostępu z sieci:

1. Postaw serwer pośredniczący z TLS (nginx, Caddy, Traefik) przed `127.0.0.1:8080`.
2. Ustaw `CZUJKA_TRUST_PROXY=true` i `CZUJKA_COOKIE_SECURE=true`.
3. Nie ustawiaj `CZUJKA_BIND=0.0.0.0` bez TLS: hasła i ciasteczko sesji szłyby jawnie.

### 5.1 Skan sieci lokalnej a tablica sąsiadów jądra

Skan adresów w tej samej podsieci co interfejs skanera tworzy wpis ARP dla każdego sondowanego adresu, także cichego. Limit tablicy sąsiadów (`net.ipv4.neigh.default.gc_thresh1/2/3`, domyślnie 128/512/1024) jest wspólny dla całego hosta, także dla kontenerów. Po przepełnieniu jądro loguje `neighbour: arp_cache: neighbor table overflow!` i usuwa wpisy samego hosta. Wtedy host przestaje m.in. rozwiązywać nazwy DNS, a skan gubi hosty.

`czujka doctor` (kontrola `neighbour_table`) porównuje `gc_thresh3` z liczbą adresów w sieci lokalnej skanera w największym włączonym zakresie i drukuje gotowe wartości. Uwaga: jądro pokazuje `gc_thresh3` tylko w przestrzeni sieciowej hosta. W kontenerze Czujki (bez `network_mode: host`) pliku nie ma; wtedy kontrola ma stan `UWAGA`, podaje potrzebną wartość i polecenie sprawdzenia na hoście (`sysctl net.ipv4.neigh.default.gc_thresh3`). Sprawdzone na jądrze Docker Desktop: w zwykłym kontenerze katalog `/proc/sys/net/ipv4/neigh/default` nie istnieje, z `--network host` jest (1024). Dla zakresu /16 skanowanego bezpośrednio, na hoście (nie w kontenerze):

```sh
cat <<'EOF' | sudo tee /etc/sysctl.d/90-czujka-neigh.conf
net.ipv4.neigh.default.gc_thresh1 = 32768
net.ipv4.neigh.default.gc_thresh2 = 131072
net.ipv4.neigh.default.gc_thresh3 = 262144
EOF
sudo sysctl --system
```

`install.sh` z paczki offline proponuje zapisanie tego pliku, gdy limit jest mniejszy (`CZUJKA_WRITE_SYSCTL=t` bez pytania). Skan przez bramę (cele poza siecią lokalną) nie zapełnia tej tablicy.

### 5.2 Instancja publiczna: zabezpieczenia

- **Blokada operatora.** Ustaw `CZUJKA_ALLOWED_NETWORKS` na sieci, które wolno skanować, np. `10.91.0.0/16,127.0.0.1`. To twarda granica wdrożenia. Cel poza nią jest odrzucany przy wpisie do zakresu, w skanie doraźnym, w ponownym sondowaniu i przy planowaniu przebiegu. Nazwa domenowa przechodzi tylko wtedy, gdy każdy jej adres leży w blokadzie. Administrator może zawęzić `allowed_networks` w polityce bezpieczeństwa, ale nie może jej poszerzyć poza blokadę (odpowiedź 422). Polityka w `GET /settings/safety` pokazuje blokadę w polu `operator_networks`. Skradziona sesja administratora nie skieruje więc skanera w internet. Przy każdym starcie Czujka przycina zapisane `allowed_networks` do blokady: sieć wewnątrz zostaje, szersza zostaje zastąpiona częścią leżącą w blokadzie, a sieć bez części wspólnej znika. Zmiana trafia do logu i do dziennika audytu (`safety.lock_clamp`). Polityka zapisana przed ustawieniem blokady nie blokuje więc późniejszych zmian innych pól.
- **Ograniczenie logowania.** Z jednego adresu klienta: 20 prób na minutę (`CZUJKA_LOGIN_RATE_PER_MIN`), potem 429. Na jedno konto: 5 nieudanych prób (`CZUJKA_LOGIN_MAX_FAILURES`) blokuje konto na 15 minut (`CZUJKA_LOGIN_LOCKOUT`), z każdego adresu. Za serwerem pośredniczącym adres klienta to ostatni wpis `X-Forwarded-For`, więc podrobiony nagłówek od klienta nie omija limitu. Uwaga: blokada konta działa też przeciw atakującemu, który zna adres e-mail. Na instancji publicznej nie używaj domyślnego `admin@czujka.local`.
- **Nagłówki bezpieczeństwa** na każdej odpowiedzi: `Content-Security-Policy` bez skryptów inline i z `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Strict-Transport-Security` przy TLS.

Sprawdzenie na prawdziwym stosie: `./e2e/lock/run.sh` (19 kontroli: blokada operatora, nagłówki, limit logowania za serwerem pośredniczącym, blokada konta, adres klienta w dzienniku audytu). Skrypt niczego nie skanuje.

## 6. Kopia zapasowa i odtwarzanie

`czujka backup` zapisuje jedno zaszyfrowane archiwum z całą bazą. `czujka restore` odtwarza je do pustej bazy. Do odtworzenia potrzebne są **dwie rzeczy**: archiwum i klucz główny. Bez klucza głównego archiwum się nie otworzy.

### 6.1 Kopia

```sh
docker compose -f deploy/docker-compose.yml exec czujka czujka backup
# backup: /var/lib/czujka/backups/czujka-20261121-145951.czbk (0.1 MiB, 49ms), master key dcad22502f9f, ...
docker compose -f deploy/docker-compose.yml cp czujka:/var/lib/czujka/backups/. ./kopie/
```

Opcja `-o PLIK` wybiera plik (`-o -`: standardowe wyjście). Klucz główny trzymaj osobno od archiwum: w `deploy/.env` (`CZUJKA_MASTER_KEY`) albo w pliku `/var/lib/czujka/master.key`.

Jak to działa:

- W środku jest `pg_dump` w formacie custom, bez rozszerzenia `pg_tde` (baza docelowa ma własne). Tabele zachowują metodę dostępu `tde_heap`.
- Archiwum jest szyfrowane AES-256-GCM w porcjach po 1 MiB. Klucz archiwum powstaje z klucza głównego (HKDF-SHA256, losowa sól dla każdego archiwum).
- Każda porcja jest związana z nagłówkiem, swoją pozycją i znacznikiem ostatniej porcji. Archiwum ucięte, zmienione albo przedłużone nie otworzy się.
- Archiwum nie zawiera jawnego tekstu. Sprawdzone: nazwa hosta, baner usługi i klucz API DefectDojo nie występują w pliku.
- Po rotacji klucza (rozdz. 7) stary klucz w `CZUJKA_MASTER_KEY_OLD` lub `master.key.old` nadal otwiera starsze archiwa.

### 6.2 Odtworzenie

```sh
docker compose -f deploy/docker-compose.yml stop czujka
docker compose -f deploy/docker-compose.yml run --rm --no-deps -v "$PWD/kopie:/backup:ro" czujka restore -i /backup/<plik>.czbk --force
docker compose -f deploy/docker-compose.yml start czujka
```

- Bez `--force` polecenie odmawia, gdy baza ma już tabele Czujki. `--force` usuwa je przed odtworzeniem (rozszerzenie `pg_tde` zostaje).
- Archiwum z innym kluczem głównym jest odrzucane przed jakąkolwiek zmianą w bazie.
- `pg_restore` działa w jednej transakcji: błąd zostawia bazę bez zmian.
- Po odtworzeniu polecenie porównuje liczby wierszy z manifestem archiwum, sprawdza klucz główny na polach szyfrowanych i stan `pg_tde`.

Na nowej maszynie: ustaw w `deploy/.env` ten sam `CZUJKA_MASTER_KEY`, uruchom stos (powstanie pusta baza z `pg_tde`), potem wykonaj kroki powyżej.

Sprawdzone na dwóch czystych stosach (`deploy/e2e/backup-restore.sh`, 11 kontroli): dane stosu A (zakres, host wpisany ręcznie, import nmap, obserwacje, klucz API DefectDojo) wracają w stosie B. Administrator stosu A loguje się w B. `pg_tde` szyfruje 23 z 23 tabel. `czujka doctor` w B pokazuje `ok` dla bazy, `pg_tde` i klucza. Odtworzenie z innym kluczem głównym jest odrzucone, a baza B zostaje pusta.

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
docker compose -f deploy/docker-compose.yml exec czujka czujka backup   # kopia z rozdz. 6
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
| Usługi opublikowane na portach hosta dockera | cel `localhost` (mapowany na `host.docker.internal`, §2.5) | sprawdzone na Docker Desktop 2026-11-21 |
| `127.0.0.1` maszyny i wszystkie sieci mostkowe Dockera; ten sam segment L2 z ARP | `deploy/docker-compose.host-network.yml` (`network_mode: host`, tylko Linux, §2.5) | cel `127.0.0.1` sprawdzony na Linuksie 2026-11-21; sieci mostkowe i ARP niesprawdzone |

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
| Nie wiem, co jest nie tak z instalacją | | `czujka doctor` (rozdz. 2.1): każda kontrola z poprawką po polsku |

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
