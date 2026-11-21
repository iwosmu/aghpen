# Czujka: skaner, który rozumie czas

```sh
git clone https://github.com/iwosmu/aghpen.git czujka && cd czujka
docker compose up -d
```

Otwórz `http://127.0.0.1:8080` i naciśnij **„Ten komputer”**, potem **„Uruchom skan”**. Login i hasło pierwszego administratora: `docker compose logs czujka | grep -A3 "first administrator"`.

Wynik: usługi na portach tego komputera, także kontenery Dockera z opublikowanymi portami, z wersjami, tytułami stron i czasem odpowiedzi. Kolejny skan pokazuje, co zniknęło, co wróciło i co zwolniło.

### Kryterium oceny → gdzie to zobaczyć

Liczby pochodzą z [`docs/WYNIKI.md`](docs/WYNIKI.md) (jedno źródło). Pełna lista wymagań z dowodami: [`docs/ZGODNOSC.md`](docs/ZGODNOSC.md).

| Waga | Kryterium | Ekran albo polecenie | Zmierzone | Dowód |
| --- | --- | --- | --- | --- |
| 30% | Discovery i identyfikacja usług w dużej sieci | przebieg /16 laboratorium; „Hosty”, „Usługi” | hosty 67 z 67, otwarte porty 154 ze 155, 0 fałszywych | [WYNIKI](docs/WYNIKI.md#wykrywanie-w-sieci-16), `e2e/lab-gate.sh` |
| 20% | Uruchomienie, import/eksport, DefectDojo, dokumentacja | `docker compose up -d`; „Import / eksport”; „Znaleziska” → „Eksport do DefectDojo” | start 51–115 s; e2e 100 ze 100 kontroli | [WYNIKI](docs/WYNIKI.md#uruchomienie), `e2e/full/transcript.txt`, `web/REPORT-LAB.md` §11 |
| 15% | Zmiany w czasie, niestabilne hosty, raport | szablon: `./quickstart.sh change` i drugi skan → „Usługa zniknęła”; `up` → „Usługa wróciła”; zatrzymany host → „nie odpowiada (niepotwierdzone)”, po około minucie „nieaktywny” | skany szablonu 18 s, 12 s, 17 s | [WYNIKI](docs/WYNIKI.md#szablon-organizatorów-jedna-maszyna), [ALGORYTMY](docs/ALGORYTMY.md) §3.4 |
| 15% | Bezpieczeństwo, tempo skanu, czytelny pulpit | górny pasek: limit, GET/HEAD, „Stop awaryjny”; „Pulpit” | żadnej sekundy ponad limit + 10% na /16; stop w 0,09 s | [WYNIKI](docs/WYNIKI.md#tempo-i-bezpieczeństwo-skanowania), [BEZPIECZENSTWO](docs/BEZPIECZENSTWO.md) |
| 10% | Fingerprinting, technologie, nagłówki, ciasteczka, sygnatury | usługa → „Technologie i dowody”; „Sygnatury” | technologie: precyzja 0,990, czułość 0,981; tytuły 122 ze 122 | [WYNIKI](docs/WYNIKI.md#wykrywanie-w-sieci-16), [SIGNATURES](docs/SIGNATURES.md) |
| 10% | Role i ochrona danych | „Administracja”; `/healthz` → `"tde":true` | 4 role i własne, 22 uprawnienia; `pg_tde` i AES-256-GCM | `TestRBACMatrixCSRFAndAudit`, [BEZPIECZENSTWO](docs/BEZPIECZENSTWO.md) §2 |

Zmierzone na czystej maszynie (`docker:dind`, 0 obrazów; zapis: [`deploy/e2e/fresh-clone-dind.txt`](deploy/e2e/fresh-clone-dind.txt)):

| Krok | Czas |
| --- | --- |
| `git clone` | 1 s |
| `docker compose up -d` do zdrowego API (pobranie obrazów i budowa) | 51–115 s, zależnie od łącza (trzy pomiary: 79 s z Docker Hub, 115 s i 51 s przez mirror.gcr.io) |
| zamiast tego paczka offline (`make bundle`, 354 MiB): rozpakowanie i `sh install.sh` | 26–29 s, bez sieci |
| logowanie, „Ten komputer”, „Uruchom skan” (przeglądarka sterowana skryptem) | 9 s |
| skan szablonu organizatorów („Ten komputer”, profil domyślny, czysty Ubuntu 24.04) | 18 s ([`docs/WYNIKI.md`](docs/WYNIKI.md)) |

Nie trzeba `.env`: hasło bazy i klucz główny powstają przy pierwszym starcie w wolumenach, a losowe hasło administratora pojawia się raz w logu. Własne wartości: `make init` zapisuje `deploy/.env`, który `docker compose up -d` też czyta.

Czujka cyklicznie i bezpiecznie skanuje duże sieci (ponad 10 000 adresów): znajduje hosty, usługi, technologie WWW, panele, środowiska testowe, nagłówki i ciasteczka.
Uczy się tygodniowego rytmu każdego hosta, więc odróżnia „pracownia jest wyłączona na noc, jak zawsze” od „ten serwer zniknął”.
Wysyła tylko `GET` i `HEAD` i nigdy się nie loguje. Cały produkt to jedna binarka w Go i PostgreSQL z szyfrowaniem.

Zgłoszenie do zadania „Attack Surface Intelligence” Centrum Bezpieczeństwa Informacji AGH, HackNation 2026. Zespół: Iwo Smura, Iwo Wojtakajtis.

![Pulpit Czujki po skanie laboratorium /16](web/screenshots/lab/40-dashboard-pl-dark-1440.png)

## Dla jury

| Co | Gdzie |
| --- | --- |
| Prezentacja (10 slajdów) | [`docs/slides/czujka.pdf`](docs/slides/czujka.pdf) |
| Film demo (około 2 minut, nagrany skryptem z prawdziwego interfejsu) | [`docs/demo/czujka-demo.mp4`](docs/demo/czujka-demo.mp4), tekst lektora [`docs/demo/lektor.txt`](docs/demo/lektor.txt) |
| Scenariusz pokazu, notatki do slajdów, pytania | [`docs/DEMO.md`](docs/DEMO.md) |
| Zgodność z treścią zadania: każde wymaganie, 12 punktów weryfikacji, 6 kryteriów, z dowodem | [`docs/ZGODNOSC.md`](docs/ZGODNOSC.md) |
| Wyniki zmierzone na laboratorium 70 hostów (precyzja, czułość, czas /16) | [`docs/WYNIKI.md`](docs/WYNIKI.md) |
| Działająca instancja z laboratorium 70 hostów | `https://czujka.dev`, konto do odczytu: dane logowania w zgłoszeniu |
| Spis całej dokumentacji | [`docs/DOKUMENTACJA.md`](docs/DOKUMENTACJA.md) |

Skanuj tylko sieci, do których masz uprawnienia.

## Test na szablonie organizatorów

Szablon `lab/jury` to jedna maszyna z usługami w Dockerze na portach hosta. Czujka działa w kontenerze, więc cel `localhost` (także `127.0.0.1` i `::1`) skanuje hosta dockera (`host.docker.internal`), a nie własny kontener. Podgląd celu pokazuje adres, pod którym cel jest skanowany. Szablon zajmuje port 8080, dlatego Czujka dostaje port 9180.

```sh
git clone https://github.com/iwosmu/aghpen.git czujka && cd czujka
CZUJKA_PORT=9180 docker compose up -d
docker compose logs czujka | grep -A3 "first administrator"
cd lab/jury && ./quickstart.sh up
```

1. Otwórz `http://127.0.0.1:9180` i zaloguj się danymi z logu.
2. Naciśnij „Ten komputer” i „Uruchom skan”. Mały zakres (jeden komputer) profil domyślny skanuje pełnym zakresem portów, więc znajduje też porty szablonu spoza top 1000. Na komputerze z innymi programami nie skanuj `localhost` pełnym zakresem portów: sondy wykrywania wersji trafiają wtedy także w lokalne usługi tych programów.
3. Wykonaj `./quickstart.sh change`, uruchom drugi skan („Przebiegi skanów” → „Uruchom skan”, profil „Ten komputer: …”): „Usługa …:8787 zniknęła”. Wykonaj `./quickstart.sh up`, skanuj trzeci raz: „Usługa …:8787 wróciła” z czasem nieobecności i liczbą skanów bez niej.

Czas odpowiedzi: Czujka zapisuje czas odpowiedzi HTTP każdej usługi i porównuje go z jej własną bazą (mediana ostatnich 5 pomiarów). Odpowiedź co najmniej 2 razy wolniejsza i dłuższa o co najmniej 300 ms to zmiana „Wolniejsza odpowiedź”. Powrót do normy to „Odpowiedź w normie”. Na stosie `modern-proxy` skanuj raz bez opóźnienia i raz z `ENABLE_LATENCY=true` w `.env`. Port otwarty, na którym HTTP nie odpowiada w czasie, to „HTTP nie odpowiedział”, a nie zniknięcie usługi.

Usługa Czujki na porcie 9180 hosta dockera ma tag `czujka` i nie daje znalezisk. Na Linuksie można też uruchomić Czujkę w sieci hosta (`deploy/docker-compose.host-network.yml`, [`docs/WDROZENIE.md`](docs/WDROZENIE.md) §2.5).

## Teza: skaner, który rozumie czas

| Funkcja | Co daje | Szczegóły |
| --- | --- | --- |
| Rytm hosta | Histogram 168 godzin tygodnia i model Bayesa. Brak odpowiedzi w porze, w której host zwykle milczy, nie jest alarmem. Serwer, który zawsze odpowiadał, jest zgłaszany po 2 brakach; stacja robocza w weekend wcale. | [`docs/ALGORYTMY.md`](docs/ALGORYTMY.md) §2 |
| Ponowne sprawdzenia | Host, który zamilkł, dostaje krótkie sprawdzenia jednego adresu (po 10, 30, 90 min; host z mniej niż 8 obserwacjami po 1, 3, 10 min) albo w godzinie, w której model spodziewa się odpowiedzi. Włączone od pierwszego startu, budżet adresów na godzinę, tylko w oknie skanu. | [`docs/API.md`](docs/API.md) |
| Wehikuł czasu | Sieć taka, jaka była w dowolnym przebiegu: hosty, usługi, znaleziska i różnica do dziś. | ekran „Wehikuł czasu” |
| Reguły ekspozycji | Czego w sieci być nie może (albo co musi być), w YAML; sprawdzane po każdym skanie, bez pakietów. | [`docs/REGULY.md`](docs/REGULY.md) |
| Retro-hunt i sygnatura z przykładu | Nowa sygnatura sprawdza zapisaną historię bez wysyłania sond; jeden klik na usłudze proponuje sygnaturę z jej rzadkich cech. | [`docs/SIGNATURES.md`](docs/SIGNATURES.md), [`docs/REGULY.md`](docs/REGULY.md) §10 |

Skaner jest bezpieczny z konstrukcji. Wysyła tylko `GET` i `HEAD`, a walidator odrzuca sygnatury z inną metodą, treścią albo hasłem. Limity polityki zawsze wygrywają z profilem, skan staje na końcu okna czasowego, a stop awaryjny zatrzymuje wszystko: wywołanie trwało 0,09 s, po sekundzie nie działał żaden proces nmap i nie wyszedł żaden pakiet IP ([`docs/BEZPIECZENSTWO.md`](docs/BEZPIECZENSTWO.md)).

Wdrożenie to jedno polecenie. Produkt to dwa kontenery: binarka z interfejsem WWW i nmapem oraz PostgreSQL z `pg_tde`; Kubernetes nie jest potrzebny ([`docs/WDROZENIE.md`](docs/WDROZENIE.md)).

## Stan

Produkt działa od końca do końca: `e2e/full/run.sh` przechodzi 100 ze 100 sprawdzeń przez REST API na prawdziwych usługach (zapis: `e2e/full/transcript.txt`). Interfejs sprawdzono na laboratorium /16 z 70 hostami (`web/REPORT-LAB.md`). Dokładny stan każdego wymagania: [`docs/ZGODNOSC.md`](docs/ZGODNOSC.md).

Pomiary trafności, tempa i czasu startu: [`docs/WYNIKI.md`](docs/WYNIKI.md). Wysyłkę z ekranu produktu do żywego DefectDojo 3.5.202 zapisuje `web/REPORT-LAB.md` §11. Alerty: webhook po każdym przebiegu, zgodny z Slack i Mattermost, z podpisem HMAC ([`docs/API.md`](docs/API.md), „Alert webhook”).

## Ograniczenia

- Zakresy CIDR IPv6 są odrzucane; pojedyncze adresy IPv6 działają. Nazwy domen dają tylko adresy IPv4 (rekordy A).
- UDP: tylko 7 portów z niegroźnymi zapytaniami (53, 123, 137, 161, 500, 1900, 5353), bez wykrywania wersji.
- REST API działa z sesją i tokenem CSRF; nie ma tokenów API. Skrypt loguje się jak przeglądarka: [`docs/API.md`](docs/API.md), „API with curl”. Logowanie nie ma drugiego składnika.
- Skala jest zmierzona na laboratorium /16 z 70 żywymi hostami. Czas dla większej sieci to ekstrapolacja, nie pomiar.

## Uruchomienie: szczegóły

Sprawdzenie stanu:

```sh
curl -s http://127.0.0.1:8080/healthz
# {"status":"ok","tde":true,"engine":true,"probe":{"mode":"nmap-raw","prober":"nmap","raw_sockets":true},...}
```

`"tde":true` oznacza, że wszystkie tabele są zaszyfrowane. `"mode":"nmap-raw"` oznacza nmap z surowymi gniazdami w kontenerze bez roota.

- Port zajęty: `CZUJKA_PORT=18080 docker compose up -d`.
- Po zmianie kodu wystarczy `docker compose up -d`: obraz Czujki ma `pull_policy: build`, więc compose buduje go przy każdym `up` (niezmienione warstwy idą z pamięci podręcznej).
- Własne hasła i klucz: `cp deploy/.env.example deploy/.env`, potem edycja. `docker compose up -d` w katalogu głównym czyta `deploy/.env` (plik `compose.yaml` włącza `deploy/docker-compose.yml`); `docker compose -f deploy/docker-compose.yml …` działa jak dotąd.
- Skan sieci dockerowej (na macOS host nie ma trasy do kontenerów): `CZUJKA_SCAN_NETWORK=<sieć> docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.scan-network.yml up -d --wait`.
- Laboratorium testowe 70 hostów: `lab/lab.sh up`, stany `lab/scenario.sh t0|t1|t2` ([`lab/README.md`](lab/README.md)).
- Własny `deploy/.env` jednym poleceniem: `make init` (losowe hasła i klucz główny, hasło administratora wydrukowane raz), potem `make up` albo `docker compose up -d`.
- Diagnoza instalacji: `docker compose -f deploy/docker-compose.yml exec czujka czujka doctor` (baza, `pg_tde`, klucz, nmap, surowe gniazda, tablica sąsiadów).
- Bez internetu: `make bundle` buduje paczkę z obrazami i instalatorem. Bez kontenerów: `make release` buduje statyczne binarki i plik usługi systemd.
- Kopia zapasowa: `czujka backup -o plik` i `czujka restore -i plik` (archiwum szyfrowane kluczem głównym).
- Zatrzymanie: `docker compose -f deploy/docker-compose.yml down` (dane zostają) albo `down -v` (usuwa dane i klucze).

Pełna instrukcja: [`docs/WDROZENIE.md`](docs/WDROZENIE.md).

### Sam silnik skanu, bez bazy

Wymaga Go 1.27. Z nmap w systemie używa nmap, bez niego własnego probera TCP.

```sh
go run ./cmd/scanprobe -targets 127.0.0.1 -ports 8080 -pps 50
# COMPLETED: 1/1 addresses, 1 hosts up, 1 open services, 25 packets (avg 1 pps, limit 50)
```

## Dokumentacja

| Dokument | Treść |
| --- | --- |
| [`docs/DOKUMENTACJA.md`](docs/DOKUMENTACJA.md) | spis całej dokumentacji |
| [`docs/ZGODNOSC.md`](docs/ZGODNOSC.md) | wymagania zadania, ich stan i dowody |
| [`docs/slides/`](docs/slides/), [`docs/DEMO.md`](docs/DEMO.md), [`docs/demo/`](docs/demo/README.md) | prezentacja, scenariusz pokazu, film i skrypt, który go nagrywa |
| [`docs/WDROZENIE.md`](docs/WDROZENIE.md) | instalacja, zmienne, kopie, rotacja klucza, sieć, problemy |
| [`docs/BEZPIECZENSTWO.md`](docs/BEZPIECZENSTWO.md) | model bezpiecznego skanowania i ochrona danych |
| [`docs/ALGORYTMY.md`](docs/ALGORYTMY.md) | model dostępności, zmiany, ocena ciekawości, grupowanie |
| [`docs/SIGNATURES.md`](docs/SIGNATURES.md) | język sygnatur i tryb bezpieczny |
| [`docs/REGULY.md`](docs/REGULY.md) | reguły ekspozycji i sygnatura z przykładu |
| [`docs/INTEGRACJE.md`](docs/INTEGRACJE.md) | import, eksport, źródła pasywne, DefectDojo |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/API.md`](docs/API.md) | architektura i REST API (po angielsku) |
| [`docs/PROBLEM_DEFINITION.md`](docs/PROBLEM_DEFINITION.md) | treść zadania |

## Budowa

| Katalog | Zawartość |
| --- | --- |
| `cmd/czujka` | binarka produktu; `cmd/scanprobe`, `cmd/fpprobe`, `cmd/dojoprobe` to narzędzia do testów modułów |
| `internal/scan`, `probe`, `targets`, `sched`, `enginewire` | silnik skanu, nmap i prober własny, cele, harmonogram i okna, połączenie silnika z produktem |
| `internal/httpfp`, `sig`, `sigwire`, `sigsuggest`, `signatures/` | kolektor HTTP/TLS, silnik sygnatur, sygnatury w bazie, sygnatura z przykładu, biblioteka 398 sygnatur |
| `internal/analyze`, `timeline`, `reprobe`, `rules` | analiza i model dostępności, wehikuł czasu, ponowne sprawdzenia, reguły ekspozycji |
| `internal/report`, `interchange`, `passive`, `defectdojo` | raport, formaty wymiany, źródła pasywne, klient DefectDojo |
| `internal/store`, `crypto`, `auth`, `api`, `runner`, `wire`, `config` | baza i migracje, szyfrowanie, role, REST API, menedżer przebiegów, składanie produktu, konfiguracja |
| `web/` | interfejs: React, TypeScript, Vite; wbudowany w binarkę |
| `deploy/` | obraz i compose produktu |
| `lab/` | laboratorium 70 hostów (/16) z prawdą wzorcową i lokalny DefectDojo |
| `e2e/` | testy end-to-end: `e2e/full` (cały produkt), `e2e/score` (ocena względem prawdy wzorcowej) |

Testy:

```sh
make test               # gofmt, build, vet, testy jednostkowe
make test-integration   # to samo na PostgreSQL z pg_tde (docker)
make e2e-full           # cały produkt przez REST API na prawdziwych usługach (około 15 minut)
```

Technologie: Go, PostgreSQL 17 (dystrybucja Percona z `pg_tde`), nmap, chi, pgx, React. Tylko oprogramowanie bezpłatne i otwarte; bez płatnych API.
