# Czujka: Attack Surface Intelligence

Czujka to narzędzie do cyklicznego, bezpiecznego skanowania discovery dużych sieci (ponad 10 000 adresów IP).
Wykrywa aktywne hosty, usługi, technologie WWW, nagłówki i ciasteczka, a potem pokazuje, co zmieniło się między przebiegami.
Rozróżnia host, który zniknął, od hosta, który o tej porze zwykle nie odpowiada.
Wysyła tylko bezpieczne zapytania: bez logowania, bez ładunków, tylko `GET` i `HEAD`.
Jedna binarka w Go, PostgreSQL z szyfrowaniem w spoczynku, start jednym poleceniem `docker compose`.

Zgłoszenie do zadania „Attack Surface Intelligence” Centrum Bezpieczeństwa Informacji AGH, HackNation 2026.
Zespół: Iwo Smura, Iwo Wojtakajtis.

## Stan

Wszystkie moduły są w repozytorium i mają testy. Binarka `czujka` nie wywołuje jeszcze części z nich: start skanu, import wyników, porównanie przebiegów, sygnatury i DefectDojo odpowiadają w API `501 not_wired`. Dokładny stan każdego wymagania: [`docs/ZGODNOSC.md`](docs/ZGODNOSC.md).

## Szybki start

Wymagania: Docker z Compose v2, dostęp do internetu podczas budowania.

```sh
git clone <adres repozytorium> czujka && cd czujka
docker compose -f deploy/docker-compose.yml up -d --build --wait
docker compose -f deploy/docker-compose.yml logs czujka | grep -A3 "first administrator"
```

Ostatnie polecenie pokazuje login (`admin@czujka.local`) i losowe hasło pierwszego administratora. Otwórz `http://127.0.0.1:8080`.

Sprawdzenie stanu:

```sh
curl -s http://127.0.0.1:8080/healthz
# {"db":"ok","engine":false,...,"status":"ok","tde":true,...}
```

`"tde":true` oznacza, że wszystkie tabele są zaszyfrowane. `"engine":false` oznacza, że silnik skanu nie jest jeszcze podłączony do binarki.

Port zajęty: `CZUJKA_PORT=18080 docker compose -f deploy/docker-compose.yml up -d --build --wait`.
Własne hasła i klucz: `cp deploy/.env.example deploy/.env`, potem edycja. Pełna instrukcja: [`docs/WDROZENIE.md`](docs/WDROZENIE.md).

Zatrzymanie: `docker compose -f deploy/docker-compose.yml down` (dane zostają) albo `down -v` (usuwa dane i klucze).

### Sam silnik skanu, bez bazy

Wymaga Go 1.27. Z nmap w systemie używa nmap, bez niego własnego probera TCP.

```sh
go run ./cmd/scanprobe -targets 127.0.0.1 -ports 8080 -pps 50
# COMPLETED: 1/1 addresses, 1 hosts up, 1 open services, 25 packets (avg 1 pps, limit 50)
```

Skanuj tylko sieci, do których masz uprawnienia.

## Funkcje a treść zadania

Status: **gotowe** = działa w binarce produktu; **biblioteka** = scalony i przetestowany moduł, którego binarka jeszcze nie wywołuje.

| Zadanie (rozdz. 2) | Funkcja | Status |
| --- | --- | --- |
| 1. Lista IP, CIDR, domen | formularz i plik CSV/JSON z podglądem błędów, duplikatów i liczby adresów | **gotowe** |
| 2. Bezpieczny skan discovery | silnik z nmap albo własnym proberem; równoległe procesy z jednym budżetem pakietów; estymata czasu; adaptacyjny podział na podgrupy | biblioteka |
| 3–4. Hosty i usługi | ICMP, TCP SYN/ACK, ARP; `nmap -sV` na otwartych portach (tylko TCP) | biblioteka |
| 5. HTTP/HTTPS | tytuł, kod, nagłówki, ciasteczka, certyfikat TLS, przekierowania | biblioteka |
| 6–7. Technologie, staging, panele | 386 sygnatur: CMS, frameworki, serwery, IoT, panele, środowiska testowe; pewność z listą dowodów | biblioteka |
| 8–9. Porównanie przebiegów | 18 rodzajów zmian z wagą; zmiany „oczekiwane” dla hostów o znanym rytmie | biblioteka |
| 10. Własne sygnatury | język YAML, walidator trybu bezpiecznego, retro-hunt bez wysyłania pakietów | biblioteka |
| 11. Formularz i plik | cele: ręcznie, CSV, JSON; wyniki: nmap XML, JSON, CSV | **gotowe** (cele), biblioteka (wyniki) |
| 12–13. RBAC i cztery role | 22 uprawnienia, role Administrator, Edytor, Analityk, Obserwator, własne role | **gotowe** |
| 14. Edycja niezależna od skanu | nadpisania pól zachowane przy kolejnych skanach, z wartością skanera obok | **gotowe** |
| 15. Interfejs i dashboard | 18 stron, polski i angielski, widok zależny od roli | zbudowany; sprawdzony na danych przykładowych |
| 16. Szyfrowanie w spoczynku | `pg_tde` dla wszystkich tabel i WAL; AES-256-GCM dla pól wrażliwych; rotacja klucza | **gotowe** |

| Zakres dodatkowy | Funkcja | Status |
| --- | --- | --- |
| Okna czasowe i harmonogram | okna tygodniowe, cron albo odstęp; skan przerywany na końcu okna i wznawiany w następnym | konfiguracja **gotowa**; wykonanie: biblioteka |
| Ograniczanie tempa | polityka bezpieczeństwa z limitami nadrzędnymi; awaryjne zatrzymanie | polityka **gotowa**; egzekwowanie: biblioteka |
| Różnice zależne od pory dnia | histogram godzin tygodnia na host, model Bayesa | biblioteka |
| Ocena ciekawości, grupowanie | punkty 0–100 z powodami; grupy podobnych usług | biblioteka |
| Tagi | cele, hosty, usługi, obserwacje | **gotowe** |
| Eksport | CSV i JSON, strumieniowo, z ochroną przed formułami | **gotowe** |
| DefectDojo | obserwacje i nmap XML, bez duplikatów przy ponownym eksporcie | biblioteka |
| Źródła pasywne | pliki, odwrotny DNS, crt.sh (domyślnie wyłączone) | biblioteka |
| Raport z przebiegu | jeden plik HTML do druku na A4 i Markdown | biblioteka; [przykład](docs/samples/raport-przyklad.html) |

Znane braki: skan UDP, ręczne dodanie hosta lub usługi, import obserwacji z pliku, prezentacja.

## Dokumentacja

| Dokument | Treść |
| --- | --- |
| [`docs/DOKUMENTACJA.md`](docs/DOKUMENTACJA.md) | spis całej dokumentacji |
| [`docs/ZGODNOSC.md`](docs/ZGODNOSC.md) | wymagania zadania i ich stan |
| [`docs/WDROZENIE.md`](docs/WDROZENIE.md) | instalacja, zmienne, kopie, rotacja klucza, sieć, problemy |
| [`docs/BEZPIECZENSTWO.md`](docs/BEZPIECZENSTWO.md) | model bezpiecznego skanowania i ochrona danych |
| [`docs/ALGORYTMY.md`](docs/ALGORYTMY.md) | model dostępności, zmiany, ocena ciekawości, grupowanie |
| [`docs/SIGNATURES.md`](docs/SIGNATURES.md) | język sygnatur i tryb bezpieczny |
| [`docs/INTEGRACJE.md`](docs/INTEGRACJE.md) | import, eksport, źródła pasywne, DefectDojo |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/API.md`](docs/API.md) | architektura i REST API (po angielsku) |
| [`docs/PROBLEM_DEFINITION.md`](docs/PROBLEM_DEFINITION.md) | treść zadania |

## Budowa

| Katalog | Zawartość |
| --- | --- |
| `cmd/czujka` | binarka produktu; `cmd/scanprobe`, `cmd/fpprobe`, `cmd/dojoprobe` to narzędzia do testów modułów |
| `internal/scan`, `probe`, `targets`, `sched` | silnik skanu, nmap i prober własny, cele, harmonogram i okna |
| `internal/httpfp`, `sig`, `signatures/` | kolektor HTTP/TLS, silnik sygnatur, biblioteka sygnatur |
| `internal/analyze`, `report`, `interchange`, `passive`, `defectdojo` | analiza, raport, formaty wymiany, źródła pasywne, klient DefectDojo |
| `internal/store`, `crypto`, `auth`, `api`, `runner` | baza i migracje, szyfrowanie, role, REST API, menedżer przebiegów |
| `web/` | interfejs: React, TypeScript, Vite |
| `deploy/`, `lab/`, `e2e/` | obrazy i compose produktu, laboratorium DefectDojo, testy end-to-end silnika |

Testy:

```sh
make test               # gofmt, build, vet, testy jednostkowe
make test-integration   # to samo na PostgreSQL z pg_tde (docker)
```

Technologie: Go, PostgreSQL 17 (dystrybucja Percona z `pg_tde`), nmap, chi, pgx, React. Tylko oprogramowanie bezpłatne i otwarte; bez płatnych API.
