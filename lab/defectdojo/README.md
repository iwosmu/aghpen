# Lokalny DefectDojo dla Czujki

Ten katalog uruchamia prawdziwy DefectDojo (oficjalne obrazy open source `defectdojo/defectdojo-django` i `defectdojo/defectdojo-nginx`) do testów integracji i do demo.
Instancja słucha tylko na `127.0.0.1`. Hasło i token poniżej są jawne, więc instancja służy wyłącznie do pracy lokalnej.

## Start

```sh
docker compose -f lab/defectdojo/docker-compose.yml up -d
```

Pierwszy start trwa około minuty (pobranie obrazów trwa dłużej). Usługa `initializer` tworzy bazę i konto administratora, a usługa `token` ustawia znany token API. Obie kończą pracę z kodem 0.

| Co | Wartość |
| --- | --- |
| Adres | http://127.0.0.1:18080 |
| Login | `admin` |
| Hasło | `Czujka-Lab-2026!` |
| Token API v2 | `c2a1b0f4d7e84c5aa3f29b6e0d1c7f58a4e3b2d1` |
| Dokumentacja API | http://127.0.0.1:18080/api/v2/oa3/swagger-ui/ |

Zmienne `DOJO_PORT`, `DOJO_ADMIN_PASSWORD`, `DOJO_API_TOKEN` i `DD_VERSION` zmieniają port, hasło, token i wersję obrazu.
Integracja była sprawdzona z DefectDojo 3.5.202 (obraz `latest` z 2026-11-21).

## Test z linii poleceń

`cmd/dojoprobe` to narzędzie deweloperskie. Używa tych samych pakietów co produkt (`internal/defectdojo`, `internal/interchange`, `internal/analyze`).

```sh
export DOJO_URL=http://127.0.0.1:18080
export DOJO_TOKEN=c2a1b0f4d7e84c5aa3f29b6e0d1c7f58a4e3b2d1

go run ./cmd/dojoprobe test                                             # połączenie i wersja serwera
go run ./cmd/dojoprobe push -file lab/defectdojo/sample-findings.json   # eksport obserwacji
go run ./cmd/dojoprobe push -file lab/defectdojo/sample-findings.json   # drugi eksport: 0 nowych, same aktualizacje
go run ./cmd/dojoprobe nmap -file lab/defectdojo/sample-nmap.xml -title "Czujka nmap run 1"
go run ./cmd/dojoprobe list -test <test_id>                             # obserwacje z endpointami
```

Pliki przykładowe pochodzą z prawdziwego skanu:

- `sample-nmap.xml` to wynik `nmap -sV --script http-title,banner -p 22,80,6379 -oX -` na trzech kontenerach (nginx, Apache httpd, Redis) w prywatnej sieci docker.
- `sample-findings.json` to obserwacje, które biblioteka analizy wyprowadza z tego pliku: `go run ./cmd/dojoprobe derive -in lab/defectdojo/sample-nmap.xml`.

Inne polecenia: `dojoprobe convert -in plik -to xml|json|csv` importuje wyniki (nmap XML, JSON Czujki, CSV) i zapisuje je w innym formacie.

## Jak Czujka zapisuje dane w DefectDojo

- Typ produktu `Czujka`, produkt `Czujka – Attack Surface`, engagement `Czujka discovery`. Nazwy można zmienić w ustawieniach integracji. Klient szuka obiektu po nazwie i tworzy go tylko wtedy, gdy go nie ma.
- Obserwacje trafiają do testu `Czujka findings` jako findings o ważności `Info` (kilka typów ma `Low`). Każda ma endpoint (adres IP, port, protokół), dowody w opisie, tagi `czujka` i typ obserwacji oraz `unique_id_from_tool` równe kluczowi obserwacji w Czujce.
- Nowe obserwacje idą przez `/import-scan` (pierwszy eksport) albo `/reimport-scan` (kolejne) z typem skanu `Generic Findings Import`. Tylko ta trasa tworzy endpointy: w DefectDojo 3.x nie ma już `POST /endpoints`, a `POST /findings` nie przyjmuje endpointów.
- Obserwacje, które już istnieją, klient znajduje po `unique_id_from_tool` i aktualizuje przez `PATCH /findings/{id}`. Sam `/reimport-scan` dopasowuje po hashu tytułu i opisu, więc obserwacja ze zmienionym opisem powstałaby drugi raz. Sprawdziliśmy to na żywej instancji.
- Status z Czujki ustawia flagi: `triaged` → `verified`, `false_positive` → `false_p`, `resolved` → `is_mitigated`, `accepted` → tag `accepted`.
- Plik nmap XML jednego przebiegu trafia do osobnego testu typu `Nmap Scan`. Ponowne wysłanie tego samego przebiegu robi reimport do tego samego testu.

Znane ograniczenie: DefectDojo sam zmienia wielkość liter w tytułach (`Panel Administracyjny: ...`), także po `PATCH`.

## Stop

```sh
docker compose -f lab/defectdojo/docker-compose.yml down       # dane zostają w wolumenach
docker compose -f lab/defectdojo/docker-compose.yml down -v    # usuwa także dane
```
