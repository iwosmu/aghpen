# Pomiar skali (`lab/scale/`)

Zapis pomiarów Czujki na 2 000 i 10 000 żywych adresów, serwer OMEN, 21–22.11.2026, wersja `736ff9a`. To N żywych adresów obsługiwanych przez M kontenerów: 2 000 adresów w 2 kontenerach i 10 000 adresów w 10 kontenerach (po 1 000 na kontener), nie tyle maszyn. Zakres skanu: `10.77.0.0/16` (65 536 adresów). Liczby w `docs/WYNIKI.md` (rozdział „Skala: 2 000 i 10 000 żywych hostów”) pochodzą z tych plików.

| Katalog | Przebiegi | Limit pakietów | `http_rps` |
| --- | --- | --- | --- |
| `2k/` | `r1-2k`: pierwszy skan | 1 000/s (domyślna polityka) | 20 (profil domyślny) |
| `10k/` | `r1-10k`: pierwszy skan | 10 000/s (polityka i profil podniesione) | 20 |
| `10k/` | `r2-10k`: drugi skan, sieć bez zmian; `r3-10k`: farma 10 wyłączona | 10 000/s | 50 (maksimum domyślnej polityki) |

| Plik | Zawartość |
| --- | --- |
| `run.log` | dziennik pomiaru: czasy statusów, pakiety, najwyższa sekunda, pamięć, rozmiar bazy, liczba zmian |
| `runs.jsonl` | jeden wiersz na przebieg: te same liczby jako JSON |
| `run-*.json` | rekord przebiegu z API (`GET /runs/{id}`) |
| `score-*.txt` | porównanie eksportu z prawdą wzorcową (`go run ./e2e/score`), z listą pominięć |
| `pps-*.txt` | pakiety wysłane przez Czujkę w każdej sekundzie (`tcpdump` w jej przestrzeni sieciowej) |
| `mem-*.txt` | pamięć kontenera Czujki i PostgreSQL co 2 s (`docker stats`) |
| `changes-*.json` | zmiany zgłoszone przez przebieg (`GET /changes?run_id=`) |
| `api-*.txt` | czasy list, eksportów i raportów: kod HTTP, czas w sekundach, bajty; dwie próby |
| `profile.json`, `policy.json` | profil i polityka bezpieczeństwa na starcie |
| `10k/services-deep-page.sql` | zapytanie dalekiej strony listy usług przed poprawką `1623497` i po niej, z czasami na bazie 10 000 |

Prawda wzorcowa (13 MB) i eksporty JSON (20 i 96 MB) nie są w repozytorium. Prawdę odtwarza `lab/scale/scale.sh truth N`, cały pomiar `lab/scale/README.md`.

Pierwsza próba serii 10 000 poszła z limitem 1 000/s, bo skrypt podnosił limit profilu metodą PUT (API odpowiada 405). Przerwaliśmy ją po 22 minutach; `measure.sh` używa teraz PATCH. Przed przebiegiem `r2-10k` mały skrypt zmienił `rate.http_rps` profilu z 20 na 50 (PATCH `/profiles/{id}`); teraz robi to `measure.sh run NAZWA 10000 50`.
