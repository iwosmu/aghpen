# Wynik kontroli `e2e/lab-gate.sh`

Zapis kontroli 3 na wersji silnika `dab9d0e` (22.11.2026, 03:04–04:20 czasu warszawskiego, obraz `czujka:acc27`, limit w jądrze `auto`, głębszy przebieg: 16 hostów). Liczby w `docs/WYNIKI.md` pochodzą z tych plików.

| Plik | Zawartość |
| --- | --- |
| `gate.txt` | tabela kontroli z wynikiem każdego wiersza (jeden wiersz nie przeszedł: przebieg ogólny 2 do 1, 934 s do 767 s, granica 1,15) |
| `run.log` | dziennik kontroli: czasy, tempo, limit w jądrze, czasy przebiegów, tablica sąsiadów |
| `score-t0.txt`, `score-strict-t0.json` | porównanie pierwszego przebiegu z opisem laboratorium (`lab/ground-truth/t0.json`), z listą pominięć; tryb ścisły w JSON |
| `score-t0-2.txt`, `score-strict-t0-2.json` | to samo dla drugiego przebiegu niezmienionego laboratorium |
| `pps-t0.txt`, `pps-t0-2.txt` | pakiety na sekundę zmierzone programem `tcpdump` |
| `kcap-t0.json`, `kcap-t0-2.json` | stan limitu w jądrze po każdym przebiegu (`GET /settings/safety`); licznik `dropped` jest liczony od startu procesu |
| `passtimes-t0.txt`, `passtimes-t0-2.txt` | czas przebiegu ogólnego i głębszego, hosty głębszego przebiegu, hosty czekające, nowe usługi |
| `changes-t0.json`, `changes-t0-2.json` | zmiany zgłoszone w przebiegach (kontrola stabilności: 0 w drugim) |
| `run-t0.json`, `run-t0-2.json` | rekordy obu przebiegów z API |
| `profile.json` | profil skanowania użyty w kontroli |

Podsumowanie pamięci w `run.log` (984,7 MiB) jest błędne: skrypt porównywał próbki jako tekst. Wartość liczona liczbowo z próbek: 1228,8 MiB (`docs/WYNIKI.md`). Nagrania ruchu (`tcpdump-*.txt.gz`, po 3 MB), próbki pamięci i pełne eksporty nie są w repozytorium. Kontrolę odtwarza polecenie `e2e/lab-gate.sh`.
