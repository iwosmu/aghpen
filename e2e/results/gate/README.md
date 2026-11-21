# Wynik kontroli `e2e/lab-gate.sh`

Zapis przebiegu kontroli na wersji silnika `6f39557` (21.11.2026, 21:45–22:15 czasu warszawskiego). Liczby w `docs/WYNIKI.md` pochodzą z tych plików.

| Plik | Zawartość |
| --- | --- |
| `run.log` | dziennik kontroli: czasy, tempo, pamięć, tablica sąsiadów |
| `score-t0.txt` | porównanie wyniku pierwszego skanu z opisem laboratorium (`lab/ground-truth/t0.json`), z listą pominięć i fałszywych wyników |
| `score-strict-t0.json` | to samo w trybie ścisłym (przypadki trudne też się liczą) |
| `pps-t0.txt` | pakiety na sekundę zmierzone programem `tcpdump`, pierwszy skan |
| `score-t0-2.txt`, `pps-t0-2.txt` | drugi skan tego samego, niezmienionego laboratorium |
| `changes-t0-2.json` | zmiany zgłoszone w drugim skanie (kontrola stabilności: zero zmian technologii i wersji) |
| `run-t0.json`, `run-t0-2.json` | rekordy obu przebiegów z API |
| `profile.json` | profil skanowania użyty w kontroli |

Nagrania ruchu (`tcpdump-*.txt.gz`, po 3 MB) i pełne eksporty nie są w repozytorium. Kontrolę odtwarza polecenie `e2e/lab-gate.sh`.
