# Test end-to-end silnika skanowania

Skrypt `run.sh` uruchamia prawdziwy skan w sieciach dockera, które sam tworzy. Nie skanuje niczego poza nimi.

## Uruchomienie

```sh
./e2e/engine/run.sh          # wszystkie scenariusze, potem sprzątanie
KEEP=1 ./e2e/engine/run.sh   # zostawia laboratorium włączone
./e2e/engine/lab.sh down     # ręczne sprzątanie
```

Wymagania: Docker i Go. Wyniki każdego scenariusza trafiają do `e2e/engine/out/` (`*.jsonl` to wyjście `scanprobe`, `*.log` to logi).

## Laboratorium (`lab.sh`)

| Adres | Usługa | Uwagi |
| --- | --- | --- |
| 10.77.0.10 | nginx, port 80 | |
| 10.77.0.20 | OpenSSH, port 22 | |
| 10.77.1.30 | Redis, port 6379 | |
| 10.77.2.40 | HTTP, port 8765 | nietypowy port |
| 10.77.2.41 | HTTP, port 8081 | nietypowy port |
| 10.77.3.50 | HTTPS, port 9443 | certyfikat samopodpisany |
| 10.77.3.60 | HTTP, port 80 | odrzuca cały ruch ICMP (iptables) |
| 10.77.3.254 / 10.78.0.254 | router z NAT | łączy sieć skanera z laboratorium |

Sieci: `czeng-net` 10.77.0.0/22 (laboratorium), `czeng-scan` 10.78.0.0/24 (skaner w trybie „routed”), `czeng-wide` 10.79.0.0/20 (pusta przestrzeń adresowa).

Skaner działa w dwóch położeniach. W położeniu `l2` stoi w sieci laboratorium i nmap używa ARP. W położeniu `routed` stoi za routerem, jak w sieci kampusowej, i używa sond ICMP oraz TCP.

## Scenariusze

| Scenariusz | Co sprawdza |
| --- | --- |
| A-local | pełny skan w segmencie lokalnym: ARP, SYN, wykrywanie wersji |
| B-routed | pełny skan przez router; host bez ICMP musi zostać wykryty sondą TCP |
| C-sweep | samo wykrywanie hostów i portów; pomiar czasu dla /22 i ekstrapolacja |
| D1-window-guard | okno zamyka się po 45 s; strażnik nie startuje kolejnej grupy; wznowienie kończy resztę |
| D2-window-cut | okno zamyka się po 22 s w trakcie pracy; procesy nmap są zatrzymane; wznowienie kończy wszystko |
| E-retry | host niestabilny wraca w rundzie ponowień; host nieistniejący jest zgłoszony jako nieaktywny po 3 próbach |
| F-native | zapasowy skaner w Go (bez nmap), tylko połączenia TCP |
| G-unprivileged | brak surowych gniazd: nmap sam przechodzi na `-sT` |
| I-adaptive | 4094 adresy przy 2000 pps: rozmiar grup rośnie z 256 w stronę 4096 |
| H-emergency | awaryjne zatrzymanie: silnik odmawia startu i nie wysyła żadnego pakietu |

Program `verify` porównuje wynik z tabelą wyżej. Sprawdza też limit tempa na dwa sposoby: liczbą pakietów, którą podaje nmap, oraz licznikiem pakietów interfejsu odczytywanym co sekundę (tolerancja 2% na niedokładność odczytu).
