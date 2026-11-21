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

Sieci: `czeng-net` 10.77.0.0/22 (laboratorium), `czeng-scan` 10.78.0.0/24 (skaner w trybie „routed”), `czeng-wide` 10.79.0.0/20 (pusta przestrzeń adresowa), `czeng-apps` 10.76.0.0/24 (prawdziwe aplikacje).

### Laboratorium aplikacji (`lab.sh apps`)

| Adres | Aplikacja | Port |
| --- | --- | --- |
| 10.76.0.10 | MariaDB 11 (baza WordPressa) | 3306 |
| 10.76.0.11 | WordPress 6 (zainstalowany) | 80 |
| 10.76.0.20 | Grafana 11.3.0 | 3000 |
| 10.76.0.21 | Gitea 1.22 | 3000, 22 |
| 10.76.0.30 | phpMyAdmin 5 | 80 |
| 10.76.0.40 | Apache Tomcat 10.1 | 8080 |
| 10.76.0.50 | HTTPS z certyfikatem samopodpisanym | 8443 |
| 10.76.0.60 | nginx na nietypowym porcie | 8181 |
| 10.76.0.70 | DNS (dnsmasq), NTP i agent SNMP po UDP | 53/udp, 123/udp, 161/udp, 53/tcp |

Hasła w tym laboratorium są losowe i istnieją tylko w kontenerach. Skaner nigdzie się nie loguje.

Skaner działa w dwóch położeniach. W położeniu `l2` stoi w sieci laboratorium i nmap używa ARP. W położeniu `routed` stoi za routerem, jak w sieci kampusowej, i używa sond ICMP oraz TCP.

## Tryby wykrywania hostów

Profil skanu ma pole `discovery.mode`:

| Tryb | Pierwsze przejście (każdy adres) | Drugie przejście | Pakiety na martwy adres |
| --- | --- | --- | --- |
| `fast` | ICMP echo, TCP SYN 80 i 443, jedno ponowienie | pozostałe sondy tylko dla hostów znanych z inwentarza | 6 |
| `balanced` (domyślny) | jak wyżej | pozostałe sondy dla cichych adresów w blokach /24, w których ktoś odpowiedział albo inwentarz zna hosta | 6 w pustym bloku, 18 w bloku z hostami |
| `thorough` | pełny zestaw sond (ICMP echo i timestamp, SYN 22, 80, 443, 3389, 8080, ACK 80, 443) | brak | 18 |

W segmencie lokalnym nmap używa ARP i wszystkie tryby robią jedno przejście.

### Ograniczenie trybu fast

Przy 2000 pps na zakresie 5115 adresów tryb `fast` pominął jeden lub dwa hosty (z 7) w 8 z 16 przebiegów. Tryby `balanced` i `thorough` nie pominęły żadnego hosta w 8 przebiegach. Przyczyna leży na ścieżce, nie w nmap: router laboratorium musi rozwiązać adres MAC każdego martwego adresu, a tablica sąsiadów jądra w maszynie Docker ma 1024 wpisy. Log jądra pokazuje `neighbour: arp_cache: neighbor table overflow!`. Pakiet do hosta, dla którego router nie może wtedy utworzyć wpisu, ginie. Tryb `fast` wysyła tylko 6 pakietów na host w dwóch krótkich seriach, więc ma najmniejszy zapas. To samo zjawisko występuje na prawdziwym routerze ostatniego skoku, gdy skan szybko przechodzi przez dużą, pustą, bezpośrednio podłączoną sieć. Zalecenie: `fast` tylko do szybkiego przeglądu; do inwentaryzacji `balanced` (domyślny) albo niższy limit pps.

## Skan UDP

Opcjonalny, domyślnie wyłączony (`udp.enabled` w profilu, `-udp` w scanprobe). Lista dozwolonych usług: DNS 53, NTP 123, NetBIOS-NS 137, SNMP 161, IKE 500, SSDP 1900, mDNS 5353. Profil może tylko zawęzić tę listę; porty polityki bezpieczeństwa filtrują ją tak jak TCP. Skan wymaga nmap z surowymi gniazdami; bez nich etap jest pomijany z wpisem w logu.

Port 161 nie trafia do nmap. Sondy nmap dla SNMP zawierają żądanie SNMPv1 ze społecznością „public”, czyli próbę domyślnego poświadczenia. Silnik wysyła własne zapytanie: SNMPv3 engine discovery (RFC 3414), bez nazwy użytkownika i bez poświadczeń, najwyżej dwa pakiety na host.

## Scenariusze

| Scenariusz | Co sprawdza |
| --- | --- |
| A-local | pełny skan w segmencie lokalnym: ARP, SYN, wykrywanie wersji |
| B-routed | pełny skan przez router; host bez ICMP musi zostać wykryty sondą TCP |
| C-sweep | samo wykrywanie hostów i portów; pomiar czasu dla /22 i ekstrapolacja |
| D1-window-guard | okno zamyka się po 45 s; strażnik nie startuje kolejnej grupy; wznowienie kończy resztę |
| D2-window-cut | okno zamyka się po 22 s w trakcie pracy; procesy nmap są zatrzymane; wznowienie kończy wszystko |
| E-retry | host niestabilny wraca w rundzie ponowień; host nieistniejący jest zgłoszony jako nieaktywny po 3 próbach (tryb `thorough`, jedna runda wykrywania) |
| F-native | zapasowy skaner w Go (bez nmap), tylko połączenia TCP |
| G-unprivileged | brak surowych gniazd: nmap sam przechodzi na `-sT` |
| I-adaptive | 4094 adresy przy 2000 pps: rozmiar grup rośnie z 256 w stronę 4096 |
| K-thorough, K-balanced | tryby wykrywania hostów na rzadkiej przestrzeni (5115 adresów, hosty w 4 z 20 bloków /24, 2000 pps); oba muszą znaleźć wszystkie 7 hostów, także ten bez ICMP |
| K-fast | ten sam zakres w trybie `fast`: wynik jest mierzony. Test nie przechodzi, gdy zginie host bez ICMP. Brak innego hosta jest wypisany jako liczba pominięć (patrz „Ograniczenie trybu fast”) |
| J-apps | jeden przebieg silnika z prawdziwym kolektorem HTTP/TLS, biblioteką 386 sygnatur i skanem UDP; sprawdzane są technologie, wersje i klasy każdej aplikacji oraz zgodność licznika żądań HTTP z liczbą żądań wysłanych przez kolektor |
| H-emergency | awaryjne zatrzymanie: silnik odmawia startu i nie wysyła żadnego pakietu |

Program `verify` porównuje wynik z tabelą wyżej. Sprawdza też limit tempa na dwa sposoby: liczbą pakietów, którą podaje nmap, oraz licznikiem pakietów interfejsu odczytywanym co sekundę (tolerancja 3% na niedokładność odczytu).
