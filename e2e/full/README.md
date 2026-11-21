# Pełny test end-to-end (`e2e/full`)

Skrypt `run.sh` uruchamia cały produkt z `docker compose`, buduje sieć docelową z prawdziwymi usługami i sprawdza produkt **wyłącznie przez REST API**. Każde sprawdzenie wypisuje `PASS` albo `FAIL`. Kod wyjścia 1 oznacza, że co najmniej jedno sprawdzenie nie przeszło. To jest test regresji całego projektu.

## Uruchomienie

```sh
make e2e-full                       # albo: ./e2e/full/run.sh
E2E_KEEP=1 ./e2e/full/run.sh        # zostawia stos i laboratorium do obejrzenia
E2E_SKIP_BUILD=1 ./e2e/full/run.sh  # bez przebudowy obrazu
./e2e/full/lab.sh down              # ręczne sprzątanie laboratorium
```

Wymagania: Docker, `curl`, `jq`, `bc`. Pakiety mierzy kontener pomocniczy `tcpdump` (obraz `czfull-tcpdump`, budowany lokalnie z Alpine), który dzieli przestrzeń sieciową z kontenerem Czujki. Czas: około 12–15 minut (najdłużej trwa test okna skanowania, które celowo zamyka się w trakcie skanu).
Skrypt sprząta po sobie: usuwa stos `czfull-e2e` z wolumenami i wszystkie kontenery `czfull-lab-*` oraz sieć `czfull-net`. Można go uruchamiać wielokrotnie.

Zmienne: `E2E_PROJECT` (domyślnie `czfull-e2e`), `E2E_PORT` (`18492`, tylko `127.0.0.1`).

## Sieć docelowa (`lab.sh`)

Skaner skanuje **tylko** sieć `czfull-net` (10.91.0.0/22), którą skrypt tworzy sam. Czujka dołącza do niej przez `deploy/docker-compose.scan-network.yml` (na macOS host nie ma trasy do adresów kontenerów). Własny adres Czujki i brama sieci (strona hosta dockera) trafiają do wykluczeń polityki bezpieczeństwa.

| Adres | Usługa | Stan 2 (`lab.sh change`) |
| --- | --- | --- |
| 10.91.0.10 | nginx 1.24.0 | nginx 1.30.7 (zmiana wersji) |
| 10.91.0.11 | — | nowy host: nginx |
| 10.91.0.20 | OpenSSH | |
| 10.91.1.30 | Redis | zatrzymany (host milknie) |
| 10.91.1.80 | WordPress 6.9 | |
| 10.91.1.81 | MariaDB 11 | |
| 10.91.2.40 | HTTP na porcie 8765 | zmieniony tytuł strony |
| 10.91.2.90 | Grafana 12.4 | |
| 10.91.3.50 | HTTPS na porcie 9443 (certyfikat samopodpisany) | |
| 10.91.3.60 | HTTP, odrzuca ICMP | |

## Co sprawdza

0. Warunek wstępny: tablica sąsiadów hosta dockera ma co najmniej 2048 wolnych wpisów (`gc_thresh3` jest wspólne dla wszystkich przestrzeni sieciowych). Inaczej skrypt kończy się kodem 3 z poleceniem `sysctl`, bo przy pełnej tablicy giną odpowiedzi ARP i wynik nic nie mówi o produkcie. Na końcu sprawdza, że tablica nie przepełniła się w czasie testu.
1. `/healthz`: silnik podłączony, nmap z surowymi gniazdami (`mode: nmap-raw`) w kontenerze bez roota; UI z tej samej binarki i tego samego portu.
2. Logowanie, polityka bezpieczeństwa (wykluczenie), zakres z CIDR, profil, estymacja ruchu.
3. Przebieg 1: start, strumień SSE do końca, hosty, usługi z technologiami, wersjami, klasami i powodami oceny, ustalenia, dashboard.
4. Edycje analityka (notatka i tagi usługi, akceptacja ustalenia).
5. Własna sygnatura przez API i retro-hunt na zapisanych obserwacjach: `tcpdump` na interfejsie sieci docelowej nie widzi żadnego pakietu do hostów laboratorium.
6. Zmiana sieci, przebieg 2: nowy host, zmiana wersji nginx, zmiana tytułu, milczący host, `GET /diff`, dopasowanie własnej sygnatury, edycje przetrwały skan.
7. Raport przebiegu (HTML i Markdown).
8. Eksport JSON, CSV i nmap XML przebiegu 2 i ponowny import.
9. Import pliku sygnatur: poprawna zapisana, niebezpieczna (POST) odrzucona z powodem.
10. Źródła pasywne: plik (adres spoza zakresu nie jest kandydatem), zatwierdzenie kandydata, PTR (nazwy z DNS dockera), crt.sh wyłączone (409).
11. Okno skanowania zamyka się w trakcie skanu: przebieg `paused` z `window_closed`, w przebiegu częściowym brak „zniknięć” usług spoza skanowanych portów, wznowienie przez harmonogram w następnym oknie, zakończenie.
12. Awaryjne zatrzymanie w trakcie skanu: brak procesów nmap po sekundzie, `tcpdump` nie widzi żadnego pakietu IP (SYN, ICMP, HTTP) później niż 1 s po zatrzymaniu, przebieg `paused` z `emergency_stop`, nowy przebieg odrzucony (409). Jądro wysyła jeszcze przez około 2 s zapytania ARP: to ponowienia rozwiązywania adresów, o które pytał nmap (warstwa 2, bez sond do usług). Skrypt podaje ich liczbę.
13. Pomiary: pamięć kontenera Czujki w czasie skanów, czas przebiegów, liczba pakietów i żądań HTTP wobec limitów.

Zapis ostatniego uruchomienia: `e2e/full/transcript.txt` (100 ze 100, 2026-11-21, około 9,5 minuty). Podsumowanie i pomiary: `deploy/INTEGRATION2_REPORT.md`.
