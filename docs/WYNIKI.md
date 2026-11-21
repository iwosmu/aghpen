# Wyniki pomiarów

Ten plik zawiera tylko liczby zmierzone na działającym produkcie. Każda ma źródło, z którego da się ją odtworzyć. Stan: 21.11.2026, wersja `35bb7c8` silnika skanowania.

## Jak mierzymy

Laboratorium `lab/` to 70 kontenerów w sieci `10.66.0.0/16` (65 536 adresów). Każdy kontener ma opis w `lab/ground-truth/t0.json`: adres, otwarte porty, usługa, wersja, technologie, klasy. Trzy hosty są celowo niestabilne i nie wchodzą do metryk.

Polecenie `e2e/lab-gate.sh` uruchamia pełny skan /16 przez produkt (REST API, profil domyślny, limit 1000 pakietów na sekundę), nagrywa ruch programem `tcpdump` i porównuje wynik z opisem laboratorium. Skan, który przekroczy limit tempa albo zgubi wyniki, nie przechodzi tej kontroli. Żadna zmiana silnika nie trafia do głównej gałęzi bez jej zaliczenia.

## Wykrywanie w sieci /16

Tryb ścisły: przypadki trudne też się liczą.

| Kategoria | Znalezione | Fałszywe | Pominięte | Precyzja | Czułość |
| --- | --- | --- | --- | --- | --- |
| Hosty | 67 | 0 | 0 | 1,000 | 1,000 |
| Otwarte porty | 154 | 0 | 1 | 1,000 | 0,994 |
| Nazwy usług | 153 | 0 | 2 | 1,000 | 0,987 |
| Technologie | 102 | 1 | 2 | 0,990 | 0,981 |
| Klasy (panel, logowanie, środowisko testowe) | 51 | 1 | 1 | 0,981 | 0,981 |

| Kontrola | Poprawne |
| --- | --- |
| Wersje usług | 30 z 32 |
| Wersje technologii | 55 z 56 |
| Tytuły stron | 122 z 122 |
| Nagłówki i ciasteczka warte uwagi | 68 z 68 |
| Flagi ciasteczek | 24 z 24 |
| Certyfikaty samopodpisane i wygasłe | 12 z 12 |
| Skrót favicon | 14 z 14 |
| Sygnatury własne użytkownika | 2 z 2 |

Czego Czujka nie znalazła:

- Port `10.66.70.11:18443`. Ten host odrzuca wszystko poza jednym wysokim portem spoza listy. Znajduje go dopiero skan pełnego zakresu portów. W sieci /16 taki skan każdego hosta trwałby około 86 minut, więc profil domyślny go nie robi. W małym zakresie Czujka skanuje pełny zakres sama.
- Wersja `dnsmasq` na porcie 53/udp i wersja NTP. Czujka nie robi wykrywania wersji po UDP.
- Jeden fałszywy wynik: port 8000 Portainera dostał nazwę „Nagios NSCA” (zgadywanie nmapa dla nieznanego portu).
- Jedna fałszywa klasa „środowisko testowe” na `10.66.60.10:80`.

Przed poprawką z 21.11 czułość portów wynosiła 0,794 (123 ze 155). 31 pominiętych portów leżało na jednym hoście z 64 otwartymi portami, poza listą domyślną. Teraz host, który pokazuje co najmniej 10 otwartych portów, dostaje dodatkowy skan portów 1-10000.

## Tempo i bezpieczeństwo skanowania

Pomiar na przewodzie, nie licznik programu. Limit 1000 pakietów na sekundę.

| Pomiar | Wartość |
| --- | --- |
| Pakiety nmapa, najwyższa sekunda | 842 |
| Wszystkie pakiety (także połączenia jądra przy wykrywaniu usług), najwyższa sekunda | 906 |
| Wszystkie pakiety, percentyl 99 | 841 |
| Sekundy powyżej limitu + 10% | 0 z 798 |
| Czas pełnego skanu /16 | 796 s (13 min 16 s) |
| Wysłane pakiety | 228 673 |
| Ostrzeżenia silnika | 0 |

Stop awaryjny (`e2e/full/transcript.txt`, sekcja 17): wywołanie trwało 0,09 s. Sekundę później nie działał żaden proces nmapa i nie wyszedł żaden pakiet IP.

Wcześniejsza wersja miała dwa błędy, które znaleźliśmy tym pomiarem i naprawiliśmy. Pierwszy: skan przekraczał limit, bo nagranie ruchu nie widziało pakietów nmapa. Drugi: po naprawie limitu skan gubił usługi, bo nmap porzucał grupy hostów po 5 minutach. Dlatego kontrola sprawdza tempo i kompletność razem.

## Pełny test produktu

`make e2e-full` (`e2e/full/transcript.txt`): 100 ze 100 kontroli przez REST API na prawdziwych usługach. Obejmuje skan, zmiany między skanami, role, szyfrowanie, import i eksport, stop awaryjny. Pamięć kontenera Czujki w czasie skanów: najwyżej 90,7 MiB.

## Uruchomienie

Pomiar na czystej maszynie (`docker:dind`, bez obrazów), zapis w `deploy/e2e/fresh-clone-dind.txt`.

| Krok | Czas |
| --- | --- |
| `git clone` | 1-2 s |
| `docker compose up -d` do działającego API | 51-115 s, zależnie od łącza (trzy pomiary) |
| Paczka offline: rozpakowanie i `sh install.sh`, bez sieci | 26-29 s |
| Logowanie, „Ten komputer”, „Uruchom skan” | 9 s |

## Szablon organizatorów (jedna maszyna)

Środowisko z `lab/jury/` uruchamiamy razem z Czujką w kontenerze `docker:dind`, żeby skan nie dotykał niczego poza szablonem. Wyniki i sposób odtworzenia: `docs/TEST-JURY.md` i `e2e/jury/`.

Zmierzone na wersji z 21.11:

- Scenariusz z README organizatorów: po zatrzymaniu usługi na porcie 8787 Czujka zgłasza „usługa zniknęła”, po jej przywróceniu „usługa wróciła po 1 min (nie było jej w 1 skanie)”.
- Opóźnienie 500 ms z Toxiproxy: „odpowiada wolniej: 482 ms, zwykle 6 ms”.
- Stos `vulnerable`: znalezione wszystkie 15 portów, WordPress 4.7.5 oznaczony jako przestarzały, rozpoznane DVWA, Adminer i Toxiproxy.

## Instancja publiczna

`https://czujka.dev` skanuje to samo laboratorium co 30 minut na serwerze z 4 vCPU i 8 GB pamięci. W nocy z 21 na 22.11 skrypt `lab/story.sh` wprowadza w laboratorium prawdziwe zmiany (hosty gasną na noc i wracają, zmieniają się wersje, otwiera się port bazy danych), więc historia w wehikule czasu pochodzi z rzeczywistych skanów.
