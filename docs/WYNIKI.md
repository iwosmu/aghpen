# Wyniki pomiarów

Ten plik zawiera tylko liczby zmierzone na działającym produkcie. Każda ma źródło, z którego da się ją odtworzyć. Stan: 22.11.2026, silnik skanowania w wersji `dab9d0e` (pomiary skali: `736ff9a`). Inne dokumenty cytują liczby stąd.

## Jak mierzymy

Laboratorium `lab/` to 70 kontenerów w sieci `10.66.0.0/16` (65 536 adresów). Każdy kontener ma opis w `lab/ground-truth/t0.json`: adres, otwarte porty, usługa, wersja, technologie, klasy. Trzy hosty są celowo niestabilne i nie wchodzą do metryk.

Polecenie `e2e/lab-gate.sh` uruchamia pełny skan /16 przez produkt (REST API, profil domyślny, limit 1000 pakietów na sekundę), nagrywa ruch programem `tcpdump` i porównuje wynik z opisem laboratorium. Potem skanuje to samo, niezmienione laboratorium drugi raz. Kontrola nie przechodzi, gdy skan przekroczy limit tempa, zgubi wyniki albo drugi skan zgłosi zmianę technologii lub wersji, której nie było. Kontrola sprawdza też limit pakietów w jądrze (rozdział „Tempo i bezpieczeństwo skanowania”) i to, czy przebieg ogólny drugiego przebiegu trwa najwyżej 1,15 raza dłużej niż pierwszego. Żadna zmiana silnika nie trafia do głównej gałęzi bez jej zaliczenia; wyjątek tej nocy opisuje rozdział „Drugi przebieg wolniejszy od pierwszego”.

Zapis kontroli na tej wersji: [`e2e/results/gate/`](../e2e/results/gate/README.md).

## Wykrywanie w sieci /16

Kontrola 3 (`e2e/lab-gate.sh`, wersja silnika `dab9d0e`, 22.11.2026, 03:04–04:20). Tryb ścisły: przypadki trudne też się liczą. Oba przebiegi dały te same liczby.

| Kategoria | Znalezione | Fałszywe | Pominięte | Precyzja | Czułość |
| --- | --- | --- | --- | --- | --- |
| Hosty | 67 | 0 | 0 | 1,000 | 1,000 |
| Otwarte porty | 154 | 0 | 1 | 1,000 | 0,994 |
| Nazwy usług | 154 | 0 | 1 | 1,000 | 0,994 |
| Technologie | 103 | 0 | 1 | 1,000 | 0,990 |
| Klasy (panel, logowanie, środowisko testowe) | 51 | 0 | 1 | 1,000 | 0,981 |

| Kontrola | Poprawne |
| --- | --- |
| Wersje usług (TCP i UDP) | 32 z 32 |
| Wersje technologii | 55 z 57 |
| Tytuły stron | 122 z 122 |
| Nagłówki i ciasteczka warte uwagi | 68 z 68 |
| Flagi ciasteczek | 24 z 24 |
| Certyfikaty samopodpisane i wygasłe | 12 z 12 |
| Skrót favicon | 14 z 14 |
| Sygnatury własne użytkownika | 2 z 2 |

Czego Czujka nie znalazła:

| Pominięcie | Przyczyna |
| --- | --- |
| `10.66.70.11:18443` (port, usługa „http”, technologia nginx, klasa „logowanie”) | Host odrzuca wszystko poza jednym wysokim portem spoza listy portów profilu. Znajduje go tylko skan pełnego zakresu. W /16 pełny zakres dostaje 16 hostów na przebieg (głębszy przebieg, rozdział „Pełny zakres portów”). Pierwsze idą hosty z otwartymi portami spoza 1000 najczęstszych, a ten host nie pokazuje żadnego. W pierwszym przebiegu nie trafia więc do szesnastki. Rotacja obejmie go w jednym z kolejnych przebiegów (70 aktywnych hostów, 16 na przebieg). |
| Wersja `dnsmasq` na 53/tcp i 53/udp | Czujka podaje „2.92rel2” (tak odpowiada serwer), opis laboratorium „2.92”. |

Od poprzedniej kontroli zniknęły dwa fałszywe wyniki i dwie pominięte wersje:

| Było | Teraz | Zmiana |
| --- | --- | --- |
| port 8000 Portainera z technologią „Nagios NSCA” | brak fałszywej technologii | słabe dopasowania nmapa (reguła z mniej niż 2 bajtami banera) zostają tylko podpowiedzią nazwy |
| fałszywa klasa „środowisko testowe” na `10.66.60.10:80` | brak | reguła nagłówka debugowania nie nadaje klasy |
| wersje usług 30 z 32 (UDP bez wersji) | 32 z 32 | `nmap -sU -sV --version-intensity 0` na otwartych portach UDP z listy |

Host, który pokazuje co najmniej 10 otwartych portów, dostaje dodatkowy skan portów 1-10000. Przed tą poprawką czułość portów wynosiła 0,794 (123 ze 155): 31 pominiętych portów leżało na jednym hoście z 64 otwartymi portami.

## Stabilność wyniku

| Kontrola | Wynik |
| --- | --- |
| Zmiany zgłoszone w drugim przebiegu niezmienionego laboratorium | 0 (`e2e/results/gate/changes-t0-2.json`) |
| Usługi w pierwszym i drugim przebiegu | 157 i 157 |
| Wyniki trudnych i fałszywych przypadków | te same w obu przebiegach |

Ta kontrola znalazła wcześniej trzy błędy, zanim trafiły do głównej gałęzi: usługa zmieniała nazwę z „http” na „ibm-db2”, a technologia „Go” pojawiała się i znikała na dwóch portach, zależnie od tego, jak długo port czekał w kolejce na wykrywanie wersji. Teraz wykrywanie wersji każdego portu trwa do końca, z jednym limitem 3 minut liczonym od startu.

## Tempo i bezpieczeństwo skanowania

Pomiar na przewodzie (`tcpdump` na interfejsie skanera), nie licznik programu. Limit polityki 1000 pakietów na sekundę. Limit w jądrze włączony (`CZUJKA_KERNEL_CAP=auto`). Kontrola używa domyślnych 16 hostów głębszego przebiegu; instancja publiczna skanuje co 30 minut z `CZUJKA_DEEP_PASS_HOSTS=4`.

| Pomiar | Pierwszy przebieg | Drugi przebieg |
| --- | --- | --- |
| Pakiety nmapa, najwyższa sekunda | 764 | 794 |
| Wszystkie pakiety (także połączenia jądra przy wykrywaniu usług), najwyższa sekunda | 913 | 937 |
| Wszystkie pakiety, percentyl 99 | 752 | 757 |
| Sekundy powyżej limitu | 0 z 2138 | 0 z 2315 |
| Przebieg ogólny /16 | 767 s (12 min 47 s) | 934 s (15 min 34 s) |
| Głębszy przebieg (16 hostów, porty 1-65535) | 1368 s (22 min 48 s) | 1380 s (23 min) |
| Cały przebieg | 2137 s | 2317 s |
| Wysłane pakiety (interfejs skanera) | 1 260 327 | 1 270 096 |
| Ostrzeżenia silnika | 0 | 0 |
| Pamięć kontenera Czujki, najwyżej | 1228,8 MiB | – |
| Baza po dwóch przebiegach | 22 MB | – |

Pamięć: szczyt 1,2 GiB trwa około minuty, około 107 s po starcie pierwszego przebiegu. Przez resztę przebiegu kontener zajmuje 200–400 MiB. Przyczyny szczytu nie zbadaliśmy. Wcześniejsza liczba w tym dokumencie (99,5 MiB) była błędna: podsumowanie w `e2e/lab-run.sh` porównywało próbki jako tekst („99,5” wypadało wyżej niż „1078”). Wartość 1228,8 MiB policzyliśmy liczbowo z próbek `docker stats` co 2 s (poprawka skryptu: `54bd34c` w gałęzi `iwosmu/czujka-accuracy`). Kontrole 1 i 2 tej nocy, tak samo przeliczone: 997,1 MiB i 1138,7 MiB.

Stop awaryjny (`e2e/full/transcript.txt`, sekcja 17): wywołanie trwało 0,09 s. Sekundę później nie działał żaden proces nmapa i nie wyszedł żaden pakiet IP.

### Limit pakietów w jądrze w kontroli

Wiersz kontroli liczy w nagraniu sondy, które liczy jądro (SYN, UDP, ICMP echo), w stałych przedziałach (`e2e/kcap-window.sh`).

| Pomiar | Granica | Pierwszy przebieg | Drugi przebieg |
| --- | --- | --- | --- |
| Limit aktywny | tak | tak | tak |
| Najwięcej sond w przedziale 100 ms | `burst` + 1100 × 0,1 = 220 | 172 | 118 |
| Najwięcej sond w sekundzie | `max_pps` 1000 | 764 | 758 |
| Odrzucone przez jądro | każde przypisane do przedziału | 393 | 22 |

Każde odrzucenie przypada na przedział tuż po przedziale prawie pustym, np. 03:18:11,1: 0, potem 172 sondy. Maszyna wirtualna stoi kilkadziesiąt milisekund, a nmap wysyła potem zaległość naraz. Jądro obcina nadmiar, a nmap wysyła te sondy ponownie w swoim tempie. Wszystkie takie przedziały leżą w głębszym przebiegu: jeden proces nmap z całym udziałem 1000 pakietów na sekundę ma tylko 10 % zapasu do limitu jądra. Wyniki wykrywania są takie same jak w kontroli bez limitu.

| Wersja wiersza | Wynik | Dlaczego zmieniona |
| --- | --- | --- |
| „odrzucone = 0” | nie przeszła w kontroli 2, przebieg 1: 24 odrzucone po zamrożeniu maszyny wirtualnej na około 60 ms przy obciążeniu hosta 60 (przedział 41,9 s: 24 sondy, przedział 42,0 s: 108) | limit w jądrze ma właśnie obcinać taki wybuch; sam wybuch to nie błąd silnika |
| „w każdym przedziale 100 ms najwyżej `burst` (110)” | błędna arytmetycznie: drugi przebieg miał 153 sondy w przedziale i 0 odrzuconych | kubełek o tempie r i pojemności b przepuszcza w stałym przedziale 100 ms do b + r × 0,1 |
| obecna: aktywny, 100 ms ≤ 220, 1 s ≤ 1000, każde odrzucenie przypisane | przeszła w kontroli 2 i 3 | sprawdza gwarancję jądra i tempo silnika osobno |

### Dwa przebiegi naraz

Pomiar budżetu wspólnego dla wszystkich przebiegów (`e2e/results/h2/H2.txt`): przebieg /16 laboratorium i, 120 s później, drugi przebieg na `10.66.10.0/24` z własnym zakresem i kopią profilu. Limit w jądrze wyłączony, żeby zmierzyć sam silnik.

| Pomiar | Wynik |
| --- | --- |
| Czas, gdy działały oba przebiegi | 696 s |
| Wszystkie pakiety skanera, najwyższa sekunda | 756 |
| Percentyl 99 / mediana | 531 / 197 |
| Sekundy powyżej 1100 (limit + 10 %) | 0 |
| Przebieg /16 przy wspólnym budżecie | 815 s |

Przed tą zmianą każdy przebieg miał własny budżet `max_pps`, więc dwa przebiegi mogły wysłać razem do 2000 pakietów na sekundę.

### Drugi przebieg wolniejszy od pierwszego: wiersz nie przeszedł

| Wersja | Przebieg ogólny 1 | Przebieg ogólny 2 | Stosunek | Granica |
| --- | --- | --- | --- | --- |
| kontrola 2 (`acc25`) | 771 s | 1524 s | 1,98 | – |
| kontrola 3 (`dab9d0e`, wydana) | 767 s | 934 s | **1,22** | 1,15 |
| poprzednia wersja na instancji publicznej (bez głębszego przebiegu) | 853 s | 940 s (cały przebieg) | 1,10 | – |

Kontrola 3 nie przeszła tego jednego wiersza. Granica zostaje 1,15.

Przyczyna: przebieg z historią dobiera wielkość pierwszej grupy z prędkości poprzednich przebiegów profilu (`measured_pps`). W kontroli 2 ta prędkość zawierała głębszy przebieg (547 zamiast 271 pakietów na sekundę). Pierwsza grupa miała wtedy 4096 adresów i wszystkie 70 aktywnych hostów, z udziałem 120 pakietów na sekundę. Wersja wydana uczy się prędkości samego przebiegu ogólnego (`general_pps`), a grupa dobiera wolny budżet między etapami, gdy żadna grupa nie czeka. Pierwsza grupa ma teraz 2267 adresów, ale nadal 58 z 70 znanych hostów. Ich skan portów idzie z udziałem 210 pakietów na sekundę, zanim inne grupy skończą.

Poprawka `04a6b1d` (grupa bierze najwyżej swoją część znanych aktywnych hostów) jest napisana i ma testy jednostkowe. Nie przeszła kontroli laboratorium, więc nie jest wydana.

## Pełny zakres portów

Pełny zakres portów (1-65535) skanujemy, gdy zakres celu ma najwyżej 256 adresów, a profil to top-N lub 1-65535; obejmuje najwyżej 16 aktywnych hostów na przebieg (grupa hostów, która nie mieści się w tym limicie, dostaje tylko porty z profilu, a przebieg pokazuje o tym notatkę). Najpierw idą porty z listy top, reszta zakresu w tle opisu usług.

Pomiar na jednym hoście testowym z dziesięcioma usługami, limit 1000 pakietów na sekundę:

| Profil | Pierwsza usługa na liście | Koniec skanu | Usługi | Najwyższa sekunda na przewodzie |
| --- | --- | --- | --- | --- |
| 7 portów podanych z nazwy | 3,5 s | 43 s | 7 | 101 |
| top-1000, potem cały zakres | 4,0 s | 222 s | 10 | 853 |
| domyślny, potem cały zakres | 4,6 s | 137 s | 10 | 866 |

Koniec skanu wyznacza najwolniejsze wykrywanie wersji w nmapie: instalator Gitei potrzebuje 42 s, port dystrybucji Erlanga 135 s. Sam nmap czeka tak samo. Usługi widać na liście od czwartej sekundy.

Usługa na porcie, którego dany skan nie objął, zachowuje stan i dostaje znacznik „nie skanowana w tym przebiegu”. Czujka nie zgłasza jej jako znikniętej.

### Rotacyjny głębszy przebieg (zakres ponad 256 adresów)

| Pomiar | Wynik |
| --- | --- |
| Hosty na przebieg | 16 (`CZUJKA_DEEP_PASS_HOSTS`, domyślnie 16, `0` wyłącza, najwyżej 64; instancja publiczna: 4) |
| Czas na host przy 1000 pakietów na sekundę | około 86 s (64 501 portów) |
| Czas głębszego przebiegu w kontroli 3 | 1368 s i 1380 s |
| Hosty czekające po przebiegu | 54 z 70 (każdy kolejny przebieg bierze inne) |
| Znalezione usługi, kontrola 2, przebieg 1 | 31, wszystkie na hoście z 64 portami (`10.66.70.14`, np. 4001–4009, 7004–7019), wszystkie zgodne z opisem laboratorium |
| Znalezione usługi, kontrola 3 | 0 nowych |

W kontroli 3 głębszy przebieg nie dodał usług, bo te same 31 portów znajduje już szeroki przebieg gęstych hostów (porty 1-10000). Głębszy przebieg pomija teraz porty, które przebieg już zeskanował na hoście. Wcześniej skanował je drugi raz i liczył podwójnie (187 usług zamiast 156; baza scalała je po porcie, więc wynik i inwentarz były poprawne).

Kolejność: najpierw hosty nigdy nie skanowane w pełni, potem hosty z większą liczbą otwartych portów TCP spoza 1000 najczęstszych, potem hosty skanowane w pełni najdawniej (`docs/ALGORYTMY.md`).

## Sygnatury na obcych usługach (zoo)

Test uogólnienia na usługach spoza laboratorium. Pełne tabele i metoda: [`e2e/zoo/RESULTS.md`](../e2e/zoo/RESULTS.md).

Zbiór odłożony: 20 usług (23 porty), których Czujka nie widziała przy strojeniu, zeskanowane raz, na końcu. „Przed” to silnik i sygnatury sprzed pracy nad zoo na danych tego samego skanu.

| Miara | Przed | Po | `nmap -sV` |
| --- | --- | --- | --- |
| Produkt | 6 z 23 | **13 z 23** | 4 z 23 |
| Wersja | 1 z 3 | 1 z 3 | 1 z 3 |
| Klasy | 4 z 14 | 4 z 14 | 0 z 14 |
| Błędne etykiety | 9 | **11** | – |

Błędnych etykiet przybyło dwie: samoopis nazwał OpenVSCode „Code” (prawda: „VS Code”), a sygnatura otwartego rejestru Dockera dodała klasę `unauth-control-api` na Docker Registry UI, który przekazuje `/v2/` do rejestru bez uwierzytelnienia. 9 z 11 błędnych etykiet dawał już silnik sprzed zmian. Siedem nowych produktów: FreshRSS, Kanboard, Directus, Graphite (import nuclei-templates) oraz Etherpad, File Browser, Gotify (samoopis strony).

Zbiór strojenia: 76 portów w 10 partiach (na tych usługach stroiliśmy sygnatury).

| Miara | Przed | Po | `nmap -sV` |
| --- | --- | --- | --- |
| Produkt | 53 z 76 | 62 z 76 | 17 z 76 |
| Wersja | 26 z 48 | 34 z 48 | 8 z 48 |
| Klasy | 26 z 54 | 42 z 54 | 0 z 54 |
| Błędne etykiety | 11 | 2 (po usunięciu jednego importu: 1) | – |

Laboratorium z importem i bez niego: precyzja technologii 0,990 w obu wariantach (dopasowanie zapisanego eksportu). Kontrola 3 z importem: precyzja technologii 1,000 (rozdział „Wykrywanie w sieci /16”).

## Skala: 2 000 i 10 000 żywych hostów

Laboratorium [`lab/scale/`](../lab/scale/README.md) na serwerze OMEN. Kontener „farma” obsługuje 1 000 żywych adresów: prawdziwy stos TCP/IP Linuksa, nginx, Dropbear SSH i lighttpd. Pomiar 2 000 to 2 kontenery, pomiar 10 000 to 10 kontenerów: tyle żywych adresów, nie tyle maszyn. Prawdę wzorcową pisze ten sam skrypt (`lab/scale/scale.sh truth`).
Zakres skanu: `10.77.0.0/16` (65 536 adresów). Profil domyślny (top-1000 i porty infrastruktury, UDP, wykrywanie wersji). Wersja `736ff9a`. Wszystko przez REST API (`lab/scale/measure.sh`), pakiety liczy `tcpdump` w przestrzeni sieciowej Czujki.
Limity: 2 000 z domyślną polityką (1 000 pakietów/s, `http_rps` 20). 10 000 z limitem podniesionym do 10 000 pakietów/s; `http_rps` 20 w przebiegu 1; 50 w przebiegach 2 (sieć bez zmian) i 3 (farma 10 wyłączona), maksimum domyślnej polityki. Surowe liczby: [`e2e/results/scale/`](../e2e/results/scale/README.md).

| Miara | 2 000, 1 000 pakietów/s | 10 000, przebieg 1 | 10 000, przebieg 2 | 10 000, przebieg 3 (farma 10 wyłączona) |
| --- | --- | --- | --- | --- |
| `http_rps` | 20 | 20 | 50 | 50 |
| Hosty | 2 000 z 2 000 | 10 000 z 10 000 | 10 000 z 10 000 | 9 000 z 9 000 (farma 10 wyłączona) |
| Otwarte porty | 4 500 z 4 500 | 22 500 z 22 500 | 22 500 z 22 500 | 20 250 z 20 250 |
| Fałszywe wyniki | 0 | 0 | 0 | 0 |
| Tytuły stron | 2 700 z 2 700 | 13 500 z 13 500 | 13 500 z 13 500 | 12 150 z 12 150 |
| Technologie WWW z wersjami | 2 700 z 2 700 | 13 500 z 13 500 | 13 500 z 13 500 | 12 150 z 12 150 |
| Nazwy i wersje usług | 4 500 z 4 500 | 18 762 z 22 500 (uwaga 1) | 18 823 z 22 500 (uwaga 1) | 16 966 z 20 250 (uwaga 1) |
| Czas przebiegu | 4 885 s (1 h 21 min) | 8 144 s (2 h 16 min) | 6 317 s (1 h 45 min) | 6 304 s (1 h 45 min) |
| Analiza | 4 s | 20 s | 24 s | 12 s |
| Pakiety na przewodzie | 3 067 499 | 13 784 368 | 13 773 202 | 12 439 163 |
| Średnio / najwyższa sekunda | 628 / 1 065 pakietów/s | 1 693 / 11 415 pakietów/s | 2 180 / 9 873 pakietów/s | 1 973 / 10 114 pakietów/s |
| Pamięć Czujki (maks.) | 914 MiB | 908 MiB | 851 MiB | 755 MiB |
| Pamięć PostgreSQL (maks.) | 253 MiB | 405 MiB | 1 057 MiB | 1 031 MiB |
| Rozmiar bazy | 45 MiB | 167 MiB | 299 MiB | 387 MiB |
| Zgłoszone zmiany | 0 (pierwszy skan) | 0 (pierwszy skan) | 8 018, wszystkie na porcie 22 (uwaga 6) | 3 792: farma 10 (1 000 hostów, 2 250 usług) i 542 na porcie 22 (uwaga 6) |

Przebieg 3 to ten sam skan z wyłączoną farmą 10 (`10.77.36.0/22`). Zmiany dotyczą dokładnie jej 1 000 hostów (`host_missing`, niepotwierdzone) i ich 2 250 usług (`service_unreachable`); poza nią zmieniły się tylko porty 22 (uwaga 6).

Czasy API (sekundy, druga z dwóch prób; strona po 50 pozycji, „daleka strona” to przesunięcie na koniec listy). Kolumna „po przebiegu 3”: ta sama baza po trzech przebiegach:

| Zapytanie | 2 000 | 10 000 | 10 000 po przebiegu 3 |
| --- | --- | --- | --- |
| Hosty: pierwsza / daleka strona | 0,012 / 0,023 | 0,030 / 0,113 | 0,023 / 0,102 |
| Usługi: pierwsza / daleka strona | 0,022 / 0,77 | 0,06 / 12,9 (przed poprawką, uwaga 5) | 0,10 / 14,7 (przed poprawką) |
| Usługi przebiegu: daleka strona | 0,85 | 13,1 (przed poprawką) | – |
| Zmiany, obserwacje, pulpit | 0,002 / 0,017 / 0,027 | 0,002 / 0,017 / 0,073 | 0,015 / 0,056 / 0,21 |
| Oś czasu / stan w chwili przebiegu | 0,006 / 0,165 | 0,006 / 0,77 | 0,024 / 2,0 |
| Wyszukiwanie „nginx” | 0,038 | 0,134 | 0,18 |
| Eksport przebiegu JSON | 0,87 (19,6 MB) | 3,2 (96,1 MB) | 4,3 (86,7 MB) |
| Eksport przebiegu CSV / nmap XML | 0,60 (1,2 MB) / 0,66 (2,4 MB) | 2,7 (5,3 MB) / 2,9 (10,8 MB) | 3,2 (4,9 MB) / 3,3 (10,0 MB) |
| Eksport usług CSV | 0,92 | 15,2 (przed poprawką, uwaga 5) | 17,8 (przed poprawką) |
| Raport HTML / Markdown | 0,13 / 0,13 | 0,45 / 0,51 | 0,62 / 0,58 |

Koszt jednego żywego hosta (z różnicy 10 000 − 2 000, przy tej mieszance usług: 2,25 otwartego portu i 1,35 usługi WWW na host): około 1 340 pakietów, 14,4 żądania HTTP (GET/HEAD) i 13–17 KB bazy na każdy przebieg (167 → 299 → 387 MiB po trzech przebiegach 10 000). Martwa część /16 kosztuje około 390 000 pakietów (około 6 na adres). Pamięć Czujki nie rośnie z liczbą hostów (około 910 MiB): wyznacza ją liczba równoległych porcji, nie wielkość sieci.

Ekstrapolacja na pełną sieć /16 z tą samą mieszanką usług (to rachunek z dwóch pomiarów, nie pomiar):

| Żywe adresy w /16 | Pakiety | Żądania HTTP | Domyślna polityka (1 000 pakietów/s, `http_rps` 20) | 10 000 pakietów/s, `http_rps` 20 | 10 000 pakietów/s, `http_rps` 50 |
| --- | --- | --- | --- | --- | --- |
| 5 % (3 277) | 4,8 mln | 47 000 | około 2,1 h | około 55 min | około 45 min |
| 20 % (13 107) | 18,0 mln | 189 000 | około 7,9 h | około 2,9 h | około 2,2 h |

Rachunek: przy 1 000 pakietów/s czas wyznaczają pakiety przy zmierzonej średniej 628 pakietów/s; przy 10 000 pakietów/s i `http_rps` 20 czas wyznacza etap HTTP (żądania / `http_rps`) plus około 900 s na skan portów i martwe adresy, tak jak w przebiegu 1; dla `http_rps` 50 skalujemy liniowo zmierzony przebieg 2 (900 s plus 0,54 s na żywy host).

Ograniczenia tego pomiaru:

1. 3 738 portów SSH w przebiegu 1 dostało nazwę `tcpwrapped` zamiast `ssh` (od 348 do 508 na farmę). To cecha laboratorium: jeden proces Dropbear obsługuje 900 adresów farmy, a jego limit `MAX_UNAUTH_PER_IP` (5) liczy każde połączenie ze skanera, który ma jeden adres. Przy 10 000 pakietów/s próby wykrywania wersji przekraczają ten limit i Dropbear zamyka połączenie od razu. W przebiegu 2 takich portów było 3 677, w przebiegu 3 (dziewięć farm) 3 284. Pomiar 2 000 przy 1 000 pakietów/s miał 1 800 z 1 800 poprawnych. W prawdziwej sieci każdy host ma własny serwer SSH.
2. Przebieg 1 przekroczył limit 10 000 pakietów/s przez 27 sekund, najwyższa sekunda: 11 415 pakietów. Przebieg 2: 0 sekund ponad limit (najwyżej 9 873), przebieg 3: 1 sekunda (10 114). Wersja `736ff9a` nie ma limitu w jądrze. Późniejsza wersja ogranicza ruch limitem w jądrze; kontrola laboratorium mierzy to przy 1 000 pakietów/s (rozdział „Tempo i bezpieczeństwo skanowania”).
3. Na gęstej sieci czas przebiegu wyznacza etap HTTP, nie pakiety. W przebiegu 1 sam etap HTTP to 144 276 żądań / 20 na sekundę = 7 214 s z 8 144 s. Grupa czterech gęstych porcji (1 000 hostów, 1 350 usług WWW) trwa około 13 minut niezależnie od limitu pakietów. Przy `http_rps` 50 (przebiegi 2 i 3) przebieg skrócił się tylko o 22 %: sam etap HTTP to wtedy 144 154 / 50 = 2 883 s z 6 317 s, resztę zajmują wykrywanie wersji i limity na host; tych dwóch nie rozdzieliliśmy.
4. Szacunek planisty przed skanem (5 944 s) nie liczy etapu HTTP; przebieg 1 trwał 8 144 s.
5. Daleka strona listy usług i eksport usług rosły szybciej niż dane (0,8 s przy 2 000, 13–38 s przy 10 000). Przyczyna: rozmiar grupy usług liczony osobno dla każdego wiersza; największa grupa ma 10 782 usługi. Poprawka `99ba021` liczy każdą grupę raz. Na bazie 10 000: zapytanie dalekiej strony 13,2 s → 0,079 s, uporządkowany przebieg pod eksportem 11,9 s → 0,032 s (pomiar zapytań SQL na tej samej bazie; tabela API pokazuje wersję `736ff9a` sprzed poprawki).
6. Przebieg 2 (sieć bez zmian) zgłosił 8 018 zmian, wszystkie na porcie 22: 4 009 zmian klas, 2 035 nowych i 1 974 zniknięte technologie. Przyczyna: port, który raz odpowiedział banerem Dropbear, a raz `tcpwrapped` (uwaga 1), tracił technologię i klasy, a przy następnym skanie je odzyskiwał; te same przejścia rozwiązały 3 948 obserwacji zdalnego dostępu. Zmianę nazwy usługi Czujka już wtedy pomijała. Poprawki: `0f3cf4a` (odpowiedź `tcpwrapped` bez banera, produktu i strony nie zmienia technologii ani klas) i `5fa2bd0` (obserwacja na takim porcie zostaje otwarta). Wersja skanu `736ff9a` ich nie ma, więc przebieg 3 pokazuje te same przejścia (542 zmiany na porcie 22 poza farmą 10).
7. Stan w chwili przebiegu (oś czasu) po trzech przebiegach 10 000 trwa 2,0 s (0,77 s po jednym).

## Szablon organizatorów (jedna maszyna)

Środowisko z `lab/jury/` uruchamiamy razem z Czujką w kontenerze `docker:dind`, żeby skan nie dotykał niczego poza szablonem. Tabela kontroli, czasy każdego stosu i sposób odtworzenia: [`docs/TEST-JURY.md`](TEST-JURY.md), zapis w `e2e/jury/transcript.txt`.

- Cel `localhost`, profil domyślny, żadnej listy portów szablonu: 31 z 31 opublikowanych portów we wszystkich czterech stosach. Pierwsza usługa na liście po 3–8 s, koniec skanu wszystkich 65 535 portów po 88–101 s.
- 159 kontroli zaliczonych, 0 niezaliczonych. Jedna znana luka: wersja vsftpd na maszynach arm64, gdzie obraz amd64 działa przez emulację.
- Scenariusz z README organizatorów na profilu domyślnym: po zatrzymaniu usługi na porcie 8787 „Usługa 172.18.0.1:8787 zniknęła (nginx 1.31.9)”, po jej przywróceniu „wróciła po 1 min (nie było jej w 1 skanie)”.
- Zamiana stosu `custom-network` na `modern`: dwie usługi zgłoszone jako zniknięte, jedna jako nowa.
- Opóźnienie 500 ms z Toxiproxy: „odpowiada wolniej”, z czasem zwykłym i zmierzonym. Limit czasu 1 s za Traefikiem: zapisany kod HTTP 502 po około 1000 ms.
- Host zatrzymany między skanami: „nie odpowiada (niepotwierdzone)” z listą jego usług od razu po skanie, „zniknął (potwierdzone)” po 110 s, bez kolejnego skanu.
- Poza listą szablonu skan pełnego zakresu znalazł port 2375: demon Dockera maszyny testowej bez TLS.

To samo na zwykłej maszynie z Ubuntu 24.04 (świeża kopia repozytorium, szablon organizatorów `quickstart.sh`, sześć portów podanych z nazwy):

| Krok | Czas skanu | Wynik |
| --- | --- | --- |
| Wszystkie usługi działają | 49 s | 5 usług z produktem i wersją |
| Po `quickstart.sh change` | 49 s | „Usługa 172.17.0.1:8787 zniknęła (nginx 1.31.9)” |
| Po `quickstart.sh up` | 49 s | „wróciła po 53 s (nie było jej w 1 skanie)” |

Polecenie odniesienia organizatorów, `nmap -Pn -sV` na tych samych portach, trwało na tej maszynie 51 s. Aktualizacja w miejscu (nowa kopia, `docker compose up -d`) trwała 55 s i zachowała historię.

## Usługi z usterkami (Toxiproxy)

`e2e/toxi-bench.sh`: osiem portów z różnymi usterkami, dwa skany.

| Usterka | Stan | Czas odpowiedzi, skan 1 i 2 |
| --- | --- | --- |
| brak | otwarty, HTTP 200 | 0 ms, 0 ms |
| opóźnienie 500 ms ± 100 ms | otwarty, HTTP 200 | 561 ms, 442 ms |
| przepustowość 12 KB/s | otwarty, HTTP 200 | 96 ms, 96 ms |
| wolne zamknięcie 5 s | otwarty, HTTP 200 | 0 ms, 0 ms |
| brak danych | otwarty, bez HTTP | brak |
| limit czasu 1 s za Traefikiem | otwarty, HTTP 502 | 1005 ms, 1002 ms |

Oba skany trwały 27 s i 28 s. Każdy port był otwarty w obu. Drugi skan zgłosił 0 zmian: wolna usługa nie jest zgłaszana jako zniknięta.

## Pełny test produktu

`make e2e-full` (`e2e/full/transcript.txt`): 100 ze 100 kontroli przez REST API na prawdziwych usługach. Obejmuje skan, zmiany między skanami, role, szyfrowanie, import i eksport, stop awaryjny.

## Uruchomienie

Pomiar na czystej maszynie (`docker:dind`, bez obrazów), zapis w `deploy/e2e/fresh-clone-dind.txt`.

| Krok | Czas |
| --- | --- |
| `git clone --depth 1` | 10 s (pomiar 22.11, łącze domowe; wcześniejszy pomiar z lokalnej paczki: 1-2 s) |
| `docker compose up -d` do działającego API | 51-115 s, zależnie od łącza (trzy pomiary); 80 s na maszynie z Ubuntu 24.04 |
| Paczka offline: rozpakowanie i `sh install.sh`, bez sieci | 26-29 s |
| Logowanie, „Ten komputer”, „Uruchom skan” | 2 kliknięcia |

## Instancja publiczna

`https://czujka.dev` skanuje to samo laboratorium co 30 minut na serwerze z 4 vCPU i 8 GB pamięci. W nocy z 21 na 22.11 skrypt `lab/story.sh` wprowadza w laboratorium prawdziwe zmiany (hosty gasną na noc i wracają, zmieniają się wersje, otwiera się port bazy danych), więc historia na osi czasu pochodzi z rzeczywistych skanów.
