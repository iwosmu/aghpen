# Wyniki pomiarów

Ten plik zawiera tylko liczby zmierzone na działającym produkcie. Każda ma źródło, z którego da się ją odtworzyć. Stan: 21.11.2026, silnik skanowania w wersji `6f39557`. Inne dokumenty cytują liczby stąd.

## Jak mierzymy

Laboratorium `lab/` to 70 kontenerów w sieci `10.66.0.0/16` (65 536 adresów). Każdy kontener ma opis w `lab/ground-truth/t0.json`: adres, otwarte porty, usługa, wersja, technologie, klasy. Trzy hosty są celowo niestabilne i nie wchodzą do metryk.

Polecenie `e2e/lab-gate.sh` uruchamia pełny skan /16 przez produkt (REST API, profil domyślny, limit 1000 pakietów na sekundę), nagrywa ruch programem `tcpdump` i porównuje wynik z opisem laboratorium. Potem skanuje to samo, niezmienione laboratorium drugi raz. Kontrola nie przechodzi, gdy skan przekroczy limit tempa, zgubi wyniki albo drugi skan zgłosi zmianę technologii lub wersji, której nie było. Żadna zmiana silnika nie trafia do głównej gałęzi bez jej zaliczenia.

Zapis kontroli na tej wersji: [`e2e/results/gate/`](../e2e/results/gate/README.md).

## Wykrywanie w sieci /16

Tryb ścisły: przypadki trudne też się liczą.

| Kategoria | Znalezione | Fałszywe | Pominięte | Precyzja | Czułość |
| --- | --- | --- | --- | --- | --- |
| Hosty | 67 | 0 | 0 | 1,000 | 1,000 |
| Otwarte porty | 154 | 0 | 1 | 1,000 | 0,994 |
| Nazwy usług | 154 | 0 | 1 | 1,000 | 0,994 |
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

- Port `10.66.70.11:18443` z jego usługą, technologią i klasą. Ten host odrzuca wszystko poza jednym wysokim portem spoza listy. Znajduje go dopiero skan pełnego zakresu portów. W sieci /16 taki skan każdego hosta trwałby około 86 minut, więc profil domyślny go tam nie robi. W małym zakresie Czujka skanuje pełny zakres sama (rozdział „Pełny zakres portów”).
- Wersje `dnsmasq` na porcie 53/udp i NTP na 123/udp. Czujka nie wykrywa wersji po UDP.
- Wersja technologii `dnsmasq` na 53/tcp: Czujka podaje „2.92rel2”, opis laboratorium „2.92”.
- Jeden fałszywy wynik: port 8000 Portainera dostał technologię „Nagios NSCA” (zgadywanie nmapa dla nieznanego portu).
- Jedna fałszywa klasa „środowisko testowe” na `10.66.60.10:80`.

Host, który pokazuje co najmniej 10 otwartych portów, dostaje dodatkowy skan portów 1-10000. Przed tą poprawką czułość portów wynosiła 0,794 (123 ze 155): 31 pominiętych portów leżało na jednym hoście z 64 otwartymi portami.

## Stabilność wyniku

Drugi skan niezmienionego laboratorium zgłosił 0 zmian (`e2e/results/gate/changes-t0-2.json`). Ta kontrola znalazła trzy błędy, zanim trafiły do głównej gałęzi: usługa zmieniała nazwę z „http” na „ibm-db2”, a technologia „Go” pojawiała się i znikała na dwóch portach, zależnie od tego, jak długo port czekał w kolejce na wykrywanie wersji. Teraz wykrywanie wersji każdego portu trwa do końca, z jednym limitem 3 minut liczonym od startu.

## Tempo i bezpieczeństwo skanowania

Pomiar na przewodzie, nie licznik programu. Limit 1000 pakietów na sekundę.

| Pomiar | Pierwszy skan | Drugi skan |
| --- | --- | --- |
| Pakiety nmapa, najwyższa sekunda | 842 | 874 |
| Wszystkie pakiety (także połączenia jądra przy wykrywaniu usług), najwyższa sekunda | 973 | 903 |
| Wszystkie pakiety, percentyl 99 | 847 | 853 |
| Sekundy powyżej limitu | 0 | 0 |
| Czas pełnego skanu /16 | 762 s (12 min 42 s) | 1016 s (16 min 56 s) |
| Wysłane pakiety | 230 914 | 231 371 |
| Ostrzeżenia silnika | 0 | 0 |

Drugi przebieg tego samego zakresu trwa dłużej przy tej samej liczbie pakietów. Planista łączy bloki znanych aktywnych hostów w większe grupy, a w dużej grupie etap HTTP hosta zaczyna się dopiero po wykrywaniu wersji całej grupy. Najdłuższy jest host z 64 usługami WWW: około 320 s przy limicie 2 żądań na sekundę na host. To znane ograniczenie planisty.

Pamięć kontenera Czujki w czasie obu skanów: najwyżej 99,5 MiB. Baza po dwóch skanach /16: 18 MB.

Stop awaryjny (`e2e/full/transcript.txt`, sekcja 17): wywołanie trwało 0,09 s. Sekundę później nie działał żaden proces nmapa i nie wyszedł żaden pakiet IP.

Wcześniejsze wersje miały dwa błędy, które znaleźliśmy pomiarem na przewodzie i naprawiliśmy. Pierwszy: skan przekraczał limit, bo nagranie ruchu nie widziało pakietów nmapa. Drugi: po naprawie limitu skan gubił usługi, bo nmap porzucał grupy hostów po 5 minutach. Dlatego kontrola sprawdza tempo i kompletność razem.

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

## Skala: 2 000 i 10 000 żywych hostów

Laboratorium [`lab/scale/`](../lab/scale/README.md) na serwerze OMEN. Kontener „farma” obsługuje 1 000 żywych adresów: prawdziwy stos TCP/IP Linuksa, nginx, Dropbear SSH i lighttpd. Pomiar 2 000 to 2 kontenery, pomiar 10 000 to 10 kontenerów: tyle żywych adresów, nie tyle maszyn. Prawdę wzorcową pisze ten sam skrypt (`lab/scale/scale.sh truth`).
Zakres skanu: `10.77.0.0/16` (65 536 adresów). Profil domyślny (top-1000 i porty infrastruktury, UDP, wykrywanie wersji). Wersja `736ff9a`. Wszystko przez REST API (`lab/scale/measure.sh`), pakiety liczy `tcpdump` w przestrzeni sieciowej Czujki.
Limity: 2 000 z domyślną polityką (1 000 pakietów/s, `http_rps` 20). 10 000 z limitem podniesionym do 10 000 pakietów/s; `http_rps` 20 w przebiegu 1; przebiegi 2 (bez zmian w sieci) i 3 (farma 10 wyłączona) idą z `http_rps` 50, maksimum domyślnej polityki, i trafią tu po zakończeniu. Surowe liczby: [`e2e/results/scale/`](../e2e/results/scale/README.md).

| Miara | 2 000, 1 000 pakietów/s | 10 000, przebieg 1 |
| --- | --- | --- |
| `http_rps` | 20 | 20 |
| Hosty | 2 000 z 2 000 | 10 000 z 10 000 |
| Otwarte porty | 4 500 z 4 500 | 22 500 z 22 500 |
| Fałszywe wyniki | 0 | 0 |
| Tytuły stron | 2 700 z 2 700 | 13 500 z 13 500 |
| Technologie WWW z wersjami | 2 700 z 2 700 | 13 500 z 13 500 |
| Nazwy i wersje usług | 4 500 z 4 500 | 18 762 z 22 500 (uwaga 1) |
| Czas przebiegu | 4 885 s (1 h 21 min) | 8 144 s (2 h 16 min) |
| Analiza | 4 s | 20 s |
| Pakiety na przewodzie | 3 067 499 | 13 784 368 |
| Średnio / najwyższa sekunda | 628 / 1 065 pakietów/s | 1 693 / 11 415 pakietów/s |
| Pamięć Czujki (maks.) | 914 MiB | 908 MiB |
| Pamięć PostgreSQL (maks.) | 253 MiB | 405 MiB |
| Rozmiar bazy | 45 MiB | 166 MiB |
| Zgłoszone zmiany | 0 (pierwszy skan) | 0 (pierwszy skan) |

Czasy API (sekundy, druga z dwóch prób; strona po 50 pozycji, „daleka strona” to przesunięcie na koniec listy):

| Zapytanie | 2 000 | 10 000 |
| --- | --- | --- |
| Hosty: pierwsza / daleka strona | 0,012 / 0,023 | 0,030 / 0,113 |
| Usługi: pierwsza / daleka strona | 0,022 / 0,77 | 0,06 / 12,9 (przed poprawką, uwaga 5) |
| Usługi przebiegu: daleka strona | 0,85 | 13,1 (przed poprawką) |
| Zmiany, obserwacje, pulpit | 0,002 / 0,017 / 0,027 | 0,002 / 0,017 / 0,073 |
| Oś czasu / stan w chwili przebiegu | 0,006 / 0,165 | 0,006 / 0,77 |
| Wyszukiwanie „nginx” | 0,038 | 0,134 |
| Eksport przebiegu JSON | 0,87 (19,6 MB) | 3,2 (96,1 MB) |
| Eksport przebiegu CSV / nmap XML | 0,60 (1,2 MB) / 0,66 (2,4 MB) | 2,7 (5,3 MB) / 2,9 (10,8 MB) |
| Eksport usług CSV | 0,92 | 15,2 (przed poprawką, uwaga 5) |
| Raport HTML / Markdown | 0,13 / 0,13 | 0,45 / 0,51 |

Koszt jednego żywego hosta (z różnicy 10 000 − 2 000, przy tej mieszance usług: 2,25 otwartego portu i 1,35 usługi WWW na host): około 1 340 pakietów, 14,4 żądania HTTP (GET/HEAD) i 15 KB bazy na przebieg. Martwa część /16 kosztuje około 390 000 pakietów (około 6 na adres). Pamięć Czujki nie rośnie z liczbą hostów (około 910 MiB): wyznacza ją liczba równoległych porcji, nie wielkość sieci.

Ekstrapolacja na pełną sieć /16 z tą samą mieszanką usług (to rachunek z dwóch pomiarów, nie pomiar):

| Żywe adresy w /16 | Pakiety | Żądania HTTP | Domyślna polityka (1 000 pakietów/s, `http_rps` 20) | 10 000 pakietów/s, `http_rps` 20 | 10 000 pakietów/s, `http_rps` 50 |
| --- | --- | --- | --- | --- | --- |
| 5 % (3 277) | 4,8 mln | 47 000 | około 2,1 h | około 55 min | około 31 min |
| 20 % (13 107) | 18,0 mln | 189 000 | około 7,9 h | około 2,9 h | około 1,3 h |

Rachunek: przy 1 000 pakietów/s czas wyznaczają pakiety przy zmierzonej średniej 628 pakietów/s; przy 10 000 pakietów/s czas wyznacza etap HTTP (żądania / `http_rps`) plus około 900 s na skan portów i martwe adresy, tak jak w przebiegu 1.

Ograniczenia tego pomiaru:

1. 3 738 portów SSH w przebiegu 1 dostało nazwę `tcpwrapped` zamiast `ssh` (od 348 do 508 na farmę). To cecha laboratorium: jeden proces Dropbear obsługuje 900 adresów farmy, a jego limit `MAX_UNAUTH_PER_IP` (5) liczy każde połączenie ze skanera, który ma jeden adres. Przy 10 000 pakietów/s próby wykrywania wersji przekraczają ten limit i Dropbear zamyka połączenie od razu. Pomiar 2 000 przy 1 000 pakietów/s miał 1 800 z 1 800 poprawnych. W prawdziwej sieci każdy host ma własny serwer SSH.
2. Przebieg 1 przekroczył limit 10 000 pakietów/s przez 27 sekund, najwyższa sekunda: 11 415 pakietów. Wersja `736ff9a` nie ma limitu w jądrze. Późniejsza wersja ogranicza ruch limitem w jądrze; kontrola laboratorium mierzy to przy 1 000 pakietów/s (rozdział „Tempo i bezpieczeństwo skanowania”).
3. Na gęstej sieci czas przebiegu wyznacza etap HTTP, nie pakiety. W przebiegu 1 sam etap HTTP to 144 276 żądań / 20 na sekundę = 7 214 s z 8 144 s. Grupa czterech gęstych porcji (1 000 hostów, 1 350 usług WWW) trwa około 13 minut niezależnie od limitu pakietów.
4. Szacunek planisty przed skanem (5 944 s) nie liczy etapu HTTP; przebieg 1 trwał 8 144 s.
5. Daleka strona listy usług i eksport usług rosły szybciej niż dane (0,8 s przy 2 000, 13–38 s przy 10 000). Przyczyna: rozmiar grupy usług liczony osobno dla każdego wiersza; największa grupa ma 10 782 usługi. Poprawka `99ba021` liczy każdą grupę raz. Na bazie 10 000: zapytanie dalekiej strony 13,2 s → 0,079 s, uporządkowany przebieg pod eksportem 11,9 s → 0,032 s (pomiar zapytań SQL na tej samej bazie; tabela API pokazuje wersję `736ff9a` sprzed poprawki).

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
| `git clone` | 1-2 s |
| `docker compose up -d` do działającego API | 51-115 s, zależnie od łącza (trzy pomiary); 80 s na maszynie z Ubuntu 24.04 |
| Paczka offline: rozpakowanie i `sh install.sh`, bez sieci | 26-29 s |
| Logowanie, „Ten komputer”, „Uruchom skan” | 2 kliknięcia |

## Instancja publiczna

`https://czujka.dev` skanuje to samo laboratorium co 30 minut na serwerze z 4 vCPU i 8 GB pamięci. W nocy z 21 na 22.11 skrypt `lab/story.sh` wprowadza w laboratorium prawdziwe zmiany (hosty gasną na noc i wracają, zmieniają się wersje, otwiera się port bazy danych), więc historia na osi czasu pochodzi z rzeczywistych skanów.
