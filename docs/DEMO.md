# Demo Czujki

Scenariusz nagrania (do 2 minut), scenariusz pokazu na scenie (5 minut), przygotowanie stanowiska i pytania jury.
Wszystko działa lokalnie na laptopie: produkt, laboratorium i DefectDojo. Internet jest potrzebny tylko dzień wcześniej, do zbudowania obrazów.

| Część | Co zawiera |
| --- | --- |
| [1. Nagranie](#1-nagranie-2-minuty) | 10 ujęć z kodem czasu, ekranem, kliknięciami, tekstem lektora i napisami |
| [2. Pokaz na scenie](#2-pokaz-na-scenie-5-minut) | kto mówi co, minuta po minucie; plan na awarię sieci |
| [3. Przygotowanie](#3-przygotowanie-stanowiska) | polecenia od zera do stanu startowego demo i reset |
| [4. Pytania jury](#4-pytania-jury) | 19 pytań z odpowiedziami i wskazaniem pliku albo ekranu |

Liczby w tekście lektora pochodzą z repozytorium: 19,9 s kreatora (`web/REPORT-LAB.md` §5), 0,06 s wywołania stopu awaryjnego i brak procesu nmap sekundę później (`e2e/full/transcript.txt` krok 17, dowód z procesów), 65 535 adresów /16 (`web/screenshots/lab/47-run-completed-pl-dark-1440.png`).
Liczby pakietów z `e2e/full/transcript.txt` (średnie tempo, „0 pakietów” po stopie i przy retro-huncie) są niepotwierdzone: przechwytywanie `tcpdump -Q out` nie widzi pakietów, które nmap wysyła przez surowe gniazdo. Demo ich nie cytuje, dopóki pomiar nie zostanie powtórzony.

## 1. Nagranie (2 minuty)

Ekran 1920 × 1080, interfejs po polsku, motyw ciemny, powiększenie przeglądarki 125 %. Lektor po polsku, spokojnym tempem. Napisy wtopione w obraz, dół ekranu, biały tekst na półprzezroczystym czarnym pasku.

Tekst lektora: **197 słów**, czyli **85,7 s** przy 2,3 słowa na sekundę. Ujęcia trwają razem 120 s; reszta to pauzy na obraz.

Stan wyjściowy: rozdział 3. Ujęcia 1–2 nagrywa się na świeżej instalacji (`czwiz`), ujęcia 3–10 na instalacji z historią (`czdemo`).

### Ujęcie 1 · 0:00–0:10 (10 s)

| | |
| --- | --- |
| Ekran | Terminal na czarnym tle, czcionka 20 pt. Potem ekran logowania Czujki. |
| Kliknięcia | Wpisz `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.scan-network.yml up -d --wait` (obrazy zbudowane wcześniej). Przyspiesz oczekiwanie 4×. Otwórz `http://127.0.0.1:8080`, wklej hasło z logu, „Zaloguj”. |
| Lektor | „Czujka staje jednym poleceniem: binarka Go i PostgreSQL w Docker Compose. Bez Kubernetesa i bez klastra.” |
| Długość | 16 słów, 7,0 s przy 2,3 słowa/s (zapas 3,0 s) |

Napisy (jedna plansza na wiersz, ⏎ = nowa linia, najwyżej 42 znaki w linii):

- Czujka staje jednym poleceniem: binarka Go ⏎ i PostgreSQL w Docker Compose.
- Bez Kubernetesa i bez klastra.

### Ujęcie 2 · 0:10–0:24 (14 s)

| | |
| --- | --- |
| Ekran | Kreator „Od logowania do pierwszego skanu w pięciu krokach” (zrzuty `20`–`25`). |
| Kliknięcia | Krok 1: nowe hasło. Krok 2: nazwa „Laboratorium CBI”, zakres `10.66.0.0/16`. Krok 3: limit 2000 pps. Krok 4: harmonogram „ręcznie”. Krok 5: „Uruchom”. Nagrywaj w czasie rzeczywistym; w montażu przytnij do 14 s i pokaż licznik czasu w rogu. |
| Lektor | „Kreator prowadzi przez pięć kroków: hasło, zakresy, limity od właściciela sieci, harmonogram i budżet ruchu. Od logowania do skanu mija dwadzieścia sekund.” |
| Długość | 22 słów, 9,6 s przy 2,3 słowa/s (zapas 4,4 s) |

Napisy (jedna plansza na wiersz, ⏎ = nowa linia, najwyżej 42 znaki w linii):

- Kreator prowadzi przez pięć kroków: hasło, ⏎ zakresy, limity od właściciela sieci,
- harmonogram i budżet ruchu.
- Od logowania do skanu mija 20 sekund.

### Ujęcie 3 · 0:24–0:38 (14 s)

| | |
| --- | --- |
| Ekran | Strona przebiegu: mapa 256 bloków /24, tabela podgrup, wskaźnik tempa (zrzuty `03`, `47`). |
| Kliknięcia | Kliknij numer przebiegu na górnym pasku. Najedź na jedną grupę roboczą w tabeli: blok podświetla się na mapie. Przyspiesz 8×, aż mapa się wypełni. |
| Lektor | „Skanujemy całe laboratorium: sześćdziesiąt pięć tysięcy adresów. Każdy kwadrat to blok slash dwadzieścia cztery. Tempo nie przekracza limitu z polityki bezpieczeństwa.” |
| Długość | 21 słów, 9,1 s przy 2,3 słowa/s (zapas 4,9 s) |

Napisy (jedna plansza na wiersz, ⏎ = nowa linia, najwyżej 42 znaki w linii):

- Skanujemy całe laboratorium: 65 tysięcy ⏎ adresów.
- Każdy kwadrat to blok /24.
- Tempo nie przekracza limitu z polityki ⏎ bezpieczeństwa.

### Ujęcie 4 · 0:38–0:50 (12 s)

| | |
| --- | --- |
| Ekran | „Zmiany” po drugim przebiegu (stan laboratorium `t1`), potem „Porównaj dwa skany”. |
| Kliknięcia | Menu „Zmiany”. Filtr „Skan” = ostatni. Kliknij wiersz `10.66.1.11` (WordPress 5.8.3 → 6.9.4), potem `10.66.2.30` (strona staje się panelem). |
| Lektor | „Drugi przebieg. Czujka pokazuje, co przybyło, co zniknęło i co się zmieniło: nowy host, nowszy WordPress, strona, która stała się panelem.” |
| Długość | 21 słów, 9,1 s przy 2,3 słowa/s (zapas 2,9 s) |

Napisy (jedna plansza na wiersz, ⏎ = nowa linia, najwyżej 42 znaki w linii):

- Drugi przebieg.
- Czujka pokazuje, co przybyło, co zniknęło ⏎ i co się zmieniło: nowy host, nowszy
- WordPress, strona, która stała się ⏎ panelem.

### Ujęcie 5 · 0:50–1:04 (14 s)

| | |
| --- | --- |
| Ekran | Szczegóły hosta niestabilnego (`10.66.70.21`, `tod-office`): mapa cieplna tygodnia, `p_alive`, pasma życia hosta, plan ponownych sprawdzeń. |
| Kliknięcia | Menu „Hosty”, filtr stanu „niestabilny”, kliknij `10.66.70.21`. Najedź na komórkę mapy cieplnej. Przewiń do „Plan ponownych sprawdzeń”. |
| Lektor | „Ten host pracuje we własnym rytmie. Czujka go zna, więc cisza w zwykłej porze nie jest alarmem. Gdy host milknie w nietypowej porze, Czujka sprawdza go ponownie.” |
| Długość | 27 słów, 11,7 s przy 2,3 słowa/s (zapas 2,3 s) |

Napisy (jedna plansza na wiersz, ⏎ = nowa linia, najwyżej 42 znaki w linii):

- Ten host pracuje we własnym rytmie.
- Czujka go zna, więc cisza w zwykłej porze ⏎ nie jest alarmem.
- Gdy host milknie w nietypowej porze, ⏎ Czujka sprawdza go ponownie.

### Ujęcie 6 · 1:04–1:14 (10 s)

| | |
| --- | --- |
| Ekran | „Wehikuł czasu” (`/time`): suwak przebiegów, liczby z różnicą do dziś, mapa adresów z tamtej chwili. |
| Kliknięcia | Menu „Wehikuł czasu”. Przeciągnij suwak na przebieg 1, potem strzałką → na przebieg 2. |
| Lektor | „Wehikuł czasu. Przesuwam suwak i widzę sieć taką, jaka była w dowolnym wcześniejszym przebiegu.” |
| Długość | 19 słów, 8,3 s przy 2,3 słowa/s (zapas 1,7 s) |

Napisy (jedna plansza na wiersz, ⏎ = nowa linia, najwyżej 42 znaki w linii):

- Wehikuł czasu.
- Przesuwam suwak i widzę sieć taką, jaka ⏎ była w dowolnym wcześniejszym przebiegu.

### Ujęcie 7 · 1:14–1:24 (10 s)

| | |
| --- | --- |
| Ekran | „Reguły ekspozycji” (`/rules`): reguła `admin-panel-outside-mgmt` z licznikiem naruszeń, potem znalezisko `policy-violation`. |
| Kliknięcia | Menu „Reguły ekspozycji”. Kliknij regułę `admin-panel-outside-mgmt`. Kliknij naruszenie `10.66.5.5:8080` (Adminer, „shadow IT” ze stanu `t1`). |
| Lektor | „Reguła mówi, czego w sieci być nie może. Zapomniany panel bazy danych na nowym adresie narusza ją od razu po skanie.” |
| Długość | 21 słów, 9,1 s przy 2,3 słowa/s (zapas 0,9 s) |

Napisy (jedna plansza na wiersz, ⏎ = nowa linia, najwyżej 42 znaki w linii):

- Reguła mówi, czego w sieci być nie może.
- Zapomniany panel bazy danych na nowym ⏎ adresie narusza ją od razu po skanie.

### Ujęcie 8 · 1:24–1:40 (16 s)

| | |
| --- | --- |
| Ekran | Usługa `10.66.60.12:80` (InfoKiosk): „Zaproponuj sygnaturę”, YAML z objaśnieniami, wynik retro-huntu. |
| Kliknięcia | Menu „Usługi”, szukaj „kiosk”, kliknij `10.66.60.12:80`. „Zaproponuj sygnaturę”. Pokaż „Wysłano 0 pakietów” i drugi kiosk na liście. „Otwórz w edytorze”, „Zapisz sygnaturę”. |
| Lektor | „Tego kiosku nie zna żadna publiczna baza sygnatur. Jeden klik: Czujka proponuje sygnaturę z rzadkich cech i sprawdza ją na zapisanej historii, bez wysyłania sond.” |
| Długość | 25 słów, 10,9 s przy 2,3 słowa/s (zapas 5,1 s) |

Napisy (jedna plansza na wiersz, ⏎ = nowa linia, najwyżej 42 znaki w linii):

- Tego kiosku nie zna żadna publiczna baza ⏎ sygnatur.
- Jeden klik: Czujka proponuje sygnaturę z ⏎ rzadkich cech i sprawdza ją na zapisanej
- historii, bez wysyłania sond.

### Ujęcie 9 · 1:40–1:50 (10 s)

| | |
| --- | --- |
| Ekran | Trwający skan, czerwony przycisk „Stop awaryjny”, pasek „Stop awaryjny jest aktywny” (zrzuty `11`–`13`). |
| Kliknięcia | Uruchom profil „Laboratorium /16” z pulpitu. Po 5 s kliknij „Stop awaryjny” na górnym pasku, potwierdź. Pokaż wskaźnik tempa: 0 pps. |
| Lektor | „Stop awaryjny zatrzymuje każdy skan. Wywołanie trwało sześć setnych sekundy, a po sekundzie nie działał już żaden proces nmap.” |
| Długość | 14 słów, 6,1 s przy 2,3 słowa/s (zapas 3,9 s) |

Napisy (jedna plansza na wiersz, ⏎ = nowa linia, najwyżej 42 znaki w linii):

- Stop awaryjny zatrzymuje każdy skan.
- Wywołanie trwało 0,06 s, a po sekundzie ⏎ nie działał już żaden proces nmap.

### Ujęcie 10 · 1:50–2:00 (10 s)

| | |
| --- | --- |
| Ekran | „Znaleziska” → „Eksport do DefectDojo”, potem lista findings w lokalnym DefectDojo (`http://127.0.0.1:18080`). Na końcu plansza: logo Czujki i zdanie tezy. |
| Kliknięcia | Menu „Znaleziska”, zaznacz pięć pierwszych, „Eksport do DefectDojo”. Przełącz kartę na DefectDojo, odśwież test. |
| Lektor | „Znaleziska trafiają do DefectDojo bez duplikatów. Czujka: skaner, który rozumie czas.” |
| Długość | 11 słów, 4,8 s przy 2,3 słowa/s (zapas 5,2 s) |

Napisy (jedna plansza na wiersz, ⏎ = nowa linia, najwyżej 42 znaki w linii):

- Znaleziska trafiają do DefectDojo bez ⏎ duplikatów.
- Czujka: skaner, który rozumie czas.

### Montaż

- Ujęcia 1 i 3: przyspieszenie zaznaczone napisem „×4” albo „×8” w prawym górnym rogu. Nie przyspieszaj ujęć 8 i 9: wynik retro-huntu i wskaźnik „0 pps” muszą być widoczne w czasie rzeczywistym.
- Kursor powiększony, kliknięcia zaznaczone kołem.
- Na końcu plansza 3 s: ikona Czujki, „Czujka: skaner, który rozumie czas”, adres repozytorium.

## 2. Pokaz na scenie (5 minut)

Role: **A** = Iwo Smura (mówi, prowadzi slajdy), **B** = Iwo Wojtakajtis (laptop z demo). Dwa ekrany: slajdy (`docs/slides/czujka.pdf`) i przeglądarka z Czujką. Przełączanie: Cmd+Tab na laptopie B; A ma pilota do slajdów.

| Czas | Kto | Ekran | Co mówi i robi |
| --- | --- | --- | --- |
| 0:00–0:30 | A | slajd 1 | „Wasze pytanie z treści zadania: adres milczy o trzeciej w nocy. Wyłączony czy zniknął? Zbudowaliśmy narzędzie, które umie na nie odpowiedzieć.” |
| 0:30–1:10 | A | slajd 2 | Teza: rytm 168 godzin, dwa przypadki z testu: 16 braków w weekend bez alarmu, 2 braki w poniedziałek z alarmem. |
| 1:10–1:40 | B | Czujka: pulpit, potem „Zmiany” | „To laboratorium /16 po drugim skanie.” Pokazuje zdanie na górze pulpitu i trzy zmiany ze stanu `t1`. |
| 1:40–2:10 | B | host `10.66.70.21`, „Wehikuł czasu” | Mapa cieplna, `p_alive`, plan ponownych sprawdzeń; suwak wehikułu na przebieg 1. |
| 2:10–2:40 | B | usługa `10.66.60.12:80` | „Zaproponuj sygnaturę” na żywo; retro-hunt czyta zapisaną historię, bez sond. |
| 2:40–3:00 | B | pulpit | Start skanu, po 5 s „Stop awaryjny”. A: „Sześć setnych sekundy. Sekundę później nie działa żaden proces nmap.” |
| 3:00–3:40 | A | slajdy 8 i 9 | Bezpieczeństwo i role; jedno polecenie wobec Kubernetesa i Helm w SecureCodeBox. |
| 3:40–4:30 | A | slajd 10 | Wyniki zmierzone; plan na pierwsze dwa tygodnie w CBI. |
| 4:30–5:00 | A i B | slajd 10 | „Czujka: skaner, który rozumie czas. Pytania?” B zostawia otwarty pulpit. |

Jeśli jury poprosi o konkretny przypadek: B ma gotowe zakładki przeglądarki: ręczne dodanie hosta (`Hosty` → „Dodaj host”), import pliku CSV z celami, eksport CSV, rola „Obserwator” w drugim oknie prywatnym (konto `viewer@czujka.local` utworzone w rozdziale 3).

### Gdy sieć na sali nie działa

Demo nie potrzebuje sieci na sali. Wszystko stoi na laptopie B:

1. Laboratorium to sieć dockerowa `czujka-lab` na laptopie. Skaner dołącza do niej przez `deploy/docker-compose.scan-network.yml`; żaden pakiet nie wychodzi z laptopa.
2. Obrazy produktu, laboratorium i DefectDojo są zbudowane dzień wcześniej. Na scenie uruchamiaj stos **bez `--build`**: `up -d --wait` nie pobiera niczego.
3. crt.sh jest domyślnie wyłączone (`/settings/passive`); nic w demo nie woła usług zewnętrznych.
4. Slajdy to PDF z wbudowanymi fontami; `docs/slides/czujka.html` też działa bez sieci.
5. Kopia nagrania (2 min) leży na pulpicie laptopa B i na pendrivie. Gdy laptop B zawiedzie, A puszcza nagranie z własnego laptopa i komentuje je według tabeli powyżej.
6. Sprawdzenie dzień wcześniej: wyłącz Wi-Fi i przejdź cały pokaz.
7. Gdy sieć działa, a laptop B nie: publiczna instancja `https://czujka.dev` z tym samym laboratorium 70 hostów (konto do odczytu dla jury: dane logowania w zgłoszeniu). Rola „Obserwator” nie uruchomi skanu ani stopu awaryjnego, więc te kroki pokazuje wtedy nagranie.

## 3. Przygotowanie stanowiska

Polecenia uruchamia się z katalogu głównego repozytorium. Wymagania: Docker Desktop (testowane: aarch64, 15 CPU, 27 GB), około 4 GB wolnej pamięci dla laboratorium i produktu.

### 3.1 Dzień wcześniej (z internetem)

```sh
lab/lab.sh build                                   # obrazy laboratorium (pierwszy raz kilka minut)
docker compose -f lab/defectdojo/docker-compose.yml pull
CZUJKA_SCAN_NETWORK=czujka-lab docker compose -p czdemo \
  -f deploy/docker-compose.yml -f deploy/docker-compose.scan-network.yml build
```

### 3.2 Stan startowy demo

```sh
# 1. laboratorium /16, stan t0 (31–32 s do „71 kontenerów healthy”)
lab/lab.sh up
lab/scenario.sh t0

# 2. DefectDojo na 127.0.0.1:18080 (login admin, hasło w lab/defectdojo/README.md)
docker compose -f lab/defectdojo/docker-compose.yml up -d

# 3. Czujka z historią: projekt czdemo, port 8080, dołączona do czujka-lab
CZUJKA_SCAN_NETWORK=czujka-lab docker compose -p czdemo \
  -f deploy/docker-compose.yml -f deploy/docker-compose.scan-network.yml up -d --wait
docker compose -p czdemo -f deploy/docker-compose.yml logs czujka | grep -A3 "first administrator"
docker inspect czdemo-czujka-1 \
  -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{$v.IPAddress}}{{"\n"}}{{end}}'   # adres Czujki w czujka-lab

# 4. Czujka bez historii do ujęć kreatora: projekt czwiz, port 8081
CZUJKA_PORT=8081 CZUJKA_SCAN_NETWORK=czujka-lab docker compose -p czwiz \
  -f deploy/docker-compose.yml -f deploy/docker-compose.scan-network.yml up -d --wait
```

W interfejsie `czdemo` (`http://127.0.0.1:8080`):

1. Przejdź kreator: zakres `10.66.0.0/16`, limit 2000 pps, harmonogram ręczny.
2. „Polityka bezpieczeństwa”: wykluczenia = adres Czujki z kroku 3, `10.66.0.1` (brama), `10.66.0.10` (skrzynka skanera); dozwolone sieci = `10.66.0.0/16`.
3. „Administracja” → „Użytkownicy”: dodaj `viewer@czujka.local` z rolą „Obserwator”.
4. Przebieg 1 na stanie `t0`. Gdy się skończy: `lab/scenario.sh t1` (9 s), potem przebieg 2.
5. Profil „Co 2 minuty: hosty niestabilne” na `10.66.70.0/24` z cronem `*/2 * * * *`, włączony przez co najmniej 30 minut przed pokazem (próbki dla `flapper`, `tod-office`, `tod-night`).
6. „Ustawienia” → „Ponowne sprawdzenia”: włączone. „Integracje” → DefectDojo: adres `http://host.docker.internal:18080` i token z `lab/defectdojo/README.md`, „Sprawdź połączenie” (tej drogi z kontenera do DefectDojo nie sprawdzono w tym zadaniu).
7. Sygnatura `lab-infokiosk` **nie** może być zainstalowana: ujęcie 8 pokazuje, że Czujka sama ją proponuje.

Podgląd hostów niestabilnych na żywo: `go run ./e2e/watchunstable`.

### 3.3 Czego demo potrzebuje od `lab/story.sh` (w przygotowaniu)

Skrypt `lab/story.sh` pisze zespół dokładności: zaplanowana seria prawdziwych zmian w laboratorium przez kilka godzin, z której powstaje prawdziwa historia. Demo potrzebuje od niego:

| Potrzeba | Ujęcie | Dlaczego |
| --- | --- | --- |
| skanów w co najmniej 8 różnych godzinach | 5 | Model nazywa rytm i nadaje `expected-offline` dopiero od 8 obserwacji (`MinObsForExpected`); mapa cieplna z jednej godziny jest pusta |
| hosta, który milknie poza swoim rytmem | 5 | plan ponownych sprawdzeń i zmiana `host_gone` po krokach `[10, 30, 90]` min |
| przejścia `t0` → `t1` między dwoma skanami | 4, 6, 7 | zmiany, dwa punkty na suwaku wehikułu, `shadow-adminer` dla reguły |
| kiosków `kiosk-1` i `kiosk-2` w obu stanach | 8 | „Zaproponuj sygnaturę” potrzebuje przykładu i podobnej instancji |
| stanu końcowego zapisanego w wolumenie bazy | wszystkie | pokaz nie może czekać godzinami: kopia `pg_dump` z `docs/WDROZENIE.md` §6 przed wyjazdem |

### 3.4 Reset

```sh
# szybki reset demo: dane Czujki od zera, laboratorium do t0
docker compose -p czdemo -f deploy/docker-compose.yml down -v
docker compose -p czwiz  -f deploy/docker-compose.yml down -v
lab/scenario.sh t0

# pełne sprzątanie
lab/lab.sh down
docker compose -f lab/defectdojo/docker-compose.yml down -v
```

`down -v` usuwa też klucz główny instalacji. Do powrotu do stanu z historią służy kopia z `docs/WDROZENIE.md` §6.

## 4. Pytania jury

| # | Pytanie | Odpowiedź | Gdzie |
| --- | --- | --- | --- |
| 1 | Dlaczego nie nmap i skrypt? | nmap jest w środku Czujki i robi sondy. Czujka dodaje to, czego skrypt nie ma: pamięć między przebiegami, wspólny budżet pakietów dla równoległych procesów nmap, okna czasowe, role, szyfrowanie i ekran dla analityka. | `internal/scan`, `internal/analyze`, `docs/ALGORYTMY.md` |
| 2 | Dlaczego nie SecureCodeBox? | SecureCodeBox wymaga Kubernetesa (4 ostatnie wydania), Helm, operatora, magazynu S3 i osobnego chartu na każdy skaner; nie ma własnego interfejsu. Orkiestruje wiele skanerów; Czujka robi discovery w czasie i może z nim współistnieć przez wspólny DefectDojo. | slajd 9; securecodebox.io/docs/getting-started/installation |
| 3 | Co z IPv6? | Pojedyncze adresy IPv6 tak; zakres CIDR IPv6 jest odrzucany z komunikatem, bo przeglądanie /64 nie ma sensu. Adresy IPv6 trzeba brać ze źródeł pasywnych (DNS, strefy), co jest następnym krokiem. | `internal/targets/parse.go`, `docs/INTEGRACJE.md` §3 |
| 4 | Co przy 10 razy większej sieci? | Liczenie adresów nie rozwija listy, plan idzie w blokach /24, zapis wsadowy. Czas rośnie liniowo z liczbą adresów przy stałym limicie pps: /16 przy 2000 pps to 7 min 24 s, więc /12 to szacunkowo około 2 godzin; to szacunek, nie pomiar. | slajd 3; `internal/targets`, `internal/scan/planner.go`; estymata przed startem w kreatorze |
| 5 | Jak nie zaszkodzić drukarkom i sterownikom? | Tylko GET i HEAD, najwyżej 2 żądania na sekundę na host, jedno połączenie HTTP na host, bez skryptów NSE, UDP tylko z listy niegroźnych zapytań. Do tego wykluczenia, dozwolone sieci, okna i stop awaryjny. | `docs/BEZPIECZENSTWO.md` §1 |
| 6 | Co nie jest skończone? | Pomiar precyzji i czułości na 70 hostach jest w toku (`docs/WYNIKI.md`), a liczby pakietów z testu e2e trzeba zmierzyć ponownie, bo przechwytywanie nie widziało surowego gniazda nmap. Zakresy IPv6 nie działają, logowanie nie ma drugiego składnika. | `docs/ZGODNOSC.md`, `deploy/INTEGRATION2_REPORT.md` |
| 7 | Jak liczycie pewność technologii? | Każdy dowód ma wagę 0–1, pewność to noisy-OR: `1 − Π(1 − wᵢ)`. Ekran usługi pokazuje liczbę razem z dowodami; poniżej 0,5 technologia nie tworzy zmian. | `docs/ALGORYTMY.md` §4; ekran usługi |
| 8 | Po ilu skanach host jest nieaktywny? | Bez stałej liczby: host jest zgłaszany, gdy prawdopodobieństwo istnienia spadnie poniżej 0,2. Serwer stały po 2 brakach, host losowy po medianie 5, stacja w weekend wcale; profil może też wymusić stałe N. | `docs/ALGORYTMY.md` §2.4–2.6 |
| 9 | A jeśli model myli się na początku? | Przez około dwa tygodnie model nie zna jeszcze godzin ciszy i może zgłosić stację nocą. Powrót hosta zamyka zgłoszenie zmianą `host_back`, a profil może ustawić stałą regułę braków. | `docs/ALGORYTMY.md` §2.8 |
| 10 | Skąd pewność, że sygnatura niczego nie zepsuje? | Walidator odrzuca metodę inną niż GET i HEAD, treść żądania, nagłówki, dane logowania, inny host i ścieżki zmieniające stan. W teście e2e sygnatura z POST została odrzucona z numerem wiersza. | `docs/SIGNATURES.md` §5; `e2e/full/transcript.txt` krok 14 |
| 11 | Co jest szyfrowane i gdzie jest klucz? | `pg_tde` szyfruje tabele i WAL, a AES-256-GCM dodatkowo klucz API DefectDojo, wartości ciasteczek, fragmenty treści i notatki. Klucz główny leży w wolumenie albo w zmiennej środowiska; rotacja to `czujka rotate-key`, zewnętrzny sejf to następny krok. | `docs/BEZPIECZENSTWO.md` §2 |
| 12 | Jak działają role? | Cztery role z treści zadania i własne role z 22 uprawnień; nikt nie nada uprawnienia, którego sam nie ma. Interfejs ukrywa przyciski, a serwer i tak odpowiada 403. | `internal/auth/roles.go`; test `TestRBACMatrixCSRFAndAudit`; drugie okno z rolą „Obserwator” |
| 13 | Jak wygląda integracja z DefectDojo? | Eksport jako Generic Findings Import i nmap XML, ze stałym kluczem znaleziska, więc drugi eksport aktualizuje, a nie dubluje. Status z DefectDojo może wrócić do Czujki. | `docs/INTEGRACJE.md` §4; ekran „Znaleziska” |
| 14 | Czy przyjmiecie wyniki z innych narzędzi? | Import nmap XML, JSON (4 kształty) i CSV z tabelą nazw kolumn; błędny wiersz nie przerywa importu. Sygnatury w stylu Wappalyzera i nuclei można przekonwertować. | `docs/INTEGRACJE.md` §1; `docs/SIGNATURES.md` §14 |
| 15 | Jak to utrzymamy po hackathonie? | Jedna binarka w Go, kilka małych zależności, testy w każdym pakiecie i test e2e całego produktu. Dokumentacja jest po polsku, a każdy próg algorytmu ma komentarz w kodzie. | `README.md`, `make test`, `e2e/full/README.md` |
| 16 | Czy działa bez internetu? | Tak. Jedyne źródło zewnętrzne, crt.sh, jest domyślnie wyłączone i włącza je tylko administrator. | `docs/INTEGRACJE.md` §3.1 |
| 17 | Jak baza zniesie długą historię? | Pełne sprawdzenie 11 reguł na 2000 hostach i 6000 usług trwa 99 ms, retro-hunt czyta obserwacje strumieniowo. Nie mierzyliśmy milionów obserwacji; to pierwszy pomiar do zrobienia w CBI. | `docs/REGULY.md` §8; `docs/SIGNATURES.md` §8 |
| 18 | Dlaczego Go? | Treść zadania sugeruje język o niskim zużyciu zasobów. Obraz ma 107 MB, a w czasie skanów kontener zużył najwyżej 99,9 MiB pamięci. | `e2e/full/transcript.txt` krok 18 |
| 19 | Czy możemy to sami wypróbować? | Tak: `https://czujka.dev` działa z laboratorium 70 hostów i zaplanowanym skanem; konto do odczytu dla jury jest w zgłoszeniu. Na serwerze 4 vCPU i 8 GB stos zbudował się i był zdrowy po 46 s. | `https://czujka.dev` |
