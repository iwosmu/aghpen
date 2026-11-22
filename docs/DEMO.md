# Demo Czujki

Scenariusz nagrania (do 2 minut), scenariusz pokazu na scenie (5 minut), przygotowanie stanowiska i pytania jury.
Wszystko działa lokalnie na laptopie: produkt, laboratorium i DefectDojo. Internet jest potrzebny tylko dzień wcześniej, do zbudowania obrazów.

| Część | Co zawiera |
| --- | --- |
| [1. Nagranie](#1-nagranie-około-2-minut) | 7 ujęć nagrywanych skryptem z prawdziwego interfejsu, napisy, tekst lektora |
| [2. Pokaz na scenie](#2-pokaz-na-scenie-5-minut) | kto mówi co; notatki do każdego slajdu; plan na awarię sieci |
| [3. Przygotowanie](#3-przygotowanie-stanowiska) | polecenia od zera do stanu startowego demo i reset |
| [4. Pytania jury](#4-pytania-jury) | 19 pytań z odpowiedziami i wskazaniem pliku albo ekranu |

Liczby w notatkach do slajdów pochodzą z repozytorium; źródło każdej jest w komentarzu w `docs/slides/czujka.src.html`.
Liczby pakietów pochodzą z `e2e/full/transcript.txt` (100 ze 100 kontroli). Przechwytywanie filtruje po adresie źródłowym Czujki, więc widzi też pakiety, które nmap wysyła przez surowe gniazdo.

## 1. Nagranie (około 2 minut)

Film nagrywa skrypt, nie człowiek: `docs/demo/record.mjs` (Playwright) prowadzi prawdziwy interfejs przez ujęcia poniżej, a Chromium zapisuje każdą klatkę ekranu. Potem ffmpeg tnie ujęcia, nakłada napisy i składa `docs/demo/czujka-demo.mp4` (1920 × 1080, 30 kl./s, bez dźwięku). Interfejs po polsku, motyw ciemny, tryb prezentacji (`?present=1`). Kursor jest widoczny, kliknięcia mają kółko, tekst wpisuje się w tempie czytania.

Ponowne nagranie to jedno polecenie (szczegóły w `docs/demo/README.md`):

```sh
CZ_URL=http://127.0.0.1:18640 CZ_PASSWORD=<hasło> docs/demo/record.sh
```

Skrypt nagrywa też plik napisów `docs/demo/czujka-demo.pl.srt` i tekst lektora z kodami czasu `docs/demo/lektor.txt`. Głos nagrywa się osobno, na gotowy film. Tekst lektora ma **136 słów**, około **59 s** przy 2,3 słowa na sekundę; resztę czasu zajmuje obraz.

| # | Ujęcie | Ekran i kliknięcia | Napis (do 6 słów) |
| --- | --- | --- | --- |
| 1 | Instalacja i kreator | Świeża instalacja: logowanie hasłem z logu, w kreatorze nowe hasło, nazwa sieci „Kampus AGH”, zakres `10.66.0.0/16`, podgląd liczby adresów, krok 3 z limitami. | Jedno polecenie, potem kreator |
| 2 | Skan /16 na żywo | „Skany” → „Uruchom skan” → profil „Laboratorium /16: pełny przegląd” → „Uruchom”. Ekran przebiegu: mapa 256 bloków /24 wypełnia się. Dwie minuty skanu pokazane w ×8, ze znakiem „×8” w rogu. | Skan całej sieci /16 |
| 3 | Zmiana między skanami | „Porównanie dwóch skanów” dla dwóch ostatnich pełnych przebiegów: nowe, zniknięte, zmienione. | Co się zmieniło między skanami |
| 4 | Host niestabilny | Szczegóły hosta `10.66.70.20`: mapa cieplna tygodnia, `p_alive`, potem „Plan ponownych sprawdzeń”. | Rytm hosta i ponowne sprawdzenia |
| 5 | Oś czasu | „Oś czasu”: strzałka w lewo przebieg po przebiegu, potem z powrotem. | Oś czasu |
| 6 | Reguła i sygnatura z przykładu | „Reguły ekspozycji”: reguła „Panel administracyjny poza siecią zarządzania” i jej naruszenia; potem usługa `10.66.1.10:80` → „Zaproponuj sygnaturę”. | Reguła i sygnatura z przykładu |
| 7 | Stop awaryjny | Przycisk „Stop awaryjny” w górnym pasku, potwierdzenie; trwający skan staje. Po nagraniu skrypt zwalnia stop i anuluje ten przebieg. | Stop awaryjny |
| 8 | Plansza końcowa | Ikona, „Czujka”, `czujka.dev`. | (bez napisu) |

Zasady montażu, które skrypt pilnuje sam: przyspieszony jest tylko fragment skanu i tylko z widocznym „×8”; pozostałe ujęcia idą w czasie rzeczywistym; żaden ekran nie jest makietą.

Pierwsza wersja (21.11.2026) powstała na lokalnym stosie `czpitch` z dwoma pełnymi skanami laboratorium i profilem co 2 minuty na hostach niestabilnych (`docs/demo/seed.sh`). Wersję końcową nagrywa się rano 22.11 na danych z całej nocy, tym samym poleceniem.

## 2. Pokaz na scenie (5 minut)

Role: **A** = Iwo Smura (mówi, prowadzi slajdy), **B** = Iwo Wojtakajtis (laptop z demo). Główną częścią pokazu jest film albo żywe demo według tych samych ujęć; slajdy tylko otwierają i zamykają.

| Czas | Kto | Ekran | Co się dzieje |
| --- | --- | --- | --- |
| 0:00–0:20 | A | slajd 1 | Pytanie. Nic więcej. |
| 0:20–2:30 | B, A mówi | film `czujka-demo.mp4` albo żywe demo według ujęć z rozdziału 1 | A czyta tekst lektora z `docs/demo/lektor.txt` (gdy film ma już nagrany głos, A milczy). |
| 2:30–4:30 | A | slajdy 2–10 | Po jednym zdaniu na slajd, według notatek poniżej. |
| 4:30–5:00 | A i B | slajd 10 | „Czujka. Działa na czujka.dev. Pytania?” B zostawia otwarty pulpit. |

### Notatki do slajdów

Na slajdzie jest tylko obraz i podpis. Szczegóły mówi prowadzący; źródło każdej liczby jest w komentarzu w `docs/slides/czujka.src.html` i w `docs/ZGODNOSC.md`.

| Slajd | Tytuł | Co powiedzieć |
| --- | --- | --- |
| 1 | Czujka | Adres milczy o trzeciej w nocy. Wyłączony na noc czy zniknął? Na to pytanie odpowiada Czujka. |
| 2 | Czujka uczy się, kiedy każdy host zwykle odpowiada. | Każdy host ma rytm 168 godzin tygodnia; model Bayesa liczy z niego p_alive. W teście stacja robocza nie odpowiada 16 razy w weekend i alarmu nie ma; dwa braki w poniedziałek w godzinach pracy zgłaszają ją jako nieaktywną. Serwer, który zawsze odpowiadał, jest zgłaszany po 2 brakach, host losowy po medianie 5 (`docs/ALGORYTMY.md` §2.6). |
| 3 | Cała sieć /16 w jednym przebiegu. | Planista dzieli sieć na bloki /24 i łączy puste w większe grupy, a rozmiar grupy idzie za zmierzonym tempem. W sieci lokalnej silnik najpierw robi jedno przeszukanie ARP, potem skanuje porty tylko na odpowiadających adresach. Czas przebiegu /16 podaje `docs/WYNIKI.md` (bramka laboratorium `e2e/lab-gate.sh`, limit 1000 pps). |
| 4 | Czujka rozpoznaje usługę i podaje powody oceny. | 398 sygnatur w YAML rozpoznaje panele, CMS, urządzenia, frameworki i środowiska testowe; pewność łączy wszystkie dowody. Ocena ciekawości 0–100 zawsze pokazuje swoje powody, tu siedem powodów dla WordPressa z formularzem logowania przez HTTP. |
| 5 | Gdy host milczy, Czujka sprawdza tylko ten adres. | Host, który zamilkł poza swoim rytmem, dostaje trzy krótkie sprawdzenia jednego adresu: po 10, 30 i 90 minutach, najwyżej 200 adresów na godzinę i tylko w oknie skanu. Gdy dalej milczy, Czujka zgłasza go jako zniknięty; gdy odpowie, wraca bez alarmu. |
| 6 | Oś czasu pokazuje sieć po dowolnym skanie. | Suwak cofa się przebieg po przebiegu i pokazuje hosty, usługi i znaleziska z tamtej chwili. Obok jest różnica do dziś: co zniknęło i co zmieniło produkt, wersję albo tytuł. |
| 7 | Reguła opisuje, czego w sieci być nie może. | Reguły w YAML mówią, czego w sieci być nie może albo co musi być; Czujka sprawdza je po każdym skanie i imporcie, bez wysyłania pakietów. Pakiet startowy ma 14 reguł; ta jedna znajduje w laboratorium 11 paneli administracyjnych poza siecią zarządzania. |
| 8 | Czujka wysyła tylko żądania GET i HEAD. | Skaner nigdy się nie loguje i nie wysyła ładunków; walidator odrzuca sygnaturę z inną metodą, treścią albo hasłem, a limity polityki zawsze wygrywają z profilem. Wywołanie stopu awaryjnego trwało 0,09 s; po stopie wyszło 5 pakietów IP, ostatni po 0,01 s, i żaden później niż po 1 s (jądro wysłało jeszcze 3 zapytania ARP). Na łączu najwięcej 641 pakietów nmapa na sekundę przy limicie 800; retro-hunt nie wysyła żadnego pakietu. |
| 9 | Czujka startuje jednym poleceniem w dwóch kontenerach. | Produkt to binarka Go z interfejsem i nmapem oraz PostgreSQL z pg_tde; uruchamia go `docker compose up -d` w katalogu głównym repozytorium. SecureCodeBox wymaga klastra Kubernetes i Helm, osobnego chartu na każdy skaner i magazynu S3. Kreator prowadzi od logowania do pierwszego skanu w 19,9 s. |
| 10 | Czujka działa publicznie na czujka.dev. | Pełny test produktu przechodzi 100 ze 100 kontroli przez REST API na prawdziwych usługach. Instancja publiczna czujka.dev wstała w 46 s na 4 vCPU; jury ma tam konto do odczytu (dane logowania w zgłoszeniu). Precyzja i czułość na 70 hostach: `docs/WYNIKI.md` (hosty 67 z 67, otwarte porty 154 ze 155). |

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

1. Przejdź kreator: zakres `10.66.0.0/16`, limit 1000 pps (domyślna polityka; tak mierzy bramka w `docs/WYNIKI.md`), harmonogram ręczny.
2. „Polityka bezpieczeństwa”: wykluczenia = adres Czujki z kroku 3, `10.66.0.1` (brama), `10.66.0.10` (skrzynka skanera); dozwolone sieci = `10.66.0.0/16`.
3. „Administracja” → „Użytkownicy”: dodaj `viewer@czujka.local` z rolą „Obserwator”.
4. Przebieg 1 na stanie `t0`. Gdy się skończy: `lab/scenario.sh t1` (9 s), potem przebieg 2.
5. Profil „Co 2 minuty: hosty niestabilne” na `10.66.70.0/24` z cronem `*/2 * * * *`, włączony przez co najmniej 30 minut przed pokazem (próbki dla `flapper`, `tod-office`, `tod-night`).
6. „Ustawienia” → „Ponowne sprawdzenia”: włączone (domyślnie). „Integracje” → DefectDojo: adres `http://host.docker.internal:18080` i token z `lab/defectdojo/README.md`, „Sprawdź połączenie” (ta droga działa: `web/REPORT-LAB.md` §11).
7. Sygnatura `lab-infokiosk` **nie** może być zainstalowana: ujęcie 8 pokazuje, że Czujka sama ją proponuje.

Podgląd hostów niestabilnych na żywo: `go run ./e2e/watchunstable`.

### 3.3 Co demo bierze z `lab/story.sh`

Skrypt `lab/story.sh` wprowadza w laboratorium zaplanowaną serię prawdziwych zmian przez kilka godzin, z której powstaje prawdziwa historia (na `czujka.dev` w nocy z 21 na 22.11). Demo potrzebuje od niego:

| Potrzeba | Ujęcie | Dlaczego |
| --- | --- | --- |
| skanów w co najmniej 8 różnych godzinach | 5 | Model nazywa rytm i nadaje `expected-offline` dopiero od 8 obserwacji (`MinObsForExpected`); mapa cieplna z jednej godziny jest pusta |
| hosta, który milknie poza swoim rytmem | 5 | plan ponownych sprawdzeń i zmiana `host_gone` po krokach `[10, 30, 90]` min (host z mniej niż 8 obserwacjami: `[1, 3, 10]`) |
| przejścia `t0` → `t1` między dwoma skanami | 4, 6, 7 | zmiany, dwa punkty na suwaku osi czasu, `shadow-adminer` dla reguły |
| kiosków `kiosk-1` i `kiosk-2` w obu stanach | 8 | „Zaproponuj sygnaturę” potrzebuje przykładu i podobnej instancji |
| stanu końcowego zapisanego w wolumenie bazy | wszystkie | pokaz nie może czekać godzinami: archiwum `czujka backup` (szyfrowane) przed wyjazdem, na miejscu `czujka restore` |

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
| 4 | Co przy 10 razy większej sieci? | Liczenie adresów nie rozwija listy, plan idzie w blokach /24, zapis wsadowy. Czas rośnie liniowo z liczbą adresów przy stałym limicie pps: /12 to 16 razy czas /16 z `docs/WYNIKI.md`. To szacunek, nie pomiar; laboratorium /16 ma 70 żywych hostów. | slajd 3; `internal/targets`, `internal/scan/planner.go`; estymata przed startem w kreatorze |
| 5 | Jak nie zaszkodzić drukarkom i sterownikom? | Tylko GET i HEAD, najwyżej 2 żądania na sekundę na host, jedno połączenie HTTP na host, bez skryptów NSE, UDP tylko z listy niegroźnych zapytań. Do tego wykluczenia, dozwolone sieci, okna i stop awaryjny. | `docs/BEZPIECZENSTWO.md` §1 |
| 6 | Co nie jest skończone? | Zakresy CIDR IPv6 nie działają, nazwy domen dają tylko IPv4, UDP nie ma wykrywania wersji, API nie ma tokenów, logowanie nie ma drugiego składnika. Pomiar skali dotyczy /16 z 70 hostami. | `docs/ZGODNOSC.md` („Najsłabsze miejsca”), README („Ograniczenia”) |
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
| 18 | Dlaczego Go? | Treść zadania sugeruje język o niskim zużyciu zasobów. Obraz ma 107 MB. Pamięć kontenera w skanie /16: 200–400 MiB, chwilowo do 1,2 GiB; przy 10 000 żywych hostów najwyżej 908 MiB. | `docs/WYNIKI.md` |
| 19 | Czy możemy to sami wypróbować? | Tak: `https://czujka.dev` działa z laboratorium 70 hostów i zaplanowanym skanem; konto do odczytu dla jury jest w zgłoszeniu. Na serwerze 4 vCPU i 8 GB stos zbudował się i był zdrowy po 46 s. | `https://czujka.dev` |
