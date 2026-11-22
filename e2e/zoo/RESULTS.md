# Zoo: wyniki testu uogólnienia

Stan: 22.11.2026, gałąź `iwosmu/czujka-zoo`. Profil skanowania: kopia profilu domyślnego. Cel: `localhost`
wewnątrz maszyny zoo (docker:dind, 3 CPU). Opis harnessu: `README.md`. Pełne tabele per port: `results/`.
Dziennik: `transcript.txt`.

## Co mierzymy

Dla każdego opublikowanego portu z `truth.tsv`:

| Miara | Znaczenie |
| --- | --- |
| produkt | nazwa produktu zgodna z opisem prawdy (nmap albo technologia) |
| wersja | wersja zgodna co do składnika (`11.6` pasuje do `11.6.16`, nie do `11.60`); tylko gdzie prawda ją podaje |
| technologie | technologie wymienione w prawdzie |
| klasy | klasy z prawdy (install-page, login, admin-panel, database, …) |
| błędne etykiety | technologie i klasy, których prawda nie dopuszcza (fałszywe alarmy); platformy (PHP, nginx, jQuery, …) nie liczą się |

Komórka tabeli: `przed → **po** (nmap -sV)`. „nmap -sV” to zwykły `nmap -sS -sV` na tych samych portach.

## 1. Zbiór odłożony: 20 usług (23 porty), których Czujka nie widziała przy strojeniu

| Miara | przed | po | nmap -sV |
| --- | --- | --- | --- |
| produkt | 6 z 23 | **13 z 23** | 4 z 23 |
| wersja | 1/3 | **1/3** | 1/3 |
| klasy | 4/14 | **4/14** | 0/14 |
| błędne etykiety | 9 | **11** | – |

Błędnych etykiet przybyło dwie: samoopis nazwał OpenVSCode „Code” (prawda oczekuje „VS Code”), a sygnatura
otwartego rejestru Dockera dodała klasę `unauth-control-api` na Docker Registry UI, który przekazuje `/v2/`
do rejestru bez uwierzytelnienia.

Podział na kategorie (komórka: `przed → **po** (nmap -sV)`):

| kategoria | porty | produkt | wersja | technologie | klasy | błędne etykiety |
| --- | --- | --- | --- | --- | --- | --- |
| cms | 6 | 1 → **4** (0) | 0/0 → **0/0** (0/0) | 2/4 → **2/4** (0/4) | 1/4 → **1/4** (0/4) | 0 → **0** |
| database | 5 | 3 → **3** (3) | 1/3 → **1/3** (1/3) | 0/0 → **0/0** (0/0) | 1/1 → **1/1** (0/1) | 1 → **1** |
| monitoring | 1 | 0 → **1** (0) | 0/0 → **0/0** (0/0) | 0/0 → **0/0** (0/0) | 0/0 → **0/0** (0/0) | 0 → **0** |
| panel | 11 | 2 → **5** (1) | 0/0 → **0/0** (0/0) | 1/1 → **1/1** (0/1) | 2/9 → **2/9** (0/9) | 8 → **10** |
| **razem** | 23 | 6 → **13** (4) | 1/3 → **1/3** (1/3) | 3/5 → **3/5** (0/5) | 4/14 → **4/14** (0/14) | 9 → **11** |

Skąd siedem nowych produktów (6 → 13):

| Źródło | Usługi |
| --- | --- |
| import nuclei-templates | FreshRSS, Kanboard, Directus, Graphite |
| samoopis strony | Etherpad (`og:site_name`), File Browser (`apple-mobile-web-app-title`), Gotify (`application-name`) |

Błędne etykiety w zbiorze odłożonym (11), z oceną:

| Port | Etykieta | Ocena |
| --- | --- | --- |
| 8070 Docker Registry UI | Docker Registry, api, dev-tool, unauth-control-api | interfejs przekazuje `/v2/` do rejestru bez uwierzytelnienia: rejestr jest otwarty, prawda tego nie przewidziała (4) |
| 43000 AdGuard Home | admin-panel, login | kreator instalacji (tytuł „Setup AdGuard Home”), prawda: install-page; brakuje sygnatury instalatora AdGuard (2) |
| 8384 Syncthing | login | prawda: panel bez logowania; klasa z klasyfikatora |
| 13300 OpenVSCode | Code | samoopis: `apple-mobile-web-app-title` = „Code”; prawda oczekuje „VS Code” |
| 18083 EMQX | Cowboy | prawdziwy serwer HTTP pod EMQX, poza listą platform |
| 8055 Directus | admin-panel | prawda: login (aplikacja SPA, tytuł „Loading…”) |
| 28180 ZooKeeper (Jetty) | error-page | strona główna to 404 Jetty |

Na zbiorze odłożonym 9 z 11 błędnych etykiet to klasy i technologie, które dawał już silnik sprzed zmian.


## 2. Zbiór strojenia: 76 portów, 10 partii (na tych usługach stroiliśmy sygnatury)

„Przed” to obraz sprzed pracy nad zoo (`3a7e44b`), „po” to obraz z commita `047412b` (sygnatury ręczne,
import nuclei-templates, samoopis). Komórka: `przed → **po** (nmap -sV)`.

| kategoria | porty | produkt | wersja | technologie | klasy | błędne etykiety |
| --- | --- | --- | --- | --- | --- | --- |
| appserver | 6 | 4 → **6** (2) | 2/4 → **4/4** (2/4) | 1/1 → **1/1** (0/1) | 3/5 → **5/5** (0/5) | 2 → **0** |
| cms | 8 | 8 → **8** (0) | 6/8 → **7/8** (0/8) | 8/8 → **8/8** (0/8) | 1/7 → **7/7** (0/7) | 4 → **0** |
| database | 14 | 5 → **7** (3) | 4/11 → **4/11** (2/11) | 0/0 → **0/0** (0/0) | 5/13 → **5/13** (0/13) | 1 → **0** |
| monitoring | 8 | 7 → **8** (1) | 4/6 → **6/6** (1/6) | 1/1 → **1/1** (0/1) | 2/3 → **3/3** (0/3) | 0 → **0** |
| panel | 15 | 12 → **13** (1) | 4/6 → **6/6** (0/6) | 0/0 → **0/0** (0/0) | 8/12 → **11/12** (0/12) | 4 → **2** |
| proxy | 6 | 5 → **5** (0) | 1/5 → **1/5** (0/5) | 1/2 → **1/2** (0/2) | 2/5 → **3/5** (0/5) | 0 → **0** |
| remote | 13 | 10 → **10** (9) | 3/5 → **3/5** (3/5) | 0/0 → **0/0** (0/0) | 3/3 → **3/3** (0/3) | 0 → **0** |
| vuln | 6 | 2 → **5** (1) | 2/3 → **3/3** (0/3) | 0/0 → **0/0** (0/0) | 2/6 → **5/6** (0/6) | 0 → **0** |
| **razem** | 76 | 53 → **62** (17) | 26/48 → **34/48** (8/48) | 11/12 → **11/12** (0/12) | 26/54 → **42/54** (0/54) | 11 → **2** |

Po skanie usunęliśmy jeszcze jeden import (`nuclei-td-sonarqubes`: liczba mnoga naszej sygnatury SonarQube,
commit `b5f08e8`). Ponowne dopasowanie tych samych eksportów obecnym silnikiem (`rematch`) daje **1** błędną
etykietę: klasa `login` na Redis Commander. Strona zawiera ukryte okno logowania (`signinPassword`), używane tylko przy włączonym uwierzytelnieniu; domyślnie jest wyłączone, więc prawda nie przewiduje klasy `login`.


## 3. Co nie wystartowało; jeden skan zbioru odłożonego

- Wiki.js (23000, brak bazy danych) i Vaultwarden (8443) nie odpowiedziały w 480 s. Dlatego w zbiorze odłożonym
  Czujka i nmap znalazły 21 z 23 portów. YOURLS (38080) miał otwarty port bez odpowiedzi HTTP.
- W zbiorze strojenia Varnish (36081) nie odpowiedział w 480 s (75 z 76 portów).
- Zbiór odłożony skanowaliśmy raz, na końcu, obrazem `zoo-after`. Opis prawdy powstał przed skanem (commit
  `96793d9`). Po skanie nie zmieniliśmy niczego, co wpływa na te liczby. Kolumna „przed” to silnik i sygnatury
  z `3a7e44b` uruchomione na danych tego samego skanu (`rematch`).

## 4. Import otwartego korpusu

Źródło: projectdiscovery/nuclei-templates (MIT, licencję sprawdziliśmy w `LICENSE.md`), commit `1ad25895`.
Szczegóły i polecenie odtworzenia: `signatures/community/LICENSES.md`, `docs/SIGNATURES.md` (14.6).

| Etap | Liczba |
| --- | --- |
| szablony po rozdzieleniu nazwanych matcherów (`tech-detect`, `favicon-detect`, `fingerprinthub`) | 59403 |
| przekonwertowane (pasywne, tryb bezpieczny) | 4265 |
| zestaw domyślny (strona główna, przekierowania, ikona, ścieżki już pobierane: **zero nowych żądań**) | 1831 |
| opt-in, nie wbudowane (własna ścieżka albo FingerprintHub) | 2428 |
| pominięte: technologia znana bibliotece ręcznej (nasze wygrywają) | 650 |
| pominięte: biblioteki front-endu, CDN, czcionki, analityka | 95 |
| pominięte przez ocenę na zapisanych wynikach (laboratorium 70 hostów + zoo strojenia, 219 usług) | 6 |

Najwięcej odpada na etapie konwersji: 53 269 matcherów FingerprintHub używa wyrażeń DSL `regex(...)`, których
konwerter nie przyjmuje. Pełna lista powodów: `signatures/community/import-report.tsv`.

Laboratorium (70 hostów, ten sam eksport, `rematch`): precyzja technologii **0,990** z importem i bez niego
(100 trafień, 1 fałszywa), klasy 0,981, wersje technologii 53/54: import nie dodaje tam żadnej błędnej etykiety.

Koszt dopasowania: `BenchmarkMatch` kontra `BenchmarkMatchHandWritten` w jednym procesie: import dodaje 30–90 %
czasu na usługę. Pomiar był pod obciążeniem maszyny (load 40–60), więc czasy bezwzględne są zawyżone. Na
nieobciążonej maszynie sama biblioteka ręczna to 1,46 ms na usługę. Pierwsza wersja importu (z FingerprintHub,
3464 sygnatury) podwajała czas, dlatego FingerprintHub jest w opt-in.

## 5. Luki po stronie silnika (poza `internal/sig` i `signatures/`)

| Luka | Dowód | Najmniejsza poprawka |
| --- | --- | --- |
| Nazwa usługi zostaje zgadnięciem nmapa, choć GET dał poprawną odpowiedź HTTP | Keycloak 8080: `rtsp`, HTTP 200 „Keycloak Administration Console”; ClickHouse 8123: `rtsp`, HTTP 200 „Ok.” | `internal/scan/pipeline.go` `nameService`: zamieniać na `http`/`https` także `rtsp` i inne nazwy spoza listy HTTP, gdy etap HTTP dostał odpowiedź (dziś tylko `tcpwrapped`) |
| Usługa nierozpoznana przez nmapa traci baner | Mailpit SMTP 1025: nmap zapisał `r(NULL,"220 … Mailpit ESMTP Service ready")` w odcisku, w eksporcie `banner` jest pusty | `internal/probe`: brać ładunek sondy NULL z `servicefp` jako `Banner`; wtedy działa sygnatura `mailpit-smtp` |
| Wersji nie da się przekształcić | Roundcube: `"rcversion":10706` = 1.7.6 | opcja `format` w regule wersji DSL (np. `decimal-3x2`) |
| Soft-404 rozpoznaje tylko identyczny SHA | Metabase, SonarQube: `/wp-login.php`, `/manager/html`, `/_profiler/` dają 200 z tą samą aplikacją SPA (inny SHA przez ścieżkę w treści) | porównanie simhash albo długości treści z odpowiedzią na losową ścieżkę |
| Strona główna SPA bez formularza | SonarQube: logowanie rysuje JavaScript, klasa `login` niewykrywalna z HTML | brak tanim GET-em; zostawić |
| Manifest aplikacji nie jest pobierany | samoopis bierze tylko meta i tytuł | `internal/httpfp`: jeden GET `<link rel="manifest">` (ta sama domena) i pole `ManifestName` w `HTTPFingerprint` |

Zmiany w `internal/sig` (dozwolone): pole `source` w DSL, ładowanie `signatures/community/*.yaml`, samoopis
(`selfdesc.go`), usunięcie klasy `login` ze stron instalatora, test przepustowości odporny na obciążenie.
`internal/model`, `internal/scan`, `internal/probe` bez zmian.

## 6. Czego nie zrobiliśmy

- rapid7/recog (BSD-2): reguły banerów mają sens dopiero po poprawce banera (druga luka wyżej).
- Korpus Wappalyzera: wersje na licencji GPL pomijamy; `tech-detect.yaml` z nuclei-templates (MIT) już jest w imporcie.
- WebWolf (9090): ścieżka `/WebWolf/login` przegrywa w rankingu ośmiu ścieżek z innymi ścieżkami Tomcata.
