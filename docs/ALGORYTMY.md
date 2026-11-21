# Algorytmy Czujki

Dokument opisuje algorytmy analizy: model dostępności hosta, wykrywanie zmian, ocenę ciekawości i grupowanie.
Wszystkie liczby w tabelach pochodzą z testów w repozytorium. Każdą można odtworzyć poleceniem podanym przy tabeli.

Kod: pakiet `internal/analyze`. Funkcje są czyste: nie czytają bazy, zegara ani sieci.

| Temat | Plik | Funkcja |
| --- | --- | --- |
| Model dostępności | `stability.go` | `Profile.Add`, `Assess`, `DownAfterMisses` |
| Opis rytmu hosta | `pattern.go` | `Pattern` |
| Zmiany między skanami | `diff.go` | `Diff` |
| Ocena ciekawości | `interest.go` | `Interest`, tabela `InterestWeights` |
| Grupowanie | `group.go` | `GroupKey`, `AssignGroupKeys` |
| Obserwacje | `findings.go` | `DeriveFindings`, `FindingKey` |
| Raport z przebiegu | `internal/report` | `HTML`, `Markdown` |

## 1. Trzy pytania z opisu zadania

| Pytanie | Odpowiedź w skrócie | Szczegóły |
| --- | --- | --- |
| Jak raportować zmianę dla hosta, który odpowiada tylko o niektórych porach? | Czujka uczy się rytmu hosta w siatce 168 godzin tygodnia. Brak odpowiedzi w porze, w której host zwykle milczy, dostaje status `expected-offline` i flagę `expected`. Taka zmiana nie trafia do liczników ani na listę zmian; raport pokazuje je wszystkie w jednym wierszu. | rozdz. 2 i 3 |
| Jak określić pewność identyfikacji technologii? | Każdy dowód ma wagę 0..1. Pewność to noisy-OR dowodów: `1 − Π(1 − wᵢ)`. Interfejs pokazuje liczbę razem z listą dowodów. Technologie o pewności poniżej 0,5 nie tworzą zmian. | rozdz. 4 |
| Po ilu skanach zgłosić host jako nieaktywny? | Nie ma stałej liczby. Model liczy prawdopodobieństwo, że host nadal istnieje (`p_alive`). Host jest zgłaszany, gdy `p_alive` spadnie poniżej 0,2. Stabilny serwer: po 2 brakach. Host losowy 50%: po około 5. Stacja robocza wyłączona na weekend: wcale. | rozdz. 2.6 |

## 2. Model dostępności hosta

### 2.1 Dane

Dla każdego hosta Czujka przechowuje:

- histogram 168 kubełków: dzień tygodnia × godzina, w strefie czasowej instalacji (domyślnie Europe/Warsaw). Każdy kubełek ma dwa liczniki: `up` (odpowiedział) i `down` (nie odpowiedział);
- ostatnie 200 obserwacji (czas, wynik).

Jedna obserwacja to jeden przebieg skanu, który sondował ten adres. Silnik skanu ponawia sondę znanego hosta przed uznaniem braku odpowiedzi, więc pojedyncza zgubiona paczka nie tworzy obserwacji `down`.

### 2.2 Częstość odpowiedzi w danej godzinie

Jeden skan dziennie wypełnia jeden kubełek na tydzień. Sam kubełek wie więc za mało przez wiele tygodni. Model łączy cztery poziomy i każdy drobniejszy poziom ściąga do grubszego:

```text
global      = (U + 1) / (N + 2)                          rozkład a priori Beta(1, 1)
hod[h]      = (U_h + m·global)  / (N_h + m)              godzina doby; sąsiednie godziny liczone z wagą 0,5
hdt[k][h]   = (U_kh + m·hod[h]) / (N_kh + m)             godzina doby × typ dnia k (roboczy albo weekend)
how[i]      = (U_i + c·hdt[k(i)][i mod 24]) / (N_i + c)  godzina tygodnia (kubełek i)
```

`U` to liczba odpowiedzi, `N` liczba obserwacji na danym poziomie, `m = 2`, `c = 4`.
Wynik `how[i]` to szacowana częstość odpowiedzi hosta w kubełku `i`.

Poziom „typ dnia" jest potrzebny, bo stacja robocza milczy w sobotę w południe, chociaż w dni robocze o tej porze odpowiada.
Silniejsze ściąganie na najdrobniejszym poziomie (`c = 4`) chroni przed fałszywym rytmem: host losowy przypadkiem wypełnia pojedyncze kubełki samymi odpowiedziami.

### 2.3 Prawdopodobieństwo, że host nadal istnieje

Gdy host odpowiada, `p_alive = 1`. Gdy nie odpowiada, model stosuje wzór Bayesa do serii braków od ostatniej odpowiedzi.

```text
p₀            = 0,5 + 0,3 · n_up / (n_up + 3)        wiara przy pierwszym braku
ε             = max(0,10 ; 1 / (n + 2))              szansa, że żywy host przegapi skan
P(brak | żyje) = 1 − how[i] · (1 − ε)
p ← p · P(brak | żyje) / (p · P(brak | żyje) + (1 − p))      po każdym braku
```

- `n_up` to liczba odpowiedzi, `n` liczba obserwacji przed serią braków.
- Host, który nie istnieje, nie odpowiada nigdy: `P(brak | nie żyje) = 1`.
- `p₀` rośnie z historią: 0,58 po jednej obserwacji, 0,77 po 30. Nigdy nie przekracza 0,80, bo brak odpowiedzi przeszedł już ponowienia w silniku.
- `ε = 0,10` gwarantuje, że jeden brak nigdy nie zgłasza hosta.
- **Seria braków jest oceniana histogramem sprzed tej serii.** Bez tego martwy host sam nauczyłby model, że „zwykle milczy".

### 2.4 Status

| Warunek | Status | Znaczenie |
| --- | --- | --- |
| odpowiedział w ostatnim skanie | `up` | aktywny |
| profil ma regułę `down_after_misses = N > 0` i host nie odpowiedział N razy z rzędu | `down` | zgłoszony jako nieaktywny z reguły profilu (zmiana `host_gone`) |
| reguła profilu wyłączona (`0`) i `p_alive < 0,2` | `down` | zgłoszony jako nieaktywny przez model (zmiana `host_gone`) |
| każdy brak z serii wypadł w godzinie o częstości odpowiedzi poniżej 0,25, a host ma co najmniej 8 obserwacji | `expected-offline` | przerwa zgodna z rytmem |
| pozostałe przypadki | `unstable` | nie odpowiada, ale jeszcze nie jest zgłoszony |
| host nigdy nie odpowiedział | `unknown` | nie ma czego zgłaszać |

**Reguła profilu.** Pole `retry.down_after_misses` profilu skanu (`model.RetryOpts.DownAfterMisses`) ustala, kiedy zgłosić nieaktywność:

| Wartość | Działanie |
| --- | --- |
| `0` (domyślnie) | decyduje model: `p_alive < 0,2` |
| `N > 0` | host jest `down` po N brakach z rzędu i nie wcześniej, niezależnie od `p_alive` i od rytmu |

Funkcje: `AssessWith(profil, strefa, AssessOptions{DownAfterMisses: N})`, `OptionsFor(profil skanu)`, `DownAfterMissesWith`. `Assess` to `AssessWith` z regułą `0`. Przy `N = 1` test dwóch przebiegów od razu daje `host_gone` i `service_gone`.

**Jedna obserwacja na przebieg.** Silnik może zgłosić ten sam host dwa razy w jednym przebiegu: część adresów skanowana ponownie po wznowieniu. `Profile.Add` łączy drugą obserwację tego samego przebiegu z pierwszą. `AssessWith` woła `NormalizeProfile`, które robi to samo z danymi z bazy i odejmuje nadmiarowy wpis z histogramu. Host jest „odpowiedział", gdy odpowiedział w którejkolwiek z tych obserwacji. `MergeHostResults` łączy wyniki silnika o tym samym adresie przed zapisem, a `ObservationKey(run, ip)` daje klucz, po którym zapis może odrzucić drugą obserwację.

`DownAfterMisses` odpowiada na pytanie analityka „ile jeszcze braków z rzędu, w zwykłych porach skanu, zanim host zostanie zgłoszony". Funkcja symuluje kolejne braki w odstępach równych medianie odstępów między ostatnimi skanami.

### 2.5 Opis rytmu

`Pattern` zamienia histogram na krótki tekst dla analityka. Godzina jest „włączona" przy częstości ≥ 0,6 i „wyłączona" przy ≤ 0,2. Tekst nazywa rytm tylko wtedy, gdy co najmniej 80% zaobserwowanych godzin jest jednoznacznych.

| Dane | Tekst |
| --- | --- |
| mniej niż 12 obserwacji | (pusty) |
| odpowiada w ≥ 95% skanów | `odpowiada stale (100% skanów)` |
| rytm tygodniowy | `zwykle aktywny pn–pt 08–16`, `zwykle aktywny sb–nd` |
| rytm dobowy, także przez północ | `zwykle aktywny codziennie 22–06` |
| brak rytmu | `odpowiada w ok. 50% skanów, bez wzorca dobowego` |

### 2.6 Zmierzone scenariusze

Polecenie: `go test ./internal/analyze -run 'TestStabilityScenarios|TestRandomHostToleranceDistribution' -v`

**Stabilny serwer.** 56 obserwacji co 6 godzin, zawsze odpowiadał.

| Brak nr | Pora | Częstość w tej godzinie | `p_alive` | Status |
| --- | --- | --- | --- | --- |
| 1 | pn 00:00 | 1,00 | 0,268 | `unstable` |
| 2 | pn 06:00 | 1,00 | 0,035 | `down` |

Zgłoszony po **2** brakach.

**Stacja robocza.** 4 tygodnie, skan co 4 godziny, host włączony w dni robocze w godzinach pracy. Wykryty rytm: `zwykle aktywny pn–pt 10–15`. Odpowiada w 24% skanów.

Test A: host wyłączony od piątku wieczorem do poniedziałku rano (16 braków z rzędu).

| Brak nr | Pora | Częstość w tej godzinie | `p_alive` | Status |
| --- | --- | --- | --- | --- |
| 1 | pt 18:00 | 0,00 | 0,779 | `expected-offline` |
| 2–15 | weekend | poniżej 0,25 | między 0,779 a 0,699 | `expected-offline` |
| 16 | pn 06:00 | 0,00 | 0,699 | `expected-offline` |

16 braków przez weekend **nie zgłasza hosta**.

Test B: host nie wraca w poniedziałek.

| Brak nr | Pora | Częstość w tej godzinie | `p_alive` | Status |
| --- | --- | --- | --- | --- |
| 1 | pn 02:00 | 0,00 | 0,699 | `expected-offline` |
| 2 | pn 06:00 | 0,00 | 0,699 | `expected-offline` |
| 3 | pn 10:00 | 0,99 | 0,205 | `unstable` |
| 4 | pn 14:00 | 0,99 | 0,028 | `down` |

Nocne braki prawie nie zmieniają `p_alive`. Host zgłaszają dopiero **2 braki w godzinach, w których zwykle pracuje**.

**Host losowy.** 120 obserwacji co 6 godzin, odpowiada w połowie skanów bez rytmu. Opis: `odpowiada w ok. 50% skanów, bez wzorca dobowego`.

| Brak nr | 1 | 2 | 3 | 4 | 5 |
| --- | --- | --- | --- | --- | --- |
| `p_alive` | 0,659 | 0,481 | 0,401 | 0,207 | 0,074 |
| Status | `unstable` | `unstable` | `unstable` | `unstable` | `down` |

Tolerancja zależy od godzin, w których wypadły braki. Dla 300 losowych historii:

| Braków do zgłoszenia | 3 | 4 | 5 | 6 | 7 |
| --- | --- | --- | --- | --- | --- |
| Liczba historii | 18 | 84 | 121 | 62 | 15 |

Mediana: **5** braków. Minimum 3, maksimum 7.

**Nowy host widziany raz.** Skan raz na dobę.

| Brak nr | 1 | 2 | 3 |
| --- | --- | --- | --- |
| `p_alive` | 0,369 | 0,202 | 0,098 |
| Status | `unstable` | `unstable` | `down` |

Zgłoszony po **3** brakach. Po drugim braku `p_alive` wynosi 0,202, tuż nad progiem.

**Host, który wrócił.** Po zgłoszeniu jako nieaktywny odpowiada ponownie: status `up`, `p_alive = 1,000`, zmiana `host_back`. Wcześniejsze braki zostają w histogramie (stabilność 0,95), więc model pamięta przerwę.

### 2.7 Stałe

| Stała | Wartość | Znaczenie |
| --- | --- | --- |
| `BetaPriorA`, `BetaPriorB` | 1, 1 | rozkład a priori częstości odpowiedzi |
| `ShrinkStrength` | 2 | siła ściągania poziomów (w pseudo-obserwacjach) |
| `CellShrinkStrength` | 4 | to samo dla kubełka godziny tygodnia |
| `NeighbourWeight` | 0,5 | waga sąsiednich godzin |
| `TransientMissRate` | 0,10 | szansa, że żywy host przegapi skan |
| `PriorBase`, `PriorGain`, `PriorHalfLife` | 0,5; 0,3; 3 | wzór na `p₀` |
| `DownThreshold` | 0,2 | próg zgłoszenia |
| `ExpectedOfflineUpRate` | 0,25 | poniżej tej częstości brak jest „zgodny z rytmem" |
| `MinObsForExpected` | 8 | młodszy profil nie może tłumaczyć braków |
| `FlakyStability` | 0,8 | poniżej tej stabilności host jest „nieregularny" |

Wszystkie stałe są w `stability.go` i `diff.go`, każda z komentarzem. Zmiana progu `DownThreshold` przesuwa kompromis: wyższy próg zgłasza szybciej i częściej się myli.

### 2.8 Ograniczenia

- **Faza uczenia.** Stacja robocza z historią krótszą niż około dwa tygodnie nie ma jeszcze nauczonych godzin ciszy. Model może ją zgłosić podczas pierwszych nocy. Po powrocie hosta zmiana `host_back` zamyka zgłoszenie.
- Rytm jest tygodniowy. Model nie zna świąt ani przerw semestralnych.
- Zmiana czasu (lato/zima) przesuwa godzinę lokalną skanu o jeden kubełek. Sąsiednie godziny z wagą 0,5 łagodzą ten efekt.
- Model ocenia host, nie pojedynczy port. Usługi hosta, który milczy, mają stan „nieznany".

### 2.9 Ponowne sondowanie sterowane modelem

Pakiet `internal/reprobe` dopytuje hosty, o których model wie za mało. Mechanizm jest włączony od pierwszego startu. Trasy: [`docs/API.md`](API.md) (`/reprobe/plan`, `/settings/reprobe`).

- **Potwierdzenie.** Host dostał `host_missing` (status `unstable`, wcześniej odpowiadał). Czujka sprawdza go ponownie 10, 30 i 90 minut po pierwszym braku odpowiedzi (`backoff_minutes`). Seria starsza niż ostatni krok plus 12 godzin nie jest już potwierdzana.
- **Szybkie potwierdzenie młodego hosta.** Host z mniej niż 8 obserwacjami (`MinObsForExpected`, rytm jeszcze nieznany) jest sprawdzany 1, 3 i 10 minut po pierwszym braku (`reprobe.YoungBackoffMinutes`). Dla hosta widzianego raz model zgłasza nieaktywność po drugim braku z rzędu (`p_alive` 0,36, potem 0,19 < 0,2). Młody profil nie zna jeszcze pory dnia, więc model daje mu jedną częstość odpowiedzi dla każdej godziny: tę, którą miałaby godzina ze wszystkimi jego obserwacjami (`youngRates`). Werdykt nie zależy więc od zegara. Wcześniej brak w następnej godzinie po ostatniej odpowiedzi (przejście pełnej godziny, północ, weekend, zmiana czasu) dawał 0,41, potem 0,26 i host nigdy nie dostawał potwierdzenia (około 1 na 6 przypadków, zależnie od minuty). Testy: `TestYoungHostVerdictAtEveryTime` (`internal/analyze`: co 5 minut przez 8 dni, obie zmiany czasu, przełom roku; host młody, zwykle aktywny i zwykle wyłączony o tej porze) i `TestVanishedHostAtClockBoundaries` (`internal/wire`, prawdziwa baza). Pierwsza sonda potwierdzająca daje więc `host_gone` i `service_gone` po około 1–2 minutach od drugiego skanu: krok wynosi 1 minutę od pierwszego braku, a wykonawca (`reprobe.Executor`) sprawdza plan raz na minutę, potem sonda sama trwa kilkanaście sekund (zmierzone w maszynie jury: 105–110 s od skanu do `host_gone`). Test: `TestVanishedHostInTwoScans` (`internal/wire`, prawdziwa baza).
- **Prawdopodobnie aktywny.** Host niestabilny jest sprawdzany 5 minut po początku najbliższej godziny, w której model daje częstość odpowiedzi co najmniej `likely_up_rate` (domyślnie 0,6). Warunek: co najmniej 8 obserwacji i prawdziwa odpowiedź w tym samym typie dnia (dzień roboczy albo weekend, godzina ±1).
- **Bezpieczeństwo.** Sondy działają tylko w oknach skanowania profilu (`sched.NextAllowed`) i pod polityką bezpieczeństwa: wykluczenia, limity pakietów i HTTP, wyłącznik awaryjny. Budżet to 200 adresów na godzinę (`budget_per_hour`), liczony razem dla wszystkich sond z ostatniej godziny. Nadmiar przechodzi na następną godzinę. Sonda sprawdza najwyżej 32 znane porty hosta.
- Wykonawca startuje co minutę. Zbiera należne sondy w jeden przebieg na profil (`trigger = reprobe`) i nie startuje nowego, dopóki poprzedni trwa.
- Operator wyłącza mechanizm w `PUT /settings/reprobe` (`enabled: false`).

### 2.10 Zegar laboratoryjny

Kubełki modelu mają domyślnie szerokość 1 h i okres 1 tygodnia (168 kubełków). Do pokazu w laboratorium zegar można skrócić zmiennymi środowiskowymi procesu `czujka`:

| Zmienna | Domyślnie | Przykład w laboratorium |
| --- | --- | --- |
| `CZUJKA_AVAIL_BUCKET` | `1h` | `3m` |
| `CZUJKA_AVAIL_PERIOD` | `168h` | `30m` |

Reguły: szerokość co najmniej 1 s, okres jest całkowitą wielokrotnością szerokości, najwyżej 168 kubełków. Przy innym zegarze model liczy kubełek jako `(czas Unix mod okres) / szerokość`, kurczy częstość kubełka prosto do częstości globalnej (bez poziomu dnia tygodnia) i opisuje rytm jako „zegar laboratoryjny”. To ustawienie służy tylko do pokazu. W produkcji zostaw wartości domyślne.

### 2.11 Skan portów: limit czasu, porty nieznane, kontrola poprawności

nmap skanuje hosty jednego procesu równolegle, w tempie przydzielonym grupie (limit pakietów minus rezerwa HTTP, podzielony między równoległe grupy). Jeden host może więc potrzebować całego czasu procesu. Limit czasu na host (`--host-timeout`) rośnie z pracą: `max(5 min, hosty × porty × 3 / tempo)`. Pomiar na serwerze publicznym przed zmianą: 8 równoległych grup po 105 pps, grupa z około 35 hostami i 1000 portów potrzebowała ponad 330 s; stały limit 5 minut odciął wszystkie hosty tej grupy. Przebieg skończył się bez błędu z 8 usługami zamiast 107, a porównanie zgłosiło 100 usług, które „zniknęły".

- nmap z `-Pn` w sieci Ethernet zapisuje host po limicie czasu jako `timedout="true"` z powodem `arp-response`. Czujka czyta ten atrybut. Taki host dostaje drugi skan portów.
- Host, którego skan i tak się nie skończył, trafia do wyniku z `ports_unknown` (powód `ports-unknown`). Baza nie oznacza jego usług jako zniknięte, a porównanie liczy je jako nieosiągalne (`services_unreachable`).
- Przebieg dostaje ostrzeżenie (`stats.warnings`, widoczne w API i na stronie przebiegu), gdy port scan nie skończył się dla jakiegoś hosta albo gdy na skan portów odpowiedziała mniej niż połowa hostów znalezionych przez wykrywanie (co najmniej 8 hostów).
- Host z co najmniej 10 otwartymi portami z listy profilu dostaje dodatkowy skan portów 1–10000 (najwyżej 4 hosty na grupę). Host z wieloma usługami zwykle nasłuchuje też na nietypowych portach. W laboratorium host z 64 portami pokazał 33 porty z listy domyślnej i ukrywał 31 portów o randze 1045–7379 w tabeli częstości nmap (albo bez rangi), wszystkie poniżej 10000.

Każda zmiana silnika przechodzi przez `e2e/lab-gate.sh` (pełny /16 laboratorium przez API produktu, progi czułości, kontrola pakietów w każdej sekundzie, tablica sąsiadów). Wyniki: `docs/WYNIKI.md`.

### 2.12 Mały zakres: szybka ścieżka, pełny zakres portów, wyniki częściowe

**Szybka ścieżka.** Grupa z co najwyżej 32 otwartymi portami TCP (wszystkie hosty razem) nie czeka na wykrywanie wersji całej grupy. Dla każdego portu działa osobny proces `nmap -sV` (najwyżej 8 naraz), a obok niego etap HTTP. Wykrywanie wersji każdego portu trwa do końca (limit 3 min jak na zwykłej ścieżce, liczony od startu procesu tego portu, nie od wejścia do kolejki; Prometheus potrzebuje 66 s, bo nmap rozpoznaje go dopiero późną sondą FourOhFourRequest), także gdy port już odpowiedział na GET. Dzięki temu wynik końcowy ma produkt i wersję z nmap i nie zależy od tego, który etap skończył się pierwszy: dwa skany niezmienionej usługi dają ten sam zestaw technologii. Wcześniejsza wersja przerywała `-sV` po odpowiedzi HTTP i traciła 17 z 32 wersji usług w laboratorium. Gdy żadna sonda nmap nie pasuje, nmap podaje nazwę z tablicy portów (`method="table"`, np. `ibm-db2` dla 50000); jeśli port odpowiedział na GET, nazwę daje odpowiedź HTTP. Wersję brokera AMQP (port 5672 albo port nazwany `amqp` w tablicy portów nmap) czytamy z ramki `Connection.Start` po 8-bajtowym nagłówku protokołu, gdy nmap nie nazwał portu w ciągu 3 s: nmap dochodzi do swojej sondy AMQP dopiero po 22 s (szczegóły w `BEZPIECZENSTWO.md`). Pomiar na jednym hoście z 7 usługami (nginx, Apache, RabbitMQ AMQP i panel, Gitea, PostgreSQL, OpenSSH): `nmap -sV` na porcie Gitea (3000) trwa 42 s przy każdej intensywności 0–9, bo nmap najpierw wysyła sondy przypisane do portu 3000, a Gitea na nie nie odpowiada (5 s oczekiwania na każdą). Kolektor HTTP rozpoznaje Gitea w mniej niż 1 s. Etap HTTP pomija porty protokołów, które nigdy nie mówią HTTP (ssh, postgresql, amqp, mysql, redis ...), chyba że mają tunel TLS. Druga runda ścieżek sygnatur nie pobiera ponownie strony głównej.

**Pełny zakres portów.** Zakres do 256 adresów z profilem z listą rankingową (`top-N`) albo z `1-65535` dostaje drugi przebieg: reszta zakresu 1-65535 dla żywych hostów, najwyżej 16 w całym przebiegu. Skan reszty zaczyna się zaraz po skanie portów z listy, obok opisu tych portów, z 90 % szybkości grupy. Pozostałe 10 % zostaje dla wykrywania wersji. Jawna lista portów (`80,443,8080`) jest skanowana tak, jak ją zapisano. Oba przebiegi respektują `allowed_ports` i `denied_ports` polityki. Gdy reszta zakresu nie skończy się (limit czasu nmap), host dostaje `ports_unknown`: usługi spoza listy nie znikają. Gdy aktywnych hostów jest więcej niż 16, grupa, która nie mieści się w limicie, dostaje tylko porty z profilu. Przebieg `full_range` podaje wtedy `hosts_skipped`, a przebieg dostaje notatkę (`RunStats.notes`, np. „pełny zakres portów (1-65535) objął 16 z 23 aktywnych hostów; pozostałe: porty z profilu").

**Pokrycie portów hosta.** Wynik końcowy każdego hosta niesie pokrycie (`HostResult.Coverage`): porty z listy profilu, plus reszta zakresu albo porty 1-10000 (host gęsty), gdy ten przebieg skończył się dla tego hosta, plus porty UDP. Baza oznacza jako zniknętą tylko usługę na porcie z pokrycia, a analiza zgłasza dokładnie te usługi jako `service_gone`. Usługa na porcie spoza pokrycia (pełny zakres pominięty: ponad 16 hostów, stop, limit czasu) zachowuje stan. Przebieg dostaje kopię jej ostatniej obserwacji z flagą `carried`: widok przebiegu dalej ją pokazuje, następny przebieg porównuje się z nią, nie powstaje żadna zmiana, a seria czasów odpowiedzi pomija kopie. Zmiana stanu w bazie zawsze ma swój wiersz zmiany. Widok usług przebiegu (`run_id`) i maszyna czasu oznaczają taką usługę polem `carried`; eksport przebiegu też (JSON `carried`, kolumna CSV `carried`, w nmap XML `reason="czujka-not-scanned"`), a import ją pomija. Licznik `services_open` przebiegu liczy tylko usługi widziane w tym przebiegu; raport podaje obok liczbę usług nieskanowanych i oznacza ich wiersze „nie skanowana w tym przebiegu”. `services_open` maszyny czasu to stan inwentarza po przebiegu, z usługami przeniesionymi. Przykład z szablonu organizatorów: port 8787 spoza listy znajduje tylko pełny zakres; po `quickstart change` kolejny skan profilem domyślnym zgłasza „Usługa …:8787 zniknęła”, po `quickstart up` „wróciła”. Test: `TestFullRangeOnlyPortGoneAndBack` (`internal/wire`, prawdziwa baza).

**Wpis ręczny i import.** Wpis ręczny i plik importu (nmap XML, masscan, CSV, JSON, import ustaleń) mówią tylko o tym, co zawierają: pokrycie hosta to dokładnie porty z wpisu, także porty podane jako zamknięte. Pozostałe usługi hosta nie są porównywane (żadnego fałszywego „zniknęła”), a werdykt o czasie odpowiedzi wymaga czasu zmierzonego w tym przebiegu. Plik nie zgłasza braku hostów, których nie wymienia. Ustalenia na portach spoza pliku zostają otwarte; wpis ręczny nie zamyka żadnego ustalenia. Test: `TestManualEntryAndImportStateOnlyWhatTheyContain` (`internal/wire`, prawdziwa baza: host z 30 usługami i wpis jednej).

**Wyniki częściowe.** Na szybkiej ścieżce opisane usługi trafiają do bazy co 2 s, zanim przebieg się skończy. Wynik częściowy ma `ports_unknown`, więc baza nie oznacza żadnej innej usługi hosta jako zniknętej. Liczniki `services_open` i `http_services` rosną od razu; wynik końcowy zastępuje w nich częściowy. Porównanie z poprzednim przebiegiem, ustalenia i reguły powstają raz, na końcu przebiegu.

**`RunStats.passes`.** Tablica jest obecna tylko wtedy, gdy przebieg ma więcej niż jeden przebieg portów: `top_ports` i `full_range` (mały zakres) albo `top_ports` i `dense` (/16). `ports_total` i `ports_done` liczą pary host-port. W trakcie skanu `ports_done` wynika z przypiętej szybkości nmap (`--min-rate` = `--max-rate`); po skanie jest dokładne. Szacunek przebiegu (`full_range_max_hosts`) liczy pakiety drugiego przebiegu.

Pomiar na hoście „jury" (jeden adres w sieci laboratorium, 7 usług, limit 1000 pps, `e2e/small-bench.sh`, wersja 6f39557):

| profil | przed: czas przebiegu | po: pierwsza usługa | po: czas przebiegu | porty |
| --- | --- | --- | --- | --- |
| 7 portów z nazwy | 68 s | 3,5 s | 43,4 s | 7 |
| top-1000 | 63 s | 4,0 s | 222 s | 1-65535 (dwa przebiegi) |
| profil domyślny | — | 4,6 s | 137 s | 1-65535 (dwa przebiegi) |

Pierwsza usługa pojawia się po 3,5–4,6 s (wyniki częściowe). Czas do końca przebiegu wyznacza `nmap -sV`: „7 portów" to Gitea na porcie 3000 (42 s), „top-1000" to port 25672 (dystrybucja Erlanga), na którym sam `nmap -sV` pracuje 135 s i kończy wynikiem „unknown". Wynik końcowy czeka na nmap tak samo jak zwykłe `nmap -sV`; w zamian ma wszystkie wersje usług (Gitea „Golang net/http server", panel RabbitMQ „Cowboy httpd", AMQP RabbitMQ 4.3.8, epmd). Szczytowy ruch: 101, 853 i 866 pakietów/s przy limicie 1000, 0 sekund ponad limit.

## 3. Wykrywanie zmian

`Diff(prev, cur)` porównuje dwa obrazy sieci i zwraca listę zmian oraz podsumowanie. Gdy nie ma poprzedniego przebiegu, nie ma zmian: pierwszy skan to punkt odniesienia.

### 3.1 Reguły tłumienia szumu

| Reguła | Powód |
| --- | --- |
| Usługa hosta, który nie odpowiedział, jest „nieznana", nie „zniknęła". Liczy się ją w `services_unreachable`. Wyjątek: gdy host zostaje zgłoszony jako nieaktywny (`host_gone`), jego otwarte usługi dostają `service_gone`. | Milczący host nic nie mówi o swoich portach. |
| Port poza zakresem nowszego skanu nie „znika". | Profil „top-100" nie widzi portu 8443 z profilu pełnego. |
| Nagłówki zmienne są pomijane (`Date`, `ETag`, `Set-Cookie`, identyfikatory żądań i śledzenia; lista w `volatileHeaders`). | Zmieniają się przy każdym żądaniu. |
| Ciasteczka są porównywane po nazwie i flagach, bez wartości. Liczby i ciągi szesnastkowe w nazwie są maskowane. | Wartość sesji jest zawsze inna. |
| W przekierowaniach parametry zapytania są pomijane. | Zawierają tokeny i znaczniki czasu. |
| Brak wartości w nowszym skanie nie jest zmianą. | Chwilowy błąd HTTP nie kasuje wiedzy. |
| Technologie o pewności poniżej 0,5 nie są porównywane. | Słaby domysł pojawia się i znika. |
| Treść strony: zmiana dopiero przy odległości simhash ≥ 16 bitów z 64. Bez simhash: inny skrót i długość różna o ≥ 30%. | Licznik odwiedzin nie jest zmianą treści. |
| Zmiana, którą tłumaczy rytm hosta, dostaje `expected = true`. | Patrz 3.3. |

### 3.2 Tabela wag

| Rodzaj zmiany | Waga | Reguła |
| --- | --- | --- |
| `host_new` | niska | nowy adres odpowiada |
| `host_gone` | średnia | model zgłosił host jako nieaktywny; informacja, gdy oczekiwana |
| `host_back` | niska | zgłoszony host znów odpowiada; informacja, gdy oczekiwana |
| `host_gone` (z regułą profilu) | średnia | N braków z rzędu przy `down_after_misses = N`; otwarte usługi dostają `service_gone` |
| `host_missing` | średnia | host odpowiedział w poprzednim porównywalnym przebiegu, teraz nie odpowiada, model nie zgłosił go jako `down`, a rytm nie tłumaczy braku; usługi idą do `services_unreachable` |
| `host_unstable` | niska | host bez odpowiedzi w poprzednim przebiegu (na przykład po przerwie zgodnej z rytmem) przestał odpowiadać; informacja i `expected`, gdy host jest znany jako nieregularny, także po odpowiedzi w poprzednim przebiegu |
| `service_new` | średnia | klasa lub port wrażliwy (panel administracyjny, baza danych, zdalny dostęp, narzędzie deweloperskie, IoT); w innym przypadku niska |
| `service_gone` | niska | |
| `service_changed` | średnia | zmienił się produkt; niska, gdy tylko wersja |
| `tech_new` | niska | |
| `tech_gone` | informacja | |
| `tech_version` | niska | |
| `title_changed` | informacja | |
| `status_changed` | niska | |
| `redirect_changed` | niska | |
| `cert_changed` | niska | średnia, gdy nowy certyfikat jest przeterminowany albo samopodpisany |
| `headers_changed` | informacja | niska, gdy usunięto nagłówek bezpieczeństwa |
| `cookies_changed` | informacja | niska, gdy ciasteczko straciło `Secure` albo `HttpOnly` |
| `content_changed` | informacja | |
| `class_changed` | średnia | usługa stała się panelem, logowaniem, bazą, zdalnym dostępem albo narzędziem deweloperskim; w innym przypadku informacja |

Czujka nie nadaje wagi „wysoka" automatycznie. Wykrywa obecność cech, nie potwierdza podatności. Wagę wysoką może nadać analityk.

### 3.3 Host, który odpowiada tylko o niektórych porach

To odpowiedź na pierwsze pytanie z opisu zadania.

1. Brak odpowiedzi w porze, w której host zwykle milczy, daje status `expected-offline`, nie `unstable`.
2. Przejście do `expected-offline` i powrót z niego tworzą zmiany z flagą `expected = true` i wagą „informacja".
3. Host znany jako nieregularny (stabilność poniżej 0,8 przy co najmniej 8 obserwacjach) też dostaje `expected = true`, gdy znów przegapi skan.
4. Zmiany oczekiwane nie wchodzą do liczników `hosts_gone`, `hosts_back`, `hosts_unstable`. Są liczone osobno w `by_kind["expected"]`.
5. Raport z przebiegu pokazuje je w jednym wierszu: „9 zmian oczekiwanych … Model dostępności je wyjaśnia, więc nie są liczone powyżej".
6. Zdanie opisujące zmianę zawiera rytm hosta, na przykład „zwykle aktywny pn–pt 08–16".
7. Gdy ten sam host przegapi skan w swoich godzinach pracy, zmiana jest zwykła i widoczna.

Przykład: w raporcie `docs/samples/raport-przyklad.html` osiem stacji roboczych wyłączonych w nocy z piątku na sobotę zajmuje jeden wiersz, a serwer, który przegapił jeden skan, ma własny.

### 3.4 Dwa przebiegi: host zatrzymany między nimi

Jury robi co najmniej dwa przebiegi i może zatrzymać kontener między nimi. Host musi być widoczny po drugim przebiegu.

| Profil | Przebieg 1 | Przebieg 2 | Zmiany po przebiegu 2 | Liczniki |
| --- | --- | --- | --- | --- |
| `down_after_misses = 0` (model) | host i 3 usługi | brak odpowiedzi | `host_missing` (średnia) + 3 × `service_unreachable` (niska); po sondzie potwierdzającej (1 min) `host_gone` + 3 × `service_gone` | `hosts_missing 1`, `services_unreachable 3` |
| `down_after_misses = 1` | host i 3 usługi | brak odpowiedzi | `host_gone` + 3 × `service_gone` | `hosts_gone 1`, `services_gone 3` |
| `down_after_misses = 2` | host i 3 usługi | brak odpowiedzi | `host_missing` + 3 × `service_unreachable`; `host_gone` po sondzie potwierdzającej | `hosts_missing 1` |

Zdania z testu `TestTwoPassMissingHost` (`go test ./internal/analyze -run TwoPass -v`):

```text
jedna wcześniejsza obserwacja, model:
  Host 10.66.3.17 nie odpowiada (niepotwierdzone): w poprzednim przebiegu odpowiadał i miał 3 otwarte usługi: 22/tcp ssh OpenSSH, 80/tcp http nginx, 8080/tcp http Jenkins; model: p_alive 0,36, zgłoszenie nieaktywności po kolejnym braku
40 obserwacji, zawsze odpowiadał, model:
  … model: p_alive 0,26, zgłoszenie nieaktywności po kolejnym braku
reguła N = 1:
  Host 10.66.3.17 zgłoszony jako nieaktywny: brak odpowiedzi w 1 przebiegu z rzędu (reguła profilu: zgłoszenie po 1 braku)
reguła N = 2:
  … model: p_alive 0,36, zgłoszenie nieaktywności po kolejnym braku, reguła profilu: 2 braki z rzędu
```

Bez reguły model zgłasza nieaktywność po drugim braku z rzędu: jeden brak nigdy nie wystarcza (`ε = 0,10`, rozdz. 2.3). Liczby `p_alive` i „po kolejnym braku" trafiają do zdania, gdy wywołujący wypełni migawkę przez `HostSnapshot.SetAssessment`. Brak, który tłumaczy rytm hosta, zostaje zmianą oczekiwaną (`host_gone` z `expected = true`), nie `host_missing`.

Każda otwarta usługa takiego hosta dostaje zmianę `service_unreachable` („Usługa … nie odpowiada (niepotwierdzone)”): drugi skan pokazuje, co zniknęło razem z hostem, zanim sonda potwierdzi stan. Raport z przebiegu mówi to w zdaniu wstępnym: „Nie odpowiada (niepotwierdzone): 1 host, z nimi 2 usługi. Ponowne sondowanie potwierdzi, czy wróciły, czy zniknęły.” Wiersze stoją w sekcji „Co zniknęło”.

## 4. Pewność identyfikacji technologii

Pewność liczy silnik sygnatur (pakiet `internal/sig`, kontrakt w `docs/ARCHITECTURE.md` §4.4). Pakiet analizy z niej korzysta.

- Każdy dopasowany element sygnatury ma wagę 0..1. Regex w nagłówku: 0,6. Dokładny skrót favicony: 0,9. Ogólne słowo w treści: 0,3.
- Pewność sygnatury to noisy-OR dopasowanych elementów: `1 − Π(1 − wᵢ)`. Nagłówek (0,6) i favicona (0,9) razem dają `1 − 0,4 · 0,1 = 0,96`.
- Pewność technologii to noisy-OR po wszystkich sygnaturach i po wyniku nmap, które ją wskazują. Pole `conf` z nmap (0–10) jest dzielone przez 10.
- Interfejs pokazuje pewność razem z listą dowodów („dlaczego tak sądzimy"): miejsce dopasowania i dopasowany fragment.

Jak analiza używa pewności:

| Miejsce | Reguła |
| --- | --- |
| Zmiany | technologia poniżej 0,5 nie tworzy `tech_new`, `tech_gone`, `tech_version` |
| Grupowanie | technologia poniżej 0,5 nie wchodzi do klucza grupy |
| Ocena ciekawości | sygnatura dodaje `round(waga_sygnatury × pewność)` punktów, najwyżej 40 |
| Obserwacje i raport | każda obserwacja niesie dowody; raport drukuje do 3 na usługę |

## 5. Ocena ciekawości (0–100)

Ocena odpowiada na pytanie „na co analityk powinien spojrzeć najpierw". Jest sumą punktów z jednej tabeli. Do 70 ocena równa się sumie. Powyżej 70 suma jest ściskana w stronę 100: `ocena = 70 + 30 · (1 − e^(−(suma − 70)/50))`, najwyżej 99 (`CompressInterest`). Każdy składnik trafia do listy powodów (`interest_why`), więc analityk widzi, skąd wzięła się liczba.

Dlaczego krzywa, a nie obcięcie: w laboratorium pięć najciekawszych usług miało ocenę 100 (strona wydziału, blog WordPress, Tomcat, phpMyAdmin, Adminer), więc ranking nic nie mówił. Z krzywą suma 100 daje 84, suma 140 daje 92, suma 200 daje 97. Większa suma zawsze daje wyższą ocenę.

| Kod | Punkty | Powód |
| --- | --- | --- |
| `admin-panel` | 30 | Panel administracyjny dostępny z sieci |
| `login-plain-http` | 25 | Strona logowania bez szyfrowania (HTTP) |
| `database` | 25 | Baza danych dostępna z sieci |
| `debug-page` | 25 | Strona diagnostyczna lub tryb debug |
| `remote-access-plaintext` | 25 | Zdalny dostęp bez szyfrowania (telnet, rlogin) |
| `staging` | 20 | Środowisko testowe lub staging |
| `iot` | 20 | Urządzenie IoT |
| `dev-tool` | 20 | Narzędzie deweloperskie (CI, repozytorium, monitoring) |
| `remote-desktop` | 20 | Zdalny pulpit (RDP, VNC) |
| `directory-listing` | 15 | Listing katalogu |
| `expired-cert` | 15 | Przeterminowany certyfikat TLS |
| `new-exposure` | 15 | Nowa ekspozycja od ostatniego skanu |
| `login` | 10 | Strona logowania |
| `self-signed-cert` | 10 | Samopodpisany certyfikat TLS |
| `rare-tech` | 10 | Rzadka technologia w tej sieci |
| `outdated` | 10 | Przestarzała wersja oprogramowania |
| `remote-access` | 5 | Usługa zdalnego dostępu (SSH) |
| `default-page` | 5 | Strona domyślna serwera |
| `cert-expiring` | 5 | Certyfikat TLS wkrótce wygaśnie |
| `hostname-mismatch` | 5 | Certyfikat TLS nie pasuje do nazwy hosta |
| `missing-security-headers` | 5 | Strona logowania bez nagłówków bezpieczeństwa |
| `sensitive-header` | 5 | Nagłówek ujawnia szczegóły oprogramowania |
| `interesting-cookie` | 5 | Ciasteczko sesyjne bez flag bezpieczeństwa |
| `scope-criticality` | 5 | Zakres o podwyższonej krytyczności |

Reguły dodatkowe:

- Dopasowana sygnatura dodaje `round(waga × pewność)` punktów, najwyżej 40 za jedną sygnaturę i najwyżej 40 za wszystkie sygnatury usługi razem (`MaxSignatureTotal`).
- **Słabe sygnały razem dają najwyżej 20 punktów** (`WeakSignalsCap`): `sensitive-header`, `missing-security-headers`, `interesting-cookie`, `default-page`, `cert-expiring`, `hostname-mismatch`, `remote-access` (SSH) oraz sygnatury kategorii nagłówek i ciasteczko. Cztery słabe sygnały nie robią z usługi celu numer jeden.
- Sygnatura nagłówka albo ciasteczka, której klasy są już policzone przez powód klasy (na przykład „formularz logowania po nieszyfrowanym HTTP" przy powodzie `login-plain-http`), nie dodaje punktów drugi raz.
- Krytyczność zakresu 4 dodaje 5 punktów, krytyczność 5 dodaje 10.
- „Rzadka technologia": grupa najwyżej 2 usług w sieci z co najmniej 20 usługami.
- „Certyfikat wkrótce wygaśnie": mniej niż 30 dni.
- „Przestarzała wersja" zależy od tagów sygnatur (`outdated`, `eol`). Analiza sama nie ocenia numerów wersji.
- Ocena hosta to najwyższa ocena jego usług, plus 5 punktów dla nowego hosta, najwyżej 100.

Przykład z laboratorium: strona logowania DefectDojo pod `http://127.0.0.1:18080` (nginx, Django, ciasteczko `csrftoken`, bez CSP, tylko HTTP). Test `TestDojoLoginCalibration` na prawdziwym wyniku `fpprobe`:

| | Przed kalibracją | Po kalibracji |
| --- | --- | --- |
| ocena usługi | 100 = sygnatura DefectDojo 40 + sygnatura „logowanie po HTTP" 40 + `login-plain-http` 25 + brak CSP 11 + ciasteczko 4, obcięte do 100 | 75 = suma 80 (sygnatura DefectDojo 40 + `login-plain-http` 25 + słabe sygnały 15: brak CSP 11, ciasteczko 4) po krzywej |
| obserwacje | 5, każda z oceną 100: logowanie po HTTP, nagłówek „logowanie po HTTP", nagłówek „brak CSP", ciasteczko `csrftoken`, ciasteczko „sesja frameworka" | 3: logowanie po HTTP **50** (z dowodami obu źródeł), nagłówki HTTP **11**, ciasteczka **10** |

Przykład z raportu przykładowego: nowa usługa Jenkins na porcie 8080 ma sumę 89 punktów (ocena 79 po krzywej) = panel administracyjny (30) + narzędzie deweloperskie (20) + sygnatura Jenkins (19) + nowa ekspozycja (15) + nagłówek ujawniający wersję (5).

## 6. Grupowanie podobnych usług

Sto drukarek tego samego modelu to jedna rzecz do obejrzenia, nie sto.

Klucz grupy usługi WWW to skrót z pięciu składników:

| Składnik | Co usuwa różnice |
| --- | --- |
| skrót favicony | |
| szablon tytułu | adresy IP, nazwy hostów, identyfikatory i liczby zamienione na znaczniki |
| pierwsza cyfra statusu HTTP | |
| posortowane nazwy technologii (pewność ≥ 0,5) | |
| zbiór nazw nagłówków | bez nagłówków zmiennych, bez wartości |

Do tego dochodzi podobieństwo treści (simhash, 64 bity):

- `GroupKey` dla jednej usługi używa 8 najstarszych bitów simhash jako kubełka.
- `AssignGroupKeys` dla całego zbioru łączy strony o tym samym kluczu bazowym, których simhash różni się najwyżej o 6 bitów. Robi to także przez granicę kubełka (struktura union-find). Klucz grupy pochodzi od najmniejszego simhash w grupie, więc jest stabilny między skanami.

Usługi inne niż WWW grupuje protokół, produkt i wersja.

Rozmiar grupy zasila regułę „rzadka technologia" w ocenie ciekawości.

## 7. Obserwacje

`DeriveFindings` zamienia usługi hosta na obserwacje. Każda ma stabilny klucz:

```text
<typ>/<ip>/<protokół>-<port>[/<temat>]      np. admin-panel/10.66.3.17/tcp-8080/jenkins
```

Ponowny skan tej samej rzeczy daje ten sam klucz. Baza aktualizuje więc obserwację zamiast tworzyć nową. Ten sam klucz jest identyfikatorem `unique_id_from_tool` w DefectDojo (patrz `docs/INTEGRACJE.md`).

**Ocena ciekawości obserwacji** wynika z jej typu i dowodów, nie z oceny usługi (`FindingBaseInterest`, `findingBuilder.interest`). Dzięki temu góra listy to to, co analityk powinien otworzyć najpierw.

| Typ obserwacji | Ocena | Uwagi |
| --- | --- | --- |
| `admin-panel` | 75 | |
| `debug-page` | 75 | |
| `database-exposed` | 70 | tylko protokół bazy; narzędzie WWW do baz (phpMyAdmin, Adminer, pgAdmin) dostaje `admin-panel` |
| `remote-access-exposed` | 20 | telnet, rlogin: 70; RDP, VNC: 50; SSH: 20 |
| `expired-cert` | 40 | na stronie logowania: 70 |
| `dev-tool` | 60 | |
| `directory-listing` | 55 | |
| `login-plain-http` | 50 | |
| `staging` | 45 | |
| `iot-device` | 45 | |
| `new-exposure` | 40 | |
| `signature` | `round(waga × pewność)` w przedziale 10–60 | |
| `self-signed-cert` | 25 | na stronie logowania: 40 |
| `hostname-mismatch`, `cert-expiring` | 20 | |
| `interesting-header` | 15 | z sygnatury: `round(waga × pewność)` w przedziale 5–25 |
| `default-page` | 15 | |
| `interesting-cookie` | 10 | ciasteczko sesyjne bez flag: 25; wartość JWT: 20; z sygnatury: 5–25 |

Modyfikatory: krytyczność zakresu 4 dodaje 5, krytyczność 5 dodaje 10 (`FindingInput.ScopeCriticality`); usługa nowa od poprzedniego przebiegu dodaje 10. Ocena usługi rozstrzyga remisy w obrębie typu: dodaje 0–4 punkty (jeden punkt na każde 10 ponad 50). W laboratorium 15 obserwacji miało wcześniej tę samą ocenę 75; teraz panel routera po zwykłym HTTP (usługa 96) stoi nad stroną logowania WordPressa (usługa 80). Wynik jest obcięty do 100. Obserwacje z reguł ekspozycji mają najwyżej 69, więc stoją pod obserwacją silnika o tym samym fakcie (`docs/REGULY.md`).

**Bliskie duplikaty na jednej usłudze** łączą się w jedną obserwację z kilkoma wierszami dowodów:

- wszystkie obserwacje nagłówków jednej usługi → jedna `interesting-header` (klucz bez tematu, tytuł „Nagłówki HTTP: …");
- wszystkie obserwacje ciasteczek jednej usługi → jedna `interesting-cookie` („Ciasteczka: …");
- sygnatura nagłówka albo ciasteczka z klasą, która już dała obserwację (na przykład „formularz logowania po nieszyfrowanym HTTP" i `login-plain-http`), dopisuje swoje dowody do tej obserwacji.

Połączona obserwacja ma najwyższą ocenę z części. Uwaga przy aktualizacji: obserwacje nagłówków i ciasteczek z sygnatur miały dotąd klucze z tematem (`interesting-header/<ip>/tcp-<port>/<sygnatura>`). Po zmianie powstaje jedna obserwacja z kluczem bez tematu, a stare, nietknięte przez analityka, analiza po przebiegu oznacza jako `resolved`.

Obserwacje są informacyjne. Waga domyślna to „informacja". Wagę „niska" mają: logowanie przez nieszyfrowane HTTP, baza danych dostępna z sieci, strona diagnostyczna, listing katalogu, przeterminowany certyfikat oraz telnet i rlogin. Wartości ciasteczek nigdy nie trafiają do dowodów.

## 8. Raport z przebiegu

`internal/report` buduje raport jednego przebiegu jako jeden plik HTML (bez zewnętrznych zasobów, drukuje się na A4) i jako Markdown. Oba formaty powstają z tego samego dokumentu pośredniego.

Kolejność: liczby nagłówkowe, co nowego, co zniknęło, co się zmieniło, zmiany oczekiwane w jednym wierszu, najważniejsze obserwacje z dowodami, najciekawsze usługi, hosty niestabilne z rytmem, parametry skanu i ruch faktycznie wysłany.

Przykład: `docs/samples/raport-przyklad.html`, `docs/samples/raport-przyklad.md`, zrzut pierwszej strony `docs/samples/raport-przyklad-strona1.png`.
Dane wejściowe przykładu to mała sieć zdefiniowana w teście. Zmiany, statusy hostów, obserwacje i oceny w przykładzie policzyły prawdziwe funkcje `analyze.Diff`, `analyze.Assess`, `analyze.DeriveFindings` i `analyze.Interest`. Statystyki ruchu w przykładzie są wpisane ręcznie.
Test `TestSampleFilesAreCurrent` pilnuje, żeby pliki przykładu były dokładnym wynikiem kodu. Polecenie `go test ./internal/report -update` zapisuje je od nowa.
