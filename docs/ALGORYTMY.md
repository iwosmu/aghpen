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
| `p_alive < 0,2` | `down` | zgłoszony jako nieaktywny (zmiana `host_gone`) |
| każdy brak z serii wypadł w godzinie o częstości odpowiedzi poniżej 0,25, a host ma co najmniej 8 obserwacji | `expected-offline` | przerwa zgodna z rytmem |
| pozostałe przypadki | `unstable` | nie odpowiada, ale jeszcze nie jest zgłoszony |
| host nigdy nie odpowiedział | `unknown` | nie ma czego zgłaszać |

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

## 3. Wykrywanie zmian

`Diff(prev, cur)` porównuje dwa obrazy sieci i zwraca listę zmian oraz podsumowanie. Gdy nie ma poprzedniego przebiegu, nie ma zmian: pierwszy skan to punkt odniesienia.

### 3.1 Reguły tłumienia szumu

| Reguła | Powód |
| --- | --- |
| Usługa hosta, który nie odpowiedział, jest „nieznana", nie „zniknęła". | Milczący host nic nie mówi o swoich portach. |
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
| `host_unstable` | niska | host przestał odpowiadać, jeszcze nie zgłoszony; informacja i `expected`, gdy host jest znany jako nieregularny |
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

Ocena odpowiada na pytanie „na co analityk powinien spojrzeć najpierw". Jest sumą punktów z jednej tabeli, obciętą do 100. Każdy składnik trafia do listy powodów (`interest_why`), więc analityk widzi, skąd wzięła się liczba.

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

- Dopasowana sygnatura dodaje `round(waga × pewność)` punktów, najwyżej 40 za jedną sygnaturę.
- Krytyczność zakresu 4 dodaje 5 punktów, krytyczność 5 dodaje 10.
- „Rzadka technologia": grupa najwyżej 2 usług w sieci z co najmniej 20 usługami.
- „Certyfikat wkrótce wygaśnie": mniej niż 30 dni.
- „Przestarzała wersja" zależy od tagów sygnatur (`outdated`, `eol`). Analiza sama nie ocenia numerów wersji.
- Ocena hosta to najwyższa ocena jego usług, plus 5 punktów dla nowego hosta, najwyżej 100.

Przykład z raportu przykładowego: nowa usługa Jenkins na porcie 8080 ma 89 punktów = panel administracyjny (30) + narzędzie deweloperskie (20) + sygnatura Jenkins (19) + nowa ekspozycja (15) + nagłówek ujawniający wersję (5).

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

Obserwacje są informacyjne. Waga domyślna to „informacja". Wagę „niska" mają: logowanie przez nieszyfrowane HTTP, baza danych dostępna z sieci, strona diagnostyczna, listing katalogu, przeterminowany certyfikat oraz telnet i rlogin. Wartości ciasteczek nigdy nie trafiają do dowodów.

## 8. Raport z przebiegu

`internal/report` buduje raport jednego przebiegu jako jeden plik HTML (bez zewnętrznych zasobów, drukuje się na A4) i jako Markdown. Oba formaty powstają z tego samego dokumentu pośredniego.

Kolejność: liczby nagłówkowe, co nowego, co zniknęło, co się zmieniło, zmiany oczekiwane w jednym wierszu, najważniejsze obserwacje z dowodami, najciekawsze usługi, hosty niestabilne z rytmem, parametry skanu i ruch faktycznie wysłany.

Przykład: `docs/samples/raport-przyklad.html`, `docs/samples/raport-przyklad.md`, zrzut pierwszej strony `docs/samples/raport-przyklad-strona1.png`.
Dane wejściowe przykładu to mała sieć zdefiniowana w teście. Zmiany, statusy hostów, obserwacje i oceny w przykładzie policzyły prawdziwe funkcje `analyze.Diff`, `analyze.Assess`, `analyze.DeriveFindings` i `analyze.Interest`. Statystyki ruchu w przykładzie są wpisane ręcznie.
Test `TestSampleFilesAreCurrent` pilnuje, żeby pliki przykładu były dokładnym wynikiem kodu. Polecenie `go test ./internal/report -update` zapisuje je od nowa.
