# Dokumentacja techniczna Czujki

Spis dokumentów. Czujka to narzędzie do cyklicznego, bezpiecznego skanowania discovery dużych sieci, zgłoszone do zadania „Attack Surface Intelligence” (CBI AGH, HackNation 2026).

Zacznij od `README.md` (czym jest Czujka, uruchomienie), `docs/ZGODNOSC.md` (każde wymaganie z dowodem) i prezentacji `docs/slides/czujka.pdf`.

| Dokument | Język | Dla kogo |
| --- | --- | --- |
| [`README.md`](../README.md) | polski | każdy: czym jest Czujka, szybki start |
| [`docs/ZGODNOSC.md`](ZGODNOSC.md) | polski | jury: wymagania zadania, stan i dowody |
| [`docs/slides/czujka.pdf`](slides/czujka.pdf) | polski | jury: prezentacja, 10 slajdów |
| [`docs/DEMO.md`](DEMO.md) | polski | jury, zespół: lista ujęć, pokaz, notatki do slajdów, przygotowanie, pytania |
| [`docs/demo/README.md`](demo/README.md) | polski | zespół: nagrywanie filmu demo jednym poleceniem |
| `docs/WYNIKI.md` (w przygotowaniu) | polski | jury: pomiary na laboratorium 70 hostów |
| [`docs/WDROZENIE.md`](WDROZENIE.md) | polski | administrator |
| [`docs/BEZPIECZENSTWO.md`](BEZPIECZENSTWO.md) | polski | jury, administrator, zespół bezpieczeństwa |
| [`docs/ALGORYTMY.md`](ALGORYTMY.md) | polski | jury, opiekunowie kodu |
| [`docs/SIGNATURES.md`](SIGNATURES.md) | polski | autorzy sygnatur |
| [`docs/REGULY.md`](REGULY.md) | polski | analitycy: reguły ekspozycji, sygnatura z przykładu |
| [`docs/INTEGRACJE.md`](INTEGRACJE.md) | polski | administrator, integrator |
| [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) | angielski | programiści |
| [`docs/API.md`](API.md) | angielski | programiści, integratorzy |
| [`docs/PROBLEM_DEFINITION.md`](PROBLEM_DEFINITION.md) | polski | treść zadania |

## Dokumenty główne

**[ZGODNOSC.md](ZGODNOSC.md): zgodność z treścią zadania.** Każde wymaganie z rozdziału 2, akapity o sygnaturach i oknach, zakres minimalny i dodatkowy, wymagania formalne, 12 punktów weryfikacji i 6 kryteriów oceny. Dla każdej pozycji: co robi Czujka, gdzie to zobaczyć (ekran albo polecenie), dowód i status: udowodnione, gotowe, częściowe albo brak. Na górze trzy najsłabsze miejsca. To jedyny dokument, który mówi o stanie na konkretny dzień.

**[slides/](slides/): prezentacja.** Dziesięć slajdów po polsku, PDF i jeden plik HTML. Każdy slajd to jeden obraz z podpisem: tytuł do 8 słów i najwyżej 12 słów poza nim; skrypt budujący PDF pilnuje tego limitu i wypisuje liczbę słów każdego slajdu (`docs/slides/README.md`). Źródło każdej liczby jest w komentarzu HTML.

**[DEMO.md](DEMO.md): demo.** Lista ujęć filmu (około 2 minut), pokaz na scenie (5 minut) z notatkami do każdego slajdu i planem na awarię sieci, polecenia przygotowania stanowiska i resetu, pytania jury z odpowiedziami.

**[demo/](demo/README.md): film.** `record.mjs` nagrywa film z prawdziwego interfejsu (Playwright, każda klatka z Chromium, cięcie w ffmpeg), z napisami i tekstem lektora z kodami czasu; `record.sh` robi to jednym poleceniem.

**WYNIKI.md: wyniki (w przygotowaniu).** Precyzja i czułość wykrycia hostów, usług i technologii na laboratorium 70 hostów, czas skanu /16. Pisze zespół dokładności.

**[WDROZENIE.md](WDROZENIE.md): wdrożenie.** Wymagania, start przez `docker compose`, wszystkie zmienne `CZUJKA_*`, pierwsze logowanie, konta, kopia zapasowa i odtwarzanie, rotacja klucza, aktualizacja, dołączanie skanera do sieci, rozwiązywanie problemów. Polecenia zostały wykonane; miejsca niesprawdzone są oznaczone.

**[BEZPIECZENSTWO.md](BEZPIECZENSTWO.md): bezpieczeństwo.** Część pierwsza: co skaner wysyła, a czego nigdy; limity tempa i miejsce ich egzekwowania; polityka bezpieczeństwa; awaryjne zatrzymanie; tryb bezpieczny sygnatur; trzymanie się zakresu. Część druga: `pg_tde`, szyfrowanie pól z listą kolumn, klucz główny i rotacja, hasła, sesje, CSRF, dziennik audytu, tabela uprawnień czterech ról. Zawiera listę znanych ograniczeń.

**[ALGORYTMY.md](ALGORYTMY.md): algorytmy.** Odpowiedzi na trzy pytania z zadania: jak raportować zmianę, jak określić pewność identyfikacji technologii, po jakim czasie uznać host za nieaktywny. Model dostępności hosta ze wzorami i zmierzonymi scenariuszami, reguły szumu w porównaniu przebiegów, tabela wag zmian, tabela punktów oceny ciekawości, grupowanie usług, klucze obserwacji, raport z przebiegu.

**Funkcje czasu.** Model rytmu hosta: `ALGORYTMY.md` §2. Wehikuł czasu (`/timeline`) i ponowne sprawdzenia (`/reprobe/plan`, `/settings/reprobe`): trasy i definicje w `API.md`, kod w `internal/timeline` i `internal/reprobe`.

**[SIGNATURES.md](SIGNATURES.md): sygnatury.** Język sygnatur w YAML: pola, 14 typów reguł, dopasowania, forma skrócona. Tryb bezpieczny walidatora z przykładami odrzuceń. Liczenie pewności. Silnik dopasowań, „miękkie 404”, retro-hunt. Biblioteka wbudowana (386 sygnatur). Kolektor HTTP/TLS. Narzędzie `fpprobe` i wyniki z laboratorium.

**[REGULY.md](REGULY.md): reguły ekspozycji.** „Powierzchnia ataku jako kod”: pola reguły, warunki, asercje, walidator, próba na sucho, cykl życia naruszeń, pakiet startowy 14 reguł. Rozdział 10: sygnatura z przykładu.

**[INTEGRACJE.md](INTEGRACJE.md): integracje.** Import wyników (nmap XML, JSON, CSV) z tabelą nazw kolumn, eksport, sprawdzenie w obie strony. Pasywne źródła danych: pliki, odwrotny DNS, crt.sh. DefectDojo: ustawienia, mapowanie pól, eksport bez duplikatów. Lokalne laboratorium DefectDojo i narzędzie `dojoprobe`.

**[ARCHITECTURE.md](ARCHITECTURE.md): architektura i kontrakt (po angielsku).** Kryteria oceny przełożone na decyzje projektowe, schemat komponentów, przepływ danych jednego przebiegu, lista pakietów, opis algorytmów, ochrona danych, role, konwencje. Dokument powstał przed kodem jako kontrakt dla zespołu; tam, gdzie różni się od kodu, obowiązuje kod i `ZGODNOSC.md`.

**[API.md](API.md): REST API (po angielsku).** Tabela tras `/api/v1` z wymaganym uprawnieniem i typem odpowiedzi, zasady sesji, stronicowania, błędów i częściowych aktualizacji. Typy danych są w `internal/model/types.go`.

**[PROBLEM_DEFINITION.md](PROBLEM_DEFINITION.md): treść zadania.** Tekst organizatora wyciągnięty z PDF. Źródło prawdy dla zakresu.

## Dokumenty przy modułach

| Dokument | Treść |
| --- | --- |
| [`deploy/README.md`](../deploy/README.md) | skrót uruchomienia i szyfrowania; pełna wersja to `WDROZENIE.md` |
| [`lab/defectdojo/README.md`](../lab/defectdojo/README.md) | lokalna instancja DefectDojo do testów |
| [`e2e/engine/README.md`](../e2e/engine/README.md) | laboratorium silnika skanu i scenariusze end-to-end |
| [`e2e/engine/REPORT.md`](../e2e/engine/REPORT.md) | pomiary silnika: tempo pakietów, okna, powtórki, czasy |
| [`e2e/full/README.md`](../e2e/full/README.md) | pełny test produktu przez REST API; zapis w `e2e/full/transcript.txt` |
| [`lab/README.md`](../lab/README.md) | laboratorium 70 hostów: plan adresów, stany `t0`–`t2`, hosty niestabilne, prawda wzorcowa |
| [`web/REPORT-LAB.md`](../web/REPORT-LAB.md) | interfejs sprawdzony na laboratorium /16 |
| [`web/README.md`](../web/README.md) | budowanie i uruchamianie interfejsu |
| [`web/DESIGN.md`](../web/DESIGN.md), [`web/PRODUCT.md`](../web/PRODUCT.md) | system wizualny i kontekst produktu |
| [`docs/samples/raport-przyklad.html`](samples/raport-przyklad.html) | przykładowy raport z przebiegu (także `.md` i zrzut strony 1) |
| `web/screenshots/lab/` | zrzuty ekranów interfejsu na danych laboratorium /16 |

## Narzędzia wiersza poleceń

| Polecenie | Do czego |
| --- | --- |
| `czujka` (`cmd/czujka`) | produkt: `serve`, `migrate`, `user create`, `rotate-key`, `genkey`, `healthcheck`, `doctor` (diagnoza instalacji), `backup` i `restore` (kopia szyfrowana), `version` |
| `scanprobe` (`cmd/scanprobe`) | sam silnik skanu, bez bazy i API |
| `fpprobe` (`cmd/fpprobe`) | kolektor HTTP/TLS i sygnatury dla jednego adresu; walidacja sygnatur |
| `dojoprobe` (`cmd/dojoprobe`) | import, konwersja formatów, wysyłka do DefectDojo |

## Czego brakuje w dokumentacji

- `docs/WYNIKI.md`: pomiary trafności (w przygotowaniu).
- Instrukcja użytkownika interfejsu ekran po ekranie.
- Polska wersja `ARCHITECTURE.md` i `API.md`.
