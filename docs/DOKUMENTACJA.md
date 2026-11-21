# Dokumentacja techniczna Czujki

Spis dokumentów. Czujka to narzędzie do cyklicznego, bezpiecznego skanowania discovery dużych sieci, zgłoszone do zadania „Attack Surface Intelligence” (CBI AGH, HackNation 2026).

Zacznij od `README.md` (uruchomienie) i `docs/ZGODNOSC.md` (co działa dziś).

| Dokument | Język | Dla kogo |
| --- | --- | --- |
| [`README.md`](../README.md) | polski | każdy: czym jest Czujka, szybki start |
| [`docs/ZGODNOSC.md`](ZGODNOSC.md) | polski | jury: wymagania zadania i ich stan |
| [`docs/WDROZENIE.md`](WDROZENIE.md) | polski | administrator |
| [`docs/BEZPIECZENSTWO.md`](BEZPIECZENSTWO.md) | polski | jury, administrator, zespół bezpieczeństwa |
| [`docs/ALGORYTMY.md`](ALGORYTMY.md) | polski | jury, opiekunowie kodu |
| [`docs/SIGNATURES.md`](SIGNATURES.md) | polski | autorzy sygnatur |
| [`docs/INTEGRACJE.md`](INTEGRACJE.md) | polski | administrator, integrator |
| [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) | angielski | programiści |
| [`docs/API.md`](API.md) | angielski | programiści, integratorzy |
| [`docs/PROBLEM_DEFINITION.md`](PROBLEM_DEFINITION.md) | polski | treść zadania |

## Dokumenty główne

**[ZGODNOSC.md](ZGODNOSC.md): zgodność z treścią zadania.** Macierz wymagań: 16 wymagań z podpunktami, akapity o sygnaturach i oknach czasowych, zakres minimalny i dodatkowy, wymagania formalne, 12 punktów weryfikacji i 6 kryteriów oceny. Dla każdej pozycji podaje, co robi Czujka, gdzie to jest w kodzie, jak to sprawdzono i jaki ma status: gotowe, w integracji albo brak. To jedyny dokument, który mówi o stanie na konkretny dzień.

**[WDROZENIE.md](WDROZENIE.md): wdrożenie.** Wymagania, start przez `docker compose`, wszystkie zmienne `CZUJKA_*`, pierwsze logowanie, konta, kopia zapasowa i odtwarzanie, rotacja klucza, aktualizacja, dołączanie skanera do sieci, rozwiązywanie problemów. Polecenia zostały wykonane; miejsca niesprawdzone są oznaczone.

**[BEZPIECZENSTWO.md](BEZPIECZENSTWO.md): bezpieczeństwo.** Część pierwsza: co skaner wysyła, a czego nigdy; limity tempa i miejsce ich egzekwowania; polityka bezpieczeństwa; awaryjne zatrzymanie; tryb bezpieczny sygnatur; trzymanie się zakresu. Część druga: `pg_tde`, szyfrowanie pól z listą kolumn, klucz główny i rotacja, hasła, sesje, CSRF, dziennik audytu, tabela uprawnień czterech ról. Zawiera listę znanych ograniczeń.

**[ALGORYTMY.md](ALGORYTMY.md): algorytmy.** Odpowiedzi na trzy pytania z zadania: jak raportować zmianę, jak określić pewność identyfikacji technologii, po jakim czasie uznać host za nieaktywny. Model dostępności hosta ze wzorami i zmierzonymi scenariuszami, reguły szumu w porównaniu przebiegów, tabela wag zmian, tabela punktów oceny ciekawości, grupowanie usług, klucze obserwacji, raport z przebiegu.

**[SIGNATURES.md](SIGNATURES.md): sygnatury.** Język sygnatur w YAML: pola, 14 typów reguł, dopasowania, forma skrócona. Tryb bezpieczny walidatora z przykładami odrzuceń. Liczenie pewności. Silnik dopasowań, „miękkie 404”, retro-hunt. Biblioteka wbudowana (386 sygnatur). Kolektor HTTP/TLS. Narzędzie `fpprobe` i wyniki z laboratorium.

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
| [`web/README.md`](../web/README.md) | budowanie i uruchamianie interfejsu |
| [`web/DESIGN.md`](../web/DESIGN.md), [`web/PRODUCT.md`](../web/PRODUCT.md) | system wizualny i kontekst produktu |
| [`docs/samples/raport-przyklad.html`](samples/raport-przyklad.html) | przykładowy raport z przebiegu (także `.md` i zrzut strony 1) |
| `web/screenshots/` | zrzuty ekranów interfejsu na danych przykładowych |

## Narzędzia wiersza poleceń

| Polecenie | Do czego |
| --- | --- |
| `czujka` (`cmd/czujka`) | produkt: `serve`, `migrate`, `user create`, `rotate-key`, `genkey`, `healthcheck`, `version` |
| `scanprobe` (`cmd/scanprobe`) | sam silnik skanu, bez bazy i API |
| `fpprobe` (`cmd/fpprobe`) | kolektor HTTP/TLS i sygnatury dla jednego adresu; walidacja sygnatur |
| `dojoprobe` (`cmd/dojoprobe`) | import, konwersja formatów, wysyłka do DefectDojo |

## Czego brakuje w dokumentacji

- Prezentacja (do 10 slajdów) i scenariusz demo.
- Instrukcja użytkownika interfejsu ekran po ekranie.
- Polska wersja `ARCHITECTURE.md` i `API.md`.
