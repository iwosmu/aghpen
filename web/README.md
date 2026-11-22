# Czujka: konsola WWW

Interfejs analityka dla Czujki. React 19, TypeScript, Vite, React Router, TanStack Query, Tailwind CSS 4. Wykresy to ręcznie pisane SVG, bez biblioteki wykresów.

## Uruchomienie

```sh
npm install
npm run dev            # wymaga działającego backendu pod /api/v1 (proxy Vite, domyślnie http://127.0.0.1:8080)
CZUJKA_DEV_API=http://127.0.0.1:18300 npm run dev:api   # to samo, z adresem backendu podanym wprost
npm run dev:fixtures   # tryb deweloperski bez backendu, dane z warstwy fixtures
npm run typecheck
npm run lint
npm test
npm run build          # tsc, vite build i kontrola paczki; wynik w web/dist
```

Binarka Go osadza `web/dist` przy budowaniu z tagiem `embedui` (`embed.go`). Bez tagu używany jest `noembed.go`, więc `go build ./...` działa także bez zbudowanego interfejsu.

## Warstwa fixtures

- Włączana tylko przez `VITE_FIXTURES=1` w serwerze deweloperskim. Stała `__CZUJKA_FIXTURES__` jest ustawiana przy kompilacji i w każdym buildzie ma wartość `false`, więc kod warstwy nie trafia do paczki.
- `npm run build` z `VITE_FIXTURES=1` kończy się błędem. Po buildzie `scripts/check-bundle.mjs` przeszukuje `dist` i przerywa build, gdy znajdzie ślad warstwy fixtures.
- Podmienia transport klienta API i źródło zdarzeń SSE. Odpowiada na wszystkie ścieżki z `docs/API.md` i symuluje postęp trwającego skanu.
- Dane opisują fikcyjną sieć uczelni (ok. 400 hostów, 700 usług). Stan wraca do początku po przeładowaniu strony.
- Konta: `admin@cbi.example`, `editor@cbi.example`, `analyst@cbi.example`, `viewer@cbi.example`, hasło `czujka`.

Zrzuty bezpośrednio w `screenshots/` pochodzą z tego trybu. Zrzuty w `screenshots/real/` pochodzą z prawdziwego serwera i prawdziwych danych (import nmap, skan `127.0.0.1`, DefectDojo). Te zrzuty pokazują interfejs sprzed uproszczenia i leżą na gałęzi `archive/screenshots`.

## Praca z prawdziwym backendem

- Serwer podaje zbudowany interfejs z katalogu wskazanego przez `CZUJKA_WEB_DIR` (na przykład `web/dist`) albo z paczki osadzonej tagiem `embedui`.
- Polityka CSP serwera nie pozwala na skrypty inline. Motyw i język przed pierwszym renderem ustawia plik `public/boot.js`.
- Klient zamienia `null` na pustą listę dla znanych pól tablicowych (`src/api/normalize.ts`), bo Go zapisuje pusty slice jako `null`.
- Odpowiedź `501 not_wired` daje spokojny stan „Funkcja niedostępna w tej instalacji”. Pozostałe kody błędów mają własne komunikaty (`explainError` w `src/ui/kit.tsx`).
- Po wygaśnięciu sesji interfejs wraca na stronę logowania z informacją i po zalogowaniu otwiera tę samą stronę. Nieaktualny token CSRF jest odświeżany raz i żądanie jest powtarzane.
- Wynik przejścia wszystkich przepływów i lista niezgodności backendu: `REPORT-REAL-BACKEND.md`.

## Struktura

| Ścieżka | Zawartość |
| --- | --- |
| `src/api` | typy kontraktu (lustro `internal/model`), klient HTTP, SSE, hooki zapytań |
| `src/pages` | ekrany: pulpit, przebiegi, hosty, usługi, zmiany, znaleziska, sygnatury, cele, profile, import/eksport, administracja |
| `src/viz` | mapa przestrzeni adresowej (krzywa Hilberta), heatmapa 7 x 24, edytor okien czasowych, wykresy |
| `src/ui` | komponenty wspólne: tabela, panele, znaczniki stanu, edycja w miejscu |
| `src/shell`, `src/session.tsx` | układ, nawigacja, sesja i uprawnienia |
| `src/i18n.ts` | teksty: polski domyślnie, przełącznik na angielski |
| `src/fixtures` | warstwa deweloperska opisana wyżej |
| `screenshots/` | zrzuty Playwright: 1440 x 900 i 390 x 844 |

## Zasady interfejsu

- Uprawnienia: kontrolka, której rola nie może użyć, nie jest renderowana. Widok tylko do odczytu mówi o tym wprost.
- Każda ocena pokazuje swoje powody: składniki oceny ciekawości, dowody technologii, wynik modelu stabilności hosta.
- Stop awaryjny jest zawsze widoczny w górnym pasku i wymaga potwierdzenia.
- Edytor sygnatur waliduje YAML w trakcie pisania i odrzuca metody inne niż GET i HEAD oraz pola wysyłające dane.

Opis systemu wizualnego: `DESIGN.md`. Kontekst produktu: `PRODUCT.md`.
