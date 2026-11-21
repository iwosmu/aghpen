# Czujka: konsola WWW

Interfejs analityka dla Czujki. React 19, TypeScript, Vite, React Router, TanStack Query, Tailwind CSS 4. Wykresy to ręcznie pisane SVG, bez biblioteki wykresów.

## Uruchomienie

```sh
npm install
npm run dev            # wymaga działającego backendu pod /api/v1 (ten sam origin albo proxy Vite)
npm run dev:fixtures   # tryb deweloperski bez backendu, dane z warstwy fixtures
npm run typecheck
npm run lint
npm test
npm run build          # wynik w web/dist
```

Binarka Go osadza `web/dist` przy budowaniu z tagiem `embedui` (`embed.go`). Bez tagu używany jest `noembed.go`, więc `go build ./...` działa także bez zbudowanego interfejsu.

## Warstwa fixtures

- Włączana tylko przez `VITE_FIXTURES=1` w trybie deweloperskim (`import.meta.env.DEV`). Nie trafia do paczki produkcyjnej.
- Podmienia transport klienta API i źródło zdarzeń SSE. Odpowiada na wszystkie ścieżki z `docs/API.md` i symuluje postęp trwającego skanu.
- Dane opisują fikcyjną sieć uczelni (ok. 400 hostów, 700 usług). Stan wraca do początku po przeładowaniu strony.
- Konta: `admin@cbi.example`, `editor@cbi.example`, `analyst@cbi.example`, `viewer@cbi.example`, hasło `czujka`.

Wszystkie zrzuty w `screenshots/` pochodzą z tego trybu. Interfejs nie był jeszcze uruchamiany z prawdziwym backendem.

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
