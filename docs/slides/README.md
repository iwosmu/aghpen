# Prezentacja Czujki

| Plik | Co to jest |
| --- | --- |
| `czujka.pdf` | prezentacja: 10 slajdów 16:9 (1920 × 1080), po polsku |
| `czujka.html` | ta sama prezentacja jako jeden plik HTML; fonty i zrzuty ekranu są w środku |
| `czujka.src.html` | źródło; przy każdej liczbie komentarz z plikiem, z którego pochodzi |
| `build.mjs` | buduje `czujka.html` i `czujka.pdf`, potem sprawdza każdy slajd |

Budowanie (Node i npm; Chromium pobiera Playwright):

```sh
cd docs/slides
npm install
npx playwright install chromium-headless-shell   # raz
npm run build
```

Skrypt kończy się kodem 1, gdy na którymś slajdzie tekst ma mniej niż 24 px, wychodzi poza slajd albo wchodzi na stopkę.

Miejsca oznaczone `DO UZUPEŁNIENIA` czekają na pomiary (`docs/WYNIKI.md`) i na zrzuty ekranów wehikułu czasu, reguł i „Zaproponuj sygnaturę” z danych laboratorium. Po dodaniu zrzutu do `web/screenshots/lab/` zamień ramkę `slot` na element `shot` (jak na slajdzie 3) i zbuduj ponownie.
