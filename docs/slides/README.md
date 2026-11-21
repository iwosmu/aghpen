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

Skrypt wypisuje liczbę słów każdego slajdu i kończy się kodem 1, gdy na którymś slajdzie:

- tytuł ma więcej niż 8 słów albo reszta slajdu więcej niż 12 (liczby też są słowami; numer slajdu się nie liczy; liczba z twardą spacją między grupami cyfr, np. „65 535”, to jedno słowo);
- jest lista, tabela albo blok kodu dłuższy niż jeden wiersz;
- tekst ma mniej niż 24 px, wychodzi poza slajd albo wchodzi na stopkę.

Slajd to jeden obraz z podpisem. Szczegóły, które nie mieszczą się w limicie, są w notatkach do slajdów (`docs/DEMO.md` rozdział 2) i w `docs/ZGODNOSC.md`. Źródło każdej liczby jest w komentarzu HTML przy slajdzie, nigdy na slajdzie.

Prezentacja nie ma już miejsc do uzupełnienia. Slajd 3 podaje czas drugiego i kolejnych przebiegów /16 (16 min 56 s, zaokrąglone do 17 minut); pierwszy przebieg trwał 12 min 42 s. Liczby pochodzą z `docs/WYNIKI.md`.
