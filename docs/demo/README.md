# Film demo: nagrywanie skryptem

`record.mjs` nagrywa film z prawdziwego produktu. Playwright klika w interfejs jak człowiek (widoczny kursor, płynne ruchy myszy, wpisywanie w tempie czytania), Chromium zapisuje każdą klatkę, ffmpeg tnie ujęcia i nakłada napisy. Lista ujęć: `docs/DEMO.md` rozdział 1.

## Jedno polecenie

```sh
CZ_URL=http://127.0.0.1:18640 CZ_PASSWORD=<hasło administratora> docs/demo/record.sh
```

Wynik w `docs/demo/`:

| Plik | Co to jest |
| --- | --- |
| `czujka-demo.mp4` | film 1920 × 1080, 60 kl./s, z głosem lektora, bez napisów na obrazie |
| `czujka-demo.pl.srt` | tekst lektora jako plik napisów |
| `lektor.txt` | tekst lektora z kodem czasu każdego ujęcia; głos nagrywa się na gotowy film |

`record.sh` stawia na chwilę świeżą instalację `czpwiz` (port 18641) do ujęcia z kreatorem i usuwa ją po nagraniu. Bez niej (`CZ_NO_WIZARD=1`) ujęcie 1 pokazuje logowanie.

## Zmienne

| Zmienna | Domyślnie | Znaczenie |
| --- | --- | --- |
| `CZ_URL` | `http://127.0.0.1:18640` | adres produktu z historią skanów |
| `CZ_EMAIL`, `CZ_PASSWORD` | `admin@czujka.local`, brak | konto; skan i stop awaryjny wymagają administratora |
| `CZ_PROFILE` | `Laboratorium /16: pełny przegląd` | profil uruchamiany na żywo w ujęciu 2; z nim liczą się też dwa ostatnie pełne przebiegi w ujęciu 3 |
| `CZ_START_SCAN` | `1` | `0`: ujęcie 2 pokazuje ostatni zakończony przebieg zamiast nowego skanu |
| `CZ_SCAN_SECONDS` | `120` | ile sekund skanu nagrać; w filmie trwa to 1/8 tego czasu, ze znakiem „×8” |
| `CZ_SCAN_WARM_CHUNKS` | film wchodzi w skan, gdy tyle podgrup jest gotowych i jest choć jeden aktywny host; faza wykrywania przed nim jest wycięta (domyślnie 8; `CZ_SCAN_WARM_MAX` ogranicza czekanie, domyślnie 900 s) |
| `CZ_SCAN_FINISH` | 1 (domyślnie): poza kadrem czeka na koniec skanu i kończy ujęcie na jego liczbach; 0: kończy na ostatnim zakończonym przebiegu (`CZ_SCAN_FINISH_MAX`, domyślnie 1800 s) |
| `CZ_TIME_STEPS` | o ile przebiegów oś czasu cofa się przez największą zmianę znalezioną w danych (domyślnie 4) |
| `CZ_HOST` | `10.66.70.20` | host niestabilny w ujęciu 4 |
| `CZ_RULE` | `Panel administracyjny poza siecią zarządzania` | reguła w ujęciu 6 |
| `CZ_SERVICE` | `10.66.1.10:80` | usługa do „Zaproponuj sygnaturę” |
| `CZ_STOP` | `1` | `0`: bez ujęcia ze stopem awaryjnym (np. na instancji publicznej) |
| `CZ_ONLY` | wszystkie | do prób: nagraj tylko wybrane ujęcia, np. `CZ_ONLY=time,rules` |

Po ujęciu ze stopem awaryjnym skrypt zwalnia stop i anuluje skan, który sam uruchomił.

## Lokalny stos do pierwszej wersji

`seed.sh` stawia stos `czpitch` (port 18640) w sieci laboratorium, ustawia politykę i ponowne sprawdzenia, dodaje profil co 2 minuty na hostach niestabilnych `10.66.70.0/24` i robi dwa pełne skany `10.66.0.0/16`. Stanu laboratorium nie zmienia. Hasło zapisuje w `docs/demo/out/.seed-czpitch.pw` (poza gitem).

```sh
docs/demo/seed.sh
CZ_PASSWORD=$(cat docs/demo/out/.seed-czpitch.pw) docs/demo/record.sh
```

Wymagania: Docker, Node 20+, ffmpeg z libx264. Ta wersja ffmpeg nie potrzebuje filtrów tekstowych: napisy i znak „×8” są obrazami PNG renderowanymi przez Chromium.
