# Testy end-to-end Czujki na laboratorium

Ten katalog zawiera narzędzia, które porównują wynik skanu z prawdą wzorcową laboratorium (`lab/ground-truth`).

| Ścieżka | Co robi |
| --- | --- |
| `e2e/score` | porównuje eksport JSON Czujki (`[]model.HostResult`) z ground truth: precision, recall, F1, lista braków i fałszywych trafień |
| `e2e/nmapconv`, `e2e/nmap2czujka` | zamienia XML nmap na `[]model.HostResult` (punkt odniesienia: „goły nmap”) |
| `e2e/labscan.sh` | skan odniesienia ze skrzynki skanera: przegląd /16, pełny skan TCP z `-sV`, trzy porty UDP, konwersja |
| `e2e/watchunstable` | oś czasu hostów niestabilnych: co widać w sieci i co mówi model dostępności |

Wszystkie skany używają tylko bezpiecznych technik: ARP/ICMP, SYN, `-sV` i cztery skrypty nmap z kategorii `safe` (`http-title`, `http-server-header`, `http-headers`, `ssl-cert`). Żadnego logowania, żadnych ładunków.

## 1. Pełna kontrola w dwóch przebiegach

```sh
# 0. start laboratorium w stanie t0
lab/lab.sh up

# 1. pierwszy skan. Cel: 10.66.0.0/16 (lab/ground-truth/targets-cidr.txt), skaner w sieci czujka-lab (lab/README.md, rozdział 4)
#    Czujka:  eksport JSON skanu -> export-t0.json
#    nmap:    e2e/labscan.sh t0 e2e/out      -> e2e/out/export-t0.json
go run ./e2e/score -truth lab/ground-truth/t0.json -export e2e/out/export-t0.json

# 2. zmiana stanu
lab/scenario.sh t1

# 3. drugi skan -> export-t1.json
e2e/labscan.sh t1 e2e/out
go run ./e2e/score -truth lab/ground-truth/t1.json -export e2e/out/export-t1.json

# 4. czy skaner zobaczył dokładnie oczekiwane zmiany?
go run ./e2e/score -changes lab/ground-truth/changes-t0-t1.json \
    -truth-from lab/ground-truth/t0.json -truth lab/ground-truth/t1.json \
    -from e2e/out/export-t0.json -to e2e/out/export-t1.json

# 5. to samo dla t2 (changes-t1-t2.json), potem sprzątanie
lab/lab.sh down
```

Kontrola jest zaliczona, gdy:

- w kroku 1 i 3 hosty i porty mają F1 = 1,000 (z pominięciem udokumentowanych przypadków trudnych),
- w kroku 4 każda oczekiwana zmiana jest na liście „matched”, a lista „observed, not expected” jest pusta,
- hosty niestabilne (`flapper`, `tod-office`, `tod-night`) nie pojawiają się jako zmiany.

`-min-f1 0.95` zamienia wynik na kod wyjścia (do CI).

## 2. Co liczy `score`

Metryki z precision, recall i F1:

| Kategoria | Jednostka | Uwagi |
| --- | --- | --- |
| hosts | adres IP | hosty niestabilne są poza metryką; brama i skrzynka skanera są pomijane |
| ports | `ip:port/proto` w stanie open | przypadki trudne (`hard`) nie liczą się jako brak, chyba że z `-strict` |
| service names | nazwa usługi | rodziny nazw są równoważne (`http`, `https`, `http-alt`, `ssl/http`); `name_alt` z ground truth też jest poprawne |
| technologies | `ip:port` + nazwa technologii | porównanie po nazwie i aliasach, bez wielkości liter; `tech_optional` nie jest fałszywym trafieniem; ustalenia kategorii `header`/`cookie`/`environment` nie są technologiami |
| classes | `ip:port` + klasa | `class_optional` nie jest fałszywym trafieniem |

Kontrole „tylko recall” (ile z oczekiwanych wartości się zgadza): wersje usług, wersje technologii (prefiks: `6.9` pasuje do `6.9.4`), tytuły stron, zebrane ciekawe nagłówki i ciasteczka, ich oznaczenie przez sygnaturę, flagi ciasteczek, flagi TLS (self-signed, expired, mismatch), hash favicony, własne sygnatury.

Flagi: `-strict` (przypadki trudne liczą się normalnie), `-min-confidence 0.5` (pomija technologie o niższej pewności), `-ignore 10.66.0.20` (adres samego skanera), `-json`, `-max-list N`.

Tryb zmian (`-changes`) wylicza zmiany między dwoma eksportami (nowy/zniknięty host, port otwarty/zamknięty, wersja, tytuł, kod HTTP, przekierowanie, nagłówki, ciasteczka, certyfikat, technologie, klasy) i porównuje je z plikiem oczekiwanych zmian. Nagłówki zmienne z natury (`Date`, `ETag`, `Set-Cookie`, identyfikatory żądań) i pola oznaczone `volatile` w ground truth są pomijane. Zmiany, których eksport nie może pokazać (np. technologie w eksporcie z gołego nmap), trafiają na listę „not checked”.

## 3. Wynik odniesienia: goły nmap

Pomiar z 2026-11-21, nmap 7.99 w skrzynce skanera, polecenia z `e2e/labscan.sh`. Czas: przegląd /16 48 s (65 536 adresów), pełny skan TCP (`-p-`, `-sV`) i UDP około 9–10 minut.

| Stan | hosts F1 | ports F1 | service names F1 | wersje usług | tytuły | flagi ciasteczek | flagi TLS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `t0` | 1,000 (67/67) | 1,000 (155/155) | 1,000 (151/151) | 32/32 | 123/123 | 24/24 | 13/13 |
| `t1` | 1,000 (67/67) | 1,000 (155/155) | 1,000 (151/151) | 30/30 | 123/123 | 25/25 | 13/13 |
| `t2` (tylko porty z ground truth) | 1,000 (67/67) | 1,000 (154/154) | 1,000 (150/150) | 31/31 | 122/122 | 26/26 | 13/13 |

Zmiany: `t0 → t1` 18 z 18 sprawdzalnych zmian znalezionych, 0 nieoczekiwanych (7 zmian technologii i klas nmap nie umie pokazać). `t1 → t2` 7 z 7, 0 nieoczekiwanych (1 zmiana kodu HTTP poza zasięgiem użytych skryptów).

Czego goły nmap **nie** daje i gdzie Czujka ma być lepsza (wiersze z wynikiem 0 w raporcie): technologie (0/104), klasy usług (0/52), oznaczenie ciekawych nagłówków i ciasteczek (0/68), hash favicony (0/14), własne sygnatury (0/2).

Hosty niestabilne (`go run ./e2e/watchunstable`, próbka co 15 s): 60 z 60 próbek zgodnych z modelem dostępności w drugim pomiarze; 93 z 96 w pierwszym (dwie kolejne próby nie zobaczyły żadnego hosta, choć dzienniki hostów pokazują włączony interfejs; przyczyny nie ustalono).

Uwagi do pomiaru:

- W tych przebiegach nmap znalazł także wszystkie hosty i porty oznaczone jako trudne (`hard`), więc z `-strict` hosty i porty mają ten sam wynik. Wymagało to pełnego zakresu portów (`-p-`) i skanu UDP portów 53, 123 i 161. Z `-strict` jedna nazwa usługi pozostaje nieustalona (RabbitMQ 10.66.10.41:25672, port dystrybucji Erlanga; service names F1 0,997).
- nmap zapisuje znaki spoza ASCII w tytułach jako `\xHH`; konwerter je odkodowuje.
- `-sV` uruchamia też własne skrypty nmap z kategorii `version` (np. `mqtt-subscribe`); wszystkie są w kategorii `safe`.
- Certyfikat TLS MariaDB (port 3306) nmap odczytuje tylko w części przebiegów, więc ground truth go nie wymaga.

## 4. Testy jednostkowe

```sh
go test ./e2e/... ./lab/...
```

Testy nie potrzebują dockera. `lab/manifest` sprawdza m.in., czy pliki generowane są aktualne względem manifestu.
