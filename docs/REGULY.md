# Reguły ekspozycji („powierzchnia ataku jako kod”)

Rozpoznanie mówi, **co istnieje**. Reguła mówi, **czego nie może być** (albo co musi być). Czujka sprawdza każdą włączoną regułę po każdym przeanalizowanym skanie i po każdym imporcie. Naruszenie trafia na listę ustaleń jako ustalenie typu `policy-violation`.

Reguła działa tylko na zapisanym inwentarzu. Sprawdzenie reguły nie wysyła żadnego pakietu.

Kod: `internal/rules`. Trasy API: [API.md](API.md#exposure-rules-and-signature-from-an-example).

## 1. Przykład

```yaml
id: no-admin-panel-outside-mgmt
name: Panel administracyjny poza siecią zarządzania
severity: high            # info | low | medium | high
description: Panele administracyjne mają być dostępne tylko z sieci zarządzania.
remediation: Ogranicz dostęp (ACL, VPN) albo przenieś panel do sieci zarządzania.
where:                    # którą część inwentarza reguła ogląda
  scope: [kampus]
  not_cidr: [10.66.10.0/24]
match:                    # warunek na usłudze (albo hoście)
  class: admin-panel
expect: absent            # absent: każde dopasowanie to naruszenie
```

Ta reguła zgłosi każdą usługę klasy `admin-panel` w zakresie „kampus”, poza siecią 10.66.10.0/24.

## 2. Pola reguły

| Pole | Znaczenie | Domyślnie |
| --- | --- | --- |
| `id` | Identyfikator: małe litery, cyfry, `-`, `_`, `.`. Gdy go brak, powstaje z `name`. | z nazwy |
| `name` | Nazwa widoczna w ustaleniu. | `id` |
| `severity` | Waga ustalenia: `info`, `low`, `medium`, `high`. | `medium` |
| `description` | Opis dla analityka. Trafia do opisu ustalenia. | puste |
| `remediation` | Zalecenie naprawy. Trafia do opisu ustalenia. | puste |
| `enabled` | Czy reguła jest włączona po dodaniu. | `true` |
| `subject` | Podmiot: `service` (każda usługa osobno) albo `host` (host pasuje, gdy pasuje jedna z jego usług). | `service` |
| `expect` | `absent`: każde dopasowanie to naruszenie. `present`: brak dopasowania to naruszenie. | `absent` |
| `per` | Tylko przy `present`: `host` (każdy host z `where` musi mieć dopasowanie) albo `scope` (wystarczy jedno dopasowanie w całym `where`). | `host` |
| `where` | Wybór części inwentarza (rozdział 3). | cały inwentarz |
| `match` | Warunek (rozdział 4). | wymagany przy `absent` |
| `tags` | Etykiety reguły. | puste |

## 3. `where`: którą część inwentarza oglądać

| Klucz | Znaczenie |
| --- | --- |
| `scope` | Nazwy zakresów albo etykiety zakresów (wielkość liter bez znaczenia). |
| `cidr` | Adresy albo sieci CIDR. Host musi należeć do jednej z nich. |
| `not_cidr` | Sieci wykluczone. |
| `tags` | Host albo usługa ma jedną z tych etykiet. |
| `not_tags` | Ani host, ani usługa nie ma żadnej z tych etykiet. |
| `state` | Stany usług: `open`, `gone`, `unknown`, `filtered`. Domyślnie tylko `open`, chyba że warunek sam sprawdza `state`. |
| `host_status` | Stany hostów: `up`, `unstable`, `down`, `expected-offline`, `unknown`. Reguła `present` bez tego klucza pomija hosty `down`. |

## 4. `match`: warunki

Kilka kluczy w jednej mapie łączy spójnik „i”. Do łączenia służą `all: [...]`, `any: [...]` i `not: {...}`.

| Warunek | Przykład | Znaczenie |
| --- | --- | --- |
| `class` | `class: [admin-panel, login]` | Klasa usługi (jedna z listy). Klasy: `admin-panel, login, staging, iot, default-page, api, dev-tool, database, remote-access, directory-listing, error-page`. |
| `tech` | `tech: "WordPress < 6.5"` | Technologia, opcjonalnie z porównaniem wersji (`<`, `<=`, `>`, `>=`, `=`, `!=`). Postać mapy: `{name: WordPress, version: "< 6.5"}`. Lista = „któraś z”. Technologia bez znanej wersji nie spełnia warunku z wersją. |
| `port` | `port: [22, "8000-8100"]` | Port albo zakres portów. |
| `proto` | `proto: udp` | `tcp` albo `udp`. |
| `service` | `service: [telnet, ftp]` | Nazwa usługi z nmap. |
| `product`, `banner` | `product: '^OpenSSH'` | Wyrażenie regularne na produkcie albo banerze. |
| `state` | `state: gone` | Stan usługi. |
| `host_status` | `host_status: unstable` | Stan hosta. |
| `tls` | `tls: {expired: false, days_left_below: 14}` | Certyfikat: `present`, `expired`, `self_signed`, `host_mismatch`, `days_left_below`, `issuer`, `subject`, `version` (trzy ostatnie to wyrażenia regularne). Dni liczą się od chwili sprawdzenia. `present: false`: usługa HTTP bez TLS. |
| `scheme` | `scheme: http` | Schemat usługi WWW. |
| `redirects_to_https` | `redirects_to_https: false` | Czy usługa przekierowuje na HTTPS (łańcuch przekierowań, nagłówek `Location`, adres końcowy). |
| `http_status` | `http_status: [200, 3xx]` | Kod HTTP albo klasa kodów. |
| `header` | `header: {name: Server, regex: 'nginx/1\.1[0-8]'}` | Nagłówek istnieje / pasuje do wyrażenia. `present: false`: nagłówka brak. |
| `cookie` | `cookie: {name_regex: '^sess', secure: false}` | Ciasteczko o nazwie i flagach (`secure`, `http_only`, `same_site`). |
| `title`, `url`, `hostname` | `title: '(?i)phpinfo'` | Wyrażenie regularne na tytule, adresie albo nazwie hosta. |
| `new_within_days` | `new_within_days: 7` | Usługa (albo host przy `subject: host`) pojawiła się w ciągu N dni. |
| `tags` | `not: {tags: [approved]}` | Usługa albo jej host ma jedną z etykiet. |
| `min_interest` | `min_interest: 60` | Ocena „co jest ciekawe” usługi co najmniej N. |

Zasada „brak danych to nie brak”: warunki `header` z `present: false`, `redirects_to_https: false` i `tls` z `present: false` nie pasują do usługi, która nie ma odpowiedzi HTTP. Usługa SSH nie jest więc „serwisem bez nagłówka HSTS”.

Wyrażenia regularne używają silnika RE2 (bez odwołań wstecznych i asercji, czas liniowy). Domyślnie nie rozróżniają wielkości liter.

## 5. Asercje (`expect: present`)

```yaml
id: www-must-answer-443
name: Serwer WWW uczelni odpowiada na 443
severity: high
expect: present
where: {cidr: [10.66.1.10]}
match: {port: 443, state: open}
```

`per: host` (domyślnie): każdy host z `where` musi mieć usługę spełniającą warunek. `per: scope`: wystarczy jedna taka usługa w całym `where`.

„Każdy serwis WWW w zakresie przekierowuje na HTTPS” zapisz jako zakaz: `expect: absent` z warunkiem `{all: [{scheme: http}, {redirects_to_https: false}]}`.

## 6. Walidator

Walidator sprawdza regułę przed zapisem. Każdy problem ma ścieżkę YAML (np. `match.any[0].tls.expird`), komunikat po polsku i numer wiersza:

```json
{"ok": false, "issues": [
  {"level": "error", "path": "match.port[0]", "message": "„70000” nie jest portem (0–65535) ani zakresem portów (wiersz 3)"},
  {"level": "error", "path": "match.title", "message": "błędne wyrażenie regularne (składnia RE2, bez odwołań wstecznych i asercji): ... (wiersz 2)"}
]}
```

Nieznane pole najwyższego poziomu daje ostrzeżenie. Nieznany warunek, błędna wartość albo błędne wyrażenie dają błąd: reguła z błędem nie jest zapisana.

## 7. Próba na sucho

`POST /api/v1/rules/dry-run` sprawdza tekst reguły na dzisiejszym inwentarzu i niczego nie zapisuje. Edytor pokazuje odpowiedź, np.:

> Ta reguła zgłosiłaby dziś 7 naruszeń (sprawdzono 2000 hostów i 6000 usług).

Pomiar na 2000 hostach i 6000 usługach (PostgreSQL 17 z pg_tde, Apple M-series): próba na sucho 55 ms.

## 8. Ustalenia i ich cykl życia

- Klucz ustalenia jest stały: `policy-violation|<id reguły>|<IP>|<port>/<proto>` (usługa), `policy-violation|<id>|<IP>` (host), `policy-violation|<id>|scope` (asercja na zakresie).
- Waga ustalenia = `severity` reguły. Ocena „ciekawe”: high 80, medium 60, low 40, info 20, plus jedna piąta oceny usługi (najwyżej 100).
- Dowody wymieniają pola, które spełniły warunek, np. `class: admin-panel`, `port: 8080/tcp`, `not: nie zachodzi: etykieta approved`.
- Naruszenie, które zniknęło, dostaje status `resolved`. Dotyczy to tylko ustaleń w statusie `new`: status nadany przez analityka (`triaged`, `accepted`, `false_positive`), notatka, etykiety i przypisanie nigdy nie są nadpisane. Waga albo tytuł zmienione ręcznie też zostają.
- Naruszenie, które wróciło, przechodzi z `resolved` znowu na `new`, ale tylko wtedy, gdy skan zaobserwował jego przyczynę po rozwiązaniu (czas obserwacji usługi albo hosta jest późniejszy niż chwila rozwiązania). Dzieje się to raz na jedno rozwiązanie i zostawia wpis `finding.reopen` w dzienniku audytu. Samo ponowne sprawdzenie reguł na tych samych danych nie otwiera ustalenia. Ta sama zasada obowiązuje ustalenia silnika.
- Statusów `accepted` i `false_positive` (od analityka albo z pobrania statusów DefectDojo) nie zmienia żaden skan ani żadna reguła.
- Wyłączenie albo usunięcie reguły rozwiązuje jej otwarte ustalenia przy następnym sprawdzeniu. Zmiana reguły uruchamia sprawdzenie w tle od razu.

Pomiar pełnego sprawdzenia (11 włączonych reguł, 2000 hostów, 6000 usług): 99 ms przy pierwszym zapisie 1160 ustaleń, 88 ms przy kolejnym przebiegu bez zmian.

## 9. Pakiet startowy

| id | Waga | Domyślnie | Co zgłasza |
| --- | --- | --- | --- |
| `admin-panel-outside-mgmt` | high | włączona | panel administracyjny na hoście bez etykiety `mgmt` |
| `login-over-plain-http` | high | włączona | formularz logowania po HTTP bez przekierowania na HTTPS |
| `tls-certificate-expired` | high | włączona | wygasły certyfikat |
| `tls-certificate-expiring-14d` | medium | włączona | certyfikat wygasa w ciągu 14 dni |
| `database-port-exposed` | high | włączona | MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis, Memcached, Elasticsearch … |
| `cleartext-remote-access` | high | włączona | telnet, FTP |
| `remote-desktop-exposed` | medium | włączona | RDP, VNC |
| `staging-or-debug-exposed` | medium | włączona | staging/test/dev albo narzędzie deweloperskie bez etykiety `approved` |
| `default-server-page` | low | włączona | domyślna strona serwera |
| `directory-listing` | medium | włączona | listowanie katalogów |
| `outdated-cms-major` | medium | włączona | WordPress < 6, Joomla < 4, Drupal < 10, TYPO3 < 12, Moodle < 4, MediaWiki < 1.39 |
| `new-service-not-approved` | medium | wyłączona | nowa usługa (7 dni) bez etykiety `approved`; włącz po pierwszym pełnym skanie |
| `tls-self-signed` | low | wyłączona | certyfikat samopodpisany |
| `web-without-https-redirect` | low | wyłączona | serwis WWW po HTTP bez przekierowania na HTTPS |

Regułę wbudowaną można tylko włączyć albo wyłączyć. Aby ją zmienić, skopiuj jej tekst, nadaj nowe `id` i zapisz jako własną regułę; wbudowaną wyłącz. Aktualizacja Czujki odświeża tekst reguł wbudowanych, ale zachowuje decyzję o włączeniu.

## 10. Sygnatura z przykładu

Na stronie usługi przycisk „Zaproponuj sygnaturę” wywołuje `POST /api/v1/signatures/suggest` (pakiet `internal/sigsuggest`). Czujka:

1. zbiera cechy usługi: nagłówki spoza listy standardowych, wartość `Server`/`X-Powered-By` bez wersji, nazwy ciasteczek, skrót favicon, tytuł (do pierwszego słowa z cyfrą), `meta generator`, ścieżki zasobów, klasy i id z HTML, komentarze HTML, napisy z numerem wersji, nazwę i organizację z certyfikatu, tytuły pobranych ścieżek;
2. odrzuca cechy zmienne (daty, długie ciągi szesnastkowe, UUID, tokeny, identyfikatory żądań) i cechy, które zmieniają się między ostatnimi obserwacjami tej usługi;
3. liczy, w ilu innych usługach występuje każda cecha (najnowsza obserwacja każdej usługi, czytana strumieniowo). Usługi, które dzielą co najmniej połowę cech strukturalnych przykładu, to „podobne instancje” tego samego produktu: nie obniżają rzadkości. Cecha w więcej niż 5% pozostałych usług jest pospolita i odpada;
4. buduje sygnaturę z najrzadszych cech (najwyżej 6, w tym najwyżej 3 reguły treści), z `min_confidence: 0.6` i z regułą wersji, gdy wersja jest widoczna;
5. sprawdza ją walidatorem trybu bezpiecznego i retro-huntem po zapisanych danych. Sygnatura musi pasować do przykładu; odpowiedź podaje, do ilu innych usług pasuje.

Gdy usługa nie ma cech jednocześnie rzadkich i stałych, Czujka mówi to wprost i nie proponuje słabej sygnatury.

Przykład z laboratorium (strona InfoKiosk, pobrana kolektorem Czujki i zapisana przez ingest):

```yaml
id: infokiosk
name: 'InfoKiosk'
category: other
tags: [sugerowana]
match:
  condition: any
  min_confidence: 0.6
  rules:
    - {type: favicon, mmh3: [1990289189], weight: 0.9}
    - {type: header, name: 'X-Infokiosk-Node', weight: 0.7}
    - {type: cookie, name: 'infokiosk_sid', weight: 0.7}
    - {type: header, name: 'Server', regex: '^ik-httpd', weight: 0.6}
    - {type: body, regex: 'InfoKiosk[ /]v?[0-9]+\.[0-9]+', weight: 0.6}
    - {type: title, regex: '^Informator — kiosk', weight: 0.55}
version:
  - {type: body, regex: 'InfoKiosk[ /]v?([0-9]+(?:\.[0-9]+)+)'}
```

Wyjaśnienie reguły: „nagłówek X-Infokiosk-Node występuje tylko w tej usłudze i w 1 podobnych instancjach (0 z 28 pozostałych usług)”. Retro-hunt: przykład i drugi kiosk, obie z wersją 4.2.1, 0 wysłanych pakietów.
