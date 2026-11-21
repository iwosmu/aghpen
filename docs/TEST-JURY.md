# Test na szablonie jury (`lab/jury`)

Szablon organizatorów to cztery stosy usług w Dockerze na portach jednej maszyny i scenariusz `quickstart.sh` (usługa znika i wraca). Ten dokument podaje najkrótszą drogę dla jurora i nasz pomiar na każdym stosie.

## Najkrótsza droga dla jurora

Uruchom na Linuksie albo w maszynie wirtualnej (ostrzeżenie niżej).

```sh
git clone https://github.com/iwosmu/aghpen.git czujka && cd czujka
CZUJKA_PORT=9180 docker compose up -d
docker compose logs czujka | grep -A3 "first administrator"
cd lab/jury && ./quickstart.sh up
```

1. Otwórz `http://127.0.0.1:9180` i zaloguj się danymi z logu.
2. Naciśnij „Ten komputer”, potem „Uruchom skan”. Cel `localhost` to host dockera, a nie kontener Czujki.
3. Wykonaj `./quickstart.sh change` i uruchom drugi skan: „Usługa …:8787 zniknęła”. Wykonaj `./quickstart.sh up` i trzeci skan: „Usługa …:8787 wróciła”.
4. Inne stosy: zatrzymaj poprzedni i uruchom jeden z `docker-compose-*.yml`, potem skanuj. Stosy zajmują te same porty, więc działa jeden naraz.

Szablon zajmuje port 8080, dlatego Czujka dostaje 9180.

## Ostrzeżenie: nie na laptopie w sieci współdzielonej

Szablon publikuje porty na `0.0.0.0`, a stos `vulnerable` ma domyślne hasła (WordPress i MySQL w pliku compose, DVWA, FTP). W sieci Wi-Fi konferencji każdy w tej sieci osiągnie te usługi. Uruchamiaj szablon w maszynie wirtualnej, w kontenerze docker-in-docker (jak nasz test niżej) albo za zaporą. Czujka tych haseł nie używa: wysyła tylko `GET` i `HEAD` i nigdy się nie loguje.

Na komputerze, na którym pracują też inne programy (zwykle Mac albo Windows z Docker Desktop), host dockera to ten sam komputer. Pełny zakres portów trafia tam sondami wykrywania wersji także w te programy. Tam skanuj tylko porty szablonu i ustaw tę samą listę w `allowed_ports` polityki bezpieczeństwa ([`WDROZENIE.md`](WDROZENIE.md)).

## Nasz test: jedna komenda

```sh
e2e/jury/dind.sh
```

Skrypt buduje Czujkę z bieżącego kodu i uruchamia „maszynę jury”: jeden kontener `docker:28-dind`, w którym działają szablon i Czujka. Do komputera z testem wychodzi tylko interfejs Czujki na `127.0.0.1:18720`. Blokada operatora (`CZUJKA_ALLOWED_NETWORKS`) to brama tej maszyny `/32`, więc żaden skan nie wychodzi poza nią.

W maszynie jury skrypt [`e2e/jury/run.sh`](../e2e/jury/run.sh) wykonuje kroki jurora przez REST API: cel `localhost`, najpierw profil domyślny (ten, który kopiuje „Ten komputer”), potem profil z portami szablonu. Wynik porównuje z tabelą prawdy [`e2e/jury/truth.tsv`](../e2e/jury/truth.tsv): porty, nazwy usług, technologie z wersjami, sygnatury, klasy i znaleziska. Wiersz z właścicielem w tabeli prawdy to znana luka (`GAP`), a nie błąd. Zapis przebiegu: [`e2e/jury/transcript.txt`](../e2e/jury/transcript.txt).

Scenariusze zmian:

- `quickstart.sh`: `up`, `change`, `up`;
- zamiana stosu `custom-network` na `modern`;
- zmiana wersji: kopia pliku `modern` z `redis:6` zamiast `redis:7` ([`e2e/jury/compose/`](../e2e/jury/compose/));
- Toxiproxy na stosie `modern-proxy`: opóźnienie 500 ms, `timeout`, `bandwidth`, `slow_close` (pliki `.env` w [`e2e/jury/env/`](../e2e/jury/env/), kopie `.env.example` z jedną zmianą).

Sygnatury dla usług szablonu, których brakowało w bibliotece, są w [`signatures/labtools.yaml`](../signatures/labtools.yaml) (Toxiproxy, API Traefika, strona domyślna Nginx Proxy Manager, DVWA, httpbin, instalator WordPressa, Redis bez hasła), każda z testem na odpowiedzi zapisanej z prawdziwej usługi.

## Wyniki

Pomiar z 21 listopada 2026 na kodzie `a5a3025`: maszyna jury `docker:28-dind` na Macu z procesorem arm64, cel `localhost`, profil domyślny (pełny zakres: najpierw 1051 portów top, potem pozostałe 64 484). Każdy wiersz pochodzi z [`e2e/jury/transcript.txt`](../e2e/jury/transcript.txt).

| Stos | Porty szablonu znalezione | Pierwsza usługa | Cały przebieg | Co rozpoznane |
| --- | --- | --- | --- | --- |
| `custom-network` | 7/7 | 7 s | 87 s | httpbin 0.9.2, PostgreSQL, RabbitMQ 3.13.7 (AMQP i panel), Gitea 28.4.0 z niedokończonym instalatorem, OpenSSH 10.3, strona domyślna nginx 1.31.9 |
| `modern` | 6/6 | 7 s | 87 s | WordPress 7.1.5 z instalatorem, phpMyAdmin 5.2.3, Redis 7.4.12 bez hasła, Nginx Proxy Manager (panel i strona domyślna), port TLS 443 |
| `vulnerable` | 15/15 (z całym zakresem FTP 21000–21010) | 4 s | 88 s | FTP, WordPress 4.7.5 (przestarzały, z instalatorem), Adminer 6.3.0, DVWA 1.10 |
| `modern-proxy` | 3/3 | 8 s | 88 s | WordPress 7.1.5 za Traefikiem i Toxiproxy, Traefik 3.1.7 z `api.insecure`, API Toxiproxy 2.12.0 bez uwierzytelniania |

Poza portami szablonu pełny zakres znalazł na każdym stosie dwa porty maszyny jury: 18080 (interfejs Czujki w tej maszynie) i 2375 (demon Dockera w `docker:dind` bez TLS). Port 2375 to prawdziwe odkrycie: każdy, kto osiągnie maszynę jury, może sterować jej Dockerem. Szablon go nie publikuje, więc nie liczymy go do wyniku.

Znaleziska z reguł (wybór): „Niedokończona instalacja aplikacji” na 3001, 8080, 8085 i 8088; „API sterujące bez uwierzytelniania” na 8474; „Przestarzała główna wersja CMS” na 8088; „Port bazy danych otwarty na sieć skanowaną” na 6379 i 15432; „Telnet albo FTP dostępny w sieci” na 21.

Scenariusze zmian, ze zdaniami, które Czujka zapisała w „Zmianach”:

| Scenariusz | Rodzaj zmiany | Zdanie Czujki |
| --- | --- | --- |
| `./quickstart.sh change` | `service_gone` | „Usługa 172.18.0.1:8787 zniknęła (nginx 1.31.9)” |
| `./quickstart.sh up` | `service_returned` | „Usługa 172.18.0.1:8787 wróciła po 18 s (nie było jej w 1 skanie) (nginx 1.31.9)” |
| zamiana `custom-network` na `modern` | `service_gone`, `service_new` | „Usługa 172.18.0.1:3001 zniknęła (http)”, „Nowa usługa 172.18.0.1:8080 (Apache httpd 2.4.71)” |
| `redis:7` na `redis:6` (kopia pliku compose) | `tech_version` | „Zmiana wersji Redis na 172.18.0.1:6379: 7.4.12 → 6.2.24” |
| Toxiproxy: opóźnienie 500 ms | `response_slower` | „Usługa 172.18.0.1:8085 odpowiada wolniej: 488 ms (zwykle 25 ms)” |
| Toxiproxy: `timeout` 1 s | wynik usługi | HTTP 502 po 1013 ms w ostatniej obserwacji 8085 |
| Toxiproxy: `bandwidth` 100 KB/s, `slow_close` 1 s | brak zmiany | skan kończy się, port 8085 zostaje otwarty |

Razem: 128 sprawdzeń PASS, 0 FAIL, 1 znana luka. Przebieg z listą portów szablonu (7–15 portów) trwa 12–45 s, pierwsza usługa po 2–14 s.

## Znane luki

- vsftpd na porcie 21 nie podaje wersji na komputerze z procesorem arm64. Obraz jest tylko dla amd64, a pod emulacją odpowiada błędem emulatora zamiast banera. Port, nazwa `ftp` i reguła FTP działają. Na hoście amd64 tej luki nie ma.
