# Laboratorium skali

Laboratorium sprawdza Czujkę na tysiącach żywych adresów. Lab główny (`lab/`) ma 70 hostów w sieci /16; ten ma 2 000 albo 10 000.

**Co to jest.** N kontenerów „farm” (domyślnie 1 000 adresów na farmę). Każda farma to prawdziwy stos TCP/IP Linuksa z prawdziwymi usługami: nginx, Dropbear SSH i lighttpd. Adresy farmy są na interfejsie `dummy`, więc jedna farma odpowiada za 1 000 adresów. 10 000 żywych adresów obsługuje więc 10 kontenerów. To nie jest 10 000 maszyn: każdy adres ma własne gniazda i odpowiedzi, ale procesy usług są wspólne dla farmy.

## Układ adresów

Adres numer `i` (od 0) farmy `K` to `10.77.(4·(K−1) + i/250).(i%250 + 1)`. Farma `K` ma więc blok `10.77.4(K−1).0/22`.

| Adresy farmy | Udział | Co odpowiada |
| --- | --- | --- |
| `i` < 900 | 90 % | nginx 80 i Dropbear 22; dodatkowo według `i % 10`: 0–2 nginx TLS 443 (samopodpisany), 3–4 lighttpd 8080 (inny nagłówek `Server`), 5 przekierowanie 301 na `/start/` |
| 900 ≤ `i` < 950 | 5 % | host żywy, każdy port TCP zamknięty (RST) |
| 950 ≤ `i` < 1000 | 5 % | host odpowiada tylko na ICMP (TCP i UDP odrzucane bez odpowiedzi) |

Strony mają tytuł z adresem (`Farm host 10.77.0.1`), więc wynik każdego adresu da się sprawdzić osobno. Hasła SSH są wyłączone (`dropbear -s`).

## Dlaczego sieć routowana

Tablica sąsiadów (ARP) jądra jest jedna dla całego hosta Dockera, a jej limit (`gc_thresh3`) to często 1 024 wpisy (`e2e/neigh-check.sh`). Tysiące adresów w jednym mostku zapełniłyby ją i zepsuły każdy kontener na maszynie. Dlatego:

- farmy stoją w sieci `czscale-net` (10.78.0.0/24, `internal`, bez wyjścia na zewnątrz), farma `K` pod 10.78.0.(10+K), skaner pod 10.78.0.2;
- skaner ma trasy: `10.77.4(K−1).0/22 via` farma `K` oraz `10.77.0.0/16 via` farma 1 (`scale.sh routes`);
- adresy /16, których nie ma żadna farma, trafiają do farmy 1 i giną bez odpowiedzi (przekazywanie wyłączone, reguła `fib daddr type != local drop`): to martwe adresy, żaden pakiet nie wychodzi poza laboratorium;
- skaner potrzebuje jednego wpisu sąsiada na farmę, a nie na adres.

Dla skanera to zwykła zdalna sieć /16 za routerem: wykrywanie hostów idzie przez ICMP i TCP, nie przez ARP. Adres mostka hosta (10.78.0.1) jest poza skanowanym zakresem, a polityka produktu ma `CZUJKA_ALLOWED_NETWORKS=10.77.0.0/16`.

## Uruchomienie

```sh
lab/scale/scale.sh build                       # obraz farmy (alpine, około 30 MB)
lab/scale/scale.sh up 2                        # 2 farmy = 2 000 żywych adresów
lab/scale/scale.sh truth 2 > truth.json        # prawda wzorcowa (format lab/ground-truth), te same reguły co farma
# produkt: binarka z -tags embedui w katalogu bin/, obraz z czujka.Dockerfile, potem
docker compose --env-file .env -f lab/scale/compose.yml up -d --wait
lab/scale/scale.sh routes czscale-czujka-1 2   # trasy w przestrzeni sieciowej Czujki
lab/scale/measure.sh setup                     # zakres 10.77.0.0/16, profil domyślny
lab/scale/measure.sh run r1                    # przebieg: czasy, pakiety na łączu, pamięć, baza, eksport
lab/scale/measure.sh run r1 10000 50           # to samo z limitem 10 000 pakietów/s i http_rps 50 (maksimum domyślnej polityki)
lab/scale/measure.sh api RUN r1                # czasy list, eksportów i raportu
go run ./e2e/score -truth truth.json -export export-r1.json
lab/scale/scale.sh stop-farm 2                 # zmiana: znika 1 000 adresów
lab/scale/scale.sh down                        # sprzątanie
```

Na gęstej sieci czas przebiegu wyznacza etap HTTP, nie pakiety: każda usługa WWW dostaje około 13 żądań GET/HEAD, a profil domyślny wysyła 20 żądań na sekundę dla wszystkich hostów razem (`rate.http_rps`).

`.env` dla `compose.yml`: `CZS_DB_PASSWORD`, `CZS_ADMIN_PASSWORD`, `CZS_TAG` (znacznik obrazu `czscale-czujka`), `CZS_PORT` (UI tylko na 127.0.0.1). Wyniki pomiarów: `e2e/results/scale/`.
