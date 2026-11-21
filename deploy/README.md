# Czujka: uruchomienie i szyfrowanie danych

## Start

```sh
cp deploy/.env.example deploy/.env        # ustaw własne sekrety
docker compose -f deploy/docker-compose.yml up -d --build --wait
# albo: make up
```

Stos startuje także bez `deploy/.env`. Wtedy baza jest dostępna tylko w sieci wewnętrznej, klucz główny
powstaje w wolumenie `czujka-keys`, a losowe hasło pierwszego administratora pojawia się raz w logu:

```sh
docker compose -f deploy/docker-compose.yml logs czujka | grep -A3 "first administrator"
```

Interfejs i API: `http://127.0.0.1:8080` (`CZUJKA_BIND`, `CZUJKA_PORT`). Stan: `GET /healthz`.

## Usługi

| Usługa | Obraz | Uwagi |
| --- | --- | --- |
| `db` | `deploy/db` (Percona Distribution for PostgreSQL 17 + `pg_tde`) | bez opublikowanego portu, sieć `internal` |
| `czujka` | `deploy/Dockerfile` (statyczna binarka Go, Alpine, nmap) | użytkownik `czujka` (10001), `cap_drop: ALL`, `cap_add: NET_RAW, NET_ADMIN`, system plików tylko do odczytu |

nmap dostaje surowe gniazda przez uprawnienia pliku (`setcap`), więc proces nie działa jako root.

## Szyfrowanie danych w spoczynku

1. **Warstwa 1: `pg_tde`.** Każda tabela używa metody dostępu `tde_heap`, WAL jest szyfrowany.
   Klucz główny bazy leży w osobnym wolumenie `czujka-tde-keys`. `CZUJKA_TDE=require` zatrzymuje start,
   gdy choć jedna tabela nie jest zaszyfrowana. `GET /healthz` pokazuje `tde: true` i liczbę tabel.
2. **Warstwa 2: szyfrowanie pól (AES-256-GCM, klucz danych na rekord, opakowany kluczem głównym).**
   Obejmuje: klucz API DefectDojo, surowe wartości cookies, surowe treści odpowiedzi i fragmenty dowodów, notatki analityków.
   Klucz główny: `CZUJKA_MASTER_KEY` albo plik `CZUJKA_MASTER_KEY_FILE`.

Sprawdzenie:

```sh
docker compose -f deploy/docker-compose.yml exec db psql -h 127.0.0.1 -U czujka -d czujka -c \
  "SELECT c.relname, am.amname, pg_tde_is_encrypted(c.oid) FROM pg_class c JOIN pg_am am ON am.oid = c.relam
   WHERE c.relkind = 'r' AND c.relnamespace = 'public'::regnamespace ORDER BY 1"
```

### Rotacja klucza głównego

```sh
NEW=$(docker compose -f deploy/docker-compose.yml exec -T czujka czujka genkey)
OLD=<dotychczasowy klucz>
docker compose -f deploy/docker-compose.yml exec -T \
  -e CZUJKA_MASTER_KEY="$NEW" -e CZUJKA_MASTER_KEY_OLD="$OLD" czujka czujka rotate-key
# potem ustaw CZUJKA_MASTER_KEY=$NEW w deploy/.env i uruchom ponownie usługę czujka
```

Rotacja opakowuje na nowo tylko klucze danych, więc jest szybka i można ją bezpiecznie powtórzyć.
Start z kluczem, który nie pasuje do bazy, kończy się czytelnym błędem.

### Ograniczenia

- `pg_tde` nie szyfruje katalogów systemowych, statystyk (`pg_statistic`) ani plików tymczasowych.
  Dlatego dane wrażliwe mają dodatkowo warstwę 2.
- Dostawca kluczy `pg_tde` to plik w wolumenie. W produkcji użyj Vault albo KMIP.
- Bez `deploy/.env` hasło roli bazy ma wartość domyślną. Baza nie ma wtedy żadnej trasy na zewnątrz, ale w produkcji ustaw własne hasło.

## Polecenia binarki

`czujka serve`, `czujka migrate`, `czujka user create --email E --role R [--password P] [--reset]`,
`czujka rotate-key`, `czujka genkey`, `czujka healthcheck`, `czujka version`.
Konfiguracja: zmienne `CZUJKA_*`, patrz `deploy/.env.example` i `internal/config`.

## Programowanie

```sh
make dev                # baza w dockerze (127.0.0.1:55432) + czujka na 127.0.0.1:8080
make test               # gofmt, build, vet, testy jednostkowe
make test-integration   # wszystkie testy na prawdziwym PostgreSQL z pg_tde
make bench              # ingest 10 000 hostów x 3 usługi + czasy API
```
