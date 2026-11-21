# Czujka bez kontenerów: binarka i systemd

Ten katalog opisuje instalację na zwykłym serwerze Linux (amd64 albo arm64). `make release` buduje statyczne binarki z wbudowanym interfejsem i pakuje je razem z tymi plikami.

## Wymagania

- Linux z systemd (sprawdzone środowisko docelowe: Debian 12, Ubuntu 24.04, AlmaLinux 9).
- **PostgreSQL 17 z rozszerzeniem `pg_tde`**: Percona Distribution for PostgreSQL 17 (wolne oprogramowanie). Bez `pg_tde` ustaw `CZUJKA_TDE=auto`: Czujka wystartuje i zgłosi brak szyfrowania bazy w `czujka doctor`.
- **nmap 7.80 lub nowszy** (`apt install nmap`, `dnf install nmap`).
- Do kopii zapasowych: `pg_dump` i `pg_restore` w wersji 17 (`postgresql-client-17`).

## Instalacja

1. Rozpakuj archiwum dla swojej architektury:
   ```sh
   tar -xzf czujka-<wersja>-linux-amd64.tar.gz && cd czujka-<wersja>-linux-amd64
   ```
2. Utwórz użytkownika i zainstaluj pliki:
   ```sh
   sudo useradd --system --home /var/lib/czujka --shell /usr/sbin/nologin czujka
   sudo install -m 0755 czujka /usr/local/bin/czujka
   sudo install -d -m 0750 -g czujka /etc/czujka
   sudo install -m 0640 -g czujka czujka.env /etc/czujka/czujka.env
   sudo install -m 0644 czujka.service /etc/systemd/system/czujka.service
   ```
3. Przygotuj bazę (rola i baza `czujka`; z `pg_tde` rozszerzenie musi być w `shared_preload_libraries`):
   ```sh
   sudo -u postgres psql -c "CREATE ROLE czujka LOGIN PASSWORD '<hasło>'" -c "CREATE DATABASE czujka OWNER czujka"
   ```
   Konfigurację `pg_tde` (klucz, dostawca kluczy, szyfrowanie WAL) pokazuje `deploy/db/initdb` w repozytorium; te same polecenia SQL działają na serwerze Percony.
4. Uzupełnij `/etc/czujka/czujka.env`: `CZUJKA_DB_URL`, `CZUJKA_ADMIN_EMAIL`, `CZUJKA_ALLOWED_NETWORKS`.
5. Sprawdź instalację i uruchom usługę:
   ```sh
   sudo -u czujka env $(sudo grep -v '^#' /etc/czujka/czujka.env | xargs) /usr/local/bin/czujka doctor
   sudo systemctl daemon-reload && sudo systemctl enable --now czujka
   journalctl -u czujka -f
   ```
   `czujka doctor` podaje dla każdego błędu polecenie naprawy po polsku.

## Co ustawia jednostka

- Czujka działa jako użytkownik `czujka`, bez roota. Dostaje tylko `CAP_NET_RAW` i `CAP_NET_ADMIN` jako zdolności otoczenia (`AmbientCapabilities`); nmap dziedziczy je i wysyła sondy SYN, ICMP i ARP.
- System plików jest tylko do odczytu poza `/var/lib/czujka` (`ProtectSystem=strict`, `StateDirectory=czujka`).
- `ExecStartPre` uruchamia migracje bazy przed każdym startem.

## Dostęp z sieci

Słuchaj na `127.0.0.1:8080` i postaw przed Czujką serwer pośredniczący z TLS (Caddy, nginx). Ustaw wtedy `CZUJKA_TRUST_PROXY=true` i `CZUJKA_COOKIE_SECURE=true`. Szczegóły i zabezpieczenia instancji publicznej: `docs/WDROZENIE.md`, rozdział 5.

## Kopia zapasowa

```sh
sudo -u czujka env $(sudo grep -v '^#' /etc/czujka/czujka.env | xargs) czujka backup     # /var/lib/czujka/backups/czujka-<czas>.czbk
sudo systemctl stop czujka
sudo -u czujka env $(sudo grep -v '^#' /etc/czujka/czujka.env | xargs) czujka restore -i <plik> --force
sudo systemctl start czujka
```
Archiwum jest zaszyfrowane kluczem pochodnym klucza głównego. Bez klucza głównego go nie odtworzysz.

## Ograniczenia

Jednostki nie uruchomiono w tym sprawdzeniu na hoście z systemd. Sprawdzone: obie binarki budują się statycznie, `czujka version` działa na linux/arm64 i linux/amd64 (emulacja), a binarka arm64 w czystym Alpine (bez tzdata i bez nmap) serwuje wbudowany interfejs i API z bazą PostgreSQL 17 z `pg_tde` (21 z 21 tabel zaszyfrowanych; bez nmap silnik używa własnego probera TCP connect). Binarka zawiera bazę stref czasowych (`time/tzdata`).
