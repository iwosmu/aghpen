# Limit pakietów w jądrze: pomiar

Sprawdza drugi limit pakietów sond (`internal/kcap`, `docs/BEZPIECZENSTWO.md` rozdz. 1.2.1). Oba skrypty tworzą własną sieć Dockera (`kcap-net`, domyślnie `192.168.231.0/24`) z kontenerem-celem: 30 otwartych portów TCP (`nc -l`). Skanują tylko ten kontener. Po pracy usuwają kontenery, sieć i swoje obrazy (`KCAP_KEEP=1` zostawia obrazy).

## `run.sh`: zamrożenie nmap z limitem i bez

Skaner to środowisko uruchomieniowe produktu: Alpine, nmap i `nft` z uprawnieniami pliku, użytkownik 10001, `cap_drop: ALL`, `NET_RAW` i `NET_ADMIN`, do tego tcpdump i binarka `czujka` (reguła z `czujka kcap apply`, ten sam kod co w serwerze).

| Faza | Limit w jądrze | Zamrożenie nmap |
| --- | --- | --- |
| `before` | wyłączony | 15 s (`SIGSTOP`, potem `SIGCONT`) |
| `after` | włączony | 15 s |
| `normal` | włączony | brak |
| `nocap` | wyłączony | brak |

Każda faza wypisuje pakiety SYN na sekundę z tcpdump na interfejsie skanera, licznik odrzuconych pakietów i znalezione porty.

```sh
e2e/kcap/run.sh | tee e2e/kcap/results/$(hostname)-run.txt
KCAP_PHASES="before after" KCAP_PPS=500 KCAP_FREEZE=15 e2e/kcap/run.sh
```

Wymaga Dockera i Go (buduje binarkę dla architektury serwera Dockera) albo `CZUJKA_BIN` z gotową binarką linuksową. Zmienne: `KCAP_PPS` (500), `KCAP_FREEZE` (15), `KCAP_PORTS` (`1-20000`), `KCAP_SUBNET`, `KCAP_PHASES`.

Wynik oczekiwany: w `before` jedna sekunda wielokrotnie ponad limit; w `after` każda sekunda najwyżej limit × 1,1 plus kubełek (500 → 605) i licznik powyżej zera; w `normal` licznik 0 i te same 30 portów co w `nocap`.

## `product.sh`: produkt na stosie z `deploy/`

Buduje obraz z `deploy/Dockerfile` (jako `czujka:kcap`, `czujka-db:kcap`) i uruchamia stos z nakładką `docker-compose.scan-network.yml` w sieci `kcap-net`. Sprawdza:

1. `kernel_cap` w `GET /settings/safety` i w `/healthz` (tylko administrator), wymianę reguły po `PUT max_pps`.
2. Przebieg bez zamrożenia: 0 odrzuconych, 30 usług.
3. Przebieg z nmap zatrzymanym na 15 s w środku skanu portów: notatka „jądro odrzuciło N pakietów ponad limit”.
4. Tryb sieci hosta z `CZUJKA_KERNEL_CAP=require`: `unavailable: host network`, brak tabeli w przestrzeni hosta, `POST /runs` → 409 `kernel_cap` (tylko Linux; `KCAP_SKIP_HOST=1` pomija).

```sh
e2e/kcap/product.sh | tee e2e/kcap/results/$(hostname)-product.txt
```

Wymaga `docker compose`, `curl`, `jq`. Porty: `KCAP_PORT` (18089), `KCAP_DB_PORT` (55499, tryb sieci hosta).

## Wyniki

| Plik | Maszyna |
| --- | --- |
| `results/linux-run.txt` | Ubuntu 24.04, jądro 6.8, Docker 29.9, nft 1.0.9 |
| `results/linux-product.txt` | jw., produkt |
| `results/docker-desktop-mac.txt` | Docker Desktop na macOS, jądro 6.12 linuxkit |

W fazie `before` skrypt wysyła jeden wybuch (około 7600 pakietów w sekundzie) w sieci, którą sam utworzył. Pakiety nie wychodzą poza tę sieć.
