# Zoo: test uogólnienia na usługach spoza laboratorium

Zoo sprawdza, jak Czujka rozpoznaje usługi, których nie ma w laboratorium `lab/`: około 75 portów
popularnego oprogramowania (CMS-y, monitoring, narzędzia deweloperskie, serwery Java, aplikacje
szkoleniowe, bazy i brokery, zdalny dostęp i poczta, proxy) oraz osobny **zbiór odłożony** (20 usług,
23 porty), którego nie oglądaliśmy przy strojeniu. Wyniki są w `RESULTS.md`.

## Zasady bezpieczeństwa

- Usługi i Czujka działają tylko wewnątrz jednego kontenera docker:dind („maszyna zoo”, `czzoo-dind`,
  najwyżej 3 CPU). Czujka skanuje cel `localhost` = bramę sieci tej maszyny, a blokada operatora
  `CZUJKA_ALLOWED_NETWORKS` to ta brama /32: żaden pakiet nie wychodzi poza maszynę.
- Na zewnątrz publikowany jest tylko interfejs Czujki, na `127.0.0.1`.
- Profil skanowania: kopia profilu domyślnego (bez zmian), czyli ten sam tryb bezpieczny co w produkcie.

## Pliki

| Plik | Zawartość |
| --- | --- |
| `batches/*.yml` | partie usług (docker compose); połowa portów poza domyślnymi |
| `batches/held-*.yml` | zbiór odłożony: opis prawdy napisany przed pierwszym skanem, skanowany raz, na końcu |
| `truth.tsv` | opis prawdy: obraz, port, usługa, produkt (wyrażenie), wersja, technologie, klasy, akceptowane etykiety dodatkowe (`ok`) |
| `dind.sh` | buduje Czujkę, stawia maszynę zoo, uruchamia partie, kopiuje wyniki do `out/<faza>/<partia>` |
| `run.sh` | wewnątrz maszyny: start partii, czekanie na gotowość, skan Czujką przez REST API, eksport, `nmap -sV` dla porównania |
| `pull.sh`, `capture.sh` | pobranie obrazów; zapis prawdziwej odpowiedzi usługi (GET) do danych testowych sygnatur |
| `score/` | ocena: dla każdego portu znaleziony / nazwany / produkt / wersja / technologie / klasy / błędne etykiety; to samo dla `nmap -sV` |
| `rematch/` | ponowne dopasowanie sygnatur do zapisanego eksportu (szybka ocena zmian bez skanu) |
| `transcript.txt` | dziennik przebiegów |
| `results/` | tabele ocen (Markdown) każdej fazy |

## Odtworzenie

```
e2e/zoo/pull.sh                                              # obrazy do lokalnej pamięci dockera
ZOO_PHASE=before ZOO_NMAP=1 e2e/zoo/dind.sh                  # wszystkie partie strojenia
go run ./e2e/zoo/score -phase before                         # ocena
ZOO_PHASE=held ZOO_NMAP=1 e2e/zoo/dind.sh held-1 held-2      # zbiór odłożony
go run ./e2e/zoo/score -phase held
```

`ZOO_KEEP=1` zostawia maszynę po przebiegu, `ZOO_NOBUILD=1` używa gotowego obrazu `czujka:$CZUJKA_VERSION`,
`ZOO_CPUS` zmienia limit CPU (domyślnie 3).
