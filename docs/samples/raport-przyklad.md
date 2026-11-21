# Raport ze skanu #42

Czujka · sieć przykładowa · wygenerowano 21.11.2026 02:05

| Przebieg |  |
| --- | --- |
| Profil | Kampus – co 12 godzin (z harmonogramu) |
| Zakres | Kampus – sieć laboratoryjna · 1 024 adresy |
| Czas | 21.11.2026 02:00–02:05 |
| Porównanie z | skan #41 z 20.11.2026 14:00 |

**Nowe: 1 host i 5 usług. Nieaktywne hosty: 1. Usługi, które zniknęły: 3. Nie odpowiadają (niepotwierdzone): 1 host i 2 usługi. Czujka sprawdzi je ponownie. Znów aktywne: 1 host. Zmiany w znanych hostach i usługach: 5. Najpierw sprawdź 5 zmian o wadze średniej lub wysokiej.**

| zmiany do przejrzenia | nowych znalezisk | aktywnych hostów | otwarte usługi | usług WWW | zmian oczekiwanych |
| ---: | ---: | ---: | ---: | ---: | ---: |
| **19** (w tym 5 o wadze średniej lub wysokiej) | **11** | **58** (+2 / −1) | **143** (+5 / −3) | **36** | **9** (nie wymagają reakcji) |

## Nowe (7)

- **średnia** — Nowa usługa 10.66.3.17:8080 (Jetty 10.0.20)
- **średnia** — Nowa usługa 10.66.3.40:80 (HP LaserJet http config)
- **średnia** — Nowa usługa 10.66.3.90:6379 (Redis key-value store 7.2.4)
- **niska** — Host 10.66.2.9 znów aktywny (był nieaktywny)
- **niska** — Nowy host 10.66.3.40 (otwarte porty: 80, 631, 9100)
- **niska** — Nowa usługa 10.66.3.40:631 (ipp)
- **niska** — Nowa usługa 10.66.3.40:9100 (jetdirect)

## Zniknęły (7)

- **średnia** — Host 10.66.1.80 nie odpowiada (niepotwierdzone), miał 2 otwarte usługi
- **średnia** — Host 10.66.2.5 nieaktywny, nie odpowiada w zwykłych godzinach
- **niska** — Usługa 10.66.1.55:3306 zniknęła (MySQL 8.0.36)
- **niska** — Usługa 10.66.1.80:22 (ssh OpenSSH) nie odpowiada (niepotwierdzone), host nie odpowiada
- **niska** — Usługa 10.66.1.80:443 (https nginx) nie odpowiada (niepotwierdzone), host nie odpowiada
- **niska** — Usługa 10.66.2.5:22 zniknęła (OpenSSH 9.6p1), host nieaktywny
- **niska** — Usługa 10.66.2.5:443 zniknęła (nginx), host nieaktywny

## Zmienione (5)

- **niska** — Nowy certyfikat TLS 10.66.1.10:443: www.kampus.example, ważny do 2027-02-18
- **niska** — Zmiana wersji 10.66.1.20:80: Apache httpd 2.4.57 → Apache httpd 2.4.62
- **niska** — Zmiana nagłówków 10.66.1.60:443: usunięto Content-Security-Policy
- **informacja** — Zmiana nagłówków 10.66.1.20:80: Server: Apache/2.4.57 (Debian) → Apache/2.4.62 (Debian)
- **informacja** — Zmiana tytułu strony 10.66.1.60:443: „Portal studenta (test)” → „Portal studenta 2.0 (test)”

_Zmiany zgodne ze wzorcem dostępności: 9 (10.66.2.31, 10.66.2.32, 10.66.2.33, 10.66.2.34 i 5 innych). Nie są liczone powyżej._

## Najważniejsze znaleziska

### Panel administracyjny: Jenkins (10.66.3.17:8080)

waga: **informacja** · ciekawość **87**/100 · `http://10.66.3.17:8080/` · nowe w tym skanie · także: narzędzie deweloperskie, nowa ekspozycja, nagłówki HTTP

- `header:X-Jenkins`: 2.440.1
- `title`: Dashboard \[Jenkins\]
- `header:Server`: Jetty(10.0.20)

### Baza danych dostępna z sieci: Redis key-value store 7.2.4 (10.66.3.90:6379)

waga: **niska** · ciekawość **80**/100 · `10.66.3.90:6379` · nowe w tym skanie · także: nowa ekspozycja

- `port:6379/tcp`: Redis key-value store 7.2.4

### Przeterminowany certyfikat TLS: poczta.kampus.example (10.66.1.30:443)

waga: **niska** · ciekawość **70**/100 · `https://poczta.kampus.example/`

- `tls:certificate`: CN=poczta.kampus.example; wystawca=R11, Let's Encrypt; ważny do 2026-11-03; sha256=77a0d3e1b6c2f945

### Urządzenie IoT: HP LaserJet (10.66.3.40:80)

waga: **informacja** · ciekawość **55**/100 · `http://10.66.3.40/` · nowe w tym skanie · także: nowa ekspozycja

- `header:Server`: HP HTTP Server; HP LaserJet Pro M404dn
- `title`: HP LaserJet Pro M404dn

### Logowanie bez szyfrowania (HTTP): Dziekanat – logowanie (10.66.1.20:80)

waga: **niska** · ciekawość **50**/100 · `http://dziekanat.kampus.example/` · także: nagłówki HTTP

- `title`: Dziekanat – logowanie
- `header:Server`: Apache/2.4.62 (Debian)

### Środowisko testowe: Portal studenta 2.0 (test) (10.66.1.60:443)

waga: **informacja** · ciekawość **45**/100 · `https://staging.kampus.example/`

- `hostname`: staging.kampus.example
- `title`: Portal studenta 2.0 (test)

_Pozostałe znaleziska (7) są w aplikacji._

## Najciekawsze usługi

| Adres | Usługa | Powody | Ciekawość |
| --- | --- | --- | ---: |
| `10.66.3.17:8080` | ci.kampus.example · Jetty 10.0.20 · „Dashboard \[Jenkins\]” | Panel administracyjny dostępny z sieci (+30); Narzędzie deweloperskie (+20); i 3 inne powody | 79 |
| `10.66.3.40:80` | HP LaserJet http config · „HP LaserJet Pro M404dn” | Urządzenie IoT (+20); Nowa ekspozycja (+15); i 1 inny powód | 44 |
| `10.66.3.90:6379` | cache-01.kampus.example · Redis key-value store 7.2.4 | Baza danych dostępna z sieci: Redis key-value store 7.2.4 (+25); Nowa ekspozycja (+15) | 40 |
| `10.66.1.20:80` | dziekanat.kampus.example · Apache httpd 2.4.62 · „Dziekanat – logowanie” | Logowanie bez szyfrowania (HTTP) (+25); Strona logowania bez nagłówków bezpieczeństwa: brak Content-Security-Policy / X… (+5); i 1 inny powód | 35 |
| `10.66.1.30:443` | poczta.kampus.example · nginx · „Poczta – logowanie” | Przeterminowany certyfikat TLS: ważny do 2026-11-03 (+15); Strona logowania (+10); i 1 inny powód | 30 |

## Hosty niestabilne i nieaktywne

| Host | Stan | Wzorzec dostępności | Szansa, że działa | Aktywny (% skanów) | Skany bez odpowiedzi z rzędu |
| --- | --- | --- | ---: | ---: | ---: |
| `10.66.2.5` git.kampus.example | nieaktywny | aktywny stale (96% skanów) | 4% | 96% | 2 |
| `10.66.1.80` pliki.kampus.example | niestabilny | aktywny stale (98% skanów) | 27% | 98% | 1 |
| `10.66.2.77` | niestabilny | aktywny w ok. 50% skanów, bez wzorca | 58% | 51% | 1 |
| `10.66.2.31` oraz 7 hostów o tym samym wzorcu | poza godzinami | zwykle aktywny pn–pt 14–15 | 76% | 38% | 1 |

## Parametry skanu

| Parametr | Wartość |
| --- | --- |
| Porty | top-100 |
| Wykrywanie hostów | ICMP echo, TCP SYN na porty 22, 80, 443, ARP w sieci lokalnej |
| Rozpoznawanie usług | tak, intensywność 5 z 9 |
| Zbieranie HTTP i TLS | tak; dodatkowe ścieżki sygnatur (najwyżej 8 na usługę); do 3 przekierowań |
| Limity profilu | do 100 pakietów/s, do 10 żądań HTTP/s, 2 połączenia naraz na host |
| Polityka bezpieczeństwa | do 300 pakietów/s, do 20 żądań HTTP/s, do 2/s na jeden host |
| Metody HTTP | GET, HEAD |
| Porty zabronione | 9100-9103 |
| Wykluczenia | 10.66.0.1, 10.66.0.128/28 |
| User-Agent | Czujka/1.0 (+https://czujka.kampus.example/o-skanerze) |

## Wysłany ruch

| Miara | Wartość |
| --- | --- |
| Sprawdzone adresy | 1 024 z 1 024 |
| Wysłane pakiety (szacunek) | 14 260 |
| Żądania HTTP | 412 |
| Średnie tempo | 44,8 pakietów/s (45% limitu 100) |
| Czas aktywnego skanowania | 5 min 18 s |
| Podgrupy | 16 z 16 |
| Hosty sprawdzone ponownie | 11 |
| Błędy | 0 |

Metody HTTP dozwolone w tym skanie: GET, HEAD.

