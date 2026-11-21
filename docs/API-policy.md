# API: reguły ekspozycji i sygnatura z przykładu

Trasy pakietów `internal/rules` i `internal/sigsuggest`. Prefiks: `/api/v1`. Uwierzytelnianie, CSRF, audyt i koperta błędów są takie same jak w [API.md](API.md): błąd ma postać `{"error": {"code", "message", "details"}}`. Integrator przenosi tę stronę do `API.md`.

Uprawnienia: odczyt, walidacja i próba na sucho wymagają `results:read` (reguły to widok na wyniki). Zapis reguły wymaga uprawnień sygnatur (`signatures:create`, `signatures:update`, `signatures:delete`), bo reguła to treść detekcji jak sygnatura i te same role ją edytują. Ręczne sprawdzenie zapisuje ustalenia, więc wymaga `results:update`. Propozycja sygnatury tylko czyta dane i niczego nie zapisuje: wymaga `signatures:read`, jak `/signatures/validate` i `/signatures/retrohunt`.

## Typ `Rule` (rekord)

```json
{
  "id": 3, "slug": "admin-panel-outside-mgmt", "name": "Panel administracyjny poza siecią zarządzania",
  "severity": "high", "description": "…", "yaml": "id: admin-panel-outside-mgmt\n…",
  "enabled": true, "builtin": true, "author": "czujka",
  "violations": 4, "last_eval_at": "2026-11-21T14:29:43Z",
  "created_at": "…", "updated_at": "…"
}
```

`violations` to liczba naruszeń przy ostatnim sprawdzeniu.

## Trasy reguł

| Metoda i ścieżka | Uprawnienie | Treść żądania | Odpowiedź |
| --- | --- | --- | --- |
| `GET /rules` | results:read | – | `Page<Rule>` (wbudowane najpierw, potem według `slug`) |
| `GET /rules/{id}` | results:read | – | `Rule` |
| `POST /rules` | signatures:create | `{"yaml": "...", "enabled": true?}` | 201 `{"rule": Rule, "validation": Validation}`; 422 `validation` z `details: Validation`; 409 gdy `id` zajęte |
| `PATCH /rules/{id}` | signatures:update | `{"yaml"?: "...", "enabled"?: bool}` | 200 `{"rule", "validation"}`; 409 przy zmianie tekstu reguły wbudowanej |
| `DELETE /rules/{id}` | signatures:delete | – | 204; 409 dla reguły wbudowanej (można ją tylko wyłączyć) |
| `POST /rules/validate` | results:read | `{"yaml": "..."}` | `Validation` |
| `POST /rules/dry-run` | results:read | `{"yaml": "...", "limit"?: 500}` | `DryRunResult` (nic nie zapisuje) |
| `POST /rules/evaluate` | results:update | – | `Report` (sprawdza wszystkie włączone reguły teraz) |
| `GET /rules/{id}/violations` | results:read | query: `status=new,triaged`, `limit`, `offset` | `Page<Finding>` (ustalenia tej reguły) |

Zapis, zmiana i usunięcie reguły uruchamiają w tle pełne sprawdzenie, więc lista ustaleń od razu odpowiada zestawowi reguł.

### `Validation`

```json
{"ok": false, "issues": [{"level": "error", "path": "match.port[0]", "message": "„abc” nie jest portem (0–65535) ani zakresem portów (wiersz 2)", "safety": false}]}
```

Ten sam kształt co `SignatureValidation` bez pola `paths`.

### `DryRunResult`

```json
{
  "validation": {"ok": true, "issues": []},
  "total": 7, "truncated": false, "hosts": 2000, "services": 6000, "took_ms": 55,
  "condition": "klasa admin-panel",
  "message": "Ta reguła zgłosiłaby dziś 7 naruszeń (sprawdzono 2000 hostów i 6000 usług).",
  "violations": [{
    "rule": "adm", "rule_name": "…", "severity": "high", "subject": "service",
    "key": "policy-violation|adm|10.66.1.10|8080/tcp", "host_id": 12, "ip": "10.66.1.10",
    "service_id": 40, "port": 8080, "proto": "tcp", "url": "http://10.66.1.10:8080/", "title": "Panel",
    "summary": "Reguła „…”: 10.66.1.10:8080/tcp (class: admin-panel)",
    "evidence": [{"matcher": "policy", "where": "rule", "snippet": "adm"}, {"matcher": "policy", "where": "class", "snippet": "admin-panel"}],
    "interest": 84, "storable": true
  }]
}
```

`subject`: `service`, `host` albo `scope`. `storable: false` ma tylko asercja `per: scope` na pustym zakresie (ustalenie wymaga hosta).

### `Report`

```json
{"run_id": 0, "rules": 11, "rejected": [], "hosts": 2000, "services": 6000, "violations": 1160, "stored": 1160,
 "created": 0, "resolved": 0, "by_rule": {"admin-panel-outside-mgmt": 200}, "eval_ms": 52, "store_ms": 35, "took_ms": 88}
```

`rejected` wymienia zapisane reguły, których walidator już nie przyjmuje (nie są sprawdzane).

### Ustalenia reguł

Naruszenie to zwykły `Finding` z `GET /findings`: `type: "policy-violation"`, `signature: "policy:<slug>"`, klucz `policy-violation|<slug>|<IP>|<port>/<proto>`. Filtr: `GET /findings?type=policy-violation`. Pola analityka (status, notatka, etykiety, przypisanie, ręcznie zmieniona waga i tytuł) nie są nadpisywane.

## Sygnatura z przykładu

| Metoda i ścieżka | Uprawnienie | Treść żądania | Odpowiedź |
| --- | --- | --- | --- |
| `POST /signatures/suggest` | signatures:read | `{"service_id": 15}` | 200 `Suggestion`; 404 gdy usługa nie ma obserwacji |

```json
{
  "ok": true,
  "message": "Sygnatura „Synology DSM” pasuje do przykładu i do 1 innych z 29 zapisanych usług (podobne instancje).",
  "service_id": 15, "target": "127.0.0.1:18114", "slug": "synology-dsm", "name": "Synology DSM",
  "yaml": "id: synology-dsm\nname: 'Synology DSM'\n…",
  "rules": [{"kind": "favicon", "feature": "233021496", "rule": "{type: favicon, mmh3: [233021496]}", "weight": 0.9, "df": 0, "others": 28,
             "explanation": "ikona (favicon mmh3 233021496) występuje tylko w tej usłudze i w 1 podobnych instancjach (0 z 28 pozostałych usług)"}],
  "rejected": [{"kind": "asset", "value": "/static/app.3f9a1c2b7d4e5f60.js", "reason": "ścieżka zasobu zawiera skrót albo znacznik czasu (zmienia się przy wdrożeniu)"}],
  "validation": {"ok": true, "issues": [], "paths": []},
  "retro_hunt": {"scanned": 30, "total_hits": 2, "packets_sent": 0, "hits": ["…RetroHit…"]},
  "matches_target": true, "other_matches": 1,
  "candidates": 9, "others_http": 28, "others_tls": 8, "look_alikes": 1, "history": 0, "took_ms": 7
}
```

Gdy usługa nie ma cech wyróżniających, `ok: false`, `yaml: ""` i `message` mówi dlaczego. Propozycja niczego nie zapisuje; analityk zapisuje YAML przez `POST /signatures`. Lista `retro_hunt.hits` ma najwyżej 50 pozycji (`total_hits` podaje pełną liczbę).
