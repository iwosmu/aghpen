# Czujka — architecture and build contract

Czujka ("sentinel") is an Attack Surface Intelligence tool for cyclic discovery scans of large networks (10 000+ addresses).
This file is the contract for everyone who builds a part of it. The brief and the scoring are in `PROBLEM_DEFINITION.md`.

## 1. What wins (scoring → design)

| Weight | Criterion | Our answer |
| --- | --- | --- |
| 30% | Discovery and service identification in a large network | nmap-based multi-stage engine, adaptive chunks, density-first ordering, retries; measured against lab ground truth (precision/recall) |
| 15% | Change detection, unstable hosts, reporting | Bayesian hour-of-week availability model, change log with "expected" flag, diff of any two runs |
| 20% | Technical quality, docs, ease of start, import/export, DefectDojo | one Go binary + `docker compose up`, nmap XML/JSON/CSV in and out, DefectDojo push and re-import |
| 15% | Safety, intensity control, dashboard clarity | global safety policy, traffic budget before start, token buckets, emergency stop, safe-signature validator, 3-30-300 dashboard |
| 10% | Fingerprinting, technologies, CMS, headers, cookies, signatures | native HTTP/TLS collector, YAML signature DSL, 150+ built-in signatures, confidence by noisy-OR, retro-hunt |
| 10% | Roles and data protection | permission-based RBAC with the 4 required roles + custom roles, audit log, TDE + field-level AES-256-GCM |

## 2. Components

```text
                +-------------------- czujka (one Go binary) --------------------+
 browser  <---> | api (REST + SSE, RBAC, audit)  <->  store (PostgreSQL, pgx)   |
                |   ^            ^                         ^                    |
                |   |            |                         |  ResultSink        |
                | sched ----> scan engine --> probe (nmap, native TCP)          |
                | (cron,        |  chunk planner, rate limiter, window guard    |
                |  windows)     +--> httpfp (HTTP/TLS collector) --> sig engine |
                |                                                               |
                | analyze (diff, stability, interest, grouping, findings)       |
                | interchange (nmap XML / JSON / CSV)   defectdojo (API v2)     |
                +---------------------------------------------------------------+
        PostgreSQL 17 with pg_tde (encryption at rest)        DefectDojo (optional)
```

Data flow of one run: targets → expand, apply exclusions → plan chunks → per chunk: host discovery → port scan → service detection → HTTP/TLS fingerprint → signatures → `ResultSink.OnHost` → store → after the last chunk: analysis (stability, diff, interest, grouping, findings) → dashboard, optional DefectDojo push.
Imported results (nmap XML, JSON, CSV) become `HostResult` records and enter at `ResultSink.OnHost`. They go through the same analysis.

## 3. Packages

The seams are the interfaces in `internal/model/contracts.go`. A package depends on those interfaces, not on another package's concrete types.

- `internal/targets` — parse IP, CIDR, range, domain; CSV and JSON target files; expansion and counting without materialising all addresses; exclusion subtraction; resolve domains.
- `internal/scan` — implements `model.Engine`. Chunk planner, worker pool, rate limiter, window guard, retries, progress and ETA. Uses `internal/probe`.
- `internal/probe` — nmap wrapper (`-oX -` XML parsing, privilege detection: SYN scan with raw sockets, connect scan without) and a native Go TCP-connect prober as a fallback when nmap is missing.
- `internal/sched` — schedules (cron or interval), time windows, next-run computation, the pause-at-window-end and resume-in-next-window rule.
- `internal/httpfp` — implements `model.Fingerprinter`.
- `internal/sig` — implements `model.SignatureEngine`; DSL parser, safe-mode validator, matcher, retro-hunt over stored observations. Built-in rules live in `signatures/*.yaml` and are embedded.
- `internal/analyze` — pure functions: stability model, diff, interest score, grouping key, finding derivation.
- `internal/interchange` — importers and exporters (pure: bytes ↔ model types).
- `internal/defectdojo` — API v2 client.
- `internal/crypto` — envelope encryption for sensitive fields, key rotation.
- `internal/store` — PostgreSQL schema (embedded migrations), repositories, the store-backed `ResultSink`.
- `internal/auth` — users, password hashing (argon2id), sessions, permission checks.
- `internal/api` — HTTP handlers per `docs/API.md`, SSE, audit middleware, serves the embedded UI.

## 4. Algorithms (the answers to the questions the brief asks)

### 4.1 Adaptive chunks and scan time

- Expand targets lazily into /24-aligned blocks. A chunk is a list of blocks, sized in addresses.
- Order: blocks with hinted live hosts first (density-first), then the rest. A run that is cut by its window has then already covered the known hosts.
- First chunks use `chunking.initial_size`. After each chunk: `next = clamp(size * target_seconds / measured_seconds, min_size, max_size)`, smoothed (EWMA) so one slow chunk does not collapse the size.
- Each chunk records duration, hosts up and packets per second. The run keeps `elapsed`, `avg_pps`, `eta`. The estimate before a run uses the measured speed of earlier runs of the same profile when it exists.
- Window guard: when `now + estimated chunk time > window_end` the engine starts no new chunk, lets running chunks finish or cancels them at `window_end`, marks the rest `deferred`, and returns `paused / window_closed`. The scheduler resumes the same run at the next window start with the remaining chunks.

### 4.2 Rate control

- One token bucket for probe packets (`min(profile.max_pps, policy.max_pps)`), split between parallel nmap processes through `--max-rate`.
- One token bucket for HTTP requests, plus a per-host limiter and per-host concurrency.
- The safety policy also filters ports (`allowed_ports`, `denied_ports`) and subtracts exclusions before planning. `emergency_stop` cancels the context of every running engine at once (traffic stops within about a second), sets the runs to `paused` with reason `emergency_stop`, and blocks new runs and resumes. No result is lost: after the release an operator resumes a paused run and it continues with its remaining chunks.

### 4.3 Unstable hosts: when is a host inactive?

- Per host keep a 168-bucket hour-of-week histogram of up/down observations (Beta prior, `a=1, b=1`).
- Inside a run, a hinted host that does not answer gets `retry.unstable_retries` extra probes with backoff and a second probe method before a miss is recorded.
- After a miss, compute `p_alive` by Bayes: prior `p0` (from age and stability), likelihood of the observed miss sequence given "alive" from the bucket up-rates of the hours in which the misses happened. A miss at an hour when the host is usually off barely lowers `p_alive`; a miss at an hour when it always answers lowers it sharply.
- Status: `up` (answered now) → `expected-offline` (missed, but the profile explains it) or `unstable` (missed, `p_alive >= 0.2`) → `down` (`p_alive < 0.2`, reported as `host_gone`). So a stable server is reported inactive after about 2 missed runs, a host that is up half of the time after about 5, and a host that is off every night is not reported at night at all. `down_after_misses` is shown in the UI.
- A change that the profile explains is stored with `expected = true` and kept out of the headline numbers.

### 4.4 Confidence of technology identification

- Every matcher has a weight in 0..1 (header regex 0.6, exact favicon hash 0.9, generic body word 0.3 ...). A signature's confidence is the noisy-OR of its matched matchers: `1 - Π(1 - w_i)`.
- A technology's confidence is the noisy-OR over all signatures and nmap evidence that name it. Version confidence is tracked the same way; versions that disagree lower it.
- The UI shows confidence as a value with its evidence list ("why do we think so"), never as a bare label.

### 4.5 Interest score (0..100)

Additive points with reasons (`InterestReason`), capped at 100: admin panel, login page, staging/test environment, IoT device, dev tool, database or remote access exposed, expired or self-signed certificate, new exposure since the last run, rare technology in this network (small group), outdated version, missing security headers on a login page, scope criticality. The reasons are shown to the analyst.

### 4.6 Grouping

`group_key` = hash of (favicon hash | title template | sorted technology names | header-name set | body simhash bucket). Services with the same key are one group; small groups are "rare".

### 4.7 Edits survive scans

Analyst edits are stored in `overrides` per entity (`field → {value, observed, by, at}`). The ingest path writes observed values to the observed columns and never touches an overridden field. The UI shows both values. Notes, tags, labels, owner, criticality and finding status are analyst-owned fields and are never written by a scan.

## 5. Data protection

1. **Encryption at rest, whole database:** PostgreSQL with `pg_tde` (Percona, open source); every table uses the `tde_heap` access method. Fallback if `pg_tde` cannot run on the host: document the reason and use an encrypted volume.
2. **Field-level encryption:** AES-256-GCM envelope encryption in `internal/crypto` for high-sensitivity fields: integration credentials, raw cookie values, raw response bodies and evidence, analyst notes. Data keys are wrapped by a master key from `CZUJKA_MASTER_KEY` or a key file; `czujka rotate-key` re-wraps.
3. Passwords: argon2id. Sessions: random 256-bit tokens, stored hashed, HttpOnly + SameSite=Strict cookie, CSRF token on mutating requests.
4. Every mutating request and every login attempt goes to the audit log.

## 6. Roles

Permission-based. Built-in roles (not deletable) and the mapping to the brief:

| Role | Brief | Permissions |
| --- | --- | --- |
| `admin` | Administracja | all |
| `editor` | Dodawanie, usuwanie, modyfikacja | read + create + update + delete of targets, results, signatures; run and configure scans; export |
| `analyst` | Modyfikacja i odczyt | read + update (targets, results, signatures); run scans; export |
| `viewer` | Odczyt | read only |

Admins can create custom roles from the permission list. The API enforces permissions; the UI hides what the user cannot do.

## 7. Conventions

- REST under `/api/v1`, JSON, snake_case. Lists return `Page<T>`. Errors: `{"error": {"code": "...", "message": "..."}}` with a fitting HTTP status. Times are RFC 3339 UTC.
- Config by environment variables with the `CZUJKA_` prefix (`CZUJKA_DB_URL`, `CZUJKA_MASTER_KEY`, `CZUJKA_LISTEN`, `CZUJKA_ADMIN_EMAIL`, `CZUJKA_ADMIN_PASSWORD`).
- Logging: `log/slog`, JSON in production.
- The product starts with `docker compose -f deploy/docker-compose.yml up`. The lab starts with `docker compose -f lab/docker-compose.yml up`.
