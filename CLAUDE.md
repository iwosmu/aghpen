# Czujka — project instructions for agents

Czujka is the entry for the CBI AGH challenge "Attack Surface Intelligence" at HackNation 2026.
Read `docs/PROBLEM_DEFINITION.md` (the brief and scoring) and `docs/ARCHITECTURE.md` (the contract) before you write code.

## Hard rules

- **Deadline: Sunday 2026-11-22 11:00 Europe/Warsaw.** Working software first. No speculative abstractions.
- **Safe detection only.** The scanner detects presence of features. It never logs in, never sends payloads, never brute-forces, never uses a method other than GET or HEAD, never runs intrusive nmap scripts. This is a scored criterion.
- **Real paths only.** No mock data in the product, no faked results, no stubbed integrations presented as working. Tests may use fakes. If a real dependency is unavailable, report a concrete blocker.
- **Free and open-source dependencies only** (challenge rule). No paid APIs, no licence-gated tools.
- `internal/model` is the shared contract. Do not change an existing field or JSON tag there. You may add a field when you need one; say so in your final report.
- Stay inside the paths your task owns. If you must touch a file outside them, keep the change minimal and list it in your report.
- Backend is Go (standard library first; allowed: chi, pgx v5, yaml.v3, x/crypto, x/time/rate, robfig/cron, and small focused libraries). Frontend is React + TypeScript + Vite in `web/`.
- UI text is Polish by default with an English toggle. Code, comments, commit messages and API field names are English. Technical documentation for the jury (`docs/`, README) is Polish.
- Every Go package has unit tests for its logic. `go build ./... && go vet ./... && go test ./...` must pass before you report done. Run `gofmt -w` on what you touch.
- Commits: Conventional Commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `chore:` ...). No AI attribution lines of any kind. Commit your work on your branch; do not push; do not merge.
- Scan only: the lab networks under `lab/`, `127.0.0.1`, and `scanme.nmap.org` (one light probe at most). Never scan any other address.

## Layout and ownership

| Path | Content |
| --- | --- |
| `cmd/czujka` | single binary entry point |
| `internal/model` | shared types and interfaces (contract) |
| `internal/targets`, `internal/scan`, `internal/probe`, `internal/sched` | target parsing, chunk planner, scan engine, nmap wrapper, scheduler and windows |
| `internal/httpfp`, `internal/sig`, `signatures/` | HTTP/TLS collector, signature DSL and engine, built-in signature library |
| `internal/analyze`, `internal/interchange`, `internal/defectdojo` | diff, stability model, interest score, grouping, findings; import/export formats; DefectDojo client |
| `internal/store`, `internal/crypto`, `internal/auth`, `internal/api` | PostgreSQL store and migrations, encryption, RBAC, REST API |
| `web/` | React UI, built into `web/dist` and embedded in the binary |
| `lab/`, `deploy/`, `e2e/` | test lab (docker compose), product Dockerfile and compose, end-to-end checks |
| `docs/` | technical documentation, slides, demo script |
