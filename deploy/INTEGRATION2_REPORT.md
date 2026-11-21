# Integration part 2: report

Branch `iwosmu/czujka-core`. Date 2026-11-21.

## What is wired

| Package | Change |
| --- | --- |
| `internal/wire` | `Build` connects the real scan engine (`enginewire.New`: nmap prober, HTTP/TLS collector with `collector.Wait = scan.HTTPWait`, shared signature engine), sigwire (seed, load, reload on change, `UpdateMatchCounts` after every analysed run and import), the full target parser, the run window function, `scan.PauseCause`, reports, passive sources and the signature importer. `Start` runs the scheduler loop (`enginewire.Scheduler`, interval `CZUJKA_SCHED_INTERVAL`). The duplicate scheduler and target code is removed; `enginewire` is the one implementation. The diff port scope uses `probe.EffectivePorts`, so `top-N` no longer counts as all ports. |
| `internal/runner` | `context.WithCancelCause`: pause and shutdown cancel with `PauseManual`, emergency stop with `PauseEmergency`, cancel with nil. |
| `internal/api` | New routes: `POST /signatures/import`, `GET /runs/{id}/report.html` and `.md`, `POST /passive/import`, `/passive/ptr`, `/passive/crtsh` (409 until an admin enables it), `/passive/confirm`, `GET/PUT /settings/passive`. `/healthz` shows `engine` and `probe {prober, raw_sockets, mode}`. `discovery.mode` defaults to `balanced` and is validated. |
| `internal/store` | Migration 0003: `chunks.work_group` (persists `model.Chunk.Group`). Passive settings. `AddHostnames` (PTR names, respects overrides). |
| `internal/config` | `CZUJKA_SCHED_INTERVAL`, `CZUJKA_NMAP_PATH`, `CZUJKA_FORCE_NATIVE`. |
| `deploy/` | Dockerfile builds the web UI and the binary with `-tags embedui`; runtime runs as uid 10001 with file capabilities on nmap (`cap_net_raw,cap_net_admin+eip`) and czujka (`cap_net_raw+ep`). Compose serves the whole product on one port; the DB has the unique alias `czujka-postgres`. `docker-compose.scan-network.yml` attaches Czujka to an external docker network. |
| `e2e/full` | `lab.sh` (10 real services on `czfull-net` 10.91.0.0/22) and `run.sh` (52 checks, REST API only, tcpdump sidecar for packet evidence, cleans up). |

`internal/model`: nothing added or changed.

## Evidence

- `gofmt -l cmd internal`: empty. `go build ./...`, `go vet ./...`: pass.
- `go test -count=1 -p 2 ./...` with the real pg_tde database (`CZUJKA_TEST_REQUIRE_TDE=1`): every package passes except `internal/enginewire` `TestSchedulerBackendWithRealStoreAndRunner` (see Gaps).
- `make e2e-core` (project `czfull-core`, port 18493): `E2E OK: every check passed`, 24 checks.
- `e2e/full/run.sh`: **PASS 52, FAIL 0**. Transcript: `e2e/full/transcript.txt`.
- `/healthz` in the container: `{"engine":true,"probe":{"mode":"nmap-raw","prober":"nmap","raw_sockets":true}}`, process uid 10001.

## Measurements (last e2e/full run, /22 with 10 live hosts, top-1000 + 3 ports, service detection, HTTP)

| | Run 1 | Run 2 |
| --- | --- | --- |
| Wall time | 74 s | 136 s |
| Packets | 17 301 | 17 287 |
| Average rate | 234 pps (cap 800) | 127 pps (cap 800) |
| HTTP requests | 77, 1 req/s average (cap 20 req/s) | 86, 0.6 req/s (cap 20 req/s) |

- Memory of the Czujka container during all scans: max 99.9 MiB (174 samples, every 2 s).
- Retro-hunt over stored observations: 3 hits, 0 packets to lab hosts (tcpdump).
- Scan window closing mid-run: paused with `window_closed` after 2 of 5 chunks; the scheduler resumed it when the next window opened (+2 s); completed. No `service_gone` outside the scanned ports.
- Emergency stop: the API call took 0.06 s; no nmap process after 1 s; 0 IP packets (SYN, ICMP, HTTP) after the stop. The kernel still sends ARP requests for about 2 s: neighbour-resolution retries for addresses nmap had asked about (layer 2, no probe reaches a service). Removing them needs `ip neigh flush` (NET_ADMIN in the czujka process) or a lower `mcast_solicit`; not done.

## Gaps and next steps

- `internal/enginewire` `TestSchedulerBackendWithRealStoreAndRunner` fails (HostsUp 2, want 1). It fails the same way on a clean checkout of `iwosmu/agh-orchestrated-kickoff`, so it is in the engine worker's package, not caused by this work. Reproduce: `CZUJKA_TEST_DB_URL=... go test -count=1 -run TestSchedulerBackendWithRealStoreAndRunner ./internal/enginewire`.
- `internal/sigwire` `TestRetroHuntScale` failed once on its heap bound under parallel load (`-p 4`); it passes alone and passed in the last full run. It is a flaky measurement in the signature worker's package.
- UDP profile fields (`udp {enabled, ports}`) are not in `internal/model` yet, so they are not stored or validated.
- The last e2e/full run used the image built before two small changes (shutdown cancel cause, `discovery.mode` default and validation). Both are covered by unit and integration tests.
- Part 3 (queued): manual hosts and services, findings files, DefectDojo depth, host_missing, AllowedNetworks, the ten UI mismatches from `web/REPORT-REAL-BACKEND.md`, and the wiring notes in `gaps-libs-report.md`.
