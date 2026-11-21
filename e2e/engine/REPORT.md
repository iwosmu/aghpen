# Scan engine: worker report (task_f4b5bf9512e9)

Branch `iwosmu/czujka-engine`. All numbers below are from real runs on 2026-11-21 (Docker Desktop aarch64, nmap 7.95 in the lab container, Go 1.27.4).

## 1. What was built

### internal/targets
- `ParseValue`, `ParseText`, `ParseCSV`, `ParseJSON`, `ParseFile`: IPv4, CIDR, ranges `a.b.c.d-e.f.g.h` and `a.b.c.d-N`, domains, single IPv6, URLs (host part). Polish reasons in `model.InvalidLine`. Duplicates are counted.
- `Set`: merged IPv4 ranges. `Count`, `Subtract`, `Union`, `Blocks` (/24-aligned), `Spec`. A /8 is one range: counting is constant time.
- `Count(targets, exclusions)` and `Preview` / `PreviewOf` (returns `model.TargetPreview`) send nothing.
- `Expand`: resolves domains (A records, 3 s timeout, 16 in parallel), keeps IP → hostnames, subtracts exclusions (IPs, CIDRs, ranges, domains).

### internal/probe
- `Prober` interface with three stages: `Discover`, `PortScan`, `ServiceScan`.
- `Nmap`: arguments built in code, targets validated by regex and passed on stdin (`-iL -`), never through a shell. Privilege detection once (raw socket test): `-sS` and `-PE -PP -PS -PA` (+ARP) with raw sockets, `-sT` and connect ping without. Always `-n`, `--max-rate`, `--max-retries`, `--host-timeout`. `-sV --version-intensity N` only on the open ports (hosts grouped by port list, groups in parallel). No `--script`, `-sC`, `-A` or `-O` (a unit test checks this).
- Streaming XML parser: product, version, extrainfo, CPE, tunnel, conf → 0..1, reason, RTT, MAC, vendor.
- `Native`: Go TCP-connect discovery, port scan and passive banner read (sends no application data). Used when nmap is missing or with `ForceNative`. The log says which prober runs.
- `ParsePorts`, `EffectivePorts`, `FilterPorts`: `top-100`, `top-1000`, lists, ranges, mixes; allow-list and deny-list of the policy.
- `Limiter` (token bucket).

### internal/scan
- `scan.New(scan.Deps{Fingerprinter, Signatures, Logger, NmapPath})` implements `model.Engine`. Optional deps: `Prober`, `ForceNative`, `Resolver`, `Now`, `OnGroup`.
- Planner: /24 blocks → fixed chunks ("units"); hinted blocks first. Adaptive work groups: `next = clamp(EWMA(size * target / measured), min, max)`. Resume from `plan.Chunks` (current exclusions are applied again).
- Worker pool, one packet `Budget` split between nmap processes, limits = min(profile, policy). HTTP stage: global and per-host limiters, `max_parallel_hosts`, per-host concurrency and delay, paths capped by `max_paths_per_host`.
- Retries for hinted hosts with backoff; last round is a direct TCP connect to the hinted ports; then `OnHost` with `Up=false` and the attempt count.
- Window guard, hard stop at `WindowEnd`, deferred chunks, `RunPaused`/`PauseWindowClosed`. Cancel causes: `scan.ErrPauseManual`, `scan.ErrPauseEmergency`, `scan.ErrPauseWindow` (or `scan.PauseCause(reason)`) → `RunPaused`; anything else → `RunCancelled`.
- `EmergencyStop`: a fresh run returns `RunFailed` + `scan.ErrEmergencyStop`; a resumed run stays `RunPaused`/`emergency_stop`. Nothing is sent.
- Progress once per second; `Estimate(plan)`.

### internal/sched
- Pure functions: `InWindow`, `WindowEnd`, `NextWindowStart`, `NextAllowed`, `ValidateWindows`, `ParseCron` + `Cron.Next`, `NextRun`, `NextStart` (for `ScanProfile.NextRunAt`).
- `Scheduler` with `Tick` and `Run`. `Backend` interface (5 methods): `ScheduledProfiles`, `LastRun`, `StartRun`, `WindowPausedRuns`, `ResumeRun`. `sched.ErrBusy` is a quiet "try later".

### cmd/scanprobe and e2e/engine
- `scanprobe`: JSON line per `HostResult`, one summary line. Flags for targets, ports, pps, chunking, hints, retries, `-stop-after`, `-resume`, `-native`, `-no-arp`, `-measure-iface`, `-emergency-stop`, `-estimate`.
- `e2e/engine/lab.sh`, `run.sh`, `verify`: see `README.md` in this directory.

## 2. Evidence

### Gate

```
$ gofmt -l .            → (empty)
$ go build ./... && go vet ./... && go test -race -count=1 ./...
ok  github.com/iwosmu/aghpen/e2e/engine/verify 1.298s
ok  github.com/iwosmu/aghpen/internal/probe    1.664s
ok  github.com/iwosmu/aghpen/internal/scan     2.481s
ok  github.com/iwosmu/aghpen/internal/sched    1.249s
ok  github.com/iwosmu/aghpen/internal/targets  1.207s
```

Unit tests cover: target parsing and counting (/8 = 16 777 216, /0, overlap, exclusion subtraction), CSV and JSON files, port specs, nmap XML from four recorded fixtures (`internal/probe/testdata`, recorded from this lab), nmap argument lists, planner sizing and density-first order, budget split, window pause and resume, cancel causes, emergency stop, HTTP and signature stage with fakes, window maths (midnight crossing, both DST changes in Europe/Warsaw), cron, scheduler tick.

### Integration run

```
$ ./e2e/engine/run.sh        → E2E RESULT: PASS   (10 scenarios, exit 0)
```

A-local, `scanprobe -targets 10.77.0.0/22 -exclude 10.77.0.1,10.77.0.2,10.77.3.254 -ports top-100,6379,8765,9443 -pps 500 -measure-iface eth0`:

```
IP           UP    REASON         TRY  RTT ms    SERVICES
10.77.0.10   true  arp-response   1    0.069     80/http (nginx 1.31.9) conf=1.0
10.77.0.20   true  arp-response   1    0.036     22/ssh (OpenSSH 9.7) conf=1.0
10.77.1.30   true  arp-response   1    0.040     6379/redis (Redis key-value store 7.4.12) conf=1.0
10.77.2.40   true  arp-response   1    0.045     8765/http (SimpleHTTPServer 0.6) conf=1.0
10.77.2.41   true  arp-response   1    0.051     8081/http (SimpleHTTPServer 0.6) conf=1.0
10.77.3.50   true  arp-response   1    0.074     9443/http+ssl (SimpleHTTPServer 0.6) conf=1.0
10.77.3.60   true  arp-response   1    0.041     80/http (SimpleHTTPServer 0.6) conf=1.0
status=completed prober=nmap privileged=true sessions=1 wall=27.6s
measured on eth0: 2889 packets sent, peak 501 pps in one second (limit 500)
adaptive group sizes (addresses): [256 254 511]
```

B-routed (same scope through the router, no ARP): 7 of 7 hosts, same services. The host that drops ICMP is found by a TCP probe:

```
10.77.3.60   true  reset          1    0.050     80/http (SimpleHTTPServer 0.6) conf=1.0
status=completed ... wall=57.0s
measured on eth0: 19118 packets sent, peak 504 pps in one second (limit 500)
```

Rate control, C-sweep (routed, discovery + port scan). nmap counted 19 036 packets, the interface counter 19 048:

```
packets 19036, average 493.9 pps, limit 500 pps
measured on eth0: peak 503 pps; per second: [502 502 498 501 500 501 500 500 500 500 500 500 500 501 498 503 497 501 416 482 500 502 499 500 500 501 498 501 502 499 500 502 498 501 499 499 500 399 246]
  group 2: chunks 2-2,  256 addresses, done 19.0s, 4708 packets, 247.2 pps (share 250)
  group 1: chunks 1-1,  254 addresses, done 19.2s, 4758 packets, 247.4 pps (share 250)
```

Window pause and resume, D1 (`-stop-after 45s -resume`):

```
msg="window guard: the next chunk does not fit before the window ends, no new chunk starts" chunk=3 size=256 estimate_ms=25294 left_ms=19705
PAUSED: window closed after 25.482s. Done 510/1021 addresses, 2 chunks deferred. Resuming the same run in a new window.
{"deferred_chunks":2,"event":"paused","pause_reason":"window_closed","stats":{"addresses_total":1021,"addresses_done":510,"chunks_total":4,"chunks_done":2,"hosts_up":3,...}}
status=completed sessions=2 — addresses 1021/1021, chunks 4/4 map[done:4], hosts up 7, open services 7
```

D2 (`-stop-after 22s -resume`): both running nmap groups are stopped at 22.01 s, 4 chunks deferred, the resumed run finishes 4/4 with 7 hosts and no host reported twice.

Unstable hosts, E-retry (`-hints 10.77.3.60:80,10.77.3.99:80 -retries 2 -backoff 6s`; 10.77.3.60 is off the network at start):

```
retry result: 10.77.3.60 up=true reason=reset attempts=2
retry result: 10.77.3.99 up=false reason=no-response attempts=3
```

Adaptive sizes, I-adaptive (4094 empty addresses, 2000 pps):

```
adaptive group sizes (addresses): [256 255 768 1024 511 1280]
packets 73692, average 1689.2 pps, limit 2000 pps; measured peak 2004 pps
```

Other scenarios: F-native (Go fallback) 7 of 7 hosts and ports, peak 503 pps; G-unprivileged (`--cap-drop NET_RAW`) nmap logs "connect scan (-sT)" and finds the hosts; H-emergency exits 1 with "emergency stop is active", 0 packets on the interface.

### Timing figure

| Mode | /22 measured | 10 000 addresses | 65 536 addresses |
| --- | --- | --- | --- |
| Routed, discovery + port scan, 500 pps (C-sweep) | 38.5 s for 1021 addresses, 19 036 packets | about 6 min 17 s | about 41 min |
| Routed, with version detection, 500 pps (B-routed) | 57.0 s | about 9 min 18 s | about 61 min |
| Local segment with ARP, 500 pps (A-local) | 27.6 s | about 4 min 30 s | about 29 min |
| Routed, empty space, 2000 pps (I-adaptive) | 43.6 s for 4094 addresses | about 1 min 47 s | about 11 min 38 s |

The extrapolation is linear. A dead address costs 18.6 packets through a router (9 probes, one retry), so the sweep time is about `addresses × 18.6 / pps`. Version detection adds time per live host, not per address: the lab has 7 live hosts in 1021 addresses.

## 3. Changes to internal/model

None.

## 4. Findings, deviations and gaps

- **nmap `--max-rate` is an average, not a ceiling.** With `--max-rate` only, I measured 1020 packets in one second against a 500 pps limit (nmap catches up after a slow start). The runner now passes `--min-rate` with the same value. The measured rate is then 498–504 pps every second, and the /22 sweep went from 60.7 s to 38.5 s. Trade-off: nmap no longer slows down by itself on packet loss; the configured rate is the pace.
- **Chunks are fixed, groups adapt.** Chunks announced through `OnPlan` never change Seq, Spec or Size, so resume is safe with any store. The adaptive size is the number of consecutive chunks one nmap process takes (`GroupEvent`, log line "chunk group finished"). Chunks of one group share `StartedAt`; `DurationMs` is the group time split by size. The store or UI cannot show the group size from `model.Chunk` alone; a `group` field would be needed.
- **XML goes to fd 3, not `-oX -`.** nmap prints "Raw packets sent" only on stdout, and `-oX -` suppresses it. The runner falls back to `-oX -` (packet counts become estimates) if fd 3 fails.
- `-sV` also runs nmap's built-in version-category NSE scripts. There is no nmap switch to turn them off. No `--script` option is passed.
- Version-detection probes use normal sockets; `--max-rate` does not pace them. Their packets are an estimate (12 per open port) in `PacketsSent`.
- `RunStats.CurrentPPS` is computed from stages that ended in the last 5 s, so it lags during a long stage. Per-chunk `PPS` and `AvgPPS` are exact for nmap with raw sockets.
- The HTTP limiters charge one fingerprint call for all its requests (page, favicon, paths). Pacing between the requests inside one call is the collector's job. Not tested with the real `httpfp` and `sig` packages (only fakes): they are other workers' packages.
- If a group is cut after some of its hosts were reported (for example during the retry rounds), those hosts are reported again when the chunk is rescanned. Counters are corrected; the sink must upsert.
- IPv6: single addresses are parsed, planned and passed to nmap with `-6`. Not covered by the e2e run.
- TCP only. No UDP scan.
- `Estimate` is conservative: it assumed 25 608 packets and 90 s for the /22; the run needed 19 118 packets and 57 s.
- The API worker must implement `sched.Backend` and call `scan.PauseCause` when it cancels a run.

Next steps I would take: add a `group` field to `model.Chunk` if the UI should show adaptive sizes, give the last lone group the whole budget also when another group just ended, run the engine with the real `httpfp` and `sig` after merge.
