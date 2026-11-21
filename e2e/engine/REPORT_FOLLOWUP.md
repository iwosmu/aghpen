# Scan engine follow-up: worker report (task_51e66206292c)

Branch `iwosmu/czujka-engine`. All numbers are from real runs on 2026-11-21 (Docker Desktop aarch64, nmap 7.95, Go 1.27.4, PostgreSQL 17 with pg_tde for the database test).

## 1. Real fingerprinting in the engine

What changed in `internal/scan`:

- **Every HTTP request is paced.** `scan.HTTPWait` is the hook for `httpfp.Collector.Wait`. The collector calls it before each request (root page, redirects, favicon, extra signature paths). It takes one token from the per-host limiter and the global limiter of the run at the same moment (`probe.WaitAll`). Both buckets have no burst. A Fingerprinter without the hook still works: the engine counts the requests in the answer and pays them after the call.
- **Call order of the fingerprint worker.** `Fingerprint` (root and favicon), then `PathsFor(svc, limit)` when the signature engine has it, a second `Fingerprint` with those paths, then `MatchHost(svc, hostnames...)`. The limit is `SafetyPolicy.MaxPathsPerHost`. An engine without `PathsFor` gets `ExtraPaths()` in one call, as before.
- **Hosts are reported once.** The hosts of a group go to the sink when the group is final. A group that a pause or a window end cuts is scanned again after the resume, and nothing of it was reported before. Test: `TestPauseInsideAGroupDoesNotReportHostsTwice`.
- `RunStats.HTTPRequests` is exact with the real collector: it counts every `HTTPWait` call.

A bug the real components exposed: waiting for the per-host limiter and then for the global limiter let requests bunch behind the slower one. The first version of the proof test failed with 10 requests in one second to one host against a cap of 8. `probe.WaitAll` fixes it.

### Request-cap proof

`internal/scan/http_real_test.go`: real `httpfp.Collector`, real `sig.NewBuiltinEngine()`, three real HTTP servers on two loopback addresses. The servers record the arrival time of every request.

```
$ go test -count=1 -race -run TestHTTPRequestCapsHoldWithRealCollector -v ./internal/scan
33 requests in 3.117s: host A 22, host B 11, extra signature paths 24;
peak per second: all 12 (cap 12), host A 8, host B 6 (cap 8)
--- PASS
```

Checked: at most cap+1 requests in any one-second window (global and per host), each extra path requested at most once per service, `RunStats.HTTPRequests` = requests the servers saw = requests the collector sent (33), only GET and HEAD.

### One engine run against real applications

`./e2e/engine/lab.sh apps` starts WordPress 6 with MariaDB, Grafana, Gitea, phpMyAdmin, Tomcat, an HTTPS server with a self-signed certificate, nginx on port 8181 and a DNS/NTP host.

```
$ scanprobe -targets 10.76.0.0/24 -ports top-100,3000,8181,8443 -pps 500 -http -http-rps 20 -per-host-rps 8 -max-paths 12 -udp
http stage: real collector, 386 signatures (386 enabled), 20 requests/s in total, 8 per host, 12 extra paths per service
IP          PORT      HTTP / TLS                         TECHNOLOGIES (signature engine)                         CLASSES
10.76.0.10  3306/tcp  -                                  MariaDB 11.8.9                                          database
10.76.0.11  80/tcp    200 "Czujka lab"                   Apache HTTP Server 2.4.67, WordPress 6.9.4, PHP 8.3.31  admin-panel, login
10.76.0.20  3000/tcp  200 "Grafana"                      Grafana 11.3.0, Grafana http                            login
10.76.0.21  22/tcp    -                                  OpenSSH 9.7                                             remote-access
10.76.0.21  3000/tcp  200 "Gitea: Git with a cup "       Go net/http, Gitea 1.22.6, Docker Registry              api, dev-tool
10.76.0.30  80/tcp    200 "phpMyAdmin"                   Apache HTTP Server 2.4.71, PHP 8.3.37, phpMyAdmin 5.2.3, Bootstrap, jQuery  admin-panel, database, login
10.76.0.40  8080/tcp  404 "HTTP Status 404 – No"         Apache Tomcat 10.1.62, Java                             error-page
10.76.0.50  8443/tcp  200 "Czujka lab" tls self-signed=true  Python 3.12.13, Python http.server 0.6              staging
10.76.0.60  8181/tcp  200 "Welcome to nginx!"            nginx 1.31.9                                            default-page
10.76.0.70  53/tcp    -                                  dnsmasq 2.90
10.76.0.70  53/udp    -
10.76.0.70  123/udp   -
http requests: 114 counted by the run, 114 sent by the collector, 7 HTTP services
PASS
```

Notes for the fingerprint worker (their packages, not changed by me): the self-signed HTTPS host gets class `staging` and no TLS class; Grafana gets a second technology "Grafana http" from the nmap product string; Gitea also matches "Docker Registry" (Gitea does answer `/v2/`).

## 2. Wiring (scope reduced by the coordinator)

`internal/enginewire` was already written when the scope change arrived. It is committed as it was and tested against PostgreSQL (`TestSchedulerBackendWithRealStoreAndRunner`, container `czeng-pg`, port 55477). It holds `New(Deps) model.Engine`, `Window` (a `runner.WindowFunc`), `TargetParser`, a `sched.Backend` and `ProfileChanged`. The integrator may use it or ignore it.

The lines the integrator needs for the engine:

```go
collector := httpfp.New()
collector.Wait = scan.HTTPWait // without this line the caps hold on average only, not per request
engine := scan.New(scan.Deps{Fingerprinter: collector, Signatures: sigs, Logger: log})
// or: engine := enginewire.New(enginewire.Deps{Signatures: sigs, Logger: log})
```

`sigs` is the shared `*sig.Engine`. The engine finds `PathsFor` and `MatchHost` by itself.

### How the runner must cancel a run

Today `runner.Manager.launch` uses `context.WithCancel` and `Manager.stop` calls `a.cancel()`. This works and loses nothing:

- The engine stops its nmap processes, marks every unfinished chunk as `deferred`, reports no host of an unfinished chunk, and returns `RunCancelled`.
- The runner takes the final status from its own `intent` (`pause`, `emergency`, `shutdown`, `cancel`), so pause, emergency stop and cancel end in the right state.
- A fresh start and a resume under emergency stop never reach the network: the runner refuses first, and the engine refuses again by itself (`scan.ErrEmergencyStop`).

To make the engine's own outcome say the same thing (`RunPaused` with the right `PauseReason`), change three places in `internal/runner/runner.go`:

```go
// launch
ctx, cancel := context.WithCancelCause(context.Background()) // activeRun.cancel becomes a context.CancelCauseFunc
defer cancel(nil)

// stop, in place of a.cancel()
switch intent {
case "pause", "shutdown":
	a.cancel(scan.PauseCause(model.PauseManual))    // engine returns RunPaused / "manual"
case "emergency":
	a.cancel(scan.PauseCause(model.PauseEmergency)) // engine returns RunPaused / "emergency_stop"
default: // "cancel"
	a.cancel(nil)                                   // engine returns RunCancelled
}
```

No other change is needed. The window end needs no cancel from the runner: the engine stops itself at `ScanPlan.WindowEnd` and returns `RunPaused` / `window_closed`.

## 3. Speed on sparse address space

`model.DiscoveryOpts.Mode`: `fast`, `balanced` (default), `thorough`.

| Mode | First pass, every address | Second pass |
| --- | --- | --- |
| fast | ICMP echo, TCP SYN 80 and 443, one retry | the other probes, only for hosts the inventory knows |
| balanced | the same | the other probes for the silent addresses of every /24 block where a host answered or a hint exists |
| thorough | the full probe set, one retry | none |

The second pass sends only the probes the first pass left out (ICMP timestamp, SYN 22, 3389, 8080, ACK 80, 443), so a block is never probed twice with the same packet. On a local segment nmap uses ARP and every mode makes one pass.

Measured through the router, discovery and port scan, 103 ports, no version detection:

| Run | Mode | Time | Discovery packets per address | Lab hosts found |
| --- | --- | --- | --- | --- |
| /22 (1021 addresses, a host in every /24), 500 pps | thorough | 38.6 s | 17.9 | 7 of 7 |
| | balanced | 39.8 s | 17.9 | 7 of 7 |
| | fast | 20.9 s | 6.0 | 7 of 7 |
| /22 + empty /20 (5115 addresses, hosts in 4 of 20 blocks), 2000 pps | thorough | 48.5 s | 18.0 | 7 of 7 |
| | balanced | 29.1 s | 8.4 (6 in empty blocks, 18 in live blocks) | 7 of 7 |
| | fast | 18.4 s | 6.0 | 7 of 7 (3 runs) |
| the same scope, 500 pps | balanced | 91.6 s | 8.4 | 7 of 7 |
| | fast | 65.3 s | 6.0 | 7 of 7 |

Extrapolation from the sparse runs (seconds per address × addresses; for thorough at 500 pps from the /22 run):

| Mode | 10 000 at 500 pps | 65 536 at 500 pps | 10 000 at 2000 pps | 65 536 at 2000 pps |
| --- | --- | --- | --- | --- |
| thorough | 6 min 18 s | 41 min 18 s | 1 min 35 s | 10 min 21 s |
| balanced (20% of blocks live) | 2 min 59 s | 19 min 34 s | 57 s | 6 min 13 s |
| fast | 2 min 8 s | 13 min 57 s | 36 s | 3 min 56 s |

Miss rate in the lab: 0 of 7 in every mode and every run, including 10.77.3.60, which drops ICMP (found by TCP SYN to port 80, reason `syn-ack`). The lab has no host that separates the modes, so the unit test `TestDiscoveryModes` does it with a network of hosts that answer only chosen probes:

- fast misses a host that drops ICMP and has neither port 80 nor 443 open, unless the inventory knows it.
- balanced misses such a host only when it is alone in a /24 block that the inventory does not know.
- thorough misses neither.

**Finding.** My first fast mode used no retry. nmap with `--max-retries 0` then sends only the first ping probe type to each host: the TCP probes never leave. Measured: 1.2 packets per address and the ICMP-dropping host lost in 1 of 2 runs. Every mode now keeps one retry, and the nmap wrapper never passes 0 retries for discovery.

The estimate names its mode: `model.ScanEstimate.DiscoveryMode`; scanprobe prints `... about 31s at 2000 pps, discovery mode fast`.

## 4. UDP

`model.ScanProfile.UDP` (`UDPOpts{Enabled, Ports}`), off by default. Allow-list in `probe.UDPServices`: DNS 53, NTP 123, NetBIOS-NS 137, SNMP 161, IKE 500, SSDP 1900, mDNS 5353. A profile can only choose a subset. The safety policy ports filter it like TCP. The stage runs on live hosts only, after the TCP stages of the group, inside the same packet share (`--min-rate` = `--max-rate`).

- Command: `nmap -sU -Pn -p U:53,123,137,500,1900,5353 ...`, no `-sV`.
- **SNMP 161 never goes to nmap.** nmap 7.94 and later take the UDP payloads from `nmap-service-probes`, and the probes for port 161 include an SNMPv1 GetRequest with the community string "public". That is a default-credential guess, so it breaks the "never log in" rule. The engine sends its own probe: the SNMPv3 engine discovery of RFC 3414 (60 bytes, no user name, no credentials), at most two packets per host, under the same rate limit. Unit test: `TestSNMPProbe` (the payload has no community string; an agent that answers is reported; a closed port is not).
- A port is reported only when the service answered (`open`). `open|filtered` is not reported.
- Without raw sockets, and with the native prober, the stage is skipped with the log line "UDP scan skipped: it needs nmap with raw sockets (root or CAP_NET_RAW)".
- Real run: `10.76.0.70 53/udp open domain`, `123/udp open ntp`; 274 packets for 9 hosts in 0.85 s. Results are `ServiceResult` with `proto: "udp"`, name from the nmap table, confidence 0.3, no version.

## 5. Chunk.Group

`model.Chunk.Group` is the `Seq` of the first chunk of the work group. Chunks with the same `Group` were scanned by one nmap process per stage; the sum of their `Size` is the adaptive group size. 0 means "not started". The live chunk events carry it. **The store does not persist it yet**: `internal/store/runs.go` lists the chunk columns by name, so `chunks` needs a column (for example `grp int not null default 0`) and the two SQL constants `chunkCols` and `chunkUpsert` need the field.

## 6. CurrentPPS

Now live. While a paced stage runs (discovery, port scan, UDP), `CurrentPPS` counts it at its rate share; when it ends, the exact packet count of nmap replaces the estimate. This is sound because the runner pins the rate (`--min-rate` = `--max-rate`; measured 247 of 250 pps per process). Limits: the version-detection stage is not paced by nmap and is not in the live figure, and the native prober can be under its share at the end of a stage, so the figure can be a little high, never over the limit.

## Fields added to internal/model

| Field | Meaning |
| --- | --- |
| `Chunk.Group int` (`group`) | work group of the chunk |
| `DiscoveryOpts.Mode string` (`mode`) | `fast`, `balanced`, `thorough`; empty = balanced |
| constants `DiscoveryFast`, `DiscoveryBalanced`, `DiscoveryThorough` | |
| `ScanEstimate.DiscoveryMode string` (`discovery_mode`) | the mode the estimate assumes |
| type `UDPOpts{Enabled bool; Ports string}` and `ScanProfile.UDP` (`udp`) | optional UDP scan |

No existing field or JSON tag changed. Profiles are stored as JSON, so the new profile fields persist without a migration. The UI needs inputs for `discovery.mode` and `udp`.

## Known gaps

- Existing profiles get `balanced` (empty mode). Set `thorough` for a profile that must not miss a silent host in an unknown block.
- The fingerprint makes the root request twice when extra paths are fetched (the collector has no "paths only" call). The limiters count both.
- The hosts of a group reach the sink when the group ends, so the live host feed comes in steps of one group (about 30 s by default), and a group of many web hosts stays in memory until then.
- UDP: no version, IPv6 not tested. An agent that speaks only SNMPv1 or v2c and ignores SNMPv3 messages is not found (by design: finding it needs a community string).
- The mode table is from one lab with 7 hosts. The miss behaviour per mode is shown by a unit test, not by a real host.
- `Chunk.Group` needs the store column named above.
