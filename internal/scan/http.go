package scan

import (
	"context"
	"strings"
	"sync/atomic"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
)

// pathPlanner is the optional part of a signature engine that picks the
// extra paths for one service after its root page is known (internal/sig).
type pathPlanner interface {
	PathsFor(svc *model.ServiceResult, limit int) []string
}

// pathFetcher is the optional part of a fingerprinter that requests only the
// extra paths of a service whose root page is known (internal/httpfp).
type pathFetcher interface {
	FetchPaths(ctx context.Context, req model.FingerprintRequest, fp *model.HTTPFingerprint) (*model.HTTPFingerprint, *model.TLSInfo, error)
}

// hostMatcher is the optional part of a signature engine that also uses the
// host names of the address (internal/sig).
type hostMatcher interface {
	MatchHost(svc *model.ServiceResult, hostnames ...string) ([]model.SigMatch, []model.Technology, []string)
}

// pacer carries the HTTP limiters of one Fingerprint call through the
// context, so a collector that calls HTTPWait before each request is paced
// request by request.
type pacer struct {
	r       *run
	host    hostLimits
	prepaid atomic.Int32 // requests already paid for before the call
	n       atomic.Int64 // HTTPWait calls of this Fingerprint call
}

type pacerKey struct{}

// HTTPWait is the per-request hook of the HTTP stage. Set it as
// httpfp.Collector.Wait. The collector calls it before every request; it
// blocks until the per-host limit and the global limit of the run allow one
// more request. Outside an engine run it returns at once.
func HTTPWait(ctx context.Context, _ string) error {
	p, _ := ctx.Value(pacerKey{}).(*pacer)
	if p == nil {
		return ctx.Err()
	}
	p.n.Add(1)
	if p.prepaid.Add(-1) >= 0 {
		return ctx.Err() // the engine waited for this request before the call
	}
	return p.r.httpWait(ctx, p.host, 1)
}

// hostLimits are the request limiters of one address: the run's own (the
// profile's per-host delay) and the engine-wide one that every run shares.
type hostLimits struct{ own, shared *probe.Limiter }

// httpWait takes n requests from the per-host limiters, the run's limiter
// and the engine-wide limiter.
func (r *run) httpWait(ctx context.Context, host hostLimits, n int) error {
	if n == 1 {
		// all limits at the same moment: waiting for one after the other
		// would let requests bunch behind the slower one
		if err := probe.WaitAll(ctx, host.own, host.shared, r.httpLim, r.globalHTTP); err != nil {
			return err
		}
	} else {
		for _, l := range []*probe.Limiter{host.own, host.shared, r.httpLim, r.globalHTTP} {
			if err := l.WaitN(ctx, n); err != nil {
				return err
			}
		}
	}
	r.stats.update(func(s *model.RunStats) { s.HTTPRequests += int64(n) })
	return nil
}

// fingerprint makes one Fingerprint call under the HTTP limits. The first
// request is paid before the call. A collector with the HTTPWait hook pays
// every further request itself. For any other Fingerprinter the engine
// counts the requests in the answer and pays them after the call, so the
// average rate still holds.
func (r *run) fingerprint(ctx context.Context, host hostLimits, req model.FingerprintRequest) (*model.HTTPFingerprint, *model.TLSInfo, error) {
	return r.paced(ctx, host, func(ctx context.Context) (*model.HTTPFingerprint, *model.TLSInfo, error) {
		return r.e.deps.Fingerprinter.Fingerprint(ctx, req)
	})
}

// paced runs one collector call under the HTTP limits (see fingerprint).
func (r *run) paced(ctx context.Context, host hostLimits, call func(context.Context) (*model.HTTPFingerprint, *model.TLSInfo, error)) (*model.HTTPFingerprint, *model.TLSInfo, error) {
	if err := r.httpWait(ctx, host, 1); err != nil {
		return nil, nil, err
	}
	p := &pacer{r: r, host: host}
	p.prepaid.Store(1)
	h, t, err := call(context.WithValue(ctx, pacerKey{}, p))
	if p.n.Load() == 0 && h != nil {
		rest := len(h.Paths) + len(h.Redirects)
		if h.FaviconSHA256 != "" || h.FaviconMMH3 != nil {
			rest++
		}
		if rest > 0 {
			_ = r.httpWait(ctx, host, rest)
		}
	}
	return h, t, err
}

// httpStage fingerprints one open TCP service: the root page and favicon
// first, then the extra signature paths that fit this service.
func (r *run) httpStage(ctx context.Context, host hostLimits, res *model.HostResult, svc *model.ServiceResult, hostname string) {
	if notHTTP(svc) {
		return
	}
	req := model.FingerprintRequest{
		IP: res.IP, Port: svc.Port, Hostname: hostname, TLSHint: svc.Tunnel == "ssl", NameHint: svc.Name,
		Opts: r.plan.Profile.HTTP, UserAgent: r.plan.Policy.UserAgent,
	}
	sigs := r.e.deps.Signatures
	wantPaths := sigs != nil && r.plan.Profile.HTTP.SignaturePaths && r.lim.MaxPaths > 0
	planner, twoPass := sigs.(pathPlanner)
	if wantPaths && !twoPass {
		req.Paths = r.paths // an engine without PathsFor: its general path list in one call
	}
	h, t, err := r.fingerprint(ctx, host, req)
	if err != nil {
		r.log.Debug("fingerprint failed", "ip", res.IP, "port", svc.Port, "error", err.Error())
	}
	if h != nil && wantPaths && twoPass && ctx.Err() == nil {
		// The root page tells which paths are worth the requests.
		seen := *svc
		seen.HTTP, seen.TLS = h, t
		if paths := planner.PathsFor(&seen, r.lim.MaxPaths); len(paths) > 0 {
			if len(paths) > r.lim.MaxPaths {
				paths = paths[:r.lim.MaxPaths]
			}
			req2 := req
			req2.Paths = paths
			req2.Opts.Favicon = false
			var h2 *model.HTTPFingerprint
			var t2 *model.TLSInfo
			var err2 error
			if pf, ok := r.e.deps.Fingerprinter.(pathFetcher); ok {
				// only the paths: the root page is already known
				h2, t2, err2 = r.paced(ctx, host, func(ctx context.Context) (*model.HTTPFingerprint, *model.TLSInfo, error) {
					return pf.FetchPaths(ctx, req2, h)
				})
			} else {
				h2, t2, err2 = r.fingerprint(ctx, host, req2)
			}
			if err2 == nil && h2 != nil {
				h2.FaviconMMH3, h2.FaviconSHA256 = h.FaviconMMH3, h.FaviconSHA256
				h = h2
				if t2 != nil {
					t = t2
				}
			} else if err2 != nil {
				r.log.Debug("path fingerprint failed", "ip", res.IP, "port", svc.Port, "error", err2.Error())
			}
		}
	}
	svc.HTTP, svc.TLS = h, t
	if t != nil && svc.Tunnel == "" {
		svc.Tunnel = "ssl"
	}
}

// match runs the signature engine on one service.
func (r *run) match(svc *model.ServiceResult, hostnames []string) {
	sigs := r.e.deps.Signatures
	if sigs == nil {
		return
	}
	var m []model.SigMatch
	var t []model.Technology
	var c []string
	if hm, ok := sigs.(hostMatcher); ok {
		m, t, c = hm.MatchHost(svc, hostnames...)
	} else {
		m, t, c = sigs.Match(svc)
	}
	if m != nil {
		svc.Matches = m
	}
	if t != nil {
		svc.Technologies = t
	}
	if c != nil {
		svc.Classes = c
	}
}

// nonHTTPNames are nmap service names of protocols that never answer HTTP.
// The HTTP stage skips such a port when it has no TLS tunnel: a GET there
// only costs requests of the per-host budget (2 per second by default), and
// on a small run those requests were most of the run time.
var nonHTTPNames = map[string]bool{
	"ssh": true, "ftp": true, "smtp": true, "submission": true, "pop3": true, "imap": true,
	"postgresql": true, "mysql": true, "redis": true, "mongodb": true, "mongod": true, "amqp": true,
	"mqtt": true, "domain": true, "ldap": true, "microsoft-ds": true, "netbios-ssn": true,
	"msrpc": true, "ms-wbt-server": true, "vnc": true, "telnet": true, "rpcbind": true, "nfs": true,
	"memcached": true, "kerberos-sec": true, "ms-sql-s": true, "oracle-tns": true, "rsync": true,
	"x11": true, "epmd": true, "zookeeper": true, "nntp": true, "sip": true, "rtsp": false,
}

func notHTTP(svc *model.ServiceResult) bool {
	if svc.Tunnel == "ssl" {
		return false // TLS: the collector reads the certificate even when HTTP is not inside
	}
	n := strings.ToLower(svc.Name)
	if nonHTTPNames[n] {
		return true
	}
	return strings.HasPrefix(n, "mosquitto version") // nmap's service name for Mosquitto
}
