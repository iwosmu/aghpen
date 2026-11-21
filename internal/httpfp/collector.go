// Package httpfp is the HTTP and TLS fingerprint collector of Czujka.
//
// It implements model.Fingerprinter. The collector is passive: it sends only
// GET (and HEAD) requests without a body, without credentials and without
// replaying cookies. It talks to exactly one address (the IP and port of the
// request) and never follows a redirect that leaves that origin.
package httpfp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Defaults used when the request leaves a limit at zero.
const (
	DefaultTimeout      = 10 * time.Second
	DefaultDialTimeout  = 5 * time.Second
	DefaultMaxBodyBytes = 256 << 10
	DefaultExcerptBytes = 64 << 10
	DefaultPathExcerpt  = 16 << 10
	DefaultMaxPaths     = 64
	DefaultUserAgent    = "Czujka/1.0 (attack surface inventory; safe detection only)"
	maxRedirectsCap     = 10
	maxFaviconBytes     = 1 << 20
	maxHeaderValueBytes = 4096
	maxTitleRunes       = 300
)

// Collector implements model.Fingerprinter. The zero value works; New sets
// the documented defaults explicitly. A Collector is safe for concurrent use.
type Collector struct {
	// DialTimeout bounds the TCP connect and the TLS handshake.
	DialTimeout time.Duration
	// Timeout bounds one request (headers and body) when HTTPOpts.TimeoutMs is 0.
	Timeout time.Duration
	// MaxBodyBytes bounds the body read from the network when HTTPOpts.MaxBodyBytes is 0.
	MaxBodyBytes int
	// ExcerptBytes bounds HTTPFingerprint.BodyExcerpt. It is never larger than the body limit.
	ExcerptBytes int
	// PathExcerptBytes bounds PathProbe.Excerpt.
	PathExcerptBytes int
	// MaxPaths bounds the number of extra paths fetched for one service.
	MaxPaths int
	// Wait, when set, is called before every request. The scan engine plugs
	// its global and per-host rate limiters in here.
	Wait func(ctx context.Context, ip string) error
	// OnRequest, when set, is called after every request that was sent.
	OnRequest func(method, url string)
	// Now is the clock used for certificate validity. Tests replace it.
	Now func() time.Time
}

// New returns a collector with the default limits.
func New() *Collector {
	return &Collector{
		DialTimeout:      DefaultDialTimeout,
		Timeout:          DefaultTimeout,
		MaxBodyBytes:     DefaultMaxBodyBytes,
		ExcerptBytes:     DefaultExcerptBytes,
		PathExcerptBytes: DefaultPathExcerpt,
		MaxPaths:         DefaultMaxPaths,
	}
}

var _ model.Fingerprinter = (*Collector)(nil)

// commonTLSPorts are tried with TLS first even without a hint from nmap.
var commonTLSPorts = map[int]bool{
	443: true, 444: true, 465: true, 636: true, 832: true, 990: true, 993: true, 995: true,
	1443: true, 2083: true, 2087: true, 2096: true, 3443: true, 4433: true, 4443: true,
	5001: true, 5443: true, 5986: true, 6443: true, 7443: true, 8006: true, 8043: true,
	8443: true, 8444: true, 8834: true, 9043: true, 9443: true, 10443: true, 12443: true,
	16443: true, 18443: true,
}

// IsCommonTLSPort reports whether the collector tries TLS first on this port.
func IsCommonTLSPort(port int) bool { return commonTLSPorts[port] }

func tlsFirst(req model.FingerprintRequest) bool {
	if req.TLSHint || commonTLSPorts[req.Port] {
		return true
	}
	n := strings.ToLower(req.NameHint)
	return strings.Contains(n, "https") || strings.Contains(n, "ssl") || strings.Contains(n, "tls")
}

// session is the state of one Fingerprint call.
type session struct {
	c         *Collector
	req       model.FingerprintRequest
	addr      string // the only address this session ever dials
	host      string // Host header without port: hostname or IP
	sni       string
	userAgent string
	timeout   time.Duration
	dialTO    time.Duration
	maxBody   int
	excerpt   int
	pathExc   int

	mu       sync.Mutex
	tlsState *tls.ConnectionState
	dialErr  error
	tr       *http.Transport
	icons    []*url.URL // same-origin icon links of the final page
}

type dialError struct{ err error }

func (e *dialError) Error() string { return e.err.Error() }
func (e *dialError) Unwrap() error { return e.err }

func (c *Collector) newSession(req model.FingerprintRequest) (*session, error) {
	ip := net.ParseIP(strings.TrimSpace(req.IP))
	if ip == nil {
		return nil, fmt.Errorf("httpfp: invalid IP %q", req.IP)
	}
	if req.Port < 1 || req.Port > 65535 {
		return nil, fmt.Errorf("httpfp: invalid port %d", req.Port)
	}
	s := &session{c: c, req: req, addr: net.JoinHostPort(ip.String(), strconv.Itoa(req.Port))}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Hostname)), ".")
	if host != "" && !validHostname(host) {
		host = ""
	}
	if host != "" && net.ParseIP(host) == nil {
		s.host, s.sni = host, host
	} else {
		s.host = ip.String()
	}
	s.userAgent = strings.TrimSpace(req.UserAgent)
	if s.userAgent == "" || strings.ContainsAny(s.userAgent, "\r\n") {
		s.userAgent = DefaultUserAgent
	}
	s.timeout = pickDur(time.Duration(req.Opts.TimeoutMs)*time.Millisecond, c.Timeout, DefaultTimeout)
	s.dialTO = pickDur(c.DialTimeout, DefaultDialTimeout, DefaultDialTimeout)
	if s.dialTO > s.timeout {
		s.dialTO = s.timeout
	}
	s.maxBody = pickInt(req.Opts.MaxBodyBytes, c.MaxBodyBytes, DefaultMaxBodyBytes)
	s.excerpt = pickInt(c.ExcerptBytes, DefaultExcerptBytes, DefaultExcerptBytes)
	if s.excerpt > s.maxBody {
		s.excerpt = s.maxBody
	}
	s.pathExc = pickInt(c.PathExcerptBytes, DefaultPathExcerpt, DefaultPathExcerpt)
	if s.pathExc > s.maxBody {
		s.pathExc = s.maxBody
	}
	return s, nil
}

func pickDur(vals ...time.Duration) time.Duration {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return 0
}

func pickInt(vals ...int) int {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return 0
}

func validHostname(h string) bool {
	if len(h) > 253 {
		return false
	}
	for _, r := range h {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_' || r == ':'
		if !ok {
			return false
		}
	}
	return true
}

func (s *session) now() time.Time {
	if s.c.Now != nil {
		return s.c.Now()
	}
	return time.Now()
}

// dial connects to the one address of this session. The network and address
// arguments that net/http passes are ignored on purpose: whatever URL is
// requested, the bytes go to the scanned IP and port only.
func (s *session) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: s.dialTO}
	conn, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		s.mu.Lock()
		s.dialErr = err
		s.mu.Unlock()
		return nil, &dialError{err}
	}
	return conn, nil
}

func (s *session) tlsConfig() *tls.Config {
	// The collector records what a server offers, also when it is weak:
	// certificates are not verified (they are recorded instead) and legacy
	// protocol versions and cipher suites stay enabled so old devices answer.
	var suites []uint16
	for _, cs := range tls.CipherSuites() {
		suites = append(suites, cs.ID)
	}
	for _, cs := range tls.InsecureCipherSuites() {
		suites = append(suites, cs.ID)
	}
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // inventory scanner: invalid certificates are data, not errors
		ServerName:         s.sni,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       suites,
		NextProtos:         []string{"http/1.1"},
	}
}

func (s *session) dialTLS(ctx context.Context) (net.Conn, error) {
	raw, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	hctx, cancel := context.WithTimeout(ctx, s.dialTO)
	defer cancel()
	conn := tls.Client(raw, s.tlsConfig())
	if err := conn.HandshakeContext(hctx); err != nil {
		raw.Close()
		return nil, err
	}
	st := conn.ConnectionState()
	s.mu.Lock()
	if s.tlsState == nil {
		s.tlsState = &st
	}
	s.mu.Unlock()
	return conn, nil
}

func (s *session) transport() *http.Transport {
	if s.tr == nil {
		s.tr = &http.Transport{
			Proxy:                  nil,
			DialContext:            func(ctx context.Context, _, _ string) (net.Conn, error) { return s.dial(ctx) },
			DialTLSContext:         func(ctx context.Context, _, _ string) (net.Conn, error) { return s.dialTLS(ctx) },
			DisableCompression:     true, // gzip is decoded by hand so a broken stream still yields data
			MaxResponseHeaderBytes: 64 << 10,
			ResponseHeaderTimeout:  s.timeout,
			MaxIdleConnsPerHost:    2,
			MaxConnsPerHost:        2,
			IdleConnTimeout:        5 * time.Second,
			ForceAttemptHTTP2:      false,
		}
	}
	return s.tr
}

func (s *session) tlsInfo() *model.TLSInfo {
	s.mu.Lock()
	st := s.tlsState
	s.mu.Unlock()
	if st == nil {
		return nil
	}
	return buildTLSInfo(st, s.sni, s.now())
}

// baseURL returns scheme://host[:port]/ for this session.
func (s *session) baseURL(scheme string) *url.URL {
	host := s.host
	def := scheme == "http" && s.req.Port == 80 || scheme == "https" && s.req.Port == 443
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	if !def {
		host += ":" + strconv.Itoa(s.req.Port)
	}
	return &url.URL{Scheme: scheme, Host: host, Path: "/"}
}

// Fingerprint looks at one open TCP port. It returns (nil, nil, nil) when the
// port speaks neither HTTP nor TLS, (nil, tls, nil) for a TLS service that is
// not HTTP, and an error when the port cannot be reached or ctx ended.
func (c *Collector) Fingerprint(ctx context.Context, req model.FingerprintRequest) (*model.HTTPFingerprint, *model.TLSInfo, error) {
	s, err := c.newSession(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if s.tr != nil {
			s.tr.CloseIdleConnections()
		}
	}()

	order := []string{"http", "https"}
	if tlsFirst(req) {
		order = []string{"https", "http"}
	}

	var fp, plainMisdirected *model.HTTPFingerprint
	var scheme string
	for _, sch := range order {
		got, misdirected, err := s.root(ctx, sch)
		if ctx.Err() != nil {
			return nil, s.tlsInfo(), ctx.Err()
		}
		var de *dialError
		if errors.As(err, &de) {
			// The port does not accept connections: the other protocol cannot work either.
			return nil, nil, fmt.Errorf("httpfp: connect %s: %w", s.addr, de.err)
		}
		if got != nil && misdirected {
			// A plain request reached a TLS port. Keep it only as a last resort.
			plainMisdirected = got
			continue
		}
		if got != nil {
			fp, scheme = got, sch
			break
		}
		if sch == "https" && s.tlsInfo() != nil {
			// TLS works but the service inside is not HTTP (IMAPS, LDAPS ...).
			return nil, s.tlsInfo(), nil
		}
	}
	if fp == nil {
		fp, scheme = plainMisdirected, "http"
	}
	if fp == nil {
		return nil, s.tlsInfo(), nil
	}

	if req.Opts.Favicon {
		s.favicon(ctx, scheme, fp)
	}
	if len(req.Paths) > 0 && ctx.Err() == nil {
		s.paths(ctx, scheme, fp)
	}
	var ti *model.TLSInfo
	if scheme == "https" {
		ti = s.tlsInfo()
	}
	return fp, ti, nil
}

// root fetches "/" and follows same-origin redirects by hand.
// misdirected is true when a plain HTTP request hit a TLS listener.
func (s *session) root(ctx context.Context, scheme string) (fp *model.HTTPFingerprint, misdirected bool, err error) {
	cur := s.baseURL(scheme)
	start := cur.String()
	maxHops := s.req.Opts.MaxRedirects
	if maxHops < 0 {
		maxHops = 0
	}
	if maxHops > maxRedirectsCap {
		maxHops = maxRedirectsCap
	}

	var (
		last      *response
		redirects []model.Redirect
		cookies   []model.Cookie
		notes     []string
		firstMs   int
		seen      = map[string]bool{start: true}
	)
	for hop := 0; ; hop++ {
		r, err := s.do(ctx, http.MethodGet, cur, s.maxBody)
		if err != nil {
			if last == nil {
				return nil, false, err
			}
			notes = append(notes, "redirect target failed: "+shortErr(err))
			break
		}
		if last == nil {
			firstMs = int(r.elapsed.Milliseconds())
			if scheme == "http" && looksLikeTLSPortAnswer(r) {
				misdirected = true
			}
		}
		last = r
		cookies = mergeCookies(cookies, r.cookies)
		if !isRedirect(r.status) {
			break
		}
		loc := r.header.Get("Location")
		if loc == "" {
			break
		}
		next, perr := cur.Parse(loc)
		if perr != nil {
			notes = append(notes, "invalid redirect location")
			break
		}
		next.Fragment = ""
		next.User = nil
		redirects = append(redirects, model.Redirect{From: cur.String(), To: next.String(), Status: r.status})
		if !sameOrigin(cur, next) {
			notes = append(notes, "redirect leaves the scanned origin, not followed: "+next.Scheme+"://"+next.Host)
			break
		}
		if hop >= maxHops {
			notes = append(notes, "redirect limit reached")
			break
		}
		if seen[next.String()] {
			notes = append(notes, "redirect loop")
			break
		}
		seen[next.String()] = true
		cur = next
	}

	if last.bodyNote != "" {
		notes = append(notes, last.bodyNote)
	}
	fp = s.build(start, last, redirects, cookies)
	fp.ResponseMs = firstMs
	fp.Error = strings.Join(notes, "; ")
	return fp, misdirected, nil
}

func (s *session) build(start string, r *response, redirects []model.Redirect, cookies []model.Cookie) *model.HTTPFingerprint {
	doc := parseHTML(r.text)
	fp := &model.HTTPFingerprint{
		Scheme:        r.url.Scheme,
		URL:           start,
		FinalURL:      r.url.String(),
		Host:          s.host,
		Status:        r.status,
		Title:         doc.title,
		Headers:       cleanHeaders(r.header),
		Cookies:       cookies,
		Redirects:     redirects,
		Server:        truncate(r.header.Get("Server"), 256),
		PoweredBy:     truncate(strings.Join(r.header.Values("X-Powered-By"), ", "), 256),
		MetaGenerator: doc.generator,
		BodyLength:    r.length,
		BodySHA256:    r.sha256,
		BodySimhash:   SimhashHex(r.text),
		BodyExcerpt:   truncateUTF8(r.text, s.excerpt),
	}
	if fp.Cookies == nil {
		fp.Cookies = []model.Cookie{}
	}
	if fp.Redirects == nil {
		fp.Redirects = []model.Redirect{}
	}
	fp.Paths = []model.PathProbe{}
	s.iconLinks(doc.icons, r.url)
	return fp
}

// sameOrigin reports whether b has the scheme, host and port of a. A redirect
// to another port is another service of the inventory, so it is not followed.
func sameOrigin(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	if !strings.EqualFold(strings.TrimSuffix(a.Hostname(), "."), strings.TrimSuffix(b.Hostname(), ".")) {
		return false
	}
	return effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// looksLikeTLSPortAnswer recognises the answers servers give to a plain HTTP
// request on a TLS port (nginx, Apache, Go, IIS, Jetty ...).
func looksLikeTLSPortAnswer(r *response) bool {
	if r.status != 400 && r.status != 497 {
		return false
	}
	b := strings.ToLower(r.text)
	for _, m := range []string{
		"plain http request was sent to https port",
		"speaking plain http to an ssl-enabled server port",
		"client sent an http request to an https server",
		"this combination of host and port requires tls",
		"http request to an https server",
	} {
		if strings.Contains(b, m) {
			return true
		}
	}
	return false
}

func shortErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 && i+2 < len(msg) {
		msg = msg[i+2:]
	}
	return truncate(msg, 160)
}
