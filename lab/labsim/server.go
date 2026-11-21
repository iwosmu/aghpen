package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iwosmu/aghpen/lab/labcfg"
)

// server owns the listeners of one imitation host and moves them between lab states.
type server struct {
	host *labcfg.Host
	mu   sync.Mutex
	open map[int]*listener
}

type listener struct {
	spec    labcfg.Listener
	tlsJSON string // TLS spec the current certificate was made from
	ln      net.Listener
	site    atomic.Pointer[labcfg.Site]
	cert    atomic.Pointer[tls.Certificate]
	httpSrv *http.Server
	counter atomic.Uint64
	stop    chan struct{}
}

func newServer(h *labcfg.Host) *server {
	return &server{host: h, open: map[int]*listener{}}
}

// apply moves the host to a state: it closes ports that the state does not
// have, opens new ones and swaps content and certificates of the others.
func (s *server) apply(state string) error {
	st, ok := s.host.States[state]
	if !ok {
		return fmt.Errorf("host %s has no state %q", s.host.Name, state)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	want := map[int]labcfg.Listener{}
	for _, l := range st.Listeners {
		want[l.Port] = l
	}
	for port, l := range s.open {
		w, keep := want[port]
		if !keep || w.Kind != l.spec.Kind || (w.TLS == nil) != (l.spec.TLS == nil) {
			l.close()
			delete(s.open, port)
		}
	}
	for port, spec := range want {
		if l, ok := s.open[port]; ok {
			if err := l.update(spec); err != nil {
				return err
			}
			continue
		}
		l, err := openListener(spec)
		if err != nil {
			return fmt.Errorf("port %d: %w", port, err)
		}
		s.open[port] = l
	}
	return nil
}

func tlsKey(t *labcfg.TLS) string {
	b, _ := json.Marshal(t)
	return string(b)
}

func openListener(spec labcfg.Listener) (*listener, error) {
	l := &listener{spec: spec, stop: make(chan struct{})}
	if err := l.update(spec); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(spec.Port))
	if err != nil {
		return nil, err
	}
	l.ln = ln
	switch spec.Kind {
	case "tarpit":
		go l.tarpit()
	default:
		srvLn := ln
		if spec.TLS != nil {
			srvLn = tls.NewListener(ln, &tls.Config{
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return l.cert.Load(), nil },
			})
		}
		l.httpSrv = &http.Server{
			Handler:           http.HandlerFunc(l.serveHTTP),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       30 * time.Second,
			ErrorLog:          log.New(discard{}, "", 0),
		}
		go func() { _ = l.httpSrv.Serve(srvLn) }()
	}
	return l, nil
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// update swaps the site and, when the TLS spec changed, the certificate.
func (l *listener) update(spec labcfg.Listener) error {
	if spec.TLS != nil {
		if key := tlsKey(spec.TLS); key != l.tlsJSON {
			cert, err := makeCert(spec.TLS, time.Now())
			if err != nil {
				return fmt.Errorf("certificate: %w", err)
			}
			l.cert.Store(cert)
			l.tlsJSON = key
		}
	}
	if spec.Site != nil {
		site := *spec.Site
		l.site.Store(&site)
	}
	l.spec = spec
	return nil
}

func (l *listener) close() {
	close(l.stop)
	if l.httpSrv != nil {
		_ = l.httpSrv.Close()
	}
	if l.ln != nil {
		_ = l.ln.Close()
	}
}

// tarpit accepts connections and feeds one byte every ten seconds, like an
// SSH tarpit. A scanner that waits for a full banner on this port stalls.
func (l *listener) tarpit() {
	sem := make(chan struct{}, 64)
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-sem; _ = c.Close() }()
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			deadline := time.After(10 * time.Minute)
			for {
				select {
				case <-l.stop:
					return
				case <-deadline:
					return
				case <-t.C:
					if _, err := c.Write([]byte{byte('a' + rand.IntN(26))}); err != nil {
						return
					}
				}
			}
		}()
	}
}

func findRoute(site *labcfg.Site, path string) *labcfg.Route {
	var fallback *labcfg.Route
	for i := range site.Routes {
		r := &site.Routes[i]
		if r.Path == path {
			return r
		}
		if r.Path == "*" {
			fallback = r
		}
	}
	return fallback
}

func cookieHeader(c labcfg.Cookie) string {
	var b strings.Builder
	b.WriteString(c.Name + "=" + c.Value)
	path := c.Path
	if path == "" {
		path = "/"
	}
	b.WriteString("; Path=" + path)
	if c.MaxAge > 0 {
		b.WriteString("; Max-Age=" + strconv.Itoa(c.MaxAge))
	}
	if c.Secure {
		b.WriteString("; Secure")
	}
	if c.HTTPOnly {
		b.WriteString("; HttpOnly")
	}
	if c.SameSite != "" {
		b.WriteString("; SameSite=" + c.SameSite)
	}
	return b.String()
}

// renderBody fills the placeholders of a volatile body.
func renderBody(body string, counter uint64, now time.Time) string {
	if !strings.Contains(body, "{{") {
		return body
	}
	r := strings.NewReplacer(
		"{{RAND}}", strconv.FormatUint(rand.Uint64(), 36),
		"{{NOW}}", now.UTC().Format(time.RFC3339Nano),
		"{{COUNTER}}", strconv.FormatUint(counter, 10),
	)
	return r.Replace(body)
}

func (l *listener) serveHTTP(w http.ResponseWriter, r *http.Request) {
	site := l.site.Load()
	if site == nil {
		http.Error(w, "no site", http.StatusServiceUnavailable)
		return
	}
	if site.DelayMs > 0 {
		select {
		case <-time.After(time.Duration(site.DelayMs) * time.Millisecond):
		case <-r.Context().Done():
			return
		}
	}
	h := w.Header()
	if site.Server != "" {
		h.Set("Server", site.Server)
	}
	for _, x := range site.Headers {
		h.Add(x.Name, x.Value)
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/favicon.ico" && site.FaviconSeed != "" {
		icon := labcfg.Favicon(site.FaviconSeed)
		h.Set("Content-Type", "image/x-icon")
		h.Set("Content-Length", strconv.Itoa(len(icon)))
		h.Set("Cache-Control", "max-age=86400")
		if r.Method == http.MethodGet {
			_, _ = w.Write(icon)
		}
		return
	}
	route := findRoute(site, r.URL.Path)
	if route == nil {
		h.Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>\n"))
		}
		return
	}
	for _, x := range route.Headers {
		v := x.Value
		if route.Volatile {
			v = renderBody(v, 0, time.Now())
		}
		h.Add(x.Name, v)
	}
	ct := route.ContentType
	if ct == "" {
		ct = "text/html; charset=utf-8"
	}
	h.Set("Content-Type", ct)
	status := route.Status
	if status == 0 {
		status = http.StatusOK
	}
	if route.BasicRealm != "" {
		h.Set("WWW-Authenticate", `Basic realm="`+route.BasicRealm+`"`)
		status = http.StatusUnauthorized
	}
	if route.Location != "" {
		h.Set("Location", route.Location)
		if route.Status == 0 {
			status = http.StatusFound
		}
	}
	if strings.HasPrefix(ct, "text/html") {
		for _, c := range site.Cookies {
			h.Add("Set-Cookie", cookieHeader(c))
		}
	}
	for _, c := range route.Cookies {
		h.Add("Set-Cookie", cookieHeader(c))
	}
	body := route.Body
	if route.Volatile {
		body = renderBody(body, l.counter.Add(1), time.Now())
		h.Set("Cache-Control", "no-store")
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(body))
	}
}
