package httpfp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// recorder remembers every request a test server saw, so tests can assert
// that the collector stays passive.
type recorder struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (r *recorder) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.reqs = append(r.reqs, req.Clone(context.Background()))
		r.mu.Unlock()
		h.ServeHTTP(w, req)
	})
}

func (r *recorder) paths() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, q := range r.reqs {
		out = append(out, q.URL.RequestURI())
	}
	return out
}

func (r *recorder) assertPassive(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, q := range r.reqs {
		if q.Method != http.MethodGet && q.Method != http.MethodHead {
			t.Errorf("request %s %s: method is not GET or HEAD", q.Method, q.URL)
		}
		if q.ContentLength > 0 {
			t.Errorf("request %s has a body", q.URL)
		}
		for _, h := range []string{"Cookie", "Authorization", "Proxy-Authorization"} {
			if q.Header.Get(h) != "" {
				t.Errorf("request %s carries a %s header", q.URL, h)
			}
		}
	}
}

func reqFor(t *testing.T, srv *httptest.Server) model.FingerprintRequest {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	return model.FingerprintRequest{
		IP:        host,
		Port:      port,
		UserAgent: "CzujkaTest/1.0",
		Opts:      model.HTTPOpts{Enabled: true, MaxRedirects: 5, MaxBodyBytes: 64 << 10, TimeoutMs: 2000, Favicon: true},
	}
}

func TestBasicFingerprint(t *testing.T) {
	rec := &recorder{}
	icon := []byte{0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0, 0x68, 4, 0, 0, 0x16, 0, 0, 0}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Add("X-Powered-By", "PHP/8.2.1")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc123secret", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark", Secure: true})
		fmt.Fprint(w, `<!doctype html><html><head>
<title>  Panel
   administracyjny  </title>
<meta name="Generator" content="WordPress 6.4.2">
<link rel="shortcut icon" href="/static/fav.ico">
</head><body><svg><title>icon</title></svg><h1>Zażółć gęślą jaźń</h1></body></html>`)
	})
	mux.HandleFunc("/static/fav.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.Write(icon)
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>Log In</title><input name="user_login"></html>`)
	})
	mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/wp-login.php", http.StatusFound)
	})
	srv := httptest.NewServer(rec.wrap(mux))
	defer srv.Close()

	req := reqFor(t, srv)
	req.Paths = []string{"/wp-login.php", "/old", "/../etc/passwd", "relative", "/a b", "/wp-login.php", "/missing"}
	var counted int
	c := New()
	c.OnRequest = func(method, url string) { counted++ }
	fp, ti, err := c.Fingerprint(context.Background(), req)
	if err != nil || fp == nil {
		t.Fatalf("fingerprint: fp=%v err=%v", fp, err)
	}
	if ti != nil {
		t.Errorf("plain HTTP must not return TLS info")
	}
	if fp.Scheme != "http" || fp.Status != 200 || fp.Host != "127.0.0.1" {
		t.Errorf("scheme/status/host = %q %d %q", fp.Scheme, fp.Status, fp.Host)
	}
	if fp.Title != "Panel administracyjny" {
		t.Errorf("title = %q", fp.Title)
	}
	if fp.MetaGenerator != "WordPress 6.4.2" || fp.Server != "nginx/1.24.0" || fp.PoweredBy != "PHP/8.2.1" {
		t.Errorf("generator/server/powered = %q %q %q", fp.MetaGenerator, fp.Server, fp.PoweredBy)
	}
	if got := fp.Headers["X-Powered-By"]; len(got) != 1 || got[0] != "PHP/8.2.1" {
		t.Errorf("headers[X-Powered-By] = %v", got)
	}
	if len(fp.Cookies) != 2 {
		t.Fatalf("cookies = %+v", fp.Cookies)
	}
	ck := fp.Cookies[0]
	sum := sha256.Sum256([]byte("abc123secret"))
	if ck.Name != "PHPSESSID" || !ck.HTTPOnly || ck.Secure || ck.SameSite != "Lax" || ck.ValueLen != 12 ||
		ck.ValueHash != hex.EncodeToString(sum[:8]) || ck.Value != "abc123secret" || ck.Path != "/" {
		t.Errorf("cookie = %+v", ck)
	}
	if !fp.Cookies[1].Secure {
		t.Errorf("second cookie must be Secure: %+v", fp.Cookies[1])
	}
	if !strings.Contains(fp.BodyExcerpt, "Zażółć gęślą jaźń") || fp.BodyLength == 0 || len(fp.BodySHA256) != 64 || len(fp.BodySimhash) != 16 {
		t.Errorf("body fields: len=%d sha=%q simhash=%q", fp.BodyLength, fp.BodySHA256, fp.BodySimhash)
	}
	if fp.FaviconMMH3 == nil || *fp.FaviconMMH3 != FaviconMMH3(icon) {
		t.Errorf("favicon mmh3 = %v, want %d", fp.FaviconMMH3, FaviconMMH3(icon))
	}
	isum := sha256.Sum256(icon)
	if fp.FaviconSHA256 != hex.EncodeToString(isum[:]) {
		t.Errorf("favicon sha256 = %q", fp.FaviconSHA256)
	}
	if len(fp.Paths) != 3 {
		t.Fatalf("paths = %+v", fp.Paths)
	}
	if p := fp.Paths[0]; p.Path != "/wp-login.php" || p.Status != 200 || p.Title != "Log In" || !strings.Contains(p.Excerpt, "user_login") {
		t.Errorf("path probe 0 = %+v", p)
	}
	if p := fp.Paths[1]; p.Status != 302 || p.Location != "/wp-login.php" {
		t.Errorf("path probe 1 must record the redirect and not follow it: %+v", p)
	}
	if p := fp.Paths[2]; p.Path != "/missing" || p.Status != 404 {
		t.Errorf("path probe 2 = %+v", p)
	}
	for _, p := range rec.paths() {
		if strings.Contains(p, "..") || strings.Contains(p, " ") || p == "relative" {
			t.Errorf("unsafe path was requested: %q", p)
		}
	}
	rec.assertPassive(t)
	if counted != len(rec.paths()) {
		t.Errorf("OnRequest counted %d, server saw %d", counted, len(rec.paths()))
	}
	for _, q := range rec.reqs {
		if q.Header.Get("User-Agent") != "CzujkaTest/1.0" {
			t.Errorf("User-Agent = %q", q.Header.Get("User-Agent"))
		}
	}
}

func TestRedirectChainAndCookies(t *testing.T) {
	rec := &recorder{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "first", Value: "1"})
		http.Redirect(w, r, "/a", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "b?x=1")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "zzz"})
		fmt.Fprint(w, "<title>done</title>")
	})
	srv := httptest.NewServer(rec.wrap(mux))
	defer srv.Close()

	req := reqFor(t, srv)
	req.Opts.Favicon = false
	fp, _, err := New().Fingerprint(context.Background(), req)
	if err != nil || fp == nil {
		t.Fatalf("fp=%v err=%v", fp, err)
	}
	if len(fp.Redirects) != 2 || fp.Redirects[0].Status != 301 || fp.Redirects[1].Status != 302 {
		t.Fatalf("redirects = %+v", fp.Redirects)
	}
	if !strings.HasSuffix(fp.Redirects[0].To, "/a") || !strings.HasSuffix(fp.Redirects[1].To, "/b?x=1") {
		t.Errorf("redirect targets = %+v", fp.Redirects)
	}
	if fp.Title != "done" || fp.Status != 200 || !strings.HasSuffix(fp.FinalURL, "/b?x=1") || !strings.HasSuffix(fp.URL, "/") {
		t.Errorf("final = %q %d %q url=%q", fp.Title, fp.Status, fp.FinalURL, fp.URL)
	}
	if len(fp.Cookies) != 2 {
		t.Errorf("cookies from every hop expected, got %+v", fp.Cookies)
	}
	rec.assertPassive(t)

	// The limit stops the chain and keeps the last response.
	req.Opts.MaxRedirects = 1
	fp, _, _ = New().Fingerprint(context.Background(), req)
	if fp.Status != 302 || len(fp.Redirects) != 2 || !strings.Contains(fp.Error, "redirect limit") {
		t.Errorf("limit: status=%d redirects=%d error=%q", fp.Status, len(fp.Redirects), fp.Error)
	}
	req.Opts.MaxRedirects = 0
	fp, _, _ = New().Fingerprint(context.Background(), req)
	if fp.Status != 301 || len(fp.Redirects) != 1 {
		t.Errorf("no-follow: status=%d redirects=%+v", fp.Status, fp.Redirects)
	}
}

func TestRedirectLoopStops(t *testing.T) {
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/x", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	}))
	defer srv.Close()
	req := reqFor(t, srv)
	req.Opts.Favicon = false
	req.Opts.MaxRedirects = 10
	fp, _, _ := New().Fingerprint(context.Background(), req)
	if fp == nil || !strings.Contains(fp.Error, "redirect loop") || n > 3 {
		t.Fatalf("loop not stopped: requests=%d fp=%+v", n, fp)
	}
}

func TestOffHostRedirectNotFollowed(t *testing.T) {
	var otherHits int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits++
		fmt.Fprint(w, "<title>other host</title>")
	}))
	defer other.Close()

	for _, tc := range []struct{ name, target string }{
		{"other port on the same IP", other.URL + "/landing"},
		{"other host name", "http://sso.example.org/login"},
		{"other IP", "http://192.0.2.10/"},
		{"other scheme", "https://127.0.0.1/"},
		{"scheme-relative", "//evil.example.org/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			srv := httptest.NewServer(rec.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/favicon.ico" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Location", tc.target)
				w.WriteHeader(http.StatusFound)
			})))
			defer srv.Close()
			fp, _, err := New().Fingerprint(context.Background(), reqFor(t, srv))
			if err != nil || fp == nil {
				t.Fatalf("fp=%v err=%v", fp, err)
			}
			if fp.Status != 302 || len(fp.Redirects) != 1 || !strings.Contains(fp.Error, "not followed") {
				t.Errorf("status=%d redirects=%+v error=%q", fp.Status, fp.Redirects, fp.Error)
			}
			if fp.FinalURL != fp.URL {
				t.Errorf("final URL moved off the origin: %q", fp.FinalURL)
			}
			for _, p := range rec.paths() {
				if p != "/" && p != "/favicon.ico" {
					t.Errorf("unexpected request %q", p)
				}
			}
		})
	}
	if otherHits != 0 {
		t.Fatalf("the collector left its scope: %d requests reached the other server", otherHits)
	}
}

func TestHostnameIsHostHeaderAndStaysOnTheIP(t *testing.T) {
	var hosts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hosts = append(hosts, r.Host)
		if r.URL.Path == "/" {
			// Same name: followed, and it must reach this test server, not DNS.
			http.Redirect(w, r, "http://"+r.Host+"/home", http.StatusFound)
			return
		}
		fmt.Fprint(w, "<title>vhost</title>")
	}))
	defer srv.Close()
	req := reqFor(t, srv)
	req.Hostname = "Intranet.Example.Test."
	req.Opts.Favicon = false
	fp, _, err := New().Fingerprint(context.Background(), req)
	if err != nil || fp == nil {
		t.Fatalf("fp=%v err=%v", fp, err)
	}
	if fp.Title != "vhost" || fp.Host != "intranet.example.test" {
		t.Errorf("title=%q host=%q error=%q", fp.Title, fp.Host, fp.Error)
	}
	for _, h := range hosts {
		if !strings.HasPrefix(h, "intranet.example.test:") {
			t.Errorf("Host header = %q", h)
		}
	}
}

func TestGzipAndCharset(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			t.Errorf("Accept-Encoding = %q", r.Header.Get("Accept-Encoding"))
		}
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		// ISO-8859-2 bytes for "Zażółć": Z a 0xBF 0xF3 0xB3 0xE6
		zw.Write([]byte("<html><head><meta charset=\"iso-8859-2\"><title>Za\xbf\xf3\xb3\xe6</title></head></html>"))
		zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/html")
		w.Write(buf.Bytes())
	})
	mux.HandleFunc("/win", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=windows-1250")
		w.Write([]byte("<title>\xb3\xf3d\x9f</title>")) // "łódź"
	})
	mux.HandleFunc("/broken", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write([]byte("<title>not gzip at all</title>"))
	})
	mux.HandleFunc("/bin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte{0x7f, 'E', 'L', 'F', 0, 1, 2, 3, 0xff, 0xfe})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req := reqFor(t, srv)
	req.Opts.Favicon = false
	req.Paths = []string{"/win", "/broken", "/bin"}
	fp, _, err := New().Fingerprint(context.Background(), req)
	if err != nil || fp == nil {
		t.Fatalf("fp=%v err=%v", fp, err)
	}
	if fp.Title != "Zażółć" {
		t.Errorf("gzip + iso-8859-2 title = %q", fp.Title)
	}
	if len(fp.Paths) != 3 {
		t.Fatalf("paths = %+v", fp.Paths)
	}
	if fp.Paths[0].Title != "łódź" {
		t.Errorf("windows-1250 title = %q", fp.Paths[0].Title)
	}
	if fp.Paths[1].Title != "not gzip at all" {
		t.Errorf("broken gzip must keep the raw body, title = %q", fp.Paths[1].Title)
	}
	if fp.Paths[2].Excerpt != "" || fp.Paths[2].Length != 10 {
		t.Errorf("binary body: excerpt=%q length=%d", fp.Paths[2].Excerpt, fp.Paths[2].Length)
	}
}

func TestOversizedAndEndlessBodies(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Length", strconv.Itoa(13+5<<20))
		fmt.Fprint(w, "<title>big</title>")
		chunk := bytes.Repeat([]byte("lorem ipsum "), 4096)
		for sent := 18; sent < 13+5<<20; {
			n := min(len(chunk), 13+5<<20-sent)
			if _, err := w.Write(chunk[:n]); err != nil {
				return
			}
			sent += n
		}
	})
	mux.HandleFunc("/endless", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fl := w.(http.Flusher)
		for {
			if _, err := w.Write(bytes.Repeat([]byte("a"), 8192)); err != nil {
				return
			}
			fl.Flush()
		}
	})
	mux.HandleFunc("/bomb", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write(bytes.Repeat([]byte{'0'}, 20<<20))
		zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		w.Write(buf.Bytes())
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req := reqFor(t, srv)
	req.Opts.Favicon = false
	req.Opts.MaxBodyBytes = 32 << 10
	req.Paths = []string{"/endless", "/bomb"}
	c := New()
	c.ExcerptBytes = 4096
	start := time.Now()
	fp, _, err := c.Fingerprint(context.Background(), req)
	if err != nil || fp == nil {
		t.Fatalf("fp=%v err=%v", fp, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("bounded reads took %v", time.Since(start))
	}
	if fp.Title != "big" || len(fp.BodyExcerpt) > 4096 || fp.BodyLength != 13+5<<20 {
		t.Errorf("big body: title=%q excerpt=%d length=%d", fp.Title, len(fp.BodyExcerpt), fp.BodyLength)
	}
	if len(fp.Paths) != 2 {
		t.Fatalf("paths = %d", len(fp.Paths))
	}
	if fp.Paths[0].Length != 32<<10 {
		t.Errorf("endless body length = %d, want the limit", fp.Paths[0].Length)
	}
	if fp.Paths[1].Length != 32<<10 {
		t.Errorf("gzip bomb decoded length = %d, want the limit", fp.Paths[1].Length)
	}
}

func TestSlowServers(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<title>slow body</title>")
		w.(http.Flusher).Flush()
		select { // the rest of the body never comes
		case <-release:
		case <-r.Context().Done():
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req := reqFor(t, srv)
	req.Opts.Favicon = false
	req.Opts.TimeoutMs = 300
	start := time.Now()
	fp, _, err := New().Fingerprint(context.Background(), req)
	if err != nil || fp == nil {
		t.Fatalf("fp=%v err=%v", fp, err)
	}
	if fp.Title != "slow body" || !strings.Contains(fp.Error, "timed out") {
		t.Errorf("partial body must be kept: title=%q error=%q", fp.Title, fp.Error)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("slow body took %v", d)
	}

	// A server that accepts and never answers is not HTTP for us.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { <-release; conn.Close() }()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	start = time.Now()
	fp, ti, err := New().Fingerprint(context.Background(), model.FingerprintRequest{
		IP: "127.0.0.1", Port: port, Opts: model.HTTPOpts{TimeoutMs: 300},
	})
	if fp != nil || ti != nil || err != nil {
		t.Errorf("silent server: fp=%v tls=%v err=%v", fp, ti, err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("silent server took %v", d)
	}

	// A cancelled context ends the call with its error.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _, err = New().Fingerprint(ctx, model.FingerprintRequest{IP: "127.0.0.1", Port: port, Opts: model.HTTPOpts{TimeoutMs: 5000}})
	if err == nil {
		t.Errorf("cancelled context must return an error")
	}
}

func TestNotHTTPAndClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			conn.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	fp, ti, err := New().Fingerprint(context.Background(), model.FingerprintRequest{IP: "127.0.0.1", Port: port, Opts: model.HTTPOpts{TimeoutMs: 1000}})
	if fp != nil || ti != nil || err != nil {
		t.Errorf("SSH banner: want (nil, nil, nil), got fp=%v tls=%v err=%v", fp, ti, err)
	}

	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ = net.SplitHostPort(closed.Addr().String())
	closed.Close()
	port, _ = strconv.Atoi(portStr)
	fp, ti, err = New().Fingerprint(context.Background(), model.FingerprintRequest{IP: "127.0.0.1", Port: port, Opts: model.HTTPOpts{TimeoutMs: 1000}})
	if fp != nil || ti != nil || err == nil {
		t.Errorf("closed port: want an error, got fp=%v tls=%v err=%v", fp, ti, err)
	}

	for _, bad := range []model.FingerprintRequest{{IP: "example.org", Port: 80}, {IP: "127.0.0.1", Port: 0}, {IP: "127.0.0.1", Port: 70000}} {
		if _, _, err := New().Fingerprint(context.Background(), bad); err == nil {
			t.Errorf("request %+v must be rejected", bad)
		}
	}
}

// testCert makes a self-signed leaf certificate.
func testCert(t *testing.T, cn string, sans []string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xC0FFEE),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Czujka Test"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, s)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func tlsServer(t *testing.T, cert tls.Certificate, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestTLSSelfSigned(t *testing.T) {
	now := time.Now()
	cert := testCert(t, "panel.example.test", []string{"panel.example.test", "*.dev.example.test", "10.1.2.3"}, now.Add(-time.Hour), now.Add(90*24*time.Hour+time.Hour))
	var sni string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>secure</title>")
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = h.ServerName
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	// No hint and an uncommon port: plain HTTP is tried first and the collector falls back to TLS.
	req := reqFor(t, srv)
	req.Opts.Favicon = false
	fp, ti, err := New().Fingerprint(context.Background(), req)
	if err != nil || fp == nil || ti == nil {
		t.Fatalf("fp=%v tls=%v err=%v", fp, ti, err)
	}
	if fp.Scheme != "https" || fp.Title != "secure" || !strings.HasPrefix(fp.URL, "https://127.0.0.1:") {
		t.Errorf("scheme=%q title=%q url=%q", fp.Scheme, fp.Title, fp.URL)
	}
	if !ti.SelfSigned || ti.Expired || ti.DaysLeft != 90 || ti.HostMismatch {
		t.Errorf("self-signed=%v expired=%v days=%d mismatch=%v", ti.SelfSigned, ti.Expired, ti.DaysLeft, ti.HostMismatch)
	}
	if ti.SubjectCN != "panel.example.test" || ti.SubjectOrg != "Czujka Test" || ti.Issuer != "panel.example.test" {
		t.Errorf("subject=%q org=%q issuer=%q", ti.SubjectCN, ti.SubjectOrg, ti.Issuer)
	}
	if len(ti.SANs) != 3 || ti.SANs[2] != "10.1.2.3" {
		t.Errorf("sans = %v", ti.SANs)
	}
	if ti.KeyType != "ECDSA" || ti.KeyBits != 256 || ti.Serial != "C0FFEE" || len(ti.SHA256) != 64 {
		t.Errorf("key=%s/%d serial=%q sha=%q", ti.KeyType, ti.KeyBits, ti.Serial, ti.SHA256)
	}
	if !strings.HasPrefix(ti.Version, "TLS 1.") || ti.Cipher == "" {
		t.Errorf("version=%q cipher=%q", ti.Version, ti.Cipher)
	}

	// With a hostname: SNI and Host carry it, and the certificate is checked against it.
	req.TLSHint = true
	req.Hostname = "panel.example.test"
	fp, ti, _ = New().Fingerprint(context.Background(), req)
	if fp == nil || ti == nil || ti.HostMismatch || sni != "panel.example.test" || fp.Host != "panel.example.test" {
		t.Errorf("hostname match: mismatch=%v sni=%q fp=%+v", ti != nil && ti.HostMismatch, sni, fp)
	}
	req.Hostname = "x.dev.example.test"
	_, ti, _ = New().Fingerprint(context.Background(), req)
	if ti == nil || ti.HostMismatch {
		t.Errorf("wildcard SAN must match")
	}
	req.Hostname = "other.example.test"
	_, ti, _ = New().Fingerprint(context.Background(), req)
	if ti == nil || !ti.HostMismatch {
		t.Errorf("hostname mismatch must be recorded")
	}
}

func TestTLSExpiredCertificate(t *testing.T) {
	now := time.Now()
	cert := testCert(t, "old.example.test", nil, now.Add(-400*24*time.Hour), now.Add(-10*24*time.Hour-time.Hour))
	srv := tlsServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>expired but alive</title>")
	}))
	req := reqFor(t, srv)
	req.TLSHint = true
	req.Opts.Favicon = false
	fp, ti, err := New().Fingerprint(context.Background(), req)
	if err != nil || fp == nil || ti == nil {
		t.Fatalf("an expired certificate must be accepted and recorded: fp=%v tls=%v err=%v", fp, ti, err)
	}
	if !ti.Expired || ti.DaysLeft != -11 || !ti.SelfSigned || fp.Title != "expired but alive" {
		t.Errorf("expired=%v days=%d self-signed=%v title=%q", ti.Expired, ti.DaysLeft, ti.SelfSigned, fp.Title)
	}
}

func TestTLSHintOnPlainPortFallsBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>plain</title>")
	}))
	defer srv.Close()
	req := reqFor(t, srv)
	req.TLSHint = true
	req.Opts.Favicon = false
	fp, ti, err := New().Fingerprint(context.Background(), req)
	if err != nil || fp == nil || ti != nil || fp.Scheme != "http" || fp.Title != "plain" {
		t.Fatalf("fp=%+v tls=%v err=%v", fp, ti, err)
	}
}

func TestTLSServiceThatIsNotHTTP(t *testing.T) {
	now := time.Now()
	cert := testCert(t, "imap.example.test", nil, now.Add(-time.Hour), now.Add(24*time.Hour))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.Write([]byte("* OK IMAP4rev1 ready\r\n"))
				buf := make([]byte, 512)
				conn.SetReadDeadline(time.Now().Add(time.Second))
				conn.Read(buf)
			}()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	fp, ti, err := New().Fingerprint(context.Background(), model.FingerprintRequest{
		IP: "127.0.0.1", Port: port, NameHint: "ssl/imap", Opts: model.HTTPOpts{TimeoutMs: 1500},
	})
	if err != nil || fp != nil || ti == nil || ti.SubjectCN != "imap.example.test" {
		t.Fatalf("want TLS info without HTTP: fp=%v tls=%+v err=%v", fp, ti, err)
	}
}

func TestFaviconFallbackAndSoftNotFound(t *testing.T) {
	icon := []byte("\x89PNG\r\n\x1a\n" + strings.Repeat("icon-bytes", 20))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// The page names an icon on another host: it must not be fetched.
		fmt.Fprint(w, `<html><head><link rel="icon" href="http://cdn.example.org/i.png"><title>x</title></head></html>`)
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(icon)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	fp, _, _ := New().Fingerprint(context.Background(), reqFor(t, srv))
	if fp == nil || fp.FaviconMMH3 == nil || *fp.FaviconMMH3 != FaviconMMH3(icon) {
		t.Fatalf("fallback to /favicon.ico failed: %+v", fp)
	}

	soft := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>login</title></html>") // also for /favicon.ico
	}))
	defer soft.Close()
	fp, _, _ = New().Fingerprint(context.Background(), reqFor(t, soft))
	if fp == nil || fp.FaviconMMH3 != nil || fp.FaviconSHA256 != "" {
		t.Fatalf("an HTML answer is not a favicon: %+v", fp)
	}

	// Favicon disabled: no request for it.
	rec := &recorder{}
	off := httptest.NewServer(rec.wrap(mux))
	defer off.Close()
	req := reqFor(t, off)
	req.Opts.Favicon = false
	New().Fingerprint(context.Background(), req)
	if got := rec.paths(); len(got) != 1 {
		t.Errorf("favicon off: requests = %v", got)
	}
}

func TestMethodGuard(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "get", ""} {
		if methodAllowed(m) {
			t.Errorf("method %q must not be allowed", m)
		}
	}
	s, _ := New().newSession(model.FingerprintRequest{IP: "127.0.0.1", Port: 9})
	if _, err := s.do(context.Background(), "POST", s.baseURL("http"), 10); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("POST must be refused before any network use, got %v", err)
	}
}

func TestSafePath(t *testing.T) {
	good := []string{"/", "/wp-login.php", "/api/v1/version", "/a/b_c-d.e~f", "/index.php?option=com_users&view=login", "/.well-known/security.txt"}
	bad := []string{"", "x", "//evil.example.org/", "/a/../b", "/..", "/a%2e%2e/b", "/a b", "/a\r\nX: y", "/a#b", "/a?b?c", "/a;b", "/a\\b", "/" + strings.Repeat("a", 300), "/a@b", "/a:b", "/<script>"}
	for _, p := range good {
		if !SafePath(p) {
			t.Errorf("SafePath(%q) = false", p)
		}
	}
	for _, p := range bad {
		if SafePath(p) {
			t.Errorf("SafePath(%q) = true", p)
		}
	}
}

func TestWaitHookCanStopRequests(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	c := New()
	c.Wait = func(ctx context.Context, ip string) error { return context.Canceled }
	fp, _, _ := c.Fingerprint(context.Background(), reqFor(t, srv))
	if fp != nil || hits != 0 {
		t.Errorf("a refusing limiter must stop every request: fp=%v hits=%d", fp, hits)
	}
}
