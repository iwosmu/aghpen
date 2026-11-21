package httpfp

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html/charset"

	"github.com/iwosmu/aghpen/internal/model"
)

// response is one fetched resource with a bounded, decoded body.
type response struct {
	url      *url.URL
	status   int
	header   http.Header
	cookies  []model.Cookie
	raw      []byte // decoded (gzip removed) bytes, at most the body limit
	text     string // raw converted to valid UTF-8
	length   int    // best known body length in bytes
	sha256   string // of raw
	elapsed  time.Duration
	bodyNote string // why the body is partial, if it is
}

// methodAllowed is the single place that decides which HTTP methods exist in
// this package. Safe detection: GET and HEAD only.
func methodAllowed(m string) bool { return m == http.MethodGet || m == http.MethodHead }

// do sends one request without a body, credentials or cookies and reads a
// bounded body. It never follows redirects.
func (s *session) do(ctx context.Context, method string, u *url.URL, maxBody int) (*response, error) {
	if !methodAllowed(method) {
		return nil, fmt.Errorf("httpfp: method %s is not allowed (safe detection: GET and HEAD only)", method)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("httpfp: scheme %q is not allowed", u.Scheme)
	}
	if s.c.Wait != nil {
		if err := s.c.Wait(ctx, s.req.IP); err != nil {
			return nil, err
		}
	}
	rctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(rctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Host = u.Host
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip")

	start := time.Now()
	resp, err := s.transport().RoundTrip(req)
	if s.c.OnRequest != nil {
		s.c.OnRequest(method, u.String())
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &response{url: u, status: resp.StatusCode, header: resp.Header, elapsed: time.Since(start)}
	r.cookies = cookiesOf(resp)

	// Read at most maxBody+1 bytes: the extra byte tells "exactly the limit" from "more".
	wire, rerr := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody)+1))
	truncated := len(wire) > maxBody
	if truncated {
		wire = wire[:maxBody]
	}
	if rerr != nil {
		switch {
		case errors.Is(rerr, context.DeadlineExceeded) || isTimeout(rerr):
			r.bodyNote = "body read timed out, partial body kept"
		default:
			r.bodyNote = "body read failed, partial body kept: " + shortErr(rerr)
		}
	}

	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	body, note := decodeBody(wire, enc, maxBody)
	if note != "" && r.bodyNote == "" {
		r.bodyNote = note
	}
	r.raw = body
	r.length = len(body)
	if truncated && (enc == "" || enc == "identity") && resp.ContentLength > int64(len(body)) {
		r.length = int(min(resp.ContentLength, int64(1)<<31-1))
	}
	sum := sha256.Sum256(body)
	r.sha256 = hex.EncodeToString(sum[:])
	r.text = toUTF8(body, resp.Header.Get("Content-Type"))
	return r, nil
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// decodeBody removes a gzip or deflate content encoding. The output is bounded
// too, so a compression bomb cannot grow past the body limit. A broken or cut
// stream returns what could be decoded.
func decodeBody(wire []byte, enc string, limit int) ([]byte, string) {
	var rd io.Reader
	switch enc {
	case "", "identity":
		return wire, ""
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(wire))
		if err != nil {
			return wire, "invalid gzip body kept as is"
		}
		rd = zr
	case "deflate":
		zr, err := zlib.NewReader(bytes.NewReader(wire))
		if err != nil {
			rd = flate.NewReader(bytes.NewReader(wire))
		} else {
			rd = zr
		}
	default:
		return wire, "unsupported content encoding " + truncate(enc, 20) + ", body kept as is"
	}
	out, err := io.ReadAll(io.LimitReader(rd, int64(limit)))
	if err != nil && len(out) == 0 {
		return wire, "broken " + enc + " body kept as is"
	}
	return out, ""
}

// toUTF8 converts a text body to valid UTF-8 using the charset of the
// Content-Type header, a <meta> declaration or a BOM. Binary bodies yield "".
func toUTF8(body []byte, contentType string) string {
	if len(body) == 0 {
		return ""
	}
	if !looksTextual(body, contentType) {
		return ""
	}
	if utf8.Valid(body) && !declaresOtherCharset(contentType) {
		return strings.ReplaceAll(string(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))), "\x00", "")
	}
	head := body
	if len(head) > 1024 {
		head = head[:1024]
	}
	e, _, _ := charset.DetermineEncoding(head, contentType)
	if e != nil {
		if out, err := e.NewDecoder().Bytes(body); err == nil {
			body = out
		}
	}
	return strings.ReplaceAll(strings.ToValidUTF8(string(body), "�"), "\x00", "")
}

func declaresOtherCharset(contentType string) bool {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	cs := strings.ToLower(params["charset"])
	return cs != "" && cs != "utf-8" && cs != "utf8" && cs != "us-ascii"
}

func looksTextual(body []byte, contentType string) bool {
	mt, _, _ := mime.ParseMediaType(contentType)
	mt = strings.ToLower(mt)
	switch {
	case strings.HasPrefix(mt, "text/"), strings.Contains(mt, "json"), strings.Contains(mt, "xml"),
		strings.Contains(mt, "javascript"), strings.Contains(mt, "html"), strings.Contains(mt, "yaml"):
		return true
	case strings.HasPrefix(mt, "image/"), strings.HasPrefix(mt, "audio/"), strings.HasPrefix(mt, "video/"),
		strings.HasPrefix(mt, "font/"), mt == "application/zip", mt == "application/pdf":
		return false
	}
	sniff := http.DetectContentType(body)
	return strings.HasPrefix(sniff, "text/") || strings.Contains(sniff, "json") || strings.Contains(sniff, "xml")
}

func cookiesOf(resp *http.Response) []model.Cookie {
	var out []model.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "" {
			continue
		}
		sum := sha256.Sum256([]byte(c.Value))
		ss := ""
		switch c.SameSite {
		case http.SameSiteLaxMode:
			ss = "Lax"
		case http.SameSiteStrictMode:
			ss = "Strict"
		case http.SameSiteNoneMode:
			ss = "None"
		}
		out = append(out, model.Cookie{
			Name:      truncate(c.Name, 128),
			Domain:    truncate(c.Domain, 255),
			Path:      truncate(c.Path, 255),
			Secure:    c.Secure,
			HTTPOnly:  c.HttpOnly,
			SameSite:  ss,
			ValueLen:  len(c.Value),
			ValueHash: hex.EncodeToString(sum[:8]),
			Value:     truncate(c.Value, 4096),
		})
	}
	return out
}

// mergeCookies keeps one cookie per name; a later hop replaces an earlier one.
func mergeCookies(have, add []model.Cookie) []model.Cookie {
	for _, c := range add {
		replaced := false
		for i := range have {
			if have[i].Name == c.Name {
				have[i], replaced = c, true
				break
			}
		}
		if !replaced && len(have) < 64 {
			have = append(have, c)
		}
	}
	return have
}

// cleanHeaders copies response headers with canonical names and bounded sizes.
func cleanHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(names) > 100 {
		names = names[:100]
	}
	for _, k := range names {
		vals := h[k]
		if len(vals) > 20 {
			vals = vals[:20]
		}
		cp := make([]string, len(vals))
		for i, v := range vals {
			cp[i] = truncate(strings.ToValidUTF8(v, "�"), maxHeaderValueBytes)
		}
		out[http.CanonicalHeaderKey(k)] = cp
	}
	return out
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string { return truncateUTF8(s, n) }

func truncateUTF8(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// SafePath is the structural check the collector applies to every extra path,
// whatever the caller's policy already did. It accepts an absolute path with
// an optional short query, made of a strict character set, without traversal.
func SafePath(p string) bool {
	if len(p) == 0 || len(p) > 256 || p[0] != '/' || strings.HasPrefix(p, "//") {
		return false
	}
	if strings.Contains(p, "..") {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '/' || c == '_' || c == '-' || c == '.' || c == '~' || c == '?' || c == '=' || c == '&' || c == '+' || c == ','
		if !ok {
			return false
		}
	}
	return strings.Count(p, "?") <= 1
}

// paths fetches the extra safe paths of the request. Redirects are recorded
// in Location and never followed.
func (s *session) paths(ctx context.Context, scheme string, fp *model.HTTPFingerprint) {
	maxPaths := pickInt(s.c.MaxPaths, DefaultMaxPaths)
	seen := map[string]bool{}
	failures := 0
	for _, p := range s.req.Paths {
		if ctx.Err() != nil || len(fp.Paths) >= maxPaths {
			return
		}
		p = strings.TrimSpace(p)
		if !SafePath(p) || seen[p] {
			continue
		}
		seen[p] = true
		u := s.baseURL(scheme)
		if i := strings.IndexByte(p, '?'); i >= 0 {
			u.Path, u.RawQuery = p[:i], p[i+1:]
		} else {
			u.Path = p
		}
		r, err := s.do(ctx, http.MethodGet, u, s.maxBody)
		if err != nil {
			// A host that stops answering is left alone after two failures in a row.
			if failures++; failures >= 2 {
				return
			}
			continue
		}
		failures = 0
		doc := parseHTML(r.text)
		fp.Paths = append(fp.Paths, model.PathProbe{
			Path:       p,
			Status:     r.status,
			Title:      doc.title,
			Length:     r.length,
			BodySHA256: r.sha256,
			Excerpt:    truncateUTF8(r.text, s.pathExc),
			Headers:    cleanHeaders(r.header),
			Location:   truncate(r.header.Get("Location"), 1024),
		})
	}
}

// favicon fetches the icon named by the page, or /favicon.ico, from the same
// origin and stores the Shodan-style MurmurHash3 and the SHA-256 of it.
func (s *session) favicon(ctx context.Context, scheme string, fp *model.HTTPFingerprint) {
	base := s.baseURL(scheme)
	cands := append([]*url.URL{}, s.icons...)
	ico := *base
	ico.Path = "/favicon.ico"
	cands = append(cands, &ico)
	tried := map[string]bool{}
	for _, u := range cands {
		if ctx.Err() != nil || len(tried) >= 3 {
			return
		}
		if tried[u.String()] || !sameOrigin(base, u) {
			continue
		}
		tried[u.String()] = true
		data := s.fetchIcon(ctx, u)
		if len(data) == 0 {
			continue
		}
		h := FaviconMMH3(data)
		sum := sha256.Sum256(data)
		fp.FaviconMMH3 = &h
		fp.FaviconSHA256 = hex.EncodeToString(sum[:])
		return
	}
}

func (s *session) fetchIcon(ctx context.Context, u *url.URL) []byte {
	for hop := 0; hop < 3; hop++ {
		r, err := s.do(ctx, http.MethodGet, u, maxFaviconBytes)
		if err != nil {
			return nil
		}
		if isRedirect(r.status) {
			next, perr := u.Parse(r.header.Get("Location"))
			if perr != nil || !sameOrigin(u, next) {
				return nil
			}
			next.Fragment, next.User = "", nil
			u = next
			continue
		}
		if r.status != http.StatusOK || len(r.raw) == 0 {
			return nil
		}
		// An HTML answer is a soft 404 or a login page, not an icon.
		ct := strings.ToLower(r.header.Get("Content-Type"))
		sniff := http.DetectContentType(r.raw)
		isSVG := strings.Contains(ct, "svg") || bytes.Contains(r.raw[:min(len(r.raw), 512)], []byte("<svg"))
		if !isSVG && (strings.HasPrefix(sniff, "text/") || strings.Contains(ct, "text/html") || strings.Contains(ct, "json")) {
			return nil
		}
		return r.raw
	}
	return nil
}

// iconLinks stores the same-origin icon URLs of a page for the favicon step.
func (s *session) iconLinks(hrefs []string, page *url.URL) {
	s.icons = s.icons[:0]
	for _, h := range hrefs {
		if strings.HasPrefix(strings.ToLower(h), "data:") {
			continue
		}
		u, err := page.Parse(h)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		u.Fragment, u.User = "", nil
		if sameOrigin(page, u) {
			s.icons = append(s.icons, u)
		}
	}
}
