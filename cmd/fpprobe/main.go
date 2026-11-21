// Command fpprobe is the developer CLI of the Czujka fingerprint stack. It
// fingerprints one HTTP or TLS service and prints the result with the
// signature matches as JSON, or validates a signature file.
//
//	fpprobe -addr 127.0.0.1:8080 [-host name] [-paths] [-brief]
//	fpprobe -validate file.yaml
//	fpprobe -list
//
// The probe is passive: GET requests only, to the given address only.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/httpfp"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/sig"
)

type output struct {
	Target         string                 `json:"target"`
	Hostname       string                 `json:"hostname,omitempty"`
	PathsRequested []string               `json:"paths_requested,omitempty"`
	Requests       int                    `json:"requests"`
	ElapsedMs      int64                  `json:"elapsed_ms"`
	HTTP           *model.HTTPFingerprint `json:"http"`
	TLS            *model.TLSInfo         `json:"tls"`
	Matches        []model.SigMatch       `json:"matches"`
	Technologies   []model.Technology     `json:"technologies"`
	Classes        []string               `json:"classes"`
}

func main() {
	var (
		addr     = flag.String("addr", "", "address to probe as IP:port, for example 127.0.0.1:8080")
		host     = flag.String("host", "", "host name for the Host header and SNI")
		tlsHint  = flag.Bool("tls", false, "try TLS first")
		paths    = flag.Bool("paths", false, "also GET the safe extra paths that signatures ask for")
		maxPaths = flag.Int("max-paths", 20, "limit of extra paths with -paths")
		timeout  = flag.Int("timeout", 8000, "timeout of one request in milliseconds")
		maxBody  = flag.Int("max-body", httpfp.DefaultMaxBodyBytes, "limit of body bytes read")
		redirs   = flag.Int("redirects", 5, "same-origin redirects to follow")
		name     = flag.String("name", "", "nmap service name hint, for example https")
		ua       = flag.String("ua", httpfp.DefaultUserAgent, "User-Agent header")
		custom   = flag.String("sigs", "", "extra signature YAML file to load on top of the built-in library")
		brief    = flag.Bool("brief", false, "print a short summary instead of the full JSON")
		full     = flag.Bool("full", false, "keep body excerpts and cookie values in the JSON output")
		validate = flag.String("validate", "", "validate a signature YAML file and exit")
		list     = flag.Bool("list", false, "list the built-in signatures and exit")
	)
	flag.Parse()

	switch {
	case *validate != "":
		os.Exit(runValidate(*validate))
	case *list:
		os.Exit(runList())
	case *addr == "":
		flag.Usage()
		os.Exit(2)
	}

	engine, err := sig.NewBuiltinEngine()
	if err != nil {
		fatal(err)
	}
	if *custom != "" {
		data, err := os.ReadFile(*custom)
		if err != nil {
			fatal(err)
		}
		records, err := sig.Builtin()
		if err != nil {
			fatal(err)
		}
		parsed, val := sig.Parse(string(data))
		if !val.OK {
			printJSON(val)
			fatal(fmt.Errorf("%s: signature rejected", *custom))
		}
		for _, s := range parsed {
			m := s.Model()
			m.Enabled = true
			records = append(records, m)
		}
		engine.Load(records)
	}

	ipStr, portStr, err := net.SplitHostPort(*addr)
	if err != nil {
		fatal(fmt.Errorf("-addr must be IP:port: %w", err))
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || net.ParseIP(ipStr) == nil {
		fatal(fmt.Errorf("-addr must be IP:port, got %q", *addr))
	}
	req := model.FingerprintRequest{
		IP: ipStr, Port: port, Hostname: *host, TLSHint: *tlsHint, NameHint: *name, UserAgent: *ua,
		Opts: model.HTTPOpts{Enabled: true, MaxRedirects: *redirs, SignaturePaths: *paths, MaxBodyBytes: *maxBody, TimeoutMs: *timeout, Favicon: true},
	}
	collector := httpfp.New()
	requests := 0
	collector.OnRequest = func(string, string) { requests++ }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	start := time.Now()
	out := output{Target: *addr, Hostname: *host}
	fp, ti, err := collector.Fingerprint(ctx, req)
	if err != nil {
		fatal(err)
	}
	if fp != nil && *paths {
		// Two passes: the root page tells which extra paths are worth the requests.
		svc := &model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: *name, HTTP: fp, TLS: ti}
		req.Paths = engine.PathsFor(svc, *maxPaths)
		out.PathsRequested = req.Paths
		req.Opts.Favicon = false
		fav, favSHA := fp.FaviconMMH3, fp.FaviconSHA256
		if fp2, ti2, err := collector.Fingerprint(ctx, req); err == nil && fp2 != nil {
			fp, ti = fp2, ti2
			fp.FaviconMMH3, fp.FaviconSHA256 = fav, favSHA
		}
	}
	out.ElapsedMs = time.Since(start).Milliseconds()
	out.Requests = requests
	out.HTTP, out.TLS = fp, ti

	svc := &model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: *name, HTTP: fp, TLS: ti}
	if ti != nil {
		svc.Tunnel = "ssl"
	}
	out.Matches, out.Technologies, out.Classes = engine.MatchHost(svc, *host)

	if *brief {
		printBrief(out)
		return
	}
	if !*full && out.HTTP != nil {
		cp := *out.HTTP
		cp.BodyExcerpt = shorten(cp.BodyExcerpt, 300)
		cp.Cookies = append([]model.Cookie(nil), cp.Cookies...)
		for i := range cp.Cookies {
			cp.Cookies[i].Value = ""
		}
		cp.Paths = append([]model.PathProbe(nil), cp.Paths...)
		for i := range cp.Paths {
			cp.Paths[i].Excerpt = shorten(cp.Paths[i].Excerpt, 120)
			cp.Paths[i].Headers = nil
		}
		out.HTTP = &cp
	}
	printJSON(out)
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + fmt.Sprintf("… [%d bytes]", len(s))
}

func printBrief(out output) {
	fmt.Printf("target:   %s\n", out.Target)
	if out.HTTP == nil {
		fmt.Println("http:     no HTTP answer")
	} else {
		h := out.HTTP
		fmt.Printf("http:     %s -> %d %q (%d B, %d ms, %d requests)\n", h.URL, h.Status, h.Title, h.BodyLength, h.ResponseMs, out.Requests)
		if h.FinalURL != h.URL {
			fmt.Printf("final:    %s (%d redirects)\n", h.FinalURL, len(h.Redirects))
		}
		fmt.Printf("server:   %q powered-by: %q generator: %q\n", h.Server, h.PoweredBy, h.MetaGenerator)
		if h.FaviconMMH3 != nil {
			fmt.Printf("favicon:  mmh3 %d sha256 %s\n", *h.FaviconMMH3, h.FaviconSHA256)
		}
		var cookies []string
		for _, c := range h.Cookies {
			cookies = append(cookies, c.Name)
		}
		if len(cookies) > 0 {
			fmt.Printf("cookies:  %s\n", strings.Join(cookies, ", "))
		}
		if h.Error != "" {
			fmt.Printf("note:     %s\n", h.Error)
		}
	}
	if t := out.TLS; t != nil {
		fmt.Printf("tls:      %s %s cn=%q issuer=%q self-signed=%t expired=%t days-left=%d key=%s/%d\n",
			t.Version, t.Cipher, t.SubjectCN, t.Issuer, t.SelfSigned, t.Expired, t.DaysLeft, t.KeyType, t.KeyBits)
	}
	var techs []string
	for _, t := range out.Technologies {
		s := t.Name
		if t.Version != "" {
			s += " " + t.Version
		}
		techs = append(techs, fmt.Sprintf("%s (%.2f)", s, t.Confidence))
	}
	fmt.Printf("tech:     %s\n", strings.Join(techs, ", "))
	fmt.Printf("classes:  %s\n", strings.Join(out.Classes, ", "))
	var findings []string
	for _, m := range out.Matches {
		if m.Category == model.CatHeader || m.Category == model.CatCookie || m.Category == model.CatEnvironment {
			findings = append(findings, m.Signature)
		}
	}
	fmt.Printf("findings: %s\n", strings.Join(findings, ", "))
}

func runValidate(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fpprobe:", err)
		return 2
	}
	val := sig.Validate(string(data))
	printJSON(val)
	if !val.OK {
		return 1
	}
	return 0
}

func runList() int {
	records, err := sig.Builtin()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fpprobe:", err)
		return 1
	}
	byCat := map[string]int{}
	for _, r := range records {
		byCat[r.Category]++
		fmt.Printf("%-34s %-12s %s\n", r.Slug, r.Category, r.Name)
	}
	fmt.Printf("\n%d signatures:", len(records))
	for _, c := range []string{model.CatCMS, model.CatFramework, model.CatWebServer, model.CatAppServer, model.CatPanel, model.CatDevOps, model.CatDatabase, model.CatIoT, model.CatProxy, model.CatSecurity, model.CatLanguage, model.CatLibrary, model.CatOS, model.CatEnvironment, model.CatHeader, model.CatCookie, model.CatOther} {
		if byCat[c] > 0 {
			fmt.Printf(" %s=%d", c, byCat[c])
		}
	}
	fmt.Println()
	return 0
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "fpprobe:", err)
	os.Exit(1)
}
