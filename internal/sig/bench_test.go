package sig

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

// corpus builds n different, realistic services: about 85 % HTTP pages with a
// body of 4 to 24 KiB, the rest plain TCP services with a banner.
func corpus(n int) []*model.ServiceResult {
	rng := rand.New(rand.NewSource(1))
	words := strings.Fields("uczelnia wydział informatyki studia rekrutacja aktualności kontakt dziekanat nauka badania projekt biblioteka system portal konto hasło student pracownik wiadomość strona katedra laboratorium " +
		"div class span href script style container header footer nav button form input label table row column data value index main content title link image menu item list page user login")
	fragments := []string{
		`<meta name="generator" content="WordPress 6.5.3" /><link href="/wp-content/themes/x/style.css">`,
		`<meta name="generator" content="Drupal 10 (https://www.drupal.org)" />`,
		`<script>M.cfg = {"wwwroot":"http://x","sesskey":"a"};</script><link href="/theme/yui_combo.php">`,
		`<title>phpMyAdmin</title><input name="pma_username">`,
		`<body class="app-grafana"><script>window.grafanaBootData = {}</script>`,
		`<a href="kontroler.php?_action=logowaniecas/index">USOSweb 7.1.2.0</a>`,
		`<form><input type="password" name="pwd"></form>`,
		`<h1>Welcome to nginx!</h1>`, `<h1>Index of /</h1>`, "", "", "", "", "",
	}
	servers := []string{"nginx/1.24.0", "Apache/2.4.57 (Debian)", "Microsoft-IIS/10.0", "cloudflare", "Jetty(11.0.20)", "lighttpd/1.4.69", "", "gunicorn", "openresty/1.25.3.1", "Caddy"}
	powered := []string{"PHP/8.2.7", "ASP.NET", "Express", "", "", "", ""}
	out := make([]*model.ServiceResult, n)
	for i := range out {
		if i%7 == 6 {
			banners := []string{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", "220 mail.example.edu ESMTP Postfix", "220 (vsFTPd 3.0.5)", "SSH-2.0-dropbear_2022.83", ""}
			names := []string{"ssh", "smtp", "ftp", "ssh", "mysql"}
			k := rng.Intn(len(banners))
			out[i] = &model.ServiceResult{Port: 22, Name: names[k], Banner: banners[k], Product: []string{"OpenSSH", "Postfix smtpd", "vsftpd", "Dropbear sshd", "MySQL"}[k], Version: "8.0.36", Confidence: 1}
			continue
		}
		var b strings.Builder
		b.WriteString("<!DOCTYPE html><html><head><title>Strona ")
		b.WriteString(fmt.Sprint(i))
		b.WriteString("</title>")
		b.WriteString(fragments[rng.Intn(len(fragments))])
		b.WriteString("</head><body>")
		size := 4096 + rng.Intn(20480)
		for b.Len() < size {
			b.WriteString("<p class=\"")
			b.WriteString(words[rng.Intn(len(words))])
			b.WriteString("\">")
			for j := 0; j < 12; j++ {
				b.WriteString(words[rng.Intn(len(words))])
				b.WriteByte(' ')
			}
			b.WriteString("</p>\n")
		}
		b.WriteString("</body></html>")
		h := &model.HTTPFingerprint{Scheme: "http", URL: fmt.Sprintf("http://10.0.%d.%d/", i/250%250, i%250), Status: 200, Title: fmt.Sprintf("Strona %d", i),
			BodyExcerpt: b.String(), Headers: map[string][]string{"Content-Type": {"text/html; charset=utf-8"}, "Date": {"Sat, 21 Nov 2026 12:00:00 GMT"}}}
		h.FinalURL = h.URL
		if s := servers[rng.Intn(len(servers))]; s != "" {
			h.Headers["Server"], h.Server = []string{s}, s
		}
		if p := powered[rng.Intn(len(powered))]; p != "" {
			h.Headers["X-Powered-By"] = []string{p}
		}
		if rng.Intn(3) == 0 {
			h.Cookies = []model.Cookie{{Name: []string{"PHPSESSID", "JSESSIONID", "MoodleSession", "csrftoken"}[rng.Intn(4)], ValueLen: 26, Value: "abcdefghijklmnopqrstuvwxyz"}}
		}
		if rng.Intn(4) == 0 {
			h.Paths = []model.PathProbe{{Path: "/robots.txt", Status: 200, BodySHA256: "r", Excerpt: "User-agent: *\nDisallow: /wp-admin/\n"}, {Path: "/wp-login.php", Status: 404}}
		}
		out[i] = &model.ServiceResult{Port: 80, Name: "http", HTTP: h}
	}
	return out
}

// BenchmarkMatch measures Match with the full built-in library. One iteration
// is one service; the corpus has 10 000 different services.
func BenchmarkMatch(b *testing.B) {
	e, err := NewBuiltinEngine()
	if err != nil {
		b.Fatal(err)
	}
	svcs := corpus(10000)
	total, _ := e.Count()
	bytes := 0
	for _, s := range svcs {
		if s.HTTP != nil {
			bytes += len(s.HTTP.BodyExcerpt)
		}
	}
	b.ReportMetric(float64(total), "signatures")
	b.SetBytes(int64(bytes / len(svcs)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Match(svcs[i%len(svcs)])
	}
}

// BenchmarkMatchParallel is BenchmarkMatch from all CPUs at once: Match takes no lock.
func BenchmarkMatchParallel(b *testing.B) {
	e, err := NewBuiltinEngine()
	if err != nil {
		b.Fatal(err)
	}
	svcs := corpus(10000)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			e.Match(svcs[i%len(svcs)])
			i++
		}
	})
}

// BenchmarkMatchNoPrefilter is the same work without the Aho-Corasick
// pre-filter: every body rule searches the body by itself. It shows what the
// pre-filter saves.
func BenchmarkMatchNoPrefilter(b *testing.B) {
	e, err := NewBuiltinEngine()
	if err != nil {
		b.Fatal(err)
	}
	st := e.cur.Load()
	svcs := corpus(10000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := newView(svcs[i%len(svcs)], nil, nil)
		for _, s := range st.enabled {
			v.evalSig(s)
		}
	}
}

// TestMatchTenThousandServices is the throughput check of the brief: 10 000
// services against the whole library must take seconds, not minutes.
func TestMatchTenThousandServices(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	e, err := NewBuiltinEngine()
	if err != nil {
		t.Fatal(err)
	}
	svcs := corpus(10000)
	res := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			e.Match(svcs[i%len(svcs)])
		}
	})
	perService := res.NsPerOp()
	total, _ := e.Count()
	t.Logf("%d signatures: %d ns per service, %.2f s for 10 000 services on one core", total, perService, float64(perService)*10000/1e9)
	// The bound catches a broken prefilter (about 50 times slower), not noise:
	// a CI runner that tests four packages at once measured 5 ms per service,
	// an idle laptop measures about 1 ms. docs/SIGNATURES.md has the numbers.
	if perService > 20_000_000 {
		t.Errorf("Match is too slow: %d ns per service", perService)
	}
}
