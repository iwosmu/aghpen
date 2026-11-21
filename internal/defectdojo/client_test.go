package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/interchange"
	"github.com/iwosmu/aghpen/internal/model"
)

// fakeDojo is an in-memory stand-in for the DefectDojo API v2. It copies the
// behaviour the real 3.5 server showed in the live tests: import-scan creates
// a test, reimport-scan matches by title and description (hash code) and
// creates what it does not know, titles change their letter case.
type fakeDojo struct {
	mu       sync.Mutex
	token    string
	nextID   int64
	types    []map[string]any
	products []map[string]any
	engs     []map[string]any
	tests    []map[string]any
	findings []map[string]any
	calls    map[string]int
	delay    time.Duration
}

func newFake() *fakeDojo {
	return &fakeDojo{token: "good-token", nextID: 100, calls: map[string]int{}}
}

func (f *fakeDojo) id() int64 { f.nextID++; return f.nextID }

func (f *fakeDojo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v2/")
	f.calls[r.Method+" "+path]++
	if r.Header.Get("Authorization") != "Token "+f.token {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"detail":"Invalid token."}`)
		return
	}
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	list := func(items []map[string]any, keep func(map[string]any) bool) {
		var sel []map[string]any
		for _, it := range items {
			if keep == nil || keep(it) {
				sel = append(sel, it)
			}
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if limit <= 0 {
			limit = 25
		}
		end := min(offset+limit, len(sel))
		pageItems := []map[string]any{}
		if offset < len(sel) {
			pageItems = sel[offset:end]
		}
		var next any
		if end < len(sel) {
			next = "http://next"
		}
		reply(200, map[string]any{"count": len(sel), "next": next, "results": pageItems})
	}
	q := r.URL.Query()
	contains := func(field string) func(map[string]any) bool {
		return func(m map[string]any) bool {
			want := q.Get(field)
			// A "contains" filter, like some DefectDojo versions: the client must compare exactly.
			return want == "" || strings.Contains(fmt.Sprint(m[field]), want)
		}
	}
	and := func(fs ...func(map[string]any) bool) func(map[string]any) bool {
		return func(m map[string]any) bool {
			for _, fn := range fs {
				if !fn(m) {
					return false
				}
			}
			return true
		}
	}
	eq := func(field, param string) func(map[string]any) bool {
		return func(m map[string]any) bool { return q.Get(param) == "" || fmt.Sprint(m[field]) == q.Get(param) }
	}
	body := func() map[string]any {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		return m
	}
	create := func(dst *[]map[string]any) {
		m := body()
		m["id"] = f.id()
		*dst = append(*dst, m)
		reply(201, m)
	}

	switch {
	case path == "user_profile/":
		reply(200, map[string]any{"user": map[string]any{"username": "admin"}})
	case path == "oa3/schema/":
		reply(200, map[string]any{"openapi": "3.0.3", "info": map[string]any{"title": "DefectDojo API v2", "version": "9.9.9"}, "paths": map[string]any{}})
	case path == "product_types/" && r.Method == http.MethodGet:
		list(f.types, contains("name"))
	case path == "product_types/":
		create(&f.types)
	case path == "products/" && r.Method == http.MethodGet:
		list(f.products, contains("name"))
	case path == "products/":
		create(&f.products)
	case path == "engagements/" && r.Method == http.MethodGet:
		list(f.engs, and(contains("name"), eq("product", "product")))
	case path == "engagements/":
		create(&f.engs)
	case path == "tests/":
		list(f.tests, and(contains("title"), eq("engagement", "engagement")))
	case path == "findings/":
		list(f.findings, eq("test", "test"))
	case strings.HasPrefix(path, "findings/") && r.Method == http.MethodPatch:
		id, _ := strconv.ParseInt(strings.Trim(strings.TrimPrefix(path, "findings/"), "/"), 10, 64)
		for _, fd := range f.findings {
			if fd["id"] == id {
				for k, v := range body() {
					if k == "title" {
						v = strings.ToUpper(fmt.Sprint(v)) // the server changes the letter case
					}
					fd[k] = v
				}
				reply(200, fd)
				return
			}
		}
		reply(404, map[string]any{"detail": "Not found."})
	case path == "location_findings/":
		reply(200, map[string]any{"count": 1, "next": nil, "results": []map[string]any{{"id": 1, "finding": mustInt(q.Get("finding_equals")), "location_value": "http://10.0.0.1:8080"}}})
	case path == "import-scan/" || path == "reimport-scan/":
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			reply(400, map[string]any{"detail": err.Error()})
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			reply(400, map[string]any{"file": "missing"})
			return
		}
		data, _ := io.ReadAll(file)
		var testID int64
		if path == "import-scan/" {
			testID = f.id()
			f.tests = append(f.tests, map[string]any{"id": testID, "title": r.FormValue("test_title"), "engagement": mustInt(r.FormValue("engagement")), "scan_type": r.FormValue("scan_type")})
		} else {
			testID = mustInt(r.FormValue("test"))
		}
		created, untouched := 0, 0
		if r.FormValue("scan_type") == scanTypeGeneric {
			var gen struct {
				Findings []map[string]any `json:"findings"`
			}
			if err := json.Unmarshal(data, &gen); err != nil {
				reply(400, map[string]any{"detail": "bad generic file"})
				return
			}
			for _, g := range gen.Findings {
				known := false
				for _, fd := range f.findings {
					if fd["test"] == testID && strings.EqualFold(fmt.Sprint(fd["title"]), fmt.Sprint(g["title"])) && fd["description"] == g["description"] {
						known = true
					}
				}
				if known {
					untouched++
					continue
				}
				g["id"] = f.id()
				g["test"] = testID
				g["title"] = strings.ToUpper(fmt.Sprint(g["title"]))
				g["is_mitigated"] = false
				g["endpoints"] = []int64{f.id()}
				f.findings = append(f.findings, g)
				created++
			}
		} else {
			if !strings.Contains(string(data), "<nmaprun") {
				reply(400, map[string]any{"detail": "not nmap"})
				return
			}
			if path == "import-scan/" {
				created = strings.Count(string(data), "<port ")
			} else {
				untouched = strings.Count(string(data), "<port ")
			}
		}
		total := map[string]any{"total": map[string]any{"total": created + untouched}}
		stats := map[string]any{"after": total}
		if path == "reimport-scan/" {
			n := func(v int) map[string]any { return map[string]any{"total": map[string]any{"total": v}} }
			stats["delta"] = map[string]any{"created": n(created), "closed": n(0), "reactivated": n(0), "untouched": n(untouched)}
		}
		reply(201, map[string]any{"test": testID, "test_id": testID, "statistics": stats})
	default:
		reply(404, map[string]any{"detail": "Not found."})
	}
}

func mustInt(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }

func setup(t *testing.T) (*fakeDojo, *Client) {
	t.Helper()
	fake := newFake()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	c, err := New(Config{URL: srv.URL + "/api/v2/", APIKey: fake.token, VerifyTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	return fake, c
}

func sampleFindings(n int) []model.Finding {
	at := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	out := make([]model.Finding, n)
	for i := range out {
		ip := fmt.Sprintf("10.66.%d.%d", i/250, i%250+1)
		out[i] = model.Finding{
			Key: fmt.Sprintf("admin-panel/%s/tcp-8080/jenkins", ip), Type: "admin-panel",
			Title: fmt.Sprintf("Panel administracyjny: Jenkins (%s:8080)", ip), Description: "Pod tym adresem odpowiada panel administracyjny.",
			Severity: model.SevInfo, Status: model.FindingNew, Interest: 50, IP: ip, Port: 8080, URL: "http://" + ip + ":8080/", Signature: "jenkins",
			Evidence: []model.Evidence{{Matcher: "header", Where: "header:X-Jenkins", Snippet: "2.440"}}, Tags: []string{"admin-panel", "Do Weryfikacji"},
			FirstSeen: at, LastSeen: at,
		}
	}
	return out
}

func TestNewValidatesConfig(t *testing.T) {
	cases := []struct {
		cfg     Config
		base    string
		wantErr string
	}{
		{Config{URL: "http://127.0.0.1:18080/api/v2/", APIKey: "k"}, "http://127.0.0.1:18080", ""},
		{Config{URL: "dojo.example/", APIKey: "k"}, "https://dojo.example", ""},
		{Config{URL: "https://dojo.example/prefix/", APIKey: "k"}, "https://dojo.example/prefix", ""},
		{Config{URL: "", APIKey: "k"}, "", "brak adresu URL"},
		{Config{URL: "ftp://x", APIKey: "k"}, "", "niepoprawny adres URL"},
		{Config{URL: "http://x", APIKey: " "}, "", "brak tokenu"},
	}
	for _, c := range cases {
		cl, err := New(c.cfg)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("New(%q): err = %v, want %q", c.cfg.URL, err, c.wantErr)
			}
			continue
		}
		if err != nil || cl.BaseURL() != c.base {
			t.Errorf("New(%q): base = %v, err = %v, want %q", c.cfg.URL, cl, err, c.base)
		}
	}
}

func TestConnectionTest(t *testing.T) {
	fake, c := setup(t)
	info, err := c.Test(context.Background())
	if err != nil || !info.OK || info.Version != "9.9.9" || info.User != "admin" || !strings.Contains(info.Message, "9.9.9") {
		t.Fatalf("info = %+v, err = %v", info, err)
	}
	fake.token = "rotated"
	info, err = c.Test(context.Background())
	if err == nil || info.OK || !strings.Contains(err.Error(), "odrzucił token API") || !strings.Contains(info.Message, "401") {
		t.Fatalf("bad token: info = %+v, err = %v", info, err)
	}
}

func TestExportFindingsCreatesThenUpdatesWithoutDuplicates(t *testing.T) {
	fake, c := setup(t)
	ctx := context.Background()
	findings := sampleFindings(3)

	first, err := c.ExportFindings(ctx, Target{}, findings)
	if err != nil {
		t.Fatal(err)
	}
	if r := first.Result; r.Exported != 3 || r.Updated != 0 || r.Failed != 0 || r.TestID == 0 || !strings.HasSuffix(r.TestURL, fmt.Sprintf("/test/%d", r.TestID)) {
		t.Fatalf("first export = %+v", first.Result)
	}
	if len(fake.findings) != 3 || len(fake.types) != 1 || len(fake.products) != 1 || len(fake.engs) != 1 || len(fake.tests) != 1 {
		t.Fatalf("server state: %d findings, %d types, %d products, %d engagements, %d tests", len(fake.findings), len(fake.types), len(fake.products), len(fake.engs), len(fake.tests))
	}
	if fake.types[0]["name"] != DefaultProductType || fake.products[0]["name"] != DefaultProduct || fake.engs[0]["name"] != DefaultEngagement || fake.tests[0]["title"] != FindingsTestTitle {
		t.Errorf("default names are not used")
	}
	sent := fake.findings[0]
	if sent["unique_id_from_tool"] != findings[0].Key || sent["severity"] != "Info" || sent["vuln_id_from_tool"] != "admin-panel" {
		t.Errorf("sent finding = %v", sent)
	}
	eps := sent["endpoints"]
	_ = eps
	ref := first.Findings[findings[0].Key]
	if ref.ID == 0 || !ref.Created || !strings.Contains(ref.URL, "/finding/") {
		t.Errorf("ref = %+v", ref)
	}

	// Second export of the same findings: nothing new, everything updated, no PATCH needed.
	second, err := c.ExportFindings(ctx, Target{}, findings)
	if err != nil {
		t.Fatal(err)
	}
	if r := second.Result; r.Exported != 0 || r.Updated != 3 || r.Failed != 0 || r.TestID != first.Result.TestID {
		t.Fatalf("second export = %+v", second.Result)
	}
	if len(fake.findings) != 3 || len(fake.tests) != 1 || second.Patched != 0 {
		t.Fatalf("duplicates after the second export: %d findings, %d tests, patched %d", len(fake.findings), len(fake.tests), second.Patched)
	}
	if second.Findings[findings[0].Key].ID != ref.ID {
		t.Errorf("the reference changed between exports")
	}

	// A changed description must update in place. Reimport alone would create a duplicate here.
	findings[1].Description += " Nowa wersja 2.441."
	findings[1].Severity = model.SevLow
	extra := sampleFindings(4)[3]
	third, err := c.ExportFindings(ctx, Target{}, append(findings, extra, extra)) // the repeated key is sent once
	if err != nil {
		t.Fatal(err)
	}
	if r := third.Result; r.Exported != 1 || r.Updated != 3 || r.Failed != 0 || third.Patched != 1 {
		t.Fatalf("third export = %+v patched=%d", third.Result, third.Patched)
	}
	if len(fake.findings) != 4 {
		t.Fatalf("want 4 findings on the server, got %d", len(fake.findings))
	}
	if d := fmt.Sprint(fake.findings[1]["description"]); !strings.Contains(d, "Nowa wersja 2.441.") || fake.findings[1]["severity"] != "Low" || fake.findings[1]["numerical_severity"] != "S3" {
		t.Errorf("finding was not updated in place: %v", fake.findings[1])
	}
}

func TestExportFindingsHandlesPagesAndBatches(t *testing.T) {
	fake, c := setup(t)
	findings := sampleFindings(620) // more than one import batch and more than three list pages
	first, err := c.ExportFindings(context.Background(), Target{}, findings)
	if err != nil || first.Result.Exported != 620 || first.Result.Failed != 0 {
		t.Fatalf("first = %+v err = %v", first.Result, err)
	}
	if fake.calls["POST import-scan/"] != 1 || fake.calls["POST reimport-scan/"] != 1 {
		t.Errorf("batches: %v", fake.calls)
	}
	second, err := c.ExportFindings(context.Background(), Target{}, findings)
	if err != nil || second.Result.Exported != 0 || second.Result.Updated != 620 || len(fake.findings) != 620 {
		t.Fatalf("second = %+v err = %v, %d findings on the server", second.Result, err, len(fake.findings))
	}
}

func TestExportFindingsStatusAndMissingKey(t *testing.T) {
	fake, c := setup(t)
	fs := sampleFindings(3)
	fs[0].Status = model.FindingResolved
	fs[1].Status = model.FindingFalsePositive
	fs[2].Key = ""
	out, err := c.ExportFindings(context.Background(), Target{ProductName: "Kampus", EngagementName: "Q4", ProductTypeName: "AGH"}, fs)
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Exported != 2 || out.Result.Failed != 1 || len(out.Result.Errors) != 1 || !strings.Contains(out.Result.Errors[0], "nie ma klucza") {
		t.Fatalf("result = %+v", out.Result)
	}
	if fake.products[0]["name"] != "Kampus" || fake.engs[0]["name"] != "Q4" || fake.types[0]["name"] != "AGH" {
		t.Errorf("target names are not used")
	}
	byKey := map[string]map[string]any{}
	for _, f := range fake.findings {
		byKey[fmt.Sprint(f["unique_id_from_tool"])] = f
	}
	if r := byKey[fs[0].Key]; r["active"] != false || r["is_mitigated"] != true {
		t.Errorf("resolved finding = active %v mitigated %v", r["active"], r["is_mitigated"])
	}
	if r := byKey[fs[1].Key]; r["active"] != false || r["false_p"] != true {
		t.Errorf("false positive = active %v false_p %v", r["active"], r["false_p"])
	}
}

func TestImportNmapXMLReimportsIntoTheSameTest(t *testing.T) {
	fake, c := setup(t)
	xml := `<?xml version="1.0"?><nmaprun><host><ports><port portid="80"/><port portid="443"/></ports></host></nmaprun>`
	first, err := c.ImportNmapXML(context.Background(), Target{}, "Czujka nmap run 7", strings.NewReader(xml), time.Now())
	if err != nil || first.Reimport || first.Created != 2 || first.TestID == 0 {
		t.Fatalf("first = %+v err = %v", first, err)
	}
	second, err := c.ImportNmapXML(context.Background(), Target{}, "Czujka nmap run 7", strings.NewReader(xml), time.Now())
	if err != nil || !second.Reimport || second.Created != 0 || second.Untouched != 2 || second.TestID != first.TestID {
		t.Fatalf("second = %+v err = %v", second, err)
	}
	other, err := c.ImportNmapXML(context.Background(), Target{}, "Czujka nmap run 8", strings.NewReader(xml), time.Now())
	if err != nil || other.Reimport || other.TestID == first.TestID || len(fake.tests) != 2 {
		t.Fatalf("other run = %+v err = %v", other, err)
	}
	if _, err := c.ImportNmapXML(context.Background(), Target{}, "x", strings.NewReader("not xml"), time.Now()); err == nil || !strings.Contains(err.Error(), "import nmap XML") {
		t.Errorf("bad file: err = %v", err)
	}
}

func TestListFindingsResolvesEndpoints(t *testing.T) {
	_, c := setup(t)
	out, err := c.ExportFindings(context.Background(), Target{}, sampleFindings(2))
	if err != nil {
		t.Fatal(err)
	}
	views, err := c.ListFindings(context.Background(), out.Result.TestID)
	if err != nil || len(views) != 2 {
		t.Fatalf("views = %+v err = %v", views, err)
	}
	if len(views[0].Endpoints) != 1 || views[0].Endpoints[0] != "http://10.0.0.1:8080" || views[0].Key == "" {
		t.Errorf("view = %+v", views[0])
	}
}

func TestTLSVerificationSwitch(t *testing.T) {
	fake := newFake()
	srv := httptest.NewTLSServer(fake) // self-signed certificate
	defer srv.Close()
	strict, _ := New(Config{URL: srv.URL, APIKey: fake.token, VerifyTLS: true})
	if _, err := strict.Test(context.Background()); err == nil || !strings.Contains(err.Error(), "certyfikatu TLS") {
		t.Errorf("verify on: err = %v", err)
	}
	lax, _ := New(Config{URL: srv.URL, APIKey: fake.token, VerifyTLS: false})
	if info, err := lax.Test(context.Background()); err != nil || !info.OK {
		t.Errorf("verify off: info = %+v err = %v", info, err)
	}
}

func TestTimeoutAndConnectionErrors(t *testing.T) {
	fake := newFake()
	fake.delay = 300 * time.Millisecond
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c, _ := New(Config{URL: srv.URL, APIKey: fake.token, Timeout: 50 * time.Millisecond})
	if _, err := c.Test(context.Background()); err == nil || !strings.Contains(err.Error(), "nie odpowiedział w wyznaczonym czasie") {
		t.Errorf("timeout: err = %v", err)
	}
	dead, _ := New(Config{URL: "http://127.0.0.1:1", APIKey: "k", Timeout: time.Second})
	if _, err := dead.Test(context.Background()); err == nil || !strings.Contains(err.Error(), "brak połączenia z DefectDojo") {
		t.Errorf("refused: err = %v", err)
	}
	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html>login</html>")
	}))
	defer html.Close()
	wrong, _ := New(Config{URL: html.URL, APIKey: "k"})
	if _, err := wrong.Test(context.Background()); err == nil || !strings.Contains(err.Error(), "zamiast JSON") {
		t.Errorf("html answer: err = %v", err)
	}
}

func TestDescriptionTagsSeverity(t *testing.T) {
	f := sampleFindings(1)[0]
	f.Note = "Zgłoszone do właściciela."
	f.Status = model.FindingAccepted
	d := Description(f)
	for _, want := range []string{"Pod tym adresem odpowiada panel administracyjny.", "**Host:** 10.66.0.1 · **Port:** 8080", "**Typ obserwacji:** admin-panel",
		"**Sygnatura:** jenkins", "- header:X-Jenkins (header): `2.440`", "**Notatka analityka:** Zgłoszone do właściciela.", "Klucz: admin-panel/10.66.0.1/tcp-8080/jenkins"} {
		if !strings.Contains(d, want) {
			t.Errorf("description lacks %q:\n%s", want, d)
		}
	}
	tags := Tags(f)
	sort.Strings(tags)
	if strings.Join(tags, ",") != "accepted,admin-panel,czujka,do-weryfikacji" {
		t.Errorf("tags = %v", tags)
	}
	for sev, want := range map[model.Severity]string{model.SevInfo: "Info/S4", model.SevLow: "Low/S3", model.SevMedium: "Medium/S2", model.SevHigh: "High/S1", "": "Info/S4"} {
		if n, num := Severity(sev); n+"/"+num != want {
			t.Errorf("Severity(%q) = %s/%s, want %s", sev, n, num, want)
		}
	}
	g := toGeneric(f)
	if len(g.Endpoints) != 1 || g.Endpoints[0].Host != "10.66.0.1" || g.Endpoints[0].Port != 8080 || g.Endpoints[0].Protocol != "http" || g.Date != "2026-11-21" || !g.Active {
		t.Errorf("generic = %+v", g)
	}
	f.URL = ""
	if e := interchange.DojoEndpoints(f); e[0].Protocol != "tcp" {
		t.Errorf("endpoint without a URL = %+v", e)
	}
	if s := TargetFromSettings(model.DefectDojoSettings{ProductName: " Kampus "}); s.ProductName != "Kampus" || s.EngagementName != DefaultEngagement {
		t.Errorf("target = %+v", s)
	}
	if cfg := FromSettings(model.DefectDojoSettings{URL: "u", APIKey: "k", VerifyTLS: true}); cfg.URL != "u" || cfg.APIKey != "k" || !cfg.VerifyTLS {
		t.Errorf("config = %+v", cfg)
	}
}
