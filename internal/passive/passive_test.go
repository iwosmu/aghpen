package passive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func parseFile(t *testing.T, name string) ([]Fact, FileReport) {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	facts, rep, err := Parse(f, name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return facts, rep
}

// brief renders facts as short sorted lines for comparison.
func brief(facts []Fact) []string {
	out := make([]string, 0, len(facts))
	for _, f := range facts {
		s := f.Kind + " " + f.Hostname
		if f.IP != "" {
			s += " -> " + f.IP
		}
		if f.Port > 0 {
			s += fmt.Sprintf(":%d", f.Port)
		}
		if f.Target != "" {
			s += " => " + f.Target
		}
		if f.Wildcard {
			s += " (wildcard)"
		}
		out = append(out, strings.Join(strings.Fields(s), " "))
	}
	sort.Strings(out)
	return out
}

func wantLines(t *testing.T, got []string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("facts:\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
}

func TestParseZoneExportCSV(t *testing.T) {
	facts, rep := parseFile(t, "strefa.csv")
	wantLines(t, brief(facts),
		"dns www.kampus.example -> 10.66.1.10",
		"dns dziekanat.kampus.example -> 10.66.1.20",
		"cname poczta.kampus.example => mx1.kampus.example",
		"dns mx1.kampus.example -> 10.66.1.30",
		"dns chmura.kampus.example -> 203.0.113.50",
		"ptr www.kampus.example -> 10.66.1.10",
	)
	if rep.Format != FormatCSV || rep.Records != 8 || rep.Skipped != 1 || rep.InvalidTotal != 1 {
		t.Errorf("report = %+v", rep)
	}
	if len(rep.Invalid) != 1 || rep.Invalid[0].Line != 9 || rep.Invalid[0].Reason != "niepoprawna nazwa hosta" {
		t.Errorf("invalid = %+v", rep.Invalid)
	}
	if facts[0].Source != "file:strefa.csv" {
		t.Errorf("source = %q", facts[0].Source)
	}
}

func TestParsePassiveDNSJSONLines(t *testing.T) {
	facts, rep := parseFile(t, "pdns.jsonl")
	wantLines(t, brief(facts),
		"dns ci.kampus.example -> 10.66.3.17",
		"dns lab-nowy.kampus.example -> 10.66.3.200",
		"dns lab-nowy.kampus.example -> 10.66.3.201",
		"cname cdn.kampus.example => kampus.cdn.example.net",
		"dns obcy.example.org -> 198.51.100.7",
	)
	if rep.Format != FormatJSONL || rep.Records != 5 || rep.Skipped != 1 || rep.InvalidTotal != 1 {
		t.Errorf("report = %+v", rep)
	}
	for _, f := range facts {
		if f.Hostname == "ci.kampus.example" {
			first := time.Unix(1761465600, 0).UTC()
			if !f.FirstSeen.Equal(first) || !f.LastSeen.Equal(time.Unix(1763686800, 0).UTC()) || f.Count != 412 || f.Sensor != "dns-1" {
				t.Errorf("ci fact = %+v", f)
			}
		}
	}
}

func TestParseCertificateList(t *testing.T) {
	facts, rep := parseFile(t, "certyfikaty.json")
	wantLines(t, brief(facts),
		"certificate www.kampus.example",
		"certificate kampus.example",
		"certificate lab.kampus.example (wildcard)",
		"certificate stary-portal.kampus.example",
		"certificate portal.inna-uczelnia.example",
	)
	if rep.Format != FormatJSON || rep.Records != 3 || rep.InvalidTotal != 0 {
		t.Errorf("report = %+v", rep)
	}
	for _, f := range facts {
		if f.Hostname != "www.kampus.example" {
			continue
		}
		c := f.Cert
		if c == nil || c.SubjectCN != "www.kampus.example" || c.Issuer != "C=US, O=Let's Encrypt, CN=R11" ||
			c.Serial != "04a1b2c3d4e5f60718293a4b5c6d7e8f9012" || c.NotAfter.Format(time.RFC3339) != "2027-02-18T08:14:02Z" {
			t.Errorf("cert = %+v", c)
		}
		if f.LastSeen.Format("2006-01-02") != "2026-11-20" {
			t.Errorf("entry_timestamp was not read: %v", f.LastSeen)
		}
	}
}

func TestParseTolerantJSON(t *testing.T) {
	facts, rep := parseFile(t, "inwentarz.json")
	wantLines(t, brief(facts),
		"observation -> 10.66.3.40:80",
		"observation -> 10.66.3.40:631",
		"dns drukarka-3p.kampus.example -> 10.66.3.40",
		"dns bez-adresu.kampus.example",
	)
	var reasons []string
	for _, i := range rep.Invalid {
		reasons = append(reasons, fmt.Sprintf("%d %s: %s", i.Line, i.Value, i.Reason))
	}
	want := []string{"5 999.1.1.1: niepoprawny adres IP", "6 : brak adresu IP i nazwy hosta", "7 70000: niepoprawny numer portu"}
	if !reflect.DeepEqual(reasons, want) {
		t.Errorf("invalid rows:\n got  %q\n want %q", reasons, want)
	}
	if rep.Records != 7 {
		t.Errorf("records = %d", rep.Records)
	}
}

func TestParseZoneFile(t *testing.T) {
	facts, rep := parseFile(t, "strefa.txt")
	wantLines(t, brief(facts),
		"dns ns1.kampus.example -> 10.66.0.53",
		"dns www.kampus.example -> 10.66.1.10",
		"dns www.kampus.example -> 2001:db8:66::10",
		"cname git.kampus.example => gitlab.kampus.example",
		"dns gitlab.kampus.example -> 10.66.2.5",
		"ptr drukarka-3p.kampus.example -> 10.66.3.40",
	)
	if rep.Format != FormatZone || rep.Skipped != 3 || rep.InvalidTotal != 0 {
		t.Errorf("report = %+v", rep) // SOA, NS and TXT are skipped
	}
}

func TestParseOtherShapes(t *testing.T) {
	cases := []struct {
		name, in string
		want     []string
	}{
		{"csv without a header", "10.66.1.10,www.kampus.example\n10.66.1.20,dziekanat.kampus.example\n",
			[]string{"dns www.kampus.example -> 10.66.1.10", "dns dziekanat.kampus.example -> 10.66.1.20"}},
		{"tab separated with a BOM and English headers", "\xef\xbb\xbfHostname\tIP Address\tFirst Seen\nA.Kampus.Example\t10.66.1.5\t2026-11-01\n",
			[]string{"dns a.kampus.example -> 10.66.1.5"}},
		{"bare array with several addresses", `[{"name":"x.kampus.example","addresses":"n/a","ip":["10.66.1.7","10.66.1.8"]}]`,
			[]string{"dns x.kampus.example -> 10.66.1.7", "dns x.kampus.example -> 10.66.1.8"}},
		{"nested certificate object", `{"hostname":"y.kampus.example","certificate":{"issuer":"CN=CA","not_after":"2027-01-01","sha256":"AB12"}}`,
			[]string{"certificate y.kampus.example"}},
		{"certificate with a subject and an address", "ip,subject,sans,not_after\n10.66.1.9,\"C=PL, CN=z.kampus.example\",z.kampus.example www.z.kampus.example,2027-03-01\n",
			[]string{"certificate z.kampus.example -> 10.66.1.9", "certificate www.z.kampus.example -> 10.66.1.9"}},
	}
	for _, c := range cases {
		facts, _, err := Parse(strings.NewReader(c.in), "x")
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		got := brief(facts)
		sort.Strings(c.want)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got  %q\n want %q", c.name, got, c.want)
		}
	}
	for name, in := range map[string]string{"empty": "  \n", "broken json": "{\"ip\": ", "free text": "to nie są dane\nani trochę\n"} {
		if _, _, err := Parse(strings.NewReader(in), "x"); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestFieldMappingHasNoClash(t *testing.T) {
	seen := map[string]Field{}
	for _, row := range FieldMapping {
		for _, n := range row.Names {
			if f, dup := seen[normName(n)]; dup {
				t.Errorf("name %q maps to %s and %s", n, f, row.Field)
			}
			seen[normName(n)] = row.Field
		}
	}
	for name, want := range map[string]Field{"IP Address": FIP, "Źródło": FSource, "time_last": FLastSeen, "name_value": FCertSANs, "RRNAME": FHostname, "Ważny do": FNotAfter} {
		if f, ok := LookupField(name); !ok || f != want {
			t.Errorf("LookupField(%q) = %v, %v; want %v", name, f, ok, want)
		}
	}
}

func TestHelpers(t *testing.T) {
	times := map[string]string{
		"2026-11-20T09:12:44.561": "2026-11-20T09:12:44Z", "2026-11-20T10:00:00+01:00": "2026-11-20T09:00:00Z",
		"2026-11-20 13:55:10": "2026-11-20T13:55:10Z", "2026-11-20": "2026-11-20T00:00:00Z", "20.11.2026 08:30": "2026-11-20T08:30:00Z",
		"1763686800": "2025-11-21T01:00:00Z", "1763686800000": "2025-11-21T01:00:00Z",
	}
	for in, want := range times {
		got, ok := parseTime(in)
		if !ok || got.Format(time.RFC3339) != want {
			t.Errorf("parseTime(%q) = %v, %v; want %s", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "wczoraj", "42"} {
		if _, ok := parseTime(bad); ok {
			t.Errorf("parseTime(%q) should fail", bad)
		}
	}
	hosts := map[string]string{"WWW.Kampus.Example.": "www.kampus.example", "*.lab.kampus.example": "lab.kampus.example", "_dmarc.kampus.example": "_dmarc.kampus.example", "localhost": "localhost"}
	for in, want := range hosts {
		if got, wc, ok := cleanHost(in); !ok || got != want || wc != strings.HasPrefix(in, "*.") {
			t.Errorf("cleanHost(%q) = %q, %v, %v", in, got, wc, ok)
		}
	}
	for _, bad := range []string{"", "10.0.0.1", "999.1.1.1", "a b.example", "-x.example", "x..example", "ex<ample>.com", strings.Repeat("a", 64) + ".example"} {
		if _, _, ok := cleanHost(bad); ok {
			t.Errorf("cleanHost(%q) should fail", bad)
		}
	}
	if a, ok := arpaToAddr("40.3.66.10.in-addr.arpa."); !ok || a.String() != "10.66.3.40" {
		t.Errorf("arpaToAddr v4 = %v, %v", a, ok)
	}
	v6 := "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.6.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	if a, ok := arpaToAddr(v6); !ok || a.String() != "2001:db8:66::10" {
		t.Errorf("arpaToAddr v6 = %v, %v", a, ok)
	}
}

func TestScope(t *testing.T) {
	s := ScopeFromTargets([]model.Target{
		{Kind: model.TargetCIDR, Value: "10.66.0.0/22", Enabled: true},
		{Kind: model.TargetIP, Value: "192.0.2.7", Enabled: true},
		{Kind: model.TargetRange, Value: "10.70.0.5-10.70.0.90", Enabled: true},
		{Kind: model.TargetRange, Value: "10.71.0.5-9", Enabled: true},
		{Kind: model.TargetDomain, Value: "Kampus.Example.", Enabled: true},
		{Kind: model.TargetCIDR, Value: "172.16.0.0/12", Enabled: false},
		{Kind: model.TargetCIDR, Value: "nonsense", Enabled: true},
	}, []string{"10.66.1.10", "bad", "10.66.1.20"})
	in := []string{"10.66.0.1", "10.66.3.255", "192.0.2.7", "10.70.0.5", "10.70.0.90", "10.71.0.9", "::ffff:10.66.1.1"}
	out := []string{"10.66.4.0", "192.0.2.8", "10.70.0.4", "10.70.0.91", "10.71.0.10", "172.16.0.1", "2001:db8::1"}
	for _, a := range in {
		if !s.ContainsIP(netip.MustParseAddr(a)) {
			t.Errorf("%s should be in scope", a)
		}
	}
	for _, a := range out {
		if s.ContainsIP(netip.MustParseAddr(a)) {
			t.Errorf("%s should be out of scope", a)
		}
	}
	for name, want := range map[string]bool{"kampus.example": true, "a.b.kampus.example.": true, "WWW.KAMPUS.EXAMPLE": true, "zlykampus.example": false, "kampus.example.org": false} {
		if s.ContainsHost(name) != want {
			t.Errorf("ContainsHost(%q) != %v", name, want)
		}
	}
	if len(s.KnownIPs) != 2 {
		t.Errorf("known = %v", s.KnownIPs)
	}
}

func testScope() Scope {
	return ScopeFromTargets([]model.Target{
		{Kind: model.TargetCIDR, Value: "10.66.0.0/16", Enabled: true},
		{Kind: model.TargetDomain, Value: "kampus.example", Enabled: true},
	}, []string{"10.66.1.10", "10.66.1.20", "10.66.3.17"})
}

// All fixtures together: what becomes a candidate, what becomes a hint and
// what is left out.
func TestCollectCandidatesAndHints(t *testing.T) {
	var sources []Source
	var files []*FileSource
	for _, n := range []string{"strefa.csv", "pdns.jsonl", "certyfikaty.json", "inwentarz.json", "strefa.txt"} {
		f := NewFileSource("testdata/" + n)
		files = append(files, f)
		sources = append(sources, f)
	}
	res := Collect(context.Background(), testScope(), Options{}, sources...)

	var ipCands, domCands []string
	for _, c := range res.Candidates {
		if c.Reason == "" || len(c.Sources) == 0 {
			t.Errorf("candidate %s has no reason or source", c.Value)
		}
		if c.Kind == model.TargetIP {
			ipCands = append(ipCands, c.Value)
		} else {
			domCands = append(domCands, c.Value)
		}
	}
	wantIPs := []string{"10.66.0.53", "10.66.1.30", "10.66.2.5", "10.66.3.40", "10.66.3.200", "10.66.3.201"}
	if !reflect.DeepEqual(ipCands, wantIPs) {
		t.Errorf("address candidates:\n got  %v\n want %v", ipCands, wantIPs)
	}
	wantDoms := []string{"bez-adresu.kampus.example", "cdn.kampus.example", "git.kampus.example", "kampus.example", "lab.kampus.example", "poczta.kampus.example", "stary-portal.kampus.example"}
	if !reflect.DeepEqual(domCands, wantDoms) {
		t.Errorf("name candidates:\n got  %v\n want %v", domCands, wantDoms)
	}

	// A name of the organisation that points to a foreign address must not
	// make that address, or the name, a target.
	var outside []string
	for _, f := range res.OutOfScope {
		outside = append(outside, strings.TrimSpace(f.Hostname+" "+f.IP))
	}
	sort.Strings(outside)
	wantOut := []string{"chmura.kampus.example 203.0.113.50", "obcy.example.org 198.51.100.7", "portal.inna-uczelnia.example", "www.kampus.example 2001:db8:66::10"}
	if !reflect.DeepEqual(outside, wantOut) {
		t.Errorf("out of scope:\n got  %q\n want %q", outside, wantOut)
	}
	for _, c := range res.Candidates {
		if strings.Contains(c.Value, "203.0.113.") || c.Value == "chmura.kampus.example" || strings.Contains(c.Value, "inna-uczelnia") {
			t.Errorf("out-of-scope data became a candidate: %+v", c)
		}
	}

	hints := map[string]Hint{}
	for _, h := range res.Hints {
		hints[h.IP] = h
	}
	if h := hints["10.66.1.10"]; !h.Known || !reflect.DeepEqual(h.Hostnames, []string{"www.kampus.example"}) || len(h.Sources) != 2 {
		t.Errorf("hint of a known host = %+v", h)
	}
	if h := hints["10.66.3.40"]; h.Known || !reflect.DeepEqual(h.Hostnames, []string{"drukarka-3p.kampus.example"}) || !reflect.DeepEqual(h.Ports, []int{80, 631}) {
		t.Errorf("hint of a new host = %+v", h)
	}
	if len(res.Sources) != 5 || res.Sources[0].Facts != 6 || res.Sources[0].Error != "" {
		t.Errorf("source reports = %+v", res.Sources)
	}
	if files[3].Report.InvalidTotal != 3 {
		t.Errorf("file report was not kept: %+v", files[3].Report)
	}
	t.Logf("5 files -> %d facts in scope, %d out of scope, %d address candidates, %d name candidates, %d hints",
		len(res.Facts), len(res.OutOfScope), len(ipCands), len(domCands), len(res.Hints))
}

func TestMergeJoinsDuplicates(t *testing.T) {
	t1, t2 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	res := Merge(testScope(), []Fact{
		{Kind: KindDNS, Hostname: "a.kampus.example", IP: "10.66.5.5", Source: "file:x", FirstSeen: t2, LastSeen: t2, Count: 2},
		{Kind: KindDNS, Hostname: "a.kampus.example", IP: "10.66.5.5", Source: "file:x", FirstSeen: t1, LastSeen: t1, Count: 3},
	})
	if len(res.Facts) != 1 || !res.Facts[0].FirstSeen.Equal(t1) || !res.Facts[0].LastSeen.Equal(t2) || res.Facts[0].Count != 5 {
		t.Errorf("merged = %+v", res.Facts)
	}
	if len(res.Candidates) != 1 || !res.Candidates[0].LastSeen.Equal(t2) {
		t.Errorf("candidates = %+v", res.Candidates)
	}
}

// ---------- reverse DNS ----------

// The one real lookup of the test suite: the PTR record of 127.0.0.1 through
// the system resolver.
func TestPTRLookupOfLocalhost(t *testing.T) {
	src := &PTRSource{}
	scope := Scope{Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, KnownIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	facts, err := src.Collect(ctx, scope)
	if err != nil {
		t.Fatalf("PTR lookup of 127.0.0.1: %v", err)
	}
	if len(facts) == 0 {
		t.Fatal("the system resolver has no name for 127.0.0.1")
	}
	found := false
	for _, f := range facts {
		t.Logf("real PTR lookup: %s -> %s (kind=%s, source=%s)", f.IP, f.Hostname, f.Kind, f.Source)
		if f.Kind != KindPTR || f.IP != "127.0.0.1" || f.Source != "ptr" || f.LastSeen.IsZero() {
			t.Errorf("fact = %+v", f)
		}
		found = found || strings.Contains(f.Hostname, "localhost")
	}
	if !found {
		t.Errorf("no localhost name among %v", brief(facts))
	}
	if src.Asked != 1 || src.Answered != 1 {
		t.Errorf("asked %d, answered %d", src.Asked, src.Answered)
	}
}

type fakeResolver struct {
	mu    sync.Mutex
	calls []string
	at    []time.Time
	names map[string][]string
	errs  map[string]error
}

func (r *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, addr)
	r.at = append(r.at, time.Now())
	if err := r.errs[addr]; err != nil {
		return nil, err
	}
	return r.names[addr], nil
}

func TestPTRAsksOnlyKnownAddressesInScopeAndKeepsTheRate(t *testing.T) {
	res := &fakeResolver{
		names: map[string][]string{"10.66.1.10": {"www.kampus.example."}, "10.66.1.20": {"Dziekanat.Kampus.Example.", "alias.kampus.example."}, "10.66.1.40": {"bad name."}},
		errs:  map[string]error{"10.66.1.30": &net.DNSError{Err: "no such host", Name: "10.66.1.30", IsNotFound: true}},
	}
	scope := testScope()
	scope.KnownIPs = nil
	for _, a := range []string{"10.66.1.30", "10.66.1.10", "8.8.8.8", "10.66.1.20", "10.66.1.10", "10.66.1.40", "10.66.1.50"} {
		scope.KnownIPs = append(scope.KnownIPs, netip.MustParseAddr(a))
	}
	src := &PTRSource{Resolver: res, Rate: 50, Now: func() time.Time { return time.Date(2026, 11, 21, 3, 0, 0, 0, time.UTC) }}
	start := time.Now()
	facts, err := src.Collect(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{"10.66.1.10", "10.66.1.20", "10.66.1.30", "10.66.1.40", "10.66.1.50"}
	if !reflect.DeepEqual(res.calls, wantCalls) {
		t.Errorf("lookups = %v, want %v (8.8.8.8 is outside the scope)", res.calls, wantCalls)
	}
	wantLines(t, brief(facts), "ptr www.kampus.example -> 10.66.1.10", "ptr dziekanat.kampus.example -> 10.66.1.20", "ptr alias.kampus.example -> 10.66.1.20")
	if src.Asked != 5 || src.Answered != 2 || src.Failed != 0 {
		t.Errorf("asked %d, answered %d, failed %d", src.Asked, src.Answered, src.Failed)
	}
	// 5 lookups at 50/s: at least 4 gaps of 20 ms.
	if el := time.Since(start); el < 75*time.Millisecond {
		t.Errorf("5 lookups took %v; the rate limit of 50/s was not kept", el)
	}
	for i := 1; i < len(res.at); i++ {
		if gap := res.at[i].Sub(res.at[i-1]); gap < 15*time.Millisecond {
			t.Errorf("gap %d = %v, want about 20 ms", i, gap)
		}
	}
}

func TestPTRErrorsAndCancel(t *testing.T) {
	res := &fakeResolver{names: map[string][]string{"10.66.1.10": {"www.kampus.example."}}, errs: map[string]error{"10.66.1.20": errors.New("server misbehaving")}}
	scope := testScope()
	src := &PTRSource{Resolver: res, Rate: 1000}
	facts, err := src.Collect(context.Background(), scope)
	if err == nil || !strings.Contains(err.Error(), "1 z 3 zapytań") || len(facts) != 1 {
		t.Errorf("facts = %d, err = %v", len(facts), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&PTRSource{Resolver: &fakeResolver{}, Rate: 1}).Collect(ctx, scope); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context: err = %v", err)
	}
	src = &PTRSource{Resolver: &fakeResolver{}, Rate: 1000, Max: 2}
	if _, err := src.Collect(context.Background(), scope); err == nil || src.Asked != 2 {
		t.Errorf("Max: asked %d, err %v", src.Asked, err)
	}
}

// ---------- Certificate Transparency ----------

// localOnly fails every request that does not go to 127.0.0.1, so a test
// can never reach crt.sh.
type localOnly struct{ calls int }

func (l *localOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	l.calls++
	if h := r.URL.Hostname(); h != "127.0.0.1" {
		return nil, fmt.Errorf("test tried to reach %s", h)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func ctServer(t *testing.T, status int) (*httptest.Server, *[]*http.Request) {
	t.Helper()
	body, err := os.ReadFile("testdata/certyfikaty.json")
	if err != nil {
		t.Fatal(err)
	}
	var reqs []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs = append(reqs, r)
		if status != http.StatusOK {
			http.Error(w, "bad gateway", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs
}

func TestCertificateTransparencyIsOffByDefault(t *testing.T) {
	srv, reqs := ctServer(t, http.StatusOK)
	tr := &localOnly{}
	client := &http.Client{Transport: tr}

	// 1. The zero value is off, even when external sources are allowed.
	off := &CTSource{BaseURL: srv.URL, Client: client}
	res := Collect(context.Background(), testScope(), Options{AllowExternal: true}, off)
	if res.Sources[0].Error != ErrExternalDisabled.Error() || len(res.Facts) != 0 {
		t.Errorf("disabled source: %+v", res.Sources[0])
	}
	// 2. An enabled source does not run unless the caller allows external sources.
	on := &CTSource{Enabled: true, BaseURL: srv.URL, Client: client}
	res = Collect(context.Background(), testScope(), Options{}, on)
	if !res.Sources[0].Skipped || !res.Sources[0].External {
		t.Errorf("not allowed: %+v", res.Sources[0])
	}
	if len(*reqs) != 0 || tr.calls != 0 {
		t.Errorf("a request was sent while the source was off: %d", tr.calls)
	}
	if !on.External() || (&FileSource{}).External() || (&PTRSource{}).External() {
		t.Error("only the CT source is external")
	}
}

func TestCertificateTransparencyAgainstLocalServer(t *testing.T) {
	srv, reqs := ctServer(t, http.StatusOK)
	tr := &localOnly{}
	src := &CTSource{Enabled: true, BaseURL: srv.URL + "/", Client: &http.Client{Transport: tr}, Delay: time.Millisecond}
	scope := testScope()
	scope.Domains = append(scope.Domains, "KAMPUS.example.") // the same domain twice: one request
	res := Collect(context.Background(), scope, Options{AllowExternal: true}, src)
	if res.Sources[0].Error != "" {
		t.Fatal(res.Sources[0].Error)
	}
	if len(*reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(*reqs))
	}
	r := (*reqs)[0]
	if r.Method != http.MethodGet || r.URL.Path != "/" || r.URL.Query().Get("q") != "%.kampus.example" || r.URL.Query().Get("output") != "json" ||
		r.Header.Get("User-Agent") != "czujka-passive" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
		t.Errorf("request = %s %s, headers %v", r.Method, r.URL, r.Header)
	}
	wantLines(t, brief(res.Facts), "certificate www.kampus.example", "certificate kampus.example", "certificate lab.kampus.example (wildcard)", "certificate stary-portal.kampus.example")
	for _, f := range res.Facts {
		if f.Source != "crt.sh" || f.IP != "" {
			t.Errorf("fact = %+v", f)
		}
	}
	// Names without an address are candidates for the analyst, never targets on their own.
	if len(res.Candidates) != 4 || res.Candidates[0].Kind != model.TargetDomain {
		t.Errorf("candidates = %+v", res.Candidates)
	}
}

func TestCertificateTransparencyErrors(t *testing.T) {
	srv, _ := ctServer(t, http.StatusBadGateway)
	src := &CTSource{Enabled: true, BaseURL: srv.URL, Client: &http.Client{Transport: &localOnly{}}}
	_, err := src.Collect(context.Background(), testScope())
	if err == nil || !strings.Contains(err.Error(), "HTTP 502") || !strings.Contains(err.Error(), "kampus.example") {
		t.Errorf("err = %v", err)
	}
	// Without a BaseURL the source would go to crt.sh: the guard transport stops the test.
	guard := &localOnly{}
	src = &CTSource{Enabled: true, Client: &http.Client{Transport: guard}}
	if _, err := src.Collect(context.Background(), testScope()); err == nil || !strings.Contains(err.Error(), "crt.sh") {
		t.Errorf("default base URL: err = %v", err)
	}
}
