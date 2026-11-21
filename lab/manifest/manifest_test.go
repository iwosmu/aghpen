package manifest

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/lab/labcfg"
	"github.com/iwosmu/aghpen/lab/truth"
)

func TestManifestIsValid(t *testing.T) {
	if err := New().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLabShapeMeetsTheBrief(t *testing.T) {
	l := New()
	if !strings.HasSuffix(Network, "/16") {
		t.Fatalf("network %s is not a /16", Network)
	}
	blocks := map[string]int{}
	hosts := 0
	for _, c := range l.Containers {
		if c.NotAHost || !c.InState("t0") {
			continue
		}
		hosts++
		p, _ := netip.MustParseAddr(c.IP).Prefix(24)
		blocks[p.String()]++
	}
	if hosts < 40 {
		t.Fatalf("only %d hosts in t0, the brief asks for at least 40", hosts)
	}
	single, cluster := 0, 0
	for _, n := range blocks {
		if n == 1 {
			single++
		}
		if n >= 5 {
			cluster++
		}
	}
	if len(blocks) < 10 || single < 3 || cluster < 3 {
		t.Fatalf("address plan is not spread enough: %d blocks, %d single-host blocks, %d clusters", len(blocks), single, cluster)
	}
	mem := 0
	for _, c := range l.Containers {
		mem += c.MemMB
	}
	if mem > 12*1024 {
		t.Fatalf("sum of memory limits is %d MiB", mem)
	}
}

func TestEveryStateHasTruthAndChanges(t *testing.T) {
	l := New()
	t0, t1, t2 := l.Truth("t0"), l.Truth("t1"), l.Truth("t2")
	for _, f := range []*truth.File{t0, t1, t2} {
		for _, h := range f.Hosts {
			if len(h.Services) == 0 {
				t.Errorf("%s: host %s has no services", f.State, h.Name)
			}
		}
	}
	kinds := map[string]bool{}
	for _, c := range truth.Diff(t0, t1) {
		kinds[c.Kind] = true
	}
	for _, c := range truth.Diff(t1, t2) {
		kinds[c.Kind] = true
	}
	for _, k := range []string{"host_new", "host_gone", "service_new", "service_gone", "service_changed", "title_changed", "cert_changed",
		"headers_changed", "cookies_changed", "class_changed", "tech_version", "status_changed", "redirect_changed"} {
		if !kinds[k] {
			t.Errorf("the scenarios never produce a %s change", k)
		}
	}
}

func TestSimTruthIsDerivedFromTheConfiguration(t *testing.T) {
	l := New()
	find := func(state, name string) truth.Host {
		for _, h := range l.Truth(state).Hosts {
			if h.Name == name {
				return h
			}
		}
		t.Fatalf("no host %s in %s", name, state)
		return truth.Host{}
	}
	chain := find("t0", "redir-chain").Services[0].HTTP
	if chain.Status != 301 || chain.Location != "/start" || chain.Title != "Biuro Karier — strona główna" {
		t.Errorf("redirect chain truth is wrong: %+v", chain)
	}
	for name, want := range map[string][3]bool{ // self-signed, expired, host mismatch
		"tls-selfsigned": {true, false, false}, "tls-expired": {false, true, false}, "tls-mismatch": {false, false, true}, "tls-valid": {false, false, false},
	} {
		var tl *truth.TLS
		for _, s := range find("t0", name).Services {
			if s.Port == 443 {
				tl = s.TLS
			}
		}
		if tl == nil {
			t.Fatalf("%s has no TLS truth", name)
		}
		if got := [3]bool{tl.SelfSigned, tl.Expired, tl.HostMismatch}; got != want {
			t.Errorf("%s: self-signed/expired/mismatch = %v, want %v", name, got, want)
		}
	}
	if find("t2", "tls-expired").Services[0].TLS.Expired {
		t.Error("the expired certificate must be renewed in t2")
	}
	kiosk := find("t0", "kiosk-1").Services[0]
	if kiosk.HTTP.FaviconMMH3 == nil || *kiosk.HTTP.FaviconMMH3 != labcfg.FaviconMMH3(labcfg.Favicon("infokiosk")) {
		t.Error("kiosk favicon hash is not in the truth")
	}
	jwt := false
	for _, c := range find("t0", "jwt-app").Services[0].HTTP.Cookies {
		if c.Name == "access_token" && c.JWT && !c.HTTPOnly && !c.Secure {
			jwt = true
		}
	}
	if !jwt {
		t.Error("the JWT cookie is not marked in the truth")
	}
	if got := HTMLTitle("<html><title> A&nbsp;B \n C</title>"); got != "A B C" {
		t.Errorf("HTMLTitle = %q", got)
	}
}

func TestUnstableHostsAreMarked(t *testing.T) {
	n := 0
	for _, h := range New().Truth("t0").Hosts {
		if h.Availability != nil {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("want 3 unstable hosts, got %d", n)
	}
}

// The generated files in the repository must match the manifest.
func TestGeneratedFilesAreUpToDate(t *testing.T) {
	l := New()
	files, err := l.Files("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f.Path)
		if err != nil {
			t.Errorf("%s: %v (run: go run ./lab/gen)", f.Path, err)
			continue
		}
		if string(raw) != f.Content {
			t.Errorf("%s is out of date (run: go run ./lab/gen)", f.Path)
		}
	}
}

func TestComposeEscapesDollarAndPinsAddresses(t *testing.T) {
	out := New().Compose()
	if !strings.Contains(out, "subnet: 10.66.0.0/16") || !strings.Contains(out, "ipv4_address: 10.66.255.254") {
		t.Fatal("compose misses the network or an address")
	}
	if strings.Contains(out, "'$SYS") && !strings.Contains(out, "'$$SYS") {
		t.Fatal("a dollar sign is not escaped for compose")
	}
	stop, start := New().StateLists("t1")
	if strings.Join(stop, " ") != "ftp legacy-php nginx-old wp-old" || strings.Join(start, " ") != "cam-3 nginx-new shadow-adminer wp-new" {
		t.Fatalf("t1 lists: stop=%v start=%v", stop, start)
	}
}
