package doctor

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func fakes() Deps {
	return Deps{
		Version:  "test",
		LookPath: func(s string) (string, error) { return "/usr/bin/" + s, nil },
		Command: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("Nmap version 7.95 ( https://nmap.org )\n"), nil
		},
		RawSocket:  func() error { return nil },
		Resolve:    func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil },
		Route:      func(netip.Addr) (netip.Addr, error) { return netip.MustParseAddr("10.0.0.5"), nil },
		Interfaces: func() ([]netip.Prefix, error) { return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, nil },
		FreeBytes:  func(string) (uint64, error) { return 50 << 30, nil },
		DataDir:    "/var/lib/czujka",
	}
}

func byName(r Report) map[string]Check {
	out := map[string]Check{}
	for _, c := range r.Checks {
		out[c.Name] = c
	}
	return out
}

func TestDoctorWithoutDatabase(t *testing.T) {
	d := fakes()
	d.StoreErr = errors.New("dial tcp 127.0.0.1:5432: connection refused")
	r := Run(context.Background(), d)
	c := byName(r)
	if r.OK || c["database"].Status != Fail || !strings.Contains(c["database"].Fix, "CZUJKA_DB_URL") {
		t.Fatalf("database: %+v", c["database"])
	}
	if c["pg_tde"].Status != Skip || c["scan_networks"].Status != Skip || c["pg_tde"].Fix != "" {
		t.Fatalf("checks that need the database must be skipped: %+v %+v", c["pg_tde"], c["scan_networks"])
	}
	if c["nmap"].Status != OK || !strings.Contains(c["nmap"].Detail, "7.95") {
		t.Fatalf("nmap: %+v", c["nmap"])
	}
	if c["raw_sockets"].Status != OK || c["disk"].Status != OK || c["backup_tools"].Status != OK || c["dns"].Status != OK {
		t.Fatalf("local checks: %+v", r.Checks)
	}
	if !strings.Contains(Text(r), "Co zrobić:") {
		t.Fatalf("the text report must show the fix:\n%s", Text(r))
	}
}

func TestDoctorFailuresCarryPolishFixes(t *testing.T) {
	d := fakes()
	d.StoreErr = errors.New("no db")
	d.KeyErr = errors.New("plik klucza nie istnieje")
	d.LookPath = func(s string) (string, error) { return "", errors.New("not found") }
	d.RawSocket = func() error { return errors.New("operation not permitted") }
	d.Resolve = func(context.Context, string) ([]string, error) { return nil, errors.New("timeout") }
	d.FreeBytes = func(string) (uint64, error) { return 100 << 20, nil }
	c := byName(Run(context.Background(), d))
	for name, want := range map[string]string{"master_key": Fail, "nmap": Warn, "raw_sockets": Warn, "dns": Fail, "disk": Fail, "backup_tools": Warn} {
		if c[name].Status != want || c[name].Fix == "" {
			t.Errorf("%s: %+v, want %s with a fix", name, c[name], want)
		}
	}
	if !strings.Contains(c["raw_sockets"].Fix, "CAP_NET_RAW") || !strings.Contains(c["backup_tools"].Fix, "postgresql") {
		t.Errorf("fixes: %q / %q", c["raw_sockets"].Fix, c["backup_tools"].Fix)
	}
}

func TestOldNmapAndFirstAddr(t *testing.T) {
	d := fakes()
	d.Command = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Nmap version 7.60 ( https://nmap.org )"), nil
	}
	d.StoreErr = errors.New("x")
	if c := byName(Run(context.Background(), d))["nmap"]; c.Status != Warn {
		t.Fatalf("old nmap: %+v", c)
	}
	res := func(context.Context, string) ([]string, error) { return []string{"192.0.2.7"}, nil }
	for _, tc := range []struct{ kind, v, want string }{
		{"ip", "10.1.1.1", "10.1.1.1"}, {"cidr", "10.1.0.0/16", "10.1.0.1"}, {"cidr", "10.1.1.1/32", "10.1.1.1"},
		{"range", "10.2.0.5-10.2.0.9", "10.2.0.5"}, {"domain", "a.example.org", "192.0.2.7"},
	} {
		a, err := firstAddr(context.Background(), targetOf(tc.kind, tc.v), res)
		if err != nil || a.String() != tc.want {
			t.Errorf("%s %s: %v %v, want %s", tc.kind, tc.v, a, err, tc.want)
		}
	}
}

func TestRouteSourceSendsNothingAndWorksForLoopback(t *testing.T) {
	src, err := routeSource(netip.MustParseAddr("127.0.0.1"))
	if err != nil || !src.IsLoopback() {
		t.Fatalf("route to loopback: %v %v", src, err)
	}
}
