package targets

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

// netResolver answers like Docker Desktop: host.docker.internal has an IPv6
// address first and an IPv4 address; network "ip4" filters.
type netResolver map[string][]string

func (f netResolver) LookupIP(_ context.Context, network string, host string) ([]net.IP, error) {
	var out []net.IP
	for _, s := range f[host] {
		ip := net.ParseIP(s)
		if network == "ip4" && ip.To4() == nil {
			continue
		}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

func withGateway(t *testing.T, a string) {
	t.Helper()
	SetHostGateway(netip.MustParseAddr(a))
	t.Cleanup(func() { SetHostGateway(netip.Addr{}) })
}

func TestIsLoopbackValue(t *testing.T) {
	for v, want := range map[string]bool{
		"localhost": true, "LOCALHOST.": true, "127.0.0.1": true, "127.1.2.3": true, "::1": true,
		"127.0.0.0/8": false, "127.0.0.1-5": false, "10.0.0.1": false, "localhost.example.com": false, "::2": false,
	} {
		if got := IsLoopbackValue(v); got != want {
			t.Errorf("IsLoopbackValue(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestMapsToOnlyWithGateway(t *testing.T) {
	if got := MapsTo("localhost"); got != "" {
		t.Fatalf("without a gateway MapsTo = %q, want empty", got)
	}
	withGateway(t, "192.168.65.254")
	for _, v := range []string{"localhost", "127.0.0.1", "::1"} {
		if got := MapsTo(v); got != "192.168.65.254" {
			t.Errorf("MapsTo(%q) = %q", v, got)
		}
	}
	if got := MapsTo("10.0.0.1"); got != "" {
		t.Errorf("MapsTo(10.0.0.1) = %q, want empty", got)
	}
	// IPv6 gateways are refused: the mapping turns off.
	SetHostGateway(netip.MustParseAddr("fdc4:f303:9324::254"))
	if HostGateway().IsValid() {
		t.Fatal("an IPv6 gateway must not be accepted")
	}
}

func TestParseTextSetsMapsTo(t *testing.T) {
	withGateway(t, "172.17.0.1")
	res := ParseText("localhost\n127.0.0.1\n10.0.0.5")
	if len(res.Targets) != 3 {
		t.Fatalf("targets: %+v", res.Targets)
	}
	if res.Targets[0].Value != "localhost" || res.Targets[0].MapsTo != "172.17.0.1" || res.Targets[0].Kind != model.TargetDomain {
		t.Errorf("localhost: %+v", res.Targets[0])
	}
	if res.Targets[1].MapsTo != "172.17.0.1" || res.Targets[2].MapsTo != "" {
		t.Errorf("maps_to: %q %q", res.Targets[1].MapsTo, res.Targets[2].MapsTo)
	}
}

func TestExpandMapsLoopbackToGateway(t *testing.T) {
	ts := []model.Target{{Kind: model.TargetDomain, Value: "localhost"}, {Kind: model.TargetIP, Value: "127.0.0.1"}, {Kind: model.TargetIP, Value: "::1"}}
	// Without a gateway: loopback is loopback, as before.
	exp := Expand(context.Background(), ts, nil, netResolver{"localhost": {"127.0.0.1", "::1"}}, 0)
	if !exp.V4.Contains(U32(netip.MustParseAddr("127.0.0.1"))) {
		t.Fatalf("without a gateway 127.0.0.1 must stay: %v", Spec(exp.V4.Ranges()))
	}

	withGateway(t, "192.168.65.254")
	exp = Expand(context.Background(), ts, nil, netResolver{}, 0)
	gw := U32(netip.MustParseAddr("192.168.65.254"))
	if exp.V4.Count() != 1 || !exp.V4.Contains(gw) || len(exp.V6) != 0 {
		t.Fatalf("scope = %v v6=%v, want only the gateway", Spec(exp.V4.Ranges()), exp.V6)
	}
	if got := exp.Hostnames["192.168.65.254"]; len(got) != 1 || got[0] != "localhost" {
		t.Errorf("hostnames of the gateway = %v, want [localhost]", got)
	}
	if len(exp.Unresolved) != 0 {
		t.Errorf("localhost must not be resolved by DNS: %v", exp.Unresolved)
	}

	// Exclusions apply to the mapped address, not to 127.0.0.1.
	exp = Expand(context.Background(), ts, []string{"127.0.0.0/8"}, netResolver{}, 0)
	if exp.V4.Count() != 1 {
		t.Errorf("an exclusion of 127.0.0.0/8 must not remove the docker host: %v", Spec(exp.V4.Ranges()))
	}
	exp = Expand(context.Background(), ts, []string{"192.168.65.254"}, netResolver{}, 0)
	if exp.V4.Count() != 0 || exp.Excluded != 1 {
		t.Errorf("an exclusion of the gateway must remove it: count=%d excluded=%d", exp.V4.Count(), exp.Excluded)
	}
	total, excluded := Count(ts, []string{"192.168.65.254"})
	if total != 1 || excluded != 1 {
		t.Errorf("Count = %d, %d; want 1, 1", total, excluded)
	}
}

func TestResolveHostGateway(t *testing.T) {
	ctx := context.Background()
	desktop := netResolver{GatewayName: {"fdc4:f303:9324::254", "192.168.65.254"}}
	cases := []struct {
		setting   string
		container bool
		res       Resolver
		want      string
		wantErr   bool
	}{
		{"", true, desktop, "192.168.65.254", false},                  // IPv6 answered first: the IPv4 address wins
		{"", false, desktop, "", false},                               // not in a container: loopback stays loopback
		{"off", true, desktop, "", false},                             // switched off
		{"10.1.2.3", false, desktop, "10.1.2.3", false},               // a literal overrides, also outside a container
		{"", true, netResolver{GatewayName: {"fdc4::254"}}, "", true}, // IPv6 only: error, mapping off
		{"::1", true, desktop, "", true},
		{"", true, netResolver{}, "", true},
	}
	for _, c := range cases {
		got, err := ResolveHostGateway(ctx, c.setting, c.container, c.res)
		if (err != nil) != c.wantErr {
			t.Errorf("%q container=%v: err = %v, wantErr %v", c.setting, c.container, err, c.wantErr)
			continue
		}
		gs := ""
		if got.IsValid() {
			gs = got.String()
		}
		if gs != c.want {
			t.Errorf("%q container=%v: got %q, want %q", c.setting, c.container, gs, c.want)
		}
	}
}

func TestShownHostname(t *testing.T) {
	for _, c := range []struct{ name, ip, want string }{
		{"localhost", "172.18.0.1", ""}, // a loopback target mapped to the docker host
		{"LOCALHOST.", "172.18.0.1", ""},
		{"127.0.0.1", "10.0.0.5", ""},
		{"localhost", "127.0.0.1", "localhost"}, // Czujka outside a container
		{"localhost", "::1", "localhost"},
		{"shop.example.org", "172.18.0.1", "shop.example.org"},
		{"", "172.18.0.1", ""},
	} {
		if got := ShownHostname(c.name, c.ip); got != c.want {
			t.Errorf("ShownHostname(%q, %q) = %q, want %q", c.name, c.ip, got, c.want)
		}
	}
	if got := ShownHostnames([]string{"localhost", "gw.lab"}, "172.18.0.1"); len(got) != 1 || got[0] != "gw.lab" {
		t.Errorf("ShownHostnames = %v", got)
	}
}
