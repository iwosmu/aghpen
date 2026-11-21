package runner

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/targets"
)

func TestAllowedNetworks(t *testing.T) {
	if _, err := ParseAllowed([]string{"10.0.0.0/8", "nie-siec"}); err == nil {
		t.Fatal("a bad network must fail")
	}
	nets, err := ParseAllowed([]string{"10.0.0.0/8", "192.168.1.5", " 2001:db8::/32 "})
	if err != nil || len(nets) != 3 {
		t.Fatalf("parse: %v %v", nets, err)
	}
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "wew.example.org":
			return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
		case "mieszany.example.org":
			return []netip.Addr{netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("8.8.8.8")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	cases := []struct {
		t    model.Target
		want bool
	}{
		{model.Target{Kind: model.TargetIP, Value: "10.20.30.40"}, true},
		{model.Target{Kind: model.TargetIP, Value: "192.168.1.5"}, true},
		{model.Target{Kind: model.TargetIP, Value: "192.168.1.6"}, false},
		{model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/16"}, true},
		{model.Target{Kind: model.TargetCIDR, Value: "0.0.0.0/0"}, false},
		{model.Target{Kind: model.TargetRange, Value: "10.0.0.1-10.0.0.9"}, true},
		{model.Target{Kind: model.TargetRange, Value: "9.255.255.250-10.0.0.9"}, false},
		{model.Target{Kind: model.TargetDomain, Value: "wew.example.org"}, true},
		{model.Target{Kind: model.TargetDomain, Value: "mieszany.example.org"}, false},
		{model.Target{Kind: model.TargetDomain, Value: "brak.example.org"}, false},
		{model.Target{Kind: model.TargetIP, Value: "2001:db8::1"}, true},
	}
	for _, c := range cases {
		ok, reason := TargetAllowed(context.Background(), c.t, nets, lookup)
		if ok != c.want {
			t.Errorf("%s %s: allowed=%v (%s), want %v", c.t.Kind, c.t.Value, ok, reason, c.want)
		}
		if !ok && reason == "" {
			t.Errorf("%s: a refusal needs a reason", c.t.Value)
		}
	}
	// An empty list allows everything.
	kept, dropped, err := FilterAllowed(context.Background(), []model.Target{{Kind: model.TargetIP, Value: "8.8.8.8"}}, model.SafetyPolicy{}, lookup)
	if err != nil || len(kept) != 1 || len(dropped) != 0 {
		t.Fatalf("no allowed networks: %v %v %v", kept, dropped, err)
	}
	kept, dropped, err = FilterAllowed(context.Background(), []model.Target{{Kind: model.TargetIP, Value: "8.8.8.8"}, {Kind: model.TargetIP, Value: "10.0.0.1"}},
		model.SafetyPolicy{AllowedNetworks: []string{"10.0.0.0/8"}}, lookup)
	if err != nil || len(kept) != 1 || len(dropped) != 1 || dropped[0].Value != "8.8.8.8" {
		t.Fatalf("filter: %v %v %v", kept, dropped, err)
	}
}

func TestOperatorLockIsAnUpperBound(t *testing.T) {
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "zewn.example.org" {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("10.9.0.5")}, nil
	}
	targets := []model.Target{
		{Kind: model.TargetIP, Value: "10.9.0.1"},
		{Kind: model.TargetIP, Value: "8.8.4.4"},
		{Kind: model.TargetCIDR, Value: "0.0.0.0/0"},
		{Kind: model.TargetDomain, Value: "zewn.example.org"},
		{Kind: model.TargetDomain, Value: "wewn.example.org"},
		{Kind: model.TargetIP, Value: "10.20.0.1"}, // inside the lock, outside allowed_networks
	}
	// The administrator allowed everything; the operator lock still bounds it.
	pol := model.SafetyPolicy{OperatorNetworks: []string{"10.0.0.0/8"}, AllowedNetworks: []string{"0.0.0.0/0"}}
	kept, dropped, err := FilterAllowed(context.Background(), targets, pol, lookup)
	if err != nil || len(kept) != 3 || len(dropped) != 3 {
		t.Fatalf("lock with a wide policy: kept %v dropped %v %v", kept, dropped, err)
	}
	for _, d := range dropped {
		if !strings.Contains(d.Reason, "blokad") || strings.Contains(d.Reason, "CZUJKA_ALLOWED_NETWORKS") {
			t.Errorf("%s: the reason must name the operator lock: %s", d.Value, d.Reason)
		}
	}
	// Both lists apply: inside the lock but outside allowed_networks is dropped too.
	pol.AllowedNetworks = []string{"10.9.0.0/16"}
	kept, _, _ = FilterAllowed(context.Background(), targets, pol, lookup)
	if len(kept) != 2 || kept[0].Value != "10.9.0.1" || kept[1].Value != "wewn.example.org" {
		t.Fatalf("lock and policy: %v", kept)
	}
	in, _ := netip.ParsePrefix("10.9.0.0/16")
	out, _ := netip.ParsePrefix("0.0.0.0/0")
	lock, _ := ParseAllowed([]string{"10.0.0.0/8"})
	if !PrefixInside(in, lock) || PrefixInside(out, lock) {
		t.Error("PrefixInside")
	}
}

func TestAdHocTargets(t *testing.T) {
	ts, err := AdHocTargets([]string{"10.0.0.1", "10.0.1.0/24"})
	if err != nil || len(ts) != 2 {
		t.Fatalf("targets: %v %v", ts, err)
	}
	if _, err := AdHocTargets([]string{"10.0.0.0/8"}); err == nil {
		t.Error("a /8 must be refused")
	}
	if _, err := AdHocTargets([]string{"przyklad.example.org;rm"}); err == nil {
		t.Error("a bad address must be refused")
	}
	if _, err := AdHocTargets(nil); err == nil {
		t.Error("an empty list must be refused")
	}
}

func TestLoopbackTargetCheckedAsDockerHost(t *testing.T) {
	targets.SetHostGateway(netip.MustParseAddr("172.17.0.1"))
	defer targets.SetHostGateway(netip.Addr{})
	lock := []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}
	for _, tg := range []model.Target{{Kind: model.TargetDomain, Value: "localhost"}, {Kind: model.TargetIP, Value: "127.0.0.1"}} {
		if ok, why := TargetAllowed(context.Background(), tg, lock, nil); !ok {
			t.Errorf("%s maps to 172.17.0.1 inside the lock, refused: %s", tg.Value, why)
		}
	}
	other := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if ok, _ := TargetAllowed(context.Background(), model.Target{Kind: model.TargetDomain, Value: "localhost"}, other, nil); ok {
		t.Error("localhost maps to 172.17.0.1, outside 10.0.0.0/8: must be refused")
	}
}

// Docker Desktop answers host.docker.internal with IPv6 first. The name is
// scanned on its IPv4 address, so only that address is checked.
func TestDomainCheckedOnItsIPv4Address(t *testing.T) {
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "host.docker.internal":
			return []netip.Addr{netip.MustParseAddr("fdc4:f303:9324::254"), netip.MustParseAddr("192.168.65.254")}, nil
		case "v6only.example.org":
			return []netip.Addr{netip.MustParseAddr("2001:db8::7")}, nil
		}
		return nil, errors.New("no such host")
	}
	lock := []netip.Prefix{netip.MustParsePrefix("192.168.65.254/32")}
	if ok, why := TargetAllowed(context.Background(), model.Target{Kind: model.TargetDomain, Value: "host.docker.internal"}, lock, lookup); !ok {
		t.Fatalf("dual-stack name with an allowed IPv4 address refused: %s", why)
	}
	ok, why := TargetAllowed(context.Background(), model.Target{Kind: model.TargetDomain, Value: "v6only.example.org"}, []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}, lookup)
	if ok || !strings.Contains(why, "IPv4") {
		t.Fatalf("a name without an IPv4 address is not scanned: ok=%v %q", ok, why)
	}
	if got := IPv4Of([]netip.Addr{netip.MustParseAddr("::ffff:10.0.0.1"), netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("::1")}); len(got) != 1 || got[0].String() != "10.0.0.1" {
		t.Fatalf("IPv4Of = %v", got)
	}
}
