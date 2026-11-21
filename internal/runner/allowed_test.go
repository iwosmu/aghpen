package runner

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
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
