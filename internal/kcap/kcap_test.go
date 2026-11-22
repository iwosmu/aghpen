package kcap

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

func TestRateAndBurst(t *testing.T) {
	for _, c := range []struct{ pps, rate, burst int }{
		{500, 550, 55}, {1000, 1100, 110}, {1, 2, 1}, {0, 2, 1}, {7, 8, 1}, {100000, 110000, 11000}, {333, 367, 37},
	} {
		if r := Rate(c.pps); r != c.rate {
			t.Errorf("Rate(%d) = %d, want %d", c.pps, r, c.rate)
		}
		if b := Burst(Rate(c.pps)); b != c.burst {
			t.Errorf("Burst(Rate(%d)) = %d, want %d", c.pps, b, c.burst)
		}
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeAuto, "auto": ModeAuto, " Require ": ModeRequire, "OFF": ModeOff} {
		if m, err := ParseMode(in); err != nil || m != want {
			t.Errorf("ParseMode(%q) = %q, %v", in, m, err)
		}
	}
	if _, err := ParseMode("on"); err == nil {
		t.Error("ParseMode(on) must fail")
	}
}

const wantRuleset = "table inet czujka_kcap {}\n" +
	"delete table inet czujka_kcap\n" +
	"table inet czujka_kcap {\n" +
	"\tcounter dropped {\n\t\tcomment \"probe packets over the cap\"\n\t}\n\n" +
	"\tlimit probes {\n\t\trate over 550/second burst 55 packets\n\t}\n\n" +
	"\tset exempt4 {\n\t\ttype ipv4_addr\n\t\telements = { 10.0.0.2, 127.0.0.11 }\n\t}\n\n" +
	"\tset exempt6 {\n\t\ttype ipv6_addr\n\t\telements = { fd00::53 }\n\t}\n\n" +
	"\tchain output {\n" +
	"\t\ttype filter hook output priority filter; policy accept;\n" +
	"\t\toifname \"lo\" accept\n" +
	"\t\tip daddr @exempt4 accept\n" +
	"\t\tip6 daddr @exempt6 accept\n" +
	"\t\ttcp flags & (syn | ack) == syn jump probe\n" +
	"\t\ttcp flags & (syn | ack | fin | rst) == ack ct state { new, invalid } jump probe\n" +
	"\t\ticmp type { echo-request, timestamp-request } jump probe\n" +
	"\t\ticmpv6 type echo-request jump probe\n" +
	"\t\tmeta l4proto udp jump probe\n" +
	"\t}\n\n" +
	"\tchain probe {\n" +
	"\t\tlimit name \"probes\" counter name \"dropped\" drop\n" +
	"\t}\n" +
	"}\n"

func TestRender(t *testing.T) {
	ex := []netip.Addr{netip.MustParseAddr("127.0.0.11"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("::ffff:10.0.0.2"), netip.MustParseAddr("fd00::53%eth0"), {}}
	got := Render(500, ex)
	if got != wantRuleset {
		t.Fatalf("ruleset differs.\n--- got\n%s\n--- want\n%s", got, wantRuleset)
	}
}

func TestRenderTouchesOnlyItsOwnTable(t *testing.T) {
	r := Render(1000, nil)
	for _, l := range strings.Split(r, "\n") {
		f := strings.Fields(l)
		if len(f) > 0 && (f[0] == "table" || f[0] == "delete" || f[0] == "flush") {
			if !strings.Contains(l, "inet "+Table) {
				t.Errorf("line names another table: %q", l)
			}
		}
	}
	for _, bad := range []string{"flush ruleset", "policy drop", "hook input", "hook forward", "hook prerouting"} {
		if strings.Contains(r, bad) {
			t.Errorf("ruleset contains %q", bad)
		}
	}
	// Sets without elements carry no elements line (nft rejects "elements = { }").
	if strings.Contains(r, "elements") {
		t.Error("empty exempt sets must have no elements line")
	}
	if !strings.Contains(r, "rate over 1100/second burst 110 packets") {
		t.Error("rate for 1000 pps")
	}
}

func TestHostNetwork(t *testing.T) {
	cases := []struct {
		in     bool
		mode   string
		ifaces []string
		host   bool
	}{
		{false, "", []string{"lo", "eth0"}, true},
		{true, "host", []string{"lo", "eth0"}, true},
		{true, "", []string{"lo", "eth0", "docker0"}, true},
		{true, "", []string{"lo", "enp3s0", "br-0aaee657049a"}, true},
		{true, "", []string{"lo", "veth12ab"}, true},
		{true, "", []string{"lo", "eth0", "eth1", "tunl0", "sit0"}, false},
		{true, "bridge", []string{"lo", "eth0"}, false},
	}
	for _, c := range cases {
		host, reason := HostNetwork(c.in, c.mode, c.ifaces)
		if host != c.host || (host && !strings.HasPrefix(reason, "unavailable: host network")) || (!host && reason != "") {
			t.Errorf("HostNetwork(%v, %q, %v) = %v, %q", c.in, c.mode, c.ifaces, host, reason)
		}
	}
}

func TestParseResolvConf(t *testing.T) {
	got := ParseResolvConf([]byte("# docker\nnameserver 127.0.0.11\nsearch x\nnameserver fe80::1%eth0\nnameserver bogus\noptions ndots:0\n"))
	if len(got) != 2 || got[0].String() != "127.0.0.11" || got[1].String() != "fe80::1" {
		t.Fatalf("got %v", got)
	}
}

func TestParseCounter(t *testing.T) {
	out := []byte(`{"nftables": [{"metainfo": {"version": "1.1.3", "json_schema_version": 1}}, {"counter": {"family": "inet", "name": "dropped", "table": "czujka_kcap", "handle": 3, "packets": 6812, "bytes": 299728}}]}`)
	if n, err := ParseCounter(out); err != nil || n != 6812 {
		t.Fatalf("ParseCounter = %d, %v", n, err)
	}
	if _, err := ParseCounter([]byte(`{"nftables": []}`)); err == nil {
		t.Error("no counter must fail")
	}
	if _, err := ParseCounter([]byte("Error")); err == nil {
		t.Error("bad JSON must fail")
	}
}

// fakeNft records calls and plays the kernel's counter.
type fakeNft struct {
	calls   []string
	applied []string
	fail    error
	counter int64
}

func (f *fakeNft) Run(_ context.Context, stdin string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if f.fail != nil {
		return nil, f.fail
	}
	switch strings.Join(args, " ") {
	case "-f -":
		f.applied = append(f.applied, stdin)
		f.counter = 0 // a new table, a new counter
	case "-j list counter inet czujka_kcap dropped":
		return []byte(`{"nftables":[{"counter":{"packets":` + strconv.FormatInt(f.counter, 10) + `}}]}`), nil
	}
	return nil, nil
}

func TestSyncInstallsReplacesAndKeepsTheCount(t *testing.T) {
	f := &fakeNft{}
	c := New(Options{Mode: ModeAuto, Runner: f, Exempt: func(context.Context) []netip.Addr { return []netip.Addr{netip.MustParseAddr("10.0.0.2")} }})
	ctx := context.Background()
	if s := c.Status(ctx); s.Active || s.Reason == "" {
		t.Fatalf("before Sync: %+v", s)
	}
	c.Sync(ctx, 500)
	c.Sync(ctx, 500) // same cap: no second install
	if len(f.applied) != 1 || !strings.Contains(f.applied[0], "rate over 550/second burst 55 packets") || !strings.Contains(f.applied[0], "10.0.0.2") {
		t.Fatalf("applied %d rulesets: %v", len(f.applied), f.applied)
	}
	f.counter = 40
	if n, ok := c.Dropped(ctx); !ok || n != 40 {
		t.Fatalf("Dropped = %d, %v", n, ok)
	}
	c.Sync(ctx, 1000) // the cap changed: replace, and keep the 40
	if len(f.applied) != 2 || !strings.Contains(f.applied[1], "rate over 1100/second burst 110 packets") {
		t.Fatalf("second install: %v", f.applied)
	}
	f.counter = 2
	s := c.Status(ctx)
	if !s.Active || s.PPS != 1100 || s.Burst != 110 || s.PolicyPPS != 1000 || s.Dropped != 42 || s.Reason != "" || s.Mode != ModeAuto {
		t.Fatalf("status %+v", s)
	}
	if err := c.Ready(); err != nil {
		t.Fatal(err)
	}
}

func TestAutoDegradesAndRequireRefuses(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []Mode{ModeAuto, ModeRequire} {
		f := &fakeNft{fail: errors.New("nft: exit status 1: Error: Could not process rule: Protocol not supported")}
		c := New(Options{Mode: mode, Runner: f})
		c.Sync(ctx, 500)
		s := c.Status(ctx)
		if s.Active || !strings.Contains(s.Reason, "Protocol not supported") {
			t.Fatalf("%s: status %+v", mode, s)
		}
		err := c.Ready()
		if (mode == ModeRequire) != (err != nil) {
			t.Fatalf("%s: Ready = %v", mode, err)
		}
		n := len(f.calls)
		c.Sync(ctx, 500) // a failed attempt is not repeated for the same cap
		if len(f.calls) != n {
			t.Fatalf("%s: retried without Retry", mode)
		}
		c.Retry()
		c.Sync(ctx, 500)
		if len(f.calls) == n {
			t.Fatalf("%s: Retry did not retry", mode)
		}
	}
}

func TestHostNetworkIsNeverTouched(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []Mode{ModeAuto, ModeRequire, ModeOff} {
		f := &fakeNft{}
		c := New(Options{Mode: mode, Runner: f, Unsafe: func() string { return "unavailable: host network (CZUJKA_NETWORK_MODE=host)" }})
		c.Sync(ctx, 500)
		c.Status(ctx)
		if len(f.calls) != 0 {
			t.Fatalf("%s: nft ran in the host namespace: %v", mode, f.calls)
		}
		s := c.Status(ctx)
		if s.Active {
			t.Fatalf("%s: active", mode)
		}
		if mode != ModeOff && !strings.HasPrefix(s.Reason, "unavailable: host network") {
			t.Fatalf("%s: reason %q", mode, s.Reason)
		}
		if (mode == ModeRequire) != (c.Ready() != nil) {
			t.Fatalf("%s: Ready = %v", mode, c.Ready())
		}
	}
}

func TestOffRemovesOnlyItsOwnTable(t *testing.T) {
	f := &fakeNft{}
	c := New(Options{Mode: ModeOff, Runner: f})
	c.Sync(context.Background(), 500)
	c.Sync(context.Background(), 900)
	if len(f.calls) != 1 || f.calls[0] != "delete table inet czujka_kcap" {
		t.Fatalf("calls %v", f.calls)
	}
	if s := c.Status(context.Background()); s.Active || s.Mode != ModeOff || !strings.HasPrefix(s.Reason, "off") {
		t.Fatalf("status %+v", s)
	}
}

func TestFailedReplaceRemovesTheStaleTable(t *testing.T) {
	f := &fakeNft{}
	c := New(Options{Mode: ModeAuto, Runner: f})
	ctx := context.Background()
	c.Sync(ctx, 500)
	f.fail = errors.New("nft: boom")
	c.Sync(ctx, 800)
	last := f.calls[len(f.calls)-1]
	if last != "delete table inet czujka_kcap" {
		t.Fatalf("last call %q", last)
	}
	if s := c.Status(ctx); s.Active {
		t.Fatal("still active after a failed replace")
	}
}
