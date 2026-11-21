package targets

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

func TestParseValue(t *testing.T) {
	cases := []struct {
		in    string
		kind  model.TargetKind
		value string
		count int64
	}{
		{"10.0.0.1", model.TargetIP, "10.0.0.1", 1},
		{" 192.168.1.0/24 ", model.TargetCIDR, "192.168.1.0/24", 256},
		{"192.168.1.77/24", model.TargetCIDR, "192.168.1.0/24", 256},
		{"10.0.0.0/8", model.TargetCIDR, "10.0.0.0/8", 16777216},
		{"0.0.0.0/0", model.TargetCIDR, "0.0.0.0/0", 4294967296},
		{"10.1.2.3/32", model.TargetIP, "10.1.2.3", 1},
		{"10.0.0.5-10.0.0.90", model.TargetRange, "10.0.0.5-10.0.0.90", 86},
		{"10.0.0.5-90", model.TargetRange, "10.0.0.5-10.0.0.90", 86},
		{"10.0.0.250-10.0.1.5", model.TargetRange, "10.0.0.250-10.0.1.5", 12},
		{"10.0.0.7-7", model.TargetIP, "10.0.0.7", 1},
		{"Example.COM.", model.TargetDomain, "example.com", 1},
		{"my-host.agh.edu.pl", model.TargetDomain, "my-host.agh.edu.pl", 1},
		{"https://panel.example.org:8443/login", model.TargetDomain, "panel.example.org", 1},
		{"2001:db8::1", model.TargetIP, "2001:db8::1", 1},
		{"::ffff:10.0.0.9", model.TargetIP, "10.0.0.9", 1},
	}
	for _, c := range cases {
		p, err := ParseValue(c.in)
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if p.Kind != c.kind || p.Value != c.value || p.Count != c.count {
			t.Errorf("%q: got (%s, %s, %d), want (%s, %s, %d)", c.in, p.Kind, p.Value, p.Count, c.kind, c.value, c.count)
		}
	}
	for _, bad := range []string{"", "10.0.0.256", "10.0.0", "10.0.0.0/33", "10.0.0.9-10.0.0.1", "10.0.0.9-300", "2001:db8::/64", "abc", "exa mple.com", "-foo.example.com", "1.2.3.4.5", "host.123", "10.0.0.x-5", "999.1.1.1-5"} {
		if _, err := ParseValue(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestParseText(t *testing.T) {
	text := "10.0.0.1\n10.0.0.0/24, example.com ; 10.0.1.5-9\n# comment\n\nbad..name\n10.0.0.1  # duplicate\n10.2.0.1 - 10.2.0.9\n300.1.1.1\r\n"
	res := ParseText(text)
	var got []string
	for _, tg := range res.Targets {
		got = append(got, tg.Value)
		if !tg.Enabled || tg.Source != "manual" {
			t.Errorf("target %s: enabled=%v source=%s", tg.Value, tg.Enabled, tg.Source)
		}
	}
	want := []string{"10.0.0.1", "10.0.0.0/24", "example.com", "10.0.1.5-10.0.1.9", "10.2.0.1-10.2.0.9"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if res.Duplicates != 1 {
		t.Errorf("duplicates = %d, want 1", res.Duplicates)
	}
	if len(res.Invalid) != 2 || res.Invalid[0].Line != 5 || res.Invalid[1].Line != 8 {
		t.Fatalf("invalid = %+v", res.Invalid)
	}
	if !strings.Contains(res.Invalid[1].Reason, "IPv4") {
		t.Errorf("reason should be Polish and name IPv4: %q", res.Invalid[1].Reason)
	}
}

func TestParseCSV(t *testing.T) {
	csvData := "Address;Note;Tags\n10.0.0.0/30;core routers;net|prod\nexample.com;\"www; main\";web\nnot an ip;;\n10.0.0.0/30;dup;\n"
	res, err := ParseCSV([]byte(csvData))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Targets) != 2 || res.Duplicates != 1 || len(res.Invalid) != 1 {
		t.Fatalf("got %d targets, %d dup, %d invalid: %+v", len(res.Targets), res.Duplicates, len(res.Invalid), res)
	}
	a := res.Targets[0]
	if a.Value != "10.0.0.0/30" || a.Note != "core routers" || !reflect.DeepEqual(a.Tags, []string{"net", "prod"}) || a.Addresses != 4 || a.Source != "csv" {
		t.Errorf("first target = %+v", a)
	}
	if res.Targets[1].Note != "www; main" {
		t.Errorf("quoted note = %q", res.Targets[1].Note)
	}
	if res.Invalid[0].Line != 4 {
		t.Errorf("invalid line = %d, want 4", res.Invalid[0].Line)
	}

	// no header: first column
	res, err = ParseCSV([]byte("10.1.1.1,foo\n10.1.1.2,bar\n"))
	if err != nil || len(res.Targets) != 2 {
		t.Fatalf("headerless: %v %+v", err, res)
	}
	// header with a different value column position
	res, _ = ParseCSV([]byte("note,ip,tags\nrouter,10.9.9.9,\"a,b\"\n"))
	if len(res.Targets) != 1 || res.Targets[0].Value != "10.9.9.9" || res.Targets[0].Note != "router" || len(res.Targets[0].Tags) != 2 {
		t.Fatalf("ip column: %+v", res)
	}
}

func TestParseJSON(t *testing.T) {
	res, err := ParseJSON([]byte(`["10.0.0.1", "10.0.0.0/24", "nope", 5]`))
	if err != nil || len(res.Targets) != 2 || len(res.Invalid) != 2 {
		t.Fatalf("strings: %v %+v", err, res)
	}
	res, err = ParseJSON([]byte(`[{"cidr":"172.16.0.0/16","note":"dc","tags":["a","b"]},{"host":"example.com","tags":"x;y"},{"note":"no value"}]`))
	if err != nil || len(res.Targets) != 2 || len(res.Invalid) != 1 {
		t.Fatalf("objects: %v %+v", err, res)
	}
	if res.Targets[0].Addresses != 65536 || res.Targets[0].Note != "dc" || len(res.Targets[0].Tags) != 2 || res.Targets[0].Source != "json" {
		t.Errorf("first = %+v", res.Targets[0])
	}
	if !reflect.DeepEqual(res.Targets[1].Tags, []string{"x", "y"}) {
		t.Errorf("tags = %v", res.Targets[1].Tags)
	}
	res, err = ParseJSON([]byte(`{"targets":["10.0.0.1"]}`))
	if err != nil || len(res.Targets) != 1 {
		t.Fatalf("wrapped: %v %+v", err, res)
	}
	if _, err := ParseJSON([]byte(`{"x":1}`)); err == nil {
		t.Error("expected an error for an object without targets")
	}
	if r, err := ParseFile("upload.bin", []byte(`["10.0.0.3"]`)); err != nil || len(r.Targets) != 1 || r.Targets[0].Source != "json" {
		t.Errorf("ParseFile sniff json: %v %+v", err, r)
	}
	if r, err := ParseFile("list.txt", []byte("target,note\n10.0.0.4,x\n")); err != nil || len(r.Targets) != 1 || r.Targets[0].Source != "csv" {
		t.Errorf("ParseFile sniff csv: %v %+v", err, r)
	}
}

func tg(vals ...string) []model.Target {
	var out []model.Target
	for _, v := range vals {
		out = append(out, model.Target{Value: v, Enabled: true})
	}
	return out
}

func TestCountLargeAndExclusions(t *testing.T) {
	total, excluded := Count(tg("10.0.0.0/8"), nil)
	if total != 16777216 || excluded != 0 {
		t.Fatalf("/8 = %d (excluded %d)", total, excluded)
	}
	// overlapping targets are counted once
	total, _ = Count(tg("10.0.0.0/8", "10.5.0.0/16", "10.0.0.1", "10.255.255.250-10.255.255.255"), nil)
	if total != 16777216 {
		t.Fatalf("overlap count = %d", total)
	}
	// exclusions: a /16, one address inside, one outside the scope, one range at the edge
	total, excluded = Count(tg("10.0.0.0/8", "192.168.0.0/24"), []string{"10.5.0.0/16", "10.9.9.9", "172.16.0.1", "192.168.0.250-192.168.1.10"})
	if total != 16777216+256 {
		t.Fatalf("total = %d", total)
	}
	if want := int64(65536 + 1 + 6); excluded != want {
		t.Fatalf("excluded = %d, want %d", excluded, want)
	}
	// domains and IPv6 count as one each
	total, excluded = Count(tg("example.com", "2001:db8::1", "10.0.0.0/30"), []string{"example.com"})
	if total != 6 || excluded != 1 {
		t.Fatalf("mixed: total %d excluded %d", total, excluded)
	}
}

func TestSetSubtractAndBlocks(t *testing.T) {
	s := NewSet(Range{10, 20}, Range{15, 30}, Range{31, 40}, Range{100, 100})
	if got := s.Ranges(); !reflect.DeepEqual(got, []Range{{10, 40}, {100, 100}}) {
		t.Fatalf("merge = %v", got)
	}
	d := s.Subtract(NewSet(Range{0, 12}, Range{20, 25}, Range{40, 99}))
	if got := d.Ranges(); !reflect.DeepEqual(got, []Range{{13, 19}, {26, 39}, {100, 100}}) {
		t.Fatalf("subtract = %v", got)
	}
	if !d.Contains(13) || d.Contains(20) || !d.Contains(100) || d.Contains(101) {
		t.Error("Contains is wrong")
	}
	full := NewSet(Range{0, ^uint32(0)})
	if full.Count() != 1<<32 {
		t.Fatalf("full count = %d", full.Count())
	}
	if got := full.Subtract(NewSet(Range{0, ^uint32(0)})); !got.IsEmpty() {
		t.Fatalf("full minus full = %v", got.Ranges())
	}

	// 10.0.0.200 - 10.0.2.9: three blocks, never crossing a /24
	st := Build([]string{"10.0.0.200-10.0.2.9"})
	var blocks []string
	st.V4.Blocks(func(b Range) bool {
		if b.Lo>>8 != b.Hi>>8 {
			t.Errorf("block %v crosses a /24", b)
		}
		blocks = append(blocks, Spec([]Range{b})...)
		return true
	})
	want := []string{"10.0.0.200-255", "10.0.1.0/24", "10.0.2.0-9"}
	if !reflect.DeepEqual(blocks, want) {
		t.Fatalf("blocks = %v, want %v", blocks, want)
	}
	if st.V4.BlockCount() != 3 {
		t.Errorf("BlockCount = %d", st.V4.BlockCount())
	}
	if n := Build([]string{"10.0.0.0/8"}).V4.BlockCount(); n != 65536 {
		t.Errorf("/8 block count = %d", n)
	}
}

func TestSpecRoundTrip(t *testing.T) {
	for _, in := range [][]string{{"10.77.0.0/22"}, {"10.0.0.5-10.0.0.90"}, {"10.0.0.7"}, {"10.0.0.250-10.0.1.5"}, {"10.0.0.0/24", "10.0.1.0/24", "10.0.5.3"}} {
		st := Build(in)
		spec := Spec(st.V4.Ranges())
		back := Build(spec)
		if len(back.Invalid) != 0 || !reflect.DeepEqual(back.V4.Ranges(), st.V4.Ranges()) {
			t.Errorf("%v → %v → %v (invalid %v)", in, spec, back.V4.Ranges(), back.Invalid)
		}
	}
	if got := Spec(Build([]string{"10.77.0.0-10.77.3.255"}).V4.Ranges()); !reflect.DeepEqual(got, []string{"10.77.0.0/22"}) {
		t.Errorf("spec = %v", got)
	}
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	ips, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []net.IP
	for _, s := range ips {
		out = append(out, net.ParseIP(s))
	}
	return out, nil
}

func TestExpandResolvesAndExcludes(t *testing.T) {
	res := fakeResolver{
		"www.example.com":   {"10.0.0.5", "10.0.9.9"},
		"alias.example.com": {"10.0.0.5"},
		"skip.example.com":  {"10.0.0.77"},
	}
	ex := Expand(context.Background(),
		tg("10.0.0.0/24", "www.example.com", "alias.example.com", "gone.example.com", "2001:db8::1", "skip.example.com"),
		[]string{"10.0.0.128/25", "skip.example.com"}, res, 0)
	if got := ex.V4.Count(); got != 127+1 { // lower half without 10.0.0.77, plus 10.0.9.9
		t.Fatalf("v4 count = %d, ranges %v", got, ex.V4.Ranges())
	}
	if !reflect.DeepEqual(ex.Hostnames["10.0.0.5"], []string{"alias.example.com", "www.example.com"}) {
		t.Errorf("hostnames = %v", ex.Hostnames)
	}
	if !reflect.DeepEqual(ex.Hostnames["10.0.9.9"], []string{"www.example.com"}) {
		t.Errorf("hostnames = %v", ex.Hostnames)
	}
	if _, ok := ex.Unresolved["gone.example.com"]; !ok {
		t.Errorf("unresolved = %v", ex.Unresolved)
	}
	if len(ex.V6) != 1 {
		t.Errorf("v6 = %v", ex.V6)
	}
	if ex.Excluded != 128+1+1 { // upper half, 10.0.0.77, and the excluded domain target
		t.Errorf("excluded = %d", ex.Excluded)
	}
	if ex.Count() != 129 {
		t.Errorf("count = %d", ex.Count())
	}
}

func TestPreview(t *testing.T) {
	p := Preview("10.0.0.0/24\n10.0.0.0/24\nbad\n10.0.1.1", []string{"10.0.0.0/25"})
	if len(p.Valid) != 2 || p.Duplicates != 1 || len(p.Invalid) != 1 || p.Excluded != 128 || p.AddressCount != 129 {
		t.Fatalf("preview = %+v", p)
	}
}
