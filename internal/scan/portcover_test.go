package scan

import (
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
)

// The coverage of a host is the profile's ports plus what a finished dense
// or full-range pass scanned on that host, plus the UDP ports.
func TestCoverage(t *testing.T) {
	base := &probe.PortSet{}
	for _, p := range []int{22, 80, 81, 82, 443} {
		base.Add(p)
	}
	r := &run{ports: base, udpPorts: []int{161, 53, 123}}
	c := r.coverage("10.0.0.1")
	want := []model.PortRange{{Lo: 22, Hi: 22}, {Lo: 80, Hi: 82}, {Lo: 443, Hi: 443}}
	if len(c.TCP) != len(want) {
		t.Fatalf("tcp %+v", c.TCP)
	}
	for i := range want {
		if c.TCP[i] != want[i] {
			t.Fatalf("tcp %+v, want %+v", c.TCP, want)
		}
	}
	if !c.Has("udp", 53) || !c.Has("udp", 161) || c.Has("udp", 54) || c.Has("tcp", 8787) || !c.Has("tcp", 81) {
		t.Errorf("coverage %+v", c)
	}
	rest := &probe.PortSet{}
	for p := 1; p <= 65535; p++ {
		if !base.Has(p) {
			rest.Add(p)
		}
	}
	r.cover("10.0.0.1", rest)
	if c := r.coverage("10.0.0.1"); len(c.TCP) != 1 || c.TCP[0] != (model.PortRange{Lo: 1, Hi: 65535}) {
		t.Errorf("after the full range: %+v", c.TCP)
	}
	if c := r.coverage("10.0.0.2"); c.Has("tcp", 8787) {
		t.Error("another host got the full range")
	}
	if (&run{}).coverage("10.0.0.1") != nil {
		t.Error("unknown port list: want nil coverage")
	}
}
