package store

import (
	"testing"

	"github.com/iwosmu/aghpen/internal/probe"
)

// The default profile, which "Ten komputer" copies, must cover the ports the
// organisers' single-machine template publishes outside nmap's top 1000.
func TestDefaultPortsCoverSingleMachineTemplate(t *testing.T) {
	ps, err := probe.ParsePorts(DefaultPorts)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []int{2223, 3001, 5673, 6379, 8474, 8787, 15432, 15673, 21000, 21010} {
		if !ps.Has(p) {
			t.Errorf("port %d is not in the default profile", p)
		}
	}
}
