package store

import (
	"testing"

	"github.com/iwosmu/aghpen/internal/probe"
)

// The default profile is top 1000 plus infrastructure ports. Ports that only
// the organisers' single-machine template publishes are not hard-coded: a
// small scope is scanned over the full range (measured: all 31 template
// ports found with the default profile in the dind jury machine).
func TestDefaultPorts(t *testing.T) {
	ps, err := probe.ParsePorts(DefaultPorts)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []int{22, 80, 443, 3001, 5173, 6379, 9200, 27017, 50000} {
		if !ps.Has(p) {
			t.Errorf("port %d is not in the default profile", p)
		}
	}
	for _, p := range []int{2223, 5673, 8474, 8787, 15432, 15673, 21000, 21010} {
		if ps.Has(p) {
			t.Errorf("template port %d is still hard-coded in the default profile", p)
		}
	}
}
