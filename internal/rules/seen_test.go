package rules

import (
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// A rule finding carries the time its subject was observed, not the time of
// the evaluation: re-evaluating unchanged data never looks like a new observation.
func TestViolationFindingUsesObservationTime(t *testing.T) {
	now := time.Date(2026, 11, 21, 15, 0, 0, 0, time.UTC)
	seen := now.Add(-3 * time.Hour)
	r := &Rule{ID: "db-port", Name: "Port bazy", Severity: model.SevHigh, Match: allCond{}}
	f := Violation{Key: "policy-violation|db-port|10.0.0.1|3306/tcp", IP: "10.0.0.1", Port: 3306, SeenAt: seen}.Finding(r, 0, now)
	if !f.LastSeen.Equal(seen) || !f.FirstSeen.Equal(seen) {
		t.Fatalf("last_seen %v, want the observation time %v", f.LastSeen, seen)
	}
	if f2 := (Violation{Key: "k", IP: "10.0.0.1"}).Finding(r, 0, now); !f2.LastSeen.Equal(now) {
		t.Fatalf("no observation time (scope level): %v, want now", f2.LastSeen)
	}
	up := now.Add(-time.Hour)
	if got := hostSeen(model.Host{LastSeen: now, LastUp: &up}); !got.Equal(up) {
		t.Fatalf("host seen = %v, want last_up", got)
	}
}
