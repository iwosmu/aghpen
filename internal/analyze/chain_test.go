package analyze

import (
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

// hostStates are the values a host change may carry in Before and After:
// aktywny, nie odpowiada (niepotwierdzone), nieaktywny, niestabilny, poza godzinami.
var hostStates = map[string]bool{
	string(model.HostUp): true, StatusMissing: true, string(model.HostDown): true,
	string(model.HostUnstable): true, string(model.HostExpectedOffline): true,
}

// runChain diffs a sequence of host snapshots and returns the host changes.
func runChain(t *testing.T, steps ...HostSnapshot) []model.Change {
	t.Helper()
	var out []model.Change
	for i := 1; i < len(steps); i++ {
		prev := snap(int64(i), steps[i-1])
		cs, _ := Diff(&prev, snap(int64(i+1), steps[i]), DiffOptions{})
		for _, c := range cs {
			if c.Field == "status" {
				out = append(out, c)
			}
		}
	}
	return out
}

// checkChain asserts the kinds, the before → after pairs, that every value is
// a host state and that each change starts where the previous one ended.
func checkChain(t *testing.T, cs []model.Change, want ...string) {
	t.Helper()
	if len(cs) != len(want) {
		t.Fatalf("changes = %v, want %d", kinds(cs), len(want))
	}
	for i, c := range cs {
		b, a := strOf(c.Before), strOf(c.After)
		if got := string(c.Kind) + " " + b + "→" + a; got != want[i] {
			t.Errorf("change %d = %q, want %q (%s)", i, got, want[i], c.Summary)
		}
		if !hostStates[b] || !hostStates[a] {
			t.Errorf("change %d: %q → %q is not a host state", i, b, a)
		}
		if i > 0 && b != strOf(cs[i-1].After) {
			t.Errorf("chain broken: %s ends at %q, %s starts at %q", cs[i-1].Kind, strOf(cs[i-1].After), c.Kind, b)
		}
	}
}

func silent(status model.HostStatus) HostSnapshot {
	return HostSnapshot{HostID: 1, IP: "10.0.0.2", Status: status, Services: []model.ServiceResult{httpSvc(80, "a", 200)}}
}

func TestHostChainMissingThenDown(t *testing.T) {
	cs := runChain(t, host("10.0.0.2", model.HostUp, httpSvc(80, "a", 200)), silent(model.HostUnstable), silent(model.HostDown))
	checkChain(t, cs, "host_missing up→missing", "host_gone missing→down")
	if cs[0].Summary != "Host 10.0.0.2 nie odpowiada (niepotwierdzone), miał 1 otwartą usługę" {
		t.Errorf("summary %q", cs[0].Summary)
	}
}

func TestHostChainMissingThenBack(t *testing.T) {
	cs := runChain(t, host("10.0.0.2", model.HostUp, httpSvc(80, "a", 200)), silent(model.HostUnstable), host("10.0.0.2", model.HostUp, httpSvc(80, "a", 200)))
	checkChain(t, cs, "host_missing up→missing", "host_back missing→up")
}

func TestHostChainDownThenBack(t *testing.T) {
	cs := runChain(t, host("10.0.0.2", model.HostUp, httpSvc(80, "a", 200)), silent(model.HostUnstable), silent(model.HostDown), host("10.0.0.2", model.HostUp))
	checkChain(t, cs, "host_missing up→missing", "host_gone missing→down", "host_back down→up")
	if cs[2].Summary != "Host 10.0.0.2 znów aktywny (był nieaktywny)" {
		t.Errorf("summary %q", cs[2].Summary)
	}
}

func TestHostChainIrregularHost(t *testing.T) {
	flap := func(up bool) HostSnapshot {
		h := HostSnapshot{HostID: 1, IP: "10.0.0.2", Up: up, Status: model.HostUnstable, Stability: 0.5, Observations: 40}
		if up {
			h.Status = model.HostUp
		}
		return h
	}
	cs := runChain(t, flap(true), flap(false), flap(true))
	checkChain(t, cs, "host_unstable up→unstable", "host_back unstable→up")
}

func TestHostChainOutsideUsualHours(t *testing.T) {
	off := silent(model.HostExpectedOffline)
	off.Pattern = "zwykle aktywny pn–pt 08–16"
	cs := runChain(t, host("10.0.0.2", model.HostUp), off, host("10.0.0.2", model.HostUp))
	checkChain(t, cs, "host_gone up→expected-offline", "host_back expected-offline→up")
}

func TestHostChainSilentAfterExpectedOffline(t *testing.T) {
	cs := runChain(t, host("10.0.0.2", model.HostUp), silent(model.HostExpectedOffline), silent(model.HostUnstable), silent(model.HostDown))
	checkChain(t, cs, "host_gone up→expected-offline", "host_unstable expected-offline→missing", "host_gone missing→down")
}
