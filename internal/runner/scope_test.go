package runner

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// H1 of the security review: an ad-hoc run (the API, the CLI and the
// re-probe executor) scans only addresses inside an enabled target.
func TestAdHocNeedsAnEnabledTarget(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	scope, err := st.CreateScope(ctx, model.Scope{Name: "Lab"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.AddTargets(ctx, scope.ID, []model.Target{
		{Kind: model.TargetIP, Value: "10.70.0.1", Enabled: true, Addresses: 1},
		{Kind: model.TargetDomain, Value: "app.lab", Enabled: true, Addresses: 1},
		{Kind: model.TargetRange, Value: "10.90.0.10-10.90.0.20", Enabled: true, Addresses: 11},
	}, nil); err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProfile(ctx, model.ScanProfile{Name: "Lab", ScopeIDs: []int64{scope.ID}, Ports: "80", Enabled: true, Rate: model.RateLimits{MaxPPS: 100}})
	if err != nil {
		t.Fatal(err)
	}
	lookups := 0
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		lookups++
		if host == "app.lab" {
			return []netip.Addr{netip.MustParseAddr("10.80.0.5")}, nil
		}
		return nil, errors.New("no such host")
	}
	m := New(st, Options{Engine: newFake(), Lookup: lookup, StopTimeout: 10 * time.Second})
	t.Cleanup(func() { m.Shutdown(context.Background()); m.Wait() })

	kept, err := m.KeepInTargets(ctx, []string{"10.70.0.1", "8.8.8.8", "10.80.0.5", "10.90.0.15", "10.90.0.21"})
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 3 || kept[0] != "10.70.0.1" || kept[1] != "10.80.0.5" || kept[2] != "10.90.0.15" {
		t.Fatalf("kept %v", kept)
	}
	for _, addrs := range [][]string{{"8.8.8.8"}, {"10.70.0.1", "10.70.0.2"}, {"10.90.0.0/24"}} {
		if _, err := m.StartAdHoc(ctx, model.AdHocScope{ProfileID: p.ID, Addresses: addrs, Ports: "80"}, nil, TriggerReprobe); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ad-hoc run on %v: %v, want ErrInvalid", addrs, err)
		}
	}
	lookups = 0
	if _, err := m.StartAdHoc(ctx, model.AdHocScope{ProfileID: p.ID, Addresses: []string{"10.70.0.1"}, Ports: "80"}, nil, TriggerReprobe); err != nil {
		t.Fatalf("ad-hoc run on a target: %v", err)
	}
	if lookups != 0 {
		t.Fatalf("a covered address needs no DNS lookup: %d lookups", lookups)
	}
	m.Wait()
	if _, err := m.StartAdHoc(ctx, model.AdHocScope{ProfileID: p.ID, Addresses: []string{"10.80.0.5"}, Ports: "80"}, nil, TriggerReprobe); err != nil {
		t.Fatalf("ad-hoc run on the address of a domain target: %v", err)
	}
}
