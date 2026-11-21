package sigwire_test

import (
	"context"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// M1 of the security review: retro-hunt must not be an oracle for cookie
// values. A caller without results:update (cookieValues false) gets cookie
// rules matched on names and flags only, so probing ^a, ^ab, ... learns nothing.
func TestRetroHuntIsNoCookieValueOracle(t *testing.T) {
	ctx := context.Background()
	w, st, _ := newWire(t)
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	run, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunRunning, ProfileName: "noc"})
	if err != nil {
		t.Fatal(err)
	}
	svc := webSvc(80, "Portal", "<p>x</p>", "nginx/1.24.0") // cookie PHPSESSID=secret-session-value
	ingest(t, st, []model.HostResult{{RunID: run.ID, IP: "10.20.0.9", Up: true, ObservedAt: time.Now().UTC(), Services: []model.ServiceResult{svc}}})

	probe := func(prefix string, cookieValues bool) int {
		t.Helper()
		y := "id: probe\nname: Probe\nmatch:\n  rules:\n    - {type: cookie, name: PHPSESSID, regex: '^" + prefix + "', weight: 0.9}\n"
		res, err := w.RetroHunt(ctx, y, false, cookieValues)
		if err != nil {
			t.Fatal(err)
		}
		return res.TotalHits
	}
	// The attack: guess the value one character at a time.
	for _, prefix := range []string{"s", "se", "sec", "secret-"} {
		if n := probe(prefix, false); n != 0 {
			t.Fatalf("prefix %q matched a hidden cookie value (%d hits): retro-hunt is an oracle", prefix, n)
		}
	}
	// With results:update the caller sees values anyway: matching works.
	if n := probe("secret-", true); n != 1 {
		t.Fatalf("with cookie values the rule must match: %d", n)
	}
	// A rule on the name and flags still works without values.
	y := "id: name-only\nname: Sesja PHP\nmatch:\n  rules:\n    - {type: cookie, name: PHPSESSID, weight: 0.9}\n"
	if res, err := w.RetroHunt(ctx, y, false, false); err != nil || res.TotalHits != 1 {
		t.Fatalf("a cookie name rule without values: %+v %v", res, err)
	}
}
