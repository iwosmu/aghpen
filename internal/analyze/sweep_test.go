package analyze

import (
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// sweepTimes: every 5 minutes over 8 days (every hour boundary, midnight,
// Saturday to Sunday, Sunday to Monday), over both DST change days of
// Europe/Warsaw and across the year boundary.
func sweepTimes() []time.Time {
	var out []time.Time
	add := func(from time.Time, d time.Duration) {
		for t := from; t.Before(from.Add(d)); t = t.Add(5 * time.Minute) {
			out = append(out, t)
		}
	}
	add(time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC), 8*24*time.Hour)
	add(time.Date(2026, 3, 28, 20, 0, 0, 0, time.UTC), 12*time.Hour)
	add(time.Date(2026, 10, 24, 20, 0, 0, 0, time.UTC), 12*time.Hour)
	add(time.Date(2026, 12, 31, 20, 0, 0, 0, time.UTC), 8*time.Hour)
	return out
}

func obs(at time.Time, up bool) model.HostObservation {
	return model.HostObservation{At: at, Up: up}
}

// sameLocal is t at the same Warsaw wall-clock time d days earlier: a
// schedule follows local time, also across a DST change.
func sameLocal(t time.Time, d int, loc *time.Location) time.Time {
	return t.In(loc).AddDate(0, 0, -d)
}

// The scenario of TestVanishedHostInTwoScans (internal/wire) at every time
// of the sweep: the host answers at now-10min, misses at now-1min, and the
// confirmation probe at now misses too. The verdict must not depend on the
// clock: a young host (seen once) and a mature host that is usually up at
// this hour are unstable after the miss ("nie odpowiada (niepotwierdzone)")
// and inactive after the confirmation; a mature host that is usually off at
// this hour stays expected-offline (quiet) after both.
func TestYoungHostVerdictAtEveryTime(t *testing.T) {
	waw, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Fatal(err)
	}
	type step struct{ miss, confirm model.HostStatus }
	cases := []struct {
		name    string
		history func(now time.Time) []model.HostObservation // before the scenario, at the same Warsaw times on the 14 previous days
		lastUp  time.Duration                               // the last answer, before now
		want    step
	}{
		{"young, seen once", func(time.Time) []model.HostObservation { return nil }, 10 * time.Minute,
			step{model.HostUnstable, model.HostDown}},
		{"mature, usually up at this hour", func(now time.Time) []model.HostObservation {
			var h []model.HostObservation
			for d := 14; d >= 1; d-- {
				h = append(h, obs(sameLocal(now.Add(-10*time.Minute), d, waw), true), obs(sameLocal(now.Add(-time.Minute), d, waw), true), obs(sameLocal(now, d, waw), true))
			}
			return h
		}, 10 * time.Minute, step{model.HostUnstable, model.HostDown}},
		{"mature, usually off at this hour", func(now time.Time) []model.HostObservation {
			var h []model.HostObservation
			for d := 14; d >= 1; d-- {
				h = append(h, obs(sameLocal(now.Add(-3*time.Hour), d, waw), true), obs(sameLocal(now.Add(-time.Minute), d, waw), false), obs(sameLocal(now, d, waw), false))
			}
			return h
		}, 3 * time.Hour, step{model.HostExpectedOffline, model.HostExpectedOffline}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bad := 0
			for _, now := range sweepTimes() {
				var p Profile
				for _, o := range c.history(now) {
					p.Add(o, waw)
				}
				p.Add(obs(now.Add(-c.lastUp), true), waw)
				p.Add(obs(now.Add(-time.Minute), false), waw)
				miss := Assess(p, waw)
				p.Add(obs(now, false), waw)
				conf := Assess(p, waw)
				if miss.Status != c.want.miss || conf.Status != c.want.confirm {
					if bad++; bad <= 10 {
						t.Errorf("now %s (%s Warsaw): miss %s (p %.3f), confirmation %s (p %.3f); want %s, %s",
							now.Format(time.RFC3339), now.In(waw).Format("Mon 15:04"), miss.Status, miss.PAlive, conf.Status, conf.PAlive, c.want.miss, c.want.confirm)
					}
				}
			}
			if bad > 0 {
				t.Errorf("%d of %d times wrong", bad, len(sweepTimes()))
			}
		})
	}
}
