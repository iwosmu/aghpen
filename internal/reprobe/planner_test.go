package reprobe

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/analyze"
	"github.com/iwosmu/aghpen/internal/model"
)

var waw, _ = time.LoadLocation("Europe/Warsaw")

// 2026-11-17 is a Tuesday.
func at(day, hh, mm int) time.Time { return time.Date(2026, 11, day, hh, mm, 0, 0, waw) }

func ptr[T any](v T) *T { return &v }

// alwaysUp is the histogram of a server that answered every scan.
func alwaysUp() (b [168]model.AvailBucket) {
	for i := range b {
		b[i].Up = 2
	}
	return b
}

// officeHours: up Monday to Friday 08:00-16:00, silent otherwise.
func officeHours() (b [168]model.AvailBucket) {
	for i := range b {
		wd, h := i/24, i%24
		if wd >= 1 && wd <= 5 && h >= 8 && h < 16 {
			b[i].Up = 4
		} else {
			b[i].Down = 4
		}
	}
	return b
}

func missingServer(ip string, streak time.Time, attempts int) Candidate {
	up := streak.Add(-24 * time.Hour)
	return Candidate{HostID: int64(len(ip)), IP: ip, Status: model.HostUnstable, LastUp: &up, StreakStart: streak, LastObsAt: streak,
		Ports: []int{22, 80, 443}, Buckets: alwaysUp(), Attempts: attempts}
}

func workstation(ip string, lastObs time.Time) Candidate {
	up := lastObs.Add(-12 * time.Hour)
	return Candidate{HostID: 99, IP: ip, Status: model.HostExpectedOffline, LastUp: &up, StreakStart: lastObs, LastObsAt: lastObs,
		Ports: []int{3389}, Buckets: officeHours()}
}

func TestBuildScenarios(t *testing.T) {
	def := DefaultSettings()
	type want struct {
		probes    int
		notBefore time.Time
		kind      string
		step      int
		reason    []string // substrings of the first probe's reason
		blocked   string
		skipped   string
		due       int
	}
	cases := []struct {
		name string
		in   Input
		want want
	}{
		{"missing server: first confirmation 10 min after the miss",
			Input{Now: at(17, 2, 6), Candidates: []Candidate{missingServer("10.66.3.17", at(17, 2, 5), 0)}},
			want{probes: 1, notBefore: at(17, 2, 15), kind: KindConfirm, step: 1, reason: []string{"Potwierdzenie 1 z 3, 10 min", "17.11 02:05"}}},
		{"missing server: second confirmation 30 min after the miss",
			Input{Now: at(17, 2, 16), Candidates: []Candidate{missingServer("10.66.3.17", at(17, 2, 5), 1)}},
			want{probes: 1, notBefore: at(17, 2, 35), kind: KindConfirm, step: 2}},
		{"overdue confirmation is due now",
			Input{Now: at(17, 2, 15), Candidates: []Candidate{missingServer("10.66.3.17", at(17, 1, 0), 0)}},
			want{probes: 1, notBefore: at(17, 2, 15), kind: KindConfirm, step: 1, due: 1}},
		{"steps exhausted: probe at the next likely-up hour",
			Input{Now: at(17, 3, 40), Candidates: []Candidate{func() Candidate {
				c := missingServer("10.66.3.17", at(17, 2, 5), 3)
				c.LastAttempt = ptr(at(17, 3, 35))
				return c
			}()}},
			want{probes: 1, notBefore: at(17, 4, 5), kind: KindLikelyUp, reason: []string{"odpowiada nieregularnie", "wt 04:00–05:00"}}},
		{"old miss streak is not confirmed any more",
			Input{Now: at(17, 2, 10), Candidates: []Candidate{missingServer("10.66.3.17", at(15, 2, 5), 0)}},
			want{probes: 1, notBefore: at(17, 2, 10), kind: KindLikelyUp, due: 1}},
		{"expected-offline workstation at night: probe at 08:05",
			Input{Now: at(17, 2, 15), Candidates: []Candidate{workstation("10.66.20.5", at(17, 2, 5))}},
			want{probes: 1, notBefore: at(17, 8, 5), kind: KindLikelyUp, reason: []string{"zgodnie ze swoim rytmem", "wt 08:00–09:00"}}},
		{"workstation on Saturday waits for Monday",
			Input{Now: at(21, 10, 0), Candidates: []Candidate{workstation("10.66.20.5", at(21, 2, 5))}},
			want{probes: 1, notBefore: at(23, 8, 5), kind: KindLikelyUp, reason: []string{"pn 08:00–09:00"}}},
		{"office machine seen only at 10:00 on weekdays: no Saturday probe, Monday 09:05",
			Input{Now: at(21, 2, 15), Candidates: []Candidate{func() Candidate {
				c := workstation("10.66.20.5", at(21, 2, 5))
				c.Buckets = [168]model.AvailBucket{}
				for d := 0; d < 7; d++ {
					c.Buckets[d*24+2] = model.AvailBucket{Down: 2}
					if d >= 1 && d <= 5 {
						c.Buckets[d*24+10] = model.AvailBucket{Up: 2}
					}
				}
				return c
			}()}},
			want{probes: 1, notBefore: at(23, 9, 5), kind: KindLikelyUp, reason: []string{"pn 09:00–10:00"}}},
		{"likely-up hour starts before the window: probe at the window start",
			Input{Now: at(17, 2, 15), Candidates: []Candidate{func() Candidate {
				c := workstation("10.66.20.5", at(17, 2, 5))
				c.Windows = []model.Window{{Days: []int{1, 2, 3, 4, 5}, Start: "12:30", End: "14:00"}}
				c.Timezone = "Europe/Warsaw"
				return c
			}()}},
			want{probes: 1, notBefore: at(17, 12, 30), kind: KindLikelyUp}},
		{"confirmation outside the window moves to the window start",
			Input{Now: at(17, 2, 6), Candidates: []Candidate{func() Candidate {
				c := missingServer("10.66.3.17", at(17, 2, 5), 0)
				c.Windows = []model.Window{{Start: "03:00", End: "05:00"}}
				return c
			}()}},
			want{probes: 1, notBefore: at(17, 3, 0), kind: KindConfirm, reason: []string{"Przesunięte do okna skanowania (start 17.11 03:00)"}}},
		{"no likely-up hour inside any window: skipped",
			Input{Now: at(17, 2, 15), Candidates: []Candidate{func() Candidate {
				c := workstation("10.66.20.5", at(17, 2, 5))
				c.Windows = []model.Window{{Start: "22:00", End: "06:00"}}
				return c
			}()}},
			want{probes: 0, skipped: "brak godziny"}},
		{"excluded address is never probed",
			Input{Now: at(17, 2, 6), Policy: model.SafetyPolicy{Exclusions: []string{"10.66.3.0/24", "example.org"}},
				Candidates: []Candidate{missingServer("10.66.3.17", at(17, 2, 5), 0)}},
			want{probes: 0, skipped: "wykluczeń"}},
		{"excluded by a range entry",
			Input{Now: at(17, 2, 6), Policy: model.SafetyPolicy{Exclusions: []string{"10.66.3.10-10.66.3.20"}},
				Candidates: []Candidate{missingServer("10.66.3.17", at(17, 2, 5), 0)}},
			want{probes: 0, skipped: "wykluczeń"}},
		{"emergency stop blocks every probe",
			Input{Now: at(17, 2, 20), Policy: model.SafetyPolicy{EmergencyStop: true}, Candidates: []Candidate{missingServer("10.66.3.17", at(17, 2, 5), 0)}},
			want{probes: 0, blocked: "awaryjny"}},
		{"disabled in the settings",
			Input{Now: at(17, 2, 20), Settings: Settings{Enabled: false}, Candidates: []Candidate{missingServer("10.66.3.17", at(17, 2, 5), 0)}},
			want{probes: 0, blocked: "wyłączone"}},
		{"too few observations for a rhythm: skipped",
			Input{Now: at(17, 2, 15), Candidates: []Candidate{func() Candidate {
				c := workstation("10.66.20.5", at(17, 2, 5))
				c.Buckets = [168]model.AvailBucket{}
				c.Buckets[analyze.BucketIndex(at(16, 10, 0), waw)] = model.AvailBucket{Up: 3}
				return c
			}()}},
			want{probes: 0, skipped: "Za mało obserwacji (3)"}},
		{"previous reprobe run still active: plan shown, start blocked",
			Input{Now: at(17, 2, 20), ActiveReprobe: true, Candidates: []Candidate{missingServer("10.66.3.17", at(17, 2, 5), 0)}},
			want{probes: 1, notBefore: at(17, 2, 20), kind: KindConfirm, due: 1, blocked: "trwa"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.in.Settings.BudgetPerHour == 0 && !strings.Contains(c.name, "disabled") {
				c.in.Settings = def
			}
			c.in.Loc = waw
			p := Build(c.in)
			if len(p.Probes) != c.want.probes {
				t.Fatalf("probes = %d, want %d: %+v skipped %+v", len(p.Probes), c.want.probes, p.Probes, p.Skipped)
			}
			if c.want.blocked != "" && !strings.Contains(p.Blocked, c.want.blocked) {
				t.Errorf("blocked = %q, want %q", p.Blocked, c.want.blocked)
			}
			if c.want.blocked == "" && p.Blocked != "" {
				t.Errorf("unexpected block %q", p.Blocked)
			}
			if c.want.skipped != "" && (len(p.Skipped) != 1 || !strings.Contains(p.Skipped[0].Reason, c.want.skipped)) {
				t.Errorf("skipped = %+v, want %q", p.Skipped, c.want.skipped)
			}
			if p.DueNow != c.want.due {
				t.Errorf("due now = %d, want %d", p.DueNow, c.want.due)
			}
			if c.want.probes == 0 {
				return
			}
			got := p.Probes[0]
			if !got.NotBefore.Equal(c.want.notBefore) {
				t.Errorf("not before = %s, want %s", got.NotBefore.In(waw), c.want.notBefore)
			}
			if got.Kind != c.want.kind || (c.want.step != 0 && got.Step != c.want.step) {
				t.Errorf("kind %s step %d, want %s %d", got.Kind, got.Step, c.want.kind, c.want.step)
			}
			for _, s := range c.want.reason {
				if !strings.Contains(got.Reason, s) {
					t.Errorf("reason %q lacks %q", got.Reason, s)
				}
			}
			t.Logf("%s -> %s %s: %s", c.name, got.Kind, got.NotBefore.In(waw).Format("Mon 02.01 15:04"), got.Reason)
		})
	}
}

func TestBuildBudget(t *testing.T) {
	s := DefaultSettings()
	s.BudgetPerHour = 2
	now := at(17, 2, 20)
	in := Input{Now: now, Loc: waw, Settings: s, Candidates: []Candidate{
		missingServer("10.66.3.1", at(17, 2, 5), 0), missingServer("10.66.3.22", at(17, 2, 5), 0), missingServer("10.66.3.133", at(17, 2, 5), 0),
	}}
	for i := range in.Candidates {
		in.Candidates[i].HostID = int64(i + 1)
	}
	p := Build(in)
	if len(p.Probes) != 3 || p.DueNow != 2 {
		t.Fatalf("probes %d due %d: %+v", len(p.Probes), p.DueNow, p.Probes)
	}
	last := p.Probes[2]
	if !last.NotBefore.Equal(now.Add(time.Hour)) || !strings.Contains(last.Reason, "limit 2 adresów na godzinę") {
		t.Errorf("third probe: %s %q", last.NotBefore.In(waw), last.Reason)
	}

	// Addresses probed in the last hour count against the first hour.
	in.UsedLastHour = 2
	in.Candidates = in.Candidates[:1]
	p = Build(in)
	if p.DueNow != 0 || !p.Probes[0].NotBefore.Equal(now.Add(time.Hour)) {
		t.Errorf("used budget: due %d, at %s", p.DueNow, p.Probes[0].NotBefore.In(waw))
	}
}

func TestBuildCapsPorts(t *testing.T) {
	s := DefaultSettings()
	s.MaxPortsPerHost = 2
	p := Build(Input{Now: at(17, 2, 6), Loc: waw, Settings: s, Candidates: []Candidate{missingServer("10.66.3.17", at(17, 2, 5), 0)}})
	if len(p.Probes) != 1 || len(p.Probes[0].Ports) != 2 {
		t.Fatalf("%+v", p.Probes)
	}
}

func TestSettingsValidate(t *testing.T) {
	s := Settings{Enabled: true}
	if err := s.Validate(); err != nil || s.BudgetPerHour != 200 || len(s.BackoffMinutes) != 3 {
		t.Fatalf("defaults: %+v %v", s, err)
	}
	for _, bad := range []Settings{{BudgetPerHour: -1}, {BackoffMinutes: []int{30, 10}}, {BackoffMinutes: []int{0}}, {LikelyUpRate: 2}, {MaxPortsPerHost: 5000}} {
		if err := bad.Validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// fakeBackend records what the executor does.
type fakeBackend struct {
	in       Input
	started  []Request
	recorded [][]Probe
	failNext bool
}

func (f *fakeBackend) Snapshot(context.Context, time.Time) (Input, error) { return f.in, nil }
func (f *fakeBackend) Start(_ context.Context, r Request) (model.ScanRun, error) {
	if f.failNext {
		f.failNext = false
		return model.ScanRun{}, errors.New("busy")
	}
	f.started = append(f.started, r)
	return model.ScanRun{ID: int64(100 + len(f.started)), Trigger: r.Trigger}, nil
}
func (f *fakeBackend) Record(_ context.Context, _ model.ScanRun, p []Probe, _ time.Time) error {
	f.recorded = append(f.recorded, p)
	return nil
}

func TestExecutorStartsDueProbesPerProfile(t *testing.T) {
	now := at(17, 2, 20)
	a, b, c := missingServer("10.66.3.1", at(17, 2, 5), 0), missingServer("10.66.3.2", at(17, 2, 5), 0), missingServer("10.66.3.3", at(17, 2, 15), 0)
	a.HostID, b.HostID, c.HostID = 1, 2, 3
	a.ProfileID, b.ProfileID = ptr(int64(7)), ptr(int64(8))
	fb := &fakeBackend{in: Input{Now: now, Loc: waw, Settings: DefaultSettings(), Candidates: []Candidate{a, b, c}}}
	e := &Executor{B: fb}
	rep, err := e.Step(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	// a and b are due (02:15); c is not (02:25). One run per profile.
	if len(fb.started) != 2 || rep.Probed != 2 || len(fb.recorded) != 2 {
		t.Fatalf("started %+v recorded %d", fb.started, len(fb.recorded))
	}
	for _, r := range fb.started {
		if r.Trigger != Trigger || len(r.Targets) != 1 || len(r.Targets[0].Ports) != 3 || !strings.Contains(r.Reason, "1 potwierdzenie braku") {
			t.Errorf("request %+v", r)
		}
	}

	// Blocked: nothing starts.
	fb.started, fb.recorded = nil, nil
	fb.in.Policy.EmergencyStop = true
	if _, err := e.Step(context.Background(), now); err != nil || len(fb.started) != 0 {
		t.Fatalf("emergency stop: started %d", len(fb.started))
	}
	fb.in.Policy.EmergencyStop = false
	fb.in.ActiveReprobe = true
	if _, err := e.Step(context.Background(), now); err != nil || len(fb.started) != 0 {
		t.Fatalf("active reprobe: started %d", len(fb.started))
	}

	// A failed start records nothing.
	fb.in.ActiveReprobe = false
	fb.in.Candidates = []Candidate{a}
	fb.failNext = true
	rep, _ = e.Step(context.Background(), now)
	if len(fb.recorded) != 0 || len(rep.Errors) != 1 {
		t.Fatalf("failed start: recorded %d errors %v", len(fb.recorded), rep.Errors)
	}
}
