// Package reprobe closes the loop of the availability model: it plans and
// starts short confirmation probes of hosts that stopped answering, so the
// verdict "inactive" or "back" comes in minutes and not at the next full scan,
// and it probes hosts with a daily rhythm at the start of their likely-up hour.
//
// Build is a pure function (the planner). Executor runs it on a timer over a
// small Backend. StoreBackend is the Backend over the Czujka store; it needs
// one capability of the runner, the Starter: a run on an ad-hoc list of
// addresses and ports that goes through the normal engine, sink and analysis
// with trigger "reprobe". See docs/API-time.md.
package reprobe

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/analyze"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/sched"
)

// Trigger is the trigger of the runs that the executor starts.
const Trigger = "reprobe"

// Settings are the operator's choices (PUT /settings/reprobe).
type Settings struct {
	Enabled         bool    `json:"enabled"`
	BudgetPerHour   int     `json:"budget_per_hour"`    // addresses probed per hour, all reprobe runs together
	BackoffMinutes  []int   `json:"backoff_minutes"`    // confirmation probes after the first miss, minutes after it
	LikelyUpRate    float64 `json:"likely_up_rate"`     // an hour counts as "likely up" from this model up-rate
	MaxPortsPerHost int     `json:"max_ports_per_host"` // known open ports probed again, at most
}

// DefaultSettings are used until an operator stores others.
func DefaultSettings() Settings {
	return Settings{Enabled: true, BudgetPerHour: 200, BackoffMinutes: []int{10, 30, 90}, LikelyUpRate: 0.6, MaxPortsPerHost: 32}
}

// Validate checks the settings and fills zero values with the defaults.
func (s *Settings) Validate() error {
	d := DefaultSettings()
	if s.BudgetPerHour == 0 {
		s.BudgetPerHour = d.BudgetPerHour
	}
	if s.BudgetPerHour < 1 || s.BudgetPerHour > 10000 {
		return fmt.Errorf("budget_per_hour must be 1..10000")
	}
	if len(s.BackoffMinutes) == 0 {
		s.BackoffMinutes = d.BackoffMinutes
	}
	if len(s.BackoffMinutes) > 10 {
		return fmt.Errorf("backoff_minutes: at most 10 steps")
	}
	prev := 0
	for _, m := range s.BackoffMinutes {
		if m < 1 || m > 1440 || m <= prev {
			return fmt.Errorf("backoff_minutes: steps must grow and be 1..1440 minutes")
		}
		prev = m
	}
	if s.LikelyUpRate == 0 {
		s.LikelyUpRate = d.LikelyUpRate
	}
	if s.LikelyUpRate < 0.3 || s.LikelyUpRate > 1 {
		return fmt.Errorf("likely_up_rate must be 0.3..1")
	}
	if s.MaxPortsPerHost == 0 {
		s.MaxPortsPerHost = d.MaxPortsPerHost
	}
	if s.MaxPortsPerHost < 1 || s.MaxPortsPerHost > 1000 {
		return fmt.Errorf("max_ports_per_host must be 1..1000")
	}
	return nil
}

// Candidate is a host that does not answer now, with what the planner needs.
type Candidate struct {
	HostID      int64
	IP          string
	Status      model.HostStatus // unstable or expected-offline
	LastUp      *time.Time
	StreakStart time.Time // first miss of the current miss streak
	LastObsAt   time.Time // latest observation of any run
	Ports       []int     // known TCP ports, open or unknown
	Buckets     [168]model.AvailBucket
	Attempts    int        // reprobes recorded since StreakStart
	LastAttempt *time.Time // latest recorded reprobe
	ProfileID   *int64     // profile of the latest run that observed the host
	Windows     []model.Window
	Timezone    string
}

// Input is everything Build needs. Loc is the timezone of the histogram.
type Input struct {
	Now           time.Time
	Settings      Settings
	Policy        model.SafetyPolicy
	Candidates    []Candidate
	UsedLastHour  int // addresses probed by reprobe runs in the last hour
	ActiveReprobe bool
	Loc           *time.Location
}

// Probe kinds.
const (
	KindConfirm  = "confirm"   // after a miss: confirm inactive or back
	KindLikelyUp = "likely-up" // at the start of the next likely-up hour
)

// Probe is one planned confirmation probe.
type Probe struct {
	HostID    int64     `json:"host_id"`
	IP        string    `json:"ip"`
	Ports     []int     `json:"ports"`
	NotBefore time.Time `json:"not_before"`
	Kind      string    `json:"kind"`
	Step      int       `json:"step"`  // confirm: 1-based step
	Steps     int       `json:"steps"` // confirm: number of steps
	Reason    string    `json:"reason"`
	ProfileID *int64    `json:"profile_id"`
}

// Skip is a candidate that gets no probe, with the reason.
type Skip struct {
	HostID int64  `json:"host_id"`
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

// Plan is the answer of GET /reprobe/plan.
type Plan struct {
	GeneratedAt   time.Time `json:"generated_at"`
	Enabled       bool      `json:"enabled"`
	Blocked       string    `json:"blocked"` // why nothing will be probed now (Polish), empty when the plan runs
	Budget        int       `json:"budget_per_hour"`
	UsedLastHour  int       `json:"used_last_hour"`
	DueNow        int       `json:"due_now"`
	ActiveReprobe bool      `json:"active_reprobe"`
	Probes        []Probe   `json:"probes"`
	Skipped       []Skip    `json:"skipped"`
	Settings      Settings  `json:"settings"`
}

const (
	// ConfirmHorizon: a miss streak older than the last backoff step plus this
	// is not confirmed any more; the likely-up rule takes over.
	ConfirmHorizon = 12 * time.Hour
	// MaxPlan bounds the length of a plan.
	MaxPlan = 5000
	// LikelyUpOffset: a likely-up probe starts this long after the hour begins.
	LikelyUpOffset = 5 * time.Minute
)

var dayNames = [7]string{"nd", "pn", "wt", "śr", "cz", "pt", "sb"}

// Build plans the confirmation probes. It is pure: same input, same plan.
func Build(in Input) Plan {
	s := in.Settings
	_ = s.Validate() // fill defaults; an invalid stored value never reaches here
	loc := in.Loc
	if loc == nil {
		loc = time.UTC
	}
	now := in.Now
	plan := Plan{GeneratedAt: now, Enabled: s.Enabled, Budget: s.BudgetPerHour, UsedLastHour: in.UsedLastHour,
		ActiveReprobe: in.ActiveReprobe, Probes: []Probe{}, Skipped: []Skip{}, Settings: s}
	switch {
	case !s.Enabled:
		plan.Blocked = "Ponowne sondowanie jest wyłączone w ustawieniach."
		return plan
	case in.Policy.EmergencyStop:
		plan.Blocked = "Wyłącznik awaryjny jest włączony: Czujka nie wysyła żadnych sond."
		return plan
	}
	excl := parseExclusions(in.Policy.Exclusions)
	steps := s.BackoffMinutes
	lastStep := time.Duration(steps[len(steps)-1]) * time.Minute

	for _, c := range in.Candidates {
		if a, err := netip.ParseAddr(c.IP); err != nil || excluded(a, excl) {
			plan.Skipped = append(plan.Skipped, Skip{c.HostID, c.IP, "Adres jest na liście wykluczeń polityki bezpieczeństwa."})
			continue
		}
		tz := loc
		if c.Timezone != "" {
			if l, err := sched.Location(c.Timezone); err == nil {
				tz = l
			}
		}
		ports := c.Ports
		if len(ports) > s.MaxPortsPerHost {
			ports = ports[:s.MaxPortsPerHost]
		}
		if ports == nil {
			ports = []int{}
		}
		p := Probe{HostID: c.HostID, IP: c.IP, Ports: ports, ProfileID: c.ProfileID}

		confirm := c.Status == model.HostUnstable && c.LastUp != nil && c.Attempts < len(steps) &&
			now.Sub(c.StreakStart) <= lastStep+ConfirmHorizon
		if confirm {
			k := c.Attempts
			at := c.StreakStart.Add(time.Duration(steps[k]) * time.Minute)
			if at.Before(now) {
				at = now
			}
			wAt, ok := sched.NextAllowed(at, c.Windows, tz)
			if !ok {
				plan.Skipped = append(plan.Skipped, Skip{c.HostID, c.IP, "Profil hosta nie ma żadnego otwartego okna skanowania."})
				continue
			}
			p.Kind, p.Step, p.Steps, p.NotBefore = KindConfirm, k+1, len(steps), wAt
			p.Reason = fmt.Sprintf("Host nie odpowiedział w skanie o %s. Potwierdzenie %d z %d, %d min po pierwszym braku: szybki werdykt, czy host wrócił, czy jest nieaktywny.",
				c.StreakStart.In(tz).Format("02.01 15:04"), k+1, len(steps), steps[k])
			if wAt.After(at) {
				p.Reason += fmt.Sprintf(" Przesunięte do okna skanowania (start %s).", wAt.In(tz).Format("02.01 15:04"))
			}
			plan.Probes = append(plan.Probes, p)
			continue
		}

		// Likely-up rule: unstable or expected-offline hosts with a known rhythm.
		n := 0
		for _, b := range c.Buckets {
			n += b.Up + b.Down
		}
		if n < analyze.MinObsForExpected {
			plan.Skipped = append(plan.Skipped, Skip{c.HostID, c.IP, fmt.Sprintf("Za mało obserwacji (%d), żeby znać rytm hosta; czeka na pełny skan.", n)})
			continue
		}
		rates := analyze.UpRates(c.Buckets)
		last := c.LastObsAt
		if c.LastAttempt != nil && c.LastAttempt.After(last) {
			last = *c.LastAttempt
		}
		lt := now.In(loc)
		hour0 := time.Date(lt.Year(), lt.Month(), lt.Day(), lt.Hour(), 0, 0, 0, loc)
		found := false
		for h := 0; h < 168 && !found; h++ {
			start := hour0.Add(time.Duration(h) * time.Hour)
			end := start.Add(time.Hour)
			b := analyze.BucketIndex(start, loc)
			if rates[b] < s.LikelyUpRate || !last.Before(start) || !seenUp(&c.Buckets, b) {
				continue
			}
			at := start.Add(LikelyUpOffset)
			if at.Before(now) {
				at = now
			}
			wAt, ok := sched.NextAllowed(at, c.Windows, tz)
			if !ok || !wAt.Before(end) {
				continue
			}
			ls := start.In(loc)
			p.Kind, p.NotBefore = KindLikelyUp, wAt
			what := "odpowiada nieregularnie"
			if c.Status == model.HostExpectedOffline {
				what = "nie odpowiada zgodnie ze swoim rytmem"
			}
			p.Reason = fmt.Sprintf("Host %s. Zwykle odpowiada w %s %02d:00–%02d:00 (model: %d%%); sonda na początku tej godziny.",
				what, dayNames[ls.Weekday()], ls.Hour(), (ls.Hour()+1)%24, int(rates[b]*100+0.5))
			found = true
		}
		if !found {
			plan.Skipped = append(plan.Skipped, Skip{c.HostID, c.IP, "W najbliższym tygodniu brak godziny, w której host zwykle odpowiada i okno skanowania jest otwarte."})
			continue
		}
		plan.Probes = append(plan.Probes, p)
	}

	sort.SliceStable(plan.Probes, func(i, j int) bool {
		a, b := plan.Probes[i], plan.Probes[j]
		if !a.NotBefore.Equal(b.NotBefore) {
			return a.NotBefore.Before(b.NotBefore)
		}
		if a.Kind != b.Kind {
			return a.Kind == KindConfirm
		}
		return a.IP < b.IP
	})
	applyBudget(&plan, in, loc)
	if len(plan.Probes) > MaxPlan {
		plan.Probes = plan.Probes[:MaxPlan]
	}
	for _, p := range plan.Probes {
		if !p.NotBefore.After(now) {
			plan.DueNow++
		}
	}
	if in.ActiveReprobe && plan.DueNow > 0 {
		plan.Blocked = "Poprzednie sondowanie jeszcze trwa; następne zacznie się po nim."
	}
	return plan
}

// seenUp reports whether the host really answered near this hour on the
// same type of day (weekday or weekend), hour ±1. The model smooths sparse
// data across day types; without this check an office machine seen only on
// weekdays would get a "likely up" probe on Saturday morning.
func seenUp(b *[168]model.AvailBucket, bucket int) bool {
	weekend := func(d int) bool { return d == 0 || d == 6 }
	wd, h := bucket/24, bucket%24
	for d := 0; d < 7; d++ {
		if weekend(d) != weekend(wd) {
			continue
		}
		for dh := -1; dh <= 1; dh++ {
			if b[d*24+(h+dh+24)%24].Up > 0 {
				return true
			}
		}
	}
	return false
}

// applyBudget moves probes to later hours so that no hour, counted from now,
// has more addresses than the budget. The first hour already holds the
// addresses probed in the last hour.
func applyBudget(plan *Plan, in Input, loc *time.Location) {
	budget := plan.Budget
	used := map[int]int{0: in.UsedLastHour}
	cand := map[int64]Candidate{}
	for _, c := range in.Candidates {
		cand[c.HostID] = c
	}
	for i := range plan.Probes {
		p := &plan.Probes[i]
		slot := int(p.NotBefore.Sub(in.Now) / time.Hour)
		if slot < 0 {
			slot = 0
		}
		moved := false
		for tries := 0; tries < 24*14 && used[slot] >= budget; tries++ {
			slot++
			moved = true
		}
		if moved {
			at := in.Now.Add(time.Duration(slot) * time.Hour)
			c := cand[p.HostID]
			tz := loc
			if c.Timezone != "" {
				if l, err := sched.Location(c.Timezone); err == nil {
					tz = l
				}
			}
			if w, ok := sched.NextAllowed(at, c.Windows, tz); ok {
				at = w
				slot = int(at.Sub(in.Now) / time.Hour)
			}
			p.NotBefore = at
			p.Reason += fmt.Sprintf(" Przesunięte na %s: limit %d adresów na godzinę.", at.In(tz).Format("02.01 15:04"), budget)
		}
		used[slot]++
	}
	sort.SliceStable(plan.Probes, func(i, j int) bool { return plan.Probes[i].NotBefore.Before(plan.Probes[j].NotBefore) })
}

// parseExclusions reads the IP and CIDR entries of the policy; domain
// entries cannot match an address and are left to the engine.
func parseExclusions(list []string) []netip.Prefix {
	var out []netip.Prefix
	for _, e := range list {
		e = strings.TrimSpace(e)
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(e); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		} else if lo, hi, ok := strings.Cut(e, "-"); ok {
			a, err1 := netip.ParseAddr(strings.TrimSpace(lo))
			b, err2 := netip.ParseAddr(strings.TrimSpace(hi))
			if err1 == nil && err2 == nil && a.Is4() && b.Is4() {
				for x := a; x.Compare(b) <= 0 && len(out) < 1<<16; x = x.Next() {
					out = append(out, netip.PrefixFrom(x, 32))
				}
			}
		}
	}
	return out
}

func excluded(a netip.Addr, excl []netip.Prefix) bool {
	a = a.Unmap()
	for _, p := range excl {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
