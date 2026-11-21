package analyze

import (
	"math"
	"sort"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Constants of the availability model (docs/ARCHITECTURE.md §4.3).
// They are the answer to "after how long do we report a host inactive?".
const (
	// BetaPriorA and BetaPriorB are the Beta(a, b) prior of an up-rate.
	// a = b = 1 is the uniform prior: with no data the up-rate is 0.5.
	BetaPriorA = 1.0
	BetaPriorB = 1.0

	// ShrinkStrength is the weight (in pseudo-observations) with which a fine
	// level is pulled to the coarser one. The levels are: global rate,
	// hour-of-day, hour-of-day by day type (working day or weekend),
	// hour-of-week. One scan a day fills one hour-of-week bucket a week, so a
	// bucket alone knows too little for many weeks.
	ShrinkStrength = 2.0

	// CellShrinkStrength is the same weight for the finest level, the
	// hour-of-week cell. A cell has few observations (four after a month of
	// daily scans), so chance alone often fills it with answers only. The
	// stronger pull stops a host that answers at random from looking as if
	// it had a schedule.
	CellShrinkStrength = 4.0

	// NeighbourWeight is the weight of the two neighbouring hours in the
	// hour-of-day rate. Scans do not start at the same minute every day.
	NeighbourWeight = 0.5

	// TransientMissRate is the chance that a live, normally answering host
	// misses one run anyway (reboot, packet loss that survived the in-run
	// retries, short maintenance). It is the floor of P(miss | alive): one
	// miss alone never reports a host inactive. With a short history the
	// rate is not known yet, so the model uses max(TransientMissRate,
	// 1/(n+2)) where n is the number of observations before the streak.
	TransientMissRate = 0.10

	// PriorBase and PriorGain build the prior P(alive) at the first miss:
	// p0 = PriorBase + PriorGain * n_up / (n_up + PriorHalfLife).
	// A host seen once starts at 0.58, a host seen in 30 runs at 0.77, and
	// no host starts above 0.80. The prior is the belief after a miss that
	// already survived the in-run retries, so it is well below 1.
	PriorBase     = 0.5
	PriorGain     = 0.3
	PriorHalfLife = 3.0

	// DownThreshold: p_alive under this value reports the host inactive.
	DownThreshold = 0.2

	// ExpectedOfflineUpRate: a miss in an hour whose up-rate is under this
	// value is explained by the profile ("the host is usually off now").
	ExpectedOfflineUpRate = 0.25

	// MinObsForExpected is the number of observations a profile needs before
	// it may explain a miss. Younger profiles cannot say "usually off".
	MinObsForExpected = 8

	// DownAfterHorizon caps the look-ahead of DownAfterMisses.
	DownAfterHorizon = 60

	// RecentCap is the number of observations Profile keeps in Recent.
	RecentCap = 200

	// DefaultScanInterval is used when the history does not show a cadence.
	DefaultScanInterval = 24 * time.Hour
)

// Profile is the persisted availability state of one host: the hour-of-week
// histogram and the latest observations (oldest first).
type Profile struct {
	Buckets [168]model.AvailBucket
	Recent  []model.HostObservation
}

// BucketIndex returns weekday*24 + hour of t in loc (weekday 0 = Sunday).
// Under a non-default clock (see Clock) it returns (unix time mod period) /
// width, and loc does not matter.
func BucketIndex(t time.Time, loc *time.Location) int {
	if !clock.IsDefault() {
		return clock.index(t)
	}
	if loc == nil {
		loc = time.UTC
	}
	lt := t.In(loc)
	return int(lt.Weekday())*24 + lt.Hour()
}

// Add records one observation: it updates the histogram bucket of the hour
// (in loc) and appends to Recent, which is kept sorted by time and capped.
// A second observation of a run already in Recent (a chunk scanned again
// after a resume) is merged into the first one: the run counts once, and it
// counts as "up" when either observation answered.
func (p *Profile) Add(obs model.HostObservation, loc *time.Location) {
	if obs.RunID != 0 {
		for k := range p.Recent {
			if p.Recent[k].RunID != obs.RunID {
				continue
			}
			old := p.Recent[k]
			merged := mergeObs(old, obs)
			p.uncount(old, loc)
			p.count(merged, loc)
			p.Recent[k] = merged
			sort.SliceStable(p.Recent, func(a, b int) bool { return p.Recent[a].At.Before(p.Recent[b].At) })
			return
		}
	}
	p.count(obs, loc)
	p.Recent = append(p.Recent, obs)
	if n := len(p.Recent); n > 1 && p.Recent[n-1].At.Before(p.Recent[n-2].At) {
		sort.SliceStable(p.Recent, func(a, b int) bool { return p.Recent[a].At.Before(p.Recent[b].At) })
	}
	if len(p.Recent) > RecentCap {
		p.Recent = append([]model.HostObservation(nil), p.Recent[len(p.Recent)-RecentCap:]...)
	}
}

func (p *Profile) count(obs model.HostObservation, loc *time.Location) {
	i := BucketIndex(obs.At, loc)
	if obs.Up {
		p.Buckets[i].Up++
	} else {
		p.Buckets[i].Down++
	}
}

func (p *Profile) uncount(obs model.HostObservation, loc *time.Location) {
	i := BucketIndex(obs.At, loc)
	if obs.Up && p.Buckets[i].Up > 0 {
		p.Buckets[i].Up--
	} else if !obs.Up && p.Buckets[i].Down > 0 {
		p.Buckets[i].Down--
	}
}

// mergeObs joins two observations of one run. The answer wins: a host that
// answered once in the run was alive in that run.
func mergeObs(a, b model.HostObservation) model.HostObservation {
	keep := a
	switch {
	case b.Up && !a.Up:
		keep = b
	case a.Up == b.Up && b.At.After(a.At):
		keep = b
	}
	keep.Attempts = max(a.Attempts, b.Attempts)
	return keep
}

// NormalizeProfile returns p with one observation per run id. The store may
// hold two observations of one run when the engine reported the host twice
// (a chunk scanned again after a resume); the histogram then counted the run
// twice. NormalizeProfile merges them as Add does and removes the extra
// counts from the histogram. Observations with run id 0 stay as they are.
func NormalizeProfile(p Profile, loc *time.Location) Profile {
	seen := make(map[int64]bool, len(p.Recent))
	dup := false
	for _, o := range p.Recent {
		if o.RunID == 0 {
			continue
		}
		if seen[o.RunID] {
			dup = true
			break
		}
		seen[o.RunID] = true
	}
	if !dup {
		return p
	}
	out := Profile{Buckets: p.Buckets, Recent: make([]model.HostObservation, 0, len(p.Recent))}
	idx := make(map[int64]int, len(p.Recent))
	for _, o := range p.Recent {
		k, ok := idx[o.RunID]
		if o.RunID == 0 || !ok {
			if o.RunID != 0 {
				idx[o.RunID] = len(out.Recent)
			}
			out.Recent = append(out.Recent, o)
			continue
		}
		old := out.Recent[k]
		merged := mergeObs(old, o)
		out.uncount(old, loc)
		out.uncount(o, loc)
		out.count(merged, loc)
		out.Recent[k] = merged
	}
	sort.SliceStable(out.Recent, func(a, b int) bool { return out.Recent[a].At.Before(out.Recent[b].At) })
	return out
}

// MissStep explains one miss of the current miss streak. The UI and the
// documentation show these numbers.
type MissStep struct {
	At          time.Time `json:"at"`
	Bucket      int       `json:"bucket"`
	UpRate      float64   `json:"up_rate"`       // model up-rate of that hour before the streak
	MissGivenUp float64   `json:"miss_given_up"` // P(miss | host alive)
	PAlive      float64   `json:"p_alive"`       // posterior after this miss
	Explained   bool      `json:"explained"`     // the profile says the host is usually off at this hour
}

// Assessment is the result of the model for one host at its latest observation.
type Assessment struct {
	Status            model.HostStatus
	PAlive            float64
	Prior             float64 // p0 used for the current miss streak
	Stability         float64 // share of all observations in which the host answered
	ConsecutiveMisses int
	DownAfterMisses   int // more misses in a row, at the usual scan times, until "down"; 0 when already down
	Pattern           string
	Expected          bool // the current absence is explained by the profile
	// Rule is the per-profile DownAfterMisses rule in force, 0 when the
	// model decides.
	Rule  int
	Steps []MissStep
}

// AssessOptions are the per-profile inputs of the model.
type AssessOptions struct {
	// DownAfterMisses is model.RetryOpts.DownAfterMisses. 0: the model
	// decides when a host is inactive. N > 0: the host is inactive after N
	// misses in a row and not before, whatever p_alive and the profile say.
	DownAfterMisses int
}

// OptionsFor returns the model inputs of a scan profile.
func OptionsFor(p model.ScanProfile) AssessOptions {
	return AssessOptions{DownAfterMisses: max(p.Retry.DownAfterMisses, 0)}
}

// rates holds the three levels of up-rate estimates built from a histogram.
type rates struct {
	global float64
	hod    [24]float64
	how    [168]float64
	nUp    int
	nAll   int
}

// buildRates computes the shrunk up-rates:
//
//	global    = (U + a) / (N + a + b)              Beta(1,1) prior
//	hod[h]    = (U_h + m*global) / (N_h + m)       U_h, N_h include the two neighbour hours at half weight
//	hdt[k][h] = (U_kh + m*hod[h]) / (N_kh + m)     k = working day or weekend
//	how[i]    = (U_i + c*hdt[k(i)][i%24]) / (N_i + c)      c = CellShrinkStrength
func buildRates(b *[168]model.AvailBucket) rates {
	if !clock.IsDefault() {
		return buildFlatRates(b, clock.Buckets())
	}
	var r rates
	var hodUp, hodAll [24]float64
	var dtUp, dtAll [2][24]float64
	for i := range b {
		up, down := b[i].Up, b[i].Down
		if up < 0 {
			up = 0
		}
		if down < 0 {
			down = 0
		}
		r.nUp += up
		r.nAll += up + down
		hodUp[i%24] += float64(up)
		hodAll[i%24] += float64(up + down)
		dtUp[dayType(i/24)][i%24] += float64(up)
		dtAll[dayType(i/24)][i%24] += float64(up + down)
	}
	r.global = (float64(r.nUp) + BetaPriorA) / (float64(r.nAll) + BetaPriorA + BetaPriorB)
	for h := 0; h < 24; h++ {
		prev, next := (h+23)%24, (h+1)%24
		u := hodUp[h] + NeighbourWeight*(hodUp[prev]+hodUp[next])
		n := hodAll[h] + NeighbourWeight*(hodAll[prev]+hodAll[next])
		r.hod[h] = (u + ShrinkStrength*r.global) / (n + ShrinkStrength)
	}
	for i := range b {
		u := float64(max(b[i].Up, 0))
		n := float64(max(b[i].Up, 0) + max(b[i].Down, 0))
		k, h := dayType(i/24), i%24
		hdt := (dtUp[k][h] + ShrinkStrength*r.hod[h]) / (dtAll[k][h] + ShrinkStrength)
		r.how[i] = (u + CellShrinkStrength*hdt) / (n + CellShrinkStrength)
	}
	return r
}

// buildFlatRates is buildRates for a non-default clock: the first n buckets
// are one cycle, and each one shrinks straight to the global rate.
//
//	how[i] = (U_i + c*global) / (N_i + c)      c = CellShrinkStrength
func buildFlatRates(b *[168]model.AvailBucket, n int) rates {
	var r rates
	for i := 0; i < n; i++ {
		r.nUp += max(b[i].Up, 0)
		r.nAll += max(b[i].Up, 0) + max(b[i].Down, 0)
	}
	r.global = (float64(r.nUp) + BetaPriorA) / (float64(r.nAll) + BetaPriorA + BetaPriorB)
	for h := range r.hod {
		r.hod[h] = r.global
	}
	for i := range r.how {
		r.how[i] = r.global
		if i < n {
			u := float64(max(b[i].Up, 0))
			all := float64(max(b[i].Up, 0) + max(b[i].Down, 0))
			r.how[i] = (u + CellShrinkStrength*r.global) / (all + CellShrinkStrength)
		}
	}
	return r
}

// youngRates is buildRates for a profile with fewer than MinObsForExpected
// observations. Such a profile knows nothing about the time of day yet, so
// every hour gets one up-rate: the rate of an hour that holds all of the
// observations. Without this, a miss in the hour of the last answer and a
// miss one minute later in the next hour (or the next day, a weekend or a
// DST change) gave different verdicts: the host seen once was confirmed
// gone in the first case (p_alive 0.36, then 0.19) and never in the second
// (0.41, then 0.26), because the empty hour borrowed only half of its
// neighbour's answers.
func youngRates(b *[168]model.AvailBucket) rates {
	var all [168]model.AvailBucket
	for i := range b {
		all[0].Up += max(b[i].Up, 0)
		all[0].Down += max(b[i].Down, 0)
	}
	flat := buildRates(&all).how[0]
	r := buildRates(b)
	for i := range r.how {
		r.how[i] = flat
	}
	return r
}

// ratesFor picks the rates of a histogram: flat for a young profile, by hour otherwise.
func ratesFor(b *[168]model.AvailBucket) rates {
	r := buildRates(b)
	if r.nAll < MinObsForExpected {
		return youngRates(b)
	}
	return r
}

// dayType is 1 for Saturday and Sunday, 0 for a working day.
func dayType(weekday int) int {
	if weekday == 0 || weekday == 6 {
		return 1
	}
	return 0
}

// UpRates returns the model up-rate of each hour-of-week bucket.
func UpRates(b [168]model.AvailBucket) [168]float64 {
	return buildRates(&b).how
}

// missGivenAlive is P(the host does not answer | it is alive) for an hour
// with the given up-rate, for a history of nObs observations.
func missGivenAlive(upRate float64, nObs int) float64 {
	eps := math.Max(TransientMissRate, 1/float64(nObs+2))
	return 1 - upRate*(1-eps)
}

// prior is p0: the belief that the host still exists at its first miss.
func prior(nUp int) float64 {
	n := float64(nUp)
	return PriorBase + PriorGain*n/(n+PriorHalfLife)
}

// bayes updates P(alive) with one miss. A host that is gone always misses.
func bayes(p, missGivenUp float64) float64 {
	num := p * missGivenUp
	den := num + (1 - p)
	if den <= 0 {
		return 0
	}
	return num / den
}

// trailingMisses returns the observations after the last answer, oldest first.
func trailingMisses(recent []model.HostObservation) []model.HostObservation {
	i := len(recent)
	for i > 0 && !recent[i-1].Up {
		i--
	}
	return recent[i:]
}

// Assess runs the model on a profile. The latest observation in p.Recent is
// "now". The histogram must already contain every observation of Recent.
//
// The likelihood of the miss streak uses the histogram as it was before the
// streak: the misses of a host that died must not teach the model that the
// host is "usually off".
func Assess(p Profile, loc *time.Location) Assessment {
	return AssessWith(p, loc, AssessOptions{})
}

// AssessWith is Assess with the per-profile options. Observations that share
// a run id count once (NormalizeProfile).
func AssessWith(p Profile, loc *time.Location, opt AssessOptions) Assessment {
	if loc == nil {
		loc = time.UTC
	}
	p = NormalizeProfile(p, loc)
	if !clock.IsDefault() {
		// The stored histogram is hour-of-week; rebuild it under the lab clock.
		p.Buckets = rebucket(p.Recent, clock)
	}
	rule := max(opt.DownAfterMisses, 0)
	var a Assessment
	a.Rule = rule
	full := buildRates(&p.Buckets)
	if full.nAll > 0 {
		a.Stability = float64(full.nUp) / float64(full.nAll)
	}
	a.Pattern = Pattern(p.Buckets)

	if len(p.Recent) == 0 {
		a.Status = model.HostUnknown
		a.PAlive = 0
		return a
	}
	misses := trailingMisses(p.Recent)
	if len(misses) == 0 {
		// Answered now.
		a.Status = model.HostUp
		a.PAlive = 1
		a.Prior = prior(full.nUp)
		a.DownAfterMisses = downAfterFrom(ratesFor(&p.Buckets), a.Prior, p.Recent, loc)
		if rule > 0 {
			a.DownAfterMisses = rule
		}
		return a
	}
	if full.nUp == 0 {
		// Never answered: nothing to lose, nothing to report.
		a.Status = model.HostUnknown
		a.ConsecutiveMisses = len(misses)
		return a
	}

	// Histogram before the streak.
	before := p.Buckets
	for _, m := range misses {
		i := BucketIndex(m.At, loc)
		if before[i].Down > 0 {
			before[i].Down--
		}
	}
	r := ratesFor(&before) // flat for a young profile: the verdict must not depend on the clock hour
	a.Prior = prior(r.nUp)
	a.ConsecutiveMisses = len(misses)

	pAlive := a.Prior
	mature := r.nAll >= MinObsForExpected
	allExplained := mature
	for _, m := range misses {
		i := BucketIndex(m.At, loc)
		up := r.how[i]
		l := missGivenAlive(up, r.nAll)
		pAlive = bayes(pAlive, l)
		explained := mature && up < ExpectedOfflineUpRate
		if !explained {
			allExplained = false
		}
		a.Steps = append(a.Steps, MissStep{At: m.At, Bucket: i, UpRate: up, MissGivenUp: l, PAlive: pAlive, Explained: explained})
	}
	a.PAlive = pAlive

	switch {
	case rule > 0 && len(misses) >= rule:
		a.Status = model.HostDown
	case rule > 0:
		a.Status = model.HostUnstable
		if allExplained {
			a.Status = model.HostExpectedOffline
			a.Expected = true
		}
		a.DownAfterMisses = rule - len(misses)
		return a
	case pAlive < DownThreshold:
		a.Status = model.HostDown
	case allExplained:
		a.Status = model.HostExpectedOffline
		a.Expected = true
	default:
		a.Status = model.HostUnstable
	}
	if a.Status != model.HostDown {
		a.DownAfterMisses = downAfterFrom(r, pAlive, p.Recent, loc)
	}
	return a
}

// scanInterval is the usual gap between runs: the median gap of the recent
// observations, or DefaultScanInterval when there are fewer than three.
func scanInterval(recent []model.HostObservation) time.Duration {
	if len(recent) < 3 {
		return DefaultScanInterval
	}
	gaps := make([]time.Duration, 0, len(recent)-1)
	for i := 1; i < len(recent); i++ {
		if g := recent[i].At.Sub(recent[i-1].At); g > 0 {
			gaps = append(gaps, g)
		}
	}
	if len(gaps) == 0 {
		return DefaultScanInterval
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	g := gaps[len(gaps)/2]
	if g < time.Minute {
		return time.Minute
	}
	return g
}

// downAfterFrom counts how many more misses in a row, at the usual scan
// times after the latest observation, bring p below DownThreshold.
// It returns DownAfterHorizon when the horizon is not enough.
func downAfterFrom(r rates, p float64, recent []model.HostObservation, loc *time.Location) int {
	if len(recent) == 0 {
		return 0
	}
	step := scanInterval(recent)
	t := recent[len(recent)-1].At
	for n := 1; n <= DownAfterHorizon; n++ {
		t = t.Add(step)
		p = bayes(p, missGivenAlive(r.how[BucketIndex(t, loc)], r.nAll))
		if p < DownThreshold {
			return n
		}
	}
	return DownAfterHorizon
}

// DownAfterMisses answers "how many more misses in a row, at the usual scan
// times, would report this host inactive". It is 0 for a host that is down.
func DownAfterMisses(p Profile, loc *time.Location) int {
	return Assess(p, loc).DownAfterMisses
}

// DownAfterMissesWith is DownAfterMisses with the per-profile options.
func DownAfterMissesWith(p Profile, loc *time.Location, opt AssessOptions) int {
	return AssessWith(p, loc, opt).DownAfterMisses
}

// PAlive returns only the probability of Assess.
func PAlive(p Profile, loc *time.Location) float64 {
	return Assess(p, loc).PAlive
}

// ApplyToHost copies the model output to the host fields it owns.
func ApplyToHost(h *model.Host, a Assessment) {
	h.Status = a.Status
	h.PAlive = round3(a.PAlive)
	h.Stability = round3(a.Stability)
	h.ConsecutiveMisses = a.ConsecutiveMisses
	h.Pattern = a.Pattern
}

// AvailabilityProfile builds the API object of GET /hosts/{id}/availability.
func AvailabilityProfile(hostID int64, p Profile, a Assessment) model.AvailabilityProfile {
	return model.AvailabilityProfile{
		HostID:          hostID,
		Buckets:         p.Buckets,
		Recent:          p.Recent,
		Pattern:         a.Pattern,
		PAlive:          round3(a.PAlive),
		DownAfterMisses: a.DownAfterMisses,
	}
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }
