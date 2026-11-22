package analyze

import (
	"fmt"
	"sort"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// ServiceHistory is what earlier runs know about one service (same host,
// port and protocol). The store fills it; Diff uses it for two things:
//
//   - a service that is open now, was not open in the previous run, but was
//     open in an earlier run has returned (service_returned), it is not new;
//   - the HTTP response time of this run against the service's own baseline
//     (response_slower, response_recovered).
type ServiceHistory struct {
	// LastOpenRun and LastOpenAt: the last earlier run in which the service
	// was open. Zero: never open before this run.
	LastOpenRun int64
	LastOpenAt  time.Time
	// RunsAway: earlier runs after LastOpenRun in which the host answered
	// and the service was not open.
	RunsAway int
	// Response: HTTP response times of the earlier open observations,
	// oldest first, at most ResponseHistory of them. NoAnswer (-1) means the
	// port was open but HTTP gave no answer (timeout, reset, not HTTP).
	Response []int
}

// Response time rule. The baseline of a service is the median of its last
// ResponseBaselineN answered observations that were not slow themselves; one
// observation is enough (a juror runs two scans). An observation is slow
// when it is at least ResponseSlowFactor times the baseline and at least
// ResponseSlowMinMs above it, or when HTTP gave no answer while a baseline
// exists. response_slower is reported when the service becomes slow,
// response_recovered when it answers in normal time again; a service that
// stays slow is not reported again.
const (
	ResponseBaselineN  = 5
	ResponseSlowFactor = 2.0
	ResponseSlowMinMs  = 300
	// ResponseHistory is how many earlier observations the store passes.
	ResponseHistory = 12
	// NoAnswer marks an observation where the port was open and HTTP did not answer.
	NoAnswer = -1
)

// ResponseValue is the HTTP response time of one observation for the
// response rule: the time of the first request in ms, or NoAnswer when the
// service has no HTTP answer.
func ResponseValue(s *model.ServiceResult) int {
	if s == nil || s.HTTP == nil || s.HTTP.Status <= 0 {
		return NoAnswer
	}
	return max(s.HTTP.ResponseMs, 0)
}

// ResponsePoint is one observation of the series with the rule applied.
type ResponsePoint struct {
	Ms       int  // NoAnswer when HTTP did not answer
	Baseline int  // baseline before this point; -1 when there was none
	Slow     bool // slow against Baseline
}

// ResponseSeries applies the response rule to a series, oldest first.
func ResponseSeries(vals []int) []ResponsePoint {
	out := make([]ResponsePoint, len(vals))
	var normal []int // answered, not slow
	for i, v := range vals {
		p := ResponsePoint{Ms: v, Baseline: -1}
		if len(normal) > 0 {
			p.Baseline = median(normal[max(0, len(normal)-ResponseBaselineN):])
			p.Slow = isSlow(v, p.Baseline)
		}
		if v >= 0 && !p.Slow {
			normal = append(normal, v)
		}
		out[i] = p
	}
	return out
}

func isSlow(v, base int) bool {
	if base < 0 {
		return false
	}
	if v < 0 {
		return true // the port is open, HTTP no longer answers
	}
	return float64(v) >= ResponseSlowFactor*float64(base) && v-base >= ResponseSlowMinMs
}

func median(xs []int) int {
	s := append([]int(nil), xs...)
	sort.Ints(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// responseChange returns the response change of the current observation, if any.
func (d *differ) response(h *HostSnapshot, s *model.ServiceResult, hist ServiceHistory) {
	if len(hist.Response) == 0 {
		return
	}
	cur := ResponseValue(s)
	pts := ResponseSeries(append(append([]int(nil), hist.Response...), cur))
	n := len(pts)
	last, prev := pts[n-1], pts[n-2]
	before := map[string]any{"baseline_ms": last.Baseline, "ms": msOrNil(prev.Ms)}
	switch {
	case last.Slow && !prev.Slow && cur >= 0:
		d.add(h, s, model.ChangeResponseSlower, model.SevLow, "http.response_ms", before, map[string]any{"ms": cur}, false, nil)
	case last.Slow && !prev.Slow:
		d.add(h, s, model.ChangeResponseSlower, model.SevLow, "http.response_ms", before, map[string]any{"ms": nil, "error": "no_answer"}, false, nil)
	case !last.Slow && prev.Slow && cur >= 0:
		d.add(h, s, model.ChangeResponseRecovered, model.SevInfo, "http.response_ms", before, map[string]any{"ms": cur}, false, nil)
	}
}

func msOrNil(v int) any {
	if v < 0 {
		return nil
	}
	return v
}

// serviceReturned reports a service that was gone and is open again.
func (d *differ) serviceReturned(h *HostSnapshot, s *model.ServiceResult, hist ServiceHistory) {
	sev := model.SevLow
	if isSensitive(s) {
		sev = model.SevMedium
	}
	away := time.Duration(0)
	if !hist.LastOpenAt.IsZero() && d.cur.At.After(hist.LastOpenAt) {
		away = d.cur.At.Sub(hist.LastOpenAt)
	}
	before := map[string]any{"state": "gone", "last_open_run_id": hist.LastOpenRun, "last_open_at": hist.LastOpenAt.UTC(),
		"away_seconds": int64(away.Seconds()), "runs_away": hist.RunsAway}
	d.add(h, s, model.ChangeServiceReturned, sev, "state", before, "open", false, productDetail(s))
}

// awayText is a duration as the UI writes it (web/src/lib/format.ts
// fmtDuration): "1 min 48 s", "2 h 5 min", "3 dni 4 h". The dashboard and the
// change summary show the same absence, so they use the same units.
func awayText(d time.Duration) string { return durationText(d, "dni") }

func durationText(d time.Duration, days string) string {
	s := int64(d.Round(time.Second) / time.Second)
	two := func(a int64, ua string, b int64, ub string) string {
		if b == 0 {
			return fmt.Sprintf("%d %s", a, ua)
		}
		return fmt.Sprintf("%d %s %d %s", a, ua, b, ub)
	}
	switch m, h := s/60, s/3600; {
	case s < 60:
		return fmt.Sprintf("%d s", s)
	case m < 60:
		return two(m, "min", s%60, "s")
	case h < 48:
		return two(h, "h", m%60, "min")
	default:
		return two(h/24, days, h%24, "h")
	}
}

// usualText names the usual response time of a service. A service on the same
// machine or switch answers in under a millisecond, and "zwykle 0 ms" reads as
// a missing value.
func usualText(baselineMs int) string {
	if baselineMs < 1 {
		return "zwykle poniżej 1 ms"
	}
	return fmt.Sprintf("zwykle %d ms", baselineMs)
}
