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
	at := addr(h.IP, s.Port)
	before := map[string]any{"baseline_ms": last.Baseline, "ms": msOrNil(prev.Ms)}
	switch {
	case last.Slow && !prev.Slow && cur >= 0:
		d.add(h, s, model.ChangeResponseSlower, model.SevLow, "http.response_ms", before, map[string]any{"ms": cur},
			false, fmt.Sprintf("Usługa %s odpowiada wolniej: %d ms (zwykle %d ms)", at, cur, last.Baseline))
	case last.Slow && !prev.Slow:
		d.add(h, s, model.ChangeResponseSlower, model.SevLow, "http.response_ms", before, map[string]any{"ms": nil, "error": "no_answer"},
			false, fmt.Sprintf("Usługa %s: port otwarty, ale HTTP nie odpowiedział w czasie (zwykle %d ms)", at, last.Baseline))
	case !last.Slow && prev.Slow && cur >= 0:
		d.add(h, s, model.ChangeResponseRecovered, model.SevInfo, "http.response_ms", before, map[string]any{"ms": cur},
			false, fmt.Sprintf("Usługa %s znów odpowiada w zwykłym czasie: %d ms (zwykle %d ms)", at, cur, last.Baseline))
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
	d.add(h, s, model.ChangeServiceReturned, sev, "state", before, "open", false,
		fmt.Sprintf("Usługa %s wróciła po %s (nie było jej w %s)%s", addr(h.IP, s.Port), awayText(away), runsText(hist.RunsAway), productNote(s)))
}

func awayText(d time.Duration) string {
	switch {
	case d <= 0:
		return "przerwie"
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	default:
		return fmt.Sprintf("%d dniach", int(d.Hours()/24))
	}
}

func runsText(n int) string {
	switch {
	case n == 1:
		return "1 skanie"
	case n > 1:
		return fmt.Sprintf("%d skanach", n)
	}
	return "poprzednim skanie"
}
