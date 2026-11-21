package analyze

import (
	"fmt"
	"math"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// Constants of the pattern detector.
const (
	// MinPatternObs: with fewer observations Pattern returns "".
	MinPatternObs = 12
	// AlwaysOnRate: at or above this share the host is "always on".
	AlwaysOnRate = 0.95
	// PatternOnRate and PatternOffRate decide if an hour is "on", "off" or mixed.
	PatternOnRate  = 0.6
	PatternOffRate = 0.2
	// PatternDecisive: share of observed hours that must be clearly on or
	// clearly off before the text names a pattern.
	PatternDecisive = 0.8
	// MinCellObs: average observations per hour-of-week cell needed to name
	// weekdays; with less data only the daily hours are named.
	MinCellObs = 2.0
	// MinHourObs: observations an hour-of-day needs in the daily mode.
	MinHourObs = 3
)

// plDay is the Polish short weekday name, indexed by time.Weekday.
var plDay = [7]string{"nd", "pn", "wt", "śr", "cz", "pt", "sb"}

// mondayFirst lists time.Weekday values in the Polish week order.
var mondayFirst = [7]int{1, 2, 3, 4, 5, 6, 0}

// Pattern describes the availability histogram in short Polish text, for
// example "zwykle aktywny pn–pt 08–16" or "odpowiada w ok. 50% skanów, bez
// wzorca dobowego". It returns "" when there is too little data.
func Pattern(b [168]model.AvailBucket) string {
	up, all, cells := 0, 0, 0
	for _, c := range b {
		up += c.Up
		all += c.Up + c.Down
		if c.Up+c.Down > 0 {
			cells++
		}
	}
	if all < MinPatternObs || up == 0 {
		return ""
	}
	share := float64(up) / float64(all)
	if share >= AlwaysOnRate {
		return fmt.Sprintf("odpowiada stale (%d%% skanów)", int(math.Round(share*100)))
	}
	if !clock.IsDefault() {
		return clockPattern(b, share)
	}

	if float64(all)/float64(cells) >= MinCellObs {
		if s := weeklyPattern(b); s != "" {
			return s
		}
	}
	if s := dailyPattern(b); s != "" {
		return s
	}
	pct := int(math.Round(share*20)) * 5
	if pct == 0 {
		pct = int(math.Max(1, math.Round(share*100)))
	}
	return fmt.Sprintf("odpowiada w ok. %d%% skanów, bez wzorca dobowego", pct)
}

// cellState is 1 for "on", -1 for "off", 0 for mixed or not observed.
func cellState(up, n, minObs int) (state int, observed bool) {
	if n < minObs || n == 0 {
		return 0, false
	}
	r := float64(up) / float64(n)
	switch {
	case r >= PatternOnRate:
		return 1, true
	case r <= PatternOffRate:
		return -1, true
	}
	return 0, true
}

func weeklyPattern(b [168]model.AvailBucket) string {
	var on [7][24]bool
	observed, decisive, nOn, nOff := 0, 0, 0, 0
	var hourObserved [24]bool
	for i, c := range b {
		st, ok := cellState(c.Up, c.Up+c.Down, 1)
		if !ok {
			continue
		}
		observed++
		hourObserved[i%24] = true
		switch st {
		case 1:
			on[i/24][i%24] = true
			decisive++
			nOn++
		case -1:
			decisive++
			nOff++
		}
	}
	if observed == 0 || nOn == 0 || nOff == 0 || float64(decisive)/float64(observed) < PatternDecisive {
		return ""
	}
	var days [7]bool
	nDays := 0
	for d := 0; d < 7; d++ {
		for h := 0; h < 24; h++ {
			if on[d][h] {
				days[d] = true
				nDays++
				break
			}
		}
	}
	// An hour is active when it is on in at least half of the active days.
	var hours [24]bool
	nHours, nObservedHours := 0, 0
	for h := 0; h < 24; h++ {
		if hourObserved[h] {
			nObservedHours++
		}
		c := 0
		for d := 0; d < 7; d++ {
			if days[d] && on[d][h] {
				c++
			}
		}
		if c*2 >= nDays {
			hours[h] = true
			nHours++
		}
	}
	if nHours == 0 {
		return ""
	}
	parts := []string{"zwykle aktywny", dayText(days)}
	if nHours < nObservedHours {
		parts = append(parts, hourText(hours))
	}
	return strings.Join(parts, " ")
}

func dailyPattern(b [168]model.AvailBucket) string {
	var up, n [24]int
	for i, c := range b {
		up[i%24] += c.Up
		n[i%24] += c.Up + c.Down
	}
	var hours [24]bool
	observed, decisive, nOn, nOff := 0, 0, 0, 0
	for h := 0; h < 24; h++ {
		st, ok := cellState(up[h], n[h], MinHourObs)
		if !ok {
			continue
		}
		observed++
		switch st {
		case 1:
			hours[h] = true
			decisive++
			nOn++
		case -1:
			decisive++
			nOff++
		}
	}
	if observed == 0 || nOn == 0 || nOff == 0 || float64(decisive)/float64(observed) < PatternDecisive {
		return ""
	}
	return "zwykle aktywny w godz. " + hourText(hours)
}

// dayText names a weekday set: "codziennie", "pn–pt", "sb–nd", "pn, śr, pt".
func dayText(days [7]bool) string {
	var seq []int // positions in the Monday-first order
	for pos, wd := range mondayFirst {
		if days[wd] {
			seq = append(seq, pos)
		}
	}
	switch len(seq) {
	case 0:
		return ""
	case 7:
		return "codziennie"
	case 1:
		return plDay[mondayFirst[seq[0]]]
	}
	if seq[len(seq)-1]-seq[0] == len(seq)-1 {
		return plDay[mondayFirst[seq[0]]] + "–" + plDay[mondayFirst[seq[len(seq)-1]]]
	}
	names := make([]string, len(seq))
	for i, pos := range seq {
		names[i] = plDay[mondayFirst[pos]]
	}
	return strings.Join(names, ", ")
}

// hourText names the active hours as one range "HH–HH" (end exclusive).
// The range starts after the longest inactive stretch of the day, so a host
// that is on from 22 to 06 reads "22–06".
func hourText(hours [24]bool) string {
	var act []int
	for h := 0; h < 24; h++ {
		if hours[h] {
			act = append(act, h)
		}
	}
	if len(act) == 0 {
		return ""
	}
	if len(act) == 24 {
		return "00–24"
	}
	// Largest circular gap between consecutive active hours.
	bestGap, startIdx := -1, 0
	for i := range act {
		next := act[(i+1)%len(act)]
		gap := (next - act[i] + 24) % 24
		if len(act) == 1 {
			gap = 24
		}
		if gap > bestGap {
			bestGap = gap
			startIdx = (i + 1) % len(act)
		}
	}
	start := act[startIdx]
	last := act[(startIdx+len(act)-1)%len(act)]
	end := last + 1
	if end == 24 && start == 0 {
		return "00–24"
	}
	if end > 24 {
		end -= 24
	}
	return fmt.Sprintf("%02d–%02d", start, end)
}

// clockPattern describes a histogram under a lab clock: the share of answers
// and the buckets in which the host is usually off.
func clockPattern(b [168]model.AvailBucket, share float64) string {
	var off []string
	for i := 0; i < clock.Buckets(); i++ {
		n := b[i].Up + b[i].Down
		if n > 0 && float64(b[i].Up)/float64(n) <= PatternOffRate {
			off = append(off, fmt.Sprint(i))
		}
	}
	s := fmt.Sprintf("odpowiada w ok. %d%% skanów (zegar laboratoryjny: %v × %d)", int(math.Round(share*100)), clock.Width, clock.Buckets())
	if len(off) > 0 {
		s += ", zwykle nieaktywny w kubełkach " + strings.Join(off, ",")
	}
	return s
}
