package sched

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Cron is a parsed 5-field cron expression: minute hour day-of-month month
// day-of-week. Fields accept "*", numbers, lists "a,b", ranges "a-b" and
// steps "*/n" or "a-b/n". Month and weekday names (jan, mon) work. Day of
// week 0 and 7 are Sunday. When both day fields are restricted, a day
// matches if either matches (standard cron behaviour).
type Cron struct {
	minute, hour, dom, month, dow uint64
	domStar, dowStar              bool
}

var (
	monthNames = map[string]int{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
	dowNames   = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
)

// ParseCron parses a 5-field expression.
func ParseCron(expr string) (Cron, error) {
	f := strings.Fields(expr)
	if len(f) != 5 {
		return Cron{}, fmt.Errorf("cron %q: want 5 fields (minute hour day month weekday), got %d", expr, len(f))
	}
	var c Cron
	var err error
	if c.minute, err = cronField(f[0], 0, 59, nil); err != nil {
		return Cron{}, fmt.Errorf("cron minute: %w", err)
	}
	if c.hour, err = cronField(f[1], 0, 23, nil); err != nil {
		return Cron{}, fmt.Errorf("cron hour: %w", err)
	}
	if c.dom, err = cronField(f[2], 1, 31, nil); err != nil {
		return Cron{}, fmt.Errorf("cron day of month: %w", err)
	}
	if c.month, err = cronField(f[3], 1, 12, monthNames); err != nil {
		return Cron{}, fmt.Errorf("cron month: %w", err)
	}
	if c.dow, err = cronField(f[4], 0, 7, dowNames); err != nil {
		return Cron{}, fmt.Errorf("cron day of week: %w", err)
	}
	if c.dow&(1<<7) != 0 {
		c.dow |= 1 // 7 is Sunday too
	}
	c.domStar = strings.HasPrefix(f[2], "*")
	c.dowStar = strings.HasPrefix(f[4], "*")
	return c, nil
}

func cronField(s string, lo, hi int, names map[string]int) (uint64, error) {
	var bits uint64
	for _, part := range strings.Split(s, ",") {
		rng, stepStr, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepStr)
			if err != nil || n < 1 {
				return 0, fmt.Errorf("bad step in %q", part)
			}
			step = n
		}
		a, b := lo, hi
		if rng != "*" {
			from, to, isRange := strings.Cut(rng, "-")
			var err error
			if a, err = cronValue(from, names); err != nil {
				return 0, err
			}
			b = a
			if isRange {
				if b, err = cronValue(to, names); err != nil {
					return 0, err
				}
			} else if hasStep {
				b = hi // "5/15" means from 5 to the end
			}
		}
		if a < lo || b > hi || a > b {
			return 0, fmt.Errorf("%q is outside %d-%d", part, lo, hi)
		}
		for v := a; v <= b; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, nil
}

func cronValue(s string, names map[string]int) (int, error) {
	if n, ok := names[strings.ToLower(s)]; ok {
		return n, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("bad value %q", s)
	}
	return n, nil
}

func (c Cron) dayMatches(t time.Time) bool {
	dom := c.dom&(1<<uint(t.Day())) != 0
	dow := c.dow&(1<<uint(t.Weekday())) != 0
	switch {
	case c.domStar && c.dowStar:
		return true
	case c.domStar:
		return dow
	case c.dowStar:
		return dom
	}
	return dom || dow
}

// Next returns the first time after t that matches, in the given location.
// It returns the zero time when nothing matches within five years. A wall
// time that a daylight-saving jump skips fires at the first moment after
// the jump; a repeated wall time fires once.
func (c Cron) Next(after time.Time, loc *time.Location) time.Time {
	lt := after.In(loc)
	y, m, d := lt.Date()
	for day := 0; day < 366*5; day++ {
		date := time.Date(y, m, d+day, 12, 0, 0, 0, loc)
		if c.month&(1<<uint(date.Month())) == 0 || !c.dayMatches(date) {
			continue
		}
		dy, dm, dd := date.Date()
		for h := 0; h < 24; h++ {
			if c.hour&(1<<uint(h)) == 0 {
				continue
			}
			for min := 0; min < 60; min++ {
				if c.minute&(1<<uint(min)) == 0 {
					continue
				}
				cand := time.Date(dy, dm, dd, h, min, 0, 0, loc)
				if cand.After(after) {
					return cand
				}
			}
		}
	}
	return time.Time{}
}
