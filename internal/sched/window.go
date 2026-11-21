// Package sched computes when scans may run and when they are due: time
// windows (with timezone, midnight crossing and daylight-saving changes),
// cron and interval schedules, and the scheduler loop that starts due runs
// and resumes runs that a closing window paused.
package sched

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// DefaultTimezone is used when a schedule names none.
const DefaultTimezone = "Europe/Warsaw"

// Location loads the schedule timezone. An empty name means Europe/Warsaw.
func Location(name string) (*time.Location, error) {
	if strings.TrimSpace(name) == "" {
		name = DefaultTimezone
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("unknown timezone %q", name)
	}
	return loc, nil
}

// parseHM parses "HH:MM" into minutes after midnight.
func parseHM(s string) (int, error) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, fmt.Errorf("time %q is not HH:MM", s)
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || (hh == 24 && mm != 0) {
		return 0, fmt.Errorf("time %q is not HH:MM", s)
	}
	return hh*60 + mm, nil
}

// ValidateWindows checks the window list of a schedule.
func ValidateWindows(ws []model.Window) error {
	for i, w := range ws {
		if _, err := parseHM(w.Start); err != nil {
			return fmt.Errorf("window %d: start: %w", i+1, err)
		}
		if _, err := parseHM(w.End); err != nil {
			return fmt.Errorf("window %d: end: %w", i+1, err)
		}
		for _, d := range w.Days {
			if d < 0 || d > 6 {
				return fmt.Errorf("window %d: day %d is not in 0..6 (0 = Sunday)", i+1, d)
			}
		}
	}
	return nil
}

// span returns the start and end of window w for the occurrence that begins
// on the given calendar day. ok is false when the window does not begin on
// that weekday or is malformed. The instants are built from wall-clock
// fields, so a window keeps its clock times across a daylight-saving change
// (its real length is then one hour shorter or longer).
func span(w model.Window, y int, m time.Month, d int, loc *time.Location) (start, end time.Time, ok bool) {
	s, err1 := parseHM(w.Start)
	e, err2 := parseHM(w.End)
	if err1 != nil || err2 != nil {
		return start, end, false
	}
	start = time.Date(y, m, d, s/60, s%60, 0, 0, loc)
	if len(w.Days) > 0 {
		wd := int(time.Date(y, m, d, 12, 0, 0, 0, loc).Weekday())
		found := false
		for _, x := range w.Days {
			if x == wd {
				found = true
			}
		}
		if !found {
			return start, end, false
		}
	}
	if e > s {
		end = time.Date(y, m, d, e/60, e%60, 0, 0, loc)
	} else {
		// End at or before Start: the window crosses midnight (equal = 24 hours)
		end = time.Date(y, m, d+1, e/60, e%60, 0, 0, loc)
	}
	return start, end, end.After(start)
}

// spansAround lists the occurrences of all windows that begin on the days
// from..to relative to the local date of t.
func spansAround(t time.Time, ws []model.Window, loc *time.Location, from, to int) [][2]time.Time {
	lt := t.In(loc)
	y, m, d := lt.Date()
	var out [][2]time.Time
	for off := from; off <= to; off++ {
		for _, w := range ws {
			if s, e, ok := span(w, y, m, d+off, loc); ok {
				out = append(out, [2]time.Time{s, e})
			}
		}
	}
	return out
}

// InWindow reports whether t is inside one of the windows. No windows means
// any time is allowed.
func InWindow(t time.Time, ws []model.Window, loc *time.Location) bool {
	if len(ws) == 0 {
		return true
	}
	for _, sp := range spansAround(t, ws, loc, -1, 0) {
		if !t.Before(sp[0]) && t.Before(sp[1]) {
			return true
		}
	}
	return false
}

// WindowEnd returns when the window that contains t closes. Windows that
// overlap or touch count as one. ok is false when t is outside every window
// or when there are no windows (then there is no limit).
func WindowEnd(t time.Time, ws []model.Window, loc *time.Location) (end time.Time, ok bool) {
	if len(ws) == 0 {
		return end, false
	}
	cur := t
	for i := 0; i < 16; i++ { // follow chains of touching windows, at most about a week
		best := time.Time{}
		for _, sp := range spansAround(cur, ws, loc, -1, 0) {
			if !cur.Before(sp[0]) && cur.Before(sp[1]) && sp[1].After(best) {
				best = sp[1]
			}
		}
		if best.IsZero() {
			break
		}
		end, ok, cur = best, true, best
	}
	return end, ok
}

// NextWindowStart returns the first window start after t. With no windows
// it returns t. ok is false when no window ever opens (all malformed).
func NextWindowStart(t time.Time, ws []model.Window, loc *time.Location) (time.Time, bool) {
	if len(ws) == 0 {
		return t, true
	}
	best := time.Time{}
	for _, sp := range spansAround(t, ws, loc, 0, 8) {
		if sp[0].After(t) && (best.IsZero() || sp[0].Before(best)) {
			best = sp[0]
		}
	}
	return best, !best.IsZero()
}

// NextAllowed returns t when it is inside a window, else the next window start.
func NextAllowed(t time.Time, ws []model.Window, loc *time.Location) (time.Time, bool) {
	if InWindow(t, ws, loc) {
		return t, true
	}
	return NextWindowStart(t, ws, loc)
}

// ErrNoSchedule means the schedule has neither a cron expression nor an interval.
var ErrNoSchedule = errors.New("schedule has no cron expression and no interval")

// NextRun returns when the schedule is due next, ignoring windows. last is
// the start of the previous run (zero when there was none); from is the
// base for a schedule that never ran. A cron schedule is due at the first
// cron time after the base. An interval schedule is due interval after the
// last run. A schedule that never ran is not due on save: an interval
// schedule is first due one interval after the base, or at the first window
// start after the base when it has windows.
func NextRun(s model.Schedule, last, from time.Time) (time.Time, error) {
	loc, err := Location(s.Timezone)
	if err != nil {
		return time.Time{}, err
	}
	base := last
	if base.IsZero() {
		base = from
	}
	switch {
	case strings.TrimSpace(s.Cron) != "":
		c, err := ParseCron(s.Cron)
		if err != nil {
			return time.Time{}, err
		}
		next := c.Next(base, loc)
		if next.IsZero() {
			return next, fmt.Errorf("cron %q never fires", s.Cron)
		}
		return next, nil
	case s.IntervalMinutes > 0:
		if last.IsZero() {
			if len(s.Windows) > 0 {
				start, ok := NextWindowStart(from, s.Windows, loc)
				if !ok {
					return time.Time{}, errors.New("no scan window ever opens")
				}
				return start, nil
			}
			return from.Add(time.Duration(s.IntervalMinutes) * time.Minute), nil
		}
		return last.Add(time.Duration(s.IntervalMinutes) * time.Minute), nil
	}
	return time.Time{}, ErrNoSchedule
}

// NextStart returns when the next run will really start: the due time, not
// before now, moved to the next window start when it falls outside the
// windows. Use it for ScanProfile.NextRunAt.
func NextStart(s model.Schedule, last, now time.Time) (time.Time, error) {
	loc, err := Location(s.Timezone)
	if err != nil {
		return time.Time{}, err
	}
	due, err := NextRun(s, last, now)
	if err != nil {
		return time.Time{}, err
	}
	if due.Before(now) {
		due = now
	}
	at, ok := NextAllowed(due, s.Windows, loc)
	if !ok {
		return time.Time{}, errors.New("no scan window ever opens")
	}
	return at, nil
}
