package analyze

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Clock is the bucket layout of the availability model: Period is split into
// buckets of Width. The default is the hour-of-week histogram (1 h, 1 week,
// 168 buckets). A shorter clock is a lab setting: the test lab compresses
// "working hours" and "night" into cycles of minutes, which an hour-of-week
// histogram cannot learn.
//
// With a non-default clock the model rebuilds its histogram from the latest
// observations of the host (Profile.Recent, at most RecentCap), puts each one
// into bucket (unix time mod Period) / Width, and shrinks every bucket
// straight to the global up-rate (the hour-of-day and day-type levels have no
// meaning there). The stored hour-of-week histogram is not changed.
type Clock struct {
	Width  time.Duration
	Period time.Duration
}

// DefaultClock is the hour-of-week histogram.
var DefaultClock = Clock{Width: time.Hour, Period: 7 * 24 * time.Hour}

// clock is the layout in force. It is set once at start (SetClock, or the
// environment variables CZUJKA_AVAIL_BUCKET and CZUJKA_AVAIL_PERIOD).
var clock = DefaultClock

func init() {
	if c, err := ClockFromEnv(os.Getenv); err == nil {
		clock = c
		if !c.IsDefault() {
			// The pattern texts do not name the clock; the log does.
			fmt.Fprintf(os.Stderr, "czujka: availability clock %s\n", c)
		}
	} else {
		fmt.Fprintf(os.Stderr, "czujka: availability clock: %v; using 1h buckets over 1 week\n", err)
	}
}

// ClockFromEnv reads CZUJKA_AVAIL_BUCKET (bucket width, Go duration, default
// 1h) and CZUJKA_AVAIL_PERIOD (cycle, default 168h).
func ClockFromEnv(getenv func(string) string) (Clock, error) {
	c := DefaultClock
	var err error
	if v := strings.TrimSpace(getenv("CZUJKA_AVAIL_BUCKET")); v != "" {
		if c.Width, err = time.ParseDuration(v); err != nil {
			return DefaultClock, fmt.Errorf("CZUJKA_AVAIL_BUCKET: %w", err)
		}
	}
	if v := strings.TrimSpace(getenv("CZUJKA_AVAIL_PERIOD")); v != "" {
		if c.Period, err = time.ParseDuration(v); err != nil {
			return DefaultClock, fmt.Errorf("CZUJKA_AVAIL_PERIOD: %w", err)
		}
	}
	return c, c.Validate()
}

// Validate checks that the clock fits the 168-bucket histogram.
func (c Clock) Validate() error {
	switch {
	case c.Width < time.Second:
		return fmt.Errorf("bucket width %v is under 1s", c.Width)
	case c.Period < c.Width || c.Period%c.Width != 0:
		return fmt.Errorf("period %v is not a whole number of %v buckets", c.Period, c.Width)
	case c.Period/c.Width > 168:
		return fmt.Errorf("period %v has %d buckets of %v, at most 168", c.Period, c.Period/c.Width, c.Width)
	}
	return nil
}

// Buckets is the number of buckets in one period.
func (c Clock) Buckets() int { return int(c.Period / c.Width) }

// IsDefault reports whether c is the hour-of-week histogram.
func (c Clock) IsDefault() bool { return c == DefaultClock }

// String is the setting as an operator writes it, for logs and the UI.
func (c Clock) String() string {
	return fmt.Sprintf("%v buckets over %v (%d)", c.Width, c.Period, c.Buckets())
}

// SetClock sets the layout in force. Call it once at start, before the
// first analysis.
func SetClock(c Clock) error {
	if err := c.Validate(); err != nil {
		return err
	}
	clock = c
	return nil
}

// CurrentClock returns the layout in force.
func CurrentClock() Clock { return clock }

// index is the bucket of t under a non-default clock.
func (c Clock) index(t time.Time) int {
	return int((t.UnixNano() % int64(c.Period)) / int64(c.Width))
}

// rebucket rebuilds the histogram of a profile from its observations under
// clock c.
func rebucket(recent []model.HostObservation, c Clock) [168]model.AvailBucket {
	var b [168]model.AvailBucket
	for _, o := range recent {
		i := c.index(o.At)
		if o.Up {
			b[i].Up++
		} else {
			b[i].Down++
		}
	}
	return b
}
