package scan

import (
	"context"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
)

// A run paused while a group waits for its retry round must not report the
// hosts of that group twice: the group is scanned again after the resume.
func TestPauseInsideAGroupDoesNotReportHostsTwice(t *testing.T) {
	netw := &fakeNet{hosts: map[string][]int{"10.7.0.5": {80}}}
	e := New(Deps{Prober: netw, Logger: quiet})
	plan := basePlan("10.7.0.0/24")
	plan.Hints = []model.HostHint{{IP: "10.7.0.9", OpenPorts: []int{22}}} // known, silent now: forces retry rounds
	plan.Profile.Retry = model.RetryOpts{UnstableRetries: 2, BackoffMs: 400}
	e.direct = func(_ context.Context, ip string, _ []int, _ time.Duration, _ *probe.Limiter) (probe.Host, int64) {
		return probe.Host{IP: ip}, 1 // the direct TCP probe of the last round: still silent
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	time.AfterFunc(150*time.Millisecond, func() { cancel(PauseCause(model.PauseManual)) })
	sink := newSink()
	out := e.Run(ctx, plan, sink)
	if out.Status != model.RunPaused || out.PauseReason != model.PauseManual {
		t.Fatalf("outcome = %+v", out)
	}
	if len(sink.hosts) != 0 {
		t.Fatalf("a deferred group reported %d hosts before its chunk was final", len(sink.hosts))
	}
	if out.Stats.HostsUp != 0 || out.Stats.AddressesDone != 0 {
		t.Errorf("stats of a deferred group must be taken back: %+v", out.Stats)
	}
	for _, c := range sink.chunks {
		if c.Status != model.ChunkDeferred || c.Group != 1 {
			t.Errorf("chunk = %+v, want deferred in group 1", c)
		}
	}

	plan.Chunks = sink.notDone()
	plan.PrevStats = &out.Stats
	plan.Profile.Retry.BackoffMs = 5
	out = e.Run(context.Background(), plan, sink)
	if out.Status != model.RunCompleted {
		t.Fatalf("resume outcome = %+v", out)
	}
	seen := map[string]int{}
	for _, h := range sink.hosts {
		seen[h.IP]++
	}
	if seen["10.7.0.5"] != 1 || seen["10.7.0.9"] != 1 || len(seen) != 2 {
		t.Errorf("hosts reported = %v, want each exactly once", seen)
	}
	if h := sink.host("10.7.0.9"); h == nil || h.Up || h.Attempts != 3 {
		t.Errorf("silent hinted host = %+v", h)
	}
	if out.Stats.HostsUp != 1 {
		t.Errorf("hosts up = %d", out.Stats.HostsUp)
	}
}
