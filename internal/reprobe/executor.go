package reprobe

import (
	"context"
	"log/slog"
	"strconv"
	"time"
)

// Executor runs the planner on a timer and starts the probes that are due.
type Executor struct {
	B    Backend
	Log  *slog.Logger
	Tick time.Duration // default 1 minute
}

// StepReport says what one step did.
type StepReport struct {
	Plan    Plan
	Started []int64 // run ids
	Probed  int     // addresses sent to Start
	Errors  []string
}

// Step plans at now and starts the due probes: one targeted run per profile.
// It starts nothing while the plan is blocked (disabled, emergency stop, a
// reprobe run still active).
func (e *Executor) Step(ctx context.Context, now time.Time) (StepReport, error) {
	in, err := e.B.Snapshot(ctx, now)
	if err != nil {
		return StepReport{}, err
	}
	plan := Build(in)
	rep := StepReport{Plan: plan}
	if plan.Blocked != "" || plan.DueNow == 0 {
		return rep, nil
	}
	type group struct {
		pid    *int64
		probes []Probe
	}
	var groups []*group
	byKey := map[int64]*group{}
	for _, p := range plan.Probes {
		if p.NotBefore.After(now) {
			continue
		}
		key := int64(0)
		if p.ProfileID != nil {
			key = *p.ProfileID
		}
		g := byKey[key]
		if g == nil {
			g = &group{pid: p.ProfileID}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.probes = append(g.probes, p)
	}
	for _, g := range groups {
		req := Request{ProfileID: g.pid, Trigger: Trigger}
		for _, p := range g.probes {
			req.Targets = append(req.Targets, Target{HostID: p.HostID, IP: p.IP, Ports: p.Ports})
		}
		n := len(req.Targets)
		req.Reason = "Ponowne sprawdzenie: " + strconv.Itoa(n) + " " + plural(n, "host", "hosty", "hostów")
		run, err := e.B.Start(ctx, req)
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
			e.log().Warn("reprobe: start failed", "error", err, "targets", len(req.Targets))
			continue
		}
		if err := e.B.Record(ctx, run, g.probes, now); err != nil {
			rep.Errors = append(rep.Errors, err.Error())
			e.log().Error("reprobe: record failed", "run", run.ID, "error", err)
		}
		rep.Started = append(rep.Started, run.ID)
		rep.Probed += len(req.Targets)
		e.log().Info("reprobe run started", "run", run.ID, "targets", len(req.Targets), "reason", req.Reason)
	}
	return rep, nil
}

// Run calls Step every Tick until ctx ends.
func (e *Executor) Run(ctx context.Context) {
	tick := e.Tick
	if tick <= 0 {
		tick = time.Minute
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		if _, err := e.Step(ctx, time.Now()); err != nil && ctx.Err() == nil {
			e.log().Error("reprobe step", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (e *Executor) log() *slog.Logger {
	if e.Log == nil {
		return slog.Default()
	}
	return e.Log
}

// plural picks the Polish form for n: one (1), few (2-4, not 12-14), many.
func plural(n int, one, few, many string) string {
	if n == 1 {
		return one
	}
	if m10, m100 := n%10, n%100; m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) {
		return few
	}
	return many
}
