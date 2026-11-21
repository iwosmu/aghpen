package scan

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/targets"
)

func TestSizerFollowsMeasuredSpeed(t *testing.T) {
	c := model.ChunkingOpts{Adaptive: true, InitialSize: 256, MinSize: 256, MaxSize: 4096, TargetSeconds: 30}
	s := newSizer(c, 256)
	if s.Next() != 256 {
		t.Fatalf("initial = %d", s.Next())
	}
	// 256 addresses in 5 s: the ideal chunk for 30 s is 1536; EWMA(0.5) gives (1536+256)/2
	s.Observe(256, 5*time.Second)
	if got := s.Next(); got != 896 {
		t.Fatalf("after a fast chunk = %d, want 896", got)
	}
	// a slow chunk: 768 addresses in 60 s → ideal 384 → (384+896)/2
	s.Observe(768, 60*time.Second)
	if got := s.Next(); got != 640 {
		t.Fatalf("after a slow chunk = %d, want 640", got)
	}
	// one very slow chunk must not collapse the size below min
	s.Observe(640, 3600*time.Second)
	if got := s.Next(); got != 448 {
		t.Fatalf("after a very slow chunk = %d, want 448 = (256+640)/2", got)
	}
	for i := 0; i < 20; i++ {
		s.Observe(s.Next(), time.Second)
	}
	if got := s.Next(); got < 4090 || got > 4096 {
		t.Fatalf("converged size = %d, want max_size 4096", got)
	}
	for i := 0; i < 20; i++ {
		s.Observe(s.Next(), time.Hour)
	}
	if got := s.Next(); got != 256 {
		t.Fatalf("floor = %d, want min_size 256", got)
	}
	if d, ok := s.Estimate(100); !ok || d <= 0 {
		t.Errorf("estimate = %v %v", d, ok)
	}

	fixed := newSizer(model.ChunkingOpts{Adaptive: false, InitialSize: 512}, 256)
	fixed.Observe(512, time.Millisecond)
	if fixed.Next() != 512 {
		t.Errorf("fixed chunks must not change: %d", fixed.Next())
	}
	if _, ok := newSizer(c, 256).Estimate(10); ok {
		t.Error("no estimate before a measurement")
	}
}

func TestNormalizeChunkingAndUnitSize(t *testing.T) {
	c := normalizeChunking(model.ChunkingOpts{})
	if !c.Adaptive || c.InitialSize != 256 || c.MinSize != 256 || c.MaxSize != 4096 || c.TargetSeconds != 30 {
		t.Errorf("defaults = %+v", c)
	}
	c = normalizeChunking(model.ChunkingOpts{InitialSize: 10000, MinSize: 5000, MaxSize: 1000})
	if c.MinSize != 1000 || c.InitialSize != 1000 {
		t.Errorf("repaired = %+v", c)
	}
	ad := model.ChunkingOpts{Adaptive: true, InitialSize: 1024, MinSize: 64, MaxSize: 4096, TargetSeconds: 30}
	if got := unitSizeFor(ad, 10000); got != 256 {
		t.Errorf("unit = %d, want one /24 block", got)
	}
	ad.MinSize = 300
	if got := unitSizeFor(ad, 10000); got != 512 {
		t.Errorf("unit = %d, want 512 (min_size rounded up to blocks)", got)
	}
	if got := unitSizeFor(model.ChunkingOpts{Adaptive: false, InitialSize: 1024}, 10000); got != 1024 {
		t.Errorf("fixed unit = %d", got)
	}
	// a /8 must not produce more than maxPlannedUnits chunks
	if got := unitSizeFor(normalizeChunking(model.ChunkingOpts{}), 1<<24); (1<<24)/got > maxPlannedUnits {
		t.Errorf("unit for a /8 = %d gives %d chunks", got, (1<<24)/got)
	}
}

func TestBuildUnitsDensityFirst(t *testing.T) {
	st := targets.Build([]string{"10.0.0.0/22", "10.0.9.7", "10.0.8.1-10.0.8.3", "192.168.1.128/25"})
	hints := []uint32{targets.U32(targets.Addr(0x0A000205)), 0x0A000209, 0x0A000301} // two in 10.0.2.0/24, one in 10.0.3.0/24
	units, err := buildUnits(3, st.V4, nil, hints, 256)
	if err != nil {
		t.Fatal(err)
	}
	var specs [][]string
	var sizes, prio []int
	total := 0
	for i, u := range units {
		if u.c.Seq != i+1 || u.c.RunID != 3 || u.c.Status != model.ChunkPending {
			t.Errorf("unit %d = %+v", i, u.c)
		}
		specs = append(specs, u.c.Spec)
		sizes = append(sizes, u.c.Size)
		prio = append(prio, u.c.Priority)
		total += u.c.Size
	}
	wantSpecs := [][]string{
		{"10.0.2.0/24"}, {"10.0.3.0/24"}, {"10.0.0.0/24"}, {"10.0.1.0/24"},
		{"10.0.8.1-3", "10.0.9.7", "192.168.1.128/25"}, // small blocks are packed together
	}
	if !reflect.DeepEqual(specs, wantSpecs) {
		t.Errorf("specs = %v", specs)
	}
	if !reflect.DeepEqual(sizes, []int{256, 256, 256, 256, 132}) || !reflect.DeepEqual(prio, []int{2, 1, 0, 0, 0}) {
		t.Errorf("sizes %v priorities %v", sizes, prio)
	}
	if int64(total) != st.V4.Count() {
		t.Errorf("planned %d addresses, scope has %d", total, st.V4.Count())
	}
	// every spec parses back to the same ranges (resume depends on it)
	for _, u := range units {
		back := targets.Build(u.c.Spec)
		if !reflect.DeepEqual(back.V4.Ranges(), u.ranges) {
			t.Errorf("spec %v does not round-trip: %v vs %v", u.c.Spec, back.V4.Ranges(), u.ranges)
		}
	}

	big := targets.Build([]string{"10.0.0.0/8"})
	units, err = buildUnits(1, big.V4, nil, nil, unitSizeFor(normalizeChunking(model.ChunkingOpts{}), 1<<24))
	if err != nil || len(units) > maxPlannedUnits {
		t.Fatalf("/8: %v, %d units", err, len(units))
	}
	if _, err := buildUnits(1, targets.Build([]string{"0.0.0.0/0"}).V4, nil, nil, 256); err == nil {
		t.Error("a /0 must be refused")
	}
}

func TestTakeGroupAndResumeUnits(t *testing.T) {
	st := targets.Build([]string{"10.0.0.0/21"})
	units, _ := buildUnits(1, st.V4, nil, nil, 256)
	g, rest := takeGroup(units, 896)
	if len(g.units) != 3 || g.size != 768 || len(rest) != 5 {
		t.Fatalf("group = %d units, %d addresses, rest %d", len(g.units), g.size, len(rest))
	}
	g, rest = takeGroup(rest, 100) // smaller than one unit: still one unit
	if len(g.units) != 1 || len(rest) != 4 {
		t.Fatalf("minimum group = %d units", len(g.units))
	}
	g, rest = takeGroup(rest, 1<<20)
	if len(g.units) != 4 || len(rest) != 0 {
		t.Fatalf("last group = %d units", len(g.units))
	}
	if g2, _ := takeGroup(nil, 256); g2 != nil {
		t.Error("no pending units, no group")
	}

	chunks := []model.Chunk{
		{ID: 11, Seq: 1, Spec: []string{"10.0.0.0/24"}, Size: 256, Status: model.ChunkDone},
		{ID: 12, Seq: 2, Spec: []string{"10.0.1.0/24"}, Size: 256, Status: model.ChunkDeferred},
		{ID: 13, Seq: 3, Spec: []string{"10.0.2.0/24"}, Size: 256, Status: model.ChunkPending, Priority: 4},
		{ID: 14, Seq: 4, Spec: []string{"10.0.3.5-9", "2001:db8::1"}, Size: 6, Status: model.ChunkFailed},
	}
	ex := targets.Build([]string{"10.0.1.0/25"}).V4
	us, err := unitsFromChunks(chunks, ex)
	if err != nil || len(us) != 3 {
		t.Fatalf("resume units: %v %d", err, len(us))
	}
	if us[0].c.ID != 13 || us[1].c.ID != 12 || us[1].c.Status != model.ChunkPending {
		t.Errorf("order must be priority first, then seq: %d %d", us[0].c.ID, us[1].c.ID)
	}
	if n := targets.NewSet(us[1].ranges...).Count(); n != 128 {
		t.Errorf("a new exclusion must apply on resume: %d addresses left", n)
	}
	if !us[2].isV6() || len(us[2].ranges) != 1 {
		t.Errorf("mixed chunk = %+v", us[2])
	}
	if _, err := unitsFromChunks([]model.Chunk{{Seq: 1, Spec: []string{"bogus"}}}, targets.Set{}); err == nil {
		t.Error("a broken spec must be an error")
	}
}

func TestBudgetSplit(t *testing.T) {
	b := NewBudget(500)
	if b.Share(2) != 250 || b.Share(3) != 166 || b.Share(1000) != 1 || b.Share(0) != 500 {
		t.Errorf("shares = %d %d %d %d", b.Share(2), b.Share(3), b.Share(1000), b.Share(0))
	}
	ctx := context.Background()
	a, _ := b.Acquire(ctx, 250)
	c, _ := b.Acquire(ctx, 200)
	d, _ := b.Acquire(ctx, 200) // only 50 left
	if a != 250 || c != 200 || d != 50 || b.InUse() != 500 {
		t.Fatalf("grants = %d %d %d, in use %d", a, c, d, b.InUse())
	}
	// the budget is spent: the next process waits until a share comes back
	got := make(chan int, 1)
	go func() {
		n, _ := b.Acquire(ctx, 300)
		got <- n
	}()
	select {
	case n := <-got:
		t.Fatalf("granted %d over the budget", n)
	case <-time.After(30 * time.Millisecond):
	}
	b.Release(c)
	select {
	case n := <-got:
		if n != 200 {
			t.Fatalf("granted %d, want the 200 that came back", n)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter was not woken")
	}
	if b.InUse() > 500 {
		t.Fatalf("in use %d > total", b.InUse())
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := b.Acquire(cctx, 10); err == nil {
		t.Error("a cancelled wait must return an error")
	}
}

func TestEffectiveLimits(t *testing.T) {
	p := model.ScanProfile{Rate: model.RateLimits{MaxPPS: 1000, MaxParallelChunks: 4, MaxParallelHosts: 16, HTTPRPS: 50, PerHostConcurrency: 3, PerHostDelayMs: 200}}
	pol := model.SafetyPolicy{MaxPPS: 300, MaxHTTPRPS: 20, MaxPerHostRPS: 2, MaxPathsPerHost: 5}
	l := EffectiveLimits(p, pol)
	if l.PPS != 300 || l.HTTPRPS != 20 || l.PerHostRPS != 2 || l.ParallelChunks != 4 || l.ParallelHosts != 16 || l.PerHostConc != 3 || l.PerHostDelay != 200*time.Millisecond || l.MaxPaths != 5 {
		t.Errorf("limits = %+v", l)
	}
	p.Rate.MaxPPS, p.Rate.HTTPRPS = 100, 5
	l = EffectiveLimits(p, pol)
	if l.PPS != 100 || l.HTTPRPS != 5 {
		t.Errorf("the profile may be stricter: %+v", l)
	}
	l = EffectiveLimits(model.ScanProfile{}, model.SafetyPolicy{})
	if l.PPS != defaultPPS || l.ParallelChunks != defaultParallelChunks || l.HTTPRPS != defaultHTTPRPS || l.MaxPaths != 0 {
		t.Errorf("defaults = %+v", l)
	}
	l = EffectiveLimits(model.ScanProfile{Rate: model.RateLimits{MaxPPS: 2, MaxParallelChunks: 8}}, model.SafetyPolicy{})
	if l.ParallelChunks != 2 {
		t.Errorf("workers must not exceed the packet budget: %+v", l)
	}
}

func TestEstimate(t *testing.T) {
	e := New(Deps{Prober: &fakeNet{}, Logger: quiet})
	plan := basePlan("172.16.0.0/16", "example.com")
	plan.Policy.Exclusions = []string{"172.16.255.0/24"}
	plan.Policy.MaxPPS = 500
	plan.Profile.Rate.MaxPPS = 2000
	plan.Profile.Ports = "top-100"
	est := e.Estimate(plan)
	if est.Addresses != 65536-256+1 || est.EffectivePPS != 500 || est.Chunks != 255+1 {
		t.Fatalf("estimate = %+v", est)
	}
	if est.EstPackets <= est.Addresses || est.EstDurationSec <= 0 || !est.FitsWindow || est.BasedOnHistory || est.ExpectedLiveRate != 0.05 {
		t.Errorf("estimate = %+v", est)
	}
	// duration follows the packet budget: packets / (pps * 0.85) plus overhead
	if min := est.EstPackets / 500; est.EstDurationSec < min {
		t.Errorf("duration %d s is under the packet budget %d s", est.EstDurationSec, min)
	}

	slow := plan
	slow.Policy.MaxPPS = 50
	if s := e.Estimate(slow); s.EstDurationSec < est.EstDurationSec*5 {
		t.Errorf("a tenth of the rate must take much longer: %d vs %d", s.EstDurationSec, est.EstDurationSec)
	}

	hist := plan
	hist.MeasuredPPS = 100
	h := e.Estimate(hist)
	if !h.BasedOnHistory || h.EstDurationSec != (h.EstPackets+99)/100 {
		t.Errorf("history estimate = %+v", h)
	}

	end := time.Now().Add(10 * time.Minute)
	win := plan
	win.WindowEnd = &end
	w := e.Estimate(win)
	if w.WindowSec < 590 || w.WindowSec > 600 || w.FitsWindow != (w.EstDurationSec <= w.WindowSec) {
		t.Errorf("window estimate = %+v", w)
	}
	short := time.Now().Add(5 * time.Second)
	win.WindowEnd = &short
	if e.Estimate(win).FitsWindow {
		t.Error("a /16 cannot fit into 5 seconds")
	}

	// hints raise the expected live rate
	hp := basePlan("10.0.0.0/24")
	for i := 0; i < 64; i++ {
		hp.Hints = append(hp.Hints, model.HostHint{IP: targets.IPString(0x0A000000 + uint32(i))})
	}
	if got := e.Estimate(hp).ExpectedLiveRate; got != 0.25 {
		t.Errorf("live rate = %v", got)
	}
	// resume: only the remaining chunks count
	rp := basePlan("10.0.0.0/22")
	rp.Chunks = []model.Chunk{{Seq: 3, Size: 256, Status: model.ChunkDeferred}, {Seq: 4, Size: 256, Status: model.ChunkPending}, {Seq: 1, Size: 256, Status: model.ChunkDone}}
	if r := e.Estimate(rp); r.Addresses != 512 || r.Chunks != 2 {
		t.Errorf("resume estimate = %+v", r)
	}
	if z := e.Estimate(basePlan()); z.Addresses != 0 || z.EstDurationSec != 0 {
		t.Errorf("empty plan = %+v", z)
	}
}

func TestStatsKeeper(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	prev := &model.RunStats{AddressesTotal: 1000, AddressesDone: 400, PacketsSent: 2000, ElapsedSec: 20, HostsUp: 3}
	k := newStatsKeeper(prev, clock)
	k.update(func(s *model.RunStats) { s.AddressesTotal = 1000 })
	t0 := now
	now = now.Add(4 * time.Second)
	k.addStage(1200, t0, now) // 300 pps for 4 s
	k.update(func(s *model.RunStats) { s.AddressesDone += 200 })
	s := k.snapshot()
	if s.PacketsSent != 3200 || s.ElapsedSec != 24 || s.HostsUp != 3 {
		t.Errorf("snapshot = %+v", s)
	}
	if s.CurrentPPS != 300 {
		t.Errorf("current pps = %v, want 300", s.CurrentPPS)
	}
	if s.AvgPPS != round1(3200.0/24) {
		t.Errorf("avg pps = %v", s.AvgPPS)
	}
	// 200 addresses in 4 s this session, 400 left → 8 s
	if s.ETASec != 8 {
		t.Errorf("eta = %d, want 8", s.ETASec)
	}
	now = now.Add(10 * time.Second) // nothing sent for 10 s
	if s = k.snapshot(); s.CurrentPPS != 0 {
		t.Errorf("current pps after silence = %v", s.CurrentPPS)
	}
	k.update(func(s *model.RunStats) { s.AddressesDone = 1000 })
	if s = k.snapshot(); s.ETASec != 0 {
		t.Errorf("eta when done = %d", s.ETASec)
	}
}
