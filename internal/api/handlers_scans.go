package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
)

func (s *Server) listProfiles(w http.ResponseWriter, r *http.Request) {
	q := query(r)
	o := q.opts()
	if !q.ok(w) {
		return
	}
	page, err := s.st.ListProfiles(r.Context(), o)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.st.GetProfile(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// profileDefaults fills the zero values of a new profile with safe defaults.
func profileDefaults(p *model.ScanProfile) {
	if p.Ports == "" {
		p.Ports = "top-1000"
	}
	d := &p.Discovery
	if !d.ICMPEcho && !d.ICMPTimestamp && !d.ARP && !d.SkipDiscovery && len(d.TCPSynPorts) == 0 && len(d.TCPAckPorts) == 0 {
		d.ICMPEcho, d.TCPSynPorts, d.TCPAckPorts = true, []int{80, 443}, []int{80}
	}
	if p.Rate.MaxPPS == 0 {
		p.Rate.MaxPPS = 500
	}
	if p.Rate.MaxParallelChunks == 0 {
		p.Rate.MaxParallelChunks = 4
	}
	if p.Rate.MaxParallelHosts == 0 {
		p.Rate.MaxParallelHosts = 16
	}
	if p.Rate.HTTPRPS == 0 {
		p.Rate.HTTPRPS = 20
	}
	if p.Rate.PerHostConcurrency == 0 {
		p.Rate.PerHostConcurrency = 1
	}
	if p.Chunking.InitialSize == 0 {
		p.Chunking = model.ChunkingOpts{Adaptive: true, InitialSize: 256, MinSize: 64, MaxSize: 4096, TargetSeconds: 60}
	}
	if p.HTTP.MaxBodyBytes == 0 {
		p.HTTP.MaxBodyBytes = 262144
	}
	if p.HTTP.TimeoutMs == 0 {
		p.HTTP.TimeoutMs = 5000
	}
	if p.Schedule.Timezone == "" {
		p.Schedule.Timezone = "Europe/Warsaw"
	}
}

// checkProfile validates a profile. A profile can only be stricter than the safety policy.
func (s *Server) checkProfile(r *http.Request, p *model.ScanProfile) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 200 {
		return invalid("the profile needs a name of at most 200 characters")
	}
	if p.ScopeIDs == nil {
		p.ScopeIDs = []int64{}
	}
	for _, id := range p.ScopeIDs {
		if _, err := s.st.GetScope(r.Context(), id); err != nil {
			return invalid("scope %d does not exist", id)
		}
	}
	policy, err := s.st.GetSafetyPolicy(r.Context())
	if err != nil {
		return err
	}
	switch {
	case p.Rate.MaxPPS < 1:
		return invalid("rate.max_pps must be at least 1")
	case p.Rate.MaxPPS > policy.MaxPPS:
		return invalid("rate.max_pps %d is above the cap of the safety policy (%d)", p.Rate.MaxPPS, policy.MaxPPS)
	case p.Rate.HTTPRPS < 0 || p.Rate.HTTPRPS > policy.MaxHTTPRPS:
		return invalid("rate.http_rps %g is above the cap of the safety policy (%g)", p.Rate.HTTPRPS, policy.MaxHTTPRPS)
	case p.Rate.MaxParallelChunks < 1 || p.Rate.MaxParallelChunks > 64:
		return invalid("rate.max_parallel_chunks must be between 1 and 64")
	case p.Rate.MaxParallelHosts < 1 || p.Rate.MaxParallelHosts > 1024:
		return invalid("rate.max_parallel_hosts must be between 1 and 1024")
	case p.VersionIntensity < 0 || p.VersionIntensity > 9:
		return invalid("version_intensity must be between 0 and 9")
	case p.Chunking.MinSize < 1 || p.Chunking.MaxSize < p.Chunking.MinSize || p.Chunking.InitialSize < p.Chunking.MinSize || p.Chunking.InitialSize > p.Chunking.MaxSize:
		return invalid("chunking needs 1 <= min_size <= initial_size <= max_size")
	case p.Chunking.TargetSeconds < 1:
		return invalid("chunking.target_seconds must be at least 1")
	case p.Retry.UnstableRetries < 0 || p.Retry.UnstableRetries > 10:
		return invalid("retry.unstable_retries must be between 0 and 10")
	case p.HTTP.MaxRedirects < 0 || p.HTTP.MaxRedirects > 10:
		return invalid("http.max_redirects must be between 0 and 10")
	case p.Schedule.IntervalMinutes < 0:
		return invalid("schedule.interval_minutes must not be negative")
	}
	if strings.ContainsAny(p.Ports, " ;|&$`'\"\\\n") {
		return invalid("ports must be an nmap port list such as top-100 or 22,80,443,8000-8100")
	}
	if _, err := time.LoadLocation(p.Schedule.Timezone); err != nil {
		return invalid("schedule.timezone %q is not an IANA timezone", p.Schedule.Timezone)
	}
	for _, win := range p.Schedule.Windows {
		for _, v := range []string{win.Start, win.End} {
			if _, err := time.Parse("15:04", v); err != nil {
				return invalid("a window time must be HH:MM, got %q", v)
			}
		}
		for _, d := range win.Days {
			if d < 0 || d > 6 {
				return invalid("window days are 0 (Sunday) to 6 (Saturday)")
			}
		}
	}
	return nil
}

var profileFields = []string{"name", "description", "scope_ids", "ports", "discovery", "service_detection", "version_intensity", "http", "rate",
	"chunking", "retry", "schedule", "enabled"}

func (s *Server) createProfile(w http.ResponseWriter, r *http.Request) {
	var raw map[string]json.RawMessage
	if !decode(w, r, &raw) {
		return
	}
	p := model.ScanProfile{Enabled: true, ServiceDetection: true, VersionIntensity: 5,
		HTTP: model.HTTPOpts{Enabled: true, MaxRedirects: 3, SignaturePaths: true, Favicon: true}, Retry: model.RetryOpts{UnstableRetries: 2, BackoffMs: 500}}
	for k := range raw { // ignore read-only fields that a client echoes back
		switch k {
		case "id", "next_run_at", "last_run_id", "created_at", "updated_at":
			delete(raw, k)
		}
	}
	err := mergePatch(&p, raw, profileFields...)
	if err == nil {
		profileDefaults(&p)
		err = s.checkProfile(r, &p)
	}
	if err == nil {
		p, err = s.st.CreateProfile(r.Context(), p)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.d.Hooks.ProfileChanged != nil {
		s.d.Hooks.ProfileChanged(r.Context(), p, false)
	}
	auditSet(r, "", "", p.ID, map[string]any{"name": p.Name})
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var raw map[string]json.RawMessage
	if !decode(w, r, &raw) {
		return
	}
	for k := range raw {
		switch k {
		case "id", "next_run_at", "last_run_id", "created_at", "updated_at":
			delete(raw, k)
		}
	}
	p, err := s.st.GetProfile(r.Context(), id)
	if err == nil {
		err = mergePatch(&p, raw, profileFields...)
	}
	if err == nil {
		err = s.checkProfile(r, &p)
	}
	if err == nil {
		p, err = s.st.UpdateProfile(r.Context(), p)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.d.Hooks.ProfileChanged != nil {
		s.d.Hooks.ProfileChanged(r.Context(), p, false)
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) deleteProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.st.GetProfile(r.Context(), id)
	if err == nil {
		var active model.Page[model.ScanRun]
		if active, err = s.st.ListRuns(r.Context(), store.RunFilter{ProfileID: id, Status: store.ActiveStatuses}); err == nil && active.Total > 0 {
			writeErr(w, http.StatusConflict, "conflict", "the profile has an active run; cancel it first")
			return
		}
	}
	if err == nil {
		err = s.st.DeleteProfile(r.Context(), id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.d.Hooks.ProfileChanged != nil {
		s.d.Hooks.ProfileChanged(r.Context(), p, true)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) estimateProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if s.d.Runner == nil {
		notWired(w, "the run manager")
		return
	}
	est, err := s.d.Runner.Estimate(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, est)
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	q := query(r)
	f := store.RunFilter{ListOpts: q.opts(), ProfileID: q.int64("profile_id"), Status: q.list("status"), Trigger: q.str("trigger")}
	if !q.ok(w) {
		return
	}
	page, err := s.st.ListRuns(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	run, err := s.st.GetRun(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ProfileID int64 `json:"profile_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	auditSet(r, "run.start", "run", nil, map[string]any{"profile_id": in.ProfileID})
	if in.ProfileID <= 0 {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "profile_id is required")
		return
	}
	if s.d.Runner == nil {
		notWired(w, "the run manager")
		return
	}
	run, err := s.d.Runner.Start(r.Context(), in.ProfileID, userID(r), "manual")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "", "", run.ID, map[string]any{"profile": run.ProfileName})
	writeJSON(w, http.StatusCreated, run)
}

func (s *Server) runAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		if s.d.Runner == nil {
			notWired(w, "the run manager")
			return
		}
		var run model.ScanRun
		var err error
		switch action {
		case "pause":
			run, err = s.d.Runner.Pause(r.Context(), id)
		case "resume":
			run, err = s.d.Runner.Resume(r.Context(), id)
		default:
			run, err = s.d.Runner.Cancel(r.Context(), id)
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, run)
	}
}

func (s *Server) listChunks(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.st.GetRun(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	chunks, err := s.st.ListChunks(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, chunks)
}

type mapBlock struct {
	CIDR    string `json:"cidr"`
	Size    int    `json:"size"`
	Status  string `json:"status"`
	HostsUp int    `json:"hosts_up"`
}

const maxMapBlocks = 16384

// runMap returns the /24 blocks of a run with the state of their chunk, for the address-space map.
func (s *Server) runMap(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.st.GetRun(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	chunks, err := s.st.ListChunks(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	up, err := s.st.RunHostsUpByBlock(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// A block that several chunks touch shows the most active state.
	rank := map[string]int{"done": 1, "failed": 2, "pending": 3, "deferred": 4, "running": 5}
	blocks := map[string]*mapBlock{}
	truncated := false
	for _, c := range chunks {
		for _, spec := range c.Spec {
			for _, cidr := range blocks24(spec, maxMapBlocks) {
				b, ok := blocks[cidr]
				if !ok {
					if len(blocks) >= maxMapBlocks {
						truncated = true
						break
					}
					b = &mapBlock{CIDR: cidr, Size: 256, HostsUp: up[cidr]}
					blocks[cidr] = b
				}
				if rank[string(c.Status)] > rank[b.Status] {
					b.Status = string(c.Status)
				}
			}
		}
	}
	out := make([]mapBlock, 0, len(blocks))
	for _, b := range blocks {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParsePrefix(out[i].CIDR)
		b, _ := netip.ParsePrefix(out[j].CIDR)
		return a.Addr().Less(b.Addr())
	})
	writeJSON(w, http.StatusOK, map[string]any{"blocks": out, "truncated": truncated})
}

// ---------- server-sent events ----------

type sse struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func newSSE(w http.ResponseWriter) *sse {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache, no-store")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // a stream has no write deadline
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()
	return &sse{w: w, rc: rc}
}

func (e *sse) send(event string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(e.w, "event: %s\ndata: %s\n\n", event, b); err != nil {
		return err
	}
	return e.rc.Flush()
}

func (e *sse) ping() error {
	if _, err := fmt.Fprint(e.w, ": ping\n\n"); err != nil {
		return err
	}
	return e.rc.Flush()
}

func finished(st model.RunStatus) bool {
	return st == model.RunCompleted || st == model.RunFailed || st == model.RunCancelled || st == model.RunPaused
}

// runEvents streams the progress of one run: progress, chunk, host, done.
func (s *Server) runEvents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	// Subscribe before reading the state, so no event between the two is lost.
	events, cancel := s.d.Bus.Subscribe(id)
	defer cancel()
	run, err := s.st.GetRun(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	stream := newSSE(w)
	if err := stream.send(runner.EventProgress, run); err != nil {
		return
	}
	if finished(run.Status) {
		_ = stream.send(runner.EventDone, run)
		return
	}
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-events:
			if err := stream.send(ev.Type, ev.Data); err != nil || ev.Type == runner.EventDone {
				return
			}
		case <-tick.C:
			if err := stream.ping(); err != nil {
				return
			}
		}
	}
}

// globalEvents streams run status changes, new changes and new findings.
func (s *Server) globalEvents(w http.ResponseWriter, r *http.Request) {
	events, cancel := s.d.Bus.Subscribe(0)
	defer cancel()
	stream := newSSE(w)
	if err := stream.ping(); err != nil {
		return
	}
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-events:
			if err := stream.send(ev.Type, ev.Data); err != nil {
				return
			}
		case <-tick.C:
			if err := stream.ping(); err != nil {
				return
			}
		}
	}
}
