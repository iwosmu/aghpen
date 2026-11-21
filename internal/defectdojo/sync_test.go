package defectdojo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/interchange"
	"github.com/iwosmu/aghpen/internal/model"
)

func i64(v int64) *int64 { return &v }

func TestProposeStatusUpdates(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	f := func(id int64, st model.FindingStatus, dojo int64) model.Finding {
		return model.Finding{ID: id, Key: "k" + strconv.FormatInt(id, 10), Status: st, DojoID: i64(dojo)}
	}
	remote := map[int64]RemoteStatus{
		1: {DojoID: 1, Flags: interchange.DojoFlags{FalseP: true}, ChangedAt: t0},
		2: {DojoID: 2, Flags: interchange.DojoFlags{Active: true, Verified: true}, ChangedAt: t0.Add(time.Hour)},
		3: {DojoID: 3, Flags: interchange.DojoFlags{IsMitigated: true}, ChangedAt: t0},
		4: {DojoID: 4, Flags: interchange.DojoFlags{RiskAccepted: true}, ChangedAt: t0},
		5: {DojoID: 5, Flags: interchange.DojoFlags{Active: true}, ChangedAt: t0.Add(time.Hour)},
		6: {DojoID: 6, Missing: true},
		7: {DojoID: 7, Flags: interchange.DojoFlags{Active: true, Verified: true}, ChangedAt: t0},
	}
	local := []LocalStatus{
		{Finding: f(11, model.FindingNew, 1)},                                   // scanner status: DefectDojo wins
		{Finding: f(12, model.FindingFalsePositive, 2), ChangedAt: t0},          // DefectDojo newer: wins
		{Finding: f(13, model.FindingTriaged, 3), ChangedAt: t0.Add(time.Hour)}, // Czujka newer: conflict
		{Finding: f(14, model.FindingTriaged, 4)},                               // no edit time: conflict
		{Finding: f(15, model.FindingAccepted, 5), ChangedAt: t0},               // DefectDojo "new": no decision
		{Finding: f(16, model.FindingNew, 6)},                                   // deleted in DefectDojo
		{Finding: f(17, model.FindingTriaged, 7)},                               // same status
		{Finding: model.Finding{ID: 18, Status: model.FindingNew}},              // not exported
	}
	out := ProposeStatusUpdates(local, remote)
	if out.Checked != 7 || len(out.Updates) != 2 || len(out.Conflicts) != 3 || len(out.Missing) != 1 || out.Missing[0] != 16 {
		t.Fatalf("%+v", out)
	}
	if u := out.Updates[0]; u.FindingID != 11 || u.To != model.FindingFalsePositive || !strings.Contains(u.Reason, "skaner") {
		t.Errorf("update 0 %+v", u)
	}
	if u := out.Updates[1]; u.FindingID != 12 || u.To != model.FindingTriaged || !strings.Contains(u.Reason, "nowsza") {
		t.Errorf("update 1 %+v", u)
	}
	// Overrides["status"].At counts as the edit time too.
	l := LocalStatus{Finding: f(19, model.FindingTriaged, 3)}
	l.Finding.Overrides = map[string]model.Override{"status": {At: t0.Add(-time.Hour)}}
	if out := ProposeStatusUpdates([]LocalStatus{l}, remote); len(out.Updates) != 1 || out.Updates[0].To != model.FindingResolved {
		t.Errorf("override time: %+v", out)
	}
}

// syncFake answers the routes of the status pull and the lifecycle.
type syncFake struct {
	mu      sync.Mutex
	finding map[int64]map[string]any
	patches map[int64]map[string]any
	notes   map[int64][]string
	files   []string
}

func (s *syncFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v2/"), "/"), "/")
	if len(parts) < 2 {
		w.WriteHeader(404)
		return
	}
	id, _ := strconv.ParseInt(parts[1], 10, 64)
	switch {
	case parts[0] == "findings" && len(parts) == 2 && r.Method == http.MethodGet:
		f, ok := s.finding[id]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"detail":"Not found."}`)
			return
		}
		json.NewEncoder(w).Encode(f)
	case parts[0] == "findings" && len(parts) == 2 && r.Method == http.MethodPatch:
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if _, bad := body["mitigated"]; bad {
			w.WriteHeader(400) // DefectDojo 3.5 with EDITABLE_MITIGATED_DATA=false
			io.WriteString(w, `{"mitigated":["Editing mitigated timestamp is disabled"]}`)
			return
		}
		s.patches[id] = body
		for k, v := range body {
			s.finding[id][k] = v
		}
		json.NewEncoder(w).Encode(s.finding[id])
	case parts[0] == "findings" && len(parts) == 3 && parts[2] == "notes":
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		s.notes[id] = append(s.notes[id], body["entry"].(string))
		w.WriteHeader(201)
		io.WriteString(w, `{}`)
	case len(parts) == 3 && parts[2] == "files" && r.Method == http.MethodPost:
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			w.WriteHeader(400)
			return
		}
		fh := r.MultipartForm.File["file"]
		if len(fh) != 1 || r.FormValue("title") == "" {
			w.WriteHeader(400)
			return
		}
		s.files = append(s.files, parts[0]+"/"+parts[1]+":"+r.FormValue("title")+":"+fh[0].Filename)
		w.WriteHeader(201)
		io.WriteString(w, `{}`)
	default:
		w.WriteHeader(404)
	}
}

func newSyncFake() (*syncFake, *Client, func()) {
	s := &syncFake{finding: map[int64]map[string]any{}, patches: map[int64]map[string]any{}, notes: map[int64][]string{}}
	srv := httptest.NewServer(s)
	c, err := New(Config{URL: srv.URL, APIKey: "t"})
	if err != nil {
		panic(err)
	}
	return s, c, srv.Close
}

func TestSyncLifecycleClosesAndReopens(t *testing.T) {
	s, c, stop := newSyncFake()
	defer stop()
	s.finding[1] = map[string]any{"id": 1, "active": true, "is_mitigated": false}
	s.finding[2] = map[string]any{"id": 2, "active": false, "is_mitigated": true}
	s.finding[3] = map[string]any{"id": 3, "active": false, "is_mitigated": true, "false_p": true}
	s.finding[4] = map[string]any{"id": 4, "active": true, "is_mitigated": false}
	t0 := time.Date(2026, 11, 21, 13, 0, 0, 0, time.UTC)
	findings := []model.Finding{
		{Key: "a", Status: model.FindingResolved, DojoID: i64(1), LastSeen: t0, LastRunID: 7}, // close
		{Key: "b", Status: model.FindingNew, DojoID: i64(2), LastSeen: t0, LastRunID: 8},      // reopen
		{Key: "c", Status: model.FindingNew, DojoID: i64(3)},                                  // false positive there: keep
		{Key: "d", Status: model.FindingTriaged, DojoID: i64(4)},                              // already open
		{Key: "e", Status: model.FindingResolved, DojoID: i64(99)},                            // deleted there
		{Key: "f", Status: model.FindingResolved},                                             // not exported
	}
	res, err := c.SyncLifecycle(context.Background(), findings, t0)
	if err != nil || res.Closed != 1 || res.Reopened != 1 || res.Skipped != 4 || len(res.Errors) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	if p := s.patches[1]; p["is_mitigated"] != true || p["active"] != false {
		t.Errorf("close patch %v", p)
	}
	if p := s.patches[2]; p["is_mitigated"] != false || p["active"] != true {
		t.Errorf("reopen patch %v", p)
	}
	if len(s.notes[1]) != 1 || !strings.Contains(s.notes[1][0], "nie jest już widoczna") || !strings.Contains(s.notes[2][0], "znów widoczna") {
		t.Errorf("notes %v", s.notes)
	}
	if _, touched := s.patches[3]; touched {
		t.Error("a false positive in DefectDojo must not be reopened")
	}
	// The pull reads the same routes and proposes, without writing.
	before := len(s.patches)
	pull, err := c.PullStatus(context.Background(), []LocalStatus{{Finding: model.Finding{ID: 3, Status: model.FindingNew, DojoID: i64(3)}}})
	if err != nil || len(pull.Updates) != 1 || pull.Updates[0].To != model.FindingFalsePositive || len(s.patches) != before {
		t.Fatalf("%v %+v", err, pull)
	}
}

func TestAttachEvidenceAndRunXML(t *testing.T) {
	s, c, stop := newSyncFake()
	defer stop()
	n, errs := c.AttachEvidence(context.Background(), []model.Finding{
		{Key: "admin-panel/10.0.0.1/tcp-80/x", Title: "Panel", IP: "10.0.0.1", Port: 80, DojoID: i64(5),
			Evidence: []model.Evidence{{Matcher: "title", Where: "title", Snippet: "Admin"}}},
		{Key: "not-exported"},
	})
	if n != 1 || len(errs) != 0 {
		t.Fatalf("%d %v", n, errs)
	}
	if err := c.AttachRunXML(context.Background(), 19, 42, []byte("<nmaprun/>")); err != nil {
		t.Fatal(err)
	}
	want := []string{"findings/5:Czujka: dowody admin-panel/10.0.0.1/tcp-80/x:czujka-evidence-admin-panel_10.0.0.1_tcp-80_x.txt",
		"tests/19:Czujka: nmap XML przebiegu #42:czujka-run-42.xml"}
	if strings.Join(s.files, "|") != strings.Join(want, "|") {
		t.Errorf("files %v", s.files)
	}
	if err := c.AttachFile(context.Background(), "products", 1, "x", "x", nil); err == nil {
		t.Error("only tests and findings take files")
	}
	ev := string(EvidenceText(model.Finding{Key: "k", IP: "10.0.0.1", Evidence: []model.Evidence{{Matcher: "cookie", Where: "cookie:sid", Snippet: "sid (HttpOnly)"}}}))
	if !strings.Contains(ev, "Klucz: k") || !strings.Contains(ev, "[cookie] cookie:sid") {
		t.Errorf("evidence %q", ev)
	}
}

func TestTargetForScopes(t *testing.T) {
	def := Target{ProductTypeName: "Czujka", ProductName: "Czujka – Attack Surface", EngagementName: "Czujka discovery"}
	maps := []ScopeMapping{
		{ScopeID: 1, ProductName: "Kampus"},
		{ScopeID: 2, ProductName: "Laboratorium", EngagementName: "Skan tygodniowy", ProductTypeName: "Uczelnia"},
	}
	if got := TargetFor([]int64{1}, maps, def); got.ProductName != "Kampus" || got.EngagementName != def.EngagementName || got.ProductTypeName != "Czujka" {
		t.Errorf("scope 1 %+v", got)
	}
	if got := TargetFor([]int64{9, 2}, maps, def); got.ProductName != "Laboratorium" || got.EngagementName != "Skan tygodniowy" || got.ProductTypeName != "Uczelnia" {
		t.Errorf("scope 2 %+v", got)
	}
	if got := TargetFor([]int64{9}, maps, def); got != def {
		t.Errorf("no mapping %+v", got)
	}
	groups := GroupByTarget([]model.Finding{{Key: "a", HostID: 1}, {Key: "b", HostID: 2}, {Key: "c", HostID: 3}},
		func(f model.Finding) []int64 { return []int64{f.HostID} }, maps, def)
	if len(groups) != 3 || len(groups[def]) != 1 {
		t.Errorf("groups %v", groups)
	}
}
