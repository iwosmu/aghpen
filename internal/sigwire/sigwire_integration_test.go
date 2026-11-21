package sigwire_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/sig"
	"github.com/iwosmu/aghpen/internal/sigwire"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// These tests need a real PostgreSQL (CZUJKA_TEST_DB_URL); without it they skip.

func newWire(t *testing.T) (*sigwire.Wire, *store.Store, *bytes.Buffer) {
	t.Helper()
	st := storetest.New(t)
	var logs bytes.Buffer
	w := sigwire.New(st, slog.New(slog.NewTextHandler(&logs, nil)))
	return w, st, &logs
}

func bySlug(t *testing.T, st *store.Store, slug string) model.Signature {
	t.Helper()
	var out model.Signature
	found := false
	err := st.EachSignature(context.Background(), store.SignatureFilter{}, func(s *model.Signature) error {
		if s.Slug == slug {
			out, found = *s, true
		}
		return nil
	})
	if err != nil || !found {
		t.Fatalf("signature %q: found=%v err=%v", slug, found, err)
	}
	return out
}

func countRows(t *testing.T, st *store.Store, where string) int {
	t.Helper()
	var n int
	if err := st.Pool().QueryRow(context.Background(), "SELECT count(*) FROM signatures WHERE "+where).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

const customPortal = `id: portal-agh
name: Portal AGH
category: cms
author: analityk
interest: 30
tags: [uczelnia]
match:
  rules:
    - {type: body, contains: 'Portal AGH', weight: 0.9}
`

func TestSeedAndReload(t *testing.T) {
	ctx := context.Background()
	w, st, logs := newWire(t)
	lib, err := sig.Builtin()
	if err != nil {
		t.Fatal(err)
	}

	// First start: every built-in becomes a row and the engine is loaded.
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, st, "builtin"); n != len(lib) {
		t.Fatalf("built-in rows = %d, library = %d", n, len(lib))
	}
	rep := w.LastReload()
	if rep.Rows != len(lib) || rep.Loaded != len(lib) || rep.Enabled != len(lib) || len(rep.Rejected) != 0 || rep.Paths == 0 {
		t.Fatalf("reload report = %+v", rep)
	}
	t.Logf("seed + reload: %d built-in signatures, %d extra paths, reload took %d ms", rep.Loaded, rep.Paths, rep.TookMs)
	total, enabled := w.Engine().Count()
	if total != len(lib) || enabled != len(lib) {
		t.Fatalf("engine count = %d/%d", total, enabled)
	}
	svc := &model.ServiceResult{Name: "http", HTTP: &model.HTTPFingerprint{Status: 200, Headers: map[string][]string{"Server": {"nginx/1.24.0"}},
		BodyExcerpt: "<h1>Portal AGH</h1>"}}
	_, techs, _ := w.Engine().Match(svc)
	if len(techs) != 1 || techs[0].Name != "nginx" || techs[0].Version != "1.24.0" {
		t.Fatalf("technologies = %+v", techs)
	}
	engineBefore := w.Engine()

	// The analyst disables a built-in, adds a custom signature and edits nothing else.
	ng := bySlug(t, st, "nginx")
	ng.Enabled = false
	if _, err := st.UpdateSignature(ctx, ng); err != nil {
		t.Fatal(err)
	}
	_, meta := w.Validate(customPortal)
	meta.Enabled = true
	if _, err := st.CreateSignature(ctx, meta); err != nil {
		t.Fatal(err)
	}
	// A row that an older version stored and that is unsafe today, and one that is broken.
	for _, bad := range []model.Signature{
		{Slug: "old-unsafe", Name: "Old unsafe", YAML: "id: old-unsafe\nname: Old unsafe\nrequests:\n  - {path: /login, method: POST}\nbody: x\n", Enabled: true},
		{Slug: "broken", Name: "Broken", YAML: "id: broken\nname: [", Enabled: true},
	} {
		if _, err := st.CreateSignature(ctx, bad); err != nil {
			t.Fatal(err)
		}
	}
	// A built-in whose stored YAML is older than the embedded one, and a retired built-in.
	if _, err := st.Pool().Exec(ctx, "UPDATE signatures SET yaml = yaml || E'\\n# old copy\\n' WHERE slug = 'apache'"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSignature(ctx, model.Signature{Slug: "retired-builtin", Name: "Retired", YAML: "id: retired-builtin\nname: Retired\nbody: zzz\n", Enabled: true, Builtin: true}); err != nil {
		t.Fatal(err)
	}

	// The hook reloads at once: the disabled built-in stops matching, the custom one starts.
	logs.Reset()
	w.Changed(ctx)
	rep = w.LastReload()
	if rep.Rows != len(lib)+4 || rep.Loaded != len(lib)+2 || rep.Enabled != len(lib)+1 || len(rep.Rejected) != 2 {
		t.Fatalf("after change: %+v", rep)
	}
	rejected := map[string]bool{}
	for _, r := range rep.Rejected {
		rejected[r.Slug] = true
	}
	if !rejected["old-unsafe"] || !rejected["broken"] {
		t.Errorf("rejected = %+v", rep.Rejected)
	}
	if out := logs.String(); !strings.Contains(out, "signature rejected") || !strings.Contains(out, "slug=old-unsafe") || !strings.Contains(out, "POST") || !strings.Contains(out, "slug=broken") {
		t.Errorf("the log must name the rejected signatures and the reason:\n%s", out)
	}
	for _, p := range w.Engine().ExtraPaths() {
		if p == "/login" {
			t.Error("the path of a rejected signature must never be requested")
		}
	}
	matches, techs, _ := w.Engine().Match(svc)
	if len(techs) != 1 || techs[0].Name != "Portal AGH" {
		t.Fatalf("after change: technologies = %+v, matches = %+v", techs, matches)
	}
	if w.Engine() != engineBefore {
		t.Error("the engine pointer must stay the same across reloads: the scan engine holds it")
	}

	// Upgrade: a second start keeps the analyst's choices and refreshes the library.
	w2 := sigwire.New(st, slog.New(slog.NewTextHandler(logs, nil)))
	seed, err := w2.Seed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if seed.Builtin != len(lib) || seed.Removed != 1 {
		t.Errorf("seed report = %+v", seed)
	}
	if bySlug(t, st, "nginx").Enabled {
		t.Error("a built-in that the analyst disabled must stay disabled after an upgrade")
	}
	if a := bySlug(t, st, "apache"); strings.Contains(a.YAML, "# old copy") || !a.Builtin {
		t.Error("a built-in with an old YAML must be refreshed from the embedded library")
	}
	if p := bySlug(t, st, "portal-agh"); p.Builtin || !p.Enabled || p.YAML != customPortal || p.Author != "analityk" {
		t.Errorf("a custom signature must not be touched: %+v", p)
	}
	if n := countRows(t, st, "slug = 'retired-builtin'"); n != 0 {
		t.Error("a built-in that the library no longer has must be removed")
	}
	if n := countRows(t, st, "builtin"); n != len(lib) {
		t.Errorf("built-in rows after upgrade = %d", n)
	}
	if _, err := w2.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if _, techs, _ := w2.Engine().Match(svc); len(techs) != 1 || techs[0].Name != "Portal AGH" {
		t.Errorf("after upgrade: %+v", techs)
	}
	// Seeding twice changes nothing.
	before := bySlug(t, st, "wordpress").UpdatedAt
	if _, err := w2.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	if after := bySlug(t, st, "wordpress").UpdatedAt; !after.Equal(before) {
		t.Error("a second seed with the same library must not rewrite the rows")
	}
}

func TestValidateAdapter(t *testing.T) {
	w := sigwire.New(nil, nil) // Validate needs no store
	val, meta := w.Validate(customPortal)
	if !val.OK || val.Issues == nil || val.Paths == nil {
		t.Fatalf("validation = %+v", val)
	}
	if meta.Slug != "portal-agh" || meta.Name != "Portal AGH" || meta.Category != model.CatCMS || meta.Author != "analityk" || meta.Interest != 30 ||
		len(meta.Tags) != 1 || meta.Tags[0] != "uczelnia" || meta.YAML != customPortal {
		t.Errorf("meta = %+v", meta)
	}
	val, meta = w.Validate("id: evil\nname: Evil\nrequests:\n  - {path: /login, method: POST}\nbody: x\n")
	if val.OK || meta.Slug != "" {
		t.Errorf("an unsafe signature must fail and give no meta: %+v %+v", val, meta)
	}
	safety := false
	for _, is := range val.Issues {
		safety = safety || is.Safety
	}
	if !safety {
		t.Error("the issue must be marked as a safety problem (the API answers unsafe_signature)")
	}
	val, _ = w.Validate("- {id: a, name: A, body: x}\n- {id: b, name: B, body: y}\n")
	if val.OK || !strings.Contains(val.Issues[len(val.Issues)-1].Message, "2 sygnatur") {
		t.Errorf("two signatures in one record must be refused: %+v", val)
	}
	val, meta = w.Validate("")
	if val.OK || meta.Slug != "" {
		t.Error("an empty text must fail")
	}
}

func webSvc(port int, title, body, server string, matches ...string) model.ServiceResult {
	svc := model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: "http", HTTP: &model.HTTPFingerprint{
		Scheme: "http", Status: 200, Title: title, BodyExcerpt: body, Headers: map[string][]string{"Server": {server}}, Server: server,
		Cookies: []model.Cookie{{Name: "PHPSESSID", Value: "secret-session-value", ValueLen: 20}},
	}}
	for _, m := range matches {
		svc.Matches = append(svc.Matches, model.SigMatch{Signature: m, Name: m, Confidence: 0.9, Evidence: []model.Evidence{{Matcher: "body", Where: "body", Snippet: "x"}}})
	}
	return svc
}

func ingest(t *testing.T, st *store.Store, hosts []model.HostResult) {
	t.Helper()
	if err := st.IngestHosts(context.Background(), hosts, store.SinkOptions{Source: "scan"}); err != nil {
		t.Fatal(err)
	}
}

const sigLogin = `id: portal-login
name: Portal login
category: cms
requests: [/login]
match:
  min_confidence: 0.5
  rules:
    - {type: body, contains: 'Portal AGH', weight: 0.6}
    - {type: path, path: /login, status: 200, contains: 'name="password"', weight: 0.9}
    - {type: header, name: Server, regex: '^nginx/([0-9.]+)', weight: 0.3, version_group: 1}
`

func TestRetroHuntOverStoredObservations(t *testing.T) {
	ctx := context.Background()
	w, st, _ := newWire(t)
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	run1, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunRunning, ProfileName: "noc 1"})
	if err != nil {
		t.Fatal(err)
	}
	run2, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunRunning, ProfileName: "noc 2"})
	if err != nil {
		t.Fatal(err)
	}
	at1 := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
	at2 := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)

	portal := webSvc(80, "Portal", "<h1>Portal AGH</h1>", "nginx/1.24.0", "nginx")
	portal.HTTP.URL = "http://portal.example.edu/"
	portal.HTTP.Paths = []model.PathProbe{{Path: "/login", Status: 200, Excerpt: `<form><input name="password" type="password"></form>`}}
	portalNoPath := webSvc(8080, "Portal", "<h1>Portal AGH</h1> kopia", "nginx/1.18.0", "nginx")
	other := webSvc(80, "Inna strona", "<p>nic</p>", "Apache/2.4.57", "apache")
	ssh := model.ServiceResult{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Banner: "SSH-2.0-OpenSSH_9.6"}

	// Run 1: the portal did not have the marker yet. Run 2: it has.
	old := webSvc(80, "Portal", "<h1>Stary portal</h1>", "nginx/1.24.0")
	ingest(t, st, []model.HostResult{{RunID: run1.ID, IP: "10.20.0.5", Up: true, ObservedAt: at1, Services: []model.ServiceResult{old}}})
	ingest(t, st, []model.HostResult{
		{RunID: run2.ID, IP: "10.20.0.5", Up: true, ObservedAt: at2, Services: []model.ServiceResult{portal, portalNoPath, ssh}},
		{RunID: run2.ID, IP: "10.20.0.6", Up: true, ObservedAt: at2, Services: []model.ServiceResult{other}},
	})

	res, err := w.RetroHunt(ctx, sigLogin, false, true)
	if err != nil {
		t.Fatal(err)
	}
	// 5 stored observations: 10.20.0.5:80 twice, :8080, :22, and 10.20.0.6:80.
	if res.Scanned != 5 || res.PacketsSent != 0 || res.TotalHits != 2 || len(res.Hits) != 2 || res.Truncated {
		t.Fatalf("result = %+v", res)
	}
	var full, partial *model.RetroHit
	for i := range res.Hits {
		switch res.Hits[i].Port {
		case 80:
			full = &res.Hits[i]
		case 8080:
			partial = &res.Hits[i]
		}
	}
	if full == nil || partial == nil {
		t.Fatalf("hits = %+v", res.Hits)
	}
	// 1 - 0.4*0.1*0.7 = 0.972: body, the stored /login probe and the header. The IP comes from the store, not from the URL.
	if full.IP != "10.20.0.5" || full.RunID != run2.ID || full.ServiceID == 0 || full.Match.Confidence != 0.972 || full.Match.Version != "1.24.0" ||
		full.URL != "http://portal.example.edu/" || !full.At.Equal(at2) {
		t.Errorf("full hit = %+v", full)
	}
	// The decrypted body excerpt and path excerpt were used: the evidence shows them.
	if len(full.Match.Evidence) != 3 || !strings.Contains(full.Match.Evidence[0].Snippet, "Portal AGH") || full.Match.Evidence[1].Where != "path:/login" {
		t.Errorf("evidence = %+v", full.Match.Evidence)
	}
	// 1 - 0.4*0.7 = 0.72 without the path, which was never fetched there.
	if partial.IP != "10.20.0.5" || partial.Match.Confidence != 0.72 || partial.Match.Version != "1.18.0" {
		t.Errorf("partial hit = %+v", partial)
	}
	// /login is missing in 3 of the 4 HTTP observations; the note says so.
	if len(res.MissingPaths) != 1 || res.MissingPaths[0] != "/login" || res.Incomplete != 3 || len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "3 z 5") {
		t.Errorf("missing = %v, incomplete = %d, notes = %v", res.MissingPaths, res.Incomplete, res.Notes)
	}

	// latestOnly: one observation per service, so the old portal page is not read.
	res, err = w.RetroHunt(ctx, sigLogin, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned != 4 || res.TotalHits != 2 {
		t.Errorf("latest only: %+v", res)
	}
	// A signature for the old marker still finds the old observation when every run is searched.
	oldSig := "id: stary\nname: Stary portal\nbody: 'Stary portal'\n"
	if res, _ = w.RetroHunt(ctx, oldSig, false, true); res.TotalHits != 1 || res.Hits[0].RunID != run1.ID {
		t.Errorf("history: %+v", res)
	}
	if res, _ = w.RetroHunt(ctx, oldSig, true, true); res.TotalHits != 0 {
		t.Errorf("latest only must not see the old page: %+v", res)
	}
	// A non-HTTP signature.
	if res, _ = w.RetroHunt(ctx, "id: ssh\nname: OpenSSH\nbanner: {regex: 'OpenSSH_([0-9.]+)', version_group: 1}\n", true, true); res.TotalHits != 1 || res.Hits[0].Port != 22 || res.Hits[0].Match.Version != "9.6" || res.Hits[0].IP != "10.20.0.5" {
		t.Errorf("ssh: %+v", res)
	}
	// An unsafe signature is an error and reads nothing.
	if _, err = w.RetroHunt(ctx, "id: evil\nname: Evil\nrequests:\n  - {path: /login, method: POST}\nbody: x\n", false, true); err == nil || !strings.Contains(err.Error(), "POST") {
		t.Errorf("unsafe signature: err = %v", err)
	}
	// The hit limit bounds the list, not the count.
	w.MaxHits = 1
	if res, _ = w.RetroHunt(ctx, sigLogin, false, true); res.TotalHits != 2 || len(res.Hits) != 1 || !res.Truncated || !strings.Contains(res.Notes[len(res.Notes)-1], "pierwsze 1 z 2") {
		t.Errorf("limit: %+v", res)
	}
	w.MaxHits = 0
	// A cancelled request stops the stream.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = w.RetroHunt(cctx, sigLogin, false, true); err == nil {
		t.Error("a cancelled context must stop the retro-hunt")
	}

	// Match counts: the newest observation of every service, from the stored matches.
	counts, err := w.UpdateMatchCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["nginx"] != 2 || counts["apache"] != 1 || len(counts) != 2 {
		t.Errorf("counts = %v", counts)
	}
	if n := bySlug(t, st, "nginx").MatchCount; n != 2 {
		t.Errorf("nginx match_count = %d", n)
	}
	if n := bySlug(t, st, "apache").MatchCount; n != 1 {
		t.Errorf("apache match_count = %d", n)
	}
	// A signature that stops matching goes back to zero.
	if _, err := st.Pool().Exec(ctx, "UPDATE signatures SET match_count = 7 WHERE slug = 'wordpress'"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.UpdateMatchCounts(ctx); err != nil {
		t.Fatal(err)
	}
	if n := bySlug(t, st, "wordpress").MatchCount; n != 0 {
		t.Errorf("wordpress match_count = %d, want 0", n)
	}
}

// TestRetroHuntScale stores many observations and checks that a retro-hunt
// reads them in bounded memory. CZUJKA_RETRO_N sets the number (default 20 000;
// the transcript in docs uses 100 000).
func TestRetroHuntScale(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	n := 20000
	if v := os.Getenv("CZUJKA_RETRO_N"); v != "" {
		fmt.Sscan(v, &n)
	}
	ctx := context.Background()
	w, st, logs := newWire(t)
	defer func() { t.Logf("service log:\n%s", logs.String()) }()
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	run, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunRunning, ProfileName: "skala"})
	if err != nil {
		t.Fatal(err)
	}
	filler := strings.Repeat("<p class=\"news\">Aktualności wydziału, rekrutacja, kontakt z dziekanatem.</p>\n", 50) // about 4 KiB
	const perHost = 4
	start := time.Now()
	batch := make([]model.HostResult, 0, 500)
	want := 0
	for i := 0; i < n/perHost; i++ {
		h := model.HostResult{RunID: run.ID, IP: fmt.Sprintf("10.%d.%d.%d", 100+i/65536, i/256%256, i%256), Up: true, ObservedAt: time.Now()}
		for p := 0; p < perHost; p++ {
			body := filler
			if (i*perHost+p)%50 == 0 { // 2 % of the services run the software we hunt for
				body += "<footer>Powered by RzadkiSystem 3." + fmt.Sprint(i%10) + "</footer>"
				want++
			}
			h.Services = append(h.Services, webSvc(8000+p, "Strona", body, "nginx/1.24.0", "nginx"))
		}
		batch = append(batch, h)
		if len(batch) == cap(batch) {
			ingest(t, st, batch)
			batch = batch[:0]
		}
	}
	ingest(t, st, batch)
	stored := n / perHost * perHost
	t.Logf("stored %d observations (about 4 KiB of encrypted body each) in %s", stored, time.Since(start).Round(time.Millisecond))

	hunt := "id: rzadki\nname: RzadkiSystem\nbody: {regex: 'Powered by RzadkiSystem ([0-9.]+)', weight: 0.9, version_group: 1}\n"
	var before, after runtime.MemStats
	// HeapInuse also holds garbage that the collector has not freed yet, so
	// with the default GOGC the peak depended on GC timing and the check
	// failed about one run in three. A low GOGC during the hunt keeps the
	// garbage small: the peak then measures what the stream keeps alive.
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	runtime.GC()
	runtime.ReadMemStats(&before)
	peak := uint64(0)
	done := make(chan struct{})
	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-done:
				return
			case <-time.After(20 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak {
					peak = m.HeapInuse
				}
			}
		}
	}()
	res, err := w.RetroHunt(ctx, hunt, false, true)
	close(done)
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if res.Scanned != stored || res.TotalHits != want || res.PacketsSent != 0 {
		t.Fatalf("scanned = %d (want %d), hits = %d (want %d)", res.Scanned, stored, res.TotalHits, want)
	}
	if res.Hits[0].Match.Version == "" || res.Hits[0].IP == "" {
		t.Errorf("first hit = %+v", res.Hits[0])
	}
	perSec := float64(res.Scanned) / (float64(res.TookMs) / 1000)
	t.Logf("retro-hunt: %d observations, %d hits, %d ms (%.0f observations/s), 0 packets, peak heap %d MiB (before %d MiB)",
		res.Scanned, res.TotalHits, res.TookMs, perSec, peak>>20, before.HeapInuse>>20)
	// All bodies together are stored*4 KiB. Bounded memory means the heap stays far below that.
	if all := uint64(stored) * 4096; stored >= 20000 && peak > before.HeapInuse+all/4 {
		t.Errorf("heap grew to %d MiB; the bodies together are %d MiB: the stream is not bounded", peak>>20, all>>20)
	}

	// The same hunt over the newest observation of every service only.
	if latest, err := w.RetroHunt(ctx, hunt, true, true); err != nil || latest.TotalHits != want {
		t.Errorf("latest only: hits = %d, err = %v", latest.TotalHits, err)
	}
	// A reload while the data is there: the hook path.
	w.Changed(ctx)

	start = time.Now()
	counts, err := w.UpdateMatchCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["nginx"] != stored {
		t.Errorf("nginx count = %d, want %d", counts["nginx"], stored)
	}
	t.Logf("match counts over %d services: %s", stored, time.Since(start).Round(time.Millisecond))
}

func TestImportForeignFile(t *testing.T) {
	ctx := context.Background()
	w, st, logs := newWire(t)
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	lib, err := sig.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	// A JSON list in a foreign shape: two good signatures, one whose id is a
	// built-in, one that is not safe.
	text := `[
  {"id": "acme-portal", "name": "ACME Portal", "category": "cms", "matchers": [{"type": "word", "part": "body", "words": ["acme-portal.css"]}]},
  {"name": "Router Admin", "category": "iot", "favicon_hash": 116323821},
  {"id": "` + lib[0].Slug + `", "name": "Clash", "body": "clash"},
  {"id": "evil", "name": "Evil", "requests": [{"path": "/login", "method": "POST", "body": "a=b"}], "body": "x"}
]`
	rep, err := w.Import(ctx, text, "analityk@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rep.Created, ",") != "acme-portal,router-admin" || len(rep.Updated) != 0 || len(rep.Skipped) != 1 || rep.Skipped[0].Slug != lib[0].Slug {
		t.Fatalf("report = %+v", rep)
	}
	unsafe := false
	for _, is := range rep.Validation.Issues {
		unsafe = unsafe || is.Safety
	}
	if rep.Validation.OK || !unsafe {
		t.Errorf("the unsafe signature must be reported: %+v", rep.Validation)
	}
	if n := countRows(t, st, "NOT builtin"); n != 2 {
		t.Errorf("custom rows = %d, want 2", n)
	}
	if n := countRows(t, st, "slug = 'evil'"); n != 0 {
		t.Error("the unsafe signature must not be stored")
	}
	if b := bySlug(t, st, lib[0].Slug); !b.Builtin || b.YAML != lib[0].YAML {
		t.Error("the built-in signature must not be replaced")
	}
	router := bySlug(t, st, "router-admin")
	if !strings.HasPrefix(router.YAML, "id: router-admin\n") || !router.Enabled || router.Author != "analityk@example.org" || router.Category != model.CatIoT {
		t.Errorf("stored row = %+v", router)
	}
	// The engine has it without a restart.
	hash := int32(116323821)
	svc := &model.ServiceResult{Port: 80, Proto: "tcp", State: "open", HTTP: &model.HTTPFingerprint{Status: 200, FaviconMMH3: &hash}}
	found := false
	matches, _, _ := w.Engine().Match(svc)
	for _, m := range matches {
		found = found || m.Signature == "router-admin"
	}
	if !found {
		t.Errorf("the imported signature does not match: %+v", matches)
	}

	// The analyst disables it; a second import replaces the text and keeps the choice.
	router.Enabled = false
	if _, err := st.UpdateSignature(ctx, router); err != nil {
		t.Fatal(err)
	}
	rep, err = w.Import(ctx, text, "ktos@example.org")
	if err != nil || strings.Join(rep.Updated, ",") != "acme-portal,router-admin" || len(rep.Created) != 0 {
		t.Fatalf("second import: %+v err=%v", rep, err)
	}
	if again := bySlug(t, st, "router-admin"); again.Enabled || again.ID != router.ID {
		t.Errorf("the enabled flag must be kept: %+v", again)
	}
	if matches, _, _ = w.Engine().Match(svc); len(matches) != 0 {
		t.Errorf("a disabled signature must not match: %+v", matches)
	}

	// A passive nuclei template is stored as Czujka YAML and its paths are known to the engine.
	tpl, err := os.ReadFile("../sig/testdata/foreign/nuclei-panel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if rep, err = w.Import(ctx, string(tpl), "analityk@example.org"); err != nil || strings.Join(rep.Created, ",") != "acme-gateway-detect" || !rep.Validation.OK {
		t.Fatalf("nuclei import: %+v err=%v", rep, err)
	}
	if row := bySlug(t, st, "acme-gateway-detect"); strings.Contains(row.YAML, "BaseURL") || !strings.Contains(row.YAML, "path: /gateway/login") {
		t.Errorf("stored nuclei row:\n%s", row.YAML)
	}
	paths := strings.Join(w.Engine().ExtraPaths(), " ")
	if !strings.Contains(paths, "/gateway/login") {
		t.Errorf("extra paths = %s", paths)
	}
	// An active template stores nothing.
	bad, _ := os.ReadFile("../sig/testdata/foreign/nuclei-active.yaml")
	if rep, err = w.Import(ctx, string(bad), "x"); err != nil || len(rep.Created)+len(rep.Updated) != 0 || rep.Validation.OK {
		t.Errorf("active template: %+v err=%v", rep, err)
	}
	if !strings.Contains(logs.String(), "signatures imported") {
		t.Errorf("log: %s", logs.String())
	}
}
