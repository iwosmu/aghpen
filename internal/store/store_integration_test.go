package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/crypto"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

var ctx = context.Background()

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func mkRun(t *testing.T, st *store.Store) model.ScanRun {
	t.Helper()
	r, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunRunning, Trigger: "manual", ProfileName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func webService(product, version, cookie string) model.ServiceResult {
	return model.ServiceResult{
		Port: 443, Proto: "tcp", State: "open", Name: "https", Product: product, Version: version, Tunnel: "ssl", Confidence: 0.9,
		HTTP: &model.HTTPFingerprint{Scheme: "https", URL: "https://10.20.0.5/", Status: 200, Title: "Panel administracyjny",
			BodyExcerpt: "<html>MARKER-BODY-" + cookie + "</html>",
			Cookies:     []model.Cookie{{Name: "PHPSESSID", Value: cookie, ValueLen: len(cookie), ValueHash: "abc"}}},
		TLS:          &model.TLSInfo{SubjectCN: "panel.example.org", NotAfter: time.Now().Add(10 * 24 * time.Hour), SHA256: "ff"},
		Technologies: []model.Technology{{Name: "nginx", Category: model.CatWebServer, Version: version, Confidence: 0.8}, {Name: "PHP", Category: model.CatLanguage}},
		Classes:      []string{model.ClassAdminPanel},
		Matches:      []model.SigMatch{{Signature: "nginx", Name: "nginx", Evidence: []model.Evidence{{Matcher: "header", Where: "header:Server", Snippet: "MARKER-SNIPPET"}}}},
	}
}

func TestMigrateIsIdempotentAndTablesAreEncrypted(t *testing.T) {
	st := storetest.New(t)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	tde := st.TDE(ctx)
	t.Logf("TDE status: %+v", tde)
	if tde.Tables < 20 {
		t.Fatalf("expected the full schema, got %d tables", tde.Tables)
	}
	if os.Getenv("CZUJKA_TEST_REQUIRE_TDE") == "1" && (!tde.Active || !tde.WALEncrypted) {
		t.Fatalf("TDE must be active with WAL encryption: %+v", tde)
	}
	if tde.Available && tde.Encrypted != tde.Tables {
		t.Fatalf("pg_tde is available but %d of %d tables are not encrypted", tde.Tables-tde.Encrypted, tde.Tables)
	}
}

// TestEditsSurviveScans is the proof for docs/ARCHITECTURE.md §4.7.
func TestEditsSurviveScans(t *testing.T) {
	st := storetest.New(t)
	sink := st.NewSink(store.SinkOptions{MarkMissing: true})

	// Run 1: the scanner sees nginx 1.24.0.
	run1 := mkRun(t, st)
	if err := sink.OnHost(ctx, model.HostResult{RunID: run1.ID, IP: "10.20.0.5", Up: true, OSGuess: "Linux 5.x", Hostnames: []string{"srv5.lab"},
		Services: []model.ServiceResult{webService("nginx", "1.24.0", "cookie-run-1")}}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	hosts, _ := st.ListHosts(ctx, store.HostFilter{})
	if hosts.Total != 1 {
		t.Fatalf("hosts: %d", hosts.Total)
	}
	host := hosts.Items[0]
	svcs, _ := st.HostServices(ctx, host.ID)
	if len(svcs) != 1 || svcs[0].Product != "nginx" || svcs[0].Version != "1.24.0" {
		t.Fatalf("services after run 1: %+v", svcs)
	}
	svc := svcs[0]
	if n, err := st.UpsertFindings(ctx, []model.Finding{{Key: "admin-panel|10.20.0.5|443", Type: "admin-panel", Title: "Panel administracyjny dostępny z sieci",
		Severity: model.SevMedium, Interest: 60, HostID: host.ID, IP: "10.20.0.5", ServiceID: &svc.ID, Port: 443, LastRunID: run1.ID,
		Evidence: []model.Evidence{{Matcher: "title", Snippet: "Panel administracyjny"}}}}); err != nil || n != 1 {
		t.Fatalf("upsert finding: n=%d err=%v", n, err)
	}
	fs, _ := st.ListFindings(ctx, store.FindingFilter{})
	finding := fs.Items[0]

	// The analyst edits: service product, service note and tags, host label and OS, finding status, note and severity.
	svc, err := st.PatchService(ctx, svc.ID, map[string]json.RawMessage{"product": raw("OpenResty (potwierdzone z adminem)"), "note": raw("nie ruszać do audytu"), "tags": raw([]string{"audyt"})}, "analityk@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.PatchHost(ctx, host.ID, map[string]json.RawMessage{"label": raw("Serwer WWW dziekanatu"), "os_guess": raw("Debian 12"), "owner": raw("DSI"), "criticality": raw(4)}, "analityk@example.org"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PatchFinding(ctx, finding.ID, map[string]json.RawMessage{"status": raw("accepted"), "note": raw("ryzyko zaakceptowane do 2027-01"), "severity": raw("low"), "assignee": raw("jan")}, "analityk@example.org"); err != nil {
		t.Fatal(err)
	}

	// Run 2: the scanner observes other values.
	run2 := mkRun(t, st)
	if err := sink.OnHost(ctx, model.HostResult{RunID: run2.ID, IP: "10.20.0.5", Up: true, OSGuess: "Linux 6.1", Hostnames: []string{"srv5.lab"},
		Services: []model.ServiceResult{webService("nginx", "1.26.2", "cookie-run-2")}}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := st.UpsertFindings(ctx, []model.Finding{{Key: "admin-panel|10.20.0.5|443", Type: "admin-panel", Title: "Panel administracyjny (nowy tytuł ze skanu)",
		Severity: model.SevHigh, Interest: 75, HostID: host.ID, IP: "10.20.0.5", ServiceID: &svc.ID, Port: 443, LastRunID: run2.ID}}); err != nil || n != 0 {
		t.Fatalf("second upsert: n=%d err=%v", n, err)
	}

	svc, _ = st.GetService(ctx, svc.ID, true)
	host, _ = st.GetHost(ctx, host.ID)
	finding, _ = st.GetFinding(ctx, finding.ID)

	t.Logf("service.product  = %q  (override: observed=%v by=%s)", svc.Product, svc.Overrides["product"].Observed, svc.Overrides["product"].By)
	t.Logf("service.version  = %q  (not overridden, follows the scan)", svc.Version)
	t.Logf("service.note     = %q  tags=%v", svc.Note, svc.Tags)
	t.Logf("host.os_guess    = %q  (override: observed=%v)  label=%q owner=%q criticality=%d", host.OSGuess, host.Overrides["os_guess"].Observed, host.Label, host.Owner, host.Criticality)
	t.Logf("finding.status   = %q  note=%q assignee=%q", finding.Status, finding.Note, finding.Assignee)
	t.Logf("finding.severity = %q  (override: observed=%v)  title=%q interest=%d last_run=%d", finding.Severity, finding.Overrides["severity"].Observed, finding.Title, finding.Interest, finding.LastRunID)

	if svc.Product != "OpenResty (potwierdzone z adminem)" {
		t.Errorf("the scan overwrote the edited product: %q", svc.Product)
	}
	if ov := svc.Overrides["product"]; ov.Observed != "nginx" || ov.By != "analityk@example.org" {
		t.Errorf("observed product must be recorded beside the override: %+v", ov)
	}
	if svc.Version != "1.26.2" {
		t.Errorf("a field without override must follow the scan: %q", svc.Version)
	}
	if svc.Note != "nie ruszać do audytu" || len(svc.Tags) != 1 || svc.Tags[0] != "audyt" {
		t.Errorf("analyst-owned service fields changed: note=%q tags=%v", svc.Note, svc.Tags)
	}
	if svc.Latest == nil || svc.Latest.RunID != run2.ID || svc.Latest.Result.Product != "nginx" || svc.Latest.Result.Version != "1.26.2" {
		t.Errorf("the observation of run 2 must hold the raw observed values: %+v", svc.Latest)
	}
	if host.OSGuess != "Debian 12" || host.Overrides["os_guess"].Observed != "Linux 6.1" {
		t.Errorf("host os_guess override lost: %q %+v", host.OSGuess, host.Overrides["os_guess"])
	}
	if host.Label != "Serwer WWW dziekanatu" || host.Owner != "DSI" || host.Criticality != 4 {
		t.Errorf("analyst-owned host fields changed: %+v", host)
	}
	if finding.Status != model.FindingAccepted || finding.Note != "ryzyko zaakceptowane do 2027-01" || finding.Assignee != "jan" {
		t.Errorf("finding status or note changed: %+v", finding)
	}
	if finding.Severity != model.SevLow || finding.Overrides["severity"].Observed != "high" {
		t.Errorf("finding severity override lost: %q %+v", finding.Severity, finding.Overrides["severity"])
	}
	if finding.Title != "Panel administracyjny (nowy tytuł ze skanu)" || finding.Interest != 75 || finding.LastRunID != run2.ID {
		t.Errorf("observed finding fields must follow the scan: %+v", finding)
	}

	// Removing the override (PATCH with null) gives the field back to the scanner.
	svc, err = st.PatchService(ctx, svc.ID, map[string]json.RawMessage{"product": raw(nil)}, "analityk@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if _, has := svc.Overrides["product"]; has || svc.Product != "nginx" {
		t.Errorf("null must remove the override and restore the observed value: %q %+v", svc.Product, svc.Overrides)
	}
	if _, err := st.PatchService(ctx, svc.ID, map[string]json.RawMessage{"interest": raw(5)}, "x"); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("unknown field must be rejected, got %v", err)
	}
	if _, err := st.PatchFinding(ctx, finding.ID, map[string]json.RawMessage{"status": raw("bogus")}, "x"); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("bad status must be rejected, got %v", err)
	}
}

func TestIngestInventoryAndFieldEncryption(t *testing.T) {
	st := storetest.New(t)
	scope, err := st.CreateScope(ctx, model.Scope{Name: "Lab", Criticality: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, dup, err := st.AddTargets(ctx, scope.ID, []model.Target{{Kind: model.TargetCIDR, Value: "10.20.0.0/24", Enabled: true, Addresses: 256},
		{Kind: model.TargetCIDR, Value: "10.20.0.0/24", Enabled: true, Addresses: 256}}, nil); err != nil || dup != 1 {
		t.Fatalf("add targets: dup=%d err=%v", dup, err)
	}
	run1 := mkRun(t, st)
	at := time.Date(2026, 11, 16, 9, 15, 0, 0, time.UTC) // Monday 10:15 in Warsaw
	sink := st.NewSink(store.SinkOptions{BatchSize: 2, MarkMissing: true})
	in := []model.HostResult{
		{RunID: run1.ID, IP: "10.20.0.5", Up: true, ObservedAt: at, Reason: "syn-ack", Services: []model.ServiceResult{
			webService("nginx", "1.24.0", "SECRET-COOKIE-VALUE-1"),
			{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Product: "OpenSSH", Version: "9.6", Banner: "SSH-2.0-OpenSSH_9.6"},
			{Port: 8080, Proto: "tcp", State: "closed"}}},
		{RunID: run1.ID, IP: "10.20.0.6", Up: true, ObservedAt: at, Services: []model.ServiceResult{{Port: 3306, State: "open", Name: "mysql", Classes: []string{model.ClassDatabase}}}},
		{RunID: run1.ID, IP: "172.16.9.9", Up: false, ObservedAt: at, Reason: "no-response"},
		{RunID: run1.ID, IP: "not-an-ip", Up: true},
	}
	for _, h := range in {
		if err := sink.OnHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.OnProgress(ctx, run1.ID, model.RunStats{HostsUp: 2, ServicesOpen: 3}); err != nil {
		t.Fatal(err)
	}

	all, _ := st.ListHosts(ctx, store.HostFilter{ListOpts: store.ListOpts{Sort: "ip"}})
	if all.Total != 3 {
		t.Fatalf("want 3 hosts, got %d", all.Total)
	}
	h5 := all.Items[0]
	if h5.IP != "10.20.0.5" || h5.Status != model.HostUp || h5.ServiceCount != 2 || fmt.Sprint(h5.OpenPorts) != "[22 443]" || fmt.Sprint(h5.Technologies) != "[PHP nginx]" || fmt.Sprint(h5.ScopeIDs) != fmt.Sprint([]int64{scope.ID}) {
		t.Fatalf("host aggregates wrong: %+v", h5)
	}
	if all.Items[2].Status != model.HostUnknown || len(all.Items[2].ScopeIDs) != 0 {
		t.Fatalf("down host outside the scope: %+v", all.Items[2])
	}
	for name, f := range map[string]store.HostFilter{
		"port": {Port: 3306}, "tech": {Tech: "nginx"}, "cidr": {CIDR: "10.20.0.4/31"}, "q": {ListOpts: store.ListOpts{Q: "20.0.6"}},
	} {
		if p, err := st.ListHosts(ctx, f); err != nil || p.Total != 1 {
			t.Errorf("host filter %s: total=%d err=%v", name, p.Total, err)
		}
	}
	if p, _ := st.ListHosts(ctx, store.HostFilter{ScopeID: scope.ID}); p.Total != 2 {
		t.Errorf("scope filter: %d", p.Total)
	}
	yes := true
	for name, f := range map[string]store.ServiceFilter{
		"class": {Class: model.ClassAdminPanel}, "tls": {TLS: &yes}, "name": {Name: "ssh"}, "tech": {Tech: "PHP"}, "port": {Port: 3306},
		"cert": {CertWithin: 30}, "q": {ListOpts: store.ListOpts{Q: "openssh"}},
	} {
		if p, err := st.ListServices(ctx, f); err != nil || p.Total != 1 {
			t.Errorf("service filter %s: total=%d err=%v", name, p.Total, err)
		}
	}
	if p, _ := st.ListServices(ctx, store.ServiceFilter{RunID: run1.ID}); p.Total != 3 {
		t.Errorf("run filter: %d", p.Total)
	}

	// Availability histogram: Monday 10:00 Warsaw is bucket 1*24+10.
	av, err := st.Availability(ctx, h5.ID)
	if err != nil || av.Buckets[34].Up != 1 || len(av.Recent) != 1 {
		t.Fatalf("availability: %+v err=%v", av.Buckets[34], err)
	}

	// Field-level encryption: the database row has no plaintext; the API value is decrypted.
	web, _ := st.ListServices(ctx, store.ServiceFilter{Port: 443})
	obs, err := st.ListObservations(ctx, web.Items[0].ID, store.ListOpts{})
	if err != nil || obs.Total != 1 {
		t.Fatalf("observations: %d %v", obs.Total, err)
	}
	if got := obs.Items[0].Result.HTTP.Cookies[0].Value; got != "SECRET-COOKIE-VALUE-1" {
		t.Fatalf("cookie value must be decrypted on read, got %q", got)
	}
	if !strings.Contains(obs.Items[0].Result.HTTP.BodyExcerpt, "MARKER-BODY") || obs.Items[0].Result.Matches[0].Evidence[0].Snippet != "MARKER-SNIPPET" {
		t.Fatalf("body excerpt and evidence must be restored: %+v", obs.Items[0].Result.HTTP)
	}
	var resultText, secret string
	if err := st.Pool().QueryRow(ctx, `SELECT result::text, secret FROM service_observations WHERE service_id = $1`, web.Items[0].ID).Scan(&resultText, &secret); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resultText, "SECRET-COOKIE") || strings.Contains(resultText, "MARKER-BODY") || strings.Contains(resultText, "MARKER-SNIPPET") {
		t.Fatalf("plaintext secret in service_observations.result: %s", resultText)
	}
	if !crypto.IsToken(secret) {
		t.Fatalf("secret column must hold a ciphertext token, got %q", secret)
	}
	t.Logf("service_observations.secret = %.60s...", secret)

	// Run 2: 10.20.0.5 lost port 22, 10.20.0.6 does not answer.
	run2 := mkRun(t, st)
	_ = sink.OnHost(ctx, model.HostResult{RunID: run2.ID, IP: "10.20.0.5", Up: true, ObservedAt: at.Add(time.Hour), Services: []model.ServiceResult{webService("nginx", "1.24.0", "c2")}})
	_ = sink.OnHost(ctx, model.HostResult{RunID: run2.ID, IP: "10.20.0.6", Up: false, ObservedAt: at.Add(time.Hour)})
	if err := sink.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	ssh, _ := st.ListServices(ctx, store.ServiceFilter{Name: "ssh"})
	if ssh.Items[0].State != model.ServiceGone {
		t.Errorf("port 22 must be gone, is %s", ssh.Items[0].State)
	}
	my, _ := st.ListServices(ctx, store.ServiceFilter{Name: "mysql"})
	if my.Items[0].State != model.ServiceUnknown {
		t.Errorf("service of a silent host must be unknown, is %s", my.Items[0].State)
	}
	h6, _ := st.ListHosts(ctx, store.HostFilter{CIDR: "10.20.0.6/32"})
	if h := h6.Items[0]; h.Status != model.HostUnstable || h.ConsecutiveMisses != 1 || h.Stability != 0.5 {
		t.Errorf("host after one miss: status=%s misses=%d stability=%v", h.Status, h.ConsecutiveMisses, h.Stability)
	}
	hints, err := st.HostHints(ctx, []int64{scope.ID})
	if err != nil || len(hints) != 2 || hints[0].IP != "10.20.0.5" || len(hints[0].OpenPorts) != 1 {
		t.Errorf("hints: %+v err=%v", hints, err)
	}

	// Rebuild the run results for export.
	n := 0
	if err := st.EachRunResult(ctx, run1.ID, func(h *model.HostResult) error {
		n++
		if h.IP == "10.20.0.5" && len(h.Services) != 2 {
			t.Errorf("run result services: %d", len(h.Services))
		}
		return nil
	}); err != nil || n != 3 {
		t.Errorf("EachRunResult: n=%d err=%v", n, err)
	}

	d, err := st.Dashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d.Headline.HostsUp != 1 || d.Headline.HostsUnstable != 1 || d.Headline.ServicesOpen != 1 || d.Headline.AdminPanels != 1 || d.Headline.AddressesInScope != 256 || len(d.CertsExpiring) != 1 {
		t.Errorf("dashboard headline: %+v certs=%d", d.Headline, len(d.CertsExpiring))
	}
	techs, _ := st.TechnologyCounts(ctx, 0)
	if len(techs) != 2 {
		t.Errorf("technologies: %+v", techs)
	}
}

func TestKeyRotation(t *testing.T) {
	st, url := storetest.NewWithURL(t)
	run := mkRun(t, st)
	if err := st.IngestHosts(ctx, []model.HostResult{{RunID: run.ID, IP: "10.9.9.9", Up: true, Services: []model.ServiceResult{webService("nginx", "1", "ROTATE-ME")}}}, store.SinkOptions{}); err != nil {
		t.Fatal(err)
	}
	hosts, _ := st.ListHosts(ctx, store.HostFilter{})
	if _, err := st.PatchHost(ctx, hosts.Items[0].ID, map[string]json.RawMessage{"note": raw("notatka przed rotacją")}, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutDefectDojo(ctx, model.DefectDojoSettings{URL: "https://dojo.example.org", APIKey: "dojo-api-key-123"}); err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyKeyring(ctx); err != nil {
		t.Fatal(err)
	}

	newKey := make([]byte, crypto.KeySize)
	for i := range newKey {
		newKey[i] = 0x77
	}
	// The new key alone cannot read the data, and the start-up check says so.
	onlyNew, _ := crypto.NewKeyring(newKey)
	stNew, err := store.Open(ctx, url, store.Options{Keyring: onlyNew})
	if err != nil {
		t.Fatal(err)
	}
	defer stNew.Close()
	if err := stNew.VerifyKeyring(ctx); err == nil {
		t.Fatal("a wrong master key must be detected")
	}

	// rotate-key: new key current, old key still in the keyring.
	both, _ := crypto.NewKeyring(newKey, storetest.Key)
	stRot, err := store.Open(ctx, url, store.Options{Keyring: both})
	if err != nil {
		t.Fatal(err)
	}
	defer stRot.Close()
	done, err := stRot.RotateKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("re-wrapped: %v", done)
	if done["hosts.note_enc"] != 1 || done["service_observations.secret"] != 1 || done["settings.secret"] != 2 {
		t.Fatalf("unexpected rotation counts: %v", done)
	}
	usage, _ := stRot.KeyUsage(ctx)
	if len(usage) != 1 || usage[both.CurrentID()] != 4 {
		t.Fatalf("every ciphertext must be under the new key: %v", usage)
	}
	again, _ := stRot.RotateKeys(ctx)
	for k, n := range again {
		if n != 0 {
			t.Fatalf("second rotation must be a no-op, %s=%d", k, n)
		}
	}
	// Now the new key alone reads everything.
	if err := stNew.VerifyKeyring(ctx); err != nil {
		t.Fatal(err)
	}
	h, err := stNew.GetHost(ctx, hosts.Items[0].ID)
	if err != nil || h.Note != "notatka przed rotacją" {
		t.Fatalf("note after rotation: %q %v", h.Note, err)
	}
	dd, err := stNew.GetDefectDojo(ctx, true)
	if err != nil || dd.APIKey != "dojo-api-key-123" || !dd.APIKeySet {
		t.Fatalf("DefectDojo key after rotation: %+v %v", dd, err)
	}
	if pub, _ := stNew.GetDefectDojo(ctx, false); pub.APIKey != "" || !pub.APIKeySet {
		t.Fatalf("the API key must be hidden without withKey: %+v", pub)
	}
}

func TestRunsChunksAndProfiles(t *testing.T) {
	st := storetest.New(t)
	p, err := st.CreateProfile(ctx, model.ScanProfile{Name: "Nocny", Ports: "top-100", Enabled: true, ScopeIDs: []int64{1}, Rate: model.RateLimits{MaxPPS: 500}})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == 0 || p.Ports != "top-100" || p.Rate.MaxPPS != 500 || len(p.ScopeIDs) != 1 {
		t.Fatalf("profile round trip: %+v", p)
	}
	if _, err := st.CreateProfile(ctx, model.ScanProfile{Name: "Nocny"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate profile name: %v", err)
	}
	r1, err := st.CreateRun(ctx, model.ScanRun{ProfileID: &p.ID, ProfileName: p.Name})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateRun(ctx, model.ScanRun{ProfileID: &p.ID, ProfileName: p.Name}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second active run of a profile must conflict, got %v", err)
	}
	chunks := []model.Chunk{{Seq: 0, Spec: []string{"10.0.0.0/24"}, Size: 256, Priority: 5}, {Seq: 1, Spec: []string{"10.0.1.0/24"}, Size: 256}, {Seq: 2, Spec: []string{"10.0.2.0/24"}, Size: 256}}
	sink := st.NewSink(store.SinkOptions{})
	if err := sink.OnPlan(ctx, r1.ID, chunks); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_ = sink.OnChunk(ctx, model.Chunk{RunID: r1.ID, Seq: 0, Spec: chunks[0].Spec, Size: 256, Priority: 5, Status: model.ChunkDone, StartedAt: &now, FinishedAt: &now, DurationMs: 1200, HostsUp: 7, PPS: 310})
	_ = sink.OnChunk(ctx, model.Chunk{RunID: r1.ID, Seq: 1, Spec: chunks[1].Spec, Size: 256, Status: model.ChunkRunning, StartedAt: &now})
	rest, err := st.RemainingChunks(ctx, r1.ID)
	if err != nil || len(rest) != 2 || rest[0].Status != model.ChunkDeferred || rest[1].Status != model.ChunkPending {
		t.Fatalf("remaining chunks: %+v err=%v", rest, err)
	}
	all, _ := st.ListChunks(ctx, r1.ID)
	if len(all) != 3 || all[0].HostsUp != 7 || all[0].Status != model.ChunkDone {
		t.Fatalf("chunks: %+v", all)
	}
	r1.Status, r1.FinishedAt = model.RunCompleted, &now
	r1.Stats = model.RunStats{HostsUp: 7, AvgPPS: 300}
	if err := st.SaveRun(ctx, r1); err != nil {
		t.Fatal(err)
	}
	if err := st.SetProfileLastRun(ctx, p.ID, r1.ID, 300); err != nil {
		t.Fatal(err)
	}
	if pps, _ := st.ProfileMeasuredPPS(ctx, p.ID); pps != 300 {
		t.Fatalf("measured pps %v", pps)
	}
	r2, err := st.CreateRun(ctx, model.ScanRun{ProfileID: &p.ID, ProfileName: p.Name})
	if err != nil {
		t.Fatalf("a new run must be possible after the first completed: %v", err)
	}
	if prev, _ := st.PrevCompletedRun(ctx, r2.ID); prev != r1.ID {
		t.Fatalf("prev run %d, want %d", prev, r1.ID)
	}
	page, _ := st.ListRuns(ctx, store.RunFilter{ProfileID: p.ID, Status: []string{"completed"}})
	if page.Total != 1 || page.Items[0].Stats.HostsUp != 7 {
		t.Fatalf("run list: %+v", page)
	}
}

func TestChangesSignaturesTags(t *testing.T) {
	st := storetest.New(t)
	run := mkRun(t, st)
	_ = st.IngestHosts(ctx, []model.HostResult{{RunID: run.ID, IP: "10.1.1.1", Up: true}}, store.SinkOptions{})
	hosts, _ := st.ListHosts(ctx, store.HostFilter{})
	hid := hosts.Items[0].ID
	if err := st.InsertChanges(ctx, []model.Change{
		{RunID: run.ID, Kind: model.ChangeHostNew, Severity: model.SevLow, HostID: hid, IP: "10.1.1.1", Summary: "nowy host"},
		{RunID: run.ID, Kind: model.ChangeServiceChanged, HostID: hid, IP: "10.1.1.1", Port: 80, Field: "version", Before: "1.0", After: "2.0", Expected: true},
	}); err != nil {
		t.Fatal(err)
	}
	no := false
	p, err := st.ListChanges(ctx, store.ChangeFilter{Expected: &no})
	if err != nil || p.Total != 1 || p.Items[0].IP != "10.1.1.1" {
		t.Fatalf("changes: %+v %v", p, err)
	}
	if n, _ := st.AckChanges(ctx, []int64{p.Items[0].ID}, "a@b"); n != 1 {
		t.Fatalf("ack: %d", n)
	}
	if p, _ := st.ListChanges(ctx, store.ChangeFilter{Acked: &no}); p.Total != 1 || p.Items[0].Before != "1.0" {
		t.Fatalf("unacked: %+v", p)
	}
	if err := st.UpsertBuiltinSignatures(ctx, []model.Signature{{Slug: "wordpress", Name: "WordPress", Category: model.CatCMS, YAML: "id: wordpress", Enabled: true, Tags: []string{"cms"}}}); err != nil {
		t.Fatal(err)
	}
	sg, err := st.CreateSignature(ctx, model.Signature{Slug: "moja", Name: "Moja", YAML: "id: moja", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSignature(ctx, model.Signature{Slug: "moja", YAML: "x"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate slug: %v", err)
	}
	yes := true
	if p, _ := st.ListSignatures(ctx, store.SignatureFilter{Builtin: &yes}); p.Total != 1 || p.Items[0].Slug != "wordpress" {
		t.Fatalf("builtin filter: %+v", p)
	}
	if err := st.DeleteSignature(ctx, sg.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PatchHost(ctx, hid, map[string]json.RawMessage{"tags": raw([]string{"krytyczny", "dmz"})}, "a"); err != nil {
		t.Fatal(err)
	}
	if p, _ := st.ListHosts(ctx, store.HostFilter{Tag: "dmz"}); p.Total != 1 {
		t.Fatalf("tag filter: %d", p.Total)
	}
	tags, _ := st.TagCounts(ctx)
	if len(tags) != 2 || tags[0].Count != 1 {
		t.Fatalf("tags: %+v", tags)
	}
	sp, err := st.PutSafetyPolicy(ctx, model.SafetyPolicy{MaxPPS: 200, AllowedMethods: []string{"GET"}})
	if err != nil || sp.MaxPPS != 200 || sp.UpdatedAt.IsZero() {
		t.Fatalf("safety policy: %+v %v", sp, err)
	}
	if sp, _ := st.SetEmergencyStop(ctx, true); !sp.EmergencyStop || sp.MaxPPS != 200 {
		t.Fatalf("emergency stop: %+v", sp)
	}
}

// TestIngestBenchmark measures the batch ingest and the list endpoints at the
// size the brief asks for. Run it with CZUJKA_BENCH=1 (make bench).
func TestIngestBenchmark(t *testing.T) {
	if os.Getenv("CZUJKA_BENCH") != "1" {
		t.Skip("set CZUJKA_BENCH=1 to run the ingest benchmark")
	}
	st := storetest.New(t)
	scope, _ := st.CreateScope(ctx, model.Scope{Name: "Kampus"})
	_, _, _ = st.AddTargets(ctx, scope.ID, []model.Target{{Kind: model.TargetCIDR, Value: "10.0.0.0/8", Enabled: true, Addresses: 1 << 24}}, nil)
	const hosts = 10000
	products := []string{"nginx", "Apache httpd", "lighttpd", "Microsoft IIS", "Caddy"}
	gen := func(runID int64, round int) []model.HostResult {
		out := make([]model.HostResult, 0, hosts)
		for i := 0; i < hosts; i++ {
			ip := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
			web := webService(products[i%len(products)], fmt.Sprintf("1.%d.%d", i%30, round), fmt.Sprintf("cookie-%d-%d", i, round))
			web.HTTP.Title = fmt.Sprintf("Serwis %d", i%200)
			out = append(out, model.HostResult{RunID: runID, IP: ip, Up: true, Reason: "syn-ack", RTTMs: 1.5, Hostnames: []string{fmt.Sprintf("h%d.kampus.example", i)}, Services: []model.ServiceResult{
				web,
				{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Product: "OpenSSH", Version: "9.6", Banner: "SSH-2.0-OpenSSH_9.6"},
				{Port: 80, Proto: "tcp", State: "open", Name: "http", Product: products[i%len(products)], HTTP: &model.HTTPFingerprint{Scheme: "http", Status: 301, Title: "Redirect"}},
			}})
		}
		return out
	}
	timeIt := func(name string, fn func() error) time.Duration {
		start := time.Now()
		if err := fn(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		d := time.Since(start)
		t.Logf("%-58s %8.1f ms", name, float64(d.Microseconds())/1000)
		return d
	}
	for round := 1; round <= 2; round++ {
		run := mkRun(t, st)
		data := gen(run.ID, round)
		sink := st.NewSink(store.SinkOptions{BatchSize: 250, MarkMissing: true})
		d := timeIt(fmt.Sprintf("run %d: ingest %d hosts x 3 services (%d observations)", round, hosts, hosts*3), func() error {
			for _, h := range data {
				if err := sink.OnHost(ctx, h); err != nil {
					return err
				}
			}
			return sink.Flush(ctx)
		})
		t.Logf("  = %.0f hosts/s, %.0f observations/s", hosts/d.Seconds(), 3*hosts/d.Seconds())
	}
	var nh, ns, no int
	_ = st.Pool().QueryRow(ctx, `SELECT (SELECT count(*) FROM hosts), (SELECT count(*) FROM services), (SELECT count(*) FROM service_observations)`).Scan(&nh, &ns, &no)
	t.Logf("rows: hosts=%d services=%d service_observations=%d", nh, ns, no)
	if nh != hosts || ns != 3*hosts || no != 6*hosts {
		t.Fatalf("unexpected row counts")
	}
	for i := 0; i < 2; i++ {
		timeIt("ListHosts page 1 (limit 50, default sort)", func() error { _, err := st.ListHosts(ctx, store.HostFilter{}); return err })
		timeIt("ListHosts filter tech=nginx port=443 q=kampus offset 500", func() error {
			_, err := st.ListHosts(ctx, store.HostFilter{Tech: "nginx", Port: 443, ListOpts: store.ListOpts{Q: "kampus", Offset: 500}})
			return err
		})
		timeIt("ListServices class=admin-panel sort=-last_seen", func() error {
			_, err := st.ListServices(ctx, store.ServiceFilter{Class: model.ClassAdminPanel, ListOpts: store.ListOpts{Sort: "-last_seen"}})
			return err
		})
		timeIt("Dashboard", func() error { _, err := st.Dashboard(ctx); return err })
	}
}

// A host whose port scan did not finish (ports_unknown) keeps its services:
// they are not marked gone. A finished scan of the same host does mark them.
func TestPortsUnknownKeepsServices(t *testing.T) {
	st := storetest.New(t)
	sink := st.NewSink(store.SinkOptions{MarkMissing: true})
	svc := func(port int) model.ServiceResult {
		return model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: "http"}
	}
	ingest := func(h model.HostResult) {
		t.Helper()
		if err := sink.OnHost(ctx, h); err != nil {
			t.Fatal(err)
		}
		if err := sink.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	states := func() map[int]string {
		hosts, _ := st.ListHosts(ctx, store.HostFilter{})
		svcs, _ := st.HostServices(ctx, hosts.Items[0].ID)
		out := map[int]string{}
		for _, s := range svcs {
			out[s.Port] = string(s.State)
		}
		return out
	}
	run1 := mkRun(t, st)
	ingest(model.HostResult{RunID: run1.ID, IP: "10.20.0.9", Up: true, Services: []model.ServiceResult{svc(22), svc(80)}})
	run2 := mkRun(t, st)
	ingest(model.HostResult{RunID: run2.ID, IP: "10.20.0.9", Up: true, Reason: model.ReasonPortsUnknown, PortsUnknown: true})
	if s := states(); s[22] != "open" || s[80] != "open" {
		t.Fatalf("after a run with unknown ports: %v", s)
	}
	run3 := mkRun(t, st)
	ingest(model.HostResult{RunID: run3.ID, IP: "10.20.0.9", Up: true, Reason: "arp-response", Services: []model.ServiceResult{svc(80)}})
	if s := states(); s[22] != "gone" || s[80] != "open" {
		t.Fatalf("after a finished scan: %v", s)
	}
}

// The engine stores partial results of a host while the run goes on (marked
// PortsUnknown) and the final result later. Nothing is marked gone by a
// partial result, and the run's stored view is the final result.
func TestPartialThenFinalResult(t *testing.T) {
	st := storetest.New(t)
	sink := st.NewSink(store.SinkOptions{MarkMissing: true})
	ingest := func(h model.HostResult) {
		t.Helper()
		if err := sink.OnHost(ctx, h); err != nil {
			t.Fatal(err)
		}
		if err := sink.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	svc := func(port int, title string) model.ServiceResult {
		s := model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: "http"}
		if title != "" {
			s.HTTP = &model.HTTPFingerprint{Status: 200, Title: title}
		}
		return s
	}
	states := func() map[int]string {
		hosts, _ := st.ListHosts(ctx, store.HostFilter{})
		svcs, _ := st.HostServices(ctx, hosts.Items[0].ID)
		out := map[int]string{}
		for _, s := range svcs {
			out[s.Port] = string(s.State)
		}
		return out
	}
	t0 := time.Now().UTC().Add(-time.Minute)
	run1 := mkRun(t, st)
	ingest(model.HostResult{RunID: run1.ID, IP: "10.20.0.10", Up: true, ObservedAt: t0, Services: []model.ServiceResult{svc(22, ""), svc(80, "Old"), svc(443, "")}})
	run2 := mkRun(t, st)
	ingest(model.HostResult{RunID: run2.ID, IP: "10.20.0.10", Up: true, PortsUnknown: true, ObservedAt: t0.Add(20 * time.Second), Services: []model.ServiceResult{svc(80, "")}})
	if s := states(); s[22] != "open" || s[443] != "open" {
		t.Fatalf("a partial result marked services gone: %v", s)
	}
	ingest(model.HostResult{RunID: run2.ID, IP: "10.20.0.10", Up: true, ObservedAt: t0.Add(30 * time.Second), Services: []model.ServiceResult{svc(22, ""), svc(80, "Final")}})
	if s := states(); s[22] != "open" || s[80] != "open" || s[443] != "gone" {
		t.Fatalf("after the final result: %v", s)
	}
	var got *model.HostResult
	if err := st.EachRunResult(ctx, run2.ID, func(h *model.HostResult) error { got = h; return nil }); err != nil {
		t.Fatal(err)
	}
	hosts, _ := st.ListHosts(ctx, store.HostFilter{})
	res, _, err := st.RunServiceResults(ctx, map[int64]int64{hosts.Items[0].ID: run2.ID})
	if err != nil || got == nil || got.PortsUnknown {
		t.Fatalf("run host = %+v, err %v", got, err)
	}
	titles := map[int]string{}
	for _, s := range res[hosts.Items[0].ID] {
		if s.HTTP != nil {
			titles[s.Port] = s.HTTP.Title
		}
	}
	if titles[80] != "Final" {
		t.Errorf("the run's service view is not the final result: %v", titles)
	}
}
