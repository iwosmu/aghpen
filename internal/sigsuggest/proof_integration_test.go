package sigsuggest_test

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/httpfp"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/rules"
	"github.com/iwosmu/aghpen/internal/sig"
	"github.com/iwosmu/aghpen/internal/sigsuggest"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// TestProofOnLiveServices fingerprints real HTTP services with the product's
// collector (internal/httpfp, GET/HEAD only) and signature engine, stores them
// through the product's ingest, then asks for a suggested signature for the
// services named in SIGSUGGEST_PROOF_TARGETS and evaluates the exposure rules.
//
//	SIGSUGGEST_PROOF="kiosk-1=127.0.0.1:18100,cam-1=127.0.0.1:18102,printer-1=127.0.0.1:18105s,..."  (s: TLS)
//	SIGSUGGEST_PROOF_TARGETS="kiosk-1,cam-1,printer-1"
//	SIGSUGGEST_PROOF_OUT=/path/to/report.json   (optional)
func TestProofOnLiveServices(t *testing.T) {
	spec := os.Getenv("SIGSUGGEST_PROOF")
	if spec == "" {
		t.Skip("SIGSUGGEST_PROOF is not set")
	}
	st := storetest.New(t)
	ctx := context.Background()
	eng, err := sig.NewBuiltinEngine()
	if err != nil {
		t.Fatal(err)
	}
	col := httpfp.New()
	opts := model.HTTPOpts{Enabled: true, MaxRedirects: 3, SignaturePaths: true, MaxBodyBytes: 256 << 10, TimeoutMs: 5000, Favicon: true}
	type svcRef struct {
		name string
		ip   string
		port int
	}
	var refs []svcRef
	byIP := map[string]*model.HostResult{}
	var order []string
	for _, item := range strings.Split(spec, ",") {
		name, addr, _ := strings.Cut(strings.TrimSpace(item), "=")
		tlsHint := strings.HasSuffix(addr, "s")
		addr = strings.TrimSuffix(addr, "s")
		ip, ps, _ := strings.Cut(addr, ":")
		port, _ := strconv.Atoi(ps)
		req := model.FingerprintRequest{IP: ip, Port: port, TLSHint: tlsHint, Opts: opts}
		h, tl, err := col.Fingerprint(ctx, req)
		if err != nil || (h == nil && tl == nil) {
			t.Logf("%s %s: no HTTP/TLS answer (%v)", name, addr, err)
			continue
		}
		svc := model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: "http", HTTP: h, TLS: tl}
		if tl != nil {
			svc.Tunnel = "ssl"
		}
		if paths := eng.PathsFor(&svc, 6); len(paths) > 0 { // second pass with the safe signature paths, as the scanner does
			req.Paths = paths
			if h2, tl2, err := col.Fingerprint(ctx, req); err == nil && h2 != nil {
				svc.HTTP, svc.TLS = h2, tl2
			}
		}
		svc.Matches, svc.Technologies, svc.Classes = eng.Match(&svc)
		hr := byIP[ip]
		if hr == nil {
			hr = &model.HostResult{IP: ip, Reason: "tcp-connect"}
			byIP[ip] = hr
			order = append(order, ip)
		}
		hr.Services = append(hr.Services, svc)
		refs = append(refs, svcRef{name, ip, port})
		title := ""
		if h != nil {
			title = h.Title
		}
		t.Logf("fingerprinted %-15s %s:%d title=%q classes=%v techs=%d", name, ip, port, title, svc.Classes, len(svc.Technologies))
	}
	var hosts []model.HostResult
	for _, ip := range order {
		hosts = append(hosts, *byIP[ip])
	}
	run, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunRunning, ProfileName: "sigsuggest-proof"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range hosts {
		hosts[i].RunID, hosts[i].ObservedAt, hosts[i].Up = run.ID, time.Now().UTC(), true
	}
	if err := st.IngestHosts(ctx, hosts, store.SinkOptions{Source: "scan"}); err != nil {
		t.Fatal(err)
	}
	sg := sigsuggest.New(st, nil)
	report := map[string]any{}
	targets := strings.Split(os.Getenv("SIGSUGGEST_PROOF_TARGETS"), ",")
	for _, ref := range refs {
		want := false
		for _, n := range targets {
			want = want || strings.TrimSpace(n) == ref.name
		}
		if !want {
			continue
		}
		var id int64
		if err := st.Pool().QueryRow(ctx, `SELECT id FROM services WHERE ip = $1::inet AND port = $2`, ref.ip, ref.port).Scan(&id); err != nil {
			t.Fatal(err)
		}
		res, err := sg.Suggest(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		var why []string
		for _, r := range res.Rules {
			why = append(why, "  - "+r.Explanation+" (waga "+strconv.FormatFloat(r.Weight, 'f', 2, 64)+")")
		}
		var hits []string
		if res.RetroHunt != nil {
			for _, h := range res.RetroHunt.Hits {
				hits = append(hits, h.IP+":"+strconv.Itoa(h.Port)+" v="+h.Match.Version)
			}
		}
		t.Logf("\n=== %s (service %d, %s) ok=%v matches_target=%v other_matches=%d took=%dms\n%s\n--- YAML ---\n%s--- why ---\n%s\n--- retro-hunt hits: %v",
			ref.name, id, res.Target, res.OK, res.MatchesTarget, res.OtherMatches, res.TookMs, res.Message, res.YAML, strings.Join(why, "\n"), hits)
		report[ref.name] = res
	}
	pol := rules.New(st, nil)
	pol.EvalOnChange = false
	if err := pol.Start(ctx); err != nil {
		t.Fatal(err)
	}
	rep, err := pol.Evaluate(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("policy evaluation on the live inventory: rules=%d hosts=%d services=%d violations=%d by_rule=%v took=%dms",
		rep.Rules, rep.Hosts, rep.Services, rep.Violations, rep.ByRule, rep.TookMs)
	report["policy"] = rep
	var vs []string
	_ = st.EachFinding(ctx, store.FindingFilter{Type: rules.FindingType}, func(f *model.Finding) error {
		vs = append(vs, f.Title+" ["+string(f.Severity)+"]")
		return nil
	})
	t.Logf("policy findings:\n  %s", strings.Join(vs, "\n  "))
	if out := os.Getenv("SIGSUGGEST_PROOF_OUT"); out != "" {
		b, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(out, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
