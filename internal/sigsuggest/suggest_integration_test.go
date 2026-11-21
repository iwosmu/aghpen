package sigsuggest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/sigsuggest"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

func page(title, server, body string, hdr map[string]string, cookies ...string) model.ServiceResult {
	h := map[string][]string{"Server": {server}, "Content-Type": {"text/html"}, "Date": {time.Now().UTC().Format(http.TimeFormat)}}
	for k, v := range hdr {
		h[k] = []string{v}
	}
	var ck []model.Cookie
	for _, c := range cookies {
		ck = append(ck, model.Cookie{Name: c})
	}
	return model.ServiceResult{Port: 80, Proto: "tcp", State: "open", Name: "http",
		HTTP: &model.HTTPFingerprint{Scheme: "http", Status: 200, Title: title, Headers: h, Cookies: ck, BodyExcerpt: body}}
}

func ingest(t *testing.T, st *store.Store, hosts []model.HostResult) {
	t.Helper()
	ctx := context.Background()
	run, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunRunning, ProfileName: "suggest-test"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range hosts {
		hosts[i].RunID, hosts[i].ObservedAt, hosts[i].Up = run.ID, time.Now().UTC(), true
	}
	if err := st.IngestHosts(ctx, hosts, store.SinkOptions{Source: "scan"}); err != nil {
		t.Fatal(err)
	}
}

func serviceID(t *testing.T, st *store.Store, ip string, port int) int64 {
	t.Helper()
	var id int64
	if err := st.Pool().QueryRow(context.Background(), `SELECT id FROM services WHERE ip = $1::inet AND port = $2`, ip, port).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func kioskPage(node, ver string) model.ServiceResult {
	return page("Informator — kiosk "+node, "ik-httpd",
		`<!doctype html><html><head><title>Informator — kiosk `+node+`</title></head><body><!-- InfoKiosk build `+ver+` -->
<main class="ik-screen"><h1>Plan zajęć</h1></main><footer class="ik-footer">InfoKiosk v`+ver+` &middot; węzeł `+node+`</footer></body></html>`,
		map[string]string{"X-InfoKiosk-Node": node}, "infokiosk_sid")
}

func nginxDefault() model.ServiceResult {
	return page("Welcome to nginx!", "nginx/1.24.0", `<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed.</p></body></html>`, nil)
}

func TestSuggestFromStoredInventory(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	hosts := []model.HostResult{
		{IP: "10.66.5.1", Services: []model.ServiceResult{kioskPage("k-7f3a", "4.2.1")}},
		{IP: "10.66.5.2", Services: []model.ServiceResult{kioskPage("k-19c0", "4.3.0")}},
	}
	for i := 0; i < 40; i++ {
		hosts = append(hosts, model.HostResult{IP: fmt.Sprintf("10.66.6.%d", i+1), Services: []model.ServiceResult{nginxDefault()}})
	}
	ingest(t, st, hosts)
	// A second observation of the first kiosk with a newer build: the version
	// changes, the features do not.
	ingest(t, st, []model.HostResult{{IP: "10.66.5.1", Services: []model.ServiceResult{kioskPage("k-7f3a", "4.3.0")}}})

	sg := sigsuggest.New(st, nil)
	res, err := sg.Suggest(ctx, serviceID(t, st, "10.66.5.1", 80))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	t.Logf("suggestion:\n%s", b)
	if !res.OK || !res.MatchesTarget || res.OtherMatches != 1 || res.Slug != "infokiosk" || res.History != 1 || res.LookAlikes != 1 {
		t.Fatalf("bad suggestion: ok=%v target=%v others=%d slug=%s history=%d msg=%s", res.OK, res.MatchesTarget, res.OtherMatches, res.Slug, res.History, res.Message)
	}
	if !strings.Contains(res.YAML, "X-InfoKiosk-Node") || !strings.Contains(res.YAML, "version:") || !res.Validation.OK {
		t.Fatalf("yaml:\n%s", res.YAML)
	}
	if res.RetroHunt == nil || res.RetroHunt.PacketsSent != 0 || res.RetroHunt.Hits[0].Match.Version == "" {
		t.Fatalf("retro-hunt: %+v", res.RetroHunt)
	}
	for _, r := range res.Rules {
		if r.DF > 1 || !strings.Contains(r.Explanation, "podobnych instancjach") {
			t.Fatalf("rule %+v", r)
		}
	}
	// A default nginx page has nothing distinctive: no signature.
	res, err = sg.Suggest(ctx, serviceID(t, st, "10.66.6.1", 80))
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.YAML != "" || !strings.Contains(res.Message, "nie ma cech wyróżniających") {
		t.Fatalf("a common page must give no signature: %+v", res)
	}
	// HTTP handler.
	srv := httptest.NewServer(http.HandlerFunc(sg.Handler))
	defer srv.Close()
	resp, err := http.Post(srv.URL, "application/json", bytes.NewBufferString(fmt.Sprintf(`{"service_id": %d}`, serviceID(t, st, "10.66.5.2", 80))))
	if err != nil {
		t.Fatal(err)
	}
	var got sigsuggest.Suggestion
	_ = json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if resp.StatusCode != 200 || !got.OK || got.OtherMatches != 1 {
		t.Fatalf("handler: %d %+v", resp.StatusCode, got)
	}
	resp, _ = http.Post(srv.URL, "application/json", bytes.NewBufferString(`{"service_id": 999999}`))
	if resp.StatusCode != 404 {
		t.Fatalf("unknown service: %d", resp.StatusCode)
	}
	resp.Body.Close()
}
