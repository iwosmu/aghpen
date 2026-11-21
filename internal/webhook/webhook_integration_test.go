package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

func allow(model.Permission) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler { return h }
}

// The settings round trip through the API (URL and key encrypted at rest),
// the test button, and the delivery after an analysed run with its audit row.
func TestWebhookEndToEnd(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	var mu sync.Mutex
	var bodies [][]byte
	var sigs []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies, sigs = append(bodies, b), append(sigs, r.Header.Get(SignatureHeader))
		mu.Unlock()
	}))
	defer hook.Close()

	n := &Notifier{St: st}
	r := chi.NewRouter()
	n.Register(r, allow)
	api := httptest.NewServer(r)
	defer api.Close()
	call := func(method, path, body string) (int, map[string]any) {
		req, _ := http.NewRequest(method, api.URL+path, strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}

	if code, m := call("GET", "/settings/webhook", ""); code != 200 || m["enabled"] != false || m["min_severity"] != "medium" {
		t.Fatalf("default: %d %v", code, m)
	}
	if code, _ := call("PUT", "/settings/webhook", `{"enabled": true, "url": "gopher://x"}`); code != 422 {
		t.Errorf("bad URL: %d", code)
	}
	code, m := call("PUT", "/settings/webhook", `{"enabled": true, "url": "`+hook.URL+`/hooks/T0K3N", "min_severity": "low", "secret": "s3cret"}`)
	if code != 200 || m["secret_set"] != true || m["secret"] != nil || m["url"] != hook.URL+"/hooks/T0K3N" || m["ui_url"] != api.URL {
		t.Fatalf("put: %d %v", code, m)
	}
	var raw []byte
	var secret string
	_ = st.Pool().QueryRow(ctx, "SELECT value::text, secret FROM settings WHERE key = 'webhook'").Scan(&raw, &secret)
	if bytes.Contains(raw, []byte("T0K3N")) || strings.Contains(secret, "T0K3N") || strings.Contains(secret, "s3cret") || secret == "" {
		t.Errorf("URL or key stored in clear: value %s secret %q", raw, secret)
	}
	// Saving again without a secret keeps the key.
	if _, m := call("PUT", "/settings/webhook", `{"enabled": true, "url": "`+hook.URL+`/hooks/T0K3N", "min_severity": "low"}`); m["secret_set"] != true {
		t.Errorf("key lost on save: %v", m)
	}

	if code, m := call("POST", "/settings/webhook/test", ""); code != 200 || m["ok"] != true || m["status"] != float64(200) {
		t.Fatalf("test: %d %v", code, m)
	}

	// An analysed run with a new service.
	run, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunCompleted, Trigger: "manual", ProfileName: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.IngestHosts(ctx, []model.HostResult{{RunID: run.ID, ObservedAt: now, IP: "10.66.0.5", Up: true,
		Services: []model.ServiceResult{{Port: 8080, Proto: "tcp", State: "open", Name: "http"}}}}, store.SinkOptions{Source: "scan", MarkMissing: true}); err != nil {
		t.Fatal(err)
	}
	hosts, _ := st.ListHosts(ctx, store.HostFilter{ListOpts: store.ListOpts{Limit: 5}})
	if len(hosts.Items) != 1 {
		t.Fatalf("hosts %+v", hosts.Items)
	}
	if err := st.InsertChanges(ctx, []model.Change{{RunID: run.ID, At: now, Kind: model.ChangeServiceNew, Severity: model.SevMedium, HostID: hosts.Items[0].ID, IP: "10.66.0.5", Port: 8080, Summary: "Nowa usługa 10.66.0.5:8080 (http)"}}); err != nil {
		t.Fatal(err)
	}
	run.Summary = &model.RunDiffSummary{ByKind: map[string]int{"service_new": 1}}
	_ = st.SaveRun(ctx, run)
	n.NotifyRun(ctx, run.ID)

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("deliveries %d", len(bodies))
	}
	var p Payload
	if err := json.Unmarshal(bodies[1], &p); err != nil {
		t.Fatal(err)
	}
	if p.Event != EventRun || p.RunID != run.ID || len(p.Changes) != 1 || !strings.Contains(p.Text, "Nowa usługa 10.66.0.5:8080") || !strings.HasPrefix(p.RunURL, api.URL+"/runs/") {
		t.Errorf("payload %+v", p)
	}
	if sigs[1] != Sign("s3cret", bodies[1]) {
		t.Errorf("signature %q", sigs[1])
	}
	audit, _ := st.ListAudit(ctx, store.AuditFilter{ListOpts: store.ListOpts{Limit: 10}})
	var sends int
	for _, a := range audit.Items {
		if a.Action == "integration.webhook.send" {
			sends++
			if a.Detail["status"] != float64(200) {
				t.Errorf("audit detail %v", a.Detail)
			}
		}
	}
	if sends != 2 {
		t.Errorf("audit rows %d, want 2 (test and run): %+v", sends, audit.Items)
	}
}
