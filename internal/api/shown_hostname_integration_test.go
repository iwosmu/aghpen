package api

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
)

// A loopback target mapped to the docker host is scanned on the host's
// address with the name "localhost". Every list, the service detail and the
// exports show it as that address: the dashboard said "localhost:8081" and
// the service list "172.18.0.1:8081" for the same service.
func TestMappedLoopbackServiceHasOneName(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	ctx := context.Background()
	run, _ := e.st.CreateRun(ctx, model.ScanRun{Status: model.RunCompleted})
	hosts := []model.HostResult{
		{RunID: run.ID, IP: "172.18.0.1", Hostnames: []string{"localhost"}, Up: true,
			Services: []model.ServiceResult{{Port: 8081, Proto: "tcp", State: "open", Name: "http", HTTP: &model.HTTPFingerprint{URL: "http://172.18.0.1:8081/", Status: 200, Title: "Sklep"}}}},
		{RunID: run.ID, IP: "10.80.0.9", Hostnames: []string{"shop.example.org"}, Up: true,
			Services: []model.ServiceResult{{Port: 443, Proto: "tcp", State: "open", Name: "https"}}},
	}
	if err := e.st.IngestHosts(ctx, hosts, store.SinkOptions{}); err != nil {
		t.Fatal(err)
	}
	var svcs model.Page[model.Service]
	admin.want(200, "GET", "/api/v1/services?limit=50", nil, &svcs)
	if svcs.Total != 2 {
		t.Fatalf("services: %+v", svcs)
	}
	for _, s := range svcs.Items {
		want := map[string]string{"172.18.0.1": "", "10.80.0.9": "shop.example.org"}[s.IP]
		if s.Hostname != want {
			t.Errorf("list: %s hostname %q, want %q", s.IP, s.Hostname, want)
		}
		var one model.Service
		admin.want(200, "GET", fmt.Sprintf("/api/v1/services/%d", s.ID), nil, &one)
		if one.Hostname != want {
			t.Errorf("detail: %s hostname %q, want %q", s.IP, one.Hostname, want)
		}
	}
	for _, path := range []string{"/api/v1/dashboard", "/api/v1/export/services.csv", "/api/v1/export/services.json",
		fmt.Sprintf("/api/v1/export/runs/%d.json", run.ID), fmt.Sprintf("/api/v1/export/runs/%d.csv", run.ID), fmt.Sprintf("/api/v1/export/runs/%d.xml", run.ID)} {
		resp, raw := admin.raw("GET", path, nil, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, raw)
		}
		if strings.Contains(string(raw), "localhost") {
			t.Errorf("%s names the docker host 'localhost': %s", path, raw)
		}
		if strings.HasPrefix(path, "/api/v1/export/") && !strings.Contains(string(raw), "shop.example.org") {
			t.Errorf("%s lost a real name: %s", path, raw)
		}
	}
}
