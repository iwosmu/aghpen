package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

func TestParseTarget(t *testing.T) {
	ok := []struct {
		in    string
		kind  model.TargetKind
		value string
		n     int64
	}{
		{"10.0.0.7", model.TargetIP, "10.0.0.7", 1},
		{" 10.1.2.3/16 ", model.TargetCIDR, "10.1.0.0/16", 65536},
		{"192.168.1.0/24", model.TargetCIDR, "192.168.1.0/24", 256},
		{"10.0.0.5-10.0.0.90", model.TargetRange, "10.0.0.5-10.0.0.90", 86},
		{"10.0.0.5-90", model.TargetRange, "10.0.0.5-10.0.0.90", 86},
		{"Portal.AGH.edu.pl.", model.TargetDomain, "portal.agh.edu.pl", 1},
		{"my-host.example.org", model.TargetDomain, "my-host.example.org", 1},
		{"2001:db8::1", model.TargetIP, "2001:db8::1", 1},
		{"2001:db8::/120", model.TargetCIDR, "2001:db8::/120", 256},
	}
	for _, c := range ok {
		got, err := ParseTarget(c.in)
		if err != nil || got.Kind != c.kind || got.Value != c.value || got.Addresses != c.n || !got.Enabled {
			t.Errorf("%q: got %+v err %v", c.in, got, err)
		}
	}
	for _, bad := range []string{"", "10.0.0.300", "10.0.0.0/33", "10.0.0.9-10.0.0.1", "localhost", "exa mple.org", "http://x.pl", "10.0.0.1-foo", "; rm -rf /"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestParseTextAndFile(t *testing.T) {
	p := BasicTargetParser{}
	valid, invalid := p.ParseText("10.0.0.1\n# komentarz\n\n10.0.1.0/24, example.org  # serwer\nzle!!\n")
	if len(valid) != 3 || len(invalid) != 1 || invalid[0].Line != 5 || invalid[0].Value != "zle!!" {
		t.Fatalf("text: valid=%+v invalid=%+v", valid, invalid)
	}
	valid, invalid, err := p.ParseFile("cele.csv", []byte("target;note;tags\n10.0.0.0/30;serwerownia;dmz|krytyczne\nbad host;;\nexample.org;www;\n"))
	if err != nil || len(valid) != 2 || len(invalid) != 1 || valid[0].Note != "serwerownia" || !reflect.DeepEqual(valid[0].Tags, []string{"dmz", "krytyczne"}) || valid[0].Source != "csv" || invalid[0].Line != 3 {
		t.Fatalf("csv: valid=%+v invalid=%+v err=%v", valid, invalid, err)
	}
	valid, invalid, err = p.ParseFile("cele.json", []byte(`["10.0.0.1", {"value": "10.0.2.0/24", "note": "lab"}, 5]`))
	if err != nil || len(valid) != 2 || len(invalid) != 1 || valid[1].Note != "lab" || valid[1].Source != "json" {
		t.Fatalf("json: valid=%+v invalid=%+v err=%v", valid, invalid, err)
	}
	if _, _, err := p.ParseFile("x.json", []byte("{not json")); err == nil {
		t.Fatal("broken JSON must be an error")
	}
}

func TestExcludedAndBlocks(t *testing.T) {
	p := BasicTargetParser{}
	targets := []model.Target{{Kind: model.TargetCIDR, Value: "10.0.0.0/24"}, {Kind: model.TargetRange, Value: "10.0.1.10-10.0.1.19"}, {Kind: model.TargetDomain, Value: "example.org"}}
	// 10.0.0.0/28 and 10.0.0.8/29 overlap (16 addresses together), 10.0.1.15 is one, example.org is one.
	if got := p.Excluded(targets, []string{"10.0.0.0/28", "10.0.0.8/29", "10.0.1.15", "example.org", "172.16.0.0/12", "junk"}); got != 18 {
		t.Fatalf("excluded = %d, want 18", got)
	}
	if got := blocks24("10.0.0.0/22", 100); !reflect.DeepEqual(got, []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"}) {
		t.Fatalf("blocks: %v", got)
	}
	if got := blocks24("10.0.5.200-10.0.6.3", 100); !reflect.DeepEqual(got, []string{"10.0.5.0/24", "10.0.6.0/24"}) {
		t.Fatalf("range blocks: %v", got)
	}
	if got := blocks24("10.0.0.0/8", 16); len(got) != 16 {
		t.Fatalf("limit: %d", len(got))
	}
}

func TestDefaultAuditAction(t *testing.T) {
	cases := []struct{ method, pattern, action, entity string }{
		{http.MethodPatch, "/api/v1/hosts/{id}", "host.update", "host"},
		{http.MethodPost, "/api/v1/scopes", "scope.create", "scope"},
		{http.MethodPost, "/api/v1/scopes/{id}/targets", "scope.target.create", "scope"},
		{http.MethodPost, "/api/v1/runs/{id}/pause", "run.pause", "run"},
		{http.MethodDelete, "/api/v1/findings/{id}", "finding.delete", "finding"},
		{http.MethodPut, "/api/v1/settings/safety", "safety.update", "safety"},
		{http.MethodPost, "/api/v1/runs", "run.start", "run"},
		{http.MethodPost, "/api/v1/emergency-stop/release", "safety.emergency_stop_release", "safety"},
		{http.MethodPost, "/api/v1/changes/ack", "change.ack", "change"},
		{http.MethodPost, "/api/v1/signatures/retrohunt", "signature.retrohunt", "signature"},
	}
	for _, c := range cases {
		if a, e := defaultAction(c.method, c.pattern); a != c.action || e != c.entity {
			t.Errorf("%s %s: got %s/%s", c.method, c.pattern, a, e)
		}
	}
}

func TestMergePatchAndCSVSafe(t *testing.T) {
	sc := model.Scope{Name: "A", Criticality: 3, Owner: "x"}
	patch := map[string]json.RawMessage{"name": json.RawMessage(`"B"`), "criticality": json.RawMessage("5")}
	if err := mergePatch(&sc, patch, "name", "criticality"); err != nil || sc.Name != "B" || sc.Criticality != 5 || sc.Owner != "x" {
		t.Fatalf("merge: %+v %v", sc, err)
	}
	if err := mergePatch(&sc, map[string]json.RawMessage{"id": json.RawMessage("9")}, "name"); err == nil {
		t.Fatal("a field that is not allowed must be rejected")
	}
	if err := mergePatch(&sc, map[string]json.RawMessage{"name": json.RawMessage("7")}, "name"); err == nil {
		t.Fatal("a wrong type must be rejected")
	}
	for in, want := range map[string]string{"=cmd|' /C calc'!A0": "'=cmd|' /C calc'!A0", "+1": "'+1", "-2": "'-2", "@x": "'@x", "nginx": "nginx", "": ""} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q", in, got)
		}
	}
}
