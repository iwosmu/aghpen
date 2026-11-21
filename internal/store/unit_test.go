package store

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func TestWhereBuilder(t *testing.T) {
	w := &where{}
	if w.sql() != "" {
		t.Fatal("empty where must give no SQL")
	}
	w.add("a = ?", 1)
	w.add("b ILIKE ? OR c ILIKE ?", "x", "y")
	if got := w.sql(); got != " WHERE (a = $1) AND (b ILIKE $2 OR c ILIKE $3)" {
		t.Fatalf("unexpected SQL %q", got)
	}
	if len(w.args) != 3 {
		t.Fatalf("args %v", w.args)
	}
}

func TestOrderByIsWhitelisted(t *testing.T) {
	allowed := map[string]string{"ip": "h.ip", "interest": "h.interest"}
	if got := orderBy("-interest,ip", allowed, "h.id", "h.id"); got != " ORDER BY h.interest DESC NULLS LAST, h.ip ASC NULLS LAST, h.id" {
		t.Fatalf("got %q", got)
	}
	// An unknown field (or an injection attempt) falls back to the default.
	if got := orderBy("ip; DROP TABLE hosts", allowed, "h.id DESC", ""); got != " ORDER BY h.id DESC" {
		t.Fatalf("got %q", got)
	}
}

func TestListOptsLimits(t *testing.T) {
	if o := (ListOpts{}).norm(); o.Limit != 50 || o.Offset != 0 {
		t.Fatalf("defaults %+v", o)
	}
	if o := (ListOpts{Limit: 99999, Offset: -4}).norm(); o.Limit != 1000 || o.Offset != 0 {
		t.Fatalf("caps %+v", o)
	}
	if like("50%_a") != `%50\%\_a%` {
		t.Fatalf("like escaping: %q", like("50%_a"))
	}
}

func TestSplitAndMergeSecrets(t *testing.T) {
	orig := model.ServiceResult{
		Port: 443, Name: "https",
		HTTP: &model.HTTPFingerprint{
			Title:       "Panel",
			BodyExcerpt: "<html>TAJNE-BODY</html>",
			Cookies:     []model.Cookie{{Name: "sid", Value: "TAJNE-COOKIE", ValueLen: 12}, {Name: "lang"}},
			Paths:       []model.PathProbe{{Path: "/login", Excerpt: "TAJNE-PATH"}},
		},
		Matches: []model.SigMatch{{Signature: "x", Evidence: []model.Evidence{{Matcher: "body", Snippet: "TAJNE-SNIPPET"}}}},
	}
	clean, sec, has := splitSecrets(orig)
	if !has {
		t.Fatal("secrets expected")
	}
	raw, _ := json.Marshal(clean)
	if strings.Contains(string(raw), "TAJNE") {
		t.Fatalf("clean result still holds secrets: %s", raw)
	}
	if orig.HTTP.Cookies[0].Value != "TAJNE-COOKIE" || orig.HTTP.BodyExcerpt == "" || orig.Matches[0].Evidence[0].Snippet == "" {
		t.Fatal("splitSecrets must not change its input")
	}
	// Round trip through JSON as the database does.
	var back model.ServiceResult
	_ = json.Unmarshal(raw, &back)
	sraw, _ := json.Marshal(sec)
	var sec2 obsSecret
	_ = json.Unmarshal(sraw, &sec2)
	mergeSecrets(&back, sec2)
	if !reflect.DeepEqual(back.HTTP.Cookies, orig.HTTP.Cookies) || back.HTTP.BodyExcerpt != orig.HTTP.BodyExcerpt ||
		back.HTTP.Paths[0].Excerpt != "TAJNE-PATH" || back.Matches[0].Evidence[0].Snippet != "TAJNE-SNIPPET" {
		t.Fatalf("merge did not restore the secrets: %+v", back)
	}
	if _, _, has := splitSecrets(model.ServiceResult{Port: 22}); has {
		t.Fatal("no secrets expected for a plain service")
	}
}

func TestScopeMatcher(t *testing.T) {
	m := newScopeMatcher([]model.Target{
		{ScopeID: 1, Kind: model.TargetCIDR, Value: "10.1.0.0/16"},
		{ScopeID: 2, Kind: model.TargetIP, Value: "10.1.2.3"},
		{ScopeID: 3, Kind: model.TargetRange, Value: "192.168.0.10-192.168.0.20"},
		{ScopeID: 4, Kind: model.TargetDomain, Value: "Portal.Example.org"},
	})
	cases := []struct {
		ip    string
		names []string
		want  []int64
	}{
		{"10.1.2.3", nil, []int64{1, 2}},
		{"10.1.255.255", nil, []int64{1}},
		{"10.2.0.0", nil, []int64{}},
		{"192.168.0.15", nil, []int64{3}},
		{"192.168.0.21", nil, []int64{}},
		{"203.0.113.9", []string{"portal.example.org."}, []int64{4}},
	}
	for _, c := range cases {
		if got := m.match(netip.MustParseAddr(c.ip), c.names); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v want %v", c.ip, got, c.want)
		}
	}
}

func TestHourBucket(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/Warsaw")
	// Sunday 2026-11-22 10:30 UTC is 11:30 in Warsaw: weekday 0, hour 11.
	if b := hourBucket(time.Date(2026, 11, 22, 10, 30, 0, 0, time.UTC), loc); b != 11 {
		t.Fatalf("bucket %d, want 11", b)
	}
	// Saturday 23:30 UTC is Sunday 00:30 in Warsaw.
	if b := hourBucket(time.Date(2026, 11, 21, 23, 30, 0, 0, time.UTC), loc); b != 0 {
		t.Fatalf("bucket %d, want 0", b)
	}
	if b := hourBucket(time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), time.UTC); b != 6*24+12 {
		t.Fatalf("bucket %d, want %d", b, 6*24+12)
	}
}

func TestDecodeKind(t *testing.T) {
	if v, err := decodeKind("text[]", json.RawMessage(`[" a ","b","a",""]`)); err != nil || !reflect.DeepEqual(v, []string{"a", "b"}) {
		t.Fatalf("text[]: %v %v", v, err)
	}
	if v, _ := decodeKind("text[]", json.RawMessage("null")); !reflect.DeepEqual(v, []string{}) {
		t.Fatalf("null text[]: %#v", v)
	}
	if _, err := decodeKind("int", json.RawMessage(`"x"`)); err == nil {
		t.Fatal("string for int must fail")
	}
	if _, err := decodeKind("text", json.RawMessage("5")); err == nil {
		t.Fatal("number for text must fail")
	}
}
