package timeline

import (
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestLocalizeSnapshotEnglish(t *testing.T) {
	d := AtDiff{ServicesGoneSince: 4, ServicesChanged: 7, FindingsOpenedSince: 1}
	snap := Snapshot{
		Run:     AtRun{Trigger: "manual-entry", ProfileName: "wpis ręczny"},
		Summary: AtSummary{Diff: d},
		Findings: Page[AtFinding]{Items: []AtFinding{
			{Type: "admin-panel", Title: "Panel administracyjny: Adminer (10.0.0.5:8080)"},
			{Type: "policy-violation", Key: "policy-violation|default-server-page|10.0.0.5/tcp-80", Title: "Domyślna strona serwera — 10.0.0.5:80"},
		}},
		Services: Page[AtService]{Items: []AtService{{Technologies: []string{"Wersja oprogramowania w Server", "nginx"}}}},
	}
	snap.Summary.Diff.Sentences = diffSentences(d)
	pl := httptest.NewRecorder()
	if got := localize(pl, snap).(Snapshot); !reflect.DeepEqual(got.Summary.Diff.Sentences, diffSentences(d)) {
		t.Errorf("Polish changed: %v", got.Summary.Diff.Sentences)
	}
	w := httptest.NewRecorder()
	w.Header().Set("Content-Language", "en")
	got := localize(w, snap).(Snapshot)
	want := []string{"Services gone since then: 4.", "Changed services: 7.", "New findings: 1."}
	if !reflect.DeepEqual(got.Summary.Diff.Sentences, want) {
		t.Errorf("sentences = %v", got.Summary.Diff.Sentences)
	}
	if got.Run.ProfileName != "manual entry" {
		t.Errorf("profile = %q", got.Run.ProfileName)
	}
	if got.Findings.Items[0].Title != "Admin panel: Adminer (10.0.0.5:8080)" || got.Findings.Items[1].Title != "Default server page — 10.0.0.5:80" {
		t.Errorf("titles = %q, %q", got.Findings.Items[0].Title, got.Findings.Items[1].Title)
	}
	if got.Services.Items[0].Technologies[0] != "Software version in Server" || got.Services.Items[0].Technologies[1] != "nginx" {
		t.Errorf("technologies = %v", got.Services.Items[0].Technologies)
	}
	if got := diffSentencesEN(AtDiff{}); len(got) != 1 || got[0] != "No changes since then." {
		t.Errorf("empty = %v", got)
	}
}
