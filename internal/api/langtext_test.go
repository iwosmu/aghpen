package api

import (
	"net/http/httptest"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

func TestLocalizeResponse(t *testing.T) {
	en := httptest.NewRecorder()
	en.Header().Set("Content-Language", "en")
	pl := httptest.NewRecorder()

	e := map[string]apiError{"error": {Code: "run_active", Message: "Ten profil ma już skan #7. Zakończ albo anuluj go przed nowym."}}
	localizeResponse(en, e)
	if e["error"].Message != "This profile already has scan #7. Let it finish or cancel it before a new one." {
		t.Errorf("error = %q", e["error"].Message)
	}
	runs := model.Page[model.ScanRun]{Items: []model.ScanRun{{Trigger: "manual-entry", ProfileName: "wpis ręczny"}, {ProfileName: "Domyślny"}, {ProfileName: "dmz"}}}
	localizeResponse(pl, runs)
	if runs.Items[0].ProfileName != "wpis ręczny" {
		t.Error("Polish changed")
	}
	localizeResponse(en, runs)
	if runs.Items[0].ProfileName != "manual entry" || runs.Items[1].ProfileName != "Default" || runs.Items[2].ProfileName != "dmz" {
		t.Errorf("runs = %+v", runs.Items)
	}
	p := localizeResponse(en, model.ScanProfile{Name: "Domyślny", Description: defaultProfileDescPL}).(model.ScanProfile)
	if p.Name != "Default" || p.Description != defaultProfileDescEN {
		t.Errorf("profile = %+v", p)
	}
	svc := model.Service{InterestWhy: []model.InterestReason{{Code: "admin-panel", Points: 30, Text: "Panel administracyjny dostępny z sieci"},
		{Code: "signature", Points: 18, Text: "Sygnatura: Wersja oprogramowania w X-Powered-By"},
		{Code: "rare-tech", Points: 10, Text: "Rzadka technologia w tej sieci: 1 z 87 usług"},
		{Code: "sensitive-header", Points: 5, Text: "Nagłówek ujawnia szczegóły oprogramowania: X-Powered-By"}},
		Technologies: []model.Technology{{Name: "Java (kontener serwletów)"}}}
	got := localizeResponse(en, svc).(model.Service)
	want := []string{"Admin panel reachable from the network", "Signature: Software version in X-Powered-By",
		"Rare technology in this network: 1 of 87 services", "Header reveals software details: X-Powered-By"}
	for i, w := range want {
		if got.InterestWhy[i].Text != w {
			t.Errorf("reason %d = %q, want %q", i, got.InterestWhy[i].Text, w)
		}
	}
	if got.Technologies[0].Name != "Java (servlet container)" {
		t.Errorf("technology = %q", got.Technologies[0].Name)
	}
	roles := []model.Role{{Slug: "viewer", Name: "Obserwator", Description: "Tylko odczyt", Builtin: true}, {Name: "Obserwator"}}
	localizeResponse(en, roles)
	if roles[0].Name != "Viewer" || roles[0].Description != "Read only" || roles[1].Name != "Obserwator" {
		t.Errorf("roles = %+v", roles)
	}
	run := localizeResponse(en, model.ScanRun{Stats: model.RunStats{Warnings: []string{"Pełny zakres portów nie został przeskanowany (błąd nmap). Usługi spoza listy portów profilu są w tym przebiegu nieznane."}}}).(model.ScanRun)
	if run.Stats.Warnings[0] != "The full port range was not scanned (nmap error). Services outside the profile's port list are unknown in this scan." {
		t.Errorf("warning = %q", run.Stats.Warnings[0])
	}
	sig := localizeResponse(en, model.Signature{Slug: "header-version-powered-by", Name: "Wersja oprogramowania w X-Powered-By", Builtin: true}).(model.Signature)
	if sig.Name != "Software version in X-Powered-By" {
		t.Errorf("signature = %q", sig.Name)
	}
}
