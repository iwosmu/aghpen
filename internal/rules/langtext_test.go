package rules

import (
	"net/http/httptest"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

func TestLocalizeRulesEnglish(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set("Content-Language", "en")
	page := model.Page[StoredRule]{Items: []StoredRule{
		{Slug: "login-over-plain-http", Name: "Formularz logowania przez zwykły HTTP", Description: "Strona logowania działa bez TLS i nie przekierowuje na HTTPS. Hasła idą przez sieć otwartym tekstem.", Builtin: true},
		{Slug: "login-over-plain-http", Name: "Moja nazwa", Builtin: true},
		{Slug: "own", Name: "Formularz logowania przez zwykły HTTP"},
	}}
	localize(w, page)
	if page.Items[0].Name != "Login form over plain HTTP" || page.Items[0].Description == "" || page.Items[0].Description[:9] != "The login" {
		t.Errorf("built-in rule = %+v", page.Items[0])
	}
	if page.Items[1].Name != "Moja nazwa" || page.Items[2].Name != "Formularz logowania przez zwykły HTTP" {
		t.Errorf("edited or own rule changed: %+v", page.Items[1:])
	}
	res := DryRunResult{Message: "Ta reguła zgłosiłaby dziś 2 naruszenia (sprawdzono 3 hostów i 9 usług).", Condition: "klasa login i schemat http",
		Violations: []Violation{{Rule: "login-over-plain-http", RuleName: "Formularz logowania przez zwykły HTTP",
			Summary: "Reguła „Formularz logowania przez zwykły HTTP”: 10.0.0.5:80/tcp (class: login; scheme: http)"},
			{Rule: "x", RuleName: "x", Summary: "Reguła „x”: host 10.0.0.6 nie spełnia wymagania (usługa ssh)"}}}
	got := localize(w, res).(DryRunResult)
	if got.Message != "This rule would report 2 violation(s) today (checked 3 hosts and 9 services)." || got.Condition != "class login and scheme http" {
		t.Errorf("dry run = %q / %q", got.Message, got.Condition)
	}
	if got.Violations[0].Summary != "Rule “Login form over plain HTTP”: 10.0.0.5:80/tcp (class: login; scheme: http)" || got.Violations[0].RuleName != "Login form over plain HTTP" {
		t.Errorf("violation = %+v", got.Violations[0])
	}
	if got.Violations[1].Summary != "Rule “x”: host 10.0.0.6 does not meet the requirement (service ssh)" {
		t.Errorf("violation = %q", got.Violations[1].Summary)
	}
	pl := httptest.NewRecorder()
	p2 := model.Page[StoredRule]{Items: []StoredRule{{Slug: "login-over-plain-http", Name: "Formularz logowania przez zwykły HTTP", Builtin: true}}}
	localize(pl, p2)
	if p2.Items[0].Name != "Formularz logowania przez zwykły HTTP" {
		t.Error("Polish changed")
	}
}
