package rules

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/iwosmu/aghpen/internal/analyze"
	"github.com/iwosmu/aghpen/internal/i18n"
	"github.com/iwosmu/aghpen/internal/model"
)

// responseLang is the language the API chose for this response (its
// Content-Language header, set by the API middleware): "en" or "pl".
func responseLang(w http.ResponseWriter) string {
	if w.Header().Get("Content-Language") == "en" {
		return "en"
	}
	return "pl"
}

// localize renders the texts of a rules answer in the response language.
// Polish passes unchanged; the stored rule YAML is never changed.
func localize(w http.ResponseWriter, v any) any {
	if responseLang(w) != "en" {
		return v
	}
	switch x := v.(type) {
	case map[string]apiError:
		if e, ok := x["error"]; ok {
			e.Message = i18n.ErrorMessage(e.Message, "en")
			x["error"] = e
		}
	case model.Page[StoredRule]:
		for i := range x.Items {
			localizeRule(&x.Items[i])
		}
	case StoredRule:
		localizeRule(&x)
		return x
	case *StoredRule:
		localizeRule(x)
	case map[string]any:
		switch r := x["rule"].(type) {
		case StoredRule:
			localizeRule(&r)
			x["rule"] = r
		case *StoredRule:
			localizeRule(r)
		}
	case DryRunResult:
		x.Message = i18n.ErrorMessage(x.Message, "en")
		x.Condition = analyze.RuleConditionIn(x.Condition, "en")
		for i := range x.Violations {
			localizeViolation(&x.Violations[i])
		}
		return x
	case []Violation:
		for i := range x {
			localizeViolation(&x[i])
		}
	case model.Page[model.Finding]:
		analyze.LocalizeFindings(x.Items, "en")
	}
	return v
}

func localizeRule(r *StoredRule) {
	if !r.Builtin {
		return
	}
	r.Name, r.Description, _ = analyze.RuleTextIn(r.Slug, r.Name, r.Description, "", "en")
}

var (
	reViolationRule = regexp.MustCompile(`^Reguła „([^”]*)”: `)
	reViolationSvc  = regexp.MustCompile(` \(usługa (\d+/\w+)\)`)
	reViolationReq  = regexp.MustCompile(`(nie spełnia wymagania|w wybranej części inwentarza nic nie spełnia wymagania) \((.*)\)`)
)

func localizeViolation(v *Violation) {
	name, _, _ := analyze.RuleTextIn(v.Rule, v.RuleName, "", "", "en")
	s := v.Summary
	if m := reViolationRule.FindStringSubmatch(s); m != nil {
		rn, _, _ := analyze.RuleTextIn(v.Rule, m[1], "", "", "en")
		s = "Rule “" + rn + "”: " + s[len(m[0]):]
	}
	s = reViolationSvc.ReplaceAllString(s, " (service $1)")
	if m := reViolationReq.FindStringSubmatchIndex(s); m != nil {
		lead := "does not meet the requirement"
		if strings.HasPrefix(s[m[2]:m[3]], "w wybranej") {
			lead = "nothing in the selected part of the inventory meets the requirement"
		}
		s = s[:m[0]] + lead + " (" + analyze.RuleConditionIn(s[m[4]:m[5]], "en") + ")" + s[m[1]:]
	}
	v.RuleName, v.Summary = name, s
	v.Evidence = analyze.EvidenceIn(v.Evidence, "en")
}
