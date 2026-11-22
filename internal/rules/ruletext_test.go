package rules

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/analyze"
	"github.com/iwosmu/aghpen/internal/model"
)

// The Polish side of the English rule catalog is the text of the built-in
// rules: a rule changed in YAML must change in the catalog too.
func TestRuleCatalogMatchesBuiltin(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != len(analyze.BuiltinRuleTexts) {
		t.Errorf("%d built-in rules, %d in the catalog", len(rs), len(analyze.BuiltinRuleTexts))
	}
	for _, r := range rs {
		c, ok := analyze.BuiltinRuleTexts[r.ID]
		if !ok {
			t.Errorf("rule %s has no English text", r.ID)
			continue
		}
		if c.Name != r.Name || c.Description != r.Description || c.Remediation != r.Remediation {
			t.Errorf("rule %s: catalog Polish text differs from the YAML", r.ID)
		}
		if c.NameEN == "" || c.DescriptionEN == "" || c.RemediationEN == "" {
			t.Errorf("rule %s: empty English text", r.ID)
		}
	}
}

var updateGolden = flag.Bool("update", false, "rewrite the golden files in testdata")

// goldenRuleFindings renders, for every built-in rule, the finding of a
// service violation, a host violation and a scope violation.
func goldenRuleFindings(t *testing.T) []model.Finding {
	t.Helper()
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	var out []model.Finding
	for _, r := range rs {
		ev := []model.Evidence{{Matcher: "policy", Where: "rule", Snippet: r.ID}}
		for _, v := range []Violation{
			{Rule: r.ID, Subject: SubjectService, Key: KeyPrefix(r.ID) + "10.0.0.5/tcp-8080", IP: "10.0.0.5", Port: 8080, Evidence: ev},
			{Rule: r.ID, Subject: SubjectHost, Key: KeyPrefix(r.ID) + "10.0.0.5", IP: "10.0.0.5", Evidence: ev},
			{Rule: r.ID, Subject: PerScope, Key: KeyPrefix(r.ID) + "scope", Evidence: ev},
		} {
			out = append(out, v.Finding(r, 1, now))
		}
	}
	return out
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := "testdata/" + name
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -run Golden -update to write it)", err)
	}
	if string(want) != got {
		wl, gl := strings.Split(string(want), "\n"), strings.Split(got, "\n")
		for i := 0; i < len(wl) || i < len(gl); i++ {
			var w, g string
			if i < len(wl) {
				w = wl[i]
			}
			if i < len(gl) {
				g = gl[i]
			}
			if w != g {
				t.Fatalf("%s line %d:\nwant %q\ngot  %q", path, i+1, w, g)
			}
		}
	}
}

// The Polish texts of every built-in rule and of the findings it stores.
// The file is the reference: the Polish output must not change.
func TestRuleTextGolden(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, r := range rs {
		fmt.Fprintf(&b, "rule %s\n  pl.name: %s\n  pl.description: %s\n  pl.remediation: %s\n  pl.condition: %s\n", r.ID, r.Name, r.Description, r.Remediation, r.Describe())
		n, d, rem := analyze.RuleTextIn(r.ID, r.Name, r.Description, r.Remediation, "en")
		fmt.Fprintf(&b, "  en.name: %s\n  en.description: %s\n  en.remediation: %s\n  en.condition: %s\n", n, d, rem, analyze.RuleConditionIn(r.Describe(), "en"))
	}
	for _, f := range goldenRuleFindings(t) {
		fmt.Fprintf(&b, "finding %s\n  pl.title: %s\n  pl.desc: %q\n", f.Key, f.Title, f.Description)
		en := analyze.RenderFinding(f, "en")
		fmt.Fprintf(&b, "  en.title: %s\n  en.desc: %q\n", en.Title, en.Description)
	}
	checkGolden(t, "ruletext.golden", b.String())
}
