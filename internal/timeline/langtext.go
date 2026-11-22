package timeline

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/iwosmu/aghpen/internal/analyze"
	"github.com/iwosmu/aghpen/internal/i18n"
)

// responseLang is the language the API chose for this response (its
// Content-Language header, set by the API middleware): "en" or "pl".
func responseLang(w http.ResponseWriter) string {
	if w.Header().Get("Content-Language") == "en" {
		return "en"
	}
	return "pl"
}

// localize renders the texts of a time-machine answer in the response
// language: the diff sentences from their counts, finding titles from their
// type and stored text, technology names, the manual-entry profile name and
// error messages. Polish passes unchanged.
func localize(w http.ResponseWriter, v any) any {
	if responseLang(w) != "en" {
		return v
	}
	switch x := v.(type) {
	case map[string]any:
		if e, ok := x["error"].(map[string]string); ok {
			e["message"] = i18n.ErrorMessage(e["message"], "en")
		}
	case Snapshot:
		x.Summary.Diff.Sentences = diffSentencesEN(x.Summary.Diff)
		localizeRun(&x.Run)
		localizeFindings(x.Findings.Items)
		localizeServices(x.Services.Items)
		return x
	case *Snapshot:
		x.Summary.Diff.Sentences = diffSentencesEN(x.Summary.Diff)
		localizeRun(&x.Run)
		localizeFindings(x.Findings.Items)
		localizeServices(x.Services.Items)
	case Page[AtFinding]:
		localizeFindings(x.Items)
	case Page[AtService]:
		localizeServices(x.Items)
	}
	return v
}

func localizeRun(r *AtRun) {
	if r.Trigger == "manual-entry" && r.ProfileName == "wpis ręczny" {
		r.ProfileName = "manual entry"
	}
	if r.ProfileName == "Domyślny" {
		r.ProfileName = "Default"
	}
}

func localizeFindings(fs []AtFinding) {
	for i := range fs {
		sig := ""
		if fs[i].Type == analyze.PolicyFindingType {
			// key: policy-violation|<rule id>|<subject>
			if parts := strings.SplitN(fs[i].Key, "|", 3); len(parts) == 3 {
				sig = "policy:" + parts[1]
			}
		}
		fs[i].Title = analyze.FindingTitleIn(fs[i].Type, sig, fs[i].Title, "en")
	}
}

func localizeServices(ss []AtService) {
	for i := range ss {
		for j, t := range ss[i].Technologies {
			ss[i].Technologies[j] = analyze.SignatureNameIn(t, "en")
		}
	}
}

// diffSentencesEN is diffSentences in English, from the same counts.
func diffSentencesEN(d AtDiff) []string {
	var s []string
	line := func(n int, label string) {
		if n > 0 {
			s = append(s, label+": "+strconv.Itoa(n)+".")
		}
	}
	line(d.ServicesGoneSince, "Services gone since then")
	line(d.ServicesNewSince, "New services")
	line(d.ServicesChanged, "Changed services")
	line(d.HostsDownSince, "Hosts down today")
	line(d.HostsNewSince, "New hosts")
	var f []string
	if d.FindingsOpenedSince > 0 {
		f = append(f, "New findings: "+strconv.Itoa(d.FindingsOpenedSince)+".")
	}
	if d.FindingsClosedSince > 0 {
		f = append(f, "Closed findings: "+strconv.Itoa(d.FindingsClosedSince)+".")
	}
	if len(f) > 0 {
		s = append(s, strings.Join(f, " "))
	}
	if len(s) == 0 {
		s = append(s, "No changes since then.")
	}
	return s
}
