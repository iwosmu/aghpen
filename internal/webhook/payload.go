// Package webhook sends one alert POST to the operator's own endpoint after
// every analysed run: a JSON summary with a "text" field, so Slack and
// Mattermost incoming webhooks render it as a message.
//
// It is an integration call, like the DefectDojo export: it never touches a
// scanned target. One attempt with a timeout, no retries; every delivery is
// in the audit log.
package webhook

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/analyze"
	"github.com/iwosmu/aghpen/internal/model"
)

// Event names (X-Czujka-Event header and the "event" field).
const (
	EventRun  = "run.analyzed"
	EventTest = "test"
)

// Limits of the message.
const (
	MaxChanges  = 10
	MaxFindings = 5
)

// Payload is the JSON body of one POST.
type Payload struct {
	Event      string         `json:"event"`
	RunID      int64          `json:"run_id"`
	RunURL     string         `json:"run_url"`
	Trigger    string         `json:"trigger"`
	Scope      string         `json:"scope"`
	FinishedAt *time.Time     `json:"finished_at"`
	Counts     map[string]int `json:"counts"`
	Changes    []Item         `json:"changes"`
	Findings   []Item         `json:"findings"`
	Text       string         `json:"text"` // Slack/Mattermost message
}

// Item is one change or finding in the message.
type Item struct {
	Kind     string `json:"kind"` // change kind, or "finding"
	Severity string `json:"severity"`
	IP       string `json:"ip"`
	Port     int    `json:"port,omitempty"`
	Summary  string `json:"summary"`
	Interest int    `json:"interest,omitempty"`
	URL      string `json:"url"`
}

var sevRank = map[model.Severity]int{model.SevInfo: 0, model.SevLow: 1, model.SevMedium: 2, model.SevHigh: 3}

// rank of a severity; unknown values count as info.
func rank(s model.Severity) int { return sevRank[s] }

// ValidSeverity reports whether s is a severity the settings accept.
func ValidSeverity(s model.Severity) bool { _, ok := sevRank[s]; return ok }

// alertKinds are the change kinds of the message: new exposures, and what is
// gone, back or slower.
var alertKinds = map[model.ChangeKind]bool{
	model.ChangeHostNew: true, model.ChangeServiceNew: true,
	model.ChangeHostGone: true, model.ChangeServiceGone: true, model.ChangeHostMissing: true, model.ChangeServiceUnreachable: true,
	model.ChangeHostBack: true, model.ChangeServiceReturned: true, model.ChangeResponseSlower: true,
}

// Build makes the payload of an analysed run. It returns ok = false when
// no change and no new finding reaches min: then nothing is sent.
func Build(run model.ScanRun, changes []model.Change, findings []model.Finding, min model.Severity, base string) (Payload, bool) {
	base = strings.TrimRight(base, "/")
	p := Payload{Event: EventRun, RunID: run.ID, RunURL: base + fmt.Sprintf("/runs/%d", run.ID), Trigger: run.Trigger,
		Scope: scopeOf(run), FinishedAt: run.FinishedAt, Counts: map[string]int{}, Changes: []Item{}, Findings: []Item{}}
	if run.Summary != nil {
		for k, v := range run.Summary.ByKind {
			p.Counts[k] = v
		}
		p.Counts["findings_new"] = run.Summary.FindingsNew
	}
	var cs []model.Change
	for _, c := range changes {
		if !c.Expected && alertKinds[c.Kind] && rank(c.Severity) >= rank(min) {
			cs = append(cs, c)
		}
	}
	sort.SliceStable(cs, func(i, j int) bool { return rank(cs[i].Severity) > rank(cs[j].Severity) })
	for i, c := range cs {
		if i == MaxChanges {
			break
		}
		u := base + fmt.Sprintf("/hosts/%d", c.HostID)
		if c.ServiceID != nil {
			u = base + fmt.Sprintf("/services/%d", *c.ServiceID)
		}
		p.Changes = append(p.Changes, Item{Kind: string(c.Kind), Severity: string(c.Severity), IP: c.IP, Port: c.Port, Summary: c.Summary, URL: u})
	}
	var fs []model.Finding
	for _, f := range findings {
		if f.FirstRunID == run.ID && rank(f.Severity) >= rank(min) {
			fs = append(fs, f)
		}
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if rank(fs[i].Severity) != rank(fs[j].Severity) {
			return rank(fs[i].Severity) > rank(fs[j].Severity)
		}
		return fs[i].Interest > fs[j].Interest
	})
	for i, f := range fs {
		if i == MaxFindings {
			break
		}
		p.Findings = append(p.Findings, Item{Kind: "finding", Severity: string(f.Severity), IP: f.IP, Port: f.Port, Summary: f.Title,
			Interest: f.Interest, URL: base + fmt.Sprintf("/hosts/%d", f.HostID)})
	}
	p.Text = text(p, len(cs), len(fs))
	return p, len(cs)+len(fs) > 0
}

func scopeOf(run model.ScanRun) string {
	switch {
	case run.AdHoc != nil && len(run.AdHoc.Addresses) > 0:
		a := run.AdHoc.Addresses
		if len(a) > 5 {
			return strings.Join(a[:5], ", ") + fmt.Sprintf(" i %d innych", len(a)-5)
		}
		return strings.Join(a, ", ")
	case run.ProfileName != "":
		return "profil " + run.ProfileName
	}
	return run.Trigger
}

var sevPL = map[string]string{"info": "informacja", "low": "niska", "medium": "średnia", "high": "wysoka"}

// text is the Slack/Mattermost message: plain lines with bare URLs, which
// both render as links.
func text(p Payload, nChanges, nFindings int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*Czujka: skan #%d przeanalizowany* (%s)\n", p.RunID, p.Scope)
	if len(p.Counts) > 0 {
		var parts []string
		for _, k := range []model.ChangeKind{model.ChangeHostNew, model.ChangeServiceNew, model.ChangeServiceGone, model.ChangeHostGone,
			model.ChangeHostMissing, model.ChangeServiceReturned, model.ChangeResponseSlower} {
			if n := p.Counts[string(k)]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s: %d", analyze.KindLabel(k), n))
			}
		}
		if n := p.Counts["findings_new"]; n > 0 {
			parts = append(parts, fmt.Sprintf("nowe znaleziska: %d", n))
		}
		if len(parts) > 0 {
			b.WriteString(strings.Join(parts, ", ") + "\n")
		}
	}
	for _, f := range p.Findings {
		fmt.Fprintf(&b, "• [%s] %s (%s) %s\n", sevPL[f.Severity], f.Summary, addr(f), f.URL)
	}
	for _, c := range p.Changes {
		fmt.Fprintf(&b, "• [%s] %s %s\n", sevPL[c.Severity], c.Summary, c.URL)
	}
	if more := nChanges - len(p.Changes) + nFindings - len(p.Findings); more > 0 {
		fmt.Fprintf(&b, "… pozostałe: %d\n", more)
	}
	fmt.Fprintf(&b, "Skan: %s", p.RunURL)
	return b.String()
}

func addr(i Item) string {
	if i.Port > 0 {
		return fmt.Sprintf("%s:%d", i.IP, i.Port)
	}
	return i.IP
}
