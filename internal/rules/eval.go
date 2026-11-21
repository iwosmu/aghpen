package rules

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Violation is one subject that breaks one rule.
type Violation struct {
	Rule      string           `json:"rule"`
	RuleName  string           `json:"rule_name"`
	Severity  model.Severity   `json:"severity"`
	Subject   string           `json:"subject"` // service | host | scope
	Key       string           `json:"key"`
	HostID    int64            `json:"host_id"`
	IP        string           `json:"ip"`
	ServiceID *int64           `json:"service_id"`
	Port      int              `json:"port"`
	Proto     string           `json:"proto"`
	URL       string           `json:"url"`
	Title     string           `json:"title"`
	Summary   string           `json:"summary"`
	Evidence  []model.Evidence `json:"evidence"`
	Interest  int              `json:"interest"`
	// Storable is false for a scope-level violation of a scope with no host:
	// a finding needs a host, so it is reported but not stored.
	Storable bool `json:"storable"`
}

// KeyPrefix is the start of the finding key of every violation of one rule.
func KeyPrefix(ruleID string) string { return FindingType + "|" + ruleID + "|" }

// Evaluator checks rules host by host. Feed every host of the inventory
// with Host, then call Finish. It keeps only the violations and, per
// scope-level assertion, one flag; memory does not grow with the inventory.
type Evaluator struct {
	rules []*Rule
	ec    ectx
	scope map[*Rule]*scopeState
	out   []Violation
	// Hosts and Services count what was checked.
	Hosts, Services int
}

type scopeState struct {
	found bool
	first *HostRec
}

// NewEvaluator returns an evaluator for the given rules at time now.
func NewEvaluator(rules []*Rule, now time.Time) *Evaluator {
	e := &Evaluator{rules: rules, ec: ectx{now: now}, scope: map[*Rule]*scopeState{}}
	for _, r := range rules {
		if r.Expect == ExpectPresent && r.Per == PerScope {
			e.scope[r] = &scopeState{}
		}
	}
	return e
}

func sevInterest(s model.Severity) int {
	switch s {
	case model.SevHigh:
		return 80
	case model.SevMedium:
		return 60
	case model.SevLow:
		return 40
	}
	return 20
}

func addrOf(h *HostRec) (netip.Addr, bool) {
	a, err := netip.ParseAddr(h.Host.IP)
	return a, err == nil
}

func (r *Rule) hostIn(h *HostRec) bool {
	w := &r.Where
	if len(w.Scopes) > 0 {
		ok := false
		for _, sc := range w.Scopes {
			if contains(h.Scopes, strings.ToLower(sc)) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(w.CIDRs) > 0 || len(w.NotCIDRs) > 0 {
		a, ok := addrOf(h)
		if !ok {
			return false
		}
		if len(w.CIDRs) > 0 {
			in := false
			for _, p := range w.CIDRs {
				if p.Contains(a) {
					in = true
					break
				}
			}
			if !in {
				return false
			}
		}
		for _, p := range w.NotCIDRs {
			if p.Contains(a) {
				return false
			}
		}
	}
	hs := w.HostStatus
	if len(hs) == 0 && r.Expect == ExpectPresent {
		// An assertion does not chase hosts that the inventory reports inactive.
		if h.Host.Status == model.HostDown {
			return false
		}
	}
	if len(hs) > 0 && !contains(hs, string(h.Host.Status)) {
		return false
	}
	return true
}

func (r *Rule) tagsOK(h *HostRec, s *SvcRec) bool {
	w := &r.Where
	if len(w.Tags) == 0 && len(w.NotTags) == 0 {
		return true
	}
	tags := lowerAll(tagsOf(h, s))
	if len(w.Tags) > 0 {
		ok := false
		for _, t := range w.Tags {
			if contains(tags, strings.ToLower(t)) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, t := range w.NotTags {
		if contains(tags, strings.ToLower(t)) {
			return false
		}
	}
	return true
}

func (r *Rule) svcIn(h *HostRec, s *SvcRec) bool {
	if len(r.Where.States) > 0 && !contains(r.Where.States, string(s.Service.State)) {
		return false
	}
	return r.tagsOK(h, s)
}

// matchHost evaluates the match for a host subject: a host matches when the
// condition holds for at least one of its selected services (or for the
// host alone when the condition names no service property).
func (e *Evaluator) matchHost(r *Rule, h *HostRec) (bool, []model.Evidence, *SvcRec) {
	if !r.matchHasSvc {
		ok, ev := r.Match.eval(&e.ec, h, nil)
		return ok, ev, nil
	}
	for _, s := range h.Services {
		if !r.svcIn(h, s) {
			continue
		}
		if ok, ev := r.Match.eval(&e.ec, h, s); ok {
			return true, ev, s
		}
	}
	return false, nil, nil
}

// Host checks every rule against one host and its services.
func (e *Evaluator) Host(h *HostRec) {
	e.Hosts++
	e.Services += len(h.Services)
	for _, r := range e.rules {
		if !r.hostIn(h) {
			continue
		}
		switch {
		case r.Expect == ExpectAbsent && r.Subject == SubjectService:
			for _, s := range h.Services {
				if !r.svcIn(h, s) {
					continue
				}
				if ok, ev := r.Match.eval(&e.ec, h, s); ok {
					e.out = append(e.out, e.serviceViolation(r, h, s, ev))
				}
			}
		case r.Expect == ExpectAbsent:
			if !r.tagsOK(h, nil) {
				continue
			}
			if ok, ev, s := e.matchHost(r, h); ok {
				v := e.hostViolation(r, h, ev)
				if s != nil {
					v.Summary += fmt.Sprintf(" (usługa %d/%s)", s.Service.Port, protoOf(s))
				}
				e.out = append(e.out, v)
			}
		case r.Per == PerScope:
			st := e.scope[r]
			if st.first == nil && r.tagsOK(h, nil) {
				st.first = &HostRec{Host: h.Host, Scopes: h.Scopes}
			}
			if !st.found {
				if ok, _, _ := e.matchHost(r, h); ok {
					st.found = true
				}
			}
		default: // present, per host
			if !r.tagsOK(h, nil) {
				continue
			}
			if ok, _, _ := e.matchHost(r, h); !ok {
				v := e.hostViolation(r, h, []model.Evidence{{Matcher: "policy", Where: "expect", Snippet: "brak wymaganego: " + r.Match.describe()}})
				v.Summary = fmt.Sprintf("Reguła „%s”: host %s nie spełnia wymagania (%s)", r.Name, h.Host.IP, r.Match.describe())
				e.out = append(e.out, v)
			}
		}
	}
}

// Finish closes the scope-level assertions and returns every violation.
func (e *Evaluator) Finish() []Violation {
	for _, r := range e.rules {
		st := e.scope[r]
		if st == nil || st.found {
			continue
		}
		v := Violation{Rule: r.ID, RuleName: r.Name, Severity: r.Severity, Subject: PerScope, Key: KeyPrefix(r.ID) + "scope",
			Interest: sevInterest(r.Severity),
			Summary:  fmt.Sprintf("Reguła „%s”: w wybranej części inwentarza nic nie spełnia wymagania (%s)", r.Name, r.Match.describe()),
			Evidence: []model.Evidence{{Matcher: "policy", Where: "rule", Snippet: r.ID}, {Matcher: "policy", Where: "expect", Snippet: "brak wymaganego: " + r.Match.describe()}}}
		if st.first != nil {
			v.HostID, v.IP, v.Storable = st.first.Host.ID, st.first.Host.IP, true
		}
		e.out = append(e.out, v)
	}
	if e.out == nil {
		e.out = []Violation{}
	}
	return e.out
}

func (e *Evaluator) serviceViolation(r *Rule, h *HostRec, s *SvcRec, ev []model.Evidence) Violation {
	proto := protoOf(s)
	id := s.Service.ID
	title := s.Service.Title
	if title == "" && s.Result != nil && s.Result.HTTP != nil {
		title = s.Result.HTTP.Title
	}
	interest := sevInterest(r.Severity) + s.Service.Interest/5
	if interest > 100 {
		interest = 100
	}
	var what []string
	for _, x := range ev {
		what = append(what, x.Where+": "+x.Snippet)
	}
	v := Violation{Rule: r.ID, RuleName: r.Name, Severity: r.Severity, Subject: SubjectService,
		Key:    KeyPrefix(r.ID) + h.Host.IP + "|" + strconv.Itoa(s.Service.Port) + "/" + proto,
		HostID: h.Host.ID, IP: h.Host.IP, Port: s.Service.Port, Proto: proto, URL: s.Service.URL, Title: title,
		Interest: interest, Storable: h.Host.ID != 0,
		Summary:  fmt.Sprintf("Reguła „%s”: %s:%d/%s (%s)", r.Name, h.Host.IP, s.Service.Port, proto, strings.Join(what, "; ")),
		Evidence: append([]model.Evidence{{Matcher: "policy", Where: "rule", Snippet: r.ID}}, ev...)}
	if id != 0 {
		v.ServiceID = &id
	}
	return v
}

func (e *Evaluator) hostViolation(r *Rule, h *HostRec, ev []model.Evidence) Violation {
	var what []string
	for _, x := range ev {
		what = append(what, x.Where+": "+x.Snippet)
	}
	return Violation{Rule: r.ID, RuleName: r.Name, Severity: r.Severity, Subject: SubjectHost,
		Key: KeyPrefix(r.ID) + h.Host.IP, HostID: h.Host.ID, IP: h.Host.IP,
		Interest: sevInterest(r.Severity), Storable: h.Host.ID != 0,
		Summary:  fmt.Sprintf("Reguła „%s”: host %s (%s)", r.Name, h.Host.IP, strings.Join(what, "; ")),
		Evidence: append([]model.Evidence{{Matcher: "policy", Where: "rule", Snippet: r.ID}}, ev...)}
}

// Finding turns a violation into the finding that the store keeps.
func (v Violation) Finding(r *Rule, runID int64, now time.Time) model.Finding {
	title := r.Name + " — " + v.IP
	if v.Port != 0 {
		title += ":" + strconv.Itoa(v.Port)
	}
	if v.Subject == PerScope {
		title = r.Name + " — brak w zakresie"
	}
	desc := r.Description
	if desc != "" {
		desc += "\n\n"
	}
	desc += "Naruszona reguła ekspozycji „" + r.ID + "”. Warunek: " + r.Match.describe() + "."
	if r.Remediation != "" {
		desc += "\nZalecenie: " + r.Remediation
	}
	return model.Finding{Key: v.Key, Type: FindingType, Title: title, Description: desc, Severity: r.Severity, Status: model.FindingNew,
		Interest: v.Interest, HostID: v.HostID, IP: v.IP, ServiceID: v.ServiceID, Port: v.Port, URL: v.URL,
		Signature: "policy:" + r.ID, Evidence: v.Evidence, FirstSeen: now, LastSeen: now, FirstRunID: runID, LastRunID: runID}
}

// Describe returns the condition of the rule in words.
func (r *Rule) Describe() string { return r.Match.describe() }
