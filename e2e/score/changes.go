package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/lab/truth"
)

// Headers that differ between any two requests. They are never a change.
var volatileHeaders = map[string]bool{
	"date": true, "content-length": true, "etag": true, "last-modified": true, "expires": true, "set-cookie": true,
	"age": true, "connection": true, "keep-alive": true, "x-request-id": true, "x-runtime": true, "cache-control": true,
	"x-jenkins-session": true, "content-security-policy": true, "x-debug-token": false,
}

// ChangeReport compares the changes seen between two exports with the expected ones.
type ChangeReport struct {
	From       string   `json:"from"`
	To         string   `json:"to"`
	Metric     Metric   `json:"metric"`
	Matched    []string `json:"matched"`
	NotChecked []string `json:"not_checked"` // expected changes the exports cannot show (no classifier or technology data)
}

func changeLabel(c truth.Change) string {
	s := c.Kind + " " + c.IP
	if c.Port != 0 {
		s += fmt.Sprintf(":%d", c.Port)
	}
	if c.Field != "" {
		s += " " + c.Field
	}
	if c.Before != "" || c.After != "" {
		s += fmt.Sprintf(" (%q -> %q)", c.Before, c.After)
	}
	return s
}

func upHosts(export []model.HostResult, skip map[string]bool) map[string]*model.HostResult {
	out := map[string]*model.HostResult{}
	for i := range export {
		if export[i].Up && !skip[export[i].IP] {
			out[export[i].IP] = &export[i]
		}
	}
	return out
}

func openServices(h *model.HostResult) map[string]*model.ServiceResult {
	out := map[string]*model.ServiceResult{}
	for i := range h.Services {
		s := &h.Services[i]
		if isOpen(*s) {
			proto := s.Proto
			if proto == "" {
				proto = "tcp"
			}
			out[fmt.Sprintf("%05d/%s", s.Port, proto)] = s
		}
	}
	return out
}

func hasAny(export []model.HostResult, f func(model.ServiceResult) bool) bool {
	for _, h := range export {
		for _, s := range h.Services {
			if f(s) {
				return true
			}
		}
	}
	return false
}

func headerMap(h *model.HTTPFingerprint) map[string]string {
	out := map[string]string{}
	if h == nil {
		return out
	}
	for k, v := range h.Headers {
		if volatileHeaders[strings.ToLower(k)] || strings.EqualFold(k, "Location") {
			continue
		}
		out[k] = strings.Join(v, ", ")
	}
	if h.Server != "" {
		if _, ok := out["Server"]; !ok {
			out["Server"] = h.Server
		}
	}
	return out
}

func location(h *model.HTTPFingerprint) string {
	if h == nil {
		return ""
	}
	for k, v := range h.Headers {
		if strings.EqualFold(k, "Location") && len(v) > 0 {
			return v[0]
		}
	}
	if len(h.Redirects) > 0 {
		return h.Redirects[0].To
	}
	return ""
}

func certID(t *model.TLSInfo) string {
	if t == nil {
		return ""
	}
	if t.SHA256 != "" {
		return t.SHA256
	}
	return t.Serial + "|" + t.SubjectCN + "|" + t.NotAfter.UTC().Format("2006-01-02T15:04:05")
}

// ObservedChanges lists the differences between two exports, in the same
// vocabulary as truth.Diff. skip holds addresses to leave out (ignored and
// unstable hosts); anyValue holds "ip|port|header" keys whose value changes
// on every request.
func ObservedChanges(from, to []model.HostResult, skip map[string]bool, anyValue map[string]bool) []truth.Change {
	var out []truth.Change
	a, b := upHosts(from, skip), upHosts(to, skip)
	for ip := range b {
		if _, ok := a[ip]; !ok {
			out = append(out, truth.Change{Kind: "host_new", IP: ip})
		}
	}
	for ip, ha := range a {
		hb, ok := b[ip]
		if !ok {
			out = append(out, truth.Change{Kind: "host_gone", IP: ip})
			continue
		}
		sa, sb := openServices(ha), openServices(hb)
		for k, s := range sb {
			if _, ok := sa[k]; !ok {
				out = append(out, truth.Change{Kind: "service_new", IP: ip, Port: s.Port, Proto: s.Proto})
			}
		}
		for k, x := range sa {
			y, ok := sb[k]
			if !ok {
				out = append(out, truth.Change{Kind: "service_gone", IP: ip, Port: x.Port, Proto: x.Proto})
				continue
			}
			out = append(out, observedServiceChanges(ip, x, y, anyValue)...)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

func observedServiceChanges(ip string, a, b *model.ServiceResult, anyValue map[string]bool) []truth.Change {
	var out []truth.Change
	add := func(kind, field, before, after string) {
		out = append(out, truth.Change{Kind: kind, IP: ip, Port: a.Port, Proto: a.Proto, Field: field, Before: before, After: after})
	}
	if a.Product != b.Product {
		add("service_changed", "product", a.Product, b.Product)
	}
	if a.Version != b.Version {
		add("service_changed", "version", a.Version, b.Version)
	}
	at, bt := map[string]string{}, map[string]string{}
	for _, t := range a.Technologies {
		at[t.Name] = t.Version
	}
	for _, t := range b.Technologies {
		bt[t.Name] = t.Version
	}
	for n, v := range bt {
		if _, ok := at[n]; !ok {
			add("tech_new", "tech:"+n, "", v)
		}
	}
	for n, v := range at {
		if w, ok := bt[n]; !ok {
			add("tech_gone", "tech:"+n, v, "")
		} else if v != w {
			add("tech_version", "tech:"+n, v, w)
		}
	}
	ac, bc := append([]string(nil), a.Classes...), append([]string(nil), b.Classes...)
	sort.Strings(ac)
	sort.Strings(bc)
	if strings.Join(ac, ",") != strings.Join(bc, ",") {
		add("class_changed", "classes", strings.Join(ac, ","), strings.Join(bc, ","))
	}
	if a.HTTP != nil && b.HTTP != nil {
		if normTitle(a.HTTP.Title) != normTitle(b.HTTP.Title) {
			add("title_changed", "title", a.HTTP.Title, b.HTTP.Title)
		}
		if a.HTTP.Status != 0 && b.HTTP.Status != 0 && a.HTTP.Status != b.HTTP.Status {
			add("status_changed", "status", fmt.Sprint(a.HTTP.Status), fmt.Sprint(b.HTTP.Status))
		}
		if la, lb := location(a.HTTP), location(b.HTTP); la != lb {
			add("redirect_changed", "location", la, lb)
		}
		ha, hb := headerMap(a.HTTP), headerMap(b.HTTP)
		seen := map[string]bool{}
		for n := range ha {
			seen[n] = true
		}
		for n := range hb {
			seen[n] = true
		}
		for n := range seen {
			if anyValue[fmt.Sprintf("%s|%d|%s", ip, a.Port, strings.ToLower(n))] {
				continue
			}
			if ha[n] != hb[n] {
				add("headers_changed", "header:"+n, ha[n], hb[n])
			}
		}
		ca, cb := map[string]model.Cookie{}, map[string]model.Cookie{}
		for _, c := range a.HTTP.Cookies {
			ca[c.Name] = c
		}
		for _, c := range b.HTTP.Cookies {
			cb[c.Name] = c
		}
		cs := map[string]bool{}
		for n := range ca {
			cs[n] = true
		}
		for n := range cb {
			cs[n] = true
		}
		for n := range cs {
			x, okx := ca[n]
			y, oky := cb[n]
			if okx != oky || x.Secure != y.Secure || x.HTTPOnly != y.HTTPOnly {
				add("cookies_changed", "cookie:"+n, truth.CookieFlags(okx, x.Secure, x.HTTPOnly), truth.CookieFlags(oky, y.Secure, y.HTTPOnly))
			}
		}
	}
	if (a.TLS == nil) != (b.TLS == nil) {
		add("cert_changed", "tls", fmt.Sprint(a.TLS != nil), fmt.Sprint(b.TLS != nil))
	} else if a.TLS != nil && certID(a.TLS) != certID(b.TLS) {
		add("cert_changed", "certificate", a.TLS.SubjectCN, b.TLS.SubjectCN)
	}
	return out
}

// normChangeKey makes expected and observed changes comparable: header names
// are case-insensitive and technology names are normalised.
func normChangeKey(c truth.Change) string {
	field := c.Field
	switch {
	case strings.HasPrefix(field, "header:"):
		field = strings.ToLower(field)
	case strings.HasPrefix(field, "tech:"):
		field = "tech:" + norm(strings.TrimPrefix(field, "tech:"))
	}
	return fmt.Sprintf("%s|%s|%d|%s", c.Kind, c.IP, c.Port, field)
}

// CompareChanges checks that the observed changes are exactly the expected ones.
// before and after are the ground truth of the two states.
func CompareChanges(expected *truth.ChangeFile, before, after *truth.File, from, to []model.HostResult) *ChangeReport {
	rep := &ChangeReport{From: expected.From, To: expected.To, Metric: Metric{Name: "changes " + expected.From + " -> " + expected.To}}
	skip := map[string]bool{}
	anyValue := map[string]bool{}
	techAlias := map[string]string{}
	for _, t := range []*truth.File{before, after} {
		if t == nil {
			continue
		}
		for _, ip := range t.Ignore {
			skip[ip] = true
		}
		for _, h := range t.Hosts {
			if h.Availability != nil {
				skip[h.IP] = true
			}
			for _, s := range h.Services {
				if s.HTTP != nil {
					for name, v := range s.HTTP.Headers {
						if v == "" {
							anyValue[fmt.Sprintf("%s|%d|%s", h.IP, s.Port, strings.ToLower(name))] = true
						}
					}
				}
				for _, tt := range s.Technologies {
					for a := range techAliases(tt) {
						techAlias[a] = norm(tt.Name)
					}
				}
			}
		}
	}
	hasTech := hasAny(from, func(s model.ServiceResult) bool { return len(s.Technologies) > 0 }) || hasAny(to, func(s model.ServiceResult) bool { return len(s.Technologies) > 0 })
	hasClass := hasAny(from, func(s model.ServiceResult) bool { return len(s.Classes) > 0 }) || hasAny(to, func(s model.ServiceResult) bool { return len(s.Classes) > 0 })
	hasHTTP := hasAny(from, func(s model.ServiceResult) bool { return s.HTTP != nil }) || hasAny(to, func(s model.ServiceResult) bool { return s.HTTP != nil })
	hasStatus := hasAny(from, func(s model.ServiceResult) bool { return s.HTTP != nil && s.HTTP.Status != 0 })
	hasTLS := hasAny(from, func(s model.ServiceResult) bool { return s.TLS != nil }) || hasAny(to, func(s model.ServiceResult) bool { return s.TLS != nil })

	checkable := func(kind string) bool {
		switch kind {
		case "tech_new", "tech_gone", "tech_version":
			return hasTech
		case "class_changed":
			return hasClass
		case "title_changed", "headers_changed", "cookies_changed", "redirect_changed":
			return hasHTTP
		case "status_changed":
			return hasStatus
		case "cert_changed":
			return hasTLS
		}
		return true
	}
	canon := func(c truth.Change) string {
		if strings.HasPrefix(c.Field, "tech:") {
			n := norm(strings.TrimPrefix(c.Field, "tech:"))
			if a, ok := techAlias[n]; ok {
				n = a
			}
			return fmt.Sprintf("%s|%s|%d|tech:%s", c.Kind, c.IP, c.Port, n)
		}
		return normChangeKey(c)
	}

	want := map[string]truth.Change{}
	for _, c := range expected.Changes {
		if !checkable(c.Kind) {
			rep.NotChecked = append(rep.NotChecked, changeLabel(c))
			continue
		}
		want[canon(c)] = c
	}
	seen := map[string]bool{}
	for _, c := range ObservedChanges(from, to, skip, anyValue) {
		k := canon(c)
		if seen[k] {
			continue
		}
		seen[k] = true
		if _, ok := want[k]; ok {
			rep.Metric.TP++
			rep.Matched = append(rep.Matched, changeLabel(c))
		} else {
			rep.Metric.FP++
			rep.Metric.Extra = append(rep.Metric.Extra, changeLabel(c))
		}
	}
	for k, c := range want {
		if !seen[k] {
			rep.Metric.FN++
			rep.Metric.Missed = append(rep.Metric.Missed, changeLabel(c))
		}
	}
	rep.Metric.finish()
	sort.Strings(rep.Matched)
	sort.Strings(rep.NotChecked)
	if rep.Matched == nil {
		rep.Matched = []string{}
	}
	if rep.NotChecked == nil {
		rep.NotChecked = []string{}
	}
	return rep
}
