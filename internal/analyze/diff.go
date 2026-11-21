package analyze

import (
	"fmt"
	"math/bits"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// ContentChangeDistance is the simhash Hamming distance (of 64 bits) from
// which a body counts as strongly changed. Near-duplicates differ by 0-6 bits.
const ContentChangeDistance = 16

// MinTechConfidence: technologies under this confidence are not compared.
// A weak guess that comes and goes is noise. Confidence 0 means "not set".
const MinTechConfidence = 0.5

// FlakyStability: a host that answered in less than this share of its runs
// (with at least MinObsForExpected observations) is known to be irregular.
// A new miss of such a host is expected and stays out of the headline.
const FlakyStability = 0.8

// HostSnapshot is the state of one host in one run.
type HostSnapshot struct {
	HostID int64
	IP     string
	// Up is true when the host answered in this run.
	Up bool
	// Status is the status after the stability model ran for this run.
	Status model.HostStatus
	// Pattern is the availability text of the host, used in summaries.
	Pattern string
	// Stability and Observations come from the stability model (share of
	// runs with an answer, number of observations). Zero means unknown.
	Stability    float64
	Observations int
	// PAlive and MissesToDown come from the stability model of this run:
	// the probability that a silent host still exists and the number of
	// further misses in a row that report it inactive. Rule is the
	// per-profile DownAfterMisses rule in force (0: the model decides).
	// They only feed the summaries; SetAssessment fills them.
	PAlive       float64
	MissesToDown int
	Rule         int
	// Services are the services observed in this run. For a host that did
	// not answer, leave it empty or carry the last known services forward;
	// Diff never reports a service of a silent host as gone.
	Services []model.ServiceResult
	// ServiceIDs maps "port/proto" to the store id, when known.
	ServiceIDs map[string]int64
}

// Snapshot is the state of the inventory after one run.
type Snapshot struct {
	RunID int64
	At    time.Time
	Hosts []HostSnapshot
}

// DiffOptions tunes Diff. The zero value is the default.
type DiffOptions struct {
	// PortInScope reports if the newer run probed this port. A port that
	// the newer run did not probe is never "gone". Nil means all ports.
	PortInScope func(proto string, port int) bool
}

// Severity of each change kind. Diff uses exactly this table.
//
//	kind             | severity | rule
//	-----------------+----------+----------------------------------------------------------------
//	host_new         | low      | a new address answers
//	host_gone        | medium   | the model (or the profile rule DownAfterMisses) reported the
//	                 |          | host inactive; info when Expected. Its open services get
//	                 |          | service_gone at the same time
//	host_missing     | medium   | answered in the previous run, silent now, not yet inactive and
//	                 |          | not explained by the profile; its services count in
//	                 |          | services_unreachable, they are not gone
//	host_back        | low      | a host reported inactive answers again; info when Expected
//	host_unstable    | low      | a host that was not up in the previous run starts to miss;
//	                 |          | Expected (info) when the host is known to answer irregularly
//	                 |          | (FlakyStability), also when it answered in the previous run
//	service_new      | medium   | sensitive class or port (admin panel, database, remote access,
//	                 |          | dev tool, IoT); low otherwise
//	service_gone     | low      |
//	service_changed  | medium   | product changed; low when only the version changed
//	tech_new         | low      |
//	tech_gone        | info     |
//	tech_version     | low      |
//	title_changed    | info     |
//	status_changed   | low      |
//	redirect_changed | low      |
//	cert_changed     | low      | medium when the new certificate is expired or self-signed
//	headers_changed  | info     | low when a security header was removed
//	cookies_changed  | info     | low when a cookie lost Secure or HttpOnly
//	content_changed  | info     |
//	class_changed    | medium   | became admin panel, login, database, remote access or dev tool;
//	                 |          | info otherwise
//
// A change with Expected = true is always info and stays out of the summary
// counters (it is counted under by_kind["expected"]).
var sensitiveClasses = map[string]bool{
	model.ClassAdminPanel: true, model.ClassDatabase: true, model.ClassRemoteAccess: true,
	model.ClassDevTool: true, model.ClassIoT: true, model.ClassLogin: true,
}

// volatileHeaders are header names that change between two requests to the
// same page. They never produce a change. Names are lower-case.
var volatileHeaders = map[string]bool{
	"date": true, "set-cookie": true, "etag": true, "last-modified": true, "expires": true, "age": true,
	"content-length": true, "x-request-id": true, "x-correlation-id": true, "x-trace-id": true, "request-id": true,
	"x-amzn-requestid": true, "x-amzn-trace-id": true, "x-amz-request-id": true, "x-amz-id-2": true, "cf-ray": true,
	"x-runtime": true, "x-response-time": true, "traceparent": true, "tracestate": true, "x-cache": true,
	"x-cache-hits": true, "x-served-by": true, "x-timer": true, "x-varnish": true, "report-to": true, "nel": true,
	"keep-alive": true, "connection": true, "transfer-encoding": true, "x-b3-traceid": true, "x-b3-spanid": true,
	"x-envoy-upstream-service-time": true, "x-req-id": true, "x-vcap-request-id": true, "server-timing": true,
	"cf-cache-status": true, "x-nonce": true, "content-security-policy-nonce": true, "x-github-request-id": true,
}

// securityHeaders: removing one of these raises the severity of headers_changed.
var securityHeaders = map[string]bool{
	"strict-transport-security": true, "content-security-policy": true, "x-frame-options": true,
	"x-content-type-options": true, "referrer-policy": true, "permissions-policy": true,
}

// IsVolatileHeader reports if a header name is ignored by the diff and the grouping key.
func IsVolatileHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return volatileHeaders[n] || strings.HasSuffix(n, "-request-id") || strings.HasSuffix(n, "-trace-id")
}

// Diff compares two snapshots and returns the changes of the newer one and
// their summary. prev == nil means "first run": there is no baseline, so
// nothing is reported as new.
//
// Noise rules:
//   - a service on a host that did not answer is unknown, not gone;
//   - a port outside the scope of the newer run is not gone;
//   - volatile headers, cookie values and query strings of redirects are ignored;
//   - a missing value (no product, no HTTP data this time) is not a change;
//   - a change that the availability profile explains gets Expected = true.
func Diff(prev *Snapshot, cur Snapshot, opts DiffOptions) ([]model.Change, model.RunDiffSummary) {
	sum := model.RunDiffSummary{ByKind: map[string]int{}}
	if prev == nil {
		return nil, sum
	}
	prevID := prev.RunID
	sum.PrevRunID = &prevID

	prevHosts := make(map[string]*HostSnapshot, len(prev.Hosts))
	for i := range prev.Hosts {
		prevHosts[prev.Hosts[i].IP] = &prev.Hosts[i]
	}
	hosts := make([]*HostSnapshot, len(cur.Hosts))
	for i := range cur.Hosts {
		hosts[i] = &cur.Hosts[i]
	}
	sort.SliceStable(hosts, func(i, j int) bool { return ipLess(hosts[i].IP, hosts[j].IP) })

	d := differ{cur: cur, prevID: prevID, opts: opts}
	for _, h := range hosts {
		d.host(prevHosts[h.IP], h)
	}
	for _, c := range d.out {
		if c.Expected {
			sum.ByKind["expected"]++
			continue
		}
		sum.ByKind[string(c.Kind)]++
		switch c.Kind {
		case model.ChangeHostNew:
			sum.HostsNew++
		case model.ChangeHostGone:
			sum.HostsGone++
		case model.ChangeHostBack:
			sum.HostsBack++
		case model.ChangeHostUnstable:
			sum.HostsUnstable++
		case model.ChangeHostMissing:
			sum.HostsMissing++
		case model.ChangeServiceNew:
			sum.ServicesNew++
		case model.ChangeServiceGone:
			sum.ServicesGone++
		case model.ChangeServiceChanged:
			sum.ServicesChanged++
		}
	}
	sum.ServicesUnreachable = d.unreachable
	return d.out, sum
}

// SetAssessment copies the output of the stability model for this run to the
// snapshot: status, pattern, stability, p_alive, misses until inactive and
// the rule. observations is the number of observations of the host.
func (h *HostSnapshot) SetAssessment(a Assessment, observations int) {
	h.Status = a.Status
	h.Pattern = a.Pattern
	h.Stability = a.Stability
	h.Observations = observations
	h.PAlive = a.PAlive
	h.MissesToDown = a.DownAfterMisses
	h.Rule = a.Rule
}

type differ struct {
	cur         Snapshot
	prevID      int64
	opts        DiffOptions
	out         []model.Change
	unreachable int
}

func (d *differ) add(h *HostSnapshot, svc *model.ServiceResult, kind model.ChangeKind, sev model.Severity, field string, before, after any, expected bool, summary string) {
	if expected {
		sev = model.SevInfo
	}
	pid := d.prevID
	c := model.Change{
		RunID: d.cur.RunID, PrevRunID: &pid, At: d.cur.At, Kind: kind, Severity: sev,
		HostID: h.HostID, IP: h.IP, Summary: summary, Field: field, Before: before, After: after, Expected: expected,
	}
	if svc != nil {
		c.Port = svc.Port
		if id, ok := h.ServiceIDs[svcKey(svc)]; ok {
			c.ServiceID = &id
		}
	}
	d.out = append(d.out, c)
}

func svcKey(s *model.ServiceResult) string {
	proto := s.Proto
	if proto == "" {
		proto = "tcp"
	}
	return strconv.Itoa(s.Port) + "/" + proto
}

func isOpen(s *model.ServiceResult) bool { return s.State == "" || s.State == "open" }

func (d *differ) host(prev, cur *HostSnapshot) {
	patternNote := ""
	if cur.Pattern != "" {
		patternNote = " (" + cur.Pattern + ")"
	}
	wasDown := prev != nil && prev.Status == model.HostDown
	known := prev != nil && prev.Status != model.HostUnknown && prev.Status != ""
	if prev != nil && !known && (prev.Up || len(prev.Services) > 0) {
		known = true // the caller did not set a status; it was seen before
	}

	switch {
	case cur.Up && !known:
		d.add(cur, nil, model.ChangeHostNew, model.SevLow, "status", nil, string(model.HostUp), false,
			fmt.Sprintf("Nowy host %s%s", cur.IP, openPortsNote(cur.Services)))
	case cur.Up && wasDown:
		d.add(cur, nil, model.ChangeHostBack, model.SevLow, "status", string(prev.Status), string(model.HostUp), false,
			fmt.Sprintf("Host %s znów odpowiada po zgłoszeniu jako nieaktywny", cur.IP))
	case cur.Up && prev.Status == model.HostExpectedOffline:
		d.add(cur, nil, model.ChangeHostBack, model.SevInfo, "status", string(prev.Status), string(model.HostUp), true,
			fmt.Sprintf("Host %s znów odpowiada, zgodnie z profilem dostępności%s", cur.IP, patternNote))
	case !cur.Up && known && cur.Status == model.HostDown && !wasDown:
		d.add(cur, nil, model.ChangeHostGone, model.SevMedium, "status", string(prev.Status), string(model.HostDown), false, goneSummary(cur))
		d.servicesGone(cur, prev)
	case !cur.Up && known && cur.Status == model.HostExpectedOffline && prev.Status != model.HostExpectedOffline && !wasDown:
		d.add(cur, nil, model.ChangeHostGone, model.SevInfo, "status", string(prev.Status), string(model.HostExpectedOffline), true,
			fmt.Sprintf("Host %s nie odpowiada, zgodnie z profilem dostępności%s", cur.IP, patternNote))
	case !cur.Up && known && cur.Status == model.HostUnstable && prev.Status != model.HostUnstable && !wasDown:
		if cur.Observations >= MinObsForExpected && cur.Stability > 0 && cur.Stability < FlakyStability {
			d.add(cur, nil, model.ChangeHostUnstable, model.SevInfo, "status", string(prev.Status), string(model.HostUnstable), true,
				fmt.Sprintf("Host %s nie odpowiedział; odpowiada nieregularnie (w ok. %d%% skanów)%s", cur.IP, int(cur.Stability*100+0.5), patternNote))
		} else if prev.Up {
			n := openCount(prev.Services)
			d.unreachable += n
			d.add(cur, nil, model.ChangeHostMissing, model.SevMedium, "status", string(model.HostUp), "missing", false, missingSummary(cur, n))
		} else {
			d.unreachable += openCount(prev.Services)
			d.add(cur, nil, model.ChangeHostUnstable, model.SevLow, "status", string(prev.Status), string(model.HostUnstable), false,
				fmt.Sprintf("Host %s nie odpowiedział w porze, w której zwykle odpowiada; jeszcze nie jest zgłoszony jako nieaktywny", cur.IP))
		}
	}

	if !cur.Up {
		return // services of a silent host are unknown
	}
	if prev == nil || !known {
		// New host: every open service is a new exposure.
		for i := range cur.Services {
			if s := &cur.Services[i]; isOpen(s) {
				d.serviceNew(cur, s)
			}
		}
		return
	}
	if !prev.Up && len(prev.Services) == 0 {
		return // no baseline for the services of this host
	}

	prevSvc := make(map[string]*model.ServiceResult, len(prev.Services))
	for i := range prev.Services {
		if isOpen(&prev.Services[i]) {
			prevSvc[svcKey(&prev.Services[i])] = &prev.Services[i]
		}
	}
	curSvc := make(map[string]*model.ServiceResult, len(cur.Services))
	order := make([]*model.ServiceResult, 0, len(cur.Services))
	for i := range cur.Services {
		s := &cur.Services[i]
		curSvc[svcKey(s)] = s
		if isOpen(s) {
			order = append(order, s)
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i].Port < order[j].Port })
	for _, s := range order {
		if p, ok := prevSvc[svcKey(s)]; ok {
			d.service(cur, p, s)
		} else {
			d.serviceNew(cur, s)
		}
	}
	gone := make([]*model.ServiceResult, 0)
	for k, p := range prevSvc {
		if c, ok := curSvc[k]; ok && isOpen(c) {
			continue
		}
		proto := p.Proto
		if proto == "" {
			proto = "tcp"
		}
		if d.opts.PortInScope != nil && !d.opts.PortInScope(proto, p.Port) {
			continue
		}
		gone = append(gone, p)
	}
	sort.SliceStable(gone, func(i, j int) bool { return gone[i].Port < gone[j].Port })
	for _, p := range gone {
		after := "closed"
		if c, ok := curSvc[svcKey(p)]; ok && c.State != "" {
			after = c.State
		}
		d.add(cur, p, model.ChangeServiceGone, model.SevLow, "state", "open", after, false,
			fmt.Sprintf("Usługa %s zniknęła%s", addr(cur.IP, p.Port), productNote(p)))
	}
}

func (d *differ) serviceNew(h *HostSnapshot, s *model.ServiceResult) {
	sev := model.SevLow
	if isSensitive(s) {
		sev = model.SevMedium
	}
	d.add(h, s, model.ChangeServiceNew, sev, "state", nil, "open", false,
		fmt.Sprintf("Nowa usługa %s%s", addr(h.IP, s.Port), productNote(s)))
}

func (d *differ) service(h *HostSnapshot, p, c *model.ServiceResult) {
	at := addr(h.IP, c.Port)

	// Product and version. A missing value on either side is not a change.
	switch {
	case p.Product != "" && c.Product != "" && !strings.EqualFold(p.Product, c.Product):
		d.add(h, c, model.ChangeServiceChanged, model.SevMedium, "product", productVersion(p), productVersion(c), false,
			fmt.Sprintf("Zmiana produktu %s: %s → %s", at, productVersion(p), productVersion(c)))
	case p.Version != "" && c.Version != "" && p.Version != c.Version && strings.EqualFold(p.Product, c.Product):
		d.add(h, c, model.ChangeServiceChanged, model.SevLow, "version", p.Version, c.Version, false,
			fmt.Sprintf("Zmiana wersji %s: %s → %s", at, productVersion(p), productVersion(c)))
	case p.Product == "" && c.Product == "" && p.Name != "" && c.Name != "" && p.Name != c.Name:
		d.add(h, c, model.ChangeServiceChanged, model.SevLow, "name", p.Name, c.Name, false,
			fmt.Sprintf("Zmiana usługi %s: %s → %s", at, p.Name, c.Name))
	}

	httpComparable := p.HTTP != nil && c.HTTP != nil && c.HTTP.Error == "" && p.HTTP.Error == ""
	httpSame := (p.HTTP == nil) == (c.HTTP == nil) && (c.HTTP == nil || c.HTTP.Error == "")

	if httpSame {
		d.techs(h, p, c, at)
		d.classes(h, p, c, at)
	}
	if httpComparable {
		d.http(h, p, c, at)
	}
	if p.TLS != nil && c.TLS != nil && p.TLS.SHA256 != "" && c.TLS.SHA256 != "" && p.TLS.SHA256 != c.TLS.SHA256 {
		sev := model.SevLow
		note := ""
		switch {
		case c.TLS.Expired:
			sev, note = model.SevMedium, ", nowy certyfikat jest przeterminowany"
		case c.TLS.SelfSigned && !p.TLS.SelfSigned:
			sev, note = model.SevMedium, ", nowy certyfikat jest samopodpisany"
		}
		d.add(h, c, model.ChangeCert, sev, "tls.sha256", certBrief(p.TLS), certBrief(c.TLS), false,
			fmt.Sprintf("Nowy certyfikat TLS %s: %s, ważny do %s%s", at, orDash(c.TLS.SubjectCN), c.TLS.NotAfter.UTC().Format("2006-01-02"), note))
	}
}

func (d *differ) techs(h *HostSnapshot, p, c *model.ServiceResult, at string) {
	pt, ct := techMap(p.Technologies), techMap(c.Technologies)
	names := make([]string, 0, len(pt)+len(ct))
	for n := range pt {
		names = append(names, n)
	}
	for n := range ct {
		if _, ok := pt[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		a, inPrev := pt[n]
		b, inCur := ct[n]
		switch {
		case !inPrev:
			d.add(h, c, model.ChangeTechNew, model.SevLow, "technologies", nil, techLabel(b), false,
				fmt.Sprintf("Nowa technologia na %s: %s", at, techLabel(b)))
		case !inCur:
			d.add(h, c, model.ChangeTechGone, model.SevInfo, "technologies", techLabel(a), nil, false,
				fmt.Sprintf("Technologia %s nie jest już widoczna na %s", techLabel(a), at))
		case a.Version != "" && b.Version != "" && a.Version != b.Version:
			d.add(h, c, model.ChangeTechVersion, model.SevLow, "technologies."+b.Name, a.Version, b.Version, false,
				fmt.Sprintf("Zmiana wersji %s na %s: %s → %s", b.Name, at, a.Version, b.Version))
		}
	}
}

func (d *differ) classes(h *HostSnapshot, p, c *model.ServiceResult, at string) {
	added, removed := setDiff(p.Classes, c.Classes)
	if len(added) == 0 && len(removed) == 0 {
		return
	}
	sev := model.SevInfo
	for _, a := range added {
		if sensitiveClasses[a] {
			sev = model.SevMedium
		}
	}
	var parts []string
	if len(added) > 0 {
		parts = append(parts, "teraz: "+strings.Join(classNames(added), ", "))
	}
	if len(removed) > 0 {
		parts = append(parts, "już nie: "+strings.Join(classNames(removed), ", "))
	}
	d.add(h, c, model.ChangeClass, sev, "classes", sortedCopy(p.Classes), sortedCopy(c.Classes), false,
		fmt.Sprintf("Zmiana klasy usługi %s (%s)", at, strings.Join(parts, "; ")))
}

func (d *differ) http(h *HostSnapshot, p, c *model.ServiceResult, at string) {
	ph, ch := p.HTTP, c.HTTP
	statusChanged := ph.Status != ch.Status && ph.Status != 0 && ch.Status != 0
	if statusChanged {
		d.add(h, c, model.ChangeHTTPStatus, model.SevLow, "http.status", ph.Status, ch.Status, false,
			fmt.Sprintf("Zmiana kodu HTTP %s: %d → %d", at, ph.Status, ch.Status))
	}
	if pt, ct := squash(ph.Title), squash(ch.Title); pt != ct {
		d.add(h, c, model.ChangeTitle, model.SevInfo, "http.title", pt, ct, false,
			fmt.Sprintf("Zmiana tytułu strony %s: %s → %s", at, quote(pt), quote(ct)))
	}
	if pr, cr := redirectTarget(ph), redirectTarget(ch); pr != cr {
		d.add(h, c, model.ChangeRedirect, model.SevLow, "http.final_url", pr, cr, false,
			fmt.Sprintf("Zmiana przekierowania %s: %s → %s", at, orNone(pr), orNone(cr)))
	}

	// Header set: names only, volatile names ignored; values of a few identifying headers.
	pn, cn := headerNames(ph.Headers), headerNames(ch.Headers)
	added, removed := setDiff(pn, cn)
	var valueNotes []string
	for _, name := range []string{"Server", "X-Powered-By", "Www-Authenticate", "X-Generator", "X-Aspnet-Version"} {
		a, b := headerValue(ph.Headers, name), headerValue(ch.Headers, name)
		if a != "" && b != "" && a != b {
			valueNotes = append(valueNotes, fmt.Sprintf("%s: %s → %s", name, a, b))
		}
	}
	if len(added)+len(removed)+len(valueNotes) > 0 {
		sev := model.SevInfo
		for _, r := range removed {
			if securityHeaders[strings.ToLower(r)] {
				sev = model.SevLow
			}
		}
		var parts []string
		if len(added) > 0 {
			parts = append(parts, "dodano "+strings.Join(added, ", "))
		}
		if len(removed) > 0 {
			parts = append(parts, "usunięto "+strings.Join(removed, ", "))
		}
		parts = append(parts, valueNotes...)
		d.add(h, c, model.ChangeHeaders, sev, "http.headers", pn, cn, false,
			fmt.Sprintf("Zmiana nagłówków %s: %s", at, strings.Join(parts, "; ")))
	}

	// Cookie set: names and flags, never values.
	pc, cc := cookieSet(ph.Cookies), cookieSet(ch.Cookies)
	cAdded, cRemoved := setDiff(keys(pc), keys(cc))
	var flagNotes []string
	sev := model.SevInfo
	for name, a := range pc {
		b, ok := cc[name]
		if !ok {
			continue
		}
		if a.Secure != b.Secure || a.HTTPOnly != b.HTTPOnly {
			flagNotes = append(flagNotes, fmt.Sprintf("%s: %s → %s", name, cookieFlags(a), cookieFlags(b)))
			if (a.Secure && !b.Secure) || (a.HTTPOnly && !b.HTTPOnly) {
				sev = model.SevLow
			}
		}
	}
	sort.Strings(flagNotes)
	if len(cAdded)+len(cRemoved)+len(flagNotes) > 0 {
		var parts []string
		if len(cAdded) > 0 {
			parts = append(parts, "dodano "+strings.Join(cAdded, ", "))
		}
		if len(cRemoved) > 0 {
			parts = append(parts, "usunięto "+strings.Join(cRemoved, ", "))
		}
		parts = append(parts, flagNotes...)
		d.add(h, c, model.ChangeCookies, sev, "http.cookies", keys(pc), keys(cc), false,
			fmt.Sprintf("Zmiana ciasteczek %s: %s", at, strings.Join(parts, "; ")))
	}

	// Strong content change. A status change already explains a new body.
	if !statusChanged {
		if dist, ok := SimhashDistance(ph.BodySimhash, ch.BodySimhash); ok {
			if dist >= ContentChangeDistance {
				d.add(h, c, model.ChangeContent, model.SevInfo, "http.body_simhash", ph.BodySimhash, ch.BodySimhash, false,
					fmt.Sprintf("Treść strony %s zmieniła się wyraźnie (odległość simhash %d/64)", at, dist))
			}
		} else if ph.BodySHA256 != "" && ch.BodySHA256 != "" && ph.BodySHA256 != ch.BodySHA256 && lengthChanged(ph.BodyLength, ch.BodyLength) {
			d.add(h, c, model.ChangeContent, model.SevInfo, "http.body_length", ph.BodyLength, ch.BodyLength, false,
				fmt.Sprintf("Treść strony %s zmieniła się wyraźnie (rozmiar %d → %d bajtów)", at, ph.BodyLength, ch.BodyLength))
		}
	}
}

// ---------- helpers ----------

// SimhashDistance returns the Hamming distance of two 64-bit simhashes given
// as hex. ok is false when a value is missing or not hex.
func SimhashDistance(a, b string) (dist int, ok bool) {
	x, okA := parseSimhash(a)
	y, okB := parseSimhash(b)
	if !okA || !okB {
		return 0, false
	}
	return bits.OnesCount64(x ^ y), true
}

func parseSimhash(s string) (uint64, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 64)
	return v, err == nil
}

func lengthChanged(a, b int) bool {
	if a == 0 || b == 0 {
		return a != b
	}
	lo, hi := a, b
	if lo > hi {
		lo, hi = hi, lo
	}
	return float64(hi-lo)/float64(hi) >= 0.3
}

func addr(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + strconv.Itoa(port)
	}
	return ip + ":" + strconv.Itoa(port)
}

func productVersion(s *model.ServiceResult) string {
	v := strings.TrimSpace(s.Product + " " + s.Version)
	if v == "" {
		return s.Name
	}
	return v
}

func productNote(s *model.ServiceResult) string {
	if v := productVersion(s); v != "" {
		return " (" + v + ")"
	}
	return ""
}

func openPortsNote(svcs []model.ServiceResult) string {
	var ports []int
	for i := range svcs {
		if isOpen(&svcs[i]) {
			ports = append(ports, svcs[i].Port)
		}
	}
	if len(ports) == 0 {
		return ""
	}
	sort.Ints(ports)
	strs := make([]string, 0, len(ports))
	for i, p := range ports {
		if i == 8 {
			strs = append(strs, "…")
			break
		}
		strs = append(strs, strconv.Itoa(p))
	}
	return fmt.Sprintf(" (otwarte porty: %s)", strings.Join(strs, ", "))
}

func isSensitive(s *model.ServiceResult) bool {
	for _, c := range EffectiveClasses(s, nil) {
		if sensitiveClasses[c] && c != model.ClassLogin {
			return true
		}
	}
	return false
}

func techMap(ts []model.Technology) map[string]model.Technology {
	m := make(map[string]model.Technology, len(ts))
	for _, t := range ts {
		if t.Name == "" || (t.Confidence > 0 && t.Confidence < MinTechConfidence) {
			continue
		}
		m[strings.ToLower(t.Name)] = t
	}
	return m
}

func techLabel(t model.Technology) string { return strings.TrimSpace(t.Name + " " + t.Version) }

func setDiff(before, after []string) (added, removed []string) {
	b := make(map[string]bool, len(before))
	for _, x := range before {
		b[x] = true
	}
	a := make(map[string]bool, len(after))
	for _, x := range after {
		a[x] = true
		if !b[x] {
			added = append(added, x)
		}
	}
	for _, x := range before {
		if !a[x] {
			removed = append(removed, x)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return dedupSorted(added), dedupSorted(removed)
}

func dedupSorted(s []string) []string {
	if len(s) < 2 {
		return s
	}
	out := s[:1]
	for _, x := range s[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

func sortedCopy(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

func headerNames(h map[string][]string) []string {
	out := make([]string, 0, len(h))
	for name := range h {
		if !IsVolatileHeader(name) {
			out = append(out, canonicalHeader(name))
		}
	}
	sort.Strings(out)
	return dedupSorted(out)
}

func canonicalHeader(name string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(name)), "-")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "-")
}

func headerValue(h map[string][]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
	}
	return ""
}

var cookieNoise = regexp.MustCompile(`[0-9a-fA-F]{8,}|\d{4,}`)

// cookieName normalises names that carry a session or site id, for example
// Drupal's SESS<hash>.
func cookieName(n string) string { return cookieNoise.ReplaceAllString(n, "#") }

func cookieSet(cs []model.Cookie) map[string]model.Cookie {
	m := make(map[string]model.Cookie, len(cs))
	for _, c := range cs {
		if c.Name != "" {
			m[cookieName(c.Name)] = c
		}
	}
	return m
}

func cookieFlags(c model.Cookie) string {
	var f []string
	if c.Secure {
		f = append(f, "Secure")
	}
	if c.HTTPOnly {
		f = append(f, "HttpOnly")
	}
	if len(f) == 0 {
		return "bez flag"
	}
	return strings.Join(f, "+")
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// redirectTarget is where the first request ended, without query and
// fragment (they often carry session ids). Empty when there was no redirect.
func redirectTarget(h *model.HTTPFingerprint) string {
	target := ""
	if len(h.Redirects) > 0 {
		target = h.Redirects[len(h.Redirects)-1].To
	}
	if target == "" && h.FinalURL != "" && h.FinalURL != h.URL {
		target = h.FinalURL
	}
	if target == "" {
		return ""
	}
	if u, err := url.Parse(target); err == nil {
		u.RawQuery, u.Fragment = "", ""
		return u.String()
	}
	return target
}

func certBrief(t *model.TLSInfo) map[string]any {
	return map[string]any{"subject_cn": t.SubjectCN, "issuer": t.Issuer, "not_after": t.NotAfter.UTC().Format(time.RFC3339), "sha256": t.SHA256}
}

func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

func quote(s string) string {
	if s == "" {
		return "(brak)"
	}
	return "„" + s + "”"
}

func orNone(s string) string {
	if s == "" {
		return "(brak)"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

var classPL = map[string]string{
	model.ClassAdminPanel: "panel administracyjny", model.ClassLogin: "strona logowania", model.ClassStaging: "środowisko testowe",
	model.ClassIoT: "urządzenie IoT", model.ClassDefaultPage: "strona domyślna", model.ClassAPI: "API",
	model.ClassDevTool: "narzędzie deweloperskie", model.ClassDatabase: "baza danych", model.ClassRemoteAccess: "zdalny dostęp",
	model.ClassDirListing: "listing katalogu", model.ClassErrorPage: "strona błędu",
}

func classNames(cs []string) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		if n, ok := classPL[c]; ok {
			out[i] = n
		} else {
			out[i] = c
		}
	}
	return out
}

// ipLess orders addresses numerically; text that is not an address sorts last.
func ipLess(a, b string) bool {
	x, errA := netip.ParseAddr(a)
	y, errB := netip.ParseAddr(b)
	switch {
	case errA == nil && errB == nil:
		return x.Less(y)
	case errA == nil:
		return true
	case errB == nil:
		return false
	}
	return a < b
}

// openCount is the number of open services in the list.
func openCount(svcs []model.ServiceResult) int {
	n := 0
	for i := range svcs {
		if isOpen(&svcs[i]) {
			n++
		}
	}
	return n
}

// servicesGone reports every open service of a host reported inactive as
// gone. Ports outside the scope of the newer run stay unknown.
func (d *differ) servicesGone(cur, prev *HostSnapshot) {
	gone := make([]*model.ServiceResult, 0, len(prev.Services))
	for i := range prev.Services {
		p := &prev.Services[i]
		if !isOpen(p) {
			continue
		}
		proto := p.Proto
		if proto == "" {
			proto = "tcp"
		}
		if d.opts.PortInScope != nil && !d.opts.PortInScope(proto, p.Port) {
			continue
		}
		gone = append(gone, p)
	}
	sort.SliceStable(gone, func(i, j int) bool { return gone[i].Port < gone[j].Port })
	for _, p := range gone {
		d.add(cur, p, model.ChangeServiceGone, model.SevLow, "state", "open", "host-down",
			false, fmt.Sprintf("Usługa %s zniknęła%s: host zgłoszony jako nieaktywny", addr(cur.IP, p.Port), productNote(p)))
	}
}

// goneSummary is the sentence of host_gone.
func goneSummary(h *HostSnapshot) string {
	if h.Rule > 0 {
		return fmt.Sprintf("Host %s zgłoszony jako nieaktywny: brak odpowiedzi w %d %s z rzędu (reguła profilu: zgłoszenie po %d %s)",
			h.IP, h.Rule, plural(h.Rule, "przebiegu", "przebiegach", "przebiegach"), h.Rule, plural(h.Rule, "braku", "brakach", "brakach"))
	}
	s := fmt.Sprintf("Host %s zgłoszony jako nieaktywny: nie odpowiada w godzinach, w których zwykle odpowiadał", h.IP)
	if h.PAlive > 0 {
		s += "; model: p_alive " + decimalPL(h.PAlive)
	}
	return s
}

// missingSummary is the sentence of host_missing, with the model's view.
func missingSummary(h *HostSnapshot, open int) string {
	prev := "w poprzednim aktywny"
	if open > 0 {
		prev += fmt.Sprintf(", %d %s", open, plural(open, "otwarta usługa", "otwarte usługi", "otwartych usług"))
	}
	s := fmt.Sprintf("Host %s nie odpowiedział w tym przebiegu (%s); ", h.IP, prev)
	var parts []string
	if h.PAlive > 0 {
		parts = append(parts, "p_alive "+decimalPL(h.PAlive))
	}
	switch {
	case h.MissesToDown == 1:
		parts = append(parts, "zgłoszenie nieaktywności po kolejnym braku")
	case h.MissesToDown > 1 && h.MissesToDown < DownAfterHorizon:
		parts = append(parts, fmt.Sprintf("zgłoszenie nieaktywności po %d kolejnych brakach", h.MissesToDown))
	case h.MissesToDown >= DownAfterHorizon:
		parts = append(parts, "zgłoszenie nieaktywności dopiero po wielu kolejnych brakach")
	}
	if len(parts) == 0 {
		parts = append(parts, "jeszcze nie zgłoszony jako nieaktywny")
	}
	if h.Rule > 0 {
		parts = append(parts, fmt.Sprintf("reguła profilu: %d %s z rzędu", h.Rule, plural(h.Rule, "brak", "braki", "braków")))
	}
	return s + "model: " + strings.Join(parts, ", ")
}

// plural picks the Polish form for n: one, few (2-4, not 12-14), many.
func plural(n int, one, few, many string) string {
	if n == 1 {
		return one
	}
	if m10, m100 := n%10, n%100; m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) {
		return few
	}
	return many
}

// decimalPL formats a probability with two decimals and a decimal comma.
func decimalPL(f float64) string {
	return strings.Replace(strconv.FormatFloat(f, 'f', 2, 64), ".", ",", 1)
}
