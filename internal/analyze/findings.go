package analyze

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Finding types produced by DeriveFindings.
const (
	FindingAdminPanel     = "admin-panel"
	FindingLoginPlainHTTP = "login-plain-http"
	FindingStaging        = "staging"
	FindingDebugPage      = "debug-page"
	FindingIoT            = "iot-device"
	FindingDevTool        = "dev-tool"
	FindingDatabase       = "database-exposed"
	FindingRemoteAccess   = "remote-access-exposed"
	FindingExpiredCert    = "expired-cert"
	FindingCertExpiring   = "cert-expiring"
	FindingSelfSigned     = "self-signed-cert"
	FindingHostMismatch   = "hostname-mismatch"
	FindingHeader         = "interesting-header"
	FindingCookie         = "interesting-cookie"
	FindingDirListing     = "directory-listing"
	FindingDefaultPage    = "default-page"
	FindingNewExposure    = "new-exposure"
	FindingSignature      = "signature"
)

// SignatureFindingMinInterest: a signature match becomes a finding of type
// "signature" when its interest weight is at least this value, or when it
// carries the tag "custom" or "finding". Plain technology matches stay
// technologies.
const SignatureFindingMinInterest = 10

// FindingService is one service of the host, with what the store knows about it.
type FindingService struct {
	Result    model.ServiceResult
	ServiceID *int64
	// New: first seen in this run, and this run is not the first one.
	New bool
	// Interest is the interest score of the service. Findings no longer
	// copy it: each finding has its own interest (FindingInterest).
	Interest int
}

// FindingInput is one host of one run.
type FindingInput struct {
	HostID    int64
	IP        string
	Hostnames []string
	Services  []FindingService
	RunID     int64
	At        time.Time
	// ScopeCriticality is the highest criticality (1..5) of the host's
	// scopes; 0 means unknown. It raises the interest of every finding.
	ScopeCriticality int
}

// FindingKey builds the stable key of a finding: type, host, port and
// subject. A rescan that sees the same thing produces the same key, so the
// store updates the finding instead of creating a new one. The key is also
// the unique_id_from_tool in DefectDojo.
func FindingKey(typ, ip string, port int, proto, subject string) string {
	if proto == "" {
		proto = "tcp"
	}
	key := fmt.Sprintf("%s/%s/%s-%d", typ, ip, proto, port)
	if s := slug(subject); s != "" {
		key += "/" + s
	}
	return key
}

var reSlug = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	s = strings.Trim(reSlug.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// Severity of derived findings. Czujka reports observations, not
// vulnerabilities, so the default is info. A few observations that an
// analyst should look at first are low:
//
//	login-plain-http, database-exposed, debug-page, directory-listing,
//	expired-cert, remote-access-exposed (telnet, rlogin only)  -> low
//	everything else                                              -> info
var lowFindings = map[string]bool{
	FindingLoginPlainHTTP: true, FindingDatabase: true, FindingDebugPage: true,
	FindingDirListing: true, FindingExpiredCert: true,
}

// DeriveFindings turns one host and its services into findings. It is
// deterministic: the same input gives the same findings in the same order.
func DeriveFindings(in FindingInput) []model.Finding {
	var out []model.Finding
	for i := range in.Services {
		fs := &in.Services[i]
		s := &fs.Result
		if !isOpen(s) {
			continue
		}
		b := findingBuilder{in: &in, fs: fs, s: s, sigPoints: -1}
		b.derive()
		b.merge()
		out = append(out, b.out...)
	}
	return out
}

type findingBuilder struct {
	in  *FindingInput
	fs  *FindingService
	s   *model.ServiceResult
	out []model.Finding
	// sigPoints is the weighted interest of the signature match being
	// added (header, cookie and signature findings); -1 when none.
	sigPoints int
}

func (b *findingBuilder) add(typ, subject, title, desc string, ev []model.Evidence, signature string, extraTags ...string) {
	s := b.s
	sev := model.SevInfo
	if lowFindings[typ] {
		sev = model.SevLow
	}
	if typ == FindingRemoteAccess {
		switch strings.ToLower(s.Name) {
		case "telnet", "rlogin", "login", "shell", "exec":
			sev = model.SevLow
		}
	}
	tags := append([]string{typ}, extraTags...)
	u := ""
	if s.HTTP != nil {
		u = firstNonEmpty(s.HTTP.URL, s.HTTP.FinalURL)
	}
	if len(ev) > 12 {
		ev = ev[:12]
	}
	b.out = append(b.out, model.Finding{
		Key: FindingKey(typ, b.in.IP, s.Port, s.Proto, subject), Type: typ,
		Title:       title + " (" + addr(b.in.IP, s.Port) + ")",
		Description: desc, Severity: sev, Status: model.FindingNew, Interest: b.interest(typ, ev),
		HostID: b.in.HostID, IP: b.in.IP, ServiceID: b.fs.ServiceID, Port: s.Port, URL: u,
		Signature: signature, Evidence: ev, Tags: dedupSorted(sortedCopy(tags)),
		FirstSeen: b.in.At, LastSeen: b.in.At, FirstRunID: b.in.RunID, LastRunID: b.in.RunID,
	})
}

// classEvidence collects the evidence of the signature matches that carry a
// class, and the slug and name of the strongest one.
func (b *findingBuilder) classEvidence(class string) (ev []model.Evidence, sigSlug, name string) {
	best := -1.0
	for _, m := range b.s.Matches {
		if !hasClass(m.Classes, class) {
			continue
		}
		ev = append(ev, m.Evidence...)
		if m.Confidence > best {
			best, sigSlug, name = m.Confidence, m.Signature, m.Name
		}
	}
	return ev, sigSlug, name
}

func (b *findingBuilder) baseEvidence() []model.Evidence {
	s := b.s
	var ev []model.Evidence
	if s.HTTP != nil && s.HTTP.Error == "" {
		if s.HTTP.Title != "" {
			ev = append(ev, model.Evidence{Matcher: "title", Where: "title", Snippet: clip(s.HTTP.Title, 120)})
		}
		if s.HTTP.Status != 0 {
			ev = append(ev, model.Evidence{Matcher: "status", Where: "url:" + s.HTTP.URL, Snippet: fmt.Sprintf("HTTP %d", s.HTTP.Status)})
		} else if s.HTTP.Title == "" {
			ev = append(ev, model.Evidence{Matcher: "path", Where: "url:" + s.HTTP.URL, Snippet: clip(firstNonEmpty(s.HTTP.Server, productVersion(s), s.HTTP.URL), 120)})
		}
	} else if v := productVersion(s); v != "" {
		ev = append(ev, model.Evidence{Matcher: "banner", Where: fmt.Sprintf("port:%d/%s", s.Port, firstNonEmpty(s.Proto, "tcp")), Snippet: clip(firstNonEmpty(s.Banner, v), 120)})
	}
	return ev
}

func (b *findingBuilder) derive() {
	s := b.s
	classes := EffectiveClasses(s, b.in.Hostnames)
	has := func(c string) bool { return hasClass(classes, c) }
	what := func(name string) string {
		if name != "" {
			return name
		}
		if s.HTTP != nil && s.HTTP.Title != "" {
			return clip(s.HTTP.Title, 60)
		}
		return productVersion(s)
	}
	withBase := func(ev []model.Evidence) []model.Evidence { return append(ev, b.baseEvidence()...) }

	if has(model.ClassAdminPanel) {
		ev, sig, name := b.classEvidence(model.ClassAdminPanel)
		b.add(FindingAdminPanel, sig, "Panel administracyjny: "+what(name),
			"Pod tym adresem odpowiada panel administracyjny. Sprawdź, czy musi być dostępny z tej sieci.",
			withBase(ev), sig)
	}
	if has(model.ClassLogin) && isPlainHTTP(s) {
		ev, sig, name := b.classEvidence(model.ClassLogin)
		b.add(FindingLoginPlainHTTP, "", "Logowanie bez szyfrowania (HTTP): "+what(name),
			"Strona logowania działa bez TLS. Hasło można podsłuchać w sieci.",
			withBase(ev), sig)
	}
	if has(model.ClassStaging) {
		ev, sig, name := b.classEvidence(model.ClassStaging)
		for _, h := range append([]string{hostOf(s)}, b.in.Hostnames...) {
			if h != "" && reStagingName.MatchString(h) {
				ev = append(ev, model.Evidence{Matcher: "hostname", Where: "hostname", Snippet: h})
				break
			}
		}
		b.add(FindingStaging, "", "Środowisko testowe: "+what(name),
			"Usługa wygląda na środowisko testowe. Sprawdź, czy musi być dostępna z tej sieci.",
			withBase(ev), sig)
	}
	if ok, ev := isDebugPage(s); ok {
		b.add(FindingDebugPage, "", "Strona diagnostyczna lub tryb debug: "+what(""),
			"Strona może ujawniać konfigurację i ścieżki aplikacji.",
			withBase(ev), "")
	}
	if has(model.ClassIoT) {
		ev, sig, name := b.classEvidence(model.ClassIoT)
		b.add(FindingIoT, sig, "Urządzenie IoT: "+what(name),
			"Pod tym adresem odpowiada urządzenie IoT. Sprawdź, czy jego interfejs musi być dostępny z tej sieci.",
			withBase(ev), sig)
	}
	if has(model.ClassDevTool) {
		ev, sig, name := b.classEvidence(model.ClassDevTool)
		b.add(FindingDevTool, sig, "Narzędzie deweloperskie: "+what(name),
			"Pod tym adresem odpowiada narzędzie deweloperskie. Takie narzędzia mają dostęp do kodu i sekretów.",
			withBase(ev), sig)
	}
	// A web tool for databases (phpMyAdmin, Adminer, pgAdmin) is an admin
	// panel, and the admin-panel finding names it; "database open to the
	// network" is for the database protocol itself. Measured on the lab: the
	// three web tools each had both findings at the top of the list.
	if has(model.ClassDatabase) && s.HTTP == nil {
		ev, sig, _ := b.classEvidence(model.ClassDatabase)
		b.add(FindingDatabase, "", "Baza danych dostępna z sieci: "+firstNonEmpty(productVersion(s), "port "+fmt.Sprint(s.Port)),
			"Port bazy danych przyjmuje połączenia z sieci, z której wykonano skan.",
			withBase(ev), sig)
	}
	if has(model.ClassRemoteAccess) {
		ev, sig, _ := b.classEvidence(model.ClassRemoteAccess)
		b.add(FindingRemoteAccess, "", "Usługa zdalnego dostępu: "+firstNonEmpty(productVersion(s), s.Name),
			"Usługa zdalnego dostępu przyjmuje połączenia z sieci, z której wykonano skan.",
			withBase(ev), sig)
	}
	if has(model.ClassDirListing) {
		ev, sig, _ := b.classEvidence(model.ClassDirListing)
		b.add(FindingDirListing, "", "Listing katalogu: "+what(""),
			"Serwer pokazuje listę plików katalogu. Listing może ujawniać kopie zapasowe i pliki konfiguracyjne.",
			withBase(ev), sig)
	}
	if has(model.ClassDefaultPage) {
		ev, sig, _ := b.classEvidence(model.ClassDefaultPage)
		b.add(FindingDefaultPage, "", "Strona domyślna serwera: "+what(""),
			"Serwer pokazuje stronę domyślną. To zwykle zapomniana lub nieskonfigurowana instalacja.",
			withBase(ev), sig)
	}

	if t := s.TLS; t != nil {
		certEv := []model.Evidence{{Matcher: "tls", Where: "tls:certificate", Snippet: clip(fmt.Sprintf("CN=%s; wystawca=%s; ważny do %s; sha256=%s",
			t.SubjectCN, t.Issuer, t.NotAfter.UTC().Format("2006-01-02"), clipHash(t.SHA256)), 200)}}
		expired, days := certState(t, b.in.At)
		switch {
		case expired:
			b.add(FindingExpiredCert, "", "Przeterminowany certyfikat TLS: "+orDash(t.SubjectCN),
				fmt.Sprintf("Certyfikat TLS stracił ważność %s.", t.NotAfter.UTC().Format("2006-01-02")), certEv, "")
		case !t.NotAfter.IsZero() && days <= CertExpiringDays:
			b.add(FindingCertExpiring, "", "Certyfikat TLS wkrótce wygaśnie: "+orDash(t.SubjectCN),
				fmt.Sprintf("Certyfikat TLS wygasa %s (za %d %s).", t.NotAfter.UTC().Format("2006-01-02"), days, plural(days, "dzień", "dni", "dni")), certEv, "")
		}
		if t.SelfSigned {
			b.add(FindingSelfSigned, "", "Samopodpisany certyfikat TLS: "+orDash(t.SubjectCN),
				"Certyfikat TLS jest samopodpisany. Klient nie może sprawdzić tożsamości serwera.", certEv, "")
		}
		if t.HostMismatch {
			b.add(FindingHostMismatch, "", "Certyfikat TLS nie pasuje do nazwy hosta: "+orDash(t.SubjectCN),
				"Nazwa w certyfikacie (CN, SAN) nie pasuje do nazwy, pod którą usługa odpowiada: "+strings.Join(clipList(t.SANs, 6), ", ")+".", certEv, "")
		}
	}

	if s.HTTP != nil && s.HTTP.Error == "" {
		if ev := interestingHeaders(s.HTTP.Headers); len(ev) > 0 {
			names := make([]string, len(ev))
			for i, e := range ev {
				names[i] = strings.TrimPrefix(e.Where, "header:")
			}
			b.add(FindingHeader, "", "Nagłówki ujawniają szczegóły oprogramowania: "+strings.Join(names, ", "),
				evidenceText(ev), ev, "")
		}
		if ev := cookieEvidence(s.HTTP.Cookies, isTLS(s)); len(ev) > 0 {
			names := make([]string, len(ev))
			for i, e := range ev {
				names[i] = strings.TrimPrefix(e.Where, "cookie:")
			}
			b.add(FindingCookie, "", "Ciasteczka: "+strings.Join(names, ", "),
				"Ciasteczka wskazują technologię albo są sesyjne bez flag Secure i HttpOnly.", ev, "")
		}
	}

	// Signature matches: header and cookie categories keep their own type;
	// other matches with an interest weight become "signature" findings.
	for _, m := range s.Matches {
		custom := false
		for _, t := range m.Tags {
			if strings.EqualFold(t, "custom") || strings.EqualFold(t, "finding") {
				custom = true
			}
		}
		name := firstNonEmpty(m.Name, m.Signature)
		b.sigPoints = sigPoints(m)
		if (m.Category == model.CatHeader || m.Category == model.CatCookie) && b.attachToClassFinding(m) {
			continue // the same observation as a class finding of this service
		}
		switch {
		case m.Category == model.CatHeader:
			b.add(FindingHeader, m.Signature, "Nagłówek: "+name,
				evidenceText(m.Evidence), m.Evidence, m.Signature, m.Tags...)
		case m.Category == model.CatCookie:
			b.add(FindingCookie, m.Signature, "Ciasteczko: "+name,
				evidenceText(m.Evidence), m.Evidence, m.Signature, m.Tags...)
		case len(m.Classes) > 0 && !custom:
			// Already reported through its class.
		case custom || m.Interest >= SignatureFindingMinInterest:
			title := "Dopasowanie sygnatury: " + strings.TrimSpace(name+" "+m.Version)
			b.add(FindingSignature, m.Signature, title,
				fmt.Sprintf("Sygnatura „%s” pasuje do tej usługi (pewność %.0f%%).", m.Signature, m.Confidence*100),
				m.Evidence, m.Signature, m.Tags...)
		}
	}

	b.sigPoints = -1
	if b.fs.New {
		b.add(FindingNewExposure, "", "Nowa ekspozycja: "+firstNonEmpty(what(""), "port "+fmt.Sprint(s.Port)),
			"Usługa nie była widoczna w poprzednich skanach. Sprawdź, czy jej wystawienie jest zamierzone.",
			b.baseEvidence(), "")
	}
}

// evidenceText lists the evidence as data: "X-Powered-By: PHP/7.4.3" for a
// header, the name only for a cookie (never its value).
func evidenceText(ev []model.Evidence) string {
	var parts []string
	for _, e := range ev {
		switch {
		case strings.HasPrefix(e.Where, "header:"):
			parts = append(parts, strings.TrimPrefix(e.Where, "header:")+": "+e.Snippet)
		case strings.HasPrefix(e.Where, "cookie:"):
			parts = append(parts, strings.TrimPrefix(e.Where, "cookie:"))
		case e.Snippet != "":
			parts = append(parts, e.Snippet)
		}
	}
	return strings.Join(clipList(dedupSorted(sortedCopy(parts)), 6), "; ")
}

func hostOf(s *model.ServiceResult) string {
	if s.HTTP != nil {
		return s.HTTP.Host
	}
	return ""
}

func clipHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}

func clipList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string{}, s[:n]...), "…")
}

// techCookies are cookie names that identify a technology.
var techCookies = map[string]string{
	"phpsessid": "PHP", "jsessionid": "Java", "asp.net_sessionid": "ASP.NET", "laravel_session": "Laravel",
	"csrftoken": "Django", "connect.sid": "Express", "ci_session": "CodeIgniter", "cakephp": "CakePHP",
	"_gitlab_session": "GitLab", "grafana_session": "Grafana", "jenkins-timestamper-offset": "Jenkins",
	"wp-settings-1": "WordPress", "symfony": "Symfony", "rack.session": "Rack", "_session_id": "Rails",
}

// cookieEvidence lists cookies worth a look. It never includes a value.
func cookieEvidence(cs []model.Cookie, tls bool) []model.Evidence {
	var ev []model.Evidence
	for _, c := range cs {
		var notes []string
		lname := strings.ToLower(c.Name)
		if tech, ok := techCookies[lname]; ok {
			notes = append(notes, "wskazuje technologię "+tech)
		} else if strings.HasPrefix(lname, "wordpress_") || strings.HasPrefix(lname, "wp-") {
			notes = append(notes, "wskazuje technologię WordPress")
		} else if strings.HasPrefix(lname, "sess") && len(c.Name) > 20 {
			notes = append(notes, "wskazuje technologię Drupal")
		}
		if reSessionCookie.MatchString(c.Name) {
			if !c.HTTPOnly {
				notes = append(notes, "brak flagi HttpOnly")
			}
			if tls && !c.Secure {
				notes = append(notes, "brak flagi Secure")
			}
		}
		if strings.HasPrefix(c.Value, "eyJ") {
			notes = append(notes, "wartość wygląda na token JWT")
		}
		if len(notes) > 0 {
			ev = append(ev, model.Evidence{Matcher: "cookie", Where: "cookie:" + c.Name, Snippet: strings.Join(notes, "; ")})
		}
	}
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].Where < ev[j].Where })
	return ev
}

// ---------- interest of one finding ----------

// FindingBaseInterest is the interest (0..100) of each finding type, from
// its own type and evidence. It answers "what should an analyst open
// first": an exposed admin panel, a debug page or a database open to the
// network on top; a revealing header or a framework cookie at the bottom.
// Modifiers (FindingInterest): signature weight for header, cookie and
// signature findings; login context for certificate findings; scope
// criticality 4 adds 5, 5 adds 10; a service new since the previous run
// adds 10. The result is capped at 100.
var FindingBaseInterest = map[string]int{
	FindingAdminPanel:     75,
	FindingDebugPage:      75,
	FindingDatabase:       70,
	FindingDevTool:        60,
	FindingDirListing:     55,
	FindingLoginPlainHTTP: 50,
	FindingStaging:        45,
	FindingIoT:            45,
	FindingExpiredCert:    40, // 70 on a login page
	FindingNewExposure:    40,
	FindingRemoteAccess:   20, // telnet/rlogin 70, RDP/VNC 50
	FindingSelfSigned:     25, // 40 on a login page
	FindingHostMismatch:   20,
	FindingCertExpiring:   20,
	FindingHeader:         15, // signature header findings: weight clamped to 5..25
	FindingDefaultPage:    15,
	FindingCookie:         10, // 25 for a session cookie without flags, 20 for a JWT
	FindingSignature:      30, // weight clamped to 10..60
}

// Bounds of the signature weight for each finding type.
const (
	WeakFindingMin = 5
	WeakFindingMax = 25
	SigFindingMin  = 10
	SigFindingMax  = 60
)

func sigPoints(m model.SigMatch) int {
	conf := m.Confidence
	if conf <= 0 || conf > 1 {
		conf = 1
	}
	return int(float64(m.Interest)*conf + 0.5)
}

func clampInt(v, lo, hi int) int {
	return max(lo, min(hi, v))
}

// interest computes the interest of a finding of type typ on this service.
func (b *findingBuilder) interest(typ string, ev []model.Evidence) int {
	s := b.s
	login := hasClass(EffectiveClasses(s, b.in.Hostnames), model.ClassLogin)
	p := FindingBaseInterest[typ]
	switch typ {
	case FindingHeader:
		if b.sigPoints >= 0 {
			p = clampInt(b.sigPoints, WeakFindingMin, WeakFindingMax)
		}
	case FindingCookie:
		if b.sigPoints >= 0 {
			p = clampInt(b.sigPoints, WeakFindingMin, WeakFindingMax)
		} else {
			for _, e := range ev {
				switch {
				case strings.Contains(e.Snippet, "brak flagi"):
					p = max(p, 25)
				case strings.Contains(e.Snippet, "JWT"):
					p = max(p, 20)
				}
			}
		}
	case FindingSignature:
		if b.sigPoints >= 0 {
			p = clampInt(b.sigPoints, SigFindingMin, SigFindingMax)
		}
	case FindingExpiredCert:
		if login {
			p = 70
		}
	case FindingSelfSigned:
		if login {
			p = 40
		}
	case FindingRemoteAccess:
		switch strings.ToLower(s.Name) {
		case "telnet", "rlogin", "login", "shell", "exec":
			p = 70
		case "ms-wbt-server", "rdp", "vnc", "vnc-http", "x11", "teamviewer":
			p = 50
		}
	}
	switch {
	case b.in.ScopeCriticality >= 5:
		p += 10
	case b.in.ScopeCriticality == 4:
		p += 5
	}
	if b.fs.New && typ != FindingNewExposure {
		p += 10
	}
	// Tie-break inside one type: the service's own interest adds 0..4 (one
	// point per 10 above 50). Measured on the lab: 15 findings shared the top
	// value 75; the service interest separates a router panel over plain
	// HTTP (96) from a WordPress login page (80).
	p += clampInt((min(b.fs.Interest, 99)-50)/10, 0, 4)
	return min(p, 100)
}

// ---------- near-duplicates on one service ----------

// classFinding maps a service class to the finding type it produces.
var classFinding = map[string]string{
	model.ClassAdminPanel: FindingAdminPanel, model.ClassLogin: FindingLoginPlainHTTP, model.ClassStaging: FindingStaging,
	model.ClassIoT: FindingIoT, model.ClassDevTool: FindingDevTool, model.ClassDatabase: FindingDatabase,
	model.ClassRemoteAccess: FindingRemoteAccess, model.ClassDirListing: FindingDirListing, model.ClassDefaultPage: FindingDefaultPage,
}

// attachToClassFinding adds the evidence of a header or cookie signature
// that carries a class to the finding that class already produced on this
// service (for example the signature "login form over plain HTTP" and the
// finding login-plain-http). It reports whether it did.
func (b *findingBuilder) attachToClassFinding(m model.SigMatch) bool {
	for _, c := range m.Classes {
		typ, ok := classFinding[c]
		if !ok {
			continue
		}
		for i := range b.out {
			if b.out[i].Type == typ {
				b.out[i].Evidence = mergeEvidence(b.out[i].Evidence, m.Evidence)
				if b.out[i].Signature == "" {
					b.out[i].Signature = m.Signature
				}
				return true
			}
		}
	}
	return false
}

// merge joins the header findings of one service into one finding, and the
// cookie findings into one: they describe the same thing (what the
// response headers or cookies reveal) with several evidence lines. The
// merged finding keeps the highest interest and the key without a subject.
func (b *findingBuilder) merge() {
	var out []model.Finding
	at := map[string]int{}
	for _, f := range b.out {
		if f.Type != FindingHeader && f.Type != FindingCookie {
			out = append(out, f)
			continue
		}
		i, ok := at[f.Type]
		if !ok {
			at[f.Type] = len(out)
			f.Key = FindingKey(f.Type, b.in.IP, b.s.Port, b.s.Proto, "")
			f.Title = mergedTitle(f.Type, []string{subjectOf(f.Title)}) + " (" + addr(b.in.IP, b.s.Port) + ")"
			out = append(out, f)
			continue
		}
		m := &out[i]
		parts := strings.Split(strings.TrimPrefix(strings.TrimSuffix(m.Title, " ("+addr(b.in.IP, b.s.Port)+")"), mergedPrefix(f.Type)), "; ")
		parts = append(parts, subjectOf(f.Title))
		m.Title = mergedTitle(f.Type, parts) + " (" + addr(b.in.IP, b.s.Port) + ")"
		m.Evidence = mergeEvidence(m.Evidence, f.Evidence)
		m.Interest = max(m.Interest, f.Interest)
		m.Tags = dedupSorted(sortedCopy(append(append([]string{}, m.Tags...), f.Tags...)))
		if m.Signature == "" {
			m.Signature = f.Signature
		}
		if !strings.Contains(m.Description, f.Description) {
			m.Description += " " + f.Description
		}
	}
	b.out = out
}

func mergedPrefix(typ string) string {
	if typ == FindingCookie {
		return "Ciasteczka: "
	}
	return "Nagłówki HTTP: "
}

func mergedTitle(typ string, parts []string) string {
	seen := map[string]bool{}
	var keep []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" && !seen[p] {
			seen[p] = true
			keep = append(keep, p)
		}
	}
	return mergedPrefix(typ) + strings.Join(keep, "; ")
}

// subjectOf returns the part of a finding title after the first ": " and
// before the address in brackets.
func subjectOf(title string) string {
	if i := strings.LastIndex(title, " ("); i > 0 {
		title = title[:i]
	}
	if _, after, ok := strings.Cut(title, ": "); ok {
		return after
	}
	return title
}

func mergeEvidence(a, b []model.Evidence) []model.Evidence {
	seen := map[string]bool{}
	out := make([]model.Evidence, 0, len(a)+len(b))
	for _, e := range append(append([]model.Evidence{}, a...), b...) {
		k := e.Matcher + "|" + e.Where + "|" + e.Snippet
		if !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}
