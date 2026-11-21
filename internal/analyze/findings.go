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
	// Interest is the interest score of the service, copied to its findings.
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
		b := findingBuilder{in: &in, fs: fs, s: s}
		b.derive()
		out = append(out, b.out...)
	}
	return out
}

type findingBuilder struct {
	in  *FindingInput
	fs  *FindingService
	s   *model.ServiceResult
	out []model.Finding
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
		Description: desc, Severity: sev, Status: model.FindingNew, Interest: b.fs.Interest,
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
			"Pod tym adresem odpowiada panel administracyjny. Czujka stwierdza tylko jego obecność; nie próbuje się logować. Sprawdź, czy panel musi być dostępny z tej sieci.",
			withBase(ev), sig)
	}
	if has(model.ClassLogin) && isPlainHTTP(s) {
		ev, sig, name := b.classEvidence(model.ClassLogin)
		b.add(FindingLoginPlainHTTP, "", "Logowanie przez nieszyfrowane HTTP: "+what(name),
			"Strona logowania jest serwowana bez TLS. Dane logowania przesyłane tą drogą można podsłuchać w sieci.",
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
		b.add(FindingStaging, "", "Środowisko testowe lub staging: "+what(name),
			"Usługa wygląda na środowisko testowe, deweloperskie lub staging. Takie środowiska często mają słabszą konfigurację i dane testowe.",
			withBase(ev), sig)
	}
	if ok, ev := isDebugPage(s); ok {
		b.add(FindingDebugPage, "", "Strona diagnostyczna lub tryb debug: "+what(""),
			"Usługa pokazuje stronę diagnostyczną albo działa w trybie debug. Taka strona może ujawniać konfigurację i ścieżki aplikacji.",
			withBase(ev), "")
	}
	if has(model.ClassIoT) {
		ev, sig, name := b.classEvidence(model.ClassIoT)
		b.add(FindingIoT, sig, "Urządzenie IoT: "+what(name),
			"Pod tym adresem odpowiada urządzenie IoT (kamera, drukarka, router, sterownik). Sprawdź, czy jego interfejs musi być dostępny z tej sieci.",
			withBase(ev), sig)
	}
	if has(model.ClassDevTool) {
		ev, sig, name := b.classEvidence(model.ClassDevTool)
		b.add(FindingDevTool, sig, "Narzędzie deweloperskie: "+what(name),
			"Pod tym adresem odpowiada narzędzie deweloperskie (CI, repozytorium kodu, monitoring). Takie narzędzia mają dostęp do kodu i sekretów.",
			withBase(ev), sig)
	}
	if has(model.ClassDatabase) {
		ev, sig, _ := b.classEvidence(model.ClassDatabase)
		b.add(FindingDatabase, "", "Baza danych dostępna z sieci: "+firstNonEmpty(productVersion(s), "port "+fmt.Sprint(s.Port)),
			"Port bazy danych przyjmuje połączenia z sieci, z której wykonano skan. Czujka nie próbuje się łączyć ani logować.",
			withBase(ev), sig)
	}
	if has(model.ClassRemoteAccess) {
		ev, sig, _ := b.classEvidence(model.ClassRemoteAccess)
		b.add(FindingRemoteAccess, "", "Usługa zdalnego dostępu: "+firstNonEmpty(productVersion(s), s.Name),
			"Usługa zdalnego dostępu przyjmuje połączenia z sieci, z której wykonano skan. Czujka nie próbuje się logować.",
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
				fmt.Sprintf("Certyfikat TLS wygasa %s (zostało %d dni).", t.NotAfter.UTC().Format("2006-01-02"), days), certEv, "")
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
				"Odpowiedź HTTP zawiera nagłówki, które ujawniają oprogramowanie, jego wersję lub środowisko.", ev, "")
		}
		if ev := cookieEvidence(s.HTTP.Cookies, isTLS(s)); len(ev) > 0 {
			names := make([]string, len(ev))
			for i, e := range ev {
				names[i] = strings.TrimPrefix(e.Where, "cookie:")
			}
			b.add(FindingCookie, "", "Interesujące ciasteczka: "+strings.Join(names, ", "),
				"Usługa ustawia ciasteczka, które wskazują technologię albo są sesyjne i nie mają flag bezpieczeństwa. Wartości ciasteczek nie są pokazywane.", ev, "")
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
		switch {
		case m.Category == model.CatHeader:
			b.add(FindingHeader, m.Signature, "Interesujący nagłówek: "+name,
				"Sygnatura wykryła charakterystyczny nagłówek HTTP.", m.Evidence, m.Signature, m.Tags...)
		case m.Category == model.CatCookie:
			b.add(FindingCookie, m.Signature, "Interesujące ciasteczko: "+name,
				"Sygnatura wykryła charakterystyczne ciasteczko. Wartość ciasteczka nie jest pokazywana.", m.Evidence, m.Signature, m.Tags...)
		case len(m.Classes) > 0 && !custom:
			// Already reported through its class.
		case custom || m.Interest >= SignatureFindingMinInterest:
			title := "Dopasowanie sygnatury: " + strings.TrimSpace(name+" "+m.Version)
			b.add(FindingSignature, m.Signature, title,
				fmt.Sprintf("Sygnatura „%s” pasuje do tej usługi (pewność %.0f%%). Sygnatury wykrywają obecność cech, nie podatności.", m.Signature, m.Confidence*100),
				m.Evidence, m.Signature, m.Tags...)
		}
	}

	if b.fs.New {
		b.add(FindingNewExposure, "", "Nowa ekspozycja: "+firstNonEmpty(what(""), "port "+fmt.Sprint(s.Port)),
			"Usługa nie była widoczna w poprzednich skanach. Sprawdź, czy jej wystawienie jest zamierzone.",
			b.baseEvidence(), "")
	}
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
