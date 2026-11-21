package analyze

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// CertExpiringDays: a certificate with fewer days left is "expiring soon".
const CertExpiringDays = 30

// RareGroupSize and RareMinServices define a rare technology: a group of at
// most RareGroupSize services in a network of at least RareMinServices.
const (
	RareGroupSize   = 2
	RareMinServices = 20
)

// MaxSignaturePoints caps the points one signature match can add.
const MaxSignaturePoints = 40

// Interest reason codes.
const (
	ReasonAdminPanel      = "admin-panel"
	ReasonLoginPlainHTTP  = "login-plain-http"
	ReasonLogin           = "login"
	ReasonStaging         = "staging"
	ReasonDebugPage       = "debug-page"
	ReasonIoT             = "iot"
	ReasonDevTool         = "dev-tool"
	ReasonDatabase        = "database"
	ReasonRemotePlain     = "remote-access-plaintext"
	ReasonRemoteDesktop   = "remote-desktop"
	ReasonRemoteAccess    = "remote-access"
	ReasonDirListing      = "directory-listing"
	ReasonDefaultPage     = "default-page"
	ReasonExpiredCert     = "expired-cert"
	ReasonCertExpiring    = "cert-expiring"
	ReasonSelfSigned      = "self-signed-cert"
	ReasonHostMismatch    = "hostname-mismatch"
	ReasonNewExposure     = "new-exposure"
	ReasonRareTech        = "rare-tech"
	ReasonOutdated        = "outdated"
	ReasonMissingHeaders  = "missing-security-headers"
	ReasonSensitiveHeader = "sensitive-header"
	ReasonCookie          = "interesting-cookie"
	ReasonSignature       = "signature"
	ReasonCriticality     = "scope-criticality"
)

// Weight is one row of the interest table.
type Weight struct {
	Code   string
	Points int
	Text   string // Polish text shown to the analyst
}

// InterestWeights is the one table of the interest score (§4.5). The score
// of a service is the sum of the rows that apply, capped at 100. Signature
// matches add round(match.Interest * match.Confidence), capped at
// MaxSignaturePoints each. Scope criticality 4 adds 5 points, 5 adds 10.
var InterestWeights = []Weight{
	{ReasonAdminPanel, 30, "Panel administracyjny dostępny z sieci"},
	{ReasonLoginPlainHTTP, 25, "Strona logowania bez szyfrowania (HTTP)"},
	{ReasonDatabase, 25, "Baza danych dostępna z sieci"},
	{ReasonDebugPage, 25, "Strona diagnostyczna lub tryb debug"},
	{ReasonRemotePlain, 25, "Zdalny dostęp bez szyfrowania (telnet, rlogin)"},
	{ReasonStaging, 20, "Środowisko testowe lub staging"},
	{ReasonIoT, 20, "Urządzenie IoT"},
	{ReasonDevTool, 20, "Narzędzie deweloperskie (CI, repozytorium, monitoring)"},
	{ReasonRemoteDesktop, 20, "Zdalny pulpit (RDP, VNC)"},
	{ReasonDirListing, 15, "Listing katalogu"},
	{ReasonExpiredCert, 15, "Przeterminowany certyfikat TLS"},
	{ReasonNewExposure, 15, "Nowa ekspozycja od ostatniego skanu"},
	{ReasonLogin, 10, "Strona logowania"},
	{ReasonSelfSigned, 10, "Samopodpisany certyfikat TLS"},
	{ReasonRareTech, 10, "Rzadka technologia w tej sieci"},
	{ReasonOutdated, 10, "Przestarzała wersja oprogramowania"},
	{ReasonRemoteAccess, 5, "Usługa zdalnego dostępu (SSH)"},
	{ReasonDefaultPage, 5, "Strona domyślna serwera"},
	{ReasonCertExpiring, 5, "Certyfikat TLS wkrótce wygaśnie"},
	{ReasonHostMismatch, 5, "Certyfikat TLS nie pasuje do nazwy hosta"},
	{ReasonMissingHeaders, 5, "Strona logowania bez nagłówków bezpieczeństwa"},
	{ReasonSensitiveHeader, 5, "Nagłówek ujawnia szczegóły oprogramowania"},
	{ReasonCookie, 5, "Ciasteczko sesyjne bez flag bezpieczeństwa"},
	{ReasonCriticality, 5, "Zakres o podwyższonej krytyczności"},
}

var weightByCode = func() map[string]Weight {
	m := make(map[string]Weight, len(InterestWeights))
	for _, w := range InterestWeights {
		m[w.Code] = w
	}
	return m
}()

// InterestInput is what the score needs about one service.
type InterestInput struct {
	Service   model.ServiceResult
	Hostnames []string
	// NewExposure: the service was first seen in the latest run (and that
	// run was not the first one).
	NewExposure bool
	// GroupSize and TotalServices feed the "rare technology" rule. Zero
	// means unknown; the rule is then skipped.
	GroupSize     int
	TotalServices int
	// ScopeCriticality is 1..5; 0 means unknown.
	ScopeCriticality int
	// Now is used to compute the days left of a certificate. Zero means
	// "trust TLSInfo.Expired and TLSInfo.DaysLeft".
	Now time.Time
}

// Interest computes the interest score of one service (0..100) and the
// reasons, highest points first.
func Interest(in InterestInput) (int, []model.InterestReason) {
	s := &in.Service
	var why []model.InterestReason
	add := func(code, detail string) {
		w := weightByCode[code]
		text := w.Text
		if detail != "" {
			text += ": " + detail
		}
		why = append(why, model.InterestReason{Code: code, Points: w.Points, Text: text})
	}
	classes := EffectiveClasses(s, in.Hostnames)
	has := func(c string) bool { return hasClass(classes, c) }

	if has(model.ClassAdminPanel) {
		add(ReasonAdminPanel, "")
	}
	if has(model.ClassLogin) {
		if isPlainHTTP(s) {
			add(ReasonLoginPlainHTTP, "")
		} else {
			add(ReasonLogin, "")
		}
		if s.HTTP != nil {
			if missing := missingSecurityHeaders(s.HTTP.Headers, isTLS(s)); len(missing) > 0 {
				add(ReasonMissingHeaders, "brak "+strings.Join(missing, ", "))
			}
		}
	}
	if has(model.ClassStaging) {
		add(ReasonStaging, "")
	}
	if ok, _ := isDebugPage(s); ok {
		add(ReasonDebugPage, "")
	}
	if has(model.ClassIoT) {
		add(ReasonIoT, "")
	}
	if has(model.ClassDevTool) {
		add(ReasonDevTool, "")
	}
	if has(model.ClassDatabase) {
		add(ReasonDatabase, productVersion(s))
	}
	if has(model.ClassRemoteAccess) {
		switch strings.ToLower(s.Name) {
		case "telnet", "rlogin", "login", "shell", "exec":
			add(ReasonRemotePlain, s.Name)
		case "ms-wbt-server", "rdp", "vnc", "vnc-http", "x11", "teamviewer":
			add(ReasonRemoteDesktop, s.Name)
		default:
			add(ReasonRemoteAccess, "")
		}
	}
	if has(model.ClassDirListing) {
		add(ReasonDirListing, "")
	}
	if has(model.ClassDefaultPage) {
		add(ReasonDefaultPage, "")
	}
	if t := s.TLS; t != nil {
		expired, days := certState(t, in.Now)
		switch {
		case expired:
			add(ReasonExpiredCert, "ważny do "+t.NotAfter.UTC().Format("2006-01-02"))
		case !t.NotAfter.IsZero() && days <= CertExpiringDays:
			add(ReasonCertExpiring, fmt.Sprintf("zostało %d dni", days))
		}
		if t.SelfSigned {
			add(ReasonSelfSigned, "")
		}
		if t.HostMismatch {
			add(ReasonHostMismatch, "")
		}
	}
	if in.NewExposure {
		add(ReasonNewExposure, "")
	}
	if in.GroupSize > 0 && in.GroupSize <= RareGroupSize && in.TotalServices >= RareMinServices {
		add(ReasonRareTech, fmt.Sprintf("%d z %d usług", in.GroupSize, in.TotalServices))
	}
	if outdated := outdatedNote(s); outdated != "" {
		add(ReasonOutdated, outdated)
	}
	if s.HTTP != nil {
		if hs := interestingHeaders(s.HTTP.Headers); len(hs) > 0 {
			names := make([]string, len(hs))
			for i, e := range hs {
				names[i] = strings.TrimPrefix(e.Where, "header:")
			}
			add(ReasonSensitiveHeader, strings.Join(names, ", "))
		}
		if cs := weakSessionCookies(s.HTTP.Cookies, isTLS(s)); len(cs) > 0 {
			add(ReasonCookie, strings.Join(cs, ", "))
		}
	}
	for _, m := range s.Matches {
		if m.Interest <= 0 {
			continue
		}
		conf := m.Confidence
		if conf <= 0 || conf > 1 {
			conf = 1
		}
		pts := int(float64(m.Interest)*conf + 0.5)
		if pts > MaxSignaturePoints {
			pts = MaxSignaturePoints
		}
		if pts > 0 {
			why = append(why, model.InterestReason{Code: ReasonSignature, Points: pts, Text: "Sygnatura: " + firstNonEmpty(m.Name, m.Signature)})
		}
	}
	switch {
	case in.ScopeCriticality >= 5:
		w := weightByCode[ReasonCriticality]
		why = append(why, model.InterestReason{Code: ReasonCriticality, Points: 2 * w.Points, Text: w.Text + " (5/5)"})
	case in.ScopeCriticality == 4:
		add(ReasonCriticality, "4/5")
	}

	sort.SliceStable(why, func(i, j int) bool { return why[i].Points > why[j].Points })
	score := 0
	for _, r := range why {
		score += r.Points
	}
	if score > 100 {
		score = 100
	}
	return score, why
}

// HostInterest is the interest of a host: the highest score of its services,
// plus 5 points when the host is new, capped at 100.
func HostInterest(serviceScores []int, newHost bool) int {
	best := 0
	for _, s := range serviceScores {
		if s > best {
			best = s
		}
	}
	if newHost {
		best += 5
	}
	if best > 100 {
		best = 100
	}
	return best
}

// certState returns expired and the days left. With a zero now it trusts the
// collector's fields.
func certState(t *model.TLSInfo, now time.Time) (expired bool, daysLeft int) {
	if now.IsZero() || t.NotAfter.IsZero() {
		return t.Expired, t.DaysLeft
	}
	left := t.NotAfter.Sub(now)
	return left < 0, int(left.Hours() / 24)
}

func missingSecurityHeaders(h map[string][]string, tls bool) []string {
	var missing []string
	if headerValue(h, "Content-Security-Policy") == "" && headerValue(h, "X-Frame-Options") == "" {
		missing = append(missing, "Content-Security-Policy / X-Frame-Options")
	}
	if tls && headerValue(h, "Strict-Transport-Security") == "" {
		missing = append(missing, "Strict-Transport-Security")
	}
	return missing
}

// revealingHeaders always count as interesting when present.
var revealingHeaders = []string{
	"X-Powered-By", "X-Aspnet-Version", "X-Aspnetmvc-Version", "X-Debug-Token", "X-Debug-Token-Link", "X-Generator",
	"X-Backend-Server", "X-Jenkins", "X-Environment", "X-Env", "X-Php-Version", "X-Drupal-Cache", "X-Redirect-By",
	"X-Runtime", "X-Version", "X-App-Version",
}

var reHasVersion = regexp.MustCompile(`\d+\.\d+`)

// interestingHeaders returns evidence for headers that reveal software
// details. Values are clipped; they are not secrets.
func interestingHeaders(h map[string][]string) []model.Evidence {
	var ev []model.Evidence
	for _, name := range revealingHeaders {
		if v := headerValue(h, name); v != "" {
			ev = append(ev, model.Evidence{Matcher: "header", Where: "header:" + name, Snippet: clip(v, 120)})
		}
	}
	if v := headerValue(h, "Server"); v != "" && reHasVersion.MatchString(v) {
		ev = append(ev, model.Evidence{Matcher: "header", Where: "header:Server", Snippet: clip(v, 120)})
	}
	if v := headerValue(h, "Via"); v != "" && reHasVersion.MatchString(v) {
		ev = append(ev, model.Evidence{Matcher: "header", Where: "header:Via", Snippet: clip(v, 120)})
	}
	return ev
}

var reSessionCookie = regexp.MustCompile(`(?i)(sess|sid$|token|auth|jwt|login|remember)`)

// weakSessionCookies returns the names of session-like cookies without
// HttpOnly, or without Secure on a TLS service.
func weakSessionCookies(cs []model.Cookie, tls bool) []string {
	var out []string
	for _, c := range cs {
		if !reSessionCookie.MatchString(c.Name) {
			continue
		}
		if !c.HTTPOnly || (tls && !c.Secure) {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out
}

// outdatedNote returns the name of a signature match tagged as outdated or
// end-of-life. The analysis library does not judge versions by itself.
func outdatedNote(s *model.ServiceResult) string {
	for _, m := range s.Matches {
		for _, t := range m.Tags {
			switch strings.ToLower(t) {
			case "outdated", "eol", "end-of-life", "old-version":
				return strings.TrimSpace(firstNonEmpty(m.Name, m.Signature) + " " + m.Version)
			}
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
