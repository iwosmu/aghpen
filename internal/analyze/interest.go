package analyze

import (
	"fmt"
	"math"
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

// MaxSignaturePoints caps the points one signature match can add, and
// MaxSignatureTotal the points of all signature matches of one service.
const (
	MaxSignaturePoints = 40
	MaxSignatureTotal  = 40
)

// WeakSignalsCap caps the points of the weak signals of one service taken
// together: revealing headers, missing security headers, cookie flags,
// default page, certificate expiring or not matching the name, SSH, and
// signature matches of the header and cookie categories. Four weak
// signals do not make a service interesting; they add at most this much.
const WeakSignalsCap = 20

// weakReasons are the reason codes of the weak signals.
var weakReasons = map[string]bool{
	ReasonMissingHeaders: true, ReasonSensitiveHeader: true, ReasonCookie: true, ReasonDefaultPage: true,
	ReasonCertExpiring: true, ReasonHostMismatch: true, ReasonRemoteAccess: true,
}

// classReason maps a class to the reason codes that already count it.
var classReason = map[string][]string{
	model.ClassAdminPanel: {ReasonAdminPanel}, model.ClassLogin: {ReasonLogin, ReasonLoginPlainHTTP},
	model.ClassStaging: {ReasonStaging}, model.ClassIoT: {ReasonIoT}, model.ClassDevTool: {ReasonDevTool},
	model.ClassDatabase: {ReasonDatabase}, model.ClassDirListing: {ReasonDirListing}, model.ClassDefaultPage: {ReasonDefaultPage},
}

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
// of a service is the sum of the rows that apply, compressed above
// InterestKnee (CompressInterest). Signature
// matches add round(match.Interest * match.Confidence), capped at
// MaxSignaturePoints each. Scope criticality 4 adds 5 points, 5 adds 10.
var InterestWeights = []Weight{
	{ReasonAdminPanel, 30, "Panel administracyjny dostępny z sieci"},
	{ReasonLoginPlainHTTP, 25, "Logowanie bez szyfrowania (HTTP)"},
	{ReasonDatabase, 25, "Baza danych dostępna z sieci"},
	{ReasonDebugPage, 25, "Strona diagnostyczna lub tryb debug"},
	{ReasonRemotePlain, 25, "Zdalny dostęp bez szyfrowania"},
	{ReasonStaging, 20, "Środowisko testowe"},
	{ReasonIoT, 20, "Urządzenie IoT"},
	{ReasonDevTool, 20, "Narzędzie deweloperskie"},
	{ReasonRemoteDesktop, 20, "Zdalny pulpit"},
	{ReasonDirListing, 15, "Listing katalogu"},
	{ReasonExpiredCert, 15, "Przeterminowany certyfikat TLS"},
	{ReasonNewExposure, 15, "Nowa ekspozycja"},
	{ReasonLogin, 10, "Strona logowania"},
	{ReasonSelfSigned, 10, "Samopodpisany certyfikat TLS"},
	{ReasonRareTech, 10, "Rzadka technologia w tej sieci"},
	{ReasonOutdated, 10, "Przestarzała wersja oprogramowania"},
	{ReasonRemoteAccess, 5, "Usługa zdalnego dostępu"},
	{ReasonDefaultPage, 5, "Strona domyślna serwera"},
	{ReasonCertExpiring, 5, "Certyfikat TLS wkrótce wygaśnie"},
	{ReasonHostMismatch, 5, "Certyfikat TLS nie pasuje do nazwy hosta"},
	{ReasonMissingHeaders, 5, "Strona logowania bez nagłówków bezpieczeństwa"},
	{ReasonSensitiveHeader, 5, "Nagłówek ujawnia szczegóły oprogramowania"},
	{ReasonCookie, 5, "Ciasteczko sesyjne bez flag bezpieczeństwa"},
	{ReasonCriticality, 5, "Krytyczny zakres"},
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
			add(ReasonCertExpiring, fmt.Sprintf("za %d %s", days, plural(days, "dzień", "dni", "dni")))
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
	counted := map[string]bool{}
	for _, r := range why {
		counted[r.Code] = true
	}
	for _, m := range s.Matches {
		if m.Interest <= 0 {
			continue
		}
		weak := m.Category == model.CatHeader || m.Category == model.CatCookie
		if weak && repeatsClass(m, counted) {
			continue // "login form over plain HTTP" is the login-plain-http reason again
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
			code := ReasonSignature
			if weak {
				code = reasonWeakSignature
			}
			why = append(why, model.InterestReason{Code: code, Points: pts, Text: "Sygnatura: " + firstNonEmpty(m.Name, m.Signature)})
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
	// Caps: the weak signals together, the signature matches together.
	weakLeft, sigLeft := WeakSignalsCap, MaxSignatureTotal
	for i := range why {
		r := &why[i]
		switch {
		case weakReasons[r.Code] || r.Code == reasonWeakSignature:
			r.Points = min(r.Points, weakLeft)
			weakLeft -= r.Points
			if r.Code == reasonWeakSignature {
				r.Code = ReasonSignature
			}
		case r.Code == ReasonSignature:
			r.Points = min(r.Points, sigLeft)
			sigLeft -= r.Points
		}
	}
	kept := why[:0]
	score := 0
	for _, r := range why {
		if r.Points > 0 {
			kept = append(kept, r)
			score += r.Points
		}
	}
	return CompressInterest(score), kept
}

// InterestKnee and InterestSpan shape the top of the score. Up to the knee
// the score is the plain sum of the reasons. Above it the sum is compressed
// towards 100: score = knee + (100-knee) * (1 - exp(-(sum-knee)/span)).
// A plain cut at 100 made the top of the list equal (measured on the lab:
// the five most interesting services all had 100, a blog login page next
// to phpMyAdmin); with the curve a sum of 100 gives 84, 140 gives 92 and 200
// gives 97, so a larger sum still ranks higher.
const (
	InterestKnee = 70
	InterestSpan = 50
)

// CompressInterest maps the sum of the reason points to the 0..99 score.
func CompressInterest(sum int) int {
	if sum <= InterestKnee {
		return max(sum, 0)
	}
	v := InterestKnee + (100-InterestKnee)*(1-math.Exp(-float64(sum-InterestKnee)/InterestSpan))
	return min(99, int(v+0.5))
}

// reasonWeakSignature marks a header or cookie signature match while the
// caps are applied; it is reported as ReasonSignature.
const reasonWeakSignature = "signature-weak"

// repeatsClass reports whether every class of a signature match is already
// counted by a class reason.
func repeatsClass(m model.SigMatch, counted map[string]bool) bool {
	if len(m.Classes) == 0 {
		return false
	}
	for _, c := range m.Classes {
		hit := false
		for _, code := range classReason[c] {
			if counted[code] {
				hit = true
			}
		}
		if !hit {
			return false
		}
	}
	return true
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
