package analyze

import (
	"regexp"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// reasonEN is the English label of each interest reason code, the
// counterpart of Weight.Text.
var reasonEN = map[string]string{
	ReasonAdminPanel:      "Admin panel reachable from the network",
	ReasonLoginPlainHTTP:  "Login over plain HTTP",
	ReasonDatabase:        "Database open to the network",
	ReasonDebugPage:       "Debug page or debug mode",
	ReasonRemotePlain:     "Remote access without encryption",
	ReasonStaging:         "Test environment",
	ReasonIoT:             "IoT device",
	ReasonDevTool:         "Developer tool",
	ReasonRemoteDesktop:   "Remote desktop",
	ReasonDirListing:      "Directory listing",
	ReasonExpiredCert:     "Expired TLS certificate",
	ReasonNewExposure:     "New exposure",
	ReasonLogin:           "Login page",
	ReasonSelfSigned:      "Self-signed TLS certificate",
	ReasonRareTech:        "Rare technology in this network",
	ReasonOutdated:        "Outdated software version",
	ReasonRemoteAccess:    "Remote access service",
	ReasonDefaultPage:     "Default server page",
	ReasonCertExpiring:    "TLS certificate expires soon",
	ReasonHostMismatch:    "TLS certificate does not match the host name",
	ReasonMissingHeaders:  "Login page without security headers",
	ReasonSensitiveHeader: "Header reveals software details",
	ReasonCookie:          "Session cookie without security flags",
	ReasonCriticality:     "Critical scope",
	ReasonSignature:       "Signature",
}

// ReasonLabel is the label of a reason code in lang, without its detail.
func ReasonLabel(code, lang string) string {
	if lang == "en" {
		if s, ok := reasonEN[code]; ok {
			return s
		}
	}
	return weightByCode[code].Text
}

var (
	reCriticality = regexp.MustCompile(`(\d)/5`)
	reDaysPL      = regexp.MustCompile(`^za (\d+) (?:dzień|dni)$`)
	reOfServices  = regexp.MustCompile(`^(\d+) z (\d+) usług$`)
)

// RenderReason renders the text of an interest reason in lang from its code
// and the detail of its stored text (a product, a header name, a date,
// counts). Polish returns the stored text. A code this code does not know
// keeps the stored text.
func RenderReason(r model.InterestReason, lang string) string {
	if lang != "en" {
		return r.Text
	}
	label, ok := reasonEN[r.Code]
	if !ok {
		return r.Text
	}
	if r.Code == ReasonCriticality {
		if m := reCriticality.FindStringSubmatch(r.Text); m != nil {
			return label + " (" + m[1] + "/5)"
		}
		return label
	}
	_, detail, has := strings.Cut(r.Text, ": ")
	if !has || detail == "" {
		return label
	}
	return label + ": " + reasonDetailEN(r.Code, detail)
}

func reasonDetailEN(code, d string) string {
	switch code {
	case ReasonSignature, ReasonOutdated:
		return SignatureNameIn(d, "en")
	case ReasonMissingHeaders:
		if rest, ok := strings.CutPrefix(d, "brak "); ok {
			return "missing " + rest
		}
	case ReasonExpiredCert:
		if rest, ok := strings.CutPrefix(d, "ważny do "); ok {
			return "valid until " + rest
		}
	case ReasonCertExpiring:
		if m := reDaysPL.FindStringSubmatch(d); m != nil {
			return "in " + m[1] + " " + pluralEN(intOf(m[1]), "day", "days")
		}
	case ReasonRareTech:
		if m := reOfServices.FindStringSubmatch(d); m != nil {
			return m[1] + " of " + m[2] + " " + pluralEN(intOf(m[2]), "service", "services")
		}
	}
	return d
}

// LocalizeReasons renders the texts of reasons in lang, in place.
func LocalizeReasons(rs []model.InterestReason, lang string) {
	if lang != "en" {
		return
	}
	for i := range rs {
		rs[i].Text = RenderReason(rs[i], lang)
	}
}

// LocalizeServices renders the interest reasons of services in lang, in place.
func LocalizeServices(ss []model.Service, lang string) {
	for i := range ss {
		LocalizeReasons(ss[i].InterestWhy, lang)
	}
}
