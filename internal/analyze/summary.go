package analyze

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// StatusMissing is the host state "nie odpowiada (niepotwierdzone)" in the
// before and after values of host changes: the host answered before, is
// silent now and is not reported inactive yet. The store keeps such a host
// as unstable; the change values name what the operator sees, so host_missing,
// host_gone and host_back read as one chain:
// up → missing → down, or up → missing → up.
const StatusMissing = "missing"

// Keys of Change.Detail. Detail holds the values a summary needs that are
// not in Before and After, and the measures of the model that the summary
// leaves out (p_alive, the profile setting, the simhash distance).
const (
	DetailPattern      = "pattern"       // availability pattern text of the host
	DetailStabilityPct = "stability_pct" // share of scans with an answer, percent
	DetailRule         = "rule"          // DownAfterMisses of the profile (0: the model decides)
	DetailPAlive       = "p_alive"       // probability that a silent host still exists
	DetailMissesToDown = "misses_to_down"
	DetailOpenServices = "open_services" // open services of a silent host in the previous scan
	DetailServices     = "services"      // their labels, "80/tcp http nginx"
	DetailPorts        = "ports"         // open ports of a new host
	DetailProduct      = "product"       // product and version of the service
	DetailName         = "name"          // service name and product
	DetailExpired      = "expired"       // the new certificate is expired
	DetailSelfSigned   = "self_signed"   // the new certificate is self-signed
	DetailValues       = "values"        // header value changes, "Server: a → b"
	DetailFlags        = "flags"         // cookie flag changes, "sid: Secure → bez flag"
	DetailDistance     = "simhash_distance"
)

// ChangeSummary renders the one-line summary of a change from its
// structured fields: kind, address, field, before, after, expected and
// detail. It says what, where and since when; no measure of the model.
func ChangeSummary(c model.Change) string {
	at := addr(c.IP, c.Port)
	d := c.Detail
	switch c.Kind {
	case model.ChangeHostNew:
		return "Nowy host " + c.IP + portsNote(intsOf(d[DetailPorts]))
	case model.ChangeHostBack:
		if strOf(c.Before) == string(model.HostDown) {
			return "Host " + c.IP + " znów aktywny (był nieaktywny)"
		}
		if strOf(c.Before) == string(model.HostExpectedOffline) {
			return "Host " + c.IP + " znów aktywny" + paren(strOf(d[DetailPattern]))
		}
		return "Host " + c.IP + " znów aktywny"
	case model.ChangeHostGone:
		if strOf(c.After) == string(model.HostExpectedOffline) {
			return "Host " + c.IP + " poza godzinami" + paren(strOf(d[DetailPattern]))
		}
		if n := intOf(d[DetailRule]); n > 0 {
			return fmt.Sprintf("Host %s nieaktywny, nie odpowiada od %d %s", c.IP, n, plural(n, "skanu", "skanów", "skanów"))
		}
		return "Host " + c.IP + " nieaktywny, nie odpowiada w zwykłych godzinach"
	case model.ChangeHostUnstable:
		if !c.Expected {
			return "Host " + c.IP + " nie odpowiada w zwykłych godzinach (niepotwierdzone)"
		}
		if p := intOf(d[DetailStabilityPct]); p > 0 {
			return fmt.Sprintf("Host %s niestabilny (aktywny w ok. %d%% skanów)", c.IP, p)
		}
		return "Host " + c.IP + " niestabilny"
	case model.ChangeHostMissing:
		s := "Host " + c.IP + " nie odpowiada (niepotwierdzone)"
		if n := intOf(d[DetailOpenServices]); n > 0 {
			s += fmt.Sprintf(", miał %d %s", n, plural(n, "otwartą usługę", "otwarte usługi", "otwartych usług"))
		}
		return s
	case model.ChangeServiceUnreachable:
		return "Usługa " + at + paren(strOf(d[DetailName])) + " nie odpowiada (niepotwierdzone), host nie odpowiada"
	case model.ChangeServiceNew:
		return "Nowa usługa " + at + paren(strOf(d[DetailProduct]))
	case model.ChangeServiceGone:
		s := "Usługa " + at + " zniknęła" + paren(strOf(d[DetailProduct]))
		if strOf(c.After) == "host-down" {
			s += ", host nieaktywny"
		}
		return s
	case model.ChangeServiceReturned:
		s := "Usługa " + at + " wróciła"
		if away := intOf(mapOf(c.Before)["away_seconds"]); away > 0 {
			s += " po " + awayText(time.Duration(away)*time.Second)
		}
		return s + paren(strOf(d[DetailProduct]))
	case model.ChangeServiceChanged:
		b, a := strOf(c.Before), strOf(c.After)
		switch c.Field {
		case "product":
			return fmt.Sprintf("Zmiana produktu %s: %s → %s", at, b, a)
		case "name":
			return fmt.Sprintf("Zmiana nazwy usługi %s: %s → %s", at, b, a)
		}
		if p := strOf(d[DetailProduct]); p != "" {
			b, a = p+" "+b, p+" "+a
		}
		return fmt.Sprintf("Zmiana wersji %s: %s → %s", at, b, a)
	case model.ChangeTechNew:
		return fmt.Sprintf("Nowa technologia %s na %s", strOf(c.After), at)
	case model.ChangeTechGone:
		return fmt.Sprintf("Technologia %s zniknęła z %s", strOf(c.Before), at)
	case model.ChangeTechVersion:
		return fmt.Sprintf("Zmiana wersji %s, %s: %s → %s", strings.TrimPrefix(c.Field, "technologies."), at, strOf(c.Before), strOf(c.After))
	case model.ChangeTitle:
		return fmt.Sprintf("Zmiana tytułu strony %s: %s → %s", at, quote(strOf(c.Before)), quote(strOf(c.After)))
	case model.ChangeHTTPStatus:
		return fmt.Sprintf("Zmiana kodu HTTP %s: %s → %s", at, strOf(c.Before), strOf(c.After))
	case model.ChangeRedirect:
		return fmt.Sprintf("Zmiana przekierowania %s: %s → %s", at, orNone(strOf(c.Before)), orNone(strOf(c.After)))
	case model.ChangeCert:
		cert := mapOf(c.After)
		s := fmt.Sprintf("Nowy certyfikat TLS %s: %s, ważny do %s", at, orDash(strOf(cert["subject_cn"])), dateOf(strOf(cert["not_after"])))
		switch {
		case boolOf(d[DetailExpired]):
			s += ", przeterminowany"
		case boolOf(d[DetailSelfSigned]):
			s += ", samopodpisany"
		}
		return s
	case model.ChangeHeaders:
		return "Zmiana nagłówków " + at + ": " + setNote(strsOf(c.Before), strsOf(c.After), strsOf(d[DetailValues]), nil)
	case model.ChangeCookies:
		return "Zmiana ciasteczek " + at + ": " + setNote(strsOf(c.Before), strsOf(c.After), strsOf(d[DetailFlags]), nil)
	case model.ChangeContent:
		if c.Field == "http.body_length" {
			return fmt.Sprintf("Zmiana treści strony %s: %d → %d B", at, intOf(c.Before), intOf(c.After))
		}
		return "Zmiana treści strony " + at
	case model.ChangeClass:
		return "Zmiana klas usługi " + at + ": " + setNote(strsOf(c.Before), strsOf(c.After), nil, classNames)
	case model.ChangeResponseSlower:
		before, after := mapOf(c.Before), mapOf(c.After)
		usual := usualText(intOf(before["baseline_ms"]))
		if strOf(after["error"]) == "no_answer" || after["ms"] == nil {
			return fmt.Sprintf("Usługa %s nie odpowiada na HTTP, port otwarty (%s)", at, usual)
		}
		return fmt.Sprintf("Usługa %s odpowiada wolniej: %d ms (%s)", at, intOf(after["ms"]), usual)
	case model.ChangeResponseRecovered:
		return fmt.Sprintf("Usługa %s znów szybka: %d ms (%s)", at, intOf(mapOf(c.After)["ms"]), usualText(intOf(mapOf(c.Before)["baseline_ms"])))
	}
	return c.Summary
}

// setNote is "dodano a, b; usunięto c; extra" for two sets of names.
func setNote(before, after, extra []string, names func([]string) []string) string {
	added, removed := setDiff(before, after)
	if names != nil {
		added, removed = names(added), names(removed)
	}
	var parts []string
	if len(added) > 0 {
		parts = append(parts, "dodano "+strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		parts = append(parts, "usunięto "+strings.Join(removed, ", "))
	}
	return strings.Join(append(parts, extra...), "; ")
}

// portsNote is " (otwarte porty: 22, 80, …)", at most 8 ports.
func portsNote(ports []int) string {
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
	return " (otwarte porty: " + strings.Join(strs, ", ") + ")"
}

func paren(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

func dateOf(rfc string) string {
	if t, err := time.Parse(time.RFC3339, rfc); err == nil {
		return t.UTC().Format("2006-01-02")
	}
	return orDash(rfc)
}

// The readers below accept the values of a change as the analysis builds
// them (string, int, []string, map) and as the store returns them (decoded
// JSON: float64, []any).

func strOf(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	}
	return fmt.Sprint(v)
}

func intOf(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

func boolOf(v any) bool { b, _ := v.(bool); return b }

func strsOf(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, strOf(e))
		}
		return out
	}
	return nil
}

func intsOf(v any) []int {
	switch x := v.(type) {
	case []int:
		return append([]int(nil), x...)
	case []any:
		out := make([]int, 0, len(x))
		for _, e := range x {
			out = append(out, intOf(e))
		}
		return out
	}
	return nil
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
