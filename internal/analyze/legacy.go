package analyze

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Changes stored before Change.Detail existed (migration 0007) carry the
// values their summary needs only inside the stored Polish text. legacyDetail
// reads them back, so an upgraded installation shows its whole history in
// the current wording and in both languages. The patterns match the texts
// the analysis wrote before and after the change; on a text that has no such
// value they find nothing and the renderer leaves that part out.
var (
	reLegacyPorts    = regexp.MustCompile(`\(otwarte porty: ([0-9, …]+)\)`)
	reLegacyPattern  = regexp.MustCompile(`zgodnie z profilem dostępności \((.+)\)$`)
	reLegacyRule     = regexp.MustCompile(`brak odpowiedzi w (\d+) przebieg`)
	reLegacyPct      = regexp.MustCompile(`w ok\. (\d+)% skanów`)
	reLegacyServices = regexp.MustCompile(`miał (\d+) otwart`)
	reLegacyName     = regexp.MustCompile(`^Usługa \S+ \(([^()]+)\) nie odpowiada`)
	reLegacyNew      = regexp.MustCompile(`^Nowa usługa \S+ \((.+)\)$`)
	reLegacyGone     = regexp.MustCompile(`zniknęła \((.+?)\)(?::|,|$)`)
	reLegacyParen    = regexp.MustCompile(`\(([^()]+)\)$`)
	reLegacyVersion  = regexp.MustCompile(`^Zmiana wersji \S+: (.+) → (.+)$`)
)

func legacyDetail(c model.Change) map[string]any {
	s := strings.TrimSpace(c.Summary)
	if s == "" {
		return nil
	}
	d := map[string]any{}
	sub := func(re *regexp.Regexp) string {
		if m := re.FindStringSubmatch(s); m != nil {
			return strings.TrimSpace(m[1])
		}
		return ""
	}
	num := func(re *regexp.Regexp) int {
		n, _ := strconv.Atoi(sub(re))
		return n
	}
	switch c.Kind {
	case model.ChangeHostNew:
		var ports []int
		for _, p := range strings.Split(sub(reLegacyPorts), ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				ports = append(ports, n)
			}
		}
		if len(ports) > 0 {
			d[DetailPorts] = ports
		}
	case model.ChangeHostBack, model.ChangeHostGone:
		if p := sub(reLegacyPattern); p != "" {
			d[DetailPattern] = p
		}
		if n := num(reLegacyRule); n > 0 {
			d[DetailRule] = n
		}
	case model.ChangeHostUnstable:
		if n := num(reLegacyPct); n > 0 {
			d[DetailStabilityPct] = n
		}
	case model.ChangeHostMissing:
		if n := num(reLegacyServices); n > 0 {
			d[DetailOpenServices] = n
		}
	case model.ChangeServiceUnreachable:
		if n := sub(reLegacyName); n != "" {
			d[DetailName] = n
		}
	case model.ChangeServiceNew:
		if p := sub(reLegacyNew); p != "" {
			d[DetailProduct] = p
		}
	case model.ChangeServiceGone:
		if p := sub(reLegacyGone); p != "" {
			d[DetailProduct] = p
		}
	case model.ChangeServiceReturned:
		if p := sub(reLegacyParen); p != "" && !strings.HasPrefix(p, "nie było") {
			d[DetailProduct] = p
		}
	case model.ChangeServiceChanged:
		if m := reLegacyVersion.FindStringSubmatch(s); m != nil && c.Field == "version" {
			if p, ok := strings.CutSuffix(m[1], " "+strOf(c.Before)); ok && p != "" {
				d[DetailProduct] = p
			}
		}
	case model.ChangeCert:
		if t, err := time.Parse(time.RFC3339, strOf(mapOf(c.After)["not_after"])); err == nil && !c.At.IsZero() && t.Before(c.At) {
			d[DetailExpired] = true
		} else if strings.Contains(s, "samopodpisany") {
			d[DetailSelfSigned] = true
		}
	case model.ChangeHeaders, model.ChangeCookies:
		// "Zmiana nagłówków A: dodano X; usunięto Y; Server: nginx → Apache"
		var notes []string
		if _, rest, ok := strings.Cut(s, ": "); ok {
			for _, p := range strings.Split(rest, "; ") {
				if strings.Contains(p, " → ") {
					notes = append(notes, p)
				}
			}
		}
		if len(notes) > 0 {
			key := DetailValues
			if c.Kind == model.ChangeCookies {
				key = DetailFlags
			}
			d[key] = notes
		}
	}
	return d
}

var dayEN = map[string]string{"nd": "Sun", "pn": "Mon", "wt": "Tue", "śr": "Wed", "cz": "Thu", "pt": "Fri", "sb": "Sat"}

// PatternText is an availability pattern text (Pattern) in lang. It also
// brings a text stored by an older version to the current wording:
// "odpowiada stale" is "aktywny stale", "w godz." and the lab clock go.
func PatternText(pl, lang string) string {
	s := strings.TrimSpace(pl)
	if i := strings.Index(s, " (zegar laboratoryjny"); i >= 0 {
		s = s[:i]
	}
	s = strings.Replace(s, "odpowiada stale", "aktywny stale", 1)
	s = strings.Replace(s, "odpowiada w ok.", "aktywny w ok.", 1)
	s = strings.Replace(s, ", bez wzorca dobowego", ", bez wzorca", 1)
	s = strings.Replace(s, "zwykle aktywny w godz. ", "zwykle aktywny ", 1)
	if lang != "en" || s == "" {
		return s
	}
	r := strings.NewReplacer("aktywny stale", "always up", "aktywny w ok.", "up in about", "zwykle aktywny", "usually up",
		"% skanów", "% of scans", ", bez wzorca", ", no pattern", "codziennie", "daily")
	s = r.Replace(s)
	words := strings.Fields(s)
	for i, w := range words {
		// day lists: "pn–pt", "pn,", "śr"
		trail := ""
		if strings.HasSuffix(w, ",") {
			w, trail = strings.TrimSuffix(w, ","), ","
		}
		parts := strings.Split(w, "–")
		ok := true
		for j, p := range parts {
			if e, found := dayEN[p]; found {
				parts[j] = e
			} else {
				ok = false
			}
		}
		if ok {
			words[i] = strings.Join(parts, "–") + trail
		}
	}
	return strings.Join(words, " ")
}
