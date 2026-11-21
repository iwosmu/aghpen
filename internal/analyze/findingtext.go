package analyze

import (
	"regexp"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// PolicyFindingType is the type of the findings stored by exposure rules
// (internal/rules.FindingType); their signature is "policy:" + rule id.
const PolicyFindingType = "policy-violation"

// RenderFinding returns f with its title, description and evidence in lang.
// Polish returns f as stored. English is rendered from the stable fields
// (type, rule id, signature) and the data parts of the stored Polish text
// (product, page title, certificate name, dates, header names), so findings
// stored by any earlier build come out in both languages. A manual or
// imported finding, and a text this code does not know, stay as stored.
func RenderFinding(f model.Finding, lang string) model.Finding {
	if lang != "en" || f.Manual {
		return f
	}
	if id, ok := strings.CutPrefix(f.Signature, "policy:"); ok && f.Type == PolicyFindingType {
		f.Title = ruleTitleEN(id, f.Title)
		f.Description = ruleDescEN(id, f.Description)
	} else {
		f.Title = findingTitleEN(f.Type, f.Title)
		f.Description = findingDescEN(f.Description)
	}
	f.Evidence = EvidenceIn(f.Evidence, lang)
	return f
}

// LocalizeFindings renders findings in lang, in place.
func LocalizeFindings(fs []model.Finding, lang string) {
	if lang != "en" {
		return
	}
	for i := range fs {
		fs[i] = RenderFinding(fs[i], lang)
	}
}

// FindingTitleIn renders a stored finding title in lang, for answers that
// carry the title without the whole finding (the time machine).
func FindingTitleIn(typ, signature, title, lang string) string {
	if lang != "en" {
		return title
	}
	if id, ok := strings.CutPrefix(signature, "policy:"); ok && typ == PolicyFindingType {
		return ruleTitleEN(id, title)
	}
	return findingTitleEN(typ, title)
}

// titlePrefixEN maps the Polish lead of a derived finding title (before
// ": ") to English.
var titlePrefixEN = map[string]string{
	"Panel administracyjny":                       "Admin panel",
	"Logowanie bez szyfrowania (HTTP)":            "Login over plain HTTP",
	"Środowisko testowe":                          "Test environment",
	"Strona diagnostyczna lub tryb debug":         "Debug page or debug mode",
	"Urządzenie IoT":                              "IoT device",
	"Narzędzie deweloperskie":                     "Developer tool",
	"Baza danych dostępna z sieci":                "Database open to the network",
	"Usługa zdalnego dostępu":                     "Remote access service",
	"Listing katalogu":                            "Directory listing",
	"Strona domyślna serwera":                     "Default server page",
	"Przeterminowany certyfikat TLS":              "Expired TLS certificate",
	"Certyfikat TLS wkrótce wygaśnie":             "TLS certificate expires soon",
	"Samopodpisany certyfikat TLS":                "Self-signed TLS certificate",
	"Certyfikat TLS nie pasuje do nazwy hosta":    "TLS certificate does not match the host name",
	"Nagłówki HTTP":                               "HTTP headers",
	"Nagłówki ujawniają szczegóły oprogramowania": "Headers reveal software details",
	"Nagłówek":                                    "Header",
	"Ciasteczka":                                  "Cookies",
	"Ciasteczko":                                  "Cookie",
	"Dopasowanie sygnatury":                       "Signature match",
	"Nowa ekspozycja":                             "New exposure",
}

// findingTitleEN renders "Lead: subject (address)". The subject is data (a
// product, a page title, a certificate name) except signature names, which
// get their English name.
func findingTitleEN(typ, title string) string {
	head, tail := title, ""
	if i := strings.LastIndex(title, " ("); i > 0 && strings.HasSuffix(title, ")") {
		head, tail = title[:i], title[i:]
	}
	lead, subject, ok := strings.Cut(head, ": ")
	if !ok {
		return title
	}
	en, ok := titlePrefixEN[lead]
	if !ok {
		return title
	}
	if typ == FindingHeader || typ == FindingCookie {
		parts := strings.Split(subject, "; ")
		for i, p := range parts {
			parts[i] = SignatureNameIn(p, "en")
		}
		subject = strings.Join(parts, "; ")
	} else {
		subject = SignatureNameIn(subject, "en")
	}
	return en + ": " + subject + tail
}

// findingTextEN rewrites the Polish sentences of finding descriptions and
// evidence. Merged header and cookie findings join several descriptions,
// so each sentence is replaced where it stands; the data between them stays.
var findingTextEN = []struct {
	re *regexp.Regexp
	to string
}{
	{lit("Pod tym adresem odpowiada panel administracyjny. Sprawdź, czy musi być dostępny z tej sieci."), "An admin panel answers at this address. Check whether it must be reachable from this network."},
	{lit("Strona logowania działa bez TLS. Hasło można podsłuchać w sieci."), "The login page runs without TLS. Passwords can be sniffed on the network."},
	{lit("Usługa wygląda na środowisko testowe. Sprawdź, czy musi być dostępna z tej sieci."), "The service looks like a test environment. Check whether it must be reachable from this network."},
	{lit("Strona może ujawniać konfigurację i ścieżki aplikacji."), "The page can reveal the application's configuration and paths."},
	{lit("Pod tym adresem odpowiada urządzenie IoT. Sprawdź, czy jego interfejs musi być dostępny z tej sieci."), "An IoT device answers at this address. Check whether its interface must be reachable from this network."},
	{lit("Pod tym adresem odpowiada narzędzie deweloperskie. Takie narzędzia mają dostęp do kodu i sekretów."), "A developer tool answers at this address. Such tools have access to code and secrets."},
	{lit("Port bazy danych przyjmuje połączenia z sieci, z której wykonano skan."), "The database port accepts connections from the network the scan ran from."},
	{lit("Usługa zdalnego dostępu przyjmuje połączenia z sieci, z której wykonano skan."), "The remote access service accepts connections from the network the scan ran from."},
	{lit("Serwer pokazuje listę plików katalogu. Listing może ujawniać kopie zapasowe i pliki konfiguracyjne."), "The server shows the file list of a directory. The listing can reveal backups and configuration files."},
	{lit("Serwer pokazuje stronę domyślną. To zwykle zapomniana lub nieskonfigurowana instalacja."), "The server shows its default page. This is usually a forgotten or unconfigured installation."},
	{lit("Certyfikat TLS jest samopodpisany. Klient nie może sprawdzić tożsamości serwera."), "The TLS certificate is self-signed. A client cannot verify the server's identity."},
	{lit("Ciasteczka wskazują technologię albo są sesyjne bez flag Secure i HttpOnly."), "The cookies reveal a technology, or are session cookies without the Secure and HttpOnly flags."},
	{lit("Usługa nie była widoczna w poprzednich skanach. Sprawdź, czy jej wystawienie jest zamierzone."), "The service was not seen in earlier scans. Check whether its exposure is intended."},
	{regexp.MustCompile(`Certyfikat TLS stracił ważność (\S+)\.`), "The TLS certificate expired on $1."},
	{regexp.MustCompile(`Certyfikat TLS wygasa (\S+) \(za 1 dzień\)\.`), "The TLS certificate expires on $1 (in 1 day)."},
	{regexp.MustCompile(`Certyfikat TLS wygasa (\S+) \(za (-?\d+) dni\)\.`), "The TLS certificate expires on $1 (in $2 days)."},
	{regexp.MustCompile(`(?m)Nazwa w certyfikacie \(CN, SAN\) nie pasuje do nazwy, pod którą usługa odpowiada: (.*)\.$`), "The name in the certificate (CN, SAN) does not match the name the service answers on: $1."},
	{regexp.MustCompile(`Sygnatura „([^”]*)” pasuje do tej usługi \(pewność (\d+)%\)\.`), "Signature “$1” matches this service (confidence $2%)."},
}

// evidenceEN rewrites the Polish words the analysis and the exposure rules
// write into evidence snippets.
var evidenceEN = []struct {
	re *regexp.Regexp
	to string
}{
	{lit("; wystawca="), "; issuer="},
	{lit("; ważny do "), "; valid until "},
	{lit("wskazuje technologię "), "reveals the technology "},
	{lit("brak flagi HttpOnly"), "no HttpOnly flag"},
	{lit("brak flagi Secure"), "no Secure flag"},
	{lit("wartość wygląda na token JWT"), "the value looks like a JWT"},
	{regexp.MustCompile(`zostało (-?\d+) dni \(do ([^)]*)\)`), "$1 days left (until $2)"},
	{regexp.MustCompile(`^usługa HTTP bez TLS$`), "HTTP service without TLS"},
	{regexp.MustCompile(`^usługa już działa po HTTPS$`), "service already runs over HTTPS"},
	{regexp.MustCompile(`^przekierowanie na `), "redirect to "},
	{regexp.MustCompile(`^adres końcowy `), "final URL "},
	{regexp.MustCompile(`: \(brak\)$`), ": (none)"},
}

func lit(s string) *regexp.Regexp { return regexp.MustCompile(regexp.QuoteMeta(s)) }

func findingDescEN(desc string) string {
	for _, r := range findingTextEN {
		desc = r.re.ReplaceAllString(desc, r.to)
	}
	return desc
}

// EvidenceIn returns the evidence with its snippets in lang; it never
// changes the slice it gets.
func EvidenceIn(ev []model.Evidence, lang string) []model.Evidence {
	if lang != "en" || len(ev) == 0 {
		return ev
	}
	out := make([]model.Evidence, len(ev))
	for i, e := range ev {
		if e.Where == "not" {
			if rest, ok := strings.CutPrefix(e.Snippet, "nie zachodzi: "); ok {
				e.Snippet = "does not hold: " + RuleConditionIn(rest, lang)
			}
		}
		for _, r := range evidenceEN {
			e.Snippet = r.re.ReplaceAllString(e.Snippet, r.to)
		}
		out[i] = e
	}
	return out
}
