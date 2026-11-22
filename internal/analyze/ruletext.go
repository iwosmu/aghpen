package analyze

import (
	"regexp"
	"strings"
)

// RuleText is the Polish and English text of one built-in exposure rule.
// The Polish side is the text of internal/rules/builtin/*.yaml (a test in
// internal/rules keeps the two equal); a rule whose stored Polish text an
// analyst changed keeps that text in English too.
type RuleText struct {
	Name, Description, Remediation       string
	NameEN, DescriptionEN, RemediationEN string
}

// BuiltinRuleTexts holds the built-in exposure rules by id.
var BuiltinRuleTexts = map[string]RuleText{
	"admin-panel-outside-mgmt": {
		Name:          "Panel administracyjny poza siecią zarządzania",
		Description:   "Panel administracyjny jest osiągalny z sieci skanowanej. Panele powinny być dostępne tylko z sieci zarządzania (hosty z etykietą mgmt są pominięte).",
		Remediation:   "Ogranicz dostęp do panelu (ACL, VPN, sieć zarządzania) albo oznacz host etykietą mgmt, jeśli należy do sieci zarządzania.",
		NameEN:        "Admin panel outside the management network",
		DescriptionEN: "An admin panel is reachable from the scanned network. Admin panels should be reachable only from the management network (hosts tagged mgmt are skipped).",
		RemediationEN: "Restrict access to the panel (ACL, VPN, management network), or tag the host mgmt if it belongs to the management network.",
	},
	"login-over-plain-http": {
		Name:          "Formularz logowania przez zwykły HTTP",
		Description:   "Strona logowania działa bez TLS i nie przekierowuje na HTTPS. Hasła idą przez sieć otwartym tekstem.",
		Remediation:   "Włącz HTTPS i przekierowanie z HTTP na HTTPS.",
		NameEN:        "Login form over plain HTTP",
		DescriptionEN: "The login page runs without TLS and does not redirect to HTTPS. Passwords cross the network in clear text.",
		RemediationEN: "Enable HTTPS and redirect HTTP to HTTPS.",
	},
	"tls-certificate-expired": {
		Name:          "Wygasły certyfikat TLS",
		Description:   "Usługa przedstawia certyfikat, którego termin ważności minął.",
		Remediation:   "Odnów certyfikat (np. ACME) i wdroż go na usłudze.",
		NameEN:        "Expired TLS certificate",
		DescriptionEN: "The service presents a certificate that has expired.",
		RemediationEN: "Renew the certificate (for example with ACME) and deploy it on the service.",
	},
	"tls-certificate-expiring-14d": {
		Name:          "Certyfikat TLS wygasa w ciągu 14 dni",
		Description:   "Certyfikat jest jeszcze ważny, ale wygaśnie w ciągu 14 dni.",
		Remediation:   "Zaplanuj odnowienie certyfikatu.",
		NameEN:        "TLS certificate expires within 14 days",
		DescriptionEN: "The certificate is still valid, but expires within 14 days.",
		RemediationEN: "Plan the certificate renewal.",
	},
	"database-port-exposed": {
		Name:          "Port bazy danych otwarty na sieć skanowaną",
		Description:   "Serwer bazy danych (lub magazyn klucz–wartość) przyjmuje połączenia z sieci, z której skanuje Czujka.",
		Remediation:   "Zamknij port w zaporze albo zwiąż usługę z adresem lokalnym; dostęp tylko z serwerów aplikacji.",
		NameEN:        "Database port open to the scanned network",
		DescriptionEN: "A database server (or a key–value store) accepts connections from the network Czujka scans from.",
		RemediationEN: "Close the port in the firewall or bind the service to a local address; allow access only from the application servers.",
	},
	"cleartext-remote-access": {
		Name:          "Telnet albo FTP dostępny w sieci",
		Description:   "Usługa przesyła dane logowania otwartym tekstem (telnet, FTP).",
		Remediation:   "Wyłącz telnet i FTP; użyj SSH i SFTP.",
		NameEN:        "Telnet or FTP reachable on the network",
		DescriptionEN: "The service sends credentials in clear text (telnet, FTP).",
		RemediationEN: "Turn off telnet and FTP; use SSH and SFTP.",
	},
	"remote-desktop-exposed": {
		Name:          "Pulpit zdalny (RDP, VNC) dostępny w sieci",
		Description:   "Usługa pulpitu zdalnego jest osiągalna z sieci skanowanej.",
		Remediation:   "Udostępniaj pulpit zdalny tylko przez VPN albo bramę RDP.",
		NameEN:        "Remote desktop (RDP, VNC) reachable on the network",
		DescriptionEN: "A remote desktop service is reachable from the scanned network.",
		RemediationEN: "Offer remote desktop only through a VPN or an RDP gateway.",
	},
	"staging-or-debug-exposed": {
		Name:          "Środowisko testowe albo narzędzie deweloperskie dostępne w sieci",
		Description:   "Środowisko staging/test/dev albo narzędzie deweloperskie (CI, konsola debugowania) jest osiągalne z sieci skanowanej.",
		Remediation:   "Ogranicz dostęp do środowisk testowych albo oznacz je etykietą approved po akceptacji ryzyka.",
		NameEN:        "Test environment or developer tool reachable on the network",
		DescriptionEN: "A staging/test/dev environment or a developer tool (CI, debug console) is reachable from the scanned network.",
		RemediationEN: "Restrict access to test environments, or tag them approved once the risk is accepted.",
	},
	"unfinished-install-page": {
		Name:          "Niedokończona instalacja aplikacji",
		Description:   "Aplikacja pokazuje kreator instalacji (np. instalator Gitea, wp-admin/install.php WordPressa). Każdy, kto pierwszy go dokończy, ustawi konto administratora i przejmie aplikację.",
		Remediation:   "Dokończ instalację od razu albo wyłącz usługę; do czasu instalacji nie wystawiaj jej do sieci.",
		NameEN:        "Unfinished application installation",
		DescriptionEN: "The application shows its installation wizard (for example the Gitea installer, WordPress wp-admin/install.php). Whoever completes it first sets the admin account and takes over the application.",
		RemediationEN: "Complete the installation now or turn the service off; do not expose it to the network until it is installed.",
	},
	"unauthenticated-control-api": {
		Name:          "API sterujące bez uwierzytelniania",
		Description:   "API do sterowania usługą odpowiada bez logowania (np. API Toxiproxy, Traefik z api.insecure, API Dockera na porcie 2375). Kto je osiągnie, zmienia konfigurację usługi albo uruchamia kontenery.",
		Remediation:   "Zwiąż API z adresem lokalnym albo włącz uwierzytelnianie (Traefik bez api.insecure, Docker przez gniazdo lub TLS na 2376).",
		NameEN:        "Control API without authentication",
		DescriptionEN: "An API that controls the service answers without login (for example the Toxiproxy API, Traefik with api.insecure, the Docker API on port 2375). Whoever reaches it can change the service configuration or start containers.",
		RemediationEN: "Bind the API to a local address or enable authentication (Traefik without api.insecure, Docker through its socket or TLS on 2376).",
	},
	"default-server-page": {
		Name:          "Domyślna strona serwera",
		Description:   "Serwer WWW pokazuje stronę domyślną po instalacji. To zwykle porzucona albo nieskonfigurowana usługa.",
		Remediation:   "Wyłącz nieużywany serwer albo skonfiguruj właściwą witrynę.",
		NameEN:        "Default server page",
		DescriptionEN: "The web server shows its post-install default page. This is usually an abandoned or unconfigured service.",
		RemediationEN: "Turn off the unused server or configure the proper site.",
	},
	"directory-listing": {
		Name:          "Listowanie katalogów",
		Description:   "Serwer WWW pokazuje listę plików katalogu.",
		Remediation:   "Wyłącz autoindeks (Options -Indexes, autoindex off).",
		NameEN:        "Directory listing",
		DescriptionEN: "The web server shows the file list of a directory.",
		RemediationEN: "Turn off autoindex (Options -Indexes, autoindex off).",
	},
	"new-service-not-approved": {
		Name:          "Nowa usługa bez akceptacji",
		Description:   "Usługa pojawiła się w ciągu ostatnich 7 dni i nikt nie oznaczył jej etykietą approved. Włącz tę regułę po pierwszym pełnym skanie, aby każda nowa ekspozycja wymagała akceptacji.",
		Remediation:   "Sprawdź usługę i dodaj etykietę approved (do usługi albo hosta), jeśli jest zamierzona.",
		NameEN:        "New service not approved",
		DescriptionEN: "The service appeared in the last 7 days and nobody tagged it approved. Turn this rule on after the first full scan, so that every new exposure needs approval.",
		RemediationEN: "Check the service and add the tag approved (to the service or the host) if it is intended.",
	},
	"outdated-cms-major": {
		Name:          "Przestarzała główna wersja CMS",
		Description:   "Wykryto system CMS w głównej wersji, która nie dostaje już poprawek bezpieczeństwa.",
		Remediation:   "Zaktualizuj CMS do wspieranej wersji głównej.",
		NameEN:        "Outdated CMS major version",
		DescriptionEN: "A CMS runs a major version that no longer gets security fixes.",
		RemediationEN: "Upgrade the CMS to a supported major version.",
	},
	"tls-self-signed": {
		Name:          "Certyfikat samopodpisany",
		Description:   "Usługa używa certyfikatu samopodpisanego. Użytkownicy uczą się ignorować ostrzeżenia przeglądarki.",
		Remediation:   "Użyj certyfikatu z zaufanego CA (np. ACME).",
		NameEN:        "Self-signed certificate",
		DescriptionEN: "The service uses a self-signed certificate. Users learn to ignore browser warnings.",
		RemediationEN: "Use a certificate from a trusted CA (for example ACME).",
	},
	"web-without-https-redirect": {
		Name:          "Serwis WWW bez przekierowania na HTTPS",
		Description:   "Usługa WWW odpowiada po zwykłym HTTP i nie przekierowuje na HTTPS.",
		Remediation:   "Dodaj przekierowanie 301 na HTTPS.",
		NameEN:        "Web site without HTTPS redirect",
		DescriptionEN: "The web service answers over plain HTTP and does not redirect to HTTPS.",
		RemediationEN: "Add a 301 redirect to HTTPS.",
	},
}

// RuleTextIn returns the name, description and remediation of a rule in
// lang. Each field of a built-in rule whose stored text is the library's
// Polish text gets the English text; anything else stays as stored.
func RuleTextIn(id, name, desc, remediation, lang string) (string, string, string) {
	if lang != "en" {
		return name, desc, remediation
	}
	t, ok := BuiltinRuleTexts[id]
	if !ok {
		return name, desc, remediation
	}
	if name == t.Name {
		name = t.NameEN
	}
	if desc == t.Description {
		desc = t.DescriptionEN
	}
	if remediation == t.Remediation {
		remediation = t.RemediationEN
	}
	return name, desc, remediation
}

// conditionEN rewrites the Polish words of a rule condition (Rule.Describe)
// in English; the values (classes, services, ports, versions) stay.
var conditionEN = []struct {
	re *regexp.Regexp
	to string
}{
	{regexp.MustCompile(`^zawsze$`), "always"},
	{regexp.MustCompile(`nowe od (\d+) dni`), "new within $1 days"},
	{regexp.MustCompile(`ważny krócej niż (\d+) dni`), "valid for less than $1 days"},
	{regexp.MustCompile(`przekierowanie na HTTPS: `), "redirects to HTTPS: "},
	{regexp.MustCompile(`ocena co najmniej `), "interest at least "},
	{regexp.MustCompile(`(^|[ (])stan hosta `), "${1}host state "},
	{regexp.MustCompile(`(^|[ (])klasa `), "${1}class "},
	{regexp.MustCompile(`(^|[ (])technologia `), "${1}technology "},
	{regexp.MustCompile(`(^|[ (])usługa `), "${1}service "},
	{regexp.MustCompile(`(^|[ (])protokół `), "${1}protocol "},
	{regexp.MustCompile(`(^|[ (])stan `), "${1}state "},
	{regexp.MustCompile(`(^|[ (])schemat `), "${1}scheme "},
	{regexp.MustCompile(`(^|[ (])kod HTTP `), "${1}HTTP status "},
	{regexp.MustCompile(`(^|[ (])etykieta `), "${1}tag "},
	{regexp.MustCompile(`(^|[ (])nagłówek `), "${1}header "},
	{regexp.MustCompile(`(^|[ (])ciasteczko\b`), "${1}cookie"},
	{regexp.MustCompile(`(^|[ (])nie \(`), "${1}not ("},
	{regexp.MustCompile(` lub `), " or "},
	{regexp.MustCompile(` i `), " and "},
}

// RuleConditionIn returns a rule condition in words (Rule.Describe, or the
// condition stored in a finding) in lang.
func RuleConditionIn(cond, lang string) string {
	if lang != "en" {
		return cond
	}
	for _, r := range conditionEN {
		cond = r.re.ReplaceAllString(cond, r.to)
	}
	return cond
}

// ruleTitleEN renders the title of a policy finding: "name — address" or
// "name — brak w zakresie".
func ruleTitleEN(id, title string) string {
	i := strings.LastIndex(title, " — ")
	if i < 0 {
		name, _, _ := RuleTextIn(id, title, "", "", "en")
		return name
	}
	name, rest := title[:i], title[i+len(" — "):]
	name, _, _ = RuleTextIn(id, name, "", "", "en")
	if rest == "brak w zakresie" {
		rest = "missing in scope"
	}
	return name + " — " + rest
}

var rePolicyDesc = regexp.MustCompile(`(?s)^(.*?)(?:\n\n)?Naruszona reguła ekspozycji „([^”]*)”\. Warunek: (.*?)\.(?:\nZalecenie: (.*))?$`)

// ruleDescEN renders the description of a policy finding: the rule's
// description, the violated rule and its condition, the remediation.
func ruleDescEN(id, desc string) string {
	m := rePolicyDesc.FindStringSubmatch(desc)
	if m == nil {
		_, d, _ := RuleTextIn(id, "", desc, "", "en")
		return d
	}
	_, d, rem := RuleTextIn(id, "", m[1], m[4], "en")
	out := d
	if out != "" {
		out += "\n\n"
	}
	out += "Exposure rule “" + m[2] + "” violated. Condition: " + RuleConditionIn(m[3], "en") + "."
	if rem != "" {
		out += "\nRemediation: " + rem
	}
	return out
}
