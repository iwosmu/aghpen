// Package i18n holds the English texts of the server's Polish messages that
// are not built from structured fields: error messages and validation
// messages. The server writes Polish; an answer in English rewrites the
// known sentences and keeps the data between them (addresses, names, counts).
package i18n

import "regexp"

type rewrite struct {
	re *regexp.Regexp
	to string
}

func lit(s string) *regexp.Regexp { return regexp.MustCompile(regexp.QuoteMeta(s)) }

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

// errorEN rewrites the Polish error messages of the API and of the packages
// whose errors it passes on (runner, targets, interchange, passive, rules).
var errorEN = []rewrite{
	// api
	{lit("Sygnatury wbudowanej nie można zmienić. Wyłącz ją albo skopiuj."), "A built-in signature cannot be changed. Disable it or copy it."},
	{lit("Sygnatury wbudowanej nie można usunąć. Wyłącz ją."), "A built-in signature cannot be deleted. Disable it."},
	{lit("Twoja rola nie może dodawać celów. Zaimportuj wyniki bez zakresu."), "Your role cannot add targets. Import the results without a scope."},
	{lit("crt.sh jest wyłączone. Administrator włącza je na stronie Administracja."), "crt.sh is turned off. An administrator turns it on in Administration."},
	{re(`Ten profil ma już skan #(\d+)\. Zakończ albo anuluj go przed nowym\.`), "This profile already has scan #$1. Let it finish or cancel it before a new one."},
	// runner
	{re(`"([^"]*)" nie jest siecią CIDR ani adresem IP`), `"$1" is not a CIDR network or an IP address`},
	{re(`"([^"]*)" nie jest siecią CIDR`), `"$1" is not a CIDR network`},
	{lit("zakresy profilu nie mają żadnego włączonego celu"), "the profile's scopes have no enabled target"},
	{lit("Każdy cel leży poza dozwolonymi sieciami albo poza blokadą operatora"), "Every target is outside the allowed networks or outside the operator lock"},
	{lit("Każdy cel leży poza dozwolonymi sieciami"), "Every target is outside the allowed networks"},
	{lit("profil jest wyłączony"), "the profile is disabled"},
	{re(`"([^"]*)" jest większy niż /16`), `"$1" is larger than /16`},
	{re(`(\d+) adresów to więcej niż limit (\d+)`), "$1 addresses is more than the limit of $2"},
	{lit("nie ma żadnego profilu skanowania"), "there is no scan profile"},
	{lit("ports: wymagana lista portów w składni nmap, np. 22,80,443,8000-8100"), "ports: a port list in nmap syntax is required, for example 22,80,443,8000-8100"},
	{lit("Adres nie leży w żadnym włączonym celu."), "The address is not in any enabled target."},
	// targets
	{re(`błąd odczytu CSV w wierszu (\d+)`), "CSV read error on line $1"},
	{lit("pusta wartość"), "empty value"},
	{lit("wartość jest za długa (ponad 255 znaków)"), "the value is too long (over 255 characters)"},
	{lit("niepoprawny adres URL; podaj adres IP, zakres CIDR lub nazwę domeny"), "invalid URL; give an IP address, a CIDR range or a domain name"},
	{lit("zakresy CIDR IPv6 nie są obsługiwane; podaj pojedyncze adresy IPv6"), "IPv6 CIDR ranges are not supported; give single IPv6 addresses"},
	{re(`niepoprawny koniec zakresu ("[^"]*") \(ostatni oktet musi być w 0–255\)`), "invalid range end $1 (the last octet must be 0–255)"},
	{re(`koniec zakresu (\S+) jest mniejszy niż początek (\S+)`), "range end $1 is lower than range start $2"},
	{re(`niepoprawny początek zakresu ("[^"]*") \(oczekiwano adresu IPv4\)`), "invalid range start $1 (an IPv4 address is expected)"},
	{lit("nazwa domeny jest za długa (ponad 253 znaki)"), "the domain name is too long (over 253 characters)"},
	{re(`nie rozpoznano ("[^"]*"): to nie jest adres IP, zakres CIDR, zakres adresów ani nazwa domeny`), "$1 not recognised: it is not an IP address, a CIDR range, an address range or a domain name"},
	{re(`niepoprawna nazwa domeny ("[^"]*") \(dozwolone litery, cyfry i myślnik\)`), "invalid domain name $1 (letters, digits and hyphens only)"},
	{re(`niepoprawna nazwa domeny ("[^"]*") \(końcówka musi składać się z liter\)`), "invalid domain name $1 (the top-level domain must be letters)"},
	// interchange and passive files
	{lit("nie można odczytać nagłówka CSV"), "cannot read the CSV header"},
	{lit("CSV nie ma kolumny z adresem (ip, host, address). Pierwszy wiersz musi być nagłówkiem."), "The CSV has no address column (ip, host, address). The first row must be the header."},
	{lit("błąd odczytu CSV"), "CSV read error"},
	{lit("nieznany protokół (dozwolone: tcp, udp, sctp)"), "unknown protocol (allowed: tcp, udp, sctp)"},
	{lit("niepoprawna data ważności certyfikatu"), "invalid certificate expiry date"},
	{lit("nieobsługiwany JSON: oczekiwano tablicy lub obiektu"), "unsupported JSON: an array or an object is expected"},
	{re(`nieobsługiwany JSON: klucz ("[^"]*") nie jest tablicą`), "unsupported JSON: key $1 is not an array"},
	{lit("eksport znalezisk Czujki musi być tablicą JSON"), "a Czujka findings export must be a JSON array"},
	{lit("nie można odczytać pliku"), "cannot read the file"},
	{re(`plik jest większy niż (\d+) MB`), "the file is larger than $1 MB"},
	{re(`nie można otworzyć pliku (\S+)`), "cannot open file $1"},
	{lit("źródło zewnętrzne jest wyłączone"), "the external source is turned off"},
	// rules
	{re(`reguła o id „([^”]*)” już istnieje`), "a rule with id “$1” already exists"},
	{lit("reguły wbudowanej nie można edytować; skopiuj ją jako własną regułę (inne id) i wyłącz wbudowaną"), "a built-in rule cannot be edited; copy it as your own rule (another id) and disable the built-in one"},
	{re(`^reguła ma błędy$`), "the rule has errors"},
	{lit("Reguła ma błędy; popraw je, aby zobaczyć wynik."), "The rule has errors; fix them to see the result."},
	{re(`Wymaganie jest dziś spełnione \(sprawdzono (\d+) hostów i (\d+) usług\)\.`), "The requirement holds today (checked $1 hosts and $2 services)."},
	{re(`Ta reguła zgłosiłaby dziś (\d+) (?:naruszenie|naruszenia|naruszeń) \(sprawdzono (\d+) hostów i (\d+) usług\)\.`), "This rule would report $1 violation(s) today (checked $2 hosts and $3 services)."},
	// timeline
	{re(`^błąd wewnętrzny$`), "internal error"},
	{re(`^nie znaleziono$`), "not found"},
}

// ErrorMessage returns msg in lang ("en" or "pl"). Polish returns msg.
func ErrorMessage(msg, lang string) string {
	if lang != "en" || msg == "" {
		return msg
	}
	for _, r := range errorEN {
		msg = r.re.ReplaceAllString(msg, r.to)
	}
	return msg
}
