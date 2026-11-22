package i18n

import "testing"

func TestText(t *testing.T) {
	cases := map[string]string{
		"Host niestabilny. Zwykle aktywny śr 09:00–10:00.":                                                    "Host unstable. Usually up Wed 09:00–10:00.",
		"Nie odpowiada od 21.11 10:05. Sprawdzenie 2 z 4. Przesunięte do okna czasowego (start 22.11 08:00).": "Not responding since 21.11 10:05. Check 2 of 4. Moved into the time window (start 22.11 08:00).",
		"pełny zakres portów (1-65535) objął 16 z 70 aktywnych hostów; pozostałe: porty z profilu":            "the full port range (1-65535) covered 16 of 70 live hosts; the others: the profile's ports",
		"Obserwator":                   "Viewer",
		"Ponowne sprawdzenie: 3 hosty": "Re-probe: 3 host(s)",
	}
	for pl, want := range cases {
		if got := Text(pl, "en"); got != want {
			t.Errorf("Text(%q) = %q, want %q", pl, got, want)
		}
		if Text(pl, "pl") != pl {
			t.Errorf("Polish changed: %q", pl)
		}
	}
}

func TestErrorMessage(t *testing.T) {
	cases := map[string]string{
		"Ten profil ma już skan #12. Zakończ albo anuluj go przed nowym.":                          "This profile already has scan #12. Let it finish or cancel it before a new one.",
		`nie rozpoznano "x y": to nie jest adres IP, zakres CIDR, zakres adresów ani nazwa domeny`: `"x y" not recognised: it is not an IP address, a CIDR range, an address range or a domain name`,
		"zakresy profilu nie mają żadnego włączonego celu":                                         "the profile's scopes have no enabled target",
		"Każdy cel leży poza dozwolonymi sieciami albo poza blokadą operatora (10.0.0.0/8)":        "Every target is outside the allowed networks or outside the operator lock (10.0.0.0/8)",
		"300000 adresów to więcej niż limit 65536":                                                 "300000 addresses is more than the limit of 65536",
		"Ta reguła zgłosiłaby dziś 7 naruszeń (sprawdzono 12 hostów i 40 usług).":                  "This rule would report 7 violation(s) today (checked 12 hosts and 40 services).",
		"not found": "not found",
	}
	for pl, want := range cases {
		if got := ErrorMessage(pl, "en"); got != want {
			t.Errorf("ErrorMessage(%q) = %q, want %q", pl, got, want)
		}
		if got := ErrorMessage(pl, "pl"); got != pl {
			t.Errorf("Polish changed: %q", got)
		}
	}
}
