package i18n

import "testing"

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
