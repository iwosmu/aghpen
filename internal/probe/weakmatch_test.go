package probe

import (
	"strings"
	"testing"
)

const probesSample = `Probe TCP NULL q||
match nagios-nsca m|^.{128}[\x52-\x7F]...$|s p/Nagios NSCA/
match thinprint m|^\x94$| p/ThinPrint print server/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)\r?\n| p/OpenSSH/ v/$2/
match stratum m|^{\"id\":null,\"method\":\"mining\.notify\"| p/Stratum bitcoin mining protocol/
match printer m|^\0$| p/Some printer/
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
match printer m|^HTTP/1\.0 200 OK\r\nServer: SomePrinter| p/Some printer/
Probe UDP NTPRequest q|\xe3|
match ntp m|^\xe4[\0\x10]..$| p/NTP/ v/v4/
`

func TestWeakMatchesAreBannerLengthGuesses(t *testing.T) {
	w := ParseWeakMatches(strings.NewReader(probesSample))
	for _, k := range []string{"nagios-nsca\x00Nagios NSCA", "thinprint\x00ThinPrint print server"} {
		if !w[k] {
			t.Errorf("%q must be weak", k)
		}
	}
	// literal content, a strong line elsewhere, and a probe-specific answer stay
	for _, k := range []string{"ssh\x00OpenSSH", "stratum\x00Stratum bitcoin mining protocol", "printer\x00Some printer", "ntp\x00NTP"} {
		if w[k] {
			t.Errorf("%q must not be weak", k)
		}
	}
	res := &Result{Hosts: []Host{{IP: "10.0.0.1", Ports: []Port{
		{Port: 8000, Name: "nagios-nsca", Product: "Nagios NSCA", CPE: []string{"cpe:/a:x"}, Confidence: 1},
		{Port: 22, Name: "ssh", Product: "OpenSSH", Version: "9.6", Confidence: 1},
	}}}}
	demoteWeak(res, w)
	p := res.Hosts[0].Ports
	if p[0].Product != "" || p[0].CPE != nil || p[0].Confidence > 0.3 || p[0].Name != "nagios-nsca" || !strings.Contains(p[0].ExtraInfo, "Nagios NSCA") {
		t.Errorf("weak match not demoted: %+v", p[0])
	}
	if p[1].Product != "OpenSSH" || p[1].Confidence != 1 {
		t.Errorf("strong match changed: %+v", p[1])
	}
}
