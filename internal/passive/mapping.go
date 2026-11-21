package passive

import (
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Field is one logical column of a passive data file.
type Field string

const (
	FIP         Field = "ip"
	FHostname   Field = "hostname"
	FPort       Field = "port"
	FFirstSeen  Field = "first_seen"
	FLastSeen   Field = "last_seen"
	FSource     Field = "source"
	FType       Field = "type"  // DNS record type: A, AAAA, CNAME, PTR
	FValue      Field = "value" // DNS record data
	FCount      Field = "count"
	FCertCN     Field = "cert_cn"
	FCertSANs   Field = "cert_sans"
	FCertIssuer Field = "cert_issuer"
	FNotBefore  Field = "cert_not_before"
	FNotAfter   Field = "cert_not_after"
	FCertSerial Field = "cert_serial"
	FCertSHA256 Field = "cert_sha256"
)

// FieldMapping is the one table that maps column names of CSV files and keys
// of JSON records to fields. Names are compared after normName (lower case,
// separators removed, Polish letters folded). The format of the organisers'
// data set is not known yet: to accept it, add its names here.
var FieldMapping = []struct {
	Field Field
	Names []string
}{
	{FIP, []string{"ip", "ip_address", "address", "addr", "ipv4", "ipv6", "host_ip", "resolved_ip", "adres", "adres_ip"}},
	{FHostname, []string{"hostname", "host", "name", "fqdn", "domain", "dns_name", "rrname", "query", "qname", "subdomain", "record", "owner", "domena", "nazwa", "nazwa_hosta"}},
	{FPort, []string{"port", "dport", "dst_port", "dest_port", "port_number"}},
	{FFirstSeen, []string{"first_seen", "time_first", "first", "first_seen_at", "seen_first", "zone_time_first", "pierwsza_obserwacja", "pierwszy_raz"}},
	{FLastSeen, []string{"last_seen", "time_last", "last", "last_seen_at", "seen_last", "zone_time_last", "timestamp", "entry_timestamp", "ostatnia_obserwacja", "ostatni_raz"}},
	{FSource, []string{"source", "src", "sensor", "sensor_id", "origin", "feed", "zrodlo"}},
	{FType, []string{"type", "rrtype", "record_type", "qtype", "rtype", "typ"}},
	{FValue, []string{"value", "rdata", "data", "answer", "answers", "target", "content", "wartosc", "dane"}},
	{FCount, []string{"count", "hits", "seen", "liczba"}},
	{FCertCN, []string{"common_name", "subject_cn", "cn", "subject", "cert_subject", "cert_cn"}},
	{FCertSANs, []string{"name_value", "sans", "san", "subject_alt_names", "dns_names", "alt_names", "names", "cert_sans"}},
	{FCertIssuer, []string{"issuer", "issuer_name", "issuer_cn", "cert_issuer", "wystawca"}},
	{FNotBefore, []string{"not_before", "valid_from", "cert_not_before", "wazny_od"}},
	{FNotAfter, []string{"not_after", "valid_to", "expires", "cert_not_after", "wazny_do"}},
	{FCertSerial, []string{"serial", "serial_number", "cert_serial"}},
	{FCertSHA256, []string{"sha256", "fingerprint", "fingerprint_sha256", "sha256_fingerprint", "cert_sha256"}},
}

var polishFold = strings.NewReplacer("ą", "a", "ć", "c", "ę", "e", "ł", "l", "ń", "n", "ó", "o", "ś", "s", "ź", "z", "ż", "z")

// normName folds a column name: "Last Seen", "last-seen" and "LastSeen" are one name.
func normName(s string) string {
	s = polishFold.Replace(strings.ToLower(strings.TrimSpace(s)))
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var fieldByName = func() map[string]Field {
	m := map[string]Field{}
	for _, row := range FieldMapping {
		for _, n := range row.Names {
			if _, dup := m[normName(n)]; !dup {
				m[normName(n)] = row.Field
			}
		}
	}
	return m
}()

// LookupField returns the field of a column name or a JSON key.
func LookupField(name string) (Field, bool) {
	f, ok := fieldByName[normName(name)]
	return f, ok
}

var timeLayouts = []string{
	time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05", "2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02", "02.01.2006 15:04:05", "02.01.2006 15:04", "02.01.2006",
	"Jan 2 15:04:05 2006 MST", "Jan _2 15:04:05 2006 MST",
}

// parseTime reads the time formats seen in passive data: RFC 3339, the
// crt.sh format without a zone, dates, and Unix time in seconds or milliseconds.
func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		switch {
		case n >= 1e11 && n < 1e14: // milliseconds
			return time.UnixMilli(int64(n)).UTC(), true
		case n >= 1e8 && n < 1e11: // seconds
			return time.Unix(int64(n), 0).UTC(), true
		}
		return time.Time{}, false
	}
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// cleanHost normalises a DNS name: lower case, no trailing dot, no "*."
// prefix. It reports wildcard = true for "*.name" and ok = false when the
// text is not a host name.
func cleanHost(s string) (name string, wildcard, ok bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if strings.HasPrefix(s, "*.") {
		s, wildcard = s[2:], true
	}
	if s == "" || len(s) > 253 {
		return "", false, false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false, false // an address is not a name
	}
	labels := strings.Split(s, ".")
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil {
		return "", false, false // "999.1.1.1": a broken address, not a name
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false, false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
				return "", false, false
			}
		}
	}
	return s, wildcard, true
}

// arpaToAddr turns "4.3.2.1.in-addr.arpa" or an ip6.arpa name into an address.
func arpaToAddr(name string) (netip.Addr, bool) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if rest, ok := strings.CutSuffix(n, ".in-addr.arpa"); ok {
		p := strings.Split(rest, ".")
		if len(p) != 4 {
			return netip.Addr{}, false
		}
		a, err := netip.ParseAddr(p[3] + "." + p[2] + "." + p[1] + "." + p[0])
		return a, err == nil
	}
	if rest, ok := strings.CutSuffix(n, ".ip6.arpa"); ok {
		p := strings.Split(rest, ".")
		if len(p) != 32 {
			return netip.Addr{}, false
		}
		var b strings.Builder
		for i := 31; i >= 0; i-- {
			if len(p[i]) != 1 {
				return netip.Addr{}, false
			}
			b.WriteString(p[i])
			if i%4 == 0 && i > 0 {
				b.WriteByte(':')
			}
		}
		a, err := netip.ParseAddr(b.String())
		return a, err == nil
	}
	return netip.Addr{}, false
}
