// Package interchange converts scan results between Czujka's model and the
// exchange formats: nmap XML, Czujka JSON and CSV. It is pure: bytes in,
// model types out, and the other way round. Imported results are
// model.HostResult records, so they enter the same pipeline as scanned data.
package interchange

import (
	"bytes"
	"strings"
)

// Format names. They are the values of model.ImportReport.Format.
const (
	FormatNmapXML = "nmap-xml"
	FormatJSON    = "czujka-json"
	FormatCSV     = "csv"
)

// Field is one canonical flat field of a result row: one row is one service
// of one host (or a host without services).
type Field string

const (
	FIP          Field = "ip"
	FHost        Field = "host" // an address or a name; resolved by its value
	FHostname    Field = "hostname"
	FUp          Field = "up"
	FPort        Field = "port"
	FProto       Field = "proto"
	FState       Field = "state"
	FService     Field = "service"
	FProduct     Field = "product"
	FVersion     Field = "version"
	FExtraInfo   Field = "extra_info"
	FBanner      Field = "banner"
	FTLS         Field = "tls"
	FURL         Field = "url"
	FStatus      Field = "status" // HTTP status code; "up"/"down" is read as host state
	FTitle       Field = "title"
	FServer      Field = "server"
	FRedirect    Field = "redirect"
	FTech        Field = "technologies"
	FClasses     Field = "classes"
	FCertCN      Field = "cert_cn"
	FCertIssuer  Field = "cert_issuer"
	FCertExpires Field = "cert_not_after"
	FCertSHA256  Field = "cert_sha256"
	FCookies     Field = "cookies"
	FCPE         Field = "cpe"
	FOS          Field = "os"
	FMAC         Field = "mac"
	FVendor      Field = "vendor"
	FRTT         Field = "rtt_ms"
	FReason      Field = "reason"
	FConfidence  Field = "confidence"
	FObservedAt  Field = "observed_at"
)

// FieldMapping is the one table that maps column names (CSV) and keys (flat
// JSON) to canonical fields. To adapt Czujka to the sample format of the
// organisers, add the names of that format here; nothing else changes.
//
// The first name of each row is the name the CSV export writes. Names are
// compared after normalisation: lower case, and space, dash and dot become
// an underscore ("HTTP Status" = "http_status").
var FieldMapping = []struct {
	Field Field
	Names []string
}{
	{FIP, []string{"ip", "ip_address", "ipaddress", "address", "addr", "ipv4", "ipv6", "host_ip", "target", "adres", "adres_ip"}},
	{FHost, []string{"host"}},
	{FHostname, []string{"hostname", "hostnames", "fqdn", "domain", "dns", "dns_name", "rdns", "nazwa", "nazwa_hosta", "domena"}},
	{FUp, []string{"up", "alive", "is_up", "host_up", "host_state", "host_status", "aktywny"}},
	{FPort, []string{"port", "portid", "port_number", "dst_port", "dport"}},
	{FProto, []string{"proto", "protocol", "transport", "protokol"}},
	{FState, []string{"state", "port_state", "stan"}},
	{FService, []string{"service", "service_name", "name", "svc", "usluga"}},
	{FProduct, []string{"product", "software", "app", "produkt"}},
	{FVersion, []string{"version", "product_version", "wersja"}},
	{FExtraInfo, []string{"extra_info", "extrainfo", "info", "extra"}},
	{FBanner, []string{"banner", "raw_banner", "baner"}},
	{FTLS, []string{"tls", "ssl", "https", "tunnel"}},
	{FURL, []string{"url", "uri", "link"}},
	{FStatus, []string{"status", "http_status", "status_code", "http_code", "code", "response_code", "kod"}},
	{FTitle, []string{"title", "http_title", "page_title", "tytul"}},
	{FServer, []string{"server", "http_server", "server_header", "web_server"}},
	{FRedirect, []string{"redirect", "final_url", "location", "redirect_url", "przekierowanie"}},
	{FTech, []string{"technologies", "technology", "tech", "techs", "cms", "framework", "technologie"}},
	{FClasses, []string{"classes", "class", "category", "categories", "klasy"}},
	{FCertCN, []string{"cert_cn", "tls_subject_cn", "ssl_cn", "cert_subject", "certificate_cn", "subject_cn"}},
	{FCertIssuer, []string{"cert_issuer", "tls_issuer", "ssl_issuer", "issuer"}},
	{FCertExpires, []string{"cert_not_after", "tls_not_after", "cert_expires", "cert_expiry", "not_after", "ssl_expiry"}},
	{FCertSHA256, []string{"cert_sha256", "tls_sha256", "cert_fingerprint", "tls_fingerprint"}},
	{FCookies, []string{"cookies", "cookie", "cookie_names", "ciasteczka"}},
	{FCPE, []string{"cpe", "cpes"}},
	{FOS, []string{"os", "os_guess", "operating_system", "system"}},
	{FMAC, []string{"mac", "mac_address"}},
	{FVendor, []string{"vendor", "mac_vendor", "producent"}},
	{FRTT, []string{"rtt_ms", "rtt", "latency_ms", "latency"}},
	{FReason, []string{"reason", "host_reason"}},
	{FConfidence, []string{"confidence", "conf"}},
	{FObservedAt, []string{"observed_at", "timestamp", "time", "date", "datetime", "scan_time", "scanned_at", "last_seen", "seen_at", "czas", "data"}},
}

var fieldByName = func() map[string]Field {
	m := map[string]Field{}
	for _, row := range FieldMapping {
		for _, n := range row.Names {
			m[normName(n)] = row.Field
		}
	}
	return m
}()

// CSVColumns is the column order of the CSV export.
var CSVColumns = func() []Field {
	out := make([]Field, 0, len(FieldMapping))
	for _, row := range FieldMapping {
		if row.Field != FHost {
			out = append(out, row.Field)
		}
	}
	return out
}()

// normName normalises a column name or JSON key.
func normName(s string) string {
	s = strings.TrimPrefix(s, "\ufeff")
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(" ", "_", "-", "_", ".", "_").Replace(s)
	return s
}

// LookupField returns the canonical field of a column name or key.
func LookupField(name string) (Field, bool) {
	f, ok := fieldByName[normName(name)]
	return f, ok
}

// Detect guesses the format from the first bytes of a file. It returns ""
// when the content is empty.
func Detect(head []byte) string {
	b := bytes.TrimLeft(bytes.TrimPrefix(head, []byte("\xef\xbb\xbf")), " \t\r\n")
	if len(b) == 0 {
		return ""
	}
	switch b[0] {
	case '<':
		return FormatNmapXML
	case '{', '[':
		return FormatJSON
	}
	return FormatCSV
}
