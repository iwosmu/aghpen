package interchange

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/analyze"
	"github.com/iwosmu/aghpen/internal/model"
)

// Findings exchange formats. They are the values of FindingsReport.Format.
//
//   - dojo-generic-json, dojo-generic-csv: DefectDojo "Generic Findings
//     Import" (JSON {"findings": [...]} and the CSV with the columns Date,
//     Title, CweId, Url, Severity, Description ...). The field lists follow
//     the parser of DefectDojo 2.x/3.x (dojo/tools/generic).
//   - dojo-api-json: a findings list read from the DefectDojo API
//     (GET /api/v2/findings/: {"count", "results": [...]}), one finding object,
//     or a bare array of such objects.
//   - czujka-findings-json, czujka-findings-csv: Czujka's own findings export
//     (GET /api/v1/export/findings.json|csv).
const (
	FormatDojoGenericJSON    = "dojo-generic-json"
	FormatDojoGenericCSV     = "dojo-generic-csv"
	FormatDojoAPIJSON        = "dojo-api-json"
	FormatCzujkaFindingsJSON = "czujka-findings-json"
	FormatCzujkaFindingsCSV  = "czujka-findings-csv"
)

// TypeImported is the Finding.Type of a finding from a foreign tool.
const TypeImported = "imported"

// DojoGenericCSVHeader is the header Czujka writes. DefectDojo reads the
// columns by name; Title, Description, Date and Severity are required.
var DojoGenericCSVHeader = []string{"Date", "Title", "CweId", "Url", "Severity", "Description", "Mitigation", "Impact",
	"References", "Active", "Verified", "FalsePositive", "IsMitigated", "Duplicate"}

// czujkaFindingsCSVHeader is the header of GET /api/v1/export/findings.csv.
var czujkaFindingsCSVHeader = []string{"id", "key", "type", "title", "severity", "status", "interest", "ip", "port", "url", "signature",
	"tags", "assignee", "first_seen", "last_seen", "dojo_url", "manual", "description", "note"}

// DojoGenericFinding is one finding of the Generic Findings Import JSON.
// Every key is in the allow-list of DefectDojo's parser: an unknown key makes
// DefectDojo reject the whole file.
type DojoGenericFinding struct {
	Title            string            `json:"title"`
	Description      string            `json:"description"`
	Severity         string            `json:"severity"`
	Date             string            `json:"date,omitempty"`
	CWE              int               `json:"cwe,omitempty"`
	Mitigation       string            `json:"mitigation,omitempty"`
	Impact           string            `json:"impact,omitempty"`
	References       string            `json:"references,omitempty"`
	Active           bool              `json:"active"`
	Verified         bool              `json:"verified"`
	FalseP           bool              `json:"false_p"`
	IsMitigated      bool              `json:"is_mitigated,omitempty"`
	RiskAccepted     bool              `json:"risk_accepted,omitempty"`
	OutOfScope       bool              `json:"out_of_scope,omitempty"`
	StaticFinding    bool              `json:"static_finding"`
	DynamicFinding   bool              `json:"dynamic_finding"`
	UniqueIDFromTool string            `json:"unique_id_from_tool,omitempty"`
	VulnIDFromTool   string            `json:"vuln_id_from_tool,omitempty"`
	Service          string            `json:"service,omitempty"`
	Endpoints        []DojoEndpoint    `json:"endpoints,omitempty"`
	Tags             []string          `json:"tags,omitempty"`
	Files            []DojoGenericFile `json:"files,omitempty"`
}

// DojoEndpoint is an endpoint object of the Generic JSON.
type DojoEndpoint struct {
	Protocol string `json:"protocol,omitempty"`
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Path     string `json:"path,omitempty"`
}

// DojoGenericFile is a file attached to a finding of the Generic JSON
// (DefectDojo stores it as a file of the finding). Data is base64.
type DojoGenericFile struct {
	Title string `json:"title"`
	Data  string `json:"data"`
}

// NewDojoFile builds an attachment from raw bytes.
func NewDojoFile(title string, data []byte) DojoGenericFile {
	return DojoGenericFile{Title: title, Data: base64.StdEncoding.EncodeToString(data)}
}

// DojoGenericReport is the top-level object of the Generic JSON.
type DojoGenericReport struct {
	Name     string               `json:"name,omitempty"`
	Type     string               `json:"type,omitempty"`
	Version  string               `json:"version,omitempty"`
	Findings []DojoGenericFinding `json:"findings"`
}

// DojoSeverity maps a Czujka severity to DefectDojo's name and numerical code.
func DojoSeverity(s model.Severity) (name, numerical string) {
	switch s {
	case model.SevHigh:
		return "High", "S1"
	case model.SevMedium:
		return "Medium", "S2"
	case model.SevLow:
		return "Low", "S3"
	}
	return "Info", "S4"
}

// SeverityFromDojo maps a DefectDojo severity name (any case) to Czujka's.
// Critical becomes high: Czujka has no higher level.
func SeverityFromDojo(s string) (model.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "s0", "s1":
		return model.SevHigh, true
	case "medium", "s2":
		return model.SevMedium, true
	case "low", "s3":
		return model.SevLow, true
	case "info", "informational", "s4", "":
		return model.SevInfo, true
	}
	return model.SevInfo, false
}

// DojoFlags are the status flags of a DefectDojo finding.
type DojoFlags struct {
	Active       bool `json:"active"`
	Verified     bool `json:"verified"`
	FalseP       bool `json:"false_p"`
	RiskAccepted bool `json:"risk_accepted"`
	IsMitigated  bool `json:"is_mitigated"`
	OutOfScope   bool `json:"out_of_scope"`
	Duplicate    bool `json:"duplicate"`
}

// FlagsOf maps Czujka's status to DefectDojo's flags.
//
//	Czujka status   | active | verified | false_p | is_mitigated | risk_accepted
//	----------------+--------+----------+---------+--------------+--------------
//	new             | true   | false    | false   | false        | false
//	triaged         | true   | true     | false   | false        | false
//	accepted        | true   | false    | false   | false        | (tag "accepted")
//	false_positive  | false  | false    | true    | false        | false
//	resolved        | false  | false    | false   | true         | false
//
// "accepted" is a tag and not risk_accepted: DefectDojo accepts a risk only
// through a Risk Acceptance object or with simple risk acceptance enabled on
// the product, so a plain flag can be refused.
func FlagsOf(st model.FindingStatus) DojoFlags {
	switch st {
	case model.FindingTriaged:
		return DojoFlags{Active: true, Verified: true}
	case model.FindingFalsePositive:
		return DojoFlags{FalseP: true}
	case model.FindingResolved:
		return DojoFlags{IsMitigated: true}
	}
	return DojoFlags{Active: true}
}

// StatusFromDojo maps DefectDojo's flags to Czujka's status. The first rule
// that matches wins:
//
//	DefectDojo flags                 | Czujka status
//	---------------------------------+---------------
//	false_p                          | false_positive
//	risk_accepted                    | accepted
//	out_of_scope                     | accepted
//	is_mitigated                     | resolved
//	not active (closed otherwise)    | resolved
//	active and verified              | triaged
//	active, not verified             | new
//
// A tag "accepted" (Czujka's own export of "accepted") also gives accepted
// for an active finding; pass hasAcceptedTag.
func StatusFromDojo(f DojoFlags, hasAcceptedTag bool) model.FindingStatus {
	switch {
	case f.FalseP:
		return model.FindingFalsePositive
	case f.RiskAccepted, f.OutOfScope:
		return model.FindingAccepted
	case f.IsMitigated, !f.Active:
		return model.FindingResolved
	case hasAcceptedTag:
		return model.FindingAccepted
	case f.Verified:
		return model.FindingTriaged
	}
	return model.FindingNew
}

// DojoTags returns the DefectDojo tags of a finding: "czujka", its type and
// its own tags, lower case, without spaces and commas.
func DojoTags(f model.Finding) []string {
	set := map[string]bool{"czujka": true}
	add := func(t string) {
		t = strings.ToLower(strings.TrimSpace(t))
		t = strings.NewReplacer(" ", "-", ",", "-", "\"", "", "'", "").Replace(t)
		if t != "" {
			set[t] = true
		}
	}
	add(f.Type)
	for _, t := range f.Tags {
		add(t)
	}
	if f.Status == model.FindingAccepted {
		add("accepted")
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// DojoDescription builds the Markdown description: the text of the finding,
// the facts, and the evidence. Cookie values and other secrets are never in
// Finding.Evidence, so they cannot reach DefectDojo. The "**Host:**" line and
// the "Klucz:" line are read back by the importer.
func DojoDescription(f model.Finding) string {
	var b strings.Builder
	b.WriteString(strings.TrimSpace(f.Description))
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "**Host:** %s", f.IP)
	if f.Port != 0 {
		fmt.Fprintf(&b, " · **Port:** %d", f.Port)
	}
	if f.URL != "" {
		fmt.Fprintf(&b, " · **URL:** %s", f.URL)
	}
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "**Typ obserwacji:** %s · **Ocena ciekawości:** %d/100", f.Type, f.Interest)
	if f.Signature != "" {
		fmt.Fprintf(&b, " · **Sygnatura:** %s", f.Signature)
	}
	b.WriteString("\n\n")
	if !f.FirstSeen.IsZero() {
		fmt.Fprintf(&b, "**Pierwsza obserwacja:** %s · **Ostatnia obserwacja:** %s\n\n",
			f.FirstSeen.UTC().Format("2006-01-02 15:04 UTC"), f.LastSeen.UTC().Format("2006-01-02 15:04 UTC"))
	}
	if len(f.Evidence) > 0 {
		b.WriteString("**Dowody**\n\n")
		for _, e := range f.Evidence {
			fmt.Fprintf(&b, "- %s (%s): `%s`\n", e.Where, e.Matcher, strings.ReplaceAll(e.Snippet, "`", "'"))
		}
		b.WriteString("\n")
	}
	if strings.TrimSpace(f.Note) != "" {
		fmt.Fprintf(&b, "**Notatka analityka:** %s\n\n", strings.TrimSpace(f.Note))
	}
	fmt.Fprintf(&b, "_Źródło: Czujka. Bezpieczna detekcja obecności cech: bez prób logowania, bez payloadów. Klucz: %s_", f.Key)
	return b.String()
}

// DojoEndpoints builds the endpoint of a finding. The host is always the IP
// address, so the endpoint does not change when a name changes.
func DojoEndpoints(f model.Finding) []DojoEndpoint {
	if f.IP == "" {
		return nil
	}
	e := DojoEndpoint{Host: f.IP, Port: f.Port, Protocol: "tcp"}
	if u, err := url.Parse(f.URL); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		e.Protocol = u.Scheme
	}
	return []DojoEndpoint{e}
}

// dojoAdvice holds the CWE, the mitigation and the impact of a finding type.
// Texts are Polish, like the rest of what Czujka writes for the analyst.
type dojoAdvice struct {
	cwe        int
	mitigation string
	impact     string
}

var adviceByType = map[string]dojoAdvice{
	analyze.FindingAdminPanel: {284, "Ogranicz dostęp do panelu (VPN, lista dozwolonych adresów) albo usuń go z sieci publicznej.",
		"Panel administracyjny dostępny z sieci zwiększa powierzchnię ataku na konta uprzywilejowane."},
	analyze.FindingLoginPlainHTTP: {319, "Wymuś HTTPS dla formularza logowania i przekierowanie z HTTP.",
		"Dane logowania mogą zostać przechwycone w sieci."},
	analyze.FindingStaging: {200, "Ukryj środowisko testowe za VPN albo uwierzytelnieniem; nie trzymaj w nim prawdziwych danych.",
		"Środowiska testowe są zwykle słabiej chronione niż produkcja."},
	analyze.FindingDebugPage: {489, "Wyłącz tryb debug i strony diagnostyczne w środowisku dostępnym z sieci.",
		"Strona diagnostyczna ujawnia szczegóły konfiguracji i ścieżki aplikacji."},
	analyze.FindingIoT: {1188, "Przenieś urządzenie do odseparowanej sieci i zmień ustawienia domyślne.",
		"Urządzenia IoT często mają domyślną konfigurację i rzadkie aktualizacje."},
	analyze.FindingDevTool: {284, "Ogranicz dostęp do narzędzia deweloperskiego do sieci wewnętrznej i kont z uwierzytelnieniem.",
		"Narzędzia CI i repozytoria dają dostęp do kodu, sekretów i potoku wdrożeń."},
	analyze.FindingDatabase: {668, "Zamknij port bazy danych dla sieci, z których baza nie musi być osiągalna.",
		"Baza dostępna z sieci jest celem prób odgadnięcia haseł i ataków na znane podatności."},
	analyze.FindingRemoteAccess: {284, "Udostępniaj zdalny dostęp tylko przez VPN albo bastion.",
		"Usługi zdalnego dostępu są celem prób logowania."},
	analyze.FindingExpiredCert:  {298, "Odnów certyfikat TLS.", "Przeglądarki ostrzegają użytkowników; uczy to ignorowania ostrzeżeń."},
	analyze.FindingCertExpiring: {298, "Odnów certyfikat TLS przed datą wygaśnięcia.", "Po wygaśnięciu usługa straci zaufanie klientów."},
	analyze.FindingSelfSigned: {295, "Użyj certyfikatu wystawionego przez zaufany urząd certyfikacji.",
		"Klient nie może sprawdzić tożsamości serwera."},
	analyze.FindingHostMismatch: {297, "Wystaw certyfikat z poprawną nazwą (SAN) dla tej usługi.", "Klient nie może sprawdzić tożsamości serwera."},
	analyze.FindingHeader: {200, "Usuń albo skróć nagłówki z nazwą i wersją oprogramowania.",
		"Wersja oprogramowania ułatwia dobór znanych podatności."},
	analyze.FindingCookie: {1004, "Ustaw flagi Secure, HttpOnly i SameSite dla ciasteczek sesyjnych.",
		"Ciasteczko bez flag można odczytać skryptem albo przesłać nieszyfrowanym połączeniem."},
	analyze.FindingDirListing: {548, "Wyłącz listowanie katalogów na serwerze WWW.", "Listing ujawnia pliki, których nikt nie miał publikować."},
	analyze.FindingDefaultPage: {1188, "Usuń stronę domyślną albo wyłącz nieużywany serwer.",
		"Strona domyślna wskazuje na niedokończoną albo zapomnianą instalację."},
	analyze.FindingNewExposure: {0, "Sprawdź, czy ta usługa ma być dostępna z sieci.", "Nowa usługa w sieci zmienia powierzchnię ataku."},
}

// ToDojoGeneric converts a Czujka finding to a Generic Findings Import finding.
func ToDojoGeneric(f model.Finding) DojoGenericFinding {
	sev, _ := DojoSeverity(f.Severity)
	fl := FlagsOf(f.Status)
	adv := adviceByType[f.Type]
	g := DojoGenericFinding{
		Title: f.Title, Description: DojoDescription(f), Severity: sev, UniqueIDFromTool: f.Key, VulnIDFromTool: f.Type,
		Active: fl.Active, Verified: fl.Verified, FalseP: fl.FalseP, IsMitigated: fl.IsMitigated, DynamicFinding: true,
		References: f.URL, Endpoints: DojoEndpoints(f), Tags: DojoTags(f), CWE: adv.cwe, Mitigation: adv.mitigation, Impact: adv.impact,
	}
	if f.Port != 0 {
		g.Service = strconv.Itoa(f.Port) + "/tcp"
	}
	if !f.FirstSeen.IsZero() {
		g.Date = f.FirstSeen.UTC().Format("2006-01-02")
	}
	return g
}

// WriteDojoGenericJSON writes findings as a DefectDojo Generic Findings
// Import JSON file. The file imports in DefectDojo with scan type
// "Generic Findings Import" (UI: Import Scan Results; API: /import-scan/).
func WriteDojoGenericJSON(w io.Writer, findings []model.Finding) error {
	rep := DojoGenericReport{Name: "Czujka", Type: "Czujka findings", Findings: make([]DojoGenericFinding, 0, len(findings))}
	for _, f := range findings {
		rep.Findings = append(rep.Findings, ToDojoGeneric(f))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// WriteDojoGenericCSV writes findings as a DefectDojo Generic Findings
// Import CSV file. The CSV format of DefectDojo has no column for the
// unique id or the tags, so the key travels in the description
// ("Klucz: ..."), where the importer finds it again.
func WriteDojoGenericCSV(w io.Writer, findings []model.Finding) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(DojoGenericCSVHeader); err != nil {
		return err
	}
	b := func(v bool) string {
		if v {
			return "True"
		}
		return "False"
	}
	for _, f := range findings {
		g := ToDojoGeneric(f)
		date := g.Date
		if date == "" {
			date = time.Now().UTC().Format("2006-01-02")
		}
		// Url is the endpoint by IP address, as in the JSON format; the URL
		// with the host name stays in References.
		u := ""
		if len(g.Endpoints) > 0 {
			u = endpointURI(g.Endpoints[0])
		}
		cwe := ""
		if g.CWE != 0 {
			cwe = strconv.Itoa(g.CWE)
		}
		row := []string{date, g.Title, cwe, u, g.Severity, g.Description, g.Mitigation, g.Impact, g.References,
			b(g.Active), b(g.Verified), b(g.FalseP), b(g.IsMitigated), "False"}
		for i := range row {
			row[i] = guard(row[i]) // CSV injection: a title can come from a scanned page
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func endpointURI(e DojoEndpoint) string {
	host := e.Host
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
		host = "[" + host + "]"
	}
	s := host
	if e.Port != 0 {
		s += ":" + strconv.Itoa(e.Port)
	}
	if e.Protocol != "" {
		s = e.Protocol + "://" + s
	}
	return s + e.Path
}

// FindingsOptions tunes ImportFindings. The zero value auto-detects.
type FindingsOptions struct {
	// Format forces one of the Format* findings formats. Empty: auto-detect.
	Format string
	// Source names where the file came from, for example "defectdojo". It
	// becomes the tag "import:<source>" on every foreign finding. Empty:
	// derived from the format.
	Source string
	// Now is the time of findings that carry no date. Zero: time.Now().
	Now time.Time
}

// FindingsReport is the result of ImportFindings: the detected format, the
// number of findings read and the rows that could not be used, with Polish
// reasons. One bad row never stops the import.
type FindingsReport struct {
	Format   string              `json:"format"`
	Findings int                 `json:"findings"`
	Skipped  int                 `json:"skipped"`
	Invalid  []model.InvalidLine `json:"invalid"`
}

func (r *FindingsReport) invalid(line int, value, reason string) {
	if len(r.Invalid) < MaxInvalidReported {
		if len(value) > 120 {
			value = value[:120]
		}
		r.Invalid = append(r.Invalid, model.InvalidLine{Line: line, Value: value, Reason: reason})
	}
	r.Skipped++
}

// DetectFindings names the findings format of the first bytes of a file, or
// "" when it is none of them.
func DetectFindings(head []byte) string {
	b := bytes.TrimLeft(bytes.TrimPrefix(head, []byte("\xef\xbb\xbf")), " \t\r\n")
	if len(b) == 0 {
		return ""
	}
	switch b[0] {
	case '{':
		switch {
		case reKey("findings").Match(b):
			return FormatDojoGenericJSON
		case reKey("results").Match(b), reKey("title").Match(b):
			return FormatDojoAPIJSON
		}
		return ""
	case '[':
		if reKey("key").Match(b) && reKey("type").Match(b) {
			return FormatCzujkaFindingsJSON
		}
		if reKey("title").Match(b) {
			return FormatDojoAPIJSON
		}
		return ""
	}
	line := b
	if i := bytes.IndexAny(b, "\r\n"); i >= 0 {
		line = b[:i]
	}
	cols := map[string]bool{}
	for _, c := range strings.Split(string(line), ",") {
		cols[strings.Trim(strings.TrimSpace(c), "\"")] = true
	}
	switch {
	case cols["Title"] && cols["Severity"] && cols["Description"] && cols["Date"]:
		return FormatDojoGenericCSV
	case cols["key"] && cols["type"] && cols["title"] && cols["severity"]:
		return FormatCzujkaFindingsCSV
	}
	return ""
}

func reKey(k string) *regexp.Regexp { return regexp.MustCompile(`"` + k + `"\s*:`) }

// ImportFindings reads findings in any supported findings format: DefectDojo
// Generic Findings JSON or CSV, a DefectDojo API findings list, or Czujka's
// own findings export. Each finding gets a stable Key (unique_id_from_tool,
// the Czujka key, or a hash of tool, title and endpoint), and the host and
// port resolved from the endpoint, the URL, the Czujka description or the
// Czujka key. Foreign findings are Manual (the analysis never resolves them)
// and carry the tag "import:<source>". The caller resolves IP to a host id.
func ImportFindings(r io.Reader, opts FindingsOptions) ([]model.Finding, FindingsReport, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	rep := FindingsReport{Invalid: []model.InvalidLine{}}
	format := opts.Format
	if format == "" {
		head, _ := br.Peek(8192)
		format = DetectFindings(head)
		if format == "" {
			if len(bytes.TrimSpace(head)) == 0 {
				return nil, rep, errors.New("plik jest pusty")
			}
			return nil, rep, errors.New("nie rozpoznano formatu obserwacji: oczekiwano DefectDojo Generic Findings (JSON/CSV), listy findings z API DefectDojo albo eksportu obserwacji Czujki")
		}
	}
	rep.Format = format
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	im := findingImporter{rep: &rep, now: now.UTC(), source: opts.Source, keys: map[string]bool{}}
	var err error
	switch format {
	case FormatDojoGenericJSON:
		if im.source == "" {
			im.source = "defectdojo-generic"
		}
		err = im.genericJSON(br)
	case FormatDojoGenericCSV:
		if im.source == "" {
			im.source = "defectdojo-generic"
		}
		err = im.genericCSV(br)
	case FormatDojoAPIJSON:
		if im.source == "" {
			im.source = "defectdojo"
		}
		err = im.apiJSON(br)
	case FormatCzujkaFindingsJSON:
		err = im.czujkaJSON(br)
	case FormatCzujkaFindingsCSV:
		err = im.czujkaCSV(br)
	default:
		err = fmt.Errorf("nieznany format obserwacji: %q", format)
	}
	rep.Findings = len(im.out)
	if im.out == nil {
		im.out = []model.Finding{}
	}
	return im.out, rep, err
}

type findingImporter struct {
	rep    *FindingsReport
	now    time.Time
	source string
	out    []model.Finding
	keys   map[string]bool
}

// rawFinding is the union of the fields of the Generic JSON and of a
// DefectDojo API finding that the importer reads.
type rawFinding struct {
	ID               int64             `json:"id"`
	Title            string            `json:"title"`
	Description      string            `json:"description"`
	Severity         string            `json:"severity"`
	Date             string            `json:"date"`
	CWE              json.RawMessage   `json:"cwe"`
	Mitigation       string            `json:"mitigation"`
	Impact           string            `json:"impact"`
	References       string            `json:"references"`
	Active           *bool             `json:"active"`
	Verified         bool              `json:"verified"`
	FalseP           bool              `json:"false_p"`
	RiskAccepted     bool              `json:"risk_accepted"`
	OutOfScope       bool              `json:"out_of_scope"`
	IsMitigated      bool              `json:"is_mitigated"`
	Duplicate        bool              `json:"duplicate"`
	UniqueIDFromTool string            `json:"unique_id_from_tool"`
	VulnIDFromTool   string            `json:"vuln_id_from_tool"`
	Service          string            `json:"service"`
	Endpoints        []json.RawMessage `json:"endpoints"`
	Tags             []string          `json:"tags"`
	Created          string            `json:"created"`
	LastStatusUpdate string            `json:"last_status_update"`
}

func (im *findingImporter) genericJSON(r io.Reader) error {
	var doc struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return fmt.Errorf("niepoprawny JSON Generic Findings: %v", err)
	}
	for i, raw := range doc.Findings {
		im.raw(i+1, raw, nil)
	}
	return nil
}

func (im *findingImporter) apiJSON(r io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(r, 512<<20))
	if err != nil {
		return err
	}
	var items []json.RawMessage
	prefetch := map[string]DojoEndpoint{}
	trim := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	if len(trim) > 0 && trim[0] == '[' {
		if err := json.Unmarshal(trim, &items); err != nil {
			return fmt.Errorf("niepoprawny JSON z API DefectDojo: %v", err)
		}
	} else {
		var page struct {
			Results  []json.RawMessage `json:"results"`
			Prefetch struct {
				Endpoints map[string]prefetchEndpoint `json:"endpoints"`
			} `json:"prefetch"`
		}
		if err := json.Unmarshal(trim, &page); err != nil {
			return fmt.Errorf("niepoprawny JSON z API DefectDojo: %v", err)
		}
		items = page.Results
		if page.Results == nil {
			items = []json.RawMessage{trim} // one finding object
		}
		for k, v := range page.Prefetch.Endpoints {
			if ep, ok := v.endpoint(); ok {
				prefetch[k] = ep
			}
		}
	}
	for i, raw := range items {
		im.raw(i+1, raw, prefetch)
	}
	return nil
}

// prefetchEndpoint is one entry of "prefetch": {"endpoints": {...}} of the
// findings API. DefectDojo 2.x sends endpoint objects (protocol, host, port,
// path); DefectDojo 3.x sends location references with location_value, a URL.
type prefetchEndpoint struct {
	Protocol      string `json:"protocol"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Path          string `json:"path"`
	LocationValue string `json:"location_value"`
}

func (p prefetchEndpoint) endpoint() (DojoEndpoint, bool) {
	if p.Host != "" {
		return DojoEndpoint{Protocol: p.Protocol, Host: p.Host, Port: p.Port, Path: p.Path}, true
	}
	return parseEndpointURI(p.LocationValue)
}

func (im *findingImporter) raw(n int, raw json.RawMessage, prefetch map[string]DojoEndpoint) {
	var rf rawFinding
	if err := json.Unmarshal(raw, &rf); err != nil {
		im.rep.invalid(n, string(raw), "niepoprawny obiekt obserwacji: "+err.Error())
		return
	}
	var eps []DojoEndpoint
	for _, e := range rf.Endpoints {
		var s string
		if json.Unmarshal(e, &s) == nil {
			if ep, ok := parseEndpointURI(s); ok {
				eps = append(eps, ep)
			}
			continue
		}
		var obj DojoEndpoint
		if json.Unmarshal(e, &obj) == nil && obj.Host != "" {
			eps = append(eps, obj)
			continue
		}
		var id int64
		if json.Unmarshal(e, &id) == nil {
			if ep, ok := prefetch[strconv.FormatInt(id, 10)]; ok {
				eps = append(eps, ep)
			}
		}
	}
	active := true
	if rf.Active != nil {
		active = *rf.Active
	}
	cwe := 0
	if len(rf.CWE) > 0 {
		var c any
		if json.Unmarshal(rf.CWE, &c) == nil {
			switch v := c.(type) {
			case float64:
				cwe = int(v)
			case string:
				cwe, _ = strconv.Atoi(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(v)), "CWE-"))
			}
		}
	}
	in := foreignFinding{
		Title: rf.Title, Description: rf.Description, Severity: rf.Severity, Date: firstNonEmpty(rf.Date, rf.Created),
		CWE: cwe, Mitigation: rf.Mitigation, Impact: rf.Impact, References: rf.References,
		Flags:    DojoFlags{Active: active, Verified: rf.Verified, FalseP: rf.FalseP, RiskAccepted: rf.RiskAccepted, OutOfScope: rf.OutOfScope, IsMitigated: rf.IsMitigated, Duplicate: rf.Duplicate},
		UniqueID: rf.UniqueIDFromTool, VulnID: rf.VulnIDFromTool, Service: rf.Service, Endpoints: eps, Tags: rf.Tags, DojoID: rf.ID,
	}
	im.foreign(n, in, string(raw))
}

// foreignFinding is a finding read from a DefectDojo file, before mapping.
type foreignFinding struct {
	Title, Description, Severity, Date string
	CWE                                int
	Mitigation, Impact, References     string
	Flags                              DojoFlags
	UniqueID, VulnID, Service, URL     string
	Endpoints                          []DojoEndpoint
	Tags                               []string
	DojoID                             int64
}

var (
	reDescHost = regexp.MustCompile(`\*\*Host:\*\*\s*([0-9A-Fa-f:.]+)(?:\s*·\s*\*\*Port:\*\*\s*(\d+))?`)
	reDescKey  = regexp.MustCompile(`Klucz:\s*([^\s_]+)`)
	reKeyAddr  = regexp.MustCompile(`^[a-z0-9-]+/([0-9A-Fa-f:.]+)/(tcp|udp)-(\d+)(?:/|$)`)
	// Exposure-rule findings (internal/rules): policy-violation|<rule>|<ip>[|<port>/<proto>] or |scope.
	reKeyRule = regexp.MustCompile(`^policy-violation\|[^|]+\|(?:scope|([0-9A-Fa-f:.]+)(?:\|(\d+)/(tcp|udp))?)$`)
)

func (im *findingImporter) foreign(n int, in foreignFinding, value string) {
	title := strings.TrimSpace(in.Title)
	if title == "" {
		im.rep.invalid(n, value, "brak tytułu (pole title / Title jest wymagane)")
		return
	}
	sev, ok := SeverityFromDojo(in.Severity)
	if !ok {
		im.rep.invalid(n, value, fmt.Sprintf("nieznana waga %q (dozwolone: Critical, High, Medium, Low, Info)", in.Severity))
		return
	}
	at := im.now
	if d := strings.TrimSpace(in.Date); d != "" {
		t, err := parseFindingTime(d)
		if err != nil {
			im.rep.invalid(n, value, fmt.Sprintf("niepoprawna data %q (oczekiwano RRRR-MM-DD)", d))
			return
		}
		at = t
	}
	f := model.Finding{Title: title, Severity: sev, FirstSeen: at, LastSeen: at, Manual: true, Type: TypeImported,
		Status: StatusFromDojo(in.Flags, containsFold(in.Tags, "accepted"))}
	desc := strings.TrimSpace(in.Description)

	// Host and port: endpoint, URL, the Czujka description, the Czujka key.
	key := strings.TrimSpace(in.UniqueID)
	if key == "" {
		if m := reDescKey.FindStringSubmatch(desc); m != nil {
			key = m[1]
		}
	}
	ownExport := false
	if m := reKeyAddr.FindStringSubmatch(key); m != nil {
		ownExport = true
	}
	ruleKey := reKeyRule.FindStringSubmatch(key)
	if ruleKey != nil {
		ownExport = true
	}
	switch {
	case len(in.Endpoints) > 0:
		e := in.Endpoints[0]
		f.IP, f.Port = e.Host, e.Port
		if e.Protocol == "http" || e.Protocol == "https" {
			f.URL = endpointURI(e)
		}
	case in.URL != "":
		if e, ok := parseEndpointURI(in.URL); ok {
			f.IP, f.Port = e.Host, e.Port
			if e.Protocol == "http" || e.Protocol == "https" {
				f.URL = in.URL
			}
		}
	}
	if _, err := netip.ParseAddr(f.IP); err != nil {
		// No address in the endpoint: a Czujka description names it.
		if m := reDescHost.FindStringSubmatch(desc); m != nil {
			f.IP = m[1]
			f.Port, _ = strconv.Atoi(m[2])
		}
	}
	if f.IP == "" {
		if m := reKeyAddr.FindStringSubmatch(key); m != nil {
			f.IP = m[1]
			f.Port, _ = strconv.Atoi(m[3])
		} else if ruleKey != nil && ruleKey[1] != "" {
			f.IP = ruleKey[1]
			f.Port, _ = strconv.Atoi(ruleKey[2])
		}
	}
	if f.IP == "" {
		im.rep.invalid(n, value, "nie można ustalić hosta: brak endpointu, adresu URL, adresu w opisie i klucza Czujki")
		return
	}
	if a, err := netip.ParseAddr(f.IP); err == nil {
		f.IP = a.Unmap().String()
	} else {
		// A host name: the caller resolves it to an address it knows.
		if f.URL == "" {
			f.URL = "//" + f.IP
			if f.Port != 0 {
				f.URL += ":" + strconv.Itoa(f.Port)
			}
		}
	}
	if f.Port == 0 && in.Service != "" {
		p, _, _ := strings.Cut(in.Service, "/")
		f.Port, _ = strconv.Atoi(p)
	}
	if f.Port < 0 || f.Port > 65535 {
		im.rep.invalid(n, value, fmt.Sprintf("niepoprawny port %d", f.Port))
		return
	}

	if ownExport {
		// A finding Czujka exported earlier: keep its key and type.
		f.Key = key
		f.Type = strings.SplitN(key, "/", 2)[0]
		if ruleKey != nil {
			f.Type = "policy-violation"
		}
		f.Manual = false
		if in.VulnID != "" {
			f.Type = in.VulnID
		}
	} else {
		f.Key = foreignKey(im.source, key, title, f.IP, f.Port)
		if in.VulnID != "" {
			f.Signature = in.VulnID
		}
	}
	if in.DojoID != 0 {
		id := in.DojoID
		f.DojoID = &id
	}
	f.Description = desc
	var extra []string
	if in.CWE > 0 {
		extra = append(extra, fmt.Sprintf("**CWE:** CWE-%d", in.CWE))
	}
	if s := strings.TrimSpace(in.Impact); s != "" {
		extra = append(extra, "**Wpływ:** "+s)
	}
	if s := strings.TrimSpace(in.Mitigation); s != "" {
		extra = append(extra, "**Zalecenia:** "+s)
	}
	if s := strings.TrimSpace(in.References); s != "" && s != f.URL {
		extra = append(extra, "**Odnośniki:** "+s)
	}
	if len(extra) > 0 && !strings.Contains(desc, extra[0]) {
		f.Description = strings.TrimSpace(desc + "\n\n" + strings.Join(extra, "\n\n"))
	}
	f.Tags = cleanTags(in.Tags)
	if !ownExport {
		f.Tags = appendUnique(f.Tags, "import:"+im.source)
	}
	im.add(n, f, value)
}

func (im *findingImporter) add(n int, f model.Finding, value string) {
	if im.keys[f.Key] {
		im.rep.invalid(n, value, "powtórzona obserwacja (ten sam klucz "+f.Key+" wystąpił wcześniej w pliku)")
		return
	}
	im.keys[f.Key] = true
	im.out = append(im.out, f)
}

// foreignKey is the stable key of a foreign finding: the tool's unique id
// when there is one, otherwise a hash of title, host and port. A second
// import of the same file gives the same keys, so the store updates the
// findings instead of adding copies.
func foreignKey(source, uniqueID, title, ip string, port int) string {
	base := uniqueID
	if base == "" {
		base = strings.ToLower(title) + "|" + ip + "|" + strconv.Itoa(port)
	}
	sum := sha256.Sum256([]byte(base))
	return fmt.Sprintf("import/%s/tcp-%d/%s", ip, port, hex.EncodeToString(sum[:])[:16])
}

func cleanTags(in []string) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		if t = strings.TrimSpace(t); t != "" {
			out = appendUnique(out, t)
		}
	}
	return out
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), v) {
			return true
		}
	}
	return false
}

func parseFindingTime(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02", time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "01/02/2006", "02.01.2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("bad date")
}

// parseEndpointURI reads "https://10.0.0.1:8443/x", "10.0.0.1:22" or "host".
func parseEndpointURI(s string) (DojoEndpoint, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return DojoEndpoint{}, false
	}
	if !strings.Contains(s, "://") {
		s = "//" + strings.TrimPrefix(s, "//")
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return DojoEndpoint{}, false
	}
	e := DojoEndpoint{Protocol: u.Scheme, Host: u.Hostname(), Path: u.EscapedPath()}
	if p := u.Port(); p != "" {
		e.Port, _ = strconv.Atoi(p)
	} else {
		switch u.Scheme {
		case "http":
			e.Port = 80
		case "https":
			e.Port = 443
		}
	}
	return e, true
}

func (im *findingImporter) genericCSV(r io.Reader) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	header, err := cr.Read()
	if err != nil {
		return fmt.Errorf("nie można odczytać nagłówka CSV: %v", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(strings.TrimPrefix(h, "\ufeff"))] = i
	}
	for _, need := range []string{"Title", "Description", "Date", "Severity"} {
		if _, ok := col[need]; !ok {
			return fmt.Errorf("brak wymaganej kolumny %q w CSV Generic Findings", need)
		}
	}
	line := 1
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			return nil
		}
		line++
		if err != nil {
			im.rep.invalid(line, "", "niepoprawny wiersz CSV: "+err.Error())
			continue
		}
		get := func(name string) string {
			if i, ok := col[name]; ok && i < len(rec) {
				return unCSVSafe(strings.TrimSpace(rec[i])) // undo the formula guard of WriteDojoGenericCSV
			}
			return ""
		}
		bv := func(name string, def bool) bool {
			v := get(name)
			if v == "" {
				return def
			}
			return strings.HasPrefix(strings.ToLower(v), "t") // DefectDojo's rule
		}
		cwe := 0
		if v := get("CweId"); v != "" {
			if cwe, err = strconv.Atoi(strings.TrimPrefix(strings.ToUpper(v), "CWE-")); err != nil {
				im.rep.invalid(line, strings.Join(rec, ","), fmt.Sprintf("niepoprawny CweId %q (oczekiwano liczby)", v))
				continue
			}
		}
		in := foreignFinding{Title: get("Title"), Description: get("Description"), Severity: get("Severity"), Date: get("Date"),
			CWE: cwe, Mitigation: get("Mitigation"), Impact: get("Impact"), References: get("References"), URL: get("Url"),
			Flags: DojoFlags{Active: bv("Active", true), Verified: bv("Verified", false), FalseP: bv("FalsePositive", false),
				IsMitigated: bv("IsMitigated", false), Duplicate: bv("Duplicate", false)}}
		if in.Date == "" {
			im.rep.invalid(line, strings.Join(rec, ","), "brak daty (kolumna Date jest wymagana przez DefectDojo)")
			continue
		}
		im.foreign(line, in, strings.Join(rec, ","))
	}
}

func (im *findingImporter) czujkaJSON(r io.Reader) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('[') {
		return errors.New("eksport obserwacji Czujki musi być tablicą JSON")
	}
	n := 0
	for dec.More() {
		n++
		var f model.Finding
		if err := dec.Decode(&f); err != nil {
			return fmt.Errorf("obiekt %d: niepoprawny JSON: %v", n, err)
		}
		im.own(n, f, f.Key)
	}
	return nil
}

func (im *findingImporter) czujkaCSV(r io.Reader) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return fmt.Errorf("nie można odczytać nagłówka CSV: %v", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(strings.TrimPrefix(h, "\ufeff"))] = i
	}
	line := 1
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			return nil
		}
		line++
		if err != nil {
			im.rep.invalid(line, "", "niepoprawny wiersz CSV: "+err.Error())
			continue
		}
		get := func(name string) string {
			if i, ok := col[name]; ok && i < len(rec) {
				return unCSVSafe(rec[i])
			}
			return ""
		}
		f := model.Finding{Key: get("key"), Type: get("type"), Title: get("title"), Severity: model.Severity(get("severity")),
			Status: model.FindingStatus(get("status")), IP: get("ip"), URL: get("url"), Signature: get("signature"),
			Assignee: get("assignee"), DojoURL: get("dojo_url"), Description: get("description"), Note: get("note")}
		f.Interest, _ = strconv.Atoi(get("interest"))
		if p := get("port"); p != "" {
			if f.Port, err = strconv.Atoi(p); err != nil {
				im.rep.invalid(line, strings.Join(rec, ","), fmt.Sprintf("niepoprawny port %q", p))
				continue
			}
		}
		f.Tags = strings.Fields(get("tags"))
		f.Manual = get("manual") == "true"
		f.FirstSeen, _ = parseFindingTime(get("first_seen"))
		f.LastSeen, _ = parseFindingTime(get("last_seen"))
		im.own(line, f, strings.Join(rec, ","))
	}
}

// unCSVSafe undoes the formula guard of the API's CSV export ("'=x" -> "=x").
func unCSVSafe(v string) string {
	if len(v) > 1 && v[0] == '\'' && strings.ContainsRune("=+-@\t\r", rune(v[1])) {
		return v[1:]
	}
	return v
}

var validSeverity = map[model.Severity]bool{model.SevInfo: true, model.SevLow: true, model.SevMedium: true, model.SevHigh: true}
var validStatus = map[model.FindingStatus]bool{model.FindingNew: true, model.FindingTriaged: true, model.FindingAccepted: true,
	model.FindingFalsePositive: true, model.FindingResolved: true}

// own checks one finding of Czujka's own export. Store ids are dropped: the
// importing instance resolves the host by IP.
func (im *findingImporter) own(n int, f model.Finding, value string) {
	f.Title = strings.TrimSpace(f.Title)
	switch {
	case f.Title == "":
		im.rep.invalid(n, value, "brak tytułu")
		return
	case !validSeverity[f.Severity]:
		im.rep.invalid(n, value, fmt.Sprintf("nieznana waga %q (dozwolone: info, low, medium, high)", f.Severity))
		return
	case f.Status != "" && !validStatus[f.Status]:
		im.rep.invalid(n, value, fmt.Sprintf("nieznany status %q", f.Status))
		return
	case f.Port < 0 || f.Port > 65535:
		im.rep.invalid(n, value, fmt.Sprintf("niepoprawny port %d", f.Port))
		return
	}
	if f.IP != "" {
		a, err := netip.ParseAddr(f.IP)
		if err != nil {
			im.rep.invalid(n, value, fmt.Sprintf("niepoprawny adres IP %q", f.IP))
			return
		}
		f.IP = a.Unmap().String()
	}
	if f.IP == "" {
		if m := reKeyAddr.FindStringSubmatch(f.Key); m != nil {
			f.IP = m[1]
			f.Port, _ = strconv.Atoi(m[3])
		} else {
			im.rep.invalid(n, value, "brak adresu IP")
			return
		}
	}
	if f.Status == "" {
		f.Status = model.FindingNew
	}
	if f.Type == "" {
		f.Type = "manual"
	}
	if f.Key == "" {
		f.Key = foreignKey("czujka", "", f.Title, f.IP, f.Port)
	}
	if f.FirstSeen.IsZero() {
		f.FirstSeen = im.now
	}
	if f.LastSeen.IsZero() {
		f.LastSeen = f.FirstSeen
	}
	f.ID, f.HostID, f.ServiceID, f.Overrides = 0, 0, nil, nil
	im.add(n, f, value)
}
