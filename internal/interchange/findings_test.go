package interchange

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func sampleFindings() []model.Finding {
	t0 := time.Date(2026, 11, 21, 12, 5, 0, 0, time.UTC)
	return []model.Finding{
		{Key: "admin-panel/10.66.3.17/tcp-8080/jenkins", Type: "admin-panel", Title: "Panel administracyjny: Jenkins (10.66.3.17:8080)",
			Description: "Panel Jenkins jest dostępny.", Severity: model.SevMedium, Status: model.FindingTriaged, Interest: 70, IP: "10.66.3.17",
			Port: 8080, URL: "http://10.66.3.17:8080/", Signature: "jenkins", Tags: []string{"ci"}, FirstSeen: t0, LastSeen: t0,
			Evidence: []model.Evidence{{Matcher: "header", Where: "header:X-Jenkins", Snippet: "2.440.1"}}},
		{Key: "database-exposed/10.66.3.90/tcp-6379", Type: "database-exposed", Title: "Baza danych dostępna z sieci: Redis 7.2.4",
			Severity: model.SevLow, Status: model.FindingFalsePositive, IP: "10.66.3.90", Port: 6379, FirstSeen: t0, LastSeen: t0},
		{Key: "expired-cert/10.66.1.30/tcp-443", Type: "expired-cert", Title: "Przeterminowany certyfikat TLS: poczta.kampus.example",
			Severity: model.SevMedium, Status: model.FindingResolved, IP: "10.66.1.30", Port: 443, URL: "https://poczta.kampus.example/",
			FirstSeen: t0, LastSeen: t0},
	}
}

// dojoAllowed is the allow-list of DefectDojo's Generic JSON parser
// (dojo/tools/generic/json_parser.py, 3.5.202) plus the keys it pops first.
var dojoAllowed = map[string]bool{"title": true, "severity": true, "description": true, "date": true, "cwe": true, "cve": true,
	"epss_score": true, "epss_percentile": true, "cvssv3": true, "cvssv3_score": true, "cvssv4": true, "cvssv4_score": true,
	"mitigation": true, "impact": true, "steps_to_reproduce": true, "severity_justification": true, "references": true, "active": true,
	"verified": true, "false_p": true, "out_of_scope": true, "risk_accepted": true, "under_review": true, "is_mitigated": true,
	"thread_id": true, "mitigated": true, "numerical_severity": true, "param": true, "payload": true, "line": true, "file_path": true,
	"component_name": true, "component_version": true, "static_finding": true, "dynamic_finding": true, "scanner_confidence": true,
	"unique_id_from_tool": true, "vuln_id_from_tool": true, "sast_source_object": true, "sast_sink_object": true,
	"sast_source_line": true, "sast_source_file_path": true, "nb_occurences": true, "publish_date": true, "service": true,
	"planned_remediation_date": true, "planned_remediation_version": true, "effort_for_fixing": true, "tags": true, "kev_date": true,
	"known_exploited": true, "ransomware_used": true, "fix_available": true, "fix_version": true,
	"endpoints": true, "files": true, "vulnerability_ids": true, "cwes": true}

func TestDojoGenericJSONOnlyAllowedKeysAndRoundTrip(t *testing.T) {
	in := sampleFindings()
	var buf bytes.Buffer
	if err := WriteDojoGenericJSON(&buf, in); err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, f := range raw.Findings {
		for k := range f {
			if !dojoAllowed[k] {
				t.Errorf("key %q is not accepted by DefectDojo's Generic parser", k)
			}
		}
	}
	if raw.Findings[0]["cwe"].(float64) != 284 || raw.Findings[0]["severity"] != "Medium" || raw.Findings[0]["verified"] != true {
		t.Errorf("first finding %+v", raw.Findings[0])
	}
	out, rep, err := ImportFindings(bytes.NewReader(buf.Bytes()), FindingsOptions{})
	if err != nil || rep.Format != FormatDojoGenericJSON || len(out) != 3 || rep.Skipped != 0 {
		t.Fatalf("import: %v %+v", err, rep)
	}
	for i, f := range out {
		w := in[i]
		if f.Key != w.Key || f.Type != w.Type || f.IP != w.IP || f.Port != w.Port || f.Severity != w.Severity || f.Status != w.Status || f.Manual {
			t.Errorf("round trip %d: got %+v\nwant %+v", i, f, w)
		}
	}
}

func TestDojoGenericCSVRoundTrip(t *testing.T) {
	in := sampleFindings()
	var buf bytes.Buffer
	if err := WriteDojoGenericCSV(&buf, in); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "Date,Title,CweId,Url,Severity,Description,") {
		t.Fatalf("header: %q", buf.String()[:60])
	}
	out, rep, err := ImportFindings(bytes.NewReader(buf.Bytes()), FindingsOptions{})
	if err != nil || rep.Format != FormatDojoGenericCSV || len(out) != 3 {
		t.Fatalf("import: %v %+v", err, rep)
	}
	for i, f := range out {
		w := in[i]
		// The CSV has no unique id column: the key comes back from "Klucz:" in the description.
		if f.Key != w.Key || f.IP != w.IP || f.Port != w.Port || f.Status != w.Status || f.Severity != w.Severity {
			t.Errorf("round trip %d: got %+v", i, f)
		}
	}
}

func TestImportDojoAPIFindingsOfLiveInstance(t *testing.T) {
	// Saved from GET /api/v2/findings/?test=19&prefetch=endpoints of the lab
	// DefectDojo 3.5.202 after it imported a Czujka Generic JSON file.
	f, err := os.Open("testdata/dojo/api-findings-czujka.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out, rep, err := ImportFindings(f, FindingsOptions{})
	if err != nil || rep.Format != FormatDojoAPIJSON || len(out) != 4 || rep.Skipped != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	got := map[string]model.Finding{}
	for _, x := range out {
		got[x.Key] = x
	}
	r := got["database-exposed/172.31.250.4/tcp-6379"]
	if r.IP != "172.31.250.4" || r.Port != 6379 || r.Severity != model.SevLow || r.Type != "database-exposed" || r.Manual || r.DojoID == nil || *r.DojoID != 70 {
		t.Errorf("redis finding %+v", r)
	}
	if !strings.Contains(r.Description, "**CWE:** CWE-668") || !strings.Contains(r.Description, "**Zalecenia:**") {
		t.Errorf("CWE and mitigation must stay in the description: %q", r.Description)
	}
}

func TestImportForeignFindingsFromDojo(t *testing.T) {
	// A file of another tool, imported into DefectDojo 3.5.202 and read back
	// from its API: endpoints are location references in "prefetch".
	f, err := os.Open("testdata/dojo/api-findings-foreign.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out, rep, err := ImportFindings(f, FindingsOptions{})
	if err != nil || len(out) != 2 {
		t.Fatalf("%v %+v", err, rep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	g := out[0]
	if g.IP != "10.66.5.20" || g.Port != 3000 || g.URL != "https://10.66.5.20:3000/login" || !g.Manual || g.Type != TypeImported ||
		g.Severity != model.SevMedium || !strings.HasPrefix(g.Key, "import/10.66.5.20/tcp-3000/") {
		t.Errorf("grafana %+v", g)
	}
	if g.Tags[len(g.Tags)-1] != "import:defectdojo" {
		t.Errorf("tags %v", g.Tags)
	}
	if out[1].Severity != model.SevHigh { // Critical
		t.Errorf("critical must become high: %s", out[1].Severity)
	}
	// Same file again: same keys, so the store updates instead of copying.
	f2, _ := os.Open("testdata/dojo/api-findings-foreign.json")
	defer f2.Close()
	again, _, _ := ImportFindings(f2, FindingsOptions{})
	sort.Slice(again, func(i, j int) bool { return again[i].IP < again[j].IP })
	if again[0].Key != g.Key {
		t.Error("the key of a foreign finding must be stable")
	}
}

func TestImportGenericForeignFile(t *testing.T) {
	f, err := os.Open("testdata/dojo/generic-foreign.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out, rep, err := ImportFindings(f, FindingsOptions{Source: "nuclei"})
	if err != nil || len(out) != 2 {
		t.Fatalf("%v %+v", err, rep)
	}
	if out[0].Status != model.FindingTriaged || out[1].Port != 22 || out[1].Tags[0] != "import:nuclei" {
		t.Errorf("%+v / %+v", out[0], out[1])
	}
}

func TestImportFindingsInvalidRowsHavePolishReasons(t *testing.T) {
	doc := `{"findings":[
	  {"title":"", "severity":"Low", "description":"x", "endpoints":["10.0.0.1:80"]},
	  {"title":"Bad sev", "severity":"Urgent", "description":"x", "endpoints":["10.0.0.1:80"]},
	  {"title":"Bad date", "severity":"Low", "description":"x", "date":"jutro", "endpoints":["10.0.0.1:80"]},
	  {"title":"No host", "severity":"Low", "description":"x"},
	  {"title":"OK", "severity":"Info", "description":"x", "endpoints":["http://10.0.0.1"]},
	  {"title":"OK", "severity":"Info", "description":"x", "endpoints":["http://10.0.0.1"]}
	]}`
	out, rep, err := ImportFindings(strings.NewReader(doc), FindingsOptions{})
	if err != nil || len(out) != 1 || rep.Skipped != 5 || len(rep.Invalid) != 5 {
		t.Fatalf("%v out=%d %+v", err, len(out), rep)
	}
	want := []string{"brak tytułu", "nieznana waga", "niepoprawna data", "nie można ustalić hosta", "powtórzona obserwacja"}
	for i, w := range want {
		if !strings.Contains(rep.Invalid[i].Reason, w) {
			t.Errorf("row %d reason %q, want %q", rep.Invalid[i].Line, rep.Invalid[i].Reason, w)
		}
	}
	if out[0].Port != 80 {
		t.Errorf("http without a port is 80: %d", out[0].Port)
	}
}

func TestImportCzujkaFindingsExport(t *testing.T) {
	// Exactly the header and the formula guard of GET /api/v1/export/findings.csv.
	csvDoc := "id,key,type,title,severity,status,interest,ip,port,url,signature,tags,assignee,first_seen,last_seen,dojo_url,manual,description,note\n" +
		"12,admin-panel/10.66.3.17/tcp-8080/jenkins,admin-panel,Panel: Jenkins,medium,triaged,70,10.66.3.17,8080,http://10.66.3.17:8080/,jenkins,ci prod,ola,2026-11-21T12:05:00Z,2026-11-21T12:05:00Z,,false,'=cmd jest tekstem,notatka\n" +
		"13,,manual,Ręczna obserwacja,low,new,0,10.66.3.18,0,,,,,,,,true,opis,\n" +
		"14,x,manual,Zła waga,critical,new,0,10.66.3.18,0,,,,,,,,true,,\n"
	out, rep, err := ImportFindings(strings.NewReader(csvDoc), FindingsOptions{})
	if err != nil || rep.Format != FormatCzujkaFindingsCSV || len(out) != 2 || rep.Skipped != 1 {
		t.Fatalf("%v %+v", err, rep)
	}
	j := out[0]
	if j.ID != 0 || j.Key != "admin-panel/10.66.3.17/tcp-8080/jenkins" || j.Status != model.FindingTriaged || j.Description != "=cmd jest tekstem" ||
		strings.Join(j.Tags, ",") != "ci,prod" || j.Assignee != "ola" {
		t.Errorf("jenkins %+v", j)
	}
	if !out[1].Manual || !strings.HasPrefix(out[1].Key, "import/10.66.3.18/") {
		t.Errorf("manual %+v", out[1])
	}
	if !strings.Contains(rep.Invalid[0].Reason, "nieznana waga") {
		t.Errorf("reason %q", rep.Invalid[0].Reason)
	}

	// JSON export: an array of model.Finding.
	js, _ := json.Marshal(sampleFindings())
	out, rep, err = ImportFindings(bytes.NewReader(js), FindingsOptions{})
	if err != nil || rep.Format != FormatCzujkaFindingsJSON || len(out) != 3 || out[1].Status != model.FindingFalsePositive {
		t.Fatalf("%v %+v", err, rep)
	}
}

func TestDetectFindings(t *testing.T) {
	cases := map[string]string{
		`{"findings": []}`:                            FormatDojoGenericJSON,
		`{"count": 1, "results": [{"title": "x"}]}`:   FormatDojoAPIJSON,
		`[{"id":1,"key":"a","type":"b","title":"c"}]`: FormatCzujkaFindingsJSON,
		"Date,Title,CweId,Url,Severity,Description\n": FormatDojoGenericCSV,
		"id,key,type,title,severity,status\n":         FormatCzujkaFindingsCSV,
		"ip,port\n10.0.0.1,80\n":                      "",
		`<?xml version="1.0"?><nmaprun></nmaprun>`:    "",
	}
	for in, want := range cases {
		if got := DetectFindings([]byte(in)); got != want {
			t.Errorf("DetectFindings(%q) = %q, want %q", in, got, want)
		}
	}
	if _, _, err := ImportFindings(strings.NewReader("ip,port\n"), FindingsOptions{}); err == nil || !strings.Contains(err.Error(), "nie rozpoznano") {
		t.Errorf("unknown format: %v", err)
	}
}

func TestStatusMappingBothWays(t *testing.T) {
	for _, st := range []model.FindingStatus{model.FindingNew, model.FindingTriaged, model.FindingFalsePositive, model.FindingResolved} {
		if got := StatusFromDojo(FlagsOf(st), false); got != st {
			t.Errorf("%s -> flags -> %s", st, got)
		}
	}
	if StatusFromDojo(FlagsOf(model.FindingAccepted), true) != model.FindingAccepted {
		t.Error("accepted travels as a tag")
	}
	cases := []struct {
		f    DojoFlags
		want model.FindingStatus
	}{
		{DojoFlags{Active: false, FalseP: true, IsMitigated: true}, model.FindingFalsePositive},
		{DojoFlags{Active: false, RiskAccepted: true}, model.FindingAccepted},
		{DojoFlags{Active: false, OutOfScope: true, IsMitigated: true}, model.FindingAccepted},
		{DojoFlags{Active: false, IsMitigated: true}, model.FindingResolved},
		{DojoFlags{Active: false}, model.FindingResolved},
		{DojoFlags{Active: true, Verified: true}, model.FindingTriaged},
		{DojoFlags{Active: true}, model.FindingNew},
	}
	for _, c := range cases {
		if got := StatusFromDojo(c.f, false); got != c.want {
			t.Errorf("%+v -> %s, want %s", c.f, got, c.want)
		}
	}
}

func TestCSVClassesSplitOnSpaces(t *testing.T) {
	doc := "ip,port,state,classes\n10.0.0.1,80,open,\"admin-panel login;staging,api\"\n"
	hosts, _, err := Import(strings.NewReader(doc), Options{})
	if err != nil || len(hosts) != 1 {
		t.Fatal(err)
	}
	got := strings.Join(hosts[0].Services[0].Classes, ",")
	if got != "admin-panel,login,staging,api" {
		t.Errorf("classes = %q", got)
	}
}
