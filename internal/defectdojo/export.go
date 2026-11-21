package defectdojo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// importBatch is the number of findings in one Generic Findings file.
const importBatch = 500

// FindingRef is where one Czujka finding lives in DefectDojo.
type FindingRef struct {
	ID      int64  `json:"id"`
	URL     string `json:"url"`
	Created bool   `json:"created"` // created by this export
}

// ExportOutcome is the result of ExportFindings. Result goes to the API
// caller; Findings lets the store set Finding.DojoID and Finding.DojoURL.
type ExportOutcome struct {
	Result   model.DojoExportResult
	Location Location
	// Findings maps the Czujka finding key to its DefectDojo finding.
	Findings map[string]FindingRef
	// Patched counts the existing findings whose content differed and was
	// changed. Result.Updated counts every existing finding that the export
	// brought up to date, changed or not.
	Patched int
}

// dojoFinding is the part of a DefectDojo finding the client reads.
type dojoFinding struct {
	ID               int64    `json:"id"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Severity         string   `json:"severity"`
	UniqueIDFromTool string   `json:"unique_id_from_tool"`
	Active           bool     `json:"active"`
	Verified         bool     `json:"verified"`
	FalseP           bool     `json:"false_p"`
	IsMitigated      bool     `json:"is_mitigated"`
	Tags             []string `json:"tags"`
	Endpoints        []int64  `json:"endpoints"`
}

// genericFinding is one finding of the "Generic Findings Import" JSON format.
type genericFinding struct {
	Title            string            `json:"title"`
	Description      string            `json:"description"`
	Severity         string            `json:"severity"`
	Date             string            `json:"date,omitempty"`
	UniqueIDFromTool string            `json:"unique_id_from_tool"`
	VulnIDFromTool   string            `json:"vuln_id_from_tool,omitempty"`
	Active           bool              `json:"active"`
	Verified         bool              `json:"verified"`
	FalseP           bool              `json:"false_p"`
	StaticFinding    bool              `json:"static_finding"`
	DynamicFinding   bool              `json:"dynamic_finding"`
	References       string            `json:"references,omitempty"`
	Endpoints        []genericEndpoint `json:"endpoints,omitempty"`
	Tags             []string          `json:"tags,omitempty"`
}

type genericEndpoint struct {
	Protocol string `json:"protocol,omitempty"`
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Path     string `json:"path,omitempty"`
}

// Severity maps a Czujka severity to DefectDojo's name and numerical code.
func Severity(s model.Severity) (name, numerical string) {
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

// statusFlags maps the analyst's status to DefectDojo's flags.
func statusFlags(st model.FindingStatus) (active, verified, falseP, mitigated bool) {
	switch st {
	case model.FindingTriaged:
		return true, true, false, false
	case model.FindingFalsePositive:
		return false, false, true, false
	case model.FindingResolved:
		return false, false, false, true
	}
	return true, false, false, false // new, accepted
}

// Tags returns the DefectDojo tags of a finding: "czujka", its type and its
// own tags, lower case, without spaces and commas.
func Tags(f model.Finding) []string {
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

// Description builds the Markdown description: the text of the finding, the
// facts, and the evidence. Cookie values and other secrets are never in
// Finding.Evidence, so they cannot reach DefectDojo.
func Description(f model.Finding) string {
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

// endpointOf builds the endpoint of a finding. The host is always the IP
// address, so the endpoint does not change when a name changes.
func endpointOf(f model.Finding) []genericEndpoint {
	if f.IP == "" {
		return nil
	}
	e := genericEndpoint{Host: f.IP, Port: f.Port, Protocol: "tcp"}
	if u, err := url.Parse(f.URL); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		e.Protocol = u.Scheme
	}
	return []genericEndpoint{e}
}

func toGeneric(f model.Finding) genericFinding {
	sev, _ := Severity(f.Severity)
	active, verified, falseP, _ := statusFlags(f.Status)
	g := genericFinding{
		Title: f.Title, Description: Description(f), Severity: sev, UniqueIDFromTool: f.Key, VulnIDFromTool: f.Type,
		Active: active, Verified: verified, FalseP: falseP, DynamicFinding: true, References: f.URL,
		Endpoints: endpointOf(f), Tags: Tags(f),
	}
	if !f.FirstSeen.IsZero() {
		g.Date = f.FirstSeen.UTC().Format("2006-01-02")
	}
	return g
}

// existingFindings reads the findings of a test, keyed by unique_id_from_tool.
// When a key exists more than once (data from another tool or an old
// export), the oldest finding wins.
func (c *Client) existingFindings(ctx context.Context, testID int64) (map[string]dojoFinding, error) {
	items, err := listAll[dojoFinding](ctx, c, "findings/", url.Values{"test": {strconv.FormatInt(testID, 10)}})
	if err != nil {
		return nil, err
	}
	out := make(map[string]dojoFinding, len(items))
	for _, it := range items {
		if it.UniqueIDFromTool == "" {
			continue
		}
		if cur, ok := out[it.UniqueIDFromTool]; !ok || it.ID < cur.ID {
			out[it.UniqueIDFromTool] = it
		}
	}
	return out, nil
}

// ExportFindings sends findings to DefectDojo as findings of the test
// "Czujka findings". A finding that already exists there (same key in
// unique_id_from_tool) is updated in place; a new one is created with its
// endpoint. Findings without a key are counted as failed.
//
// The returned error is not nil only when nothing could be done (no
// connection, no permission). Problems of single findings are in
// Result.Errors and Result.Failed.
func (c *Client) ExportFindings(ctx context.Context, t Target, findings []model.Finding) (ExportOutcome, error) {
	out := ExportOutcome{Findings: map[string]FindingRef{}, Result: model.DojoExportResult{Errors: []string{}}}
	fail := func(format string, args ...any) {
		out.Result.Failed++
		if len(out.Result.Errors) < 50 {
			out.Result.Errors = append(out.Result.Errors, fmt.Sprintf(format, args...))
		}
	}
	loc, err := c.Ensure(ctx, t)
	if err != nil {
		return out, err
	}
	out.Location = loc
	testID, haveTest, err := c.findTest(ctx, loc.EngagementID, FindingsTestTitle)
	if err != nil {
		return out, err
	}
	existing := map[string]dojoFinding{}
	if haveTest {
		if existing, err = c.existingFindings(ctx, testID); err != nil {
			return out, err
		}
	}

	// Split into new and known. A key that repeats in the input is sent once.
	seen := map[string]bool{}
	var fresh, known []model.Finding
	for _, f := range findings {
		switch {
		case strings.TrimSpace(f.Key) == "":
			fail("obserwacja %q nie ma klucza i nie może być wyeksportowana", f.Title)
		case seen[f.Key]:
		default:
			seen[f.Key] = true
			if _, ok := existing[f.Key]; ok {
				known = append(known, f)
			} else {
				fresh = append(fresh, f)
			}
		}
	}

	// Create the new ones through the Generic Findings import.
	for start := 0; start < len(fresh); start += importBatch {
		batch := fresh[start:min(start+importBatch, len(fresh))]
		gen := struct {
			Findings []genericFinding `json:"findings"`
		}{Findings: make([]genericFinding, len(batch))}
		for i, f := range batch {
			gen.Findings[i] = toGeneric(f)
		}
		body, err := json.Marshal(gen)
		if err != nil {
			return out, err
		}
		res, err := c.scanImport(ctx, scanTypeGeneric, loc.EngagementID, testID, FindingsTestTitle, "czujka-findings.json", bytes.NewReader(body), time.Time{},
			map[string]string{"tags": "czujka"})
		if err != nil {
			for range batch {
				out.Result.Failed++
			}
			if len(out.Result.Errors) < 50 {
				out.Result.Errors = append(out.Result.Errors, fmt.Sprintf("import %d obserwacji nie powiódł się: %v", len(batch), err))
			}
			if testID == 0 {
				return out, err // the test does not exist; nothing more can be done
			}
			continue
		}
		testID = res.TestID
	}
	if testID != 0 {
		out.Result.TestID = testID
		out.Result.TestURL = fmt.Sprintf("%s/test/%d", c.base, testID)
	}

	// Read back what DefectDojo holds now: ids for the links and the proof of creation.
	if len(fresh) > 0 && testID != 0 {
		after, err := c.existingFindings(ctx, testID)
		if err != nil {
			return out, err
		}
		for _, f := range fresh {
			df, ok := after[f.Key]
			if !ok {
				fail("DefectDojo nie utworzył obserwacji %s", f.Key)
				continue
			}
			out.Result.Exported++
			out.Findings[f.Key] = FindingRef{ID: df.ID, URL: fmt.Sprintf("%s/finding/%d", c.base, df.ID), Created: true}
			// The import keeps most fields; status flags that the import ignores are set here.
			if patch := diffPatch(f, df, true); len(patch) > 0 {
				if err := c.sendJSON(ctx, http.MethodPatch, fmt.Sprintf("findings/%d/", df.ID), patch, nil); err != nil {
					fail("nie można ustawić statusu obserwacji %s: %v", f.Key, err)
				}
			}
		}
	}

	// Update the known ones in place.
	for _, f := range known {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		df := existing[f.Key]
		ref := FindingRef{ID: df.ID, URL: fmt.Sprintf("%s/finding/%d", c.base, df.ID)}
		if patch := diffPatch(f, df, false); len(patch) > 0 {
			if err := c.sendJSON(ctx, http.MethodPatch, fmt.Sprintf("findings/%d/", df.ID), patch, nil); err != nil {
				fail("nie można zaktualizować obserwacji %s (DefectDojo #%d): %v", f.Key, df.ID, err)
				continue
			}
			out.Patched++
		}
		out.Result.Updated++
		out.Findings[f.Key] = ref
	}
	return out, nil
}

// diffPatch returns the PATCH body that brings a DefectDojo finding in line
// with the Czujka finding. An empty map means "already up to date".
// statusOnly limits the comparison to the status flags (right after an import).
func diffPatch(f model.Finding, df dojoFinding, statusOnly bool) map[string]any {
	patch := map[string]any{}
	active, verified, falseP, mitigated := statusFlags(f.Status)
	if df.Active != active {
		patch["active"] = active
	}
	if df.Verified != verified {
		patch["verified"] = verified
	}
	if df.FalseP != falseP {
		patch["false_p"] = falseP
	}
	if df.IsMitigated != mitigated {
		patch["is_mitigated"] = mitigated
	}
	if statusOnly {
		return patch
	}
	sev, num := Severity(f.Severity)
	if df.Severity != sev {
		patch["severity"] = sev
		patch["numerical_severity"] = num
	}
	// DefectDojo changes the letter case of titles on import; compare without it.
	if !strings.EqualFold(df.Title, f.Title) {
		patch["title"] = f.Title
	}
	if desc := Description(f); strings.TrimSpace(df.Description) != strings.TrimSpace(desc) {
		patch["description"] = desc
	}
	want := Tags(f)
	have := append([]string{}, df.Tags...)
	sort.Strings(have)
	if strings.Join(want, ",") != strings.Join(have, ",") {
		patch["tags"] = want
	}
	return patch
}

// FindingView is a finding as DefectDojo holds it, with its endpoints.
type FindingView struct {
	ID        int64    `json:"id"`
	URL       string   `json:"url"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity"`
	Active    bool     `json:"active"`
	Key       string   `json:"unique_id_from_tool"`
	Tags      []string `json:"tags"`
	Endpoints []string `json:"endpoints"` // for example "http://10.66.3.17:8080"
}

// ListFindings returns the findings of a test with their endpoints resolved.
// It is used to show and to verify what an export created.
//
// DefectDojo 3.x keeps endpoints as "locations": Finding.endpoints holds the
// ids of location references, read from /location_findings. DefectDojo 2.x
// holds endpoint ids, read from /endpoints/{id}. Both are handled.
func (c *Client) ListFindings(ctx context.Context, testID int64) ([]FindingView, error) {
	items, err := listAll[dojoFinding](ctx, c, "findings/", url.Values{"test": {strconv.FormatInt(testID, 10)}})
	if err != nil {
		return nil, err
	}
	type locRef struct {
		ID      int64  `json:"id"`
		Finding int64  `json:"finding"`
		Value   string `json:"location_value"`
	}
	byFinding := map[int64][]string{}
	locations := true
	for _, it := range items {
		if len(it.Endpoints) == 0 {
			continue
		}
		if locations {
			refs, err := listAll[locRef](ctx, c, "location_findings/", url.Values{"finding_equals": {strconv.FormatInt(it.ID, 10)}})
			var apiErr *APIError
			switch {
			case errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound:
				locations = false // DefectDojo 2.x
			case err != nil:
				return nil, err
			default:
				for _, r := range refs {
					if r.Finding == it.ID {
						byFinding[it.ID] = append(byFinding[it.ID], r.Value)
					}
				}
				continue
			}
		}
		for _, id := range it.Endpoints {
			var ep struct {
				Protocol string `json:"protocol"`
				Host     string `json:"host"`
				Port     int    `json:"port"`
			}
			if err := c.get(ctx, fmt.Sprintf("endpoints/%d/", id), nil, &ep); err != nil {
				return nil, err
			}
			v := ep.Host
			if ep.Port != 0 {
				v += ":" + strconv.Itoa(ep.Port)
			}
			if ep.Protocol != "" {
				v = ep.Protocol + "://" + v
			}
			byFinding[it.ID] = append(byFinding[it.ID], v)
		}
	}
	out := make([]FindingView, 0, len(items))
	for _, it := range items {
		eps := byFinding[it.ID]
		if eps == nil {
			eps = []string{}
		}
		sort.Strings(eps)
		out = append(out, FindingView{ID: it.ID, URL: fmt.Sprintf("%s/finding/%d", c.base, it.ID), Title: it.Title, Severity: it.Severity,
			Active: it.Active, Key: it.UniqueIDFromTool, Tags: it.Tags, Endpoints: eps})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
