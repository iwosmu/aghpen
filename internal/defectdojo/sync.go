package defectdojo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/interchange"
	"github.com/iwosmu/aghpen/internal/model"
)

// ---------- (a) status pull ----------

// RemoteStatus is the state of one exported finding in DefectDojo.
type RemoteStatus struct {
	DojoID    int64                 `json:"dojo_id"`
	Key       string                `json:"key"` // unique_id_from_tool
	Flags     interchange.DojoFlags `json:"flags"`
	Tags      []string              `json:"tags"`
	ChangedAt time.Time             `json:"changed_at"` // last_status_update, or mitigated, or created
	Status    model.FindingStatus   `json:"status"`     // interchange.StatusFromDojo of Flags
	Missing   bool                  `json:"missing"`    // DefectDojo answered 404: the finding was deleted there
}

// LocalStatus is one Czujka finding and the time of the analyst's last status
// edit (from the audit log). A zero ChangedAt means "not known".
type LocalStatus struct {
	Finding   model.Finding
	ChangedAt time.Time
}

// StatusUpdate is a proposed change of one Czujka finding status. Nothing is
// written: the caller shows the list or applies it.
type StatusUpdate struct {
	FindingID   int64               `json:"finding_id"`
	Key         string              `json:"key"`
	DojoID      int64               `json:"dojo_id"`
	From        model.FindingStatus `json:"from"`
	To          model.FindingStatus `json:"to"`
	DojoChanged time.Time           `json:"dojo_changed_at"`
	Reason      string              `json:"reason"` // Polish
}

// StatusConflict is a finding whose status differs, where the analyst's edit
// in Czujka wins and nothing is proposed.
type StatusConflict struct {
	FindingID int64               `json:"finding_id"`
	Key       string              `json:"key"`
	DojoID    int64               `json:"dojo_id"`
	Local     model.FindingStatus `json:"local"`
	Remote    model.FindingStatus `json:"remote"`
	Reason    string              `json:"reason"`
}

// StatusPull is the answer of PullStatus.
type StatusPull struct {
	Checked   int              `json:"checked"`
	Updates   []StatusUpdate   `json:"updates"`
	Conflicts []StatusConflict `json:"conflicts"`
	Missing   []int64          `json:"missing"` // Czujka finding ids whose DefectDojo finding no longer exists
	Errors    []string         `json:"errors"`
}

// analystStatus is true for the statuses only an analyst sets. new and
// resolved are set by the scanner and the analysis.
func analystStatus(s model.FindingStatus) bool {
	return s == model.FindingTriaged || s == model.FindingAccepted || s == model.FindingFalsePositive
}

// ProposeStatusUpdates compares the Czujka status of exported findings with
// their DefectDojo state (the mapping table is interchange.StatusFromDojo):
//
//   - same status: nothing;
//   - Czujka status is new or resolved (set by the scanner, not by an
//     analyst): DefectDojo wins, an update is proposed;
//   - Czujka status was set by an analyst: DefectDojo wins only when its
//     status change (last_status_update) is newer than the analyst's edit
//     (LocalStatus.ChangedAt, also Overrides["status"].At); with no known
//     edit time the analyst wins and the finding is listed as a conflict;
//   - DefectDojo "active, not verified" (= new) never replaces a decision of
//     an analyst: it carries no decision.
func ProposeStatusUpdates(local []LocalStatus, remote map[int64]RemoteStatus) StatusPull {
	out := StatusPull{Updates: []StatusUpdate{}, Conflicts: []StatusConflict{}, Missing: []int64{}, Errors: []string{}}
	for _, l := range local {
		f := l.Finding
		if f.DojoID == nil {
			continue
		}
		r, ok := remote[*f.DojoID]
		if !ok {
			continue
		}
		out.Checked++
		if r.Missing {
			out.Missing = append(out.Missing, f.ID)
			continue
		}
		to := r.Status
		if to == "" {
			to = interchange.StatusFromDojo(r.Flags, containsFold(r.Tags, "accepted"))
		}
		from := f.Status
		if from == "" {
			from = model.FindingNew
		}
		if to == from {
			continue
		}
		edited := l.ChangedAt
		if o, ok := f.Overrides["status"]; ok && o.At.After(edited) {
			edited = o.At
		}
		up := StatusUpdate{FindingID: f.ID, Key: f.Key, DojoID: r.DojoID, From: from, To: to, DojoChanged: r.ChangedAt}
		conflict := func(reason string) {
			out.Conflicts = append(out.Conflicts, StatusConflict{FindingID: f.ID, Key: f.Key, DojoID: r.DojoID, Local: from, Remote: to, Reason: reason})
		}
		switch {
		case !analystStatus(from):
			up.Reason = fmt.Sprintf("DefectDojo: %s; w Czujce status ustawił skaner (%s)", dojoLabel(r.Flags), from)
		case to == model.FindingNew:
			conflict("DefectDojo ma stan domyślny (aktywna, niezweryfikowana); decyzja analityka w Czujce zostaje")
			continue
		case edited.IsZero():
			conflict("nie wiadomo, kiedy analityk zmienił status w Czujce; decyzja analityka zostaje")
			continue
		case !r.ChangedAt.After(edited):
			conflict(fmt.Sprintf("edycja w Czujce (%s) jest nowsza niż zmiana w DefectDojo (%s)", edited.UTC().Format(time.RFC3339), r.ChangedAt.UTC().Format(time.RFC3339)))
			continue
		default:
			up.Reason = fmt.Sprintf("DefectDojo: %s, zmiana %s jest nowsza niż edycja w Czujce (%s)", dojoLabel(r.Flags),
				r.ChangedAt.UTC().Format(time.RFC3339), edited.UTC().Format(time.RFC3339))
		}
		out.Updates = append(out.Updates, up)
	}
	sort.SliceStable(out.Updates, func(i, j int) bool { return out.Updates[i].FindingID < out.Updates[j].FindingID })
	return out
}

func dojoLabel(f interchange.DojoFlags) string {
	var parts []string
	add := func(on bool, s string) {
		if on {
			parts = append(parts, s)
		}
	}
	add(f.Active, "aktywna")
	add(!f.Active, "nieaktywna")
	add(f.Verified, "zweryfikowana")
	add(f.FalseP, "fałszywy alarm")
	add(f.RiskAccepted, "ryzyko zaakceptowane")
	add(f.OutOfScope, "poza zakresem")
	add(f.IsMitigated, "usunięta (mitigated)")
	return strings.Join(parts, ", ")
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), v) {
			return true
		}
	}
	return false
}

// dojoStatusFinding is the part of a DefectDojo finding the status pull reads.
type dojoStatusFinding struct {
	ID               int64    `json:"id"`
	UniqueIDFromTool string   `json:"unique_id_from_tool"`
	Active           bool     `json:"active"`
	Verified         bool     `json:"verified"`
	FalseP           bool     `json:"false_p"`
	RiskAccepted     bool     `json:"risk_accepted"`
	IsMitigated      bool     `json:"is_mitigated"`
	OutOfScope       bool     `json:"out_of_scope"`
	Duplicate        bool     `json:"duplicate"`
	Tags             []string `json:"tags"`
	LastStatusUpdate string   `json:"last_status_update"`
	Mitigated        string   `json:"mitigated"`
	Created          string   `json:"created"`
}

func (d dojoStatusFinding) remote() RemoteStatus {
	r := RemoteStatus{DojoID: d.ID, Key: d.UniqueIDFromTool, Tags: d.Tags,
		Flags: interchange.DojoFlags{Active: d.Active, Verified: d.Verified, FalseP: d.FalseP, RiskAccepted: d.RiskAccepted,
			IsMitigated: d.IsMitigated, OutOfScope: d.OutOfScope, Duplicate: d.Duplicate}}
	for _, s := range []string{d.LastStatusUpdate, d.Mitigated, d.Created} {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			r.ChangedAt = t.UTC()
			break
		}
	}
	r.Status = interchange.StatusFromDojo(r.Flags, containsFold(d.Tags, "accepted"))
	return r
}

// RemoteStatuses reads the state of DefectDojo findings by id (GET only).
// A deleted finding comes back with Missing set.
func (c *Client) RemoteStatuses(ctx context.Context, ids []int64) (map[int64]RemoteStatus, []string) {
	out := make(map[int64]RemoteStatus, len(ids))
	var errs []string
	seen := map[int64]bool{}
	for _, id := range ids {
		if id == 0 || seen[id] {
			continue
		}
		seen[id] = true
		if err := ctx.Err(); err != nil {
			errs = append(errs, err.Error())
			break
		}
		var d dojoStatusFinding
		err := c.get(ctx, fmt.Sprintf("findings/%d/", id), nil, &d)
		var apiErr *APIError
		switch {
		case errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound:
			out[id] = RemoteStatus{DojoID: id, Missing: true}
		case err != nil:
			if len(errs) < 50 {
				errs = append(errs, fmt.Sprintf("odczyt znaleziska DefectDojo #%d: %v", id, err))
			}
		default:
			out[id] = d.remote()
		}
	}
	return out, errs
}

// PullStatus reads the DefectDojo state of exported findings (those with a
// DojoID) and returns the proposed Czujka status updates. It only reads from
// DefectDojo and writes nowhere.
func (c *Client) PullStatus(ctx context.Context, local []LocalStatus) (StatusPull, error) {
	ids := make([]int64, 0, len(local))
	for _, l := range local {
		if l.Finding.DojoID != nil {
			ids = append(ids, *l.Finding.DojoID)
		}
	}
	remote, errs := c.RemoteStatuses(ctx, ids)
	out := ProposeStatusUpdates(local, remote)
	out.Errors = append(out.Errors, errs...)
	if len(ids) > 0 && len(remote) == 0 && len(errs) > 0 {
		return out, errors.New(errs[0])
	}
	return out, nil
}

// ---------- (b) close resolved, reopen observed ----------

// LifecycleResult is the answer of SyncLifecycle.
type LifecycleResult struct {
	Closed   int      `json:"closed"`   // marked mitigated in DefectDojo
	Reopened int      `json:"reopened"` // active again in DefectDojo
	Skipped  int      `json:"skipped"`  // already in the right state, or not exported
	Errors   []string `json:"errors"`
}

// SyncLifecycle follows the life of exported findings in DefectDojo:
//
//   - a Czujka finding with status resolved (no longer observed) whose
//     DefectDojo finding is still open is closed: is_mitigated = true,
//     active = false (DefectDojo stamps the mitigated time), plus a note;
//   - a Czujka finding observed again (status new or triaged) whose
//     DefectDojo finding is mitigated is reopened: active = true,
//     is_mitigated = false, plus a note.
//
// False positive, risk accepted and out of scope in DefectDojo are never
// reopened: they are decisions of an analyst there.
func (c *Client) SyncLifecycle(ctx context.Context, findings []model.Finding, now time.Time) (LifecycleResult, error) {
	res := LifecycleResult{Errors: []string{}}
	if now.IsZero() {
		now = time.Now()
	}
	ids := make([]int64, 0, len(findings))
	for _, f := range findings {
		if f.DojoID != nil {
			ids = append(ids, *f.DojoID)
		}
	}
	remote, errs := c.RemoteStatuses(ctx, ids)
	res.Errors = append(res.Errors, errs...)
	if len(ids) > 0 && len(remote) == 0 && len(errs) > 0 {
		return res, errors.New(errs[0])
	}
	for _, f := range findings {
		if f.DojoID == nil {
			res.Skipped++
			continue
		}
		r, ok := remote[*f.DojoID]
		if !ok || r.Missing {
			res.Skipped++
			continue
		}
		decided := r.Flags.FalseP || r.Flags.RiskAccepted || r.Flags.OutOfScope
		switch {
		case f.Status == model.FindingResolved && !r.Flags.IsMitigated && !decided:
			// DefectDojo sets the mitigated time itself; editing it is refused
			// unless EDITABLE_MITIGATED_DATA is on (checked on 3.5.202).
			patch := map[string]any{"is_mitigated": true, "active": false}
			note := fmt.Sprintf("Czujka: znalezisko %s zniknęło (ostatnia obserwacja %s, skan #%d). Zamknięte.",
				f.Key, f.LastSeen.UTC().Format("2006-01-02 15:04 UTC"), f.LastRunID)
			if err := c.lifecycle(ctx, *f.DojoID, patch, note); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("zamknięcie znaleziska DefectDojo #%d: %v", *f.DojoID, err))
				continue
			}
			res.Closed++
		case (f.Status == model.FindingNew || f.Status == model.FindingTriaged) && r.Flags.IsMitigated && !decided:
			patch := map[string]any{"is_mitigated": false, "active": true}
			note := fmt.Sprintf("Czujka: znalezisko %s wróciło (skan #%d, %s). Otwarte ponownie.",
				f.Key, f.LastRunID, f.LastSeen.UTC().Format("2006-01-02 15:04 UTC"))
			if err := c.lifecycle(ctx, *f.DojoID, patch, note); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("ponowne otwarcie znaleziska DefectDojo #%d: %v", *f.DojoID, err))
				continue
			}
			res.Reopened++
		default:
			res.Skipped++
		}
	}
	return res, nil
}

func (c *Client) lifecycle(ctx context.Context, id int64, patch map[string]any, note string) error {
	if err := c.sendJSON(ctx, http.MethodPatch, fmt.Sprintf("findings/%d/", id), patch, nil); err != nil {
		return err
	}
	return c.AddNote(ctx, id, note)
}

// AddNote adds a public note to a DefectDojo finding.
func (c *Client) AddNote(ctx context.Context, findingID int64, text string) error {
	return c.sendJSON(ctx, http.MethodPost, fmt.Sprintf("findings/%d/notes/", findingID), map[string]any{"entry": text, "private": false}, nil)
}

// ---------- (c) per-scope product and engagement ----------

// ScopeMapping sends the findings of one Czujka scope to its own product and
// engagement. Empty names fall back to the default Target.
type ScopeMapping struct {
	ScopeID         int64  `json:"scope_id"`
	ScopeName       string `json:"scope_name"`
	ProductTypeName string `json:"product_type_name"`
	ProductName     string `json:"product_name"`
	EngagementName  string `json:"engagement_name"`
}

// TargetFor returns the DefectDojo target of a finding in the given scopes:
// the first mapping (in the order of maps) that names one of the scopes, with
// its empty names taken from def. No mapping: def.
func TargetFor(scopeIDs []int64, maps []ScopeMapping, def Target) Target {
	for _, m := range maps {
		for _, id := range scopeIDs {
			if id == m.ScopeID {
				t := def
				if s := strings.TrimSpace(m.ProductTypeName); s != "" {
					t.ProductTypeName = s
				}
				if s := strings.TrimSpace(m.ProductName); s != "" {
					t.ProductName = s
				}
				if s := strings.TrimSpace(m.EngagementName); s != "" {
					t.EngagementName = s
				}
				return t
			}
		}
	}
	return def
}

// GroupByTarget splits findings by their DefectDojo target. scopesOf returns
// the scope ids of a finding's host. The caller exports each group with
// ExportFindings.
func GroupByTarget(findings []model.Finding, scopesOf func(model.Finding) []int64, maps []ScopeMapping, def Target) map[Target][]model.Finding {
	out := map[Target][]model.Finding{}
	for _, f := range findings {
		var ids []int64
		if scopesOf != nil {
			ids = scopesOf(f)
		}
		t := TargetFor(ids, maps, def)
		out[t] = append(out[t], f)
	}
	return out
}

// ---------- (d) evidence files ----------

// AttachFile uploads a file to a DefectDojo test ("tests") or finding
// ("findings") through POST /api/v2/{kind}/{id}/files/ (multipart: title,
// file). DefectDojo 2.x and 3.x have this route.
func (c *Client) AttachFile(ctx context.Context, kind string, id int64, title, fileName string, data []byte) error {
	if kind != "tests" && kind != "findings" {
		return fmt.Errorf("defectdojo: files attach to tests or findings, not %q", kind)
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("title", title); err != nil {
		return err
	}
	fw, err := mw.CreateFormFile("file", fileName)
	if err != nil {
		return err
	}
	if _, err := fw.Write(data); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, fmt.Sprintf("%s/%d/files/", kind, id), nil, &buf, mw.FormDataContentType(), nil)
}

// EvidenceText is the small evidence file of a finding: the facts and the
// evidence lines, plain text. Cookie values are never in Finding.Evidence.
func EvidenceText(f model.Finding) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "Czujka – dowody znaleziska\n\nKlucz: %s\nTytuł: %s\nTyp: %s\nHost: %s\n", f.Key, f.Title, f.Type, f.IP)
	if f.Port != 0 {
		fmt.Fprintf(&b, "Port: %d\n", f.Port)
	}
	if f.URL != "" {
		fmt.Fprintf(&b, "URL: %s\n", f.URL)
	}
	if !f.FirstSeen.IsZero() {
		fmt.Fprintf(&b, "Pierwsza obserwacja: %s\nOstatnia obserwacja: %s (skan #%d)\n", f.FirstSeen.UTC().Format(time.RFC3339),
			f.LastSeen.UTC().Format(time.RFC3339), f.LastRunID)
	}
	if f.Signature != "" {
		fmt.Fprintf(&b, "Sygnatura: %s\n", f.Signature)
	}
	b.WriteString("\nDowody:\n")
	for _, e := range f.Evidence {
		fmt.Fprintf(&b, "- [%s] %s: %s\n", e.Matcher, e.Where, e.Snippet)
	}
	return []byte(b.String())
}

// AttachEvidence uploads EvidenceText of each exported finding (DojoID set)
// to its DefectDojo finding. It returns the number of files uploaded.
func (c *Client) AttachEvidence(ctx context.Context, findings []model.Finding) (int, []string) {
	n := 0
	var errs []string
	for _, f := range findings {
		if f.DojoID == nil {
			continue
		}
		name := "czujka-evidence-" + safeName(f.Key) + ".txt"
		if err := c.AttachFile(ctx, "findings", *f.DojoID, "Czujka: dowody "+f.Key, name, EvidenceText(f)); err != nil {
			errs = append(errs, fmt.Sprintf("załącznik do znaleziska DefectDojo #%d: %v", *f.DojoID, err))
			continue
		}
		n++
	}
	return n, errs
}

// AttachRunXML uploads the nmap XML of a run to a DefectDojo test.
func (c *Client) AttachRunXML(ctx context.Context, testID, runID int64, xml []byte) error {
	return c.AttachFile(ctx, "tests", testID, fmt.Sprintf("Czujka: nmap XML skanu #%d", runID), fmt.Sprintf("czujka-run-%d.xml", runID), xml)
}

func safeName(s string) string {
	b := []byte(s)
	for i, ch := range b {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '.') {
			b[i] = '_'
		}
	}
	if len(b) > 80 {
		b = b[:80]
	}
	return string(b)
}
