package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// ---------- changes ----------

const changeCols = `c.id, c.run_id, c.prev_run_id, c.at, c.kind, c.severity, c.host_id, COALESCE(host(c.ip), '') AS ip, c.service_id, c.port,
  c.summary, c.field, c.before, c.after, c.expected, c.acked_by, c.acked_at`

// ChangeFilter are the filters of GET /changes.
type ChangeFilter struct {
	ListOpts
	RunID    int64
	Kind     []string
	Severity []string
	HostID   int64
	Acked    *bool
	Expected *bool
	From, To *time.Time
}

func (f ChangeFilter) where() *where {
	w := &where{}
	if f.RunID != 0 {
		w.add("c.run_id = ?", f.RunID)
	}
	if len(f.Kind) > 0 {
		w.add("c.kind = ANY(?)", f.Kind)
	}
	if len(f.Severity) > 0 {
		w.add("c.severity = ANY(?)", f.Severity)
	}
	if f.HostID != 0 {
		w.add("c.host_id = ?", f.HostID)
	}
	if f.Acked != nil {
		if *f.Acked {
			w.add("c.acked_at IS NOT NULL")
		} else {
			w.add("c.acked_at IS NULL")
		}
	}
	if f.Expected != nil {
		w.add("c.expected = ?", *f.Expected)
	}
	if f.From != nil {
		w.add("c.at >= ?", *f.From)
	}
	if f.To != nil {
		w.add("c.at <= ?", *f.To)
	}
	if f.Q != "" {
		w.add("c.summary ILIKE ? OR host(c.ip) ILIKE ? OR c.field ILIKE ?", like(f.Q), like(f.Q), like(f.Q))
	}
	return w
}

var changeSort = map[string]string{"id": "c.id", "at": "c.at", "kind": "c.kind", "severity": "c.severity", "ip": "c.ip", "port": "c.port", "run_id": "c.run_id"}

// ListChanges returns a page of changes, newest first by default.
func (s *Store) ListChanges(ctx context.Context, f ChangeFilter) (model.Page[model.Change], error) {
	return listPage[model.Change](ctx, s.db, changeCols, "changes c", f.where(), orderBy(f.Sort, changeSort, "c.at DESC", "c.id DESC"), f.ListOpts, nil)
}

// EachChange streams every change that matches the filter.
func (s *Store) EachChange(ctx context.Context, f ChangeFilter, fn func(*model.Change) error) error {
	return streamAll[model.Change](ctx, s.db, changeCols, "changes c", f.where(), orderBy(f.Sort, changeSort, "c.at DESC", "c.id DESC"), nil, fn)
}

// InsertChanges stores the changes that the analysis found, in one statement.
func (s *Store) InsertChanges(ctx context.Context, changes []model.Change) error {
	if len(changes) == 0 {
		return nil
	}
	now := time.Now().UTC()
	type in struct {
		model.Change
		IPAddr *string `json:"ip_addr"`
	}
	rows := make([]in, 0, len(changes))
	for _, c := range changes {
		if c.At.IsZero() {
			c.At = now
		}
		if c.Severity == "" {
			c.Severity = model.SevInfo
		}
		r := in{Change: c}
		if c.IP != "" {
			ip := c.IP
			r.IPAddr = &ip
		}
		rows = append(rows, r)
	}
	_, err := s.db.Exec(ctx, `INSERT INTO changes (run_id, prev_run_id, at, kind, severity, host_id, ip, service_id, port, summary, field, before, after, expected)
		SELECT d.run_id, d.prev_run_id, d.at, d.kind, d.severity, d.host_id, d.ip_addr, d.service_id, d.port, d.summary, d.field, d.before, d.after, d.expected
		FROM jsonb_to_recordset($1::jsonb) AS d(run_id bigint, prev_run_id bigint, at timestamptz, kind text, severity text, host_id bigint, ip_addr inet,
			service_id bigint, port int, summary text, field text, before jsonb, after jsonb, expected boolean)`, js(rows))
	return mapErr(err)
}

// DeleteRunChanges removes the changes of one run (before the analysis of that run is repeated).
func (s *Store) DeleteRunChanges(ctx context.Context, runID int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM changes WHERE run_id = $1`, runID)
	return err
}

// AckChanges marks changes as acknowledged and returns how many rows changed.
func (s *Store) AckChanges(ctx context.Context, ids []int64, by string) (int, error) {
	tag, err := s.db.Exec(ctx, `UPDATE changes SET acked_by = $2, acked_at = now() WHERE id = ANY($1) AND acked_at IS NULL`, ids, by)
	return int(tag.RowsAffected()), mapErr(err)
}

// GetChange returns one change.
func (s *Store) GetChange(ctx context.Context, id int64) (model.Change, error) {
	return jsonRow[model.Change](ctx, s.db, wrapJSON("SELECT "+changeCols+" FROM changes c WHERE c.id = $1"), id)
}

// ---------- findings ----------

const findingCols = `f.id, f.key, f.type, f.title, f.description, f.severity, f.status, f.interest, f.host_id, COALESCE(host(f.ip), '') AS ip,
  f.service_id, f.port, f.url, f.signature, f.evidence_enc, f.note_enc AS note, f.tags, f.assignee, f.first_seen, f.last_seen,
  f.first_run_id, f.last_run_id, f.overrides, f.dojo_id, f.dojo_url, f.manual`

type findingRow struct {
	model.Finding
	EvidenceEnc string `json:"evidence_enc"`
}

// FindingFilter are the filters of GET /findings.
type FindingFilter struct {
	ListOpts
	Status      []string
	Severity    []string
	Type        string
	HostID      int64
	ServiceID   int64
	Tag         string
	MinInterest int
	Exported    *bool
	IDs         []int64
	FirstRunID  int64
	LastRunID   int64
	HostIDs     []int64
}

func (f FindingFilter) where() *where {
	w := &where{}
	if len(f.Status) > 0 {
		w.add("f.status = ANY(?)", f.Status)
	}
	if len(f.Severity) > 0 {
		w.add("f.severity = ANY(?)", f.Severity)
	}
	if f.Type != "" {
		w.add("f.type = ?", f.Type)
	}
	if f.HostID != 0 {
		w.add("f.host_id = ?", f.HostID)
	}
	if f.ServiceID != 0 {
		w.add("f.service_id = ?", f.ServiceID)
	}
	if f.Tag != "" {
		w.add("f.tags @> ARRAY[?]::text[]", f.Tag)
	}
	if f.MinInterest > 0 {
		w.add("f.interest >= ?", f.MinInterest)
	}
	if f.Exported != nil {
		if *f.Exported {
			w.add("f.dojo_id IS NOT NULL")
		} else {
			w.add("f.dojo_id IS NULL")
		}
	}
	if len(f.IDs) > 0 {
		w.add("f.id = ANY(?)", f.IDs)
	}
	if f.FirstRunID != 0 {
		w.add("f.first_run_id = ?", f.FirstRunID)
	}
	if f.LastRunID != 0 {
		w.add("f.last_run_id = ?", f.LastRunID)
	}
	if len(f.HostIDs) > 0 {
		w.add("f.host_id = ANY(?)", f.HostIDs)
	}
	if f.Q != "" {
		q := like(f.Q)
		w.add("f.title ILIKE ? OR f.description ILIKE ? OR host(f.ip) ILIKE ? OR f.url ILIKE ? OR f.signature ILIKE ? OR f.type ILIKE ?", q, q, q, q, q, q)
	}
	return w
}

var findingSort = map[string]string{"id": "f.id", "interest": "f.interest", "status": "f.status", "type": "f.type", "title": "f.title",
	"first_seen": "f.first_seen", "last_seen": "f.last_seen", "ip": "f.ip", "port": "f.port",
	"severity": "(CASE f.severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)"}

func (s *Store) postFinding(r *findingRow) error {
	note, err := s.kr.DecryptString(r.Note, "findings|note|"+strconv.FormatInt(r.ID, 10))
	if err != nil {
		return err
	}
	r.Note = note
	r.Evidence = []model.Evidence{}
	if r.EvidenceEnc != "" {
		raw, err := s.kr.Decrypt(r.EvidenceEnc, "findings|evidence|"+r.Key)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &r.Evidence); err != nil {
			return err
		}
	}
	return nil
}

// ListFindings returns a page of findings, most interesting first by default.
func (s *Store) ListFindings(ctx context.Context, f FindingFilter) (model.Page[model.Finding], error) {
	page, err := listPage[findingRow](ctx, s.db, findingCols, "findings f", f.where(), orderBy(f.Sort, findingSort, "f.interest DESC", "f.id DESC"), f.ListOpts, s.postFinding)
	out := model.Page[model.Finding]{Items: make([]model.Finding, 0, len(page.Items)), Total: page.Total, Limit: page.Limit, Offset: page.Offset}
	for _, r := range page.Items {
		out.Items = append(out.Items, r.Finding)
	}
	return out, err
}

// EachFinding streams every finding that matches the filter.
func (s *Store) EachFinding(ctx context.Context, f FindingFilter, fn func(*model.Finding) error) error {
	return streamAll[findingRow](ctx, s.db, findingCols, "findings f", f.where(), orderBy(f.Sort, findingSort, "f.interest DESC", "f.id DESC"), s.postFinding,
		func(r *findingRow) error { return fn(&r.Finding) })
}

// GetFinding returns one finding.
func (s *Store) GetFinding(ctx context.Context, id int64) (model.Finding, error) {
	r, err := jsonRow[findingRow](ctx, s.db, wrapJSON("SELECT "+findingCols+" FROM findings f WHERE f.id = $1"), id)
	if err != nil {
		return r.Finding, err
	}
	return r.Finding, s.postFinding(&r)
}

type findingIn struct {
	Key         string    `json:"key"`
	Type        string    `json:"type"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Interest    int       `json:"interest"`
	HostID      int64     `json:"host_id"`
	IP          *string   `json:"ip"`
	ServiceID   *int64    `json:"service_id"`
	Port        int       `json:"port"`
	URL         string    `json:"url"`
	Signature   string    `json:"signature"`
	EvidenceEnc string    `json:"evidence_enc"`
	Tags        []string  `json:"tags"`
	Assignee    string    `json:"assignee"`
	At          time.Time `json:"at"`
	RunID       int64     `json:"run_id"`
	Manual      bool      `json:"manual"`
}

func (s *Store) toFindingIn(f model.Finding, now time.Time) (findingIn, error) {
	if f.Key == "" {
		return findingIn{}, fmt.Errorf("%w: finding without key", ErrInvalid)
	}
	in := findingIn{Key: f.Key, Type: f.Type, Title: f.Title, Description: f.Description, Severity: string(f.Severity), Status: string(f.Status),
		Interest: f.Interest, HostID: f.HostID, ServiceID: f.ServiceID, Port: f.Port, URL: f.URL, Signature: f.Signature, Tags: nonNil(f.Tags),
		Assignee: f.Assignee, At: f.LastSeen, RunID: f.LastRunID, Manual: f.Manual}
	if in.Severity == "" {
		in.Severity = string(model.SevInfo)
	}
	if in.Status == "" {
		in.Status = string(model.FindingNew)
	}
	if in.At.IsZero() {
		in.At = now
	}
	if f.IP != "" {
		ip := f.IP
		in.IP = &ip
	}
	if len(f.Evidence) > 0 {
		enc, err := s.kr.Encrypt(js(f.Evidence), "findings|evidence|"+f.Key)
		if err != nil {
			return in, err
		}
		in.EvidenceEnc = enc
	}
	return in, nil
}

// UpsertFindings stores findings that the analysis derived, keyed by Finding.Key,
// in one statement. For a finding that exists already it refreshes the observed
// data and last_seen. Overridden title, description and severity keep the
// analyst value (the new observed value goes to overrides). Status, note, tags
// and assignee are analyst-owned and are not written, with one exception: a
// finding that was "resolved" becomes "new" when its cause is observed after
// the resolution (Finding.LastSeen later than resolved_at). It is reopened
// once per resolution, gets an audit entry "finding.reopen" (its history),
// and the DefectDojo status sync then reopens it there. Accepted and false
// positive findings are never reopened. An observation older than the
// resolution (a rule evaluation over unchanged data, a run that saw the
// cause before an analyst resolved it) does not reopen.
// It returns the number of findings that did not exist before.
func (s *Store) UpsertFindings(ctx context.Context, findings []model.Finding) (created int, err error) {
	if len(findings) == 0 {
		return 0, nil
	}
	now := time.Now().UTC()
	seen := map[string]bool{}
	rows := make([]findingIn, 0, len(findings))
	for _, f := range findings {
		if seen[f.Key] {
			continue
		}
		seen[f.Key] = true
		in, err := s.toFindingIn(f, now)
		if err != nil {
			return 0, err
		}
		rows = append(rows, in)
	}
	err = s.db.QueryRow(ctx, `WITH d AS (
		SELECT * FROM jsonb_to_recordset($1::jsonb) AS d(key text, type text, title text, description text, severity text, interest int, host_id bigint,
			ip inet, service_id bigint, port int, url text, signature text, evidence_enc text, at timestamptz, run_id bigint)
	), reopen AS (
		SELECT f.id, f.resolved_at, d.at, d.run_id FROM findings f JOIN d ON d.key = f.key
		WHERE f.status = 'resolved' AND d.at > COALESCE(f.resolved_at, '-infinity'::timestamptz)
	), audit AS (
		INSERT INTO audit_log (user_email, action, entity, entity_id, detail)
		SELECT 'system', 'finding.reopen', 'finding', r.id::text,
			jsonb_build_object('from', 'resolved', 'to', 'new', 'resolved_at', r.resolved_at, 'seen_at', r.at, 'run_id', r.run_id,
				'reason', 'przyczyna zaobserwowana ponownie po rozwiązaniu')
		FROM reopen r
	), up AS (
		INSERT INTO findings AS f (key, type, title, description, severity, status, interest, host_id, ip, service_id, port, url, signature,
			evidence_enc, first_seen, last_seen, first_run_id, last_run_id, manual)
		SELECT d.key, d.type, d.title, d.description, d.severity, 'new', d.interest, d.host_id, d.ip, d.service_id, d.port, d.url, d.signature,
			d.evidence_enc, d.at, d.at, d.run_id, d.run_id, false
		FROM d
		ON CONFLICT (key) DO UPDATE SET
			type = EXCLUDED.type,
			title = CASE WHEN f.overrides ? 'title' THEN f.title ELSE EXCLUDED.title END,
			description = CASE WHEN f.overrides ? 'description' THEN f.description ELSE EXCLUDED.description END,
			severity = CASE WHEN f.overrides ? 'severity' THEN f.severity ELSE EXCLUDED.severity END,
			overrides = czujka_observed(czujka_observed(czujka_observed(f.overrides, 'title', to_jsonb(EXCLUDED.title)),
				'description', to_jsonb(EXCLUDED.description)), 'severity', to_jsonb(EXCLUDED.severity)),
			interest = EXCLUDED.interest, ip = EXCLUDED.ip, service_id = EXCLUDED.service_id, port = EXCLUDED.port, url = EXCLUDED.url,
			signature = EXCLUDED.signature, evidence_enc = EXCLUDED.evidence_enc,
			last_seen = GREATEST(f.last_seen, EXCLUDED.last_seen), last_run_id = GREATEST(f.last_run_id, EXCLUDED.last_run_id),
			status = CASE WHEN f.status = 'resolved' AND EXCLUDED.last_seen > COALESCE(f.resolved_at, '-infinity'::timestamptz) THEN 'new' ELSE f.status END
			-- note, tags, assignee and every other status are analyst-owned: never written here
		RETURNING (xmax = 0) AS inserted)
		SELECT count(*) FILTER (WHERE inserted) FROM up`, js(rows)).Scan(&created)
	return created, mapErr(err)
}

// CreateManualFinding stores a finding that an analyst wrote by hand.
func (s *Store) CreateManualFinding(ctx context.Context, f model.Finding) (model.Finding, error) {
	f.Manual = true
	now := time.Now().UTC()
	in, err := s.toFindingIn(f, now)
	if err != nil {
		return f, err
	}
	var id int64
	err = s.db.QueryRow(ctx, `INSERT INTO findings (key, type, title, description, severity, status, interest, host_id, ip, service_id, port, url, signature,
			evidence_enc, tags, assignee, first_seen, last_seen, manual)
		SELECT d.key, d.type, d.title, d.description, d.severity, d.status, d.interest, d.host_id, d.ip, d.service_id, d.port, d.url, d.signature,
			d.evidence_enc, d.tags, d.assignee, d.at, d.at, true
		FROM jsonb_to_recordset($1::jsonb) AS d(key text, type text, title text, description text, severity text, status text, interest int, host_id bigint,
			ip inet, service_id bigint, port int, url text, signature text, evidence_enc text, tags text[], assignee text, at timestamptz)
		RETURNING id`, js([]findingIn{in})).Scan(&id)
	if err != nil {
		return f, mapErr(err)
	}
	if f.Note != "" {
		if err := s.applyPatch(ctx, findingPatchManual, id, map[string]json.RawMessage{"note": json.RawMessage(js(f.Note))}, ""); err != nil {
			return f, err
		}
	}
	_ = s.rememberTags(ctx, f.Tags)
	return s.GetFinding(ctx, id)
}

var (
	severities      = oneOf(string(model.SevInfo), string(model.SevLow), string(model.SevMedium), string(model.SevHigh))
	findingStatuses = oneOf(string(model.FindingNew), string(model.FindingTriaged), string(model.FindingAccepted), string(model.FindingFalsePositive), string(model.FindingResolved))
)

func findingSpec(observed bool) patchSpec {
	return patchSpec{table: "findings", noteAD: "findings|note|", fields: map[string]patchField{
		"title":       {col: "title", kind: "text", observed: observed},
		"description": {col: "description", kind: "text", observed: observed},
		"severity":    {col: "severity", kind: "text", observed: observed, check: severities},
		"status":      {col: "status", kind: "text", check: findingStatuses},
		"tags":        {col: "tags", kind: "text[]"},
		"assignee":    {col: "assignee", kind: "text"},
	}}
}

var (
	findingPatchDerived = findingSpec(true)
	findingPatchManual  = findingSpec(false)
)

// PatchFinding applies an analyst edit to a finding and returns the new state.
func (s *Store) PatchFinding(ctx context.Context, id int64, patch map[string]json.RawMessage, by string) (model.Finding, error) {
	var manual bool
	if err := s.db.QueryRow(ctx, `SELECT manual FROM findings WHERE id = $1`, id).Scan(&manual); err != nil {
		return model.Finding{}, mapErr(err)
	}
	spec := findingPatchDerived
	if manual {
		spec = findingPatchManual
	}
	if err := s.applyPatch(ctx, spec, id, patch, by); err != nil {
		return model.Finding{}, err
	}
	return s.GetFinding(ctx, id)
}

// DeleteFinding removes a finding.
func (s *Store) DeleteFinding(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM findings WHERE id = $1`, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetFindingDojo records the DefectDojo id and link of an exported finding.
func (s *Store) SetFindingDojo(ctx context.Context, id, dojoID int64, url string) error {
	_, err := s.db.Exec(ctx, `UPDATE findings SET dojo_id = $2, dojo_url = $3 WHERE id = $1`, id, dojoID, url)
	return mapErr(err)
}

// ResolveFindings marks findings that are no longer observed as resolved.
// Only findings that no analyst has triaged yet (status "new") change.
func (s *Store) ResolveFindings(ctx context.Context, ids []int64) (int, error) {
	tag, err := s.db.Exec(ctx, `UPDATE findings SET status = 'resolved' WHERE id = ANY($1) AND status = 'new' AND NOT manual`, ids)
	return int(tag.RowsAffected()), mapErr(err)
}

// ---------- results of the analysis ----------

// HostAnalysis is what the stability model and the interest score set on a host.
type HostAnalysis struct {
	ID       int64            `json:"id"`
	Status   model.HostStatus `json:"status"`
	PAlive   float64          `json:"p_alive"`
	Pattern  string           `json:"pattern"`
	Interest int              `json:"interest"` // a negative value keeps the stored score
}

// UpdateHostAnalysis stores model results for many hosts in one statement.
func (s *Store) UpdateHostAnalysis(ctx context.Context, rows []HostAnalysis) error {
	if len(rows) == 0 {
		return nil
	}
	_, err := s.db.Exec(ctx, `UPDATE hosts h SET status = d.status, p_alive = d.p_alive, pattern = d.pattern, interest = CASE WHEN d.interest < 0 THEN h.interest ELSE d.interest END
		FROM jsonb_to_recordset($1::jsonb) AS d(id bigint, status text, p_alive float8, pattern text, interest int) WHERE h.id = d.id`, js(rows))
	return mapErr(err)
}

// ServiceAnalysis is what the interest score and the grouping set on a service.
type ServiceAnalysis struct {
	ID          int64                  `json:"id"`
	Interest    int                    `json:"interest"`
	InterestWhy []model.InterestReason `json:"interest_why"`
	GroupKey    string                 `json:"group_key"`
	Classes     []string               `json:"classes"` // effective classes; nil keeps the stored ones; an analyst override always wins
	// ResponseSlow: the HTTP response of this run is slow against the service's baseline.
	ResponseSlow bool `json:"response_slow"`
}

// UpdateServiceAnalysis stores interest and grouping for many services in one statement.
func (s *Store) UpdateServiceAnalysis(ctx context.Context, rows []ServiceAnalysis) error {
	if len(rows) == 0 {
		return nil
	}
	for i := range rows {
		rows[i].InterestWhy = nonNil(rows[i].InterestWhy)
	}
	_, err := s.db.Exec(ctx, `UPDATE services s SET interest = d.interest, interest_why = d.interest_why, group_key = d.group_key,
			classes = CASE WHEN s.overrides ? 'classes' OR d.classes IS NULL THEN s.classes ELSE d.classes END, response_slow = d.response_slow
		FROM jsonb_to_recordset($1::jsonb) AS d(id bigint, interest int, interest_why jsonb, group_key text, classes text[], response_slow boolean) WHERE s.id = d.id`, js(rows))
	return mapErr(err)
}

// ---------- signatures ----------

const signatureCols = `g.id, g.slug, g.name, g.category, g.description, g.yaml, g.enabled, g.builtin, g.author, g.tags, g.interest, g.match_count, g.created_at, g.updated_at`

// SignatureFilter are the filters of GET /signatures.
type SignatureFilter struct {
	ListOpts
	Category string
	Enabled  *bool
	Builtin  *bool
	Tag      string
}

func (f SignatureFilter) where() *where {
	w := &where{}
	if f.Category != "" {
		w.add("g.category = ?", f.Category)
	}
	if f.Enabled != nil {
		w.add("g.enabled = ?", *f.Enabled)
	}
	if f.Builtin != nil {
		w.add("g.builtin = ?", *f.Builtin)
	}
	if f.Tag != "" {
		w.add("g.tags @> ARRAY[?]::text[]", f.Tag)
	}
	if f.Q != "" {
		q := like(f.Q)
		w.add("g.slug ILIKE ? OR g.name ILIKE ? OR g.description ILIKE ? OR g.yaml ILIKE ?", q, q, q, q)
	}
	return w
}

var signatureSort = map[string]string{"id": "g.id", "slug": "g.slug", "name": "g.name", "category": "g.category", "enabled": "g.enabled",
	"builtin": "g.builtin", "interest": "g.interest", "match_count": "g.match_count", "updated_at": "g.updated_at"}

// ListSignatures returns a page of signatures.
func (s *Store) ListSignatures(ctx context.Context, f SignatureFilter) (model.Page[model.Signature], error) {
	return listPage[model.Signature](ctx, s.db, signatureCols, "signatures g", f.where(), orderBy(f.Sort, signatureSort, "g.name ASC", "g.id"), f.ListOpts, nil)
}

// EachSignature streams every signature that matches the filter.
func (s *Store) EachSignature(ctx context.Context, f SignatureFilter, fn func(*model.Signature) error) error {
	return streamAll[model.Signature](ctx, s.db, signatureCols, "signatures g", f.where(), orderBy(f.Sort, signatureSort, "g.slug ASC", "g.id"), nil, fn)
}

// GetSignature returns one signature.
func (s *Store) GetSignature(ctx context.Context, id int64) (model.Signature, error) {
	return jsonRow[model.Signature](ctx, s.db, wrapJSON("SELECT "+signatureCols+" FROM signatures g WHERE g.id = $1"), id)
}

// CreateSignature inserts a signature. The slug must be unique.
func (s *Store) CreateSignature(ctx context.Context, g model.Signature) (model.Signature, error) {
	var id int64
	err := s.db.QueryRow(ctx, `INSERT INTO signatures (slug, name, category, description, yaml, enabled, builtin, author, tags, interest)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
		g.Slug, g.Name, g.Category, g.Description, g.YAML, g.Enabled, g.Builtin, g.Author, nonNil(g.Tags), g.Interest).Scan(&id)
	if err != nil {
		return g, mapErr(err)
	}
	return s.GetSignature(ctx, id)
}

// UpsertBuiltinSignatures loads the built-in signature library in one
// statement. A built-in rule is refreshed from the library; its enabled flag
// (an operator choice) is kept.
func (s *Store) UpsertBuiltinSignatures(ctx context.Context, sigs []model.Signature) error {
	if len(sigs) == 0 {
		return nil
	}
	for i := range sigs {
		sigs[i].Tags = nonNil(sigs[i].Tags)
	}
	_, err := s.db.Exec(ctx, `INSERT INTO signatures (slug, name, category, description, yaml, enabled, builtin, author, tags, interest)
		SELECT d.slug, d.name, d.category, d.description, d.yaml, d.enabled, true, d.author, d.tags, d.interest
		FROM jsonb_to_recordset($1::jsonb) AS d(slug text, name text, category text, description text, yaml text, enabled boolean, author text, tags text[], interest int)
		ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name, category = EXCLUDED.category, description = EXCLUDED.description, yaml = EXCLUDED.yaml,
			builtin = true, author = EXCLUDED.author, tags = EXCLUDED.tags, interest = EXCLUDED.interest, updated_at = now()
		WHERE signatures.yaml IS DISTINCT FROM EXCLUDED.yaml OR NOT signatures.builtin`, js(sigs))
	return mapErr(err)
}

// UpdateSignature stores a changed signature.
func (s *Store) UpdateSignature(ctx context.Context, g model.Signature) (model.Signature, error) {
	tag, err := s.db.Exec(ctx, `UPDATE signatures SET slug = $2, name = $3, category = $4, description = $5, yaml = $6, enabled = $7, author = $8,
		tags = $9, interest = $10, updated_at = now() WHERE id = $1`,
		g.ID, g.Slug, g.Name, g.Category, g.Description, g.YAML, g.Enabled, g.Author, nonNil(g.Tags), g.Interest)
	if err != nil {
		return g, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return g, ErrNotFound
	}
	return s.GetSignature(ctx, g.ID)
}

// DeleteSignature removes a signature.
func (s *Store) DeleteSignature(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM signatures WHERE id = $1`, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetSignatureMatchCounts stores how many services each signature matched (slug → count).
func (s *Store) SetSignatureMatchCounts(ctx context.Context, counts map[string]int) error {
	if len(counts) == 0 {
		return nil
	}
	_, err := s.db.Exec(ctx, `UPDATE signatures g SET match_count = d.value::int FROM jsonb_each_text($1::jsonb) AS d WHERE g.slug = d.key`, js(counts))
	return mapErr(err)
}
