package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
)

var (
	// ErrNotFound means the rule does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict means another rule has the same id, or a built-in rule cannot change that way.
	ErrConflict = errors.New("conflict")
	// ErrInvalid means the validator refused the rule.
	ErrInvalid = errors.New("invalid rule")
)

// StoredRule is one row of the policy_rules table, the wire format of the API.
type StoredRule struct {
	ID          int64      `json:"id"`
	Slug        string     `json:"slug"`
	Name        string     `json:"name"`
	Severity    string     `json:"severity"`
	Description string     `json:"description"`
	YAML        string     `json:"yaml"`
	Enabled     bool       `json:"enabled"`
	Builtin     bool       `json:"builtin"`
	Author      string     `json:"author"`
	Violations  int        `json:"violations"` // open violations at the last evaluation
	LastEvalAt  *time.Time `json:"last_eval_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Service is the store-backed rule service. It is safe for concurrent use.
type Service struct {
	st  *store.Store
	log *slog.Logger
	mu  sync.Mutex // serialises Evaluate
	// EvalOnChange re-evaluates every rule in the background after a create,
	// update or delete, so the findings follow the rule set at once.
	EvalOnChange bool
	// Now is the clock (tests).
	Now func() time.Time
	wg  sync.WaitGroup
}

// New returns the rule service. Call Start before use.
func New(st *store.Store, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{st: st, log: logger, EvalOnChange: true, Now: func() time.Time { return time.Now().UTC() }}
}

const ddl = `CREATE TABLE IF NOT EXISTS policy_rules (
  id           BIGSERIAL PRIMARY KEY,
  slug         TEXT NOT NULL UNIQUE,
  name         TEXT NOT NULL DEFAULT '',
  severity     TEXT NOT NULL DEFAULT 'medium',
  description  TEXT NOT NULL DEFAULT '',
  yaml         TEXT NOT NULL,
  enabled      BOOLEAN NOT NULL DEFAULT true,
  builtin      BOOLEAN NOT NULL DEFAULT false,
  author       TEXT NOT NULL DEFAULT '',
  violations   INT NOT NULL DEFAULT 0,
  last_eval_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// Start creates the table (with the access method of the findings table, so
// it is a tde_heap table when the store uses pg_tde) and seeds the starter pack.
func (s *Service) Start(ctx context.Context) error {
	if err := s.ensureTable(ctx); err != nil {
		return err
	}
	_, err := s.Seed(ctx)
	return err
}

func (s *Service) ensureTable(ctx context.Context) error {
	var am string
	_ = s.st.Pool().QueryRow(ctx, `SELECT COALESCE((SELECT a.amname::text FROM pg_class c JOIN pg_am a ON a.oid = c.relam
		WHERE c.oid = to_regclass('findings')), '')`).Scan(&am)
	create := func(using string) error {
		tx, err := s.st.Pool().Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(741100331)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, ddl+using); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if am == "tde_heap" {
		if err := create(" USING tde_heap"); err == nil {
			return nil
		} else {
			s.log.Warn("policy_rules: tde_heap table cannot be created; using the default access method", "error", err)
		}
	}
	if err := create(""); err != nil {
		return fmt.Errorf("rules: create table: %w", err)
	}
	return nil
}

// Seed writes the starter pack as built-in rows. A built-in row gets the new
// text when the pack changed; its enabled flag (the analyst's choice) stays.
// A custom rule with the same id is never touched. Built-in rows that the
// pack no longer has are removed.
func (s *Service) Seed(ctx context.Context) (int, error) {
	pack, err := Builtin()
	if err != nil {
		return 0, err
	}
	slugs := make([]string, len(pack))
	for i, r := range pack {
		slugs[i] = r.ID
		_, err := s.st.Pool().Exec(ctx, `INSERT INTO policy_rules (slug, name, severity, description, yaml, enabled, builtin, author)
			VALUES ($1, $2, $3, $4, $5, $6, true, 'czujka')
			ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name, severity = EXCLUDED.severity, description = EXCLUDED.description,
				yaml = EXCLUDED.yaml, updated_at = now()
			WHERE policy_rules.builtin AND policy_rules.yaml <> EXCLUDED.yaml`,
			r.ID, r.Name, string(r.Severity), r.Description, r.YAML, r.Enabled)
		if err != nil {
			return 0, fmt.Errorf("rules: seed %s: %w", r.ID, err)
		}
	}
	if _, err := s.st.Pool().Exec(ctx, `DELETE FROM policy_rules WHERE builtin AND NOT (slug = ANY($1::text[]))`, slugs); err != nil {
		return 0, fmt.Errorf("rules: remove retired built-in rules: %w", err)
	}
	return len(pack), nil
}

const ruleCols = `id, slug, name, severity, description, yaml, enabled, builtin, author, violations, last_eval_at, created_at, updated_at`

func scanRule(row pgx.Row) (StoredRule, error) {
	var r StoredRule
	err := row.Scan(&r.ID, &r.Slug, &r.Name, &r.Severity, &r.Description, &r.YAML, &r.Enabled, &r.Builtin, &r.Author,
		&r.Violations, &r.LastEvalAt, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// List returns every rule, built-in first, then by id.
func (s *Service) List(ctx context.Context) ([]StoredRule, error) {
	rows, err := s.st.Pool().Query(ctx, `SELECT `+ruleCols+` FROM policy_rules ORDER BY builtin DESC, slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StoredRule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns one rule.
func (s *Service) Get(ctx context.Context, id int64) (StoredRule, error) {
	return scanRule(s.st.Pool().QueryRow(ctx, `SELECT `+ruleCols+` FROM policy_rules WHERE id = $1`, id))
}

// Validate checks a rule text without storing it.
func (s *Service) Validate(text string) Validation {
	_, v := Parse(text)
	return v
}

func isUnique(err error) bool { return err != nil && strings.Contains(err.Error(), "SQLSTATE 23505") }

// Create stores a new custom rule. enabled, when set, overrides the YAML.
func (s *Service) Create(ctx context.Context, text string, enabled *bool, author string) (StoredRule, Validation, error) {
	r, val := Parse(text)
	if r == nil {
		return StoredRule{}, val, ErrInvalid
	}
	en := r.Enabled
	if enabled != nil {
		en = *enabled
	}
	out, err := scanRule(s.st.Pool().QueryRow(ctx, `INSERT INTO policy_rules (slug, name, severity, description, yaml, enabled, builtin, author)
		VALUES ($1, $2, $3, $4, $5, $6, false, $7) RETURNING `+ruleCols, r.ID, r.Name, string(r.Severity), r.Description, text, en, author))
	if isUnique(err) {
		return out, val, fmt.Errorf("%w: Reguła o id „%s” już istnieje.", ErrConflict, r.ID)
	}
	if err == nil {
		s.changed()
	}
	return out, val, err
}

// Update changes the text and/or the enabled flag of a rule. A built-in rule
// can only be switched on or off; copy it as a custom rule to change it.
func (s *Service) Update(ctx context.Context, id int64, text *string, enabled *bool) (StoredRule, Validation, error) {
	val := Validation{OK: true, Issues: []Issue{}}
	cur, err := s.Get(ctx, id)
	if err != nil {
		return cur, val, err
	}
	if text != nil && *text != cur.YAML {
		if cur.Builtin {
			return cur, val, fmt.Errorf("%w: Reguły wbudowanej nie można edytować. Skopiuj ją jako własną regułę (inne id) i wyłącz wbudowaną.", ErrConflict)
		}
		r, v := Parse(*text)
		if r == nil {
			return cur, v, ErrInvalid
		}
		val = v
		cur.Slug, cur.Name, cur.Severity, cur.Description, cur.YAML = r.ID, r.Name, string(r.Severity), r.Description, *text
	}
	if enabled != nil {
		cur.Enabled = *enabled
	}
	out, err := scanRule(s.st.Pool().QueryRow(ctx, `UPDATE policy_rules SET slug = $2, name = $3, severity = $4, description = $5, yaml = $6,
		enabled = $7, updated_at = now() WHERE id = $1 RETURNING `+ruleCols, id, cur.Slug, cur.Name, cur.Severity, cur.Description, cur.YAML, cur.Enabled))
	if isUnique(err) {
		return out, val, fmt.Errorf("%w: Reguła o id „%s” już istnieje.", ErrConflict, cur.Slug)
	}
	if err == nil {
		s.changed()
	}
	return out, val, err
}

// Delete removes a custom rule. A built-in rule can only be disabled.
func (s *Service) Delete(ctx context.Context, id int64) error {
	cur, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if cur.Builtin {
		return fmt.Errorf("%w: Reguły wbudowanej nie można usunąć. Wyłącz ją.", ErrConflict)
	}
	if _, err := s.st.Pool().Exec(ctx, `DELETE FROM policy_rules WHERE id = $1`, id); err != nil {
		return err
	}
	s.changed()
	return nil
}

func (s *Service) changed() {
	if !s.EvalOnChange {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if _, err := s.Evaluate(ctx, 0); err != nil {
			s.log.Error("policy evaluation after a rule change failed", "error", err)
		}
	}()
}

// Wait blocks until background evaluations started by rule changes end.
func (s *Service) Wait() { s.wg.Wait() }

// Rejected is a stored rule that no longer passes the validator.
type Rejected struct {
	Slug   string  `json:"slug"`
	Issues []Issue `json:"issues"`
}

func (s *Service) enabledRules(ctx context.Context) ([]*Rule, []Rejected, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	var out []*Rule
	var rej []Rejected
	for _, row := range all {
		if !row.Enabled {
			continue
		}
		r, val := Parse(row.YAML)
		if r == nil {
			rej = append(rej, Rejected{Slug: row.Slug, Issues: val.Issues})
			s.log.Warn("policy rule rejected by the validator; it is not evaluated", "slug", row.Slug)
			continue
		}
		r.ID = row.Slug
		out = append(out, r)
	}
	return out, rej, nil
}

// ---------- inventory ----------

// EachHost streams the inventory host by host, each host with its services
// and the newest observation of every service. It sends no packet. Hosts
// are held in memory (small rows); services and observations are streamed.
func (s *Service) EachHost(ctx context.Context, fn func(*HostRec) error) error {
	scopes, err := s.st.ListScopes(ctx, store.ListOpts{Limit: 100000})
	if err != nil {
		return fmt.Errorf("rules: read scopes: %w", err)
	}
	scopeKeys := map[int64][]string{}
	for _, sc := range scopes.Items {
		keys := []string{strings.ToLower(sc.Name)}
		for _, t := range sc.Tags {
			keys = append(keys, strings.ToLower(t))
		}
		scopeKeys[sc.ID] = keys
	}
	hosts := map[int64]*HostRec{}
	var order []int64
	if err := s.st.EachHost(ctx, store.HostFilter{}, func(h *model.Host) error {
		rec := &HostRec{Host: *h}
		for _, id := range h.ScopeIDs {
			rec.Scopes = append(rec.Scopes, scopeKeys[id]...)
		}
		hosts[h.ID] = rec
		order = append(order, h.ID)
		return nil
	}); err != nil {
		return fmt.Errorf("rules: read hosts: %w", err)
	}
	rows, err := s.st.Pool().Query(ctx, `SELECT s.id, s.host_id, s.hostname, s.port, s.proto, s.state, s.name, s.product, s.version, s.banner,
		s.tls, s.title, s.http_status, s.url, s.technologies, s.classes, s.interest, s.tags, s.first_seen, s.last_seen, lo.result
		FROM services s LEFT JOIN LATERAL (SELECT o.result FROM service_observations o WHERE o.service_id = s.id
			ORDER BY o.at DESC, o.id DESC LIMIT 1) lo ON true
		ORDER BY s.host_id, s.port, s.id`)
	if err != nil {
		return fmt.Errorf("rules: read services: %w", err)
	}
	defer rows.Close()
	done := map[int64]bool{}
	var cur *HostRec
	flush := func() error {
		if cur == nil {
			return nil
		}
		done[cur.Host.ID] = true
		err := fn(cur)
		cur.Services = nil // the host keeps its row; the services go
		cur = nil
		return err
	}
	for rows.Next() {
		var sv model.Service
		var state string
		var techs, result []byte
		if err := rows.Scan(&sv.ID, &sv.HostID, &sv.Hostname, &sv.Port, &sv.Proto, &state, &sv.Name, &sv.Product, &sv.Version, &sv.Banner,
			&sv.TLS, &sv.Title, &sv.HTTPStatus, &sv.URL, &techs, &sv.Classes, &sv.Interest, &sv.Tags, &sv.FirstSeen, &sv.LastSeen, &result); err != nil {
			return fmt.Errorf("rules: read services: %w", err)
		}
		sv.State = model.ServiceState(state)
		if len(techs) > 0 {
			_ = json.Unmarshal(techs, &sv.Technologies)
		}
		h := hosts[sv.HostID]
		if h == nil {
			continue // a host created after the host list was read
		}
		sv.IP = h.Host.IP
		if cur != h {
			if err := flush(); err != nil {
				return err
			}
			cur = h
		}
		rec := &SvcRec{Service: sv}
		if len(result) > 0 {
			var res model.ServiceResult
			if json.Unmarshal(result, &res) == nil {
				rec.Result = &res
			}
		}
		cur.Services = append(cur.Services, rec)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rules: read services: %w", err)
	}
	if err := flush(); err != nil {
		return err
	}
	for _, id := range order {
		if !done[id] {
			if err := fn(hosts[id]); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------- evaluation ----------

// Report says what one evaluation did.
type Report struct {
	RunID      int64          `json:"run_id"`
	Rules      int            `json:"rules"`
	Rejected   []Rejected     `json:"rejected"`
	Hosts      int            `json:"hosts"`
	Services   int            `json:"services"`
	Violations int            `json:"violations"`
	Stored     int            `json:"stored"`
	Created    int            `json:"created"`
	Resolved   int            `json:"resolved"`
	ByRule     map[string]int `json:"by_rule"`
	EvalMs     int64          `json:"eval_ms"`  // reading the inventory and checking the rules
	StoreMs    int64          `json:"store_ms"` // writing and resolving findings
	TookMs     int64          `json:"took_ms"`
}

// Evaluate checks every enabled rule against the whole stored inventory and
// stores the result as findings of type policy-violation (store.UpsertFindings:
// analyst-owned fields are never overwritten). A violation that is gone is
// resolved (store.ResolveFindings: only findings still in status "new").
// Call it after every analysed run and after every import; runID is stored
// as the last run of the findings (0 outside a run).
func (s *Service) Evaluate(ctx context.Context, runID int64) (Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	start := time.Now()
	now := s.Now()
	rep := Report{RunID: runID, ByRule: map[string]int{}, Rejected: []Rejected{}}
	rules, rej, err := s.enabledRules(ctx)
	if err != nil {
		return rep, err
	}
	if rej != nil {
		rep.Rejected = rej
	}
	rep.Rules = len(rules)
	byID := map[string]*Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	ev := NewEvaluator(rules, now)
	if err := s.EachHost(ctx, func(h *HostRec) error { ev.Host(h); return ctx.Err() }); err != nil {
		return rep, err
	}
	vs := ev.Finish()
	rep.Hosts, rep.Services, rep.Violations = ev.Hosts, ev.Services, len(vs)
	rep.EvalMs = time.Since(start).Milliseconds()

	storeStart := time.Now()
	produced := map[string]bool{}
	findings := make([]model.Finding, 0, len(vs))
	for _, v := range vs {
		rep.ByRule[v.Rule]++
		if !v.Storable || produced[v.Key] {
			continue
		}
		produced[v.Key] = true
		findings = append(findings, v.Finding(byID[v.Rule], runID, now))
	}
	rep.Stored = len(findings)
	const batch = 2000
	for lo := 0; lo < len(findings); lo += batch {
		n, err := s.st.UpsertFindings(ctx, findings[lo:min(lo+batch, len(findings))])
		if err != nil {
			return rep, fmt.Errorf("rules: store findings: %w", err)
		}
		rep.Created += n
	}
	var stale []int64
	if err := s.st.EachFinding(ctx, store.FindingFilter{Type: FindingType, Status: []string{string(model.FindingNew)}}, func(f *model.Finding) error {
		if !produced[f.Key] && !f.Manual {
			stale = append(stale, f.ID)
		}
		return nil
	}); err != nil {
		return rep, fmt.Errorf("rules: read findings: %w", err)
	}
	if len(stale) > 0 {
		if rep.Resolved, err = s.st.ResolveFindings(ctx, stale); err != nil {
			return rep, fmt.Errorf("rules: resolve findings: %w", err)
		}
	}
	slugs := make([]string, 0, len(rep.ByRule))
	counts := make([]int32, 0, len(rep.ByRule))
	for k, n := range rep.ByRule {
		slugs, counts = append(slugs, k), append(counts, int32(n))
	}
	if _, err := s.st.Pool().Exec(ctx, `UPDATE policy_rules p SET violations = COALESCE(c.n, 0), last_eval_at = $3
		FROM policy_rules q LEFT JOIN unnest($1::text[], $2::int[]) AS c(slug, n) ON c.slug = q.slug
		WHERE p.id = q.id`, slugs, counts, now); err != nil {
		return rep, fmt.Errorf("rules: store counts: %w", err)
	}
	rep.StoreMs = time.Since(storeStart).Milliseconds()
	rep.TookMs = time.Since(start).Milliseconds()
	s.log.Info("policy rules evaluated", "run", runID, "rules", rep.Rules, "hosts", rep.Hosts, "services", rep.Services,
		"violations", rep.Violations, "created", rep.Created, "resolved", rep.Resolved, "took_ms", rep.TookMs)
	return rep, nil
}

// DryRunResult is the answer of a dry run.
type DryRunResult struct {
	Validation Validation  `json:"validation"`
	Total      int         `json:"total"`
	Violations []Violation `json:"violations"`
	Truncated  bool        `json:"truncated"`
	Hosts      int         `json:"hosts"`
	Services   int         `json:"services"`
	TookMs     int64       `json:"took_ms"`
	Condition  string      `json:"condition"`
	Message    string      `json:"message"` // "Ta reguła zgłosiłaby dziś 7 naruszeń."
}

// DryRun evaluates one rule text against the current inventory and returns
// the violations. It stores nothing. The rule is checked even when it says
// enabled: false. limit bounds the violation list (0: 500).
func (s *Service) DryRun(ctx context.Context, text string, limit int) (DryRunResult, error) {
	start := time.Now()
	r, val := Parse(text)
	res := DryRunResult{Validation: val, Violations: []Violation{}}
	if r == nil {
		res.Message = "Reguła ma błędy; popraw je, aby zobaczyć wynik."
		return res, nil
	}
	if limit <= 0 {
		limit = 500
	}
	ev := NewEvaluator([]*Rule{r}, s.Now())
	if err := s.EachHost(ctx, func(h *HostRec) error { ev.Host(h); return ctx.Err() }); err != nil {
		return res, err
	}
	vs := ev.Finish()
	res.Total, res.Hosts, res.Services, res.Condition = len(vs), ev.Hosts, ev.Services, r.Describe()
	if len(vs) > limit {
		vs, res.Truncated = vs[:limit], true
	}
	res.Violations = vs
	res.TookMs = time.Since(start).Milliseconds()
	res.Message = DryRunMessage(r, res.Total, res.Hosts, res.Services)
	return res, nil
}

// DryRunMessage is the sentence the editor shows.
func DryRunMessage(r *Rule, n, hosts, services int) string {
	if r.Expect == ExpectPresent && n == 0 {
		return fmt.Sprintf("Wymaganie jest dziś spełnione (sprawdzono %d hostów i %d usług).", hosts, services)
	}
	return fmt.Sprintf("Ta reguła zgłosiłaby dziś %d %s (sprawdzono %d hostów i %d usług).", n, plural(n, "naruszenie", "naruszenia", "naruszeń"), hosts, services)
}

func plural(n int, one, few, many string) string {
	switch {
	case n == 1:
		return one
	case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
		return few
	}
	return many
}

// Violations returns the stored findings of one rule (all statuses unless
// statuses is set), most interesting first.
func (s *Service) Violations(ctx context.Context, id int64, statuses []string, limit, offset int) (model.Page[model.Finding], error) {
	page := model.Page[model.Finding]{Items: []model.Finding{}, Limit: limit, Offset: offset}
	r, err := s.Get(ctx, id)
	if err != nil {
		return page, err
	}
	if limit <= 0 || limit > 1000 {
		page.Limit = 100
	}
	prefix := KeyPrefix(r.Slug)
	err = s.st.EachFinding(ctx, store.FindingFilter{Type: FindingType, Status: statuses, ListOpts: store.ListOpts{Q: "policy:" + r.Slug}}, func(f *model.Finding) error {
		if !strings.HasPrefix(f.Key, prefix) {
			return nil
		}
		if page.Total >= offset && len(page.Items) < page.Limit {
			page.Items = append(page.Items, *f)
		}
		page.Total++
		return nil
	})
	return page, err
}
