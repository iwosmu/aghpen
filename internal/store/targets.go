package store

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

const scopeCols = `s.id, s.name, s.description, s.owner, s.criticality, s.tags, s.created_at, s.updated_at,
  (SELECT count(*) FROM targets t WHERE t.scope_id = s.id) AS target_count,
  (SELECT COALESCE(sum(t.addresses), 0) FROM targets t WHERE t.scope_id = s.id AND t.enabled) AS address_count`

// ListScopes returns a page of scopes.
func (s *Store) ListScopes(ctx context.Context, o ListOpts) (model.Page[model.Scope], error) {
	w := &where{}
	if o.Q != "" {
		w.add("s.name ILIKE ? OR s.description ILIKE ? OR s.owner ILIKE ?", like(o.Q), like(o.Q), like(o.Q))
	}
	order := orderBy(o.Sort, map[string]string{"id": "s.id", "name": "s.name", "criticality": "s.criticality", "created_at": "s.created_at", "updated_at": "s.updated_at"}, "s.name ASC", "s.id")
	return listPage[model.Scope](ctx, s.db, scopeCols, "scopes s", w, order, o, nil)
}

// GetScope returns one scope.
func (s *Store) GetScope(ctx context.Context, id int64) (model.Scope, error) {
	return jsonRow[model.Scope](ctx, s.db, wrapJSON("SELECT "+scopeCols+" FROM scopes s WHERE s.id = $1"), id)
}

// CreateScope inserts a scope.
func (s *Store) CreateScope(ctx context.Context, sc model.Scope) (model.Scope, error) {
	var id int64
	err := s.db.QueryRow(ctx, `INSERT INTO scopes (name, description, owner, criticality, tags) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		sc.Name, sc.Description, sc.Owner, sc.Criticality, nonNil(sc.Tags)).Scan(&id)
	if err != nil {
		return sc, mapErr(err)
	}
	return s.GetScope(ctx, id)
}

// UpdateScope stores the editable fields of a scope.
func (s *Store) UpdateScope(ctx context.Context, sc model.Scope) (model.Scope, error) {
	tag, err := s.db.Exec(ctx, `UPDATE scopes SET name = $2, description = $3, owner = $4, criticality = $5, tags = $6, updated_at = now() WHERE id = $1`,
		sc.ID, sc.Name, sc.Description, sc.Owner, sc.Criticality, nonNil(sc.Tags))
	if err != nil {
		return sc, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return sc, ErrNotFound
	}
	s.invalidateScopes()
	return s.GetScope(ctx, sc.ID)
}

// DeleteScope removes a scope and its targets.
func (s *Store) DeleteScope(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM scopes WHERE id = $1`, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	s.invalidateScopes()
	return nil
}

const targetCols = `t.id, t.scope_id, t.kind, t.value, t.note, t.tags, t.enabled, t.source, t.addresses, t.created_at, t.created_by`

// ListTargets returns a page of targets of one scope.
func (s *Store) ListTargets(ctx context.Context, scopeID int64, o ListOpts) (model.Page[model.Target], error) {
	w := &where{}
	w.add("t.scope_id = ?", scopeID)
	if o.Q != "" {
		w.add("t.value ILIKE ? OR t.note ILIKE ?", like(o.Q), like(o.Q))
	}
	order := orderBy(o.Sort, map[string]string{"id": "t.id", "value": "t.value", "kind": "t.kind", "addresses": "t.addresses", "created_at": "t.created_at", "enabled": "t.enabled"}, "t.id ASC", "t.id")
	return listPage[model.Target](ctx, s.db, targetCols, "targets t", w, order, o, nil)
}

// GetTarget returns one target.
func (s *Store) GetTarget(ctx context.Context, id int64) (model.Target, error) {
	return jsonRow[model.Target](ctx, s.db, wrapJSON("SELECT "+targetCols+" FROM targets t WHERE t.id = $1"), id)
}

// AddTargets inserts targets into a scope in one statement. Targets whose
// value is already in the scope are skipped and counted as duplicates.
func (s *Store) AddTargets(ctx context.Context, scopeID int64, targets []model.Target, createdBy *int64) (saved []model.Target, duplicates int, err error) {
	if len(targets) == 0 {
		return []model.Target{}, 0, nil
	}
	type in struct {
		Kind      string   `json:"kind"`
		Value     string   `json:"value"`
		Note      string   `json:"note"`
		Tags      []string `json:"tags"`
		Enabled   bool     `json:"enabled"`
		Source    string   `json:"source"`
		Addresses int64    `json:"addresses"`
	}
	rows := make([]in, 0, len(targets))
	for _, t := range targets {
		src := t.Source
		if src == "" {
			src = "manual"
		}
		rows = append(rows, in{string(t.Kind), t.Value, t.Note, nonNil(t.Tags), t.Enabled, src, t.Addresses})
	}
	saved, err = jsonRows[model.Target](ctx, s.db, `WITH ins AS (
		INSERT INTO targets (scope_id, kind, value, note, tags, enabled, source, addresses, created_by)
		SELECT $1, d.kind, d.value, d.note, d.tags, d.enabled, d.source, d.addresses, $3
		FROM jsonb_to_recordset($2::jsonb) AS d(kind text, value text, note text, tags text[], enabled boolean, source text, addresses bigint)
		ON CONFLICT (scope_id, value) DO NOTHING
		RETURNING id, scope_id, kind, value, note, tags, enabled, source, addresses, created_at, created_by)
		SELECT row_to_json(ins) FROM ins ORDER BY id`, scopeID, js(rows), createdBy)
	if err != nil {
		return nil, 0, mapErr(err)
	}
	_, _ = s.db.Exec(ctx, `UPDATE scopes SET updated_at = now() WHERE id = $1`, scopeID)
	s.invalidateScopes()
	return saved, len(targets) - len(saved), nil
}

// UpdateTarget stores the editable fields of a target.
func (s *Store) UpdateTarget(ctx context.Context, t model.Target) (model.Target, error) {
	tag, err := s.db.Exec(ctx, `UPDATE targets SET kind = $2, value = $3, note = $4, tags = $5, enabled = $6, addresses = $7 WHERE id = $1`,
		t.ID, string(t.Kind), t.Value, t.Note, nonNil(t.Tags), t.Enabled, t.Addresses)
	if err != nil {
		return t, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return t, ErrNotFound
	}
	s.invalidateScopes()
	return s.GetTarget(ctx, t.ID)
}

// DeleteTarget removes one target.
func (s *Store) DeleteTarget(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM targets WHERE id = $1`, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	s.invalidateScopes()
	return nil
}

// EnabledTargets returns the enabled targets of the given scopes; all scopes when scopeIDs is nil.
func (s *Store) EnabledTargets(ctx context.Context, scopeIDs []int64) ([]model.Target, error) {
	if scopeIDs == nil {
		return jsonRows[model.Target](ctx, s.db, wrapJSON("SELECT "+targetCols+" FROM targets t WHERE t.enabled ORDER BY t.id"))
	}
	return jsonRows[model.Target](ctx, s.db, wrapJSON("SELECT "+targetCols+" FROM targets t WHERE t.enabled AND t.scope_id = ANY($1) ORDER BY t.id"), scopeIDs)
}

// AddressesInScope sums the addresses of every enabled target.
func (s *Store) AddressesInScope(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRow(ctx, `SELECT COALESCE(sum(addresses), 0) FROM targets WHERE enabled`).Scan(&n)
	return n, err
}

// ---------- matching an address to scopes ----------

type scopeRange struct {
	from, to netip.Addr
	scope    int64
}

// scopeMatcher answers "which scopes contain this address" from the enabled targets.
type scopeMatcher struct {
	ranges  []scopeRange
	domains map[string][]int64
}

func (s *Store) invalidateScopes() {
	s.sh.mu.Lock()
	s.sh.scopes = nil
	s.sh.mu.Unlock()
}

// scopeIndex returns a cached matcher; it is rebuilt after target changes and every 30 seconds.
func (s *Store) scopeIndex(ctx context.Context) (*scopeMatcher, error) {
	s.sh.mu.Lock()
	if s.sh.scopes != nil && time.Since(s.sh.scopeAt) < 30*time.Second {
		m := s.sh.scopes
		s.sh.mu.Unlock()
		return m, nil
	}
	s.sh.mu.Unlock()
	targets, err := s.EnabledTargets(ctx, nil)
	if err != nil {
		return nil, err
	}
	m := newScopeMatcher(targets)
	s.sh.mu.Lock()
	s.sh.scopes, s.sh.scopeAt = m, time.Now()
	s.sh.mu.Unlock()
	return m, nil
}

func newScopeMatcher(targets []model.Target) *scopeMatcher {
	m := &scopeMatcher{domains: map[string][]int64{}}
	for _, t := range targets {
		switch t.Kind {
		case model.TargetIP:
			if a, err := netip.ParseAddr(t.Value); err == nil {
				m.ranges = append(m.ranges, scopeRange{a.Unmap(), a.Unmap(), t.ScopeID})
			}
		case model.TargetCIDR:
			if p, err := netip.ParsePrefix(t.Value); err == nil {
				p = p.Masked()
				m.ranges = append(m.ranges, scopeRange{p.Addr(), lastAddr(p), t.ScopeID})
			}
		case model.TargetRange:
			if a, b, ok := strings.Cut(t.Value, "-"); ok {
				from, err1 := netip.ParseAddr(strings.TrimSpace(a))
				to, err2 := netip.ParseAddr(strings.TrimSpace(b))
				if err1 == nil && err2 == nil {
					m.ranges = append(m.ranges, scopeRange{from, to, t.ScopeID})
				}
			}
		case model.TargetDomain:
			d := strings.ToLower(strings.TrimSuffix(t.Value, "."))
			m.domains[d] = append(m.domains[d], t.ScopeID)
		}
	}
	return m
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func (m *scopeMatcher) match(ip netip.Addr, hostnames []string) []int64 {
	seen := map[int64]bool{}
	for _, r := range m.ranges {
		if r.from.BitLen() == ip.BitLen() && ip.Compare(r.from) >= 0 && ip.Compare(r.to) <= 0 {
			seen[r.scope] = true
		}
	}
	for _, h := range hostnames {
		for _, id := range m.domains[strings.ToLower(strings.TrimSuffix(h, "."))] {
			seen[id] = true
		}
	}
	out := make([]int64, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
