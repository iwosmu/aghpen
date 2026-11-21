package store

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// HostIDsByIP returns the ids of the known hosts with the given addresses.
func (s *Store) HostIDsByIP(ctx context.Context, ips []string) (map[string]int64, error) {
	out := map[string]int64{}
	clean := make([]string, 0, len(ips))
	for _, ip := range ips {
		if a, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
			clean = append(clean, a.Unmap().String())
		}
	}
	if len(clean) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx, `SELECT id, host(ip) FROM hosts WHERE ip = ANY($1::inet[])`, clean)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var ip string
		if err := rows.Scan(&id, &ip); err != nil {
			return nil, err
		}
		if a, err := netip.ParseAddr(ip); err == nil {
			ip = a.Unmap().String()
		}
		out[ip] = id
	}
	return out, mapErr(rows.Err())
}

// ServiceIDsOf returns the service ids of the given hosts, keyed by ServiceKey(port, proto) per host.
func (s *Store) ServiceIDsOf(ctx context.Context, hostIDs []int64) (map[int64]map[string]int64, error) {
	out := map[int64]map[string]int64{}
	if len(hostIDs) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx, `SELECT id, host_id, port, proto FROM services WHERE host_id = ANY($1)`, hostIDs)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, host int64
		var port int
		var proto string
		if err := rows.Scan(&id, &host, &port, &proto); err != nil {
			return nil, err
		}
		if out[host] == nil {
			out[host] = map[string]int64{}
		}
		out[host][ServiceKey(port, proto)] = id
	}
	return out, mapErr(rows.Err())
}

// HostScopeIDs returns the scope ids of the given hosts.
func (s *Store) HostScopeIDs(ctx context.Context, hostIDs []int64) (map[int64][]int64, error) {
	out := map[int64][]int64{}
	if len(hostIDs) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx, `SELECT id, scope_ids FROM hosts WHERE id = ANY($1)`, hostIDs)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var ids []int64
		if err := rows.Scan(&id, &ids); err != nil {
			return nil, err
		}
		out[id] = ids
	}
	return out, mapErr(rows.Err())
}

// ImportFindings stores findings read from a file (DefectDojo Generic
// Findings, a DefectDojo API list, a Czujka findings export), keyed by
// Finding.Key, so a second import of the same file updates and never
// duplicates. A new finding takes the status of the file. An existing one
// keeps its analyst-owned fields; its status changes only when the file
// carries a decision (not "new") and no analyst set the status in Czujka.
// Every finding needs a HostID.
func (s *Store) ImportFindings(ctx context.Context, findings []model.Finding) (created, updated int, err error) {
	if len(findings) == 0 {
		return 0, 0, nil
	}
	now := time.Now().UTC()
	type row struct {
		findingIn
		DojoID  *int64 `json:"dojo_id"`
		DojoURL string `json:"dojo_url"`
	}
	rows := make([]row, 0, len(findings))
	seen := map[string]bool{}
	for _, f := range findings {
		if seen[f.Key] || f.HostID == 0 {
			continue
		}
		seen[f.Key] = true
		in, err := s.toFindingIn(f, now)
		if err != nil {
			return 0, 0, err
		}
		rows = append(rows, row{in, f.DojoID, f.DojoURL})
	}
	if len(rows) == 0 {
		return 0, 0, nil
	}
	err = s.db.QueryRow(ctx, `WITH up AS (
		INSERT INTO findings AS f (key, type, title, description, severity, status, interest, host_id, ip, service_id, port, url, signature,
			evidence_enc, tags, first_seen, last_seen, first_run_id, last_run_id, manual, dojo_id, dojo_url)
		SELECT d.key, d.type, d.title, d.description, d.severity, d.status, d.interest, d.host_id, d.ip, d.service_id, d.port, d.url, d.signature,
			d.evidence_enc, d.tags, d.at, d.at, COALESCE(d.run_id, 0), COALESCE(d.run_id, 0), d.manual, d.dojo_id, COALESCE(d.dojo_url, '')
		FROM jsonb_to_recordset($1::jsonb) AS d(key text, type text, title text, description text, severity text, status text, interest int, host_id bigint,
			ip inet, service_id bigint, port int, url text, signature text, evidence_enc text, tags text[], at timestamptz, run_id bigint, manual boolean,
			dojo_id bigint, dojo_url text)
		ON CONFLICT (key) DO UPDATE SET
			title = CASE WHEN f.overrides ? 'title' THEN f.title ELSE EXCLUDED.title END,
			description = CASE WHEN f.overrides ? 'description' THEN f.description ELSE EXCLUDED.description END,
			severity = CASE WHEN f.overrides ? 'severity' THEN f.severity ELSE EXCLUDED.severity END,
			status = CASE WHEN EXCLUDED.status <> 'new' AND NOT f.overrides ? 'status' THEN EXCLUDED.status ELSE f.status END,
			tags = ARRAY(SELECT DISTINCT unnest(f.tags || EXCLUDED.tags)),
			service_id = COALESCE(EXCLUDED.service_id, f.service_id),
			dojo_id = COALESCE(EXCLUDED.dojo_id, f.dojo_id),
			dojo_url = CASE WHEN EXCLUDED.dojo_url <> '' THEN EXCLUDED.dojo_url ELSE f.dojo_url END,
			last_seen = GREATEST(f.last_seen, EXCLUDED.last_seen)
		RETURNING (xmax = 0) AS inserted)
		SELECT count(*) FILTER (WHERE inserted), count(*) FILTER (WHERE NOT inserted) FROM up`, js(rows)).Scan(&created, &updated)
	if err == nil {
		var tags []string
		for _, r := range rows {
			tags = append(tags, r.Tags...)
		}
		_ = s.rememberTags(ctx, tags)
	}
	return created, updated, mapErr(err)
}
