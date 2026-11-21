package store

import (
	"context"
	"sync"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Dashboard builds the 3-30-300 dashboard. Every part is one indexed query;
// the parts run in parallel.
func (s *Store) Dashboard(ctx context.Context) (model.Dashboard, error) {
	d := model.Dashboard{GeneratedAt: time.Now().UTC()}
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)
	run := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
			}
		}()
	}

	run(func() error {
		h, err := jsonRow[model.Headline](ctx, s.db, wrapJSON(`SELECT
			(SELECT COALESCE(sum(addresses), 0) FROM targets WHERE enabled) AS addresses_in_scope,
			h.up AS hosts_up, h.unstable AS hosts_unstable, h.down AS hosts_down,
			sv.open AS services_open, sv.web AS web_services, sv.admin AS admin_panels, sv.staging AS staging_envs,
			f.open AS findings_open, f.high AS findings_high,
			(SELECT count(*) FROM changes WHERE acked_at IS NULL AND NOT expected) AS changes_unacked
			FROM (SELECT count(*) FILTER (WHERE status = 'up') AS up, count(*) FILTER (WHERE status IN ('unstable', 'expected-offline')) AS unstable,
					count(*) FILTER (WHERE status = 'down') AS down FROM hosts) h,
				(SELECT count(*) FILTER (WHERE state = 'open') AS open, count(*) FILTER (WHERE state = 'open' AND http_status > 0) AS web,
					count(*) FILTER (WHERE state = 'open' AND classes @> ARRAY['admin-panel']) AS admin,
					count(*) FILTER (WHERE state = 'open' AND classes @> ARRAY['staging']) AS staging FROM services) sv,
				(SELECT count(*) FILTER (WHERE status IN ('new', 'triaged')) AS open,
					count(*) FILTER (WHERE status IN ('new', 'triaged') AND severity = 'high') AS high FROM findings) f`))
		if err != nil {
			return err
		}
		runs, err := jsonRows[model.ScanRun](ctx, s.db, wrapJSON("SELECT "+runCols+" FROM runs r WHERE r.status = 'completed' ORDER BY r.id DESC LIMIT 1"))
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		if len(runs) > 0 {
			d.LastRun = &runs[0]
			if sum := runs[0].Summary; sum != nil {
				h.NewSinceLastRun = sum.HostsNew + sum.ServicesNew
				h.GoneSinceLastRun = sum.HostsGone + sum.ServicesGone
			}
		}
		d.Headline = h
		return nil
	})
	run(func() error {
		runs, err := jsonRows[model.ScanRun](ctx, s.db, wrapJSON("SELECT "+runCols+" FROM runs r WHERE r.status IN ('queued', 'running', 'analyzing') ORDER BY r.id DESC LIMIT 1"))
		if err == nil && len(runs) > 0 {
			d.ActiveRun = &runs[0]
		}
		return err
	})
	run(func() (err error) {
		d.NextRunAt, err = s.NextScheduledRun(ctx)
		return err
	})
	run(func() error {
		p, err := s.ListFindings(ctx, FindingFilter{Status: []string{"new", "triaged"}, ListOpts: ListOpts{Limit: 10}})
		d.TopFindings = p.Items
		return err
	})
	run(func() error {
		no := false
		p, err := s.ListChanges(ctx, ChangeFilter{Expected: &no, ListOpts: ListOpts{Limit: 15}})
		d.RecentChanges = p.Items
		return err
	})
	run(func() error {
		p, err := s.ListServices(ctx, ServiceFilter{State: []string{"open"}, MinInterest: 1, ListOpts: ListOpts{Limit: 10}})
		d.TopServices = p.Items
		return err
	})
	run(func() (err error) {
		d.Technologies, err = s.TechnologyCounts(ctx, 15)
		return err
	})
	run(func() (err error) {
		d.Ports, err = jsonRows[model.NameCount](ctx, s.db, wrapJSON(`SELECT port::text AS name, count(*)::int AS count, COALESCE(mode() WITHIN GROUP (ORDER BY name), '') AS extra
			FROM services WHERE state = 'open' GROUP BY port ORDER BY count DESC, port LIMIT 15`))
		return err
	})
	run(func() (err error) {
		d.Classes, err = jsonRows[model.NameCount](ctx, s.db, wrapJSON(`SELECT c AS name, count(*)::int AS count FROM services, unnest(classes) AS c
			WHERE state = 'open' GROUP BY c ORDER BY count DESC, c`))
		return err
	})
	run(func() error {
		pts, err := jsonRows[model.CountPoint](ctx, s.db, wrapJSON(`SELECT COALESCE(r.finished_at, r.created_at) AS at, r.id AS run_id,
			COALESCE((r.stats->>'hosts_up')::int, 0) AS hosts, COALESCE((r.stats->>'services_open')::int, 0) AS services,
			(SELECT count(*) FROM changes c WHERE c.run_id = r.id AND NOT c.expected)::int AS changes,
			(SELECT count(*) FROM findings f WHERE f.first_run_id = r.id)::int AS findings
			FROM runs r WHERE r.status = 'completed' ORDER BY r.id DESC LIMIT 30`))
		for i, j := 0, len(pts)-1; i < j; i, j = i+1, j-1 {
			pts[i], pts[j] = pts[j], pts[i]
		}
		d.Trend = pts
		return err
	})
	run(func() error {
		yes := true
		p, err := s.ListHosts(ctx, HostFilter{Unstable: &yes, ListOpts: ListOpts{Limit: 10}})
		d.UnstableHosts = p.Items
		return err
	})
	run(func() error {
		p, err := s.ListServices(ctx, ServiceFilter{State: []string{"open"}, CertWithin: 30, ListOpts: ListOpts{Limit: 10, Sort: "cert_not_after"}})
		d.CertsExpiring = p.Items
		return err
	})
	run(func() (err error) {
		d.Safety, err = s.GetSafetyPolicy(ctx)
		return err
	})
	wg.Wait()
	return d, first
}
