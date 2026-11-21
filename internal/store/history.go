package store

import (
	"context"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// responseExpr is the HTTP response time of a service observation in ms, or
// -1 when the port was open and HTTP gave no answer (analyze.NoAnswer). The
// time is stored in the observation result (http.response_ms).
const responseExpr = `CASE WHEN COALESCE((o.result->'http'->>'status')::int, 0) > 0
	THEN GREATEST(COALESCE((o.result->'http'->>'response_ms')::int, 0), 0) ELSE -1 END`

// finishedScan selects host observations ho whose port scan finished. A run
// stopped after a partial result has a subset of the services, often without
// their HTTP answer yet: it counts neither as a run the service was away nor
// as a response time (a missing answer would read as "no answer").
const finishedScan = `ho.reason IS DISTINCT FROM '` + model.ReasonPortsUnknown + `'`

// ServiceHistory is what the runs before runID know about one service.
type ServiceHistory struct {
	ServiceID   int64     `json:"service_id"`
	LastOpenRun int64     `json:"last_open_run"`
	LastOpenAt  time.Time `json:"last_open_at"`
	RunsAway    int       `json:"runs_away"`
	Response    []int     `json:"response"` // oldest first
}

// ServiceHistories returns, for the given services, the last earlier run in
// which each was open, the number of later runs before runID in which its
// host answered (the runs it was away), and the response times of its last
// `limit` open observations before runID, oldest first.
func (s *Store) ServiceHistories(ctx context.Context, runID int64, serviceIDs []int64, limit int) (map[int64]ServiceHistory, error) {
	out := make(map[int64]ServiceHistory, len(serviceIDs))
	const batch = 1000
	for lo := 0; lo < len(serviceIDs); lo += batch {
		part := serviceIDs[lo:min(lo+batch, len(serviceIDs))]
		err := eachJSON(ctx, s.db, wrapJSON(`SELECT s.id AS service_id, COALESCE(lo.run_id, 0) AS last_open_run, lo.at AS last_open_at,
			CASE WHEN lo.run_id IS NULL THEN 0 ELSE (SELECT count(DISTINCT ho.run_id) FROM host_observations ho
				WHERE ho.host_id = s.host_id AND ho.up AND ho.run_id > lo.run_id AND ho.run_id < $2 AND `+finishedScan+`) END AS runs_away,
			COALESCE((SELECT array_agg(x.v ORDER BY x.at, x.id) FROM (SELECT * FROM (SELECT DISTINCT ON (o.run_id) o.id, o.at, `+responseExpr+` AS v
				FROM service_observations o JOIN host_observations ho ON ho.host_id = o.host_id AND ho.run_id = o.run_id
				WHERE o.service_id = s.id AND o.run_id < $2 AND o.state = 'open' AND `+finishedScan+` ORDER BY o.run_id, o.at DESC, o.id DESC) r
				ORDER BY r.at DESC, r.id DESC LIMIT $3) x), '{}') AS response
			FROM services s
			LEFT JOIN LATERAL (SELECT o.run_id, o.at FROM service_observations o WHERE o.service_id = s.id AND o.run_id < $2 AND o.state = 'open'
				ORDER BY o.run_id DESC, o.at DESC LIMIT 1) lo ON true
			WHERE s.id = ANY($1)`), []any{part, runID, limit}, func(h *ServiceHistory) error {
			out[h.ServiceID] = *h
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ResponsePoint is one observation of a service's HTTP response time.
type ResponsePoint struct {
	RunID int64     `json:"run_id"`
	At    time.Time `json:"at"`
	Ms    int       `json:"ms"` // -1: the port was open, HTTP gave no answer
}

// ResponseSeries returns the last `limit` response times of a service, oldest
// first, one per run (the latest observation of the run).
func (s *Store) ResponseSeries(ctx context.Context, serviceID int64, limit int) ([]ResponsePoint, error) {
	if _, err := s.GetService(ctx, serviceID, false); err != nil {
		return nil, err
	}
	out := []ResponsePoint{}
	err := eachJSON(ctx, s.db, wrapJSON(`SELECT * FROM (SELECT * FROM (SELECT DISTINCT ON (o.run_id) o.run_id, o.at, `+responseExpr+` AS ms FROM service_observations o
		JOIN host_observations ho ON ho.host_id = o.host_id AND ho.run_id = o.run_id
		WHERE o.service_id = $1 AND o.state = 'open' AND `+finishedScan+` ORDER BY o.run_id, o.at DESC, o.id DESC) r ORDER BY r.at DESC LIMIT $2) x ORDER BY x.at, x.run_id`), []any{serviceID, limit},
		func(p *ResponsePoint) error {
			out = append(out, *p)
			return nil
		})
	return out, err
}
