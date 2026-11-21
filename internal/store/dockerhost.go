package store

import "context"

// DockerHostLabel is the label of the docker host when loopback targets are
// scanned through the host gateway (targets.HostGateway). It is set only
// when the host has no label, so an analyst's label wins.
const DockerHostLabel = "Host dockera (ten komputer)"

// SelfTag is the tag of the service that is Czujka itself: its UI on the
// port the docker host publishes it on. The service stays visible; the
// analysis derives no finding from it.
const SelfTag = "czujka"

// MarkDockerHost names the host the loopback targets were scanned as (label
// and the hostname "localhost") and tags Czujka's own service on selfPort
// (title "Czujka"). It returns the ids of the services with the tag.
func (s *Store) MarkDockerHost(ctx context.Context, hostID int64, selfPort int) ([]int64, error) {
	if _, err := s.db.Exec(ctx, `UPDATE hosts SET label = CASE WHEN label = '' THEN $2 ELSE label END,
		hostnames = CASE WHEN 'localhost' = ANY(hostnames) THEN hostnames ELSE array_prepend('localhost', hostnames) END
		WHERE id = $1 AND (label = '' OR NOT 'localhost' = ANY(hostnames))`, hostID, DockerHostLabel); err != nil {
		return nil, mapErr(err)
	}
	if selfPort <= 0 {
		return nil, nil
	}
	if _, err := s.db.Exec(ctx, `UPDATE services SET tags = array_append(tags, $3)
		WHERE host_id = $1 AND port = $2 AND proto = 'tcp' AND title ILIKE '%czujka%' AND NOT $3 = ANY(tags)`, hostID, selfPort, SelfTag); err != nil {
		return nil, mapErr(err)
	}
	rows, err := s.db.Query(ctx, `SELECT id FROM services WHERE host_id = $1 AND $2 = ANY(tags)`, hostID, SelfTag)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, mapErr(rows.Err())
}
