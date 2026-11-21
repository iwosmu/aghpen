-- The rotating deep pass (scan.deepPass): when a run last scanned every TCP
-- port of a host, the run whose deep pass scanned a service, and the
-- changes of such services ("found by the deeper pass").
ALTER TABLE hosts ADD COLUMN deep_scan_at TIMESTAMPTZ;
ALTER TABLE services ADD COLUMN deep_run_id BIGINT;
ALTER TABLE changes ADD COLUMN deep_pass BOOLEAN NOT NULL DEFAULT false;
