-- The services list deep page and the ordered pass behind the services export,
-- before (group size counted per row) and after (one count per group, 1623497).
-- Measured on the 10 000-host database after run 1 (psql \timing):
--   deep page, offset 22 440:  13 211.9 ms -> 78.7 ms   (sum of group_size 186 900 both)
--   ordered pass, all rows:    11 939.9 ms -> 31.7 ms   (sum 161 881 088 both)
\timing on
SELECT sum(group_size) FROM (SELECT s.id, (CASE WHEN s.group_key = '' THEN 0 ELSE (SELECT count(*) FROM services g WHERE g.group_key = s.group_key) END) AS group_size, (SELECT o.at FROM service_observations o WHERE o.service_id = s.id ORDER BY o.at DESC, o.id DESC LIMIT 1) FROM services s ORDER BY (CASE WHEN s.state = 'open' THEN s.interest ELSE 0 END) DESC, s.interest DESC, s.ip, s.port LIMIT 50 OFFSET 22440) x;
SELECT sum(group_size) FROM (SELECT s.id, COALESCE(gs.n, 0) AS group_size, (SELECT o.at FROM service_observations o WHERE o.service_id = s.id ORDER BY o.at DESC, o.id DESC LIMIT 1) FROM services s LEFT JOIN (SELECT group_key, count(*) AS n FROM services WHERE group_key <> '' GROUP BY group_key) gs ON gs.group_key = s.group_key ORDER BY (CASE WHEN s.state = 'open' THEN s.interest ELSE 0 END) DESC, s.interest DESC, s.ip, s.port LIMIT 50 OFFSET 22440) x;
SELECT sum(group_size) FROM (SELECT s.id, (CASE WHEN s.group_key = '' THEN 0 ELSE (SELECT count(*) FROM services g WHERE g.group_key = s.group_key) END) AS group_size FROM services s ORDER BY s.ip, s.port, s.id) x;
SELECT sum(group_size) FROM (SELECT s.id, COALESCE(gs.n, 0) AS group_size FROM services s LEFT JOIN (SELECT group_key, count(*) AS n FROM services WHERE group_key <> '' GROUP BY group_key) gs ON gs.group_key = s.group_key ORDER BY s.ip, s.port, s.id) x;
