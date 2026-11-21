-- Czujka schema, version 1.
-- Every table is created with the access method that the migration runner
-- selected: tde_heap when pg_tde is active, heap otherwise ({{AM}} is replaced).

CREATE FUNCTION czujka_observed(overrides jsonb, field text, observed jsonb, has_value boolean DEFAULT true)
RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN overrides ? field AND has_value
              THEN jsonb_set(overrides, ARRAY[field, 'observed'], COALESCE(observed, 'null'::jsonb))
              ELSE overrides END
$$;

CREATE TABLE roles (
  id          BIGSERIAL PRIMARY KEY,
  slug        TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  builtin     BOOLEAN NOT NULL DEFAULT false,
  permissions TEXT[] NOT NULL DEFAULT '{}'
) {{AM}};

CREATE TABLE users (
  id            BIGSERIAL PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role_id       BIGINT NOT NULL REFERENCES roles(id),
  disabled      BOOLEAN NOT NULL DEFAULT false,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at TIMESTAMPTZ,
  failed_logins INT NOT NULL DEFAULT 0,
  locked_until  TIMESTAMPTZ
) {{AM}};
CREATE INDEX users_role_idx ON users(role_id);

CREATE TABLE sessions (
  token_hash BYTEA PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip         TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT ''
) {{AM}};
CREATE INDEX sessions_user_idx ON sessions(user_id);
CREATE INDEX sessions_expires_idx ON sessions(expires_at);

CREATE TABLE audit_log (
  id         BIGSERIAL PRIMARY KEY,
  at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id    BIGINT,
  user_email TEXT NOT NULL DEFAULT '',
  action     TEXT NOT NULL,
  entity     TEXT NOT NULL DEFAULT '',
  entity_id  TEXT NOT NULL DEFAULT '',
  detail     JSONB NOT NULL DEFAULT '{}',
  ip         TEXT NOT NULL DEFAULT ''
) {{AM}};
CREATE INDEX audit_at_idx ON audit_log(at DESC);
CREATE INDEX audit_user_idx ON audit_log(user_id, at DESC);
CREATE INDEX audit_action_idx ON audit_log(action, at DESC);
CREATE INDEX audit_entity_idx ON audit_log(entity, at DESC);

CREATE TABLE scopes (
  id          BIGSERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  owner       TEXT NOT NULL DEFAULT '',
  criticality INT NOT NULL DEFAULT 3,
  tags        TEXT[] NOT NULL DEFAULT '{}',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
) {{AM}};

CREATE TABLE targets (
  id         BIGSERIAL PRIMARY KEY,
  scope_id   BIGINT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,
  value      TEXT NOT NULL,
  note       TEXT NOT NULL DEFAULT '',
  tags       TEXT[] NOT NULL DEFAULT '{}',
  enabled    BOOLEAN NOT NULL DEFAULT true,
  source     TEXT NOT NULL DEFAULT 'manual',
  addresses  BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by BIGINT,
  UNIQUE (scope_id, value)
) {{AM}};

-- Global settings: the safety policy and integration settings.
-- "secret" holds field-level encrypted values (for example the DefectDojo API key).
CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value      JSONB NOT NULL DEFAULT '{}',
  secret     TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
) {{AM}};

CREATE TABLE scan_profiles (
  id           BIGSERIAL PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  scope_ids    BIGINT[] NOT NULL DEFAULT '{}',
  config       JSONB NOT NULL,
  enabled      BOOLEAN NOT NULL DEFAULT true,
  next_run_at  TIMESTAMPTZ,
  last_run_id  BIGINT,
  measured_pps DOUBLE PRECISION NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
) {{AM}};

CREATE TABLE runs (
  id           BIGSERIAL PRIMARY KEY,
  profile_id   BIGINT REFERENCES scan_profiles(id) ON DELETE SET NULL,
  profile_name TEXT NOT NULL DEFAULT '',
  status       TEXT NOT NULL,
  pause_reason TEXT NOT NULL DEFAULT '',
  trigger      TEXT NOT NULL DEFAULT 'manual',
  created_by   BIGINT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at   TIMESTAMPTZ,
  finished_at  TIMESTAMPTZ,
  window_end   TIMESTAMPTZ,
  resume_at    TIMESTAMPTZ,
  stats        JSONB NOT NULL DEFAULT '{}',
  summary      JSONB,
  error        TEXT NOT NULL DEFAULT '',
  import_file  TEXT NOT NULL DEFAULT ''
) {{AM}};
CREATE INDEX runs_profile_idx ON runs(profile_id, id DESC);
CREATE INDEX runs_status_idx ON runs(status);
-- One active run per profile, enforced by the database.
CREATE UNIQUE INDEX runs_one_active_per_profile ON runs(profile_id)
  WHERE profile_id IS NOT NULL AND status IN ('queued', 'running', 'analyzing', 'paused');

CREATE TABLE chunks (
  id          BIGSERIAL PRIMARY KEY,
  run_id      BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  seq         INT NOT NULL,
  spec        TEXT[] NOT NULL DEFAULT '{}',
  size        INT NOT NULL DEFAULT 0,
  priority    INT NOT NULL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT 'pending',
  started_at  TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  duration_ms BIGINT NOT NULL DEFAULT 0,
  hosts_up    INT NOT NULL DEFAULT 0,
  pps         DOUBLE PRECISION NOT NULL DEFAULT 0,
  error       TEXT NOT NULL DEFAULT '',
  UNIQUE (run_id, seq)
) {{AM}};

CREATE TABLE hosts (
  id                 BIGSERIAL PRIMARY KEY,
  ip                 INET NOT NULL UNIQUE,
  hostnames          TEXT[] NOT NULL DEFAULT '{}',
  scope_ids          BIGINT[] NOT NULL DEFAULT '{}',
  status             TEXT NOT NULL DEFAULT 'unknown',
  p_alive            DOUBLE PRECISION NOT NULL DEFAULT 1,
  stability          DOUBLE PRECISION NOT NULL DEFAULT 1,
  consecutive_misses INT NOT NULL DEFAULT 0,
  pattern            TEXT NOT NULL DEFAULT '',
  first_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen          TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_up            TIMESTAMPTZ,
  os_guess           TEXT NOT NULL DEFAULT '',
  mac                TEXT NOT NULL DEFAULT '',
  vendor             TEXT NOT NULL DEFAULT '',
  label              TEXT NOT NULL DEFAULT '',
  owner              TEXT NOT NULL DEFAULT '',
  criticality        INT NOT NULL DEFAULT 0,
  note_enc           TEXT NOT NULL DEFAULT '',   -- field-level encrypted
  tags               TEXT[] NOT NULL DEFAULT '{}',
  interest           INT NOT NULL DEFAULT 0,
  service_count      INT NOT NULL DEFAULT 0,
  open_ports         INT[] NOT NULL DEFAULT '{}',
  technologies       TEXT[] NOT NULL DEFAULT '{}',
  overrides          JSONB NOT NULL DEFAULT '{}',
  source             TEXT NOT NULL DEFAULT 'scan',
  obs_total          INT NOT NULL DEFAULT 0,
  obs_up             INT NOT NULL DEFAULT 0,
  last_run_id        BIGINT
) {{AM}};
CREATE INDEX hosts_status_idx ON hosts(status);
CREATE INDEX hosts_interest_idx ON hosts(interest DESC);
CREATE INDEX hosts_last_seen_idx ON hosts(last_seen DESC);
CREATE INDEX hosts_tags_idx ON hosts USING gin(tags);
CREATE INDEX hosts_scopes_idx ON hosts USING gin(scope_ids);
CREATE INDEX hosts_ports_idx ON hosts USING gin(open_ports);
CREATE INDEX hosts_tech_idx ON hosts USING gin(technologies);

CREATE TABLE host_observations (
  id       BIGSERIAL PRIMARY KEY,
  host_id  BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  run_id   BIGINT NOT NULL,
  at       TIMESTAMPTZ NOT NULL,
  up       BOOLEAN NOT NULL,
  rtt_ms   DOUBLE PRECISION NOT NULL DEFAULT 0,
  attempts INT NOT NULL DEFAULT 1,
  reason   TEXT NOT NULL DEFAULT ''
) {{AM}};
CREATE INDEX host_obs_host_idx ON host_observations(host_id, at DESC);
CREATE INDEX host_obs_run_idx ON host_observations(run_id, host_id);

-- The 168-bucket hour-of-week availability histogram (bucket = weekday*24 + hour).
CREATE TABLE host_availability (
  host_id BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  bucket  SMALLINT NOT NULL,
  up      INT NOT NULL DEFAULT 0,
  down    INT NOT NULL DEFAULT 0,
  PRIMARY KEY (host_id, bucket)
) {{AM}};

CREATE TABLE services (
  id             BIGSERIAL PRIMARY KEY,
  host_id        BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  ip             INET NOT NULL,
  hostname       TEXT NOT NULL DEFAULT '',
  port           INT NOT NULL,
  proto          TEXT NOT NULL DEFAULT 'tcp',
  state          TEXT NOT NULL DEFAULT 'open',
  name           TEXT NOT NULL DEFAULT '',
  product        TEXT NOT NULL DEFAULT '',
  version        TEXT NOT NULL DEFAULT '',
  banner         TEXT NOT NULL DEFAULT '',
  confidence     DOUBLE PRECISION NOT NULL DEFAULT 0,
  tls            BOOLEAN NOT NULL DEFAULT false,
  title          TEXT NOT NULL DEFAULT '',
  http_status    INT NOT NULL DEFAULT 0,
  url            TEXT NOT NULL DEFAULT '',
  technologies   JSONB NOT NULL DEFAULT '[]',
  tech_names     TEXT[] NOT NULL DEFAULT '{}',
  classes        TEXT[] NOT NULL DEFAULT '{}',
  interest       INT NOT NULL DEFAULT 0,
  interest_why   JSONB NOT NULL DEFAULT '[]',
  group_key      TEXT NOT NULL DEFAULT '',
  note_enc       TEXT NOT NULL DEFAULT '',   -- field-level encrypted
  tags           TEXT[] NOT NULL DEFAULT '{}',
  first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_changed   TIMESTAMPTZ,
  overrides      JSONB NOT NULL DEFAULT '{}',
  obs_hash       TEXT NOT NULL DEFAULT '',
  last_run_id    BIGINT,
  cert_not_after TIMESTAMPTZ,
  UNIQUE (host_id, port, proto)
) {{AM}};
CREATE INDEX services_port_idx ON services(port);
CREATE INDEX services_state_idx ON services(state);
CREATE INDEX services_name_idx ON services(name);
CREATE INDEX services_interest_idx ON services(interest DESC);
CREATE INDEX services_group_idx ON services(group_key);
CREATE INDEX services_run_idx ON services(last_run_id);
CREATE INDEX services_cert_idx ON services(cert_not_after) WHERE cert_not_after IS NOT NULL;
CREATE INDEX services_tags_idx ON services USING gin(tags);
CREATE INDEX services_classes_idx ON services USING gin(classes);
CREATE INDEX services_tech_idx ON services USING gin(tech_names);

-- One row per service per run. "result" is the full ServiceResult without its
-- sensitive parts; "secret" holds those parts (raw cookie values, body
-- excerpts, evidence snippets) with field-level encryption.
CREATE TABLE service_observations (
  id          BIGSERIAL PRIMARY KEY,
  service_id  BIGINT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  host_id     BIGINT NOT NULL,
  run_id      BIGINT NOT NULL,
  at          TIMESTAMPTZ NOT NULL,
  state       TEXT NOT NULL DEFAULT 'open',
  name        TEXT NOT NULL DEFAULT '',
  product     TEXT NOT NULL DEFAULT '',
  version     TEXT NOT NULL DEFAULT '',
  title       TEXT NOT NULL DEFAULT '',
  http_status INT NOT NULL DEFAULT 0,
  tls         BOOLEAN NOT NULL DEFAULT false,
  result      JSONB NOT NULL,
  secret      TEXT NOT NULL DEFAULT ''
) {{AM}};
CREATE INDEX service_obs_service_idx ON service_observations(service_id, at DESC);
CREATE INDEX service_obs_run_idx ON service_observations(run_id, host_id);

CREATE TABLE technologies (
  service_id BIGINT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  host_id    BIGINT NOT NULL,
  name       TEXT NOT NULL,
  category   TEXT NOT NULL DEFAULT '',
  version    TEXT NOT NULL DEFAULT '',
  confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
  cpe        TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (service_id, name)
) {{AM}};
CREATE INDEX technologies_name_idx ON technologies(name);
CREATE INDEX technologies_host_idx ON technologies(host_id);

CREATE TABLE changes (
  id          BIGSERIAL PRIMARY KEY,
  run_id      BIGINT NOT NULL,
  prev_run_id BIGINT,
  at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind        TEXT NOT NULL,
  severity    TEXT NOT NULL DEFAULT 'info',
  host_id     BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  ip          INET,
  service_id  BIGINT REFERENCES services(id) ON DELETE SET NULL,
  port        INT NOT NULL DEFAULT 0,
  summary     TEXT NOT NULL DEFAULT '',
  field       TEXT NOT NULL DEFAULT '',
  before      JSONB,
  after       JSONB,
  expected    BOOLEAN NOT NULL DEFAULT false,
  acked_by    TEXT NOT NULL DEFAULT '',
  acked_at    TIMESTAMPTZ
) {{AM}};
CREATE INDEX changes_run_idx ON changes(run_id);
CREATE INDEX changes_at_idx ON changes(at DESC);
CREATE INDEX changes_host_idx ON changes(host_id, at DESC);
CREATE INDEX changes_kind_idx ON changes(kind);
CREATE INDEX changes_unacked_idx ON changes(at DESC) WHERE acked_at IS NULL;

CREATE TABLE findings (
  id           BIGSERIAL PRIMARY KEY,
  key          TEXT NOT NULL UNIQUE,
  type         TEXT NOT NULL DEFAULT '',
  title        TEXT NOT NULL DEFAULT '',
  description  TEXT NOT NULL DEFAULT '',
  severity     TEXT NOT NULL DEFAULT 'info',
  status       TEXT NOT NULL DEFAULT 'new',
  interest     INT NOT NULL DEFAULT 0,
  host_id      BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  ip           INET,
  service_id   BIGINT REFERENCES services(id) ON DELETE SET NULL,
  port         INT NOT NULL DEFAULT 0,
  url          TEXT NOT NULL DEFAULT '',
  signature    TEXT NOT NULL DEFAULT '',
  evidence_enc TEXT NOT NULL DEFAULT '',   -- field-level encrypted JSON
  note_enc     TEXT NOT NULL DEFAULT '',   -- field-level encrypted
  tags         TEXT[] NOT NULL DEFAULT '{}',
  assignee     TEXT NOT NULL DEFAULT '',
  first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
  first_run_id BIGINT NOT NULL DEFAULT 0,
  last_run_id  BIGINT NOT NULL DEFAULT 0,
  overrides    JSONB NOT NULL DEFAULT '{}',
  dojo_id      BIGINT,
  dojo_url     TEXT NOT NULL DEFAULT '',
  manual       BOOLEAN NOT NULL DEFAULT false
) {{AM}};
CREATE INDEX findings_status_idx ON findings(status);
CREATE INDEX findings_severity_idx ON findings(severity);
CREATE INDEX findings_type_idx ON findings(type);
CREATE INDEX findings_host_idx ON findings(host_id);
CREATE INDEX findings_interest_idx ON findings(interest DESC);
CREATE INDEX findings_first_run_idx ON findings(first_run_id);
CREATE INDEX findings_tags_idx ON findings USING gin(tags);

CREATE TABLE signatures (
  id          BIGSERIAL PRIMARY KEY,
  slug        TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL DEFAULT '',
  category    TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  yaml        TEXT NOT NULL,
  enabled     BOOLEAN NOT NULL DEFAULT true,
  builtin     BOOLEAN NOT NULL DEFAULT false,
  author      TEXT NOT NULL DEFAULT '',
  tags        TEXT[] NOT NULL DEFAULT '{}',
  interest    INT NOT NULL DEFAULT 0,
  match_count INT NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
) {{AM}};
CREATE INDEX signatures_category_idx ON signatures(category);
CREATE INDEX signatures_tags_idx ON signatures USING gin(tags);

-- Registry of tag names that analysts used. Counts come from the tagged rows.
CREATE TABLE tags (
  name       TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
) {{AM}};
