// Mirror of internal/model/types.go. The JSON tags there are the wire format.
// Keep this file in step with the Go types; do not rename a field here alone.

export type Permission =
  | 'targets:read' | 'targets:create' | 'targets:update' | 'targets:delete'
  | 'scans:read' | 'scans:run' | 'scans:configure'
  | 'results:read' | 'results:update' | 'results:create' | 'results:delete'
  | 'signatures:read' | 'signatures:create' | 'signatures:update' | 'signatures:delete'
  | 'export:run' | 'integrations:manage' | 'safety:manage' | 'safety:stop'
  | 'users:manage' | 'roles:manage' | 'audit:read';

export const ALL_PERMISSIONS: Permission[] = [
  'targets:read', 'targets:create', 'targets:update', 'targets:delete',
  'scans:read', 'scans:run', 'scans:configure',
  'results:read', 'results:update', 'results:create', 'results:delete',
  'signatures:read', 'signatures:create', 'signatures:update', 'signatures:delete',
  'export:run', 'integrations:manage', 'safety:manage', 'safety:stop',
  'users:manage', 'roles:manage', 'audit:read',
];

export interface PermissionInfo { permission: Permission; group: string; label_pl: string; label_en: string }

export interface Role {
  id: number; slug: string; name: string; description: string; builtin: boolean;
  permissions: Permission[]; user_count: number;
}

export interface User {
  id: number; email: string; name: string; role_id: number; role_slug: string; role_name: string;
  disabled: boolean; created_at: string; last_login_at: string | null;
}

export interface Session { user: User; permissions: Permission[]; csrf_token: string }

export interface AuditEntry {
  id: number; at: string; user_id: number | null; user_email: string; action: string;
  entity: string; entity_id: string; detail: Record<string, unknown> | null; ip: string;
}

export type TargetKind = 'ip' | 'cidr' | 'range' | 'domain';

export interface Scope {
  id: number; name: string; description: string; owner: string; criticality: number; tags: string[];
  target_count: number; address_count: number; created_at: string; updated_at: string;
}

export interface Target {
  id: number; scope_id: number; kind: TargetKind; value: string; note: string; tags: string[];
  enabled: boolean; source: string; addresses: number; created_at: string; created_by: number | null;
  /** the address a loopback target (localhost, 127.0.0.1) is scanned as, e.g. the docker host; absent = scanned as written */
  maps_to?: string;
}

export interface InvalidLine { line: number; value: string; reason: string }

export interface TargetPreview {
  valid: Target[]; invalid: InvalidLine[]; duplicates: number; excluded: number; address_count: number;
}

export interface SafetyPolicy {
  max_pps: number; max_http_rps: number; max_per_host_rps: number; max_paths_per_host: number;
  allowed_ports: string; denied_ports: string; exclusions: string[]; allowed_methods: string[];
  emergency_stop: boolean; user_agent: string; updated_at: string;
  allowed_networks?: string[] | null;
  /** Operator lock (CZUJKA_ALLOWED_NETWORKS), read only; empty = no lock. */
  operator_networks?: string[] | null;
}

export interface DiscoveryOpts {
  icmp_echo: boolean; icmp_timestamp: boolean; tcp_syn_ports: number[]; tcp_ack_ports: number[];
  arp: boolean; skip_discovery: boolean;
  /** fast | balanced | thorough; empty means balanced. */
  mode: DiscoveryMode | '';
}
export type DiscoveryMode = 'fast' | 'balanced' | 'thorough';
/** Optional UDP scan of a short allow-list of harmless protocol queries. */
export interface UDPOpts { enabled: boolean; ports: string }
export interface HTTPOpts {
  enabled: boolean; max_redirects: number; signature_paths: boolean; max_body_bytes: number;
  timeout_ms: number; favicon: boolean;
}
export interface RateLimits {
  max_pps: number; max_parallel_chunks: number; max_parallel_hosts: number; http_rps: number;
  per_host_concurrency: number; per_host_delay_ms: number;
}
export interface ChunkingOpts { adaptive: boolean; initial_size: number; min_size: number; max_size: number; target_seconds: number }
export interface RetryOpts { unstable_retries: number; backoff_ms: number; /** 0 = the availability model decides. */ down_after_misses: number }
/** Days use 0 = Sunday .. 6 = Saturday. End before Start crosses midnight. */
export interface Window { days: number[]; start: string; end: string }
export interface Schedule { enabled: boolean; cron: string; interval_minutes: number; windows: Window[]; timezone: string }

export interface ScanProfile {
  id: number; name: string; description: string; scope_ids: number[]; ports: string;
  discovery: DiscoveryOpts; service_detection: boolean; version_intensity: number; http: HTTPOpts;
  udp: UDPOpts; rate: RateLimits; chunking: ChunkingOpts; retry: RetryOpts; schedule: Schedule; enabled: boolean;
  next_run_at: string | null; last_run_id: number | null; created_at: string; updated_at: string;
}

export interface ScanEstimate {
  addresses: number; chunks: number; est_packets: number; est_duration_sec: number; effective_pps: number;
  fits_window: boolean; window_sec: number; based_on_history: boolean; expected_live_rate: number;
  discovery_mode?: string;
}

export type RunStatus = 'queued' | 'running' | 'paused' | 'analyzing' | 'completed' | 'failed' | 'cancelled';

export interface RunStats {
  addresses_total: number; addresses_done: number; chunks_total: number; chunks_done: number;
  hosts_up: number; services_open: number; http_services: number; packets_sent: number; http_requests: number;
  current_pps: number; avg_pps: number; elapsed_sec: number; eta_sec: number; retried: number; errors: number;
  /** The part of packets_sent that is an estimate (a stage whose nmap output had no count). */
  packets_estimated?: number;
  /** measured: exact counts of finished stages; pace: includes the pinned nmap pace of running stages. */
  current_pps_basis?: 'measured' | 'pace' | '';
  /** engine sanity checks that failed: the run ended, but its result is not complete (Polish text) */
  warnings?: string[]; ports_unknown?: number;
  /** facts about coverage, not failed checks (Polish text), e.g. the full-range host budget */
  notes?: string[];
  /** port passes of a staged run (top ports, then the full range); absent = one pass */
  passes?: RunPass[];
}

export interface RunPass {
  name: 'top_ports' | 'full_range' | 'dense' | string; state: 'pending' | 'running' | 'done' | 'skipped' | string;
  hosts: number; ports_total: number; ports_done: number;
  /** live hosts the pass did not cover (full_range over its host budget) */
  hosts_skipped?: number;
}

export interface RunDiffSummary {
  prev_run_id: number | null; hosts_new: number; hosts_gone: number; hosts_back: number; hosts_unstable: number;
  services_new: number; services_gone: number; services_changed: number;
  /** Silent hosts that are not reported inactive yet, and their open services. */
  hosts_missing?: number; services_unreachable?: number; by_kind: Record<string, number> | null;
  findings_new: number;
  /** services open again after a gone run (service_returned), services that answer slower (response_slower) */
  services_returned?: number; responses_slower?: number;
}

/** GET /services/{id}/response-times: one point per run, oldest first; ms null = HTTP did not answer. */
export interface ResponseTimes {
  service_id: number; rule: { baseline_n: number; slow_factor: number; slow_min_ms: number };
  points: { run_id: number; at: string; ms: number | null; baseline_ms: number | null; slow: boolean }[];
}

export interface ScanRun {
  id: number; profile_id: number | null; profile_name: string; status: RunStatus; pause_reason: string;
  trigger: string; created_by: number | null; created_at: string; started_at: string | null;
  finished_at: string | null; window_end: string | null; resume_at: string | null; stats: RunStats;
  summary: RunDiffSummary | null; error: string; import_file: string;
  note?: string; label?: string; ad_hoc?: AdHocScope | null;
}
export interface AdHocScope { profile_id: number; addresses: string[]; ports: string; reason: string }

export type ChunkStatus = 'pending' | 'running' | 'done' | 'deferred' | 'failed';

export interface Chunk {
  id: number; run_id: number; seq: number; spec: string[]; size: number; priority: number; status: ChunkStatus;
  started_at: string | null; finished_at: string | null; duration_ms: number; hosts_up: number; pps: number; error: string;
  /** Seq of the first chunk of the adaptive work group; 0 = not started. */
  group?: number;
}

export interface MapBlock { cidr: string; size: number; status: ChunkStatus; hosts_up: number }
export interface RunMap { blocks: MapBlock[] }

export interface Cookie {
  name: string; domain: string; path: string; secure: boolean; http_only: boolean; same_site: string;
  value_len: number; value_hash: string; value?: string;
}
export interface Redirect { from: string; to: string; status: number }
export interface PathProbe {
  path: string; status: number; title: string; length: number; body_sha256: string; excerpt: string;
  headers: Record<string, string[]> | null; location: string;
}
export interface HTTPFingerprint {
  scheme: string; url: string; final_url: string; host: string; status: number; title: string;
  headers: Record<string, string[]> | null; cookies: Cookie[] | null; redirects: Redirect[] | null;
  server: string; powered_by: string; meta_generator: string; body_length: number; body_sha256: string;
  body_simhash: string; body_excerpt: string; favicon_mmh3: number | null; favicon_sha256: string;
  paths: PathProbe[] | null; response_ms: number; error: string;
}
export interface TLSInfo {
  version: string; cipher: string; subject_cn: string; subject_org: string; sans: string[] | null; issuer: string;
  not_before: string; not_after: string; serial: string; sha256: string; self_signed: boolean; expired: boolean;
  days_left: number; host_mismatch: boolean; key_type: string; key_bits: number;
}
export interface Evidence { matcher: string; where: string; snippet: string }
export interface SigMatch {
  signature: string; name: string; category: string; version: string; confidence: number; interest: number;
  classes: string[] | null; tags: string[] | null; evidence: Evidence[] | null;
}
export interface Technology { name: string; category: string; version: string; confidence: number; sources: string[] | null; cpe: string }

export interface ServiceResult {
  port: number; proto: string; state: string; name: string; product: string; version: string; extra_info: string;
  cpe: string[] | null; banner: string; tunnel: string; confidence: number; http: HTTPFingerprint | null;
  tls: TLSInfo | null; matches: SigMatch[] | null; technologies: Technology[] | null; classes: string[] | null;
}

export type HostStatus = 'up' | 'unstable' | 'down' | 'expected-offline' | 'unknown';

export interface Override { value: unknown; observed: unknown; by: string; at: string }

export interface Host {
  id: number; ip: string; hostnames: string[] | null; scope_ids: number[] | null; status: HostStatus;
  p_alive: number; stability: number; consecutive_misses: number; pattern: string; first_seen: string;
  last_seen: string; last_up: string | null; os_guess: string; mac: string; vendor: string; label: string;
  owner: string; criticality: number; note: string; tags: string[] | null; interest: number;
  service_count: number; open_ports: number[] | null; technologies: string[] | null;
  overrides: Record<string, Override> | null; source: string;
}

export interface AvailBucket { up: number; down: number }
export interface HostObservation { run_id: number; at: string; up: boolean; rtt_ms: number; attempts: number; reason: string }
/** buckets index = weekday*24 + hour, weekday 0 = Sunday. */
export interface AvailabilityProfile {
  host_id: number; buckets: AvailBucket[]; recent: HostObservation[] | null; pattern: string;
  p_alive: number; down_after_misses: number;
}

export type ServiceState = 'open' | 'gone' | 'unknown' | 'filtered';
export interface InterestReason { code: string; points: number; text: string }

export interface Service {
  id: number; host_id: number; ip: string; hostname: string; port: number; proto: string; state: ServiceState;
  name: string; product: string; version: string; banner: string; confidence: number; tls: boolean; title: string;
  http_status: number; url: string; technologies: Technology[] | null; classes: string[] | null; interest: number;
  interest_why: InterestReason[] | null; group_key: string; group_size: number; note: string; tags: string[] | null;
  first_seen: string; last_seen: string; last_changed: string | null; overrides: Record<string, Override> | null;
  latest?: ServiceObservation | null;
  /** latest HTTP response time (ms); null: not HTTP or no answer. Optional: older servers do not send it. */
  response_ms?: number | null; response_slow?: boolean;
}
export interface ServiceObservation { id: number; service_id: number; run_id: number; at: string; result: ServiceResult }
export interface ServiceGroup {
  key: string; label: string; count: number; technologies: string[] | null; title: string;
  sample_ids: number[] | null; interest: number;
}

export type ChangeKind =
  | 'host_new' | 'host_gone' | 'host_back' | 'host_unstable' | 'host_missing' | 'service_new' | 'service_gone' | 'service_changed'
  | 'tech_new' | 'tech_gone' | 'tech_version' | 'title_changed' | 'status_changed' | 'cert_changed'
  | 'headers_changed' | 'cookies_changed' | 'content_changed' | 'redirect_changed' | 'class_changed'
  | 'service_returned' | 'response_slower' | 'response_recovered';

export type Severity = 'info' | 'low' | 'medium' | 'high';

export interface Change {
  id: number; run_id: number; prev_run_id: number | null; at: string; kind: ChangeKind; severity: Severity;
  host_id: number; ip: string; service_id: number | null; port: number; summary: string; field: string;
  before: unknown; after: unknown; expected: boolean; acked_by: string; acked_at: string | null;
}

export interface DiffReport { from: ScanRun; to: ScanRun; summary: RunDiffSummary; changes: Change[] | null }

export type FindingStatus = 'new' | 'triaged' | 'accepted' | 'false_positive' | 'resolved';

export interface Finding {
  id: number; key: string; type: string; title: string; description: string; severity: Severity;
  status: FindingStatus; interest: number; host_id: number; ip: string; service_id: number | null; port: number;
  url: string; signature: string; evidence: Evidence[] | null; note: string; tags: string[] | null; assignee: string;
  first_seen: string; last_seen: string; first_run_id: number; last_run_id: number;
  overrides: Record<string, Override> | null; dojo_id: number | null; dojo_url: string; manual: boolean;
}

export interface Signature {
  id: number; slug: string; name: string; category: string; description: string; yaml: string; enabled: boolean;
  builtin: boolean; author: string; tags: string[] | null; interest: number; match_count: number;
  created_at: string; updated_at: string;
}
export interface SignatureIssue { level: 'error' | 'warning' | string; path: string; message: string; safety: boolean }
export interface SignatureValidation { ok: boolean; issues: SignatureIssue[] | null; paths: string[] | null }
export interface RetroHit { service_id: number; ip: string; port: number; url: string; run_id: number; at: string; match: SigMatch }
export interface RetroHuntResult {
  scanned: number; hits: RetroHit[] | null; took_ms: number; packets_sent: number;
  missing_paths?: string[] | null; incomplete?: number; notes?: string[] | null; total_hits?: number; truncated?: boolean;
}
export interface SignatureImportReport {
  created: string[] | null; updated: string[] | null; skipped: { slug: string; reason: string }[] | null;
  validation: SignatureValidation;
}

export interface DefectDojoSettings {
  enabled: boolean; url: string; api_key?: string; api_key_set: boolean; product_name: string;
  engagement_name: string; product_type_name: string; verify_tls: boolean; auto_export: boolean; min_interest: number;
  status_sync?: boolean; scope_mappings?: DojoScopeMapping[] | null;
  /** Public base for links to DefectDojo (dojo_url); present once the server supports it. */
  link_url?: string;
}
export interface DojoScopeMapping { scope_id: number; product_type_name: string; product_name: string; engagement_name: string }
export interface DojoPullUpdate { finding_id: number; key: string; dojo_id: number; from: string; to: string; dojo_changed_at: string | null; reason: string }
export interface DojoPullConflict { finding_id: number; key: string; dojo_id: number; local: string; remote: string; reason: string }
export interface DojoPullResult { checked: number; updates: DojoPullUpdate[] | null; conflicts: DojoPullConflict[] | number | null; missing: unknown; errors: unknown; applied: number; linked?: number }
export interface DojoSyncResult { closed: number; reopened: number; skipped: number; errors: unknown }
export interface FindingsImportReport { format: string; findings: number; skipped: number; invalid: InvalidLine[] | null; created: number; updated: number; hosts_created: number; run_id: number | null }
export interface ManualEntryResult { run: ScanRun; host: Host }
export interface DojoTestResult { ok: boolean; message: string; version: string }
export interface DojoExportResult { exported: number; updated: number; failed: number; test_id: number; test_url: string; errors: string[] | null }
export interface ImportReport {
  format: string; run_id: number | null; hosts: number; services: number; targets: number; skipped: number;
  invalid: InvalidLine[] | null; hosts_down?: number;
}

export interface CountPoint { at: string; run_id: number; hosts: number; services: number; changes: number; findings: number }
export interface NameCount { name: string; count: number; extra?: string }

export interface Headline {
  addresses_in_scope: number; hosts_up: number; hosts_unstable: number; hosts_down: number; services_open: number;
  web_services: number; findings_open: number; findings_high: number; changes_unacked: number;
  new_since_last_run: number; gone_since_last_run: number; admin_panels: number; staging_envs: number;
  hosts_missing?: number;
}

export interface Dashboard {
  generated_at: string; headline: Headline; last_run: ScanRun | null; active_run: ScanRun | null;
  next_run_at: string | null; top_findings: Finding[] | null; recent_changes: Change[] | null;
  top_services: Service[] | null; technologies: NameCount[] | null; ports: NameCount[] | null;
  classes: NameCount[] | null; trend: CountPoint[] | null; unstable_hosts: Host[] | null;
  certs_expiring: Service[] | null; safety: SafetyPolicy;
}

export interface Page<T> { items: T[]; total: number; limit: number; offset: number }
export interface ProbeInfo { prober: string; mode: 'nmap-raw' | 'nmap-connect' | 'native' | string; raw_sockets: boolean }
export interface Health {
  status: string; version: string; db: string; tde: string; tde_detail?: string; field_encryption?: boolean;
  engine?: boolean; probe?: ProbeInfo;
  /** the docker host a loopback target maps to; '' = no mapping (loopback is this machine); absent = older server */
  host_gateway?: string;
}

// Passive sources (internal/passive). Nothing is sent to a scope address.
export interface PassiveFact {
  hostname?: string; ip?: string; port?: number; kind: string; target?: string; source: string; sensor?: string;
  first_seen?: string; last_seen?: string; count?: number; wildcard?: boolean;
}
export interface PassiveCandidate {
  kind: TargetKind; value: string; hostnames?: string[]; ports?: number[]; sources: string[]; last_seen?: string; reason: string;
}
export interface PassiveHint { ip: string; hostnames: string[]; ports?: number[]; sources: string[]; known: boolean }
export interface PassiveSourceReport { name: string; external: boolean; facts: number; skipped: boolean; error?: string }
export interface PassiveFileReport { format: string; records: number; facts: number; skipped: number; invalid_total: number; invalid: InvalidLine[] | null }
export interface PassiveResult {
  facts: PassiveFact[] | null; out_of_scope: PassiveFact[] | null; candidates: PassiveCandidate[] | null;
  hints: PassiveHint[] | null; sources: PassiveSourceReport[] | null; file?: PassiveFileReport; hosts_updated?: number;
}
export interface PassiveSettings { crtsh_enabled: boolean }
export interface HostEvent { ip: string; up: boolean; services: number }

// ---------- time machine and re-probing (docs/API-time.md) ----------
export interface RunPoint {
  run_id: number; at: string; trigger: string; status: string; profile_name: string;
  hosts_up: number; hosts_missing: number; hosts_down: number; services_open: number; services_unknown: number; findings_open: number;
  probed: number; probed_up: number; changes: number; changes_expected: number; changes_by_kind: Record<string, number> | null;
}
export interface Timeline { runs: RunPoint[]; from: string; to: string; took_ms: number }
export interface AtHost { id: number; ip: string; hostnames: string[]; label: string; status: string; up: boolean; observed_at: string; run_id: number; status_now: string; open_ports: number[] }
export interface AtService {
  id: number; host_id: number; ip: string; port: number; proto: string; state: string; name: string; product: string; version: string;
  title: string; http_status: number; tls: boolean; technologies: string[]; classes: string[]; observed_at: string; run_id: number; state_now: string; changed_since: boolean;
}
export interface AtFinding { id: number; key: string; type: string; title: string; severity: string; interest: number; host_id: number; ip: string; port: number; first_seen: string; last_seen: string; first_run_id: number; last_run_id: number; status_now: string }
export interface DiffToNow {
  services_gone_since: number; services_new_since: number; services_changed: number; hosts_down_since: number; hosts_up_since: number;
  hosts_new_since: number; findings_opened_since: number; findings_closed_since: number; sentences: string[];
}
export interface SnapshotSummary {
  hosts_up: number; hosts_missing: number; hosts_down: number; services_open: number; services_unknown: number; findings_open: number;
  findings_by_severity: Record<string, number> | null; diff_to_now: DiffToNow;
}
export interface Snapshot { run: RunPoint; summary: SnapshotSummary; hosts: Page<AtHost>; services: Page<AtService>; findings: Page<AtFinding>; took_ms: number }
export interface LifeInterval { state: string; status: string; from: string; to: string; from_run: number; to_run: number; observations: number; ongoing: boolean }
export interface ServiceLane { service_id: number; port: number; proto: string; name: string; state_now: string; intervals: LifeInterval[]; versions: { at: string; run_id: number; before: string; after: string }[] | null }
export interface HostLife { host_id: number; ip: string; status_now: string; first_seen: string; last_seen: string; host: LifeInterval[]; services: ServiceLane[] }
export interface FieldHistory { field: string; values: { value: string; from: string; to: string; from_run: number; to_run: number; observations: number }[] }
export interface ServiceHistory { service_id: number; host_id: number; ip: string; port: number; proto: string; observations: number; changed: FieldHistory[]; unchanged: Record<string, string> | null }
export interface ReprobeSettings { enabled: boolean; budget_per_hour: number; backoff_minutes: number[]; likely_up_rate: number; max_ports_per_host: number }
export interface ReprobeProbe { host_id: number; ip: string; ports: number[] | string | null; not_before: string; kind: 'confirm' | 'likely-up'; step: number; steps: number; reason: string; profile_id: number }
export interface ReprobeSkip { host_id: number; ip: string; reason: string }
export interface ReprobePlan {
  generated_at: string; enabled: boolean; blocked: string; budget_per_hour: number; used_last_hour: number; due_now: number;
  active_reprobe: unknown; probes: ReprobeProbe[] | null; skipped: ReprobeSkip[] | null; settings: ReprobeSettings;
}

// ---------- exposure rules and signature suggest (docs/API-policy.md) ----------
export interface ExposureRule {
  id: number; slug: string; name: string; severity: string; description: string; yaml: string; enabled: boolean; builtin: boolean;
  author: string; violations: number; last_eval_at: string | null; created_at: string; updated_at: string;
}
export interface RuleIssue { level: string; path: string; message: string; safety: boolean }
export interface RuleValidation { ok: boolean; issues: RuleIssue[] }
export interface RuleViolation {
  rule: string; rule_name: string; severity: string; subject: string; key: string; host_id: number; ip: string; service_id: number;
  port: number; proto: string; url: string; title: string; summary: string; interest: number; storable: boolean;
}
export interface RuleDryRun { validation: RuleValidation; total: number; truncated: boolean; hosts: number; services: number; took_ms: number; condition: string; message: string; violations: RuleViolation[] | null }
export interface SuggestRule { kind: string; feature: string; rule: string; weight: number; df: number; others: number; explanation: string }
export interface Suggestion {
  ok: boolean; message: string; service_id: number; target: string; slug: string; name: string; yaml: string;
  rules: SuggestRule[] | null; rejected: { kind: string; value: string; reason: string }[] | null;
  validation: { ok: boolean; issues: RuleIssue[] } | null;
  retro_hunt: { scanned: number; total_hits: number; packets_sent: number; hits: unknown[] | null } | null;
  matches_target: boolean; other_matches: number; took_ms: number;
}
