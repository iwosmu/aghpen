// Package model holds the shared domain types of Czujka.
// It is the contract between the scan engine, the fingerprint and signature
// library, the analysis library, the store, the HTTP API and the web UI.
// JSON tags are the wire format of the REST API. Do not rename a tag without
// updating docs/API.md and web/src/api/types.ts.
package model

import "time"

// ---------- Auth and RBAC ----------

// Permission is a single capability. Roles are sets of permissions.
type Permission string

const (
	PermTargetsRead      Permission = "targets:read"
	PermTargetsCreate    Permission = "targets:create"
	PermTargetsUpdate    Permission = "targets:update"
	PermTargetsDelete    Permission = "targets:delete"
	PermScansRead        Permission = "scans:read"
	PermScansRun         Permission = "scans:run"       // start, pause, resume, cancel a run
	PermScansConfigure   Permission = "scans:configure" // create, update, delete scan profiles and schedules
	PermResultsRead      Permission = "results:read"    // hosts, services, changes, findings, dashboard
	PermResultsUpdate    Permission = "results:update"  // edit hosts, services, findings, tags, ack changes
	PermResultsCreate    Permission = "results:create"  // manual findings, result import
	PermResultsDelete    Permission = "results:delete"
	PermSignaturesRead   Permission = "signatures:read"
	PermSignaturesCreate Permission = "signatures:create"
	PermSignaturesUpdate Permission = "signatures:update"
	PermSignaturesDelete Permission = "signatures:delete"
	PermExportRun        Permission = "export:run"          // JSON/CSV export and DefectDojo push
	PermIntegrations     Permission = "integrations:manage" // DefectDojo settings, passive sources
	PermSafetyManage     Permission = "safety:manage"       // global safety policy, emergency stop release
	PermEmergencyStop    Permission = "safety:stop"         // press the emergency stop
	PermUsersManage      Permission = "users:manage"
	PermRolesManage      Permission = "roles:manage"
	PermAuditRead        Permission = "audit:read"
)

// AllPermissions lists every permission in display order.
var AllPermissions = []Permission{
	PermTargetsRead, PermTargetsCreate, PermTargetsUpdate, PermTargetsDelete,
	PermScansRead, PermScansRun, PermScansConfigure,
	PermResultsRead, PermResultsUpdate, PermResultsCreate, PermResultsDelete,
	PermSignaturesRead, PermSignaturesCreate, PermSignaturesUpdate, PermSignaturesDelete,
	PermExportRun, PermIntegrations, PermSafetyManage, PermEmergencyStop,
	PermUsersManage, PermRolesManage, PermAuditRead,
}

// Built-in role slugs. They map to the four roles the challenge requires.
const (
	RoleAdmin   = "admin"   // Administracja: everything
	RoleEditor  = "editor"  // Dodawanie, usuwanie, modyfikacja
	RoleAnalyst = "analyst" // Modyfikacja i odczyt
	RoleViewer  = "viewer"  // Odczyt
)

type Role struct {
	ID          int64        `json:"id"`
	Slug        string       `json:"slug"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Builtin     bool         `json:"builtin"`
	Permissions []Permission `json:"permissions"`
	UserCount   int          `json:"user_count"`
}

type User struct {
	ID          int64      `json:"id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	RoleID      int64      `json:"role_id"`
	RoleSlug    string     `json:"role_slug"`
	RoleName    string     `json:"role_name"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

// Session is the answer of POST /auth/login and GET /me.
type Session struct {
	User        User         `json:"user"`
	Permissions []Permission `json:"permissions"`
	CSRFToken   string       `json:"csrf_token"`
}

type AuditEntry struct {
	ID        int64          `json:"id"`
	At        time.Time      `json:"at"`
	UserID    *int64         `json:"user_id"`
	UserEmail string         `json:"user_email"`
	Action    string         `json:"action"` // e.g. "finding.update", "run.start", "auth.login_failed"
	Entity    string         `json:"entity"`
	EntityID  string         `json:"entity_id"`
	Detail    map[string]any `json:"detail"`
	IP        string         `json:"ip"`
}

// ---------- Scope and targets ----------

type TargetKind string

const (
	TargetIP     TargetKind = "ip"
	TargetCIDR   TargetKind = "cidr"
	TargetRange  TargetKind = "range" // "10.0.0.5-10.0.0.90"
	TargetDomain TargetKind = "domain"
)

// Scope is a named group of targets (for example "Kampus – serwery WWW").
type Scope struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	Owner        string    `json:"owner"`
	Criticality  int       `json:"criticality"` // 1 (low) .. 5 (critical); feeds the interest score
	Tags         []string  `json:"tags"`
	TargetCount  int       `json:"target_count"`
	AddressCount int64     `json:"address_count"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Target struct {
	ID        int64      `json:"id"`
	ScopeID   int64      `json:"scope_id"`
	Kind      TargetKind `json:"kind"`
	Value     string     `json:"value"`
	Note      string     `json:"note"`
	Tags      []string   `json:"tags"`
	Enabled   bool       `json:"enabled"`
	Source    string     `json:"source"` // manual | csv | json | api
	Addresses int64      `json:"addresses"`
	CreatedAt time.Time  `json:"created_at"`
	CreatedBy *int64     `json:"created_by"`
}

// TargetPreview is the answer of POST /targets/preview and of an import dry run.
type TargetPreview struct {
	Valid        []Target      `json:"valid"`
	Invalid      []InvalidLine `json:"invalid"`
	Duplicates   int           `json:"duplicates"`
	Excluded     int64         `json:"excluded"` // addresses removed by the safety policy exclusions
	AddressCount int64         `json:"address_count"`
}

type InvalidLine struct {
	Line   int    `json:"line"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// ---------- Safety policy ----------

// SafetyPolicy is the global guardrail set by an administrator. A scan profile
// can only be stricter than the policy. The engine enforces it on every run.
type SafetyPolicy struct {
	MaxPPS          int       `json:"max_pps"`            // hard cap on probe packets per second, all workers together
	MaxHTTPRPS      float64   `json:"max_http_rps"`       // hard cap on HTTP requests per second, all hosts together
	MaxPerHostRPS   float64   `json:"max_per_host_rps"`   // hard cap on HTTP requests per second to one host
	MaxPathsPerHost int       `json:"max_paths_per_host"` // extra signature paths fetched per HTTP service
	AllowedPorts    string    `json:"allowed_ports"`      // nmap port spec; empty means all ports allowed
	DeniedPorts     string    `json:"denied_ports"`
	Exclusions      []string  `json:"exclusions"`      // IPs, CIDRs or domains that are never touched
	AllowedMethods  []string  `json:"allowed_methods"` // always a subset of GET, HEAD
	EmergencyStop   bool      `json:"emergency_stop"`  // when true no run may start and running runs are cancelled
	UserAgent       string    `json:"user_agent"`      // identifies the scanner to administrators of scanned hosts
	UpdatedAt       time.Time `json:"updated_at"`
}

// ---------- Scan configuration ----------

type DiscoveryOpts struct {
	ICMPEcho      bool  `json:"icmp_echo"`
	ICMPTimestamp bool  `json:"icmp_timestamp"`
	TCPSynPorts   []int `json:"tcp_syn_ports"`
	TCPAckPorts   []int `json:"tcp_ack_ports"`
	ARP           bool  `json:"arp"`
	SkipDiscovery bool  `json:"skip_discovery"` // treat every address as up (-Pn); slow, off by default
}

type HTTPOpts struct {
	Enabled        bool `json:"enabled"`
	MaxRedirects   int  `json:"max_redirects"`
	SignaturePaths bool `json:"signature_paths"` // fetch the safe extra paths that enabled signatures ask for
	MaxBodyBytes   int  `json:"max_body_bytes"`
	TimeoutMs      int  `json:"timeout_ms"`
	Favicon        bool `json:"favicon"`
}

type RateLimits struct {
	MaxPPS             int     `json:"max_pps"`
	MaxParallelChunks  int     `json:"max_parallel_chunks"`
	MaxParallelHosts   int     `json:"max_parallel_hosts"` // service detection and HTTP stage
	HTTPRPS            float64 `json:"http_rps"`
	PerHostConcurrency int     `json:"per_host_concurrency"`
	PerHostDelayMs     int     `json:"per_host_delay_ms"`
}

type ChunkingOpts struct {
	Adaptive      bool `json:"adaptive"`
	InitialSize   int  `json:"initial_size"` // addresses in the first chunks
	MinSize       int  `json:"min_size"`
	MaxSize       int  `json:"max_size"`
	TargetSeconds int  `json:"target_seconds"` // wanted wall time of one chunk
}

type RetryOpts struct {
	UnstableRetries int `json:"unstable_retries"` // extra probes for a known host that did not answer
	BackoffMs       int `json:"backoff_ms"`
}

// Window is one allowed time window. Days use 0 = Sunday .. 6 = Saturday.
// End before Start means the window crosses midnight.
type Window struct {
	Days  []int  `json:"days"`
	Start string `json:"start"` // "HH:MM"
	End   string `json:"end"`   // "HH:MM"
}

type Schedule struct {
	Enabled         bool     `json:"enabled"`
	Cron            string   `json:"cron"`             // 5-field cron; empty when IntervalMinutes is used
	IntervalMinutes int      `json:"interval_minutes"` // run every N minutes inside the windows
	Windows         []Window `json:"windows"`          // empty means any time
	Timezone        string   `json:"timezone"`         // IANA name, default Europe/Warsaw
}

type ScanProfile struct {
	ID               int64         `json:"id"`
	Name             string        `json:"name"`
	Description      string        `json:"description"`
	ScopeIDs         []int64       `json:"scope_ids"`
	Ports            string        `json:"ports"` // nmap spec: "top-100", "top-1000", "22,80,443,8000-8100"
	Discovery        DiscoveryOpts `json:"discovery"`
	ServiceDetection bool          `json:"service_detection"`
	VersionIntensity int           `json:"version_intensity"` // 0..9, nmap --version-intensity
	HTTP             HTTPOpts      `json:"http"`
	Rate             RateLimits    `json:"rate"`
	Chunking         ChunkingOpts  `json:"chunking"`
	Retry            RetryOpts     `json:"retry"`
	Schedule         Schedule      `json:"schedule"`
	Enabled          bool          `json:"enabled"`
	NextRunAt        *time.Time    `json:"next_run_at"`
	LastRunID        *int64        `json:"last_run_id"`
	CreatedAt        time.Time     `json:"created_at"`
	UpdatedAt        time.Time     `json:"updated_at"`
}

// ScanEstimate is the answer of POST /profiles/{id}/estimate. It is the
// "traffic budget" shown to the operator before a run starts.
type ScanEstimate struct {
	Addresses        int64   `json:"addresses"`
	Chunks           int     `json:"chunks"`
	EstPackets       int64   `json:"est_packets"`
	EstDurationSec   int64   `json:"est_duration_sec"`
	EffectivePPS     int     `json:"effective_pps"` // after the safety policy cap
	FitsWindow       bool    `json:"fits_window"`
	WindowSec        int64   `json:"window_sec"`
	BasedOnHistory   bool    `json:"based_on_history"` // true when earlier runs gave a measured speed
	ExpectedLiveRate float64 `json:"expected_live_rate"`
}

// ---------- Scan runs ----------

type RunStatus string

const (
	RunQueued    RunStatus = "queued"
	RunRunning   RunStatus = "running"
	RunPaused    RunStatus = "paused"    // PauseReason says why; a window overrun resumes in the next window
	RunAnalyzing RunStatus = "analyzing" // probing done, diff and scoring in progress
	RunCompleted RunStatus = "completed"
	RunFailed    RunStatus = "failed"
	RunCancelled RunStatus = "cancelled"
)

const (
	PauseWindowClosed = "window_closed"
	PauseManual       = "manual"
	PauseEmergency    = "emergency_stop"
)

type RunStats struct {
	AddressesTotal int64   `json:"addresses_total"`
	AddressesDone  int64   `json:"addresses_done"`
	ChunksTotal    int     `json:"chunks_total"`
	ChunksDone     int     `json:"chunks_done"`
	HostsUp        int     `json:"hosts_up"`
	ServicesOpen   int     `json:"services_open"`
	HTTPServices   int     `json:"http_services"`
	PacketsSent    int64   `json:"packets_sent"` // estimate from nmap stats plus native probes
	HTTPRequests   int64   `json:"http_requests"`
	CurrentPPS     float64 `json:"current_pps"`
	AvgPPS         float64 `json:"avg_pps"`
	ElapsedSec     int64   `json:"elapsed_sec"` // active time only, pauses excluded
	ETASec         int64   `json:"eta_sec"`
	Retried        int     `json:"retried"` // unstable hosts probed again
	Errors         int     `json:"errors"`
}

type ScanRun struct {
	ID          int64           `json:"id"`
	ProfileID   *int64          `json:"profile_id"`
	ProfileName string          `json:"profile_name"`
	Status      RunStatus       `json:"status"`
	PauseReason string          `json:"pause_reason"`
	Trigger     string          `json:"trigger"` // manual | schedule | import
	CreatedBy   *int64          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	StartedAt   *time.Time      `json:"started_at"`
	FinishedAt  *time.Time      `json:"finished_at"`
	WindowEnd   *time.Time      `json:"window_end"` // the run must stop at this time
	ResumeAt    *time.Time      `json:"resume_at"`  // start of the next window when paused by a window
	Stats       RunStats        `json:"stats"`
	Summary     *RunDiffSummary `json:"summary"` // filled after analysis
	Error       string          `json:"error"`
	ImportFile  string          `json:"import_file"`
}

type ChunkStatus string

const (
	ChunkPending  ChunkStatus = "pending"
	ChunkRunning  ChunkStatus = "running"
	ChunkDone     ChunkStatus = "done"
	ChunkDeferred ChunkStatus = "deferred" // not finished before the window closed; resumed later
	ChunkFailed   ChunkStatus = "failed"
)

// Chunk is one sub-group of addresses. The planner sizes chunks from measured speed.
type Chunk struct {
	ID         int64       `json:"id"`
	RunID      int64       `json:"run_id"`
	Seq        int         `json:"seq"`
	Spec       []string    `json:"spec"`     // CIDRs, ranges or single IPs
	Size       int         `json:"size"`     // number of addresses
	Priority   int         `json:"priority"` // higher first; blocks with known live hosts get a higher value
	Status     ChunkStatus `json:"status"`
	StartedAt  *time.Time  `json:"started_at"`
	FinishedAt *time.Time  `json:"finished_at"`
	DurationMs int64       `json:"duration_ms"`
	HostsUp    int         `json:"hosts_up"`
	PPS        float64     `json:"pps"`
	Error      string      `json:"error"`
}

// ---------- Engine output (one record per probed host) ----------

// HostResult is what the scan engine emits for one address in one run.
// Result import (nmap XML, JSON, CSV) produces the same records, so imported
// data goes through the same pipeline as scanned data.
type HostResult struct {
	RunID      int64           `json:"run_id"`
	IP         string          `json:"ip"`
	Hostnames  []string        `json:"hostnames"`
	Up         bool            `json:"up"`
	Reason     string          `json:"reason"` // echo-reply, syn-ack, reset, arp-response, tcp-connect, no-response, imported
	RTTMs      float64         `json:"rtt_ms"`
	Attempts   int             `json:"attempts"` // probes rounds used; more than 1 means the retry logic ran
	MAC        string          `json:"mac"`
	Vendor     string          `json:"vendor"`
	OSGuess    string          `json:"os_guess"`
	ObservedAt time.Time       `json:"observed_at"`
	Services   []ServiceResult `json:"services"`
	Scripts    []ScriptResult  `json:"scripts,omitempty"` // nmap host scripts, kept for import/export round trips
}

// ScriptResult is the output of one nmap script (NSE), as found in imported
// nmap XML. Czujka itself runs only safe default detection; the field keeps
// imported data lossless.
type ScriptResult struct {
	ID     string `json:"id"`
	Output string `json:"output"`
}

type ServiceResult struct {
	Port         int              `json:"port"`
	Proto        string           `json:"proto"` // tcp | udp
	State        string           `json:"state"` // open | closed | filtered
	Name         string           `json:"name"`  // nmap service name: http, ssh, mysql ...
	Product      string           `json:"product"`
	Version      string           `json:"version"`
	ExtraInfo    string           `json:"extra_info"`
	CPE          []string         `json:"cpe"`
	Banner       string           `json:"banner"`
	Tunnel       string           `json:"tunnel"`     // "ssl" when the service runs over TLS
	Confidence   float64          `json:"confidence"` // 0..1 confidence of Name/Product
	HTTP         *HTTPFingerprint `json:"http"`
	TLS          *TLSInfo         `json:"tls"`
	Matches      []SigMatch       `json:"matches"`
	Technologies []Technology     `json:"technologies"`
	Classes      []string         `json:"classes"`           // see Class* constants
	Scripts      []ScriptResult   `json:"scripts,omitempty"` // nmap port scripts from imported XML
}

// Service classes set by the classifier.
const (
	ClassAdminPanel   = "admin-panel"
	ClassLogin        = "login"
	ClassStaging      = "staging" // test, dev, staging, UAT environment
	ClassIoT          = "iot"
	ClassDefaultPage  = "default-page"
	ClassAPI          = "api"
	ClassDevTool      = "dev-tool" // CI, repos, debug consoles
	ClassDatabase     = "database"
	ClassRemoteAccess = "remote-access"
	ClassDirListing   = "directory-listing"
	ClassErrorPage    = "error-page"
)

type Cookie struct {
	Name      string `json:"name"`
	Domain    string `json:"domain"`
	Path      string `json:"path"`
	Secure    bool   `json:"secure"`
	HTTPOnly  bool   `json:"http_only"`
	SameSite  string `json:"same_site"`
	ValueLen  int    `json:"value_len"`
	ValueHash string `json:"value_hash"`      // sha256 prefix; the raw value is kept only in encrypted evidence
	Value     string `json:"value,omitempty"` // raw value; filled by the collector, stored encrypted, hidden from roles without results:update
}

type Redirect struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Status int    `json:"status"`
}

// PathProbe is one extra safe GET that a signature asked for (for example /login).
type PathProbe struct {
	Path       string              `json:"path"`
	Status     int                 `json:"status"`
	Title      string              `json:"title"`
	Length     int                 `json:"length"`
	BodySHA256 string              `json:"body_sha256"`
	Excerpt    string              `json:"excerpt"`
	Headers    map[string][]string `json:"headers"`
	Location   string              `json:"location"`
}

type HTTPFingerprint struct {
	Scheme        string              `json:"scheme"`
	URL           string              `json:"url"`
	FinalURL      string              `json:"final_url"`
	Host          string              `json:"host"` // Host header used (IP or domain)
	Status        int                 `json:"status"`
	Title         string              `json:"title"`
	Headers       map[string][]string `json:"headers"` // canonical header names
	Cookies       []Cookie            `json:"cookies"`
	Redirects     []Redirect          `json:"redirects"`
	Server        string              `json:"server"`
	PoweredBy     string              `json:"powered_by"`
	MetaGenerator string              `json:"meta_generator"`
	BodyLength    int                 `json:"body_length"`
	BodySHA256    string              `json:"body_sha256"`
	BodySimhash   string              `json:"body_simhash"` // 64-bit simhash as hex; near-duplicate grouping
	BodyExcerpt   string              `json:"body_excerpt"` // first bytes of the body; kept for retro-hunt, stored encrypted
	FaviconMMH3   *int32              `json:"favicon_mmh3"` // Shodan-style favicon hash
	FaviconSHA256 string              `json:"favicon_sha256"`
	Paths         []PathProbe         `json:"paths"`
	ResponseMs    int                 `json:"response_ms"`
	Error         string              `json:"error"`
}

type TLSInfo struct {
	Version      string    `json:"version"`
	Cipher       string    `json:"cipher"`
	SubjectCN    string    `json:"subject_cn"`
	SubjectOrg   string    `json:"subject_org"`
	SANs         []string  `json:"sans"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Serial       string    `json:"serial"`
	SHA256       string    `json:"sha256"`
	SelfSigned   bool      `json:"self_signed"`
	Expired      bool      `json:"expired"`
	DaysLeft     int       `json:"days_left"`
	HostMismatch bool      `json:"host_mismatch"`
	KeyType      string    `json:"key_type"`
	KeyBits      int       `json:"key_bits"`
}

type Evidence struct {
	Matcher string `json:"matcher"` // header | cookie | body | title | favicon | path | banner | tls | meta | status
	Where   string `json:"where"`   // for example "header:X-Powered-By" or "path:/wp-login.php"
	Snippet string `json:"snippet"` // the matched text, short
}

type SigMatch struct {
	Signature  string     `json:"signature"` // signature slug
	Name       string     `json:"name"`      // technology or finding name
	Category   string     `json:"category"`
	Version    string     `json:"version"`
	Confidence float64    `json:"confidence"` // 0..1
	Interest   int        `json:"interest"`   // 0..100 weight for the interest score
	Classes    []string   `json:"classes"`
	Tags       []string   `json:"tags"`
	Evidence   []Evidence `json:"evidence"`
}

// Technology categories.
const (
	CatCMS         = "cms"
	CatFramework   = "framework"
	CatAppServer   = "app-server"
	CatWebServer   = "web-server"
	CatIoT         = "iot"
	CatPanel       = "panel"
	CatDatabase    = "database"
	CatDevOps      = "devops"
	CatLanguage    = "language"
	CatProxy       = "proxy"
	CatSecurity    = "security"
	CatOS          = "os"
	CatLibrary     = "library"
	CatEnvironment = "environment"
	CatHeader      = "header" // interesting header finding
	CatCookie      = "cookie" // interesting cookie finding
	CatOther       = "other"
)

type Technology struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Version    string   `json:"version"`
	Confidence float64  `json:"confidence"` // noisy-OR of all supporting evidence
	Sources    []string `json:"sources"`    // signature slugs, "nmap", "header:server"
	CPE        string   `json:"cpe"`
}

// ---------- Persistent inventory ----------

type HostStatus string

const (
	HostUp              HostStatus = "up"
	HostUnstable        HostStatus = "unstable"         // answers in some runs only, or missed recent runs but is still likely alive
	HostDown            HostStatus = "down"             // reported inactive: probability of being alive fell under the threshold
	HostExpectedOffline HostStatus = "expected-offline" // not answering now, and its time-of-day profile says this is normal
	HostUnknown         HostStatus = "unknown"
)

// Override records a value that an analyst set by hand. The scanner never
// overwrites an overridden field; the observed value stays visible beside it.
type Override struct {
	Value    any       `json:"value"`
	Observed any       `json:"observed"`
	By       string    `json:"by"`
	At       time.Time `json:"at"`
}

type Host struct {
	ID                int64               `json:"id"`
	IP                string              `json:"ip"`
	Hostnames         []string            `json:"hostnames"`
	ScopeIDs          []int64             `json:"scope_ids"`
	Status            HostStatus          `json:"status"`
	PAlive            float64             `json:"p_alive"`   // model probability that the host still exists
	Stability         float64             `json:"stability"` // share of runs in which it answered, 0..1
	ConsecutiveMisses int                 `json:"consecutive_misses"`
	Pattern           string              `json:"pattern"` // human text, for example "zwykle aktywny pn–pt 08–16"
	FirstSeen         time.Time           `json:"first_seen"`
	LastSeen          time.Time           `json:"last_seen"` // last run that probed it
	LastUp            *time.Time          `json:"last_up"`
	OSGuess           string              `json:"os_guess"`
	MAC               string              `json:"mac"`
	Vendor            string              `json:"vendor"`
	Label             string              `json:"label"` // analyst-given name
	Owner             string              `json:"owner"`
	Criticality       int                 `json:"criticality"`
	Note              string              `json:"note"`
	Tags              []string            `json:"tags"`
	Interest          int                 `json:"interest"` // 0..100, max of its services plus host factors
	ServiceCount      int                 `json:"service_count"`
	OpenPorts         []int               `json:"open_ports"`
	Technologies      []string            `json:"technologies"`
	Overrides         map[string]Override `json:"overrides"`
	Source            string              `json:"source"` // scan | import | manual
}

// AvailabilityProfile is the hour-of-week picture of one host.
type AvailabilityProfile struct {
	HostID          int64             `json:"host_id"`
	Buckets         [168]AvailBucket  `json:"buckets"` // index = weekday*24 + hour, weekday 0 = Sunday, in the profile timezone
	Recent          []HostObservation `json:"recent"`
	Pattern         string            `json:"pattern"`
	PAlive          float64           `json:"p_alive"`
	DownAfterMisses int               `json:"down_after_misses"` // misses in a row needed now to report the host inactive
}

type AvailBucket struct {
	Up   int `json:"up"`
	Down int `json:"down"`
}

type HostObservation struct {
	RunID    int64     `json:"run_id"`
	At       time.Time `json:"at"`
	Up       bool      `json:"up"`
	RTTMs    float64   `json:"rtt_ms"`
	Attempts int       `json:"attempts"`
	Reason   string    `json:"reason"`
}

type ServiceState string

const (
	ServiceOpen     ServiceState = "open"
	ServiceGone     ServiceState = "gone"    // was open, host is up, port no longer open
	ServiceUnknown  ServiceState = "unknown" // host did not answer in the last run
	ServiceFiltered ServiceState = "filtered"
)

type Service struct {
	ID           int64               `json:"id"`
	HostID       int64               `json:"host_id"`
	IP           string              `json:"ip"`
	Hostname     string              `json:"hostname"`
	Port         int                 `json:"port"`
	Proto        string              `json:"proto"`
	State        ServiceState        `json:"state"`
	Name         string              `json:"name"`
	Product      string              `json:"product"`
	Version      string              `json:"version"`
	Banner       string              `json:"banner"`
	Confidence   float64             `json:"confidence"`
	TLS          bool                `json:"tls"`
	Title        string              `json:"title"`
	HTTPStatus   int                 `json:"http_status"`
	URL          string              `json:"url"`
	Technologies []Technology        `json:"technologies"`
	Classes      []string            `json:"classes"`
	Interest     int                 `json:"interest"`
	InterestWhy  []InterestReason    `json:"interest_why"`
	GroupKey     string              `json:"group_key"` // services with the same key look alike
	GroupSize    int                 `json:"group_size"`
	Note         string              `json:"note"`
	Tags         []string            `json:"tags"`
	FirstSeen    time.Time           `json:"first_seen"`
	LastSeen     time.Time           `json:"last_seen"`
	LastChanged  *time.Time          `json:"last_changed"`
	Overrides    map[string]Override `json:"overrides"`
	Latest       *ServiceObservation `json:"latest,omitempty"` // only on GET /services/{id}
}

type InterestReason struct {
	Code   string `json:"code"` // admin-panel, staging, expired-cert, new-exposure, rare-tech, outdated, default-creds-page, sensitive-header ...
	Points int    `json:"points"`
	Text   string `json:"text"`
}

// ServiceObservation is the full record of one service in one run.
type ServiceObservation struct {
	ID        int64         `json:"id"`
	ServiceID int64         `json:"service_id"`
	RunID     int64         `json:"run_id"`
	At        time.Time     `json:"at"`
	Result    ServiceResult `json:"result"`
}

type ServiceGroup struct {
	Key          string   `json:"key"`
	Label        string   `json:"label"`
	Count        int      `json:"count"`
	Technologies []string `json:"technologies"`
	Title        string   `json:"title"`
	SampleIDs    []int64  `json:"sample_ids"`
	Interest     int      `json:"interest"`
}

// ---------- Changes between runs ----------

type ChangeKind string

const (
	ChangeHostNew        ChangeKind = "host_new"
	ChangeHostGone       ChangeKind = "host_gone"     // reported inactive
	ChangeHostBack       ChangeKind = "host_back"     // was inactive, answers again
	ChangeHostUnstable   ChangeKind = "host_unstable" // started to flap
	ChangeServiceNew     ChangeKind = "service_new"
	ChangeServiceGone    ChangeKind = "service_gone"
	ChangeServiceChanged ChangeKind = "service_changed" // product, version, banner
	ChangeTechNew        ChangeKind = "tech_new"
	ChangeTechGone       ChangeKind = "tech_gone"
	ChangeTechVersion    ChangeKind = "tech_version"
	ChangeTitle          ChangeKind = "title_changed"
	ChangeHTTPStatus     ChangeKind = "status_changed"
	ChangeCert           ChangeKind = "cert_changed"
	ChangeHeaders        ChangeKind = "headers_changed"
	ChangeCookies        ChangeKind = "cookies_changed"
	ChangeContent        ChangeKind = "content_changed" // body differs strongly (simhash distance)
	ChangeRedirect       ChangeKind = "redirect_changed"
	ChangeClass          ChangeKind = "class_changed" // for example became an admin panel
)

type Severity string

const (
	SevInfo   Severity = "info"
	SevLow    Severity = "low"
	SevMedium Severity = "medium"
	SevHigh   Severity = "high"
)

type Change struct {
	ID        int64      `json:"id"`
	RunID     int64      `json:"run_id"`
	PrevRunID *int64     `json:"prev_run_id"`
	At        time.Time  `json:"at"`
	Kind      ChangeKind `json:"kind"`
	Severity  Severity   `json:"severity"`
	HostID    int64      `json:"host_id"`
	IP        string     `json:"ip"`
	ServiceID *int64     `json:"service_id"`
	Port      int        `json:"port"`
	Summary   string     `json:"summary"`
	Field     string     `json:"field"`
	Before    any        `json:"before"`
	After     any        `json:"after"`
	Expected  bool       `json:"expected"` // true when the time-of-day profile explains the change
	AckedBy   string     `json:"acked_by"`
	AckedAt   *time.Time `json:"acked_at"`
}

type RunDiffSummary struct {
	PrevRunID       *int64         `json:"prev_run_id"`
	HostsNew        int            `json:"hosts_new"`
	HostsGone       int            `json:"hosts_gone"`
	HostsBack       int            `json:"hosts_back"`
	HostsUnstable   int            `json:"hosts_unstable"`
	ServicesNew     int            `json:"services_new"`
	ServicesGone    int            `json:"services_gone"`
	ServicesChanged int            `json:"services_changed"`
	ByKind          map[string]int `json:"by_kind"`
	FindingsNew     int            `json:"findings_new"`
}

// DiffReport is the answer of GET /diff?from=&to= for any two runs.
type DiffReport struct {
	From    ScanRun        `json:"from"`
	To      ScanRun        `json:"to"`
	Summary RunDiffSummary `json:"summary"`
	Changes []Change       `json:"changes"`
}

// ---------- Findings ----------

type FindingStatus string

const (
	FindingNew           FindingStatus = "new"
	FindingTriaged       FindingStatus = "triaged"
	FindingAccepted      FindingStatus = "accepted"
	FindingFalsePositive FindingStatus = "false_positive"
	FindingResolved      FindingStatus = "resolved" // no longer observed
)

// Finding is one observation worth an analyst's attention. Findings are
// informational: Czujka detects presence of features, it does not exploit.
type Finding struct {
	ID          int64               `json:"id"`
	Key         string              `json:"key"`  // stable dedup key: type + host + port + subject
	Type        string              `json:"type"` // admin-panel, staging, expired-cert, self-signed-cert, interesting-header, interesting-cookie, new-exposure, signature, outdated, manual ...
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Severity    Severity            `json:"severity"`
	Status      FindingStatus       `json:"status"`
	Interest    int                 `json:"interest"`
	HostID      int64               `json:"host_id"`
	IP          string              `json:"ip"`
	ServiceID   *int64              `json:"service_id"`
	Port        int                 `json:"port"`
	URL         string              `json:"url"`
	Signature   string              `json:"signature"`
	Evidence    []Evidence          `json:"evidence"`
	Note        string              `json:"note"`
	Tags        []string            `json:"tags"`
	Assignee    string              `json:"assignee"`
	FirstSeen   time.Time           `json:"first_seen"`
	LastSeen    time.Time           `json:"last_seen"`
	FirstRunID  int64               `json:"first_run_id"`
	LastRunID   int64               `json:"last_run_id"`
	Overrides   map[string]Override `json:"overrides"`
	DojoID      *int64              `json:"dojo_id"` // DefectDojo finding id after export
	DojoURL     string              `json:"dojo_url"`
	Manual      bool                `json:"manual"`
}

// ---------- Signatures ----------

// Signature is a detection rule stored as YAML. See docs/SIGNATURES.md for the DSL.
type Signature struct {
	ID          int64     `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	YAML        string    `json:"yaml"`
	Enabled     bool      `json:"enabled"`
	Builtin     bool      `json:"builtin"`
	Author      string    `json:"author"`
	Tags        []string  `json:"tags"`
	Interest    int       `json:"interest"`
	MatchCount  int       `json:"match_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SignatureIssue is one problem found by the validator.
type SignatureIssue struct {
	Level   string `json:"level"` // error | warning
	Path    string `json:"path"`  // YAML path
	Message string `json:"message"`
	Safety  bool   `json:"safety"` // true when the rule broke a safe-detection rule
}

type SignatureValidation struct {
	OK     bool             `json:"ok"`
	Issues []SignatureIssue `json:"issues"`
	Paths  []string         `json:"paths"` // extra paths this signature would request
}

// RetroHit is one match of a signature against a stored observation.
type RetroHit struct {
	ServiceID int64     `json:"service_id"`
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	URL       string    `json:"url"`
	RunID     int64     `json:"run_id"`
	At        time.Time `json:"at"`
	Match     SigMatch  `json:"match"`
}

type RetroHuntResult struct {
	Scanned     int        `json:"scanned"` // stored observations checked
	Hits        []RetroHit `json:"hits"`
	TookMs      int64      `json:"took_ms"`
	PacketsSent int        `json:"packets_sent"` // always 0: retro-hunt reads stored data only
	// MissingPaths lists the extra paths the signature needs that at least one
	// checked observation never fetched; Incomplete counts those observations.
	// Path rules could not match there. Notes explains it in Polish.
	MissingPaths []string `json:"missing_paths"`
	Incomplete   int      `json:"incomplete"`
	Notes        []string `json:"notes"`
	// TotalHits counts every hit. Hits holds at most the hit limit of the
	// caller; Truncated says that the list was cut.
	TotalHits int  `json:"total_hits"`
	Truncated bool `json:"truncated"`
}

// ---------- Integrations ----------

type DefectDojoSettings struct {
	Enabled         bool   `json:"enabled"`
	URL             string `json:"url"`
	APIKey          string `json:"api_key,omitempty"` // write-only; GET returns APIKeySet instead
	APIKeySet       bool   `json:"api_key_set"`
	ProductName     string `json:"product_name"`
	EngagementName  string `json:"engagement_name"`
	ProductTypeName string `json:"product_type_name"`
	VerifyTLS       bool   `json:"verify_tls"`
	AutoExport      bool   `json:"auto_export"` // push new findings after each run
	MinInterest     int    `json:"min_interest"`
}

type DojoExportResult struct {
	Exported int      `json:"exported"`
	Updated  int      `json:"updated"`
	Failed   int      `json:"failed"`
	TestID   int64    `json:"test_id"`
	TestURL  string   `json:"test_url"`
	Errors   []string `json:"errors"`
}

type ImportReport struct {
	Format   string        `json:"format"` // nmap-xml | czujka-json | csv | targets-csv | targets-json
	RunID    *int64        `json:"run_id"`
	Hosts    int           `json:"hosts"`
	Services int           `json:"services"`
	Targets  int           `json:"targets"`
	Skipped  int           `json:"skipped"`
	Invalid  []InvalidLine `json:"invalid"`
}

// ---------- Dashboard ----------

type CountPoint struct {
	At       time.Time `json:"at"`
	RunID    int64     `json:"run_id"`
	Hosts    int       `json:"hosts"`
	Services int       `json:"services"`
	Changes  int       `json:"changes"`
	Findings int       `json:"findings"`
}

type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
	Extra string `json:"extra,omitempty"`
}

// Dashboard follows the 3-30-300 rule: Headline is read in 3 seconds,
// the top lists in 30 seconds, the links lead to full detail.
type Dashboard struct {
	GeneratedAt   time.Time    `json:"generated_at"`
	Headline      Headline     `json:"headline"`
	LastRun       *ScanRun     `json:"last_run"`
	ActiveRun     *ScanRun     `json:"active_run"`
	NextRunAt     *time.Time   `json:"next_run_at"`
	TopFindings   []Finding    `json:"top_findings"`
	RecentChanges []Change     `json:"recent_changes"`
	TopServices   []Service    `json:"top_services"` // highest interest
	Technologies  []NameCount  `json:"technologies"`
	Ports         []NameCount  `json:"ports"`
	Classes       []NameCount  `json:"classes"`
	Trend         []CountPoint `json:"trend"`
	UnstableHosts []Host       `json:"unstable_hosts"`
	CertsExpiring []Service    `json:"certs_expiring"`
	Safety        SafetyPolicy `json:"safety"`
}

type Headline struct {
	AddressesInScope int64 `json:"addresses_in_scope"`
	HostsUp          int   `json:"hosts_up"`
	HostsUnstable    int   `json:"hosts_unstable"`
	HostsDown        int   `json:"hosts_down"`
	ServicesOpen     int   `json:"services_open"`
	WebServices      int   `json:"web_services"`
	FindingsOpen     int   `json:"findings_open"`
	FindingsHigh     int   `json:"findings_high"`
	ChangesUnacked   int   `json:"changes_unacked"`
	NewSinceLastRun  int   `json:"new_since_last_run"`
	GoneSinceLastRun int   `json:"gone_since_last_run"`
	AdminPanels      int   `json:"admin_panels"`
	StagingEnvs      int   `json:"staging_envs"`
}

// Page is the envelope of every list endpoint.
type Page[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}
