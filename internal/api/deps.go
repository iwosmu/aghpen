// Package api is the REST API of Czujka (docs/API.md): chi router, session
// and permission checks, input validation, audit log, SSE, streaming exports,
// and the static files of the web UI.
package api

import (
	"context"
	"io"
	"io/fs"
	"log/slog"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/iwosmu/aghpen/internal/auth"
	"github.com/iwosmu/aghpen/internal/defectdojo"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/passive"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
)

// The interfaces below are the seams to the packages that other workers build.
// They are small and use model types only, so an adapter is a few lines. A nil
// dependency makes its routes answer 501 with code "not_wired".

// RunManager controls scan runs. Implemented by *runner.Manager.
type RunManager interface {
	Start(ctx context.Context, profileID int64, userID *int64, trigger string) (model.ScanRun, error)
	Pause(ctx context.Context, runID int64) (model.ScanRun, error)
	Resume(ctx context.Context, runID int64) (model.ScanRun, error)
	Cancel(ctx context.Context, runID int64) (model.ScanRun, error)
	EmergencyStop(ctx context.Context) (model.SafetyPolicy, error)
	ReleaseEmergencyStop(ctx context.Context) (model.SafetyPolicy, error)
	// Estimate is the Estimator seam: it builds the plan and asks model.Engine.Estimate.
	Estimate(ctx context.Context, profileID int64) (model.ScanEstimate, error)
	Import(ctx context.Context, filename string, hosts []model.HostResult, userID *int64) (model.ScanRun, error)
	// Ingest stores host results that do not come from the engine (trigger manual-entry) through the same sink and analysis.
	Ingest(ctx context.Context, trigger, name string, hosts []model.HostResult, userID *int64) (model.ScanRun, error)
	// StartAdHoc probes chosen addresses and ports through the normal engine, sink and analysis (trigger reprobe).
	StartAdHoc(ctx context.Context, scope model.AdHocScope, userID *int64, trigger string) (model.ScanRun, error)
	EngineWired() bool
}

// TargetParser parses target lists. internal/targets replaces the built-in basic parser.
type TargetParser interface {
	// ParseText parses one target per line (IP, CIDR, range, domain). Lines are numbered from 1.
	ParseText(text string) (valid []model.Target, invalid []model.InvalidLine)
	// ParseFile parses a CSV or JSON target file.
	ParseFile(filename string, data []byte) (valid []model.Target, invalid []model.InvalidLine, err error)
	// Excluded counts the addresses of targets that the exclusions of the safety policy remove.
	Excluded(targets []model.Target, exclusions []string) int64
}

// Importer turns a result file (nmap XML, Czujka JSON, CSV; auto-detected) into
// host results. The report carries the format, the invalid rows and the
// skipped count. Implemented by internal/wire over internal/interchange.
type Importer interface {
	ParseResults(ctx context.Context, filename string, data []byte) (hosts []model.HostResult, report model.ImportReport, err error)
}

// ResultWriter streams the host results of one run in an exchange format.
type ResultWriter interface {
	WriteHost(h model.HostResult) error
	Close() error
}

// Exporter writes the results of one run as "xml" (nmap XML), "json" (Czujka
// JSON, lossless) or "csv". Files in these formats import again through
// Importer. Implemented by internal/wire over internal/interchange.
type Exporter interface {
	RunWriter(w io.Writer, format string, run model.ScanRun) (ResultWriter, error)
}

// DojoUpload is the outcome of the upload of a run's nmap XML to DefectDojo.
type DojoUpload struct {
	TestID   int64  `json:"test_id"`
	TestURL  string `json:"test_url"`
	Reimport bool   `json:"reimport"` // the test existed and was updated
	// Mode is "import" (first upload: a new test) or "reimport" (a later run
	// of the same profile into the same test, with close_old_findings).
	Mode        string `json:"mode"`
	Title       string `json:"title"` // the test title, the key of the test in the engagement
	Created     int    `json:"created"`
	Closed      int    `json:"closed"`
	Reactivated int    `json:"reactivated"`
	Untouched   int    `json:"untouched"`
	Total       int    `json:"total"`
}

// DojoLink ties an exported finding to its DefectDojo record.
type DojoLink struct {
	FindingID int64
	DojoID    int64
	URL       string
}

// DojoPull is the answer of the status pull: the proposed updates, the
// conflicts where the Czujka analyst wins, and how many updates were applied.
type DojoPull struct {
	defectdojo.StatusPull
	Applied int `json:"applied"`
	// Linked counts findings that an unconfirmed export had sent and that
	// the pull linked by key (dojo_id and dojo_url set).
	Linked int `json:"linked"`
}

// DojoClient talks to DefectDojo API v2. Implemented by internal/defectdojo.
type DojoClient interface {
	// PullStatus reads the DefectDojo state of exported findings; apply writes the proposed status updates.
	PullStatus(ctx context.Context, settings model.DefectDojoSettings, apply bool) (DojoPull, error)
	// SyncLifecycle closes resolved findings in DefectDojo and reopens observed ones.
	SyncLifecycle(ctx context.Context, settings model.DefectDojoSettings) (defectdojo.LifecycleResult, error)
	Test(ctx context.Context, settings model.DefectDojoSettings) (ok bool, message, version string)
	Export(ctx context.Context, settings model.DefectDojoSettings, findings []model.Finding) (model.DojoExportResult, []DojoLink, error)
	// UploadNmap sends the nmap XML of one run as an "Nmap Scan" import; the same title re-imports into the same test.
	UploadNmap(ctx context.Context, settings model.DefectDojoSettings, title string, xml io.Reader, scanDate time.Time) (DojoUpload, error)
}

// SignatureValidator parses and checks signature YAML. meta holds the fields
// read from the YAML (slug, name, category, description, author, tags, interest). Implemented by internal/sig.
type SignatureValidator interface {
	Validate(yaml string) (result model.SignatureValidation, meta model.Signature)
}

// RetroHunter matches a signature against stored observations without sending
// a packet. The adapter reads them with store.EachObservation. Implemented by internal/sig.
type RetroHunter interface {
	RetroHunt(ctx context.Context, yaml string, latestOnly bool) (model.RetroHuntResult, error)
}

// SignatureImportReport says what POST /signatures/import did with a file.
type SignatureImportReport struct {
	Created    []string                  `json:"created"`    // slugs of new custom signatures
	Updated    []string                  `json:"updated"`    // slugs of custom signatures that were replaced
	Skipped    []SignatureImportSkip     `json:"skipped"`    // valid signatures that were not stored, with the reason
	Validation model.SignatureValidation `json:"validation"` // issues of the whole file (rejected signatures and why)
}

// SignatureImportSkip is one signature that the import did not store.
type SignatureImportSkip struct {
	Slug   string `json:"slug"`
	Reason string `json:"reason"`
}

// SignatureImporter stores every valid signature of a file (Czujka YAML,
// JSON, lists, passive nuclei templates) as a custom row and reloads the
// engine. Implemented by internal/sigwire.
type SignatureImporter interface {
	ImportSignatures(ctx context.Context, text, author string) (SignatureImportReport, error)
}

// Reporter writes the report of one run as "html" or "md". Implemented by
// internal/wire over internal/report.
type Reporter interface {
	RunReport(ctx context.Context, runID int64, format string, w io.Writer) error
}

// PassiveResult is the answer of the passive routes: candidates with their
// source, hostname hints, facts outside the scope, and what each source did.
type PassiveResult struct {
	passive.Result
	File         *passive.FileReport `json:"file,omitempty"` // POST /passive/import: rows read and rejected
	HostsUpdated int                 `json:"hosts_updated"`  // POST /passive/ptr: known hosts that got new hostnames
}

// PassiveSources reads passive sources. Nothing is sent to a scope address.
// Implemented by internal/wire over internal/passive.
type PassiveSources interface {
	// ImportFile reads a DNS zone, CSV, JSON or JSONL file; nothing is saved.
	ImportFile(ctx context.Context, name string, data []byte) (PassiveResult, error)
	// PTR looks up the reverse names of the known live hosts and adds them to the hosts.
	PTR(ctx context.Context) (PassiveResult, error)
	// CT asks crt.sh for the certificates of the scope domains; only when an admin enabled it.
	CT(ctx context.Context) (PassiveResult, error)
}

// Analyzer is the part of internal/analyze that the API calls directly.
type Analyzer interface {
	// Diff compares any two runs.
	Diff(ctx context.Context, fromRunID, toRunID int64) (model.DiffReport, error)
	// DownAfterMisses tells how many misses in a row would now report the host inactive.
	DownAfterMisses(profile model.AvailabilityProfile) int
}

// Hooks are optional callbacks into other components.
type Hooks struct {
	// SignaturesChanged tells the signature engine to reload after a create, update or delete.
	SignaturesChanged func(ctx context.Context)
	// ProfileChanged tells the scheduler to recompute the next run of a profile (deleted = true after a delete).
	ProfileChanged func(ctx context.Context, profile model.ScanProfile, deleted bool)
}

// Deps is everything the API needs.
type Deps struct {
	Store   *store.Store
	Auth    *auth.Service
	Runner  RunManager
	Bus     *runner.Bus
	Logger  *slog.Logger
	Version string

	CookieSecure string // auto | true | false
	TrustProxy   bool   // take the client address from X-Forwarded-For
	WebDir       string // directory with the built UI; wins over WebFS
	WebFS        fs.FS  // embedded UI

	// Seams to other workers' packages; nil answers 501 not_wired.
	TargetParser TargetParser // nil uses the built-in basic parser
	Importer     Importer
	Exporter     Exporter
	Dojo         DojoClient
	Signatures   SignatureValidator
	RetroHunter  RetroHunter
	SigImporter  SignatureImporter
	Reporter     Reporter
	Passive      PassiveSources
	Analyzer     Analyzer
	Hooks        Hooks

	// Mounts are sub-routers of other packages, mounted under /api/v1.
	Mounts []Mount
	// Routes register routes of other packages directly on the /api/v1 router
	// (after the built-in routes), guarded by the permission middleware.
	Routes []func(r chi.Router, can Guard)

	// Lookup resolves domain targets for the allowed-networks check; nil uses the system resolver.
	Lookup runner.LookupFunc

	// Doctor runs the installation checks of GET /doctor (internal/doctor); nil answers 501.
	Doctor func(ctx context.Context) any

	// EngineInfo describes the prober for /healthz (prober, mode, raw_sockets); nil omits it.
	EngineInfo func() map[string]any
}
