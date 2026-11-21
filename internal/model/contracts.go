package model

import (
	"context"
	"time"
)

// The interfaces in this file are the seams between the packages that are
// built in parallel. Each package depends on these interfaces, not on the
// concrete types of another package.

// FingerprintRequest asks the HTTP/TLS collector to look at one open TCP port.
type FingerprintRequest struct {
	IP        string
	Port      int
	Hostname  string // optional; used as SNI and Host header
	TLSHint   bool   // nmap reported an ssl tunnel
	NameHint  string // nmap service name, may be empty
	Opts      HTTPOpts
	UserAgent string
	Paths     []string // extra safe paths to GET, already capped by the safety policy
}

// Fingerprinter collects HTTP and TLS data from one service. It returns
// (nil, nil, nil) when the port does not speak HTTP or TLS.
// Implemented by internal/httpfp.
type Fingerprinter interface {
	Fingerprint(ctx context.Context, req FingerprintRequest) (*HTTPFingerprint, *TLSInfo, error)
}

// SignatureEngine evaluates the enabled signatures against one service result.
// It fills nothing itself; the caller stores the returned values.
// Implemented by internal/sig.
type SignatureEngine interface {
	// Match returns signature matches, the technologies derived from them
	// (confidence combined by noisy-OR) and the service classes.
	Match(svc *ServiceResult) (matches []SigMatch, techs []Technology, classes []string)
	// ExtraPaths returns the safe paths that enabled signatures need, most useful first.
	ExtraPaths() []string
}

// HostHint is what the inventory already knows about an address. The engine
// uses hints to order chunks (known live blocks first) and to retry hosts
// that were up before and do not answer now.
type HostHint struct {
	IP        string
	OpenPorts []int
	Stability float64
	LastUp    time.Time
}

// ScanPlan is the full input of one engine run.
type ScanPlan struct {
	RunID       int64
	Targets     []Target // enabled targets of the profile scopes
	Profile     ScanProfile
	Policy      SafetyPolicy
	Hints       []HostHint
	Chunks      []Chunk    // not empty when a paused run resumes: pending and deferred chunks to do
	WindowEnd   *time.Time // stop cleanly before this time and defer the rest
	PrevStats   *RunStats  // stats so far when resuming
	MeasuredPPS float64    // speed measured in earlier runs of this profile; 0 when unknown
}

// ResultSink receives engine output. The store-backed implementation persists
// it; tests use an in-memory one. Calls can come from several goroutines.
type ResultSink interface {
	// OnPlan is called once with the planned chunks (also on resume, with the remaining ones).
	OnPlan(ctx context.Context, runID int64, chunks []Chunk) error
	// OnChunk is called when a chunk changes status.
	OnChunk(ctx context.Context, chunk Chunk) error
	// OnHost is called once per address that was up now or that a hint named.
	// Addresses with no answer and no hint are not reported.
	OnHost(ctx context.Context, res HostResult) error
	// OnProgress is called about once per second while the run is active.
	OnProgress(ctx context.Context, runID int64, stats RunStats) error
}

// RunOutcome is the engine's answer when Run returns.
type RunOutcome struct {
	Status      RunStatus // completed, paused, cancelled or failed
	PauseReason string
	Stats       RunStats
	Err         error
}

// Engine runs one scan plan. Cancel the context to stop; the engine then
// marks unfinished chunks as deferred and returns RunPaused or RunCancelled.
// Implemented by internal/scan.
type Engine interface {
	Run(ctx context.Context, plan ScanPlan, sink ResultSink) RunOutcome
	// Estimate computes the traffic budget without sending anything.
	Estimate(plan ScanPlan) ScanEstimate
}
