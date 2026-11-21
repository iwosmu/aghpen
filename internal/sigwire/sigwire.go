// Package sigwire connects the signature engine (internal/sig) to the store
// and to the seams of the API (internal/api/deps.go).
//
// One Wire owns the shared *sig.Engine of the process. In cmd/czujka/wire.go:
//
//	sw := sigwire.New(st, logger)
//	if err := sw.Start(ctx); err != nil { ... }     // seed the built-ins, load the engine
//	w.API.Signatures  = sw                           // api.SignatureValidator
//	w.API.RetroHunter = sw                           // api.RetroHunter
//	w.API.Hooks.SignaturesChanged = sw.Changed       // reload after create, update, delete
//	scanEngine := scan.New(..., sw.Engine(), ...)    // model.SignatureEngine
//	// after a finished run or import:  sw.UpdateMatchCounts(ctx)
//	// optional, a whole signature file in any accepted format:  sw.Import(ctx, text, author)
package sigwire

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/sig"
	"github.com/iwosmu/aghpen/internal/store"
)

// DefaultMaxHits bounds the hit list of one retro-hunt. The total is still counted.
const DefaultMaxHits = 5000

// Wire is the store-backed signature service. It is safe for concurrent use.
type Wire struct {
	st  *store.Store
	log *slog.Logger
	eng *sig.Engine

	// MaxHits bounds the hit list of a retro-hunt (0: DefaultMaxHits, negative: no limit).
	MaxHits int

	mu   sync.Mutex // serialises Seed and Reload
	last ReloadReport
}

// SeedReport says what Seed did.
type SeedReport struct {
	Builtin int   `json:"builtin"` // signatures in the embedded library
	Removed int64 `json:"removed"` // built-in rows that the library no longer has
	TookMs  int64 `json:"took_ms"`
}

// ReloadReport says what Reload did.
type ReloadReport struct {
	Rows     int            `json:"rows"`     // rows read from the store
	Loaded   int            `json:"loaded"`   // signatures in the engine
	Enabled  int            `json:"enabled"`  // enabled signatures
	Rejected []sig.Rejected `json:"rejected"` // rows that the validator refused
	Paths    int            `json:"paths"`    // extra paths the enabled signatures ask for
	TookMs   int64          `json:"took_ms"`
}

// New returns a Wire with an empty engine. Call Start before the first scan.
func New(st *store.Store, logger *slog.Logger) *Wire {
	if logger == nil {
		logger = slog.Default()
	}
	return &Wire{st: st, log: logger, eng: sig.NewEngine()}
}

var (
	_ model.SignatureEngine = (*sig.Engine)(nil)
)

// Engine returns the shared engine. It is the model.SignatureEngine of the
// scan engine; Reload swaps its signature set in place, so the pointer never
// changes.
func (w *Wire) Engine() *sig.Engine { return w.eng }

// Start seeds the built-in library into the store and loads the engine.
func (w *Wire) Start(ctx context.Context) error {
	if _, err := w.Seed(ctx); err != nil {
		return err
	}
	_, err := w.Reload(ctx)
	return err
}

// Seed writes the embedded library into the signatures table as built-in
// rows. A built-in row is refreshed when the embedded YAML changed; the
// enabled flag of an existing row (the analyst's choice) is kept. Built-in
// rows that the library no longer has are removed. Custom rows are not touched.
func (w *Wire) Seed(ctx context.Context) (SeedReport, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	start := time.Now()
	lib, err := sig.Builtin()
	if err != nil {
		return SeedReport{}, fmt.Errorf("sigwire: built-in library: %w", err)
	}
	if err := w.st.UpsertBuiltinSignatures(ctx, lib); err != nil {
		return SeedReport{}, fmt.Errorf("sigwire: seed built-in signatures: %w", err)
	}
	slugs := make([]string, len(lib))
	for i, s := range lib {
		slugs[i] = s.Slug
	}
	tag, err := w.st.Pool().Exec(ctx, `DELETE FROM signatures WHERE builtin AND NOT (slug = ANY($1::text[]))`, slugs)
	if err != nil {
		return SeedReport{}, fmt.Errorf("sigwire: remove retired built-in signatures: %w", err)
	}
	rep := SeedReport{Builtin: len(lib), Removed: tag.RowsAffected(), TookMs: time.Since(start).Milliseconds()}
	w.log.Info("signatures seeded", "builtin", rep.Builtin, "removed", rep.Removed, "took_ms", rep.TookMs)
	return rep, nil
}

// Reload reads every signature row and swaps the set of the engine. A row
// that the validator refuses is logged and skipped; it never stops the load.
// When the store cannot be read, the engine keeps its current set.
func (w *Wire) Reload(ctx context.Context) (ReloadReport, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	start := time.Now()
	var rows []model.Signature
	err := w.st.EachSignature(ctx, store.SignatureFilter{}, func(s *model.Signature) error {
		rows = append(rows, *s)
		return nil
	})
	if err != nil {
		w.log.Error("signature reload failed; the engine keeps its current set", "error", err)
		return w.last, fmt.Errorf("sigwire: read signatures: %w", err)
	}
	load := w.eng.Load(rows)
	rep := ReloadReport{Rows: len(rows), Loaded: load.Loaded, Enabled: load.Enabled, Rejected: load.Rejected,
		Paths: len(w.eng.ExtraPaths()), TookMs: time.Since(start).Milliseconds()}
	if rep.Rejected == nil {
		rep.Rejected = []sig.Rejected{}
	}
	for _, r := range rep.Rejected {
		reason := ""
		if len(r.Issues) > 0 {
			reason = r.Issues[0].Path + ": " + r.Issues[0].Message
		}
		w.log.Warn("signature rejected; it is not loaded", "slug", r.Slug, "issues", len(r.Issues), "reason", reason)
	}
	w.log.Info("signatures loaded", "rows", rep.Rows, "loaded", rep.Loaded, "enabled", rep.Enabled,
		"rejected", len(rep.Rejected), "paths", rep.Paths, "took_ms", rep.TookMs)
	w.last = rep
	return rep, nil
}

// Changed is the api.Hooks.SignaturesChanged callback.
func (w *Wire) Changed(ctx context.Context) {
	_, _ = w.Reload(ctx) // Reload logs the error and keeps the current set
}

// LastReload returns the report of the last successful Reload.
func (w *Wire) LastReload() ReloadReport {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.last
}

// Validate is api.SignatureValidator. meta holds the fields read from the
// YAML. A text with more than one signature is refused here: one store row
// holds one signature. A text in a foreign format (JSON, a nuclei template)
// is accepted when it converts to one safe signature; meta.YAML then holds
// the converted Czujka YAML.
func (w *Wire) Validate(yaml string) (model.SignatureValidation, model.Signature) {
	sigs, val := sig.Parse(yaml)
	if val.Issues == nil {
		val.Issues = []model.SignatureIssue{}
	}
	if val.Paths == nil {
		val.Paths = []string{}
	}
	if len(sigs) > 1 {
		val.OK = false
		val.Issues = append(val.Issues, model.SignatureIssue{Level: "error", Path: "",
			Message: fmt.Sprintf("tekst zawiera %d sygnatur; jeden rekord przechowuje jedną sygnaturę. Dodaj je osobno.", len(sigs))})
	}
	if len(sigs) == 0 {
		return val, model.Signature{}
	}
	meta := sigs[0].Model()
	if meta.Tags == nil {
		meta.Tags = []string{}
	}
	return val, meta
}

// RetroHunt is api.RetroHunter. It streams the stored observations from the
// store into the matcher one at a time, so memory use does not grow with the
// number of observations. It sends no packet. With latestOnly it checks only
// the newest observation of every service. Without cookieValues (a caller
// without results:update) cookie values are blanked before matching.
func (w *Wire) RetroHunt(ctx context.Context, yaml string, latestOnly, cookieValues bool) (model.RetroHuntResult, error) {
	h, val := sig.NewHunter(yaml)
	if h == nil {
		var msgs []string
		for _, is := range val.Issues {
			if is.Level == "error" {
				msgs = append(msgs, strings.TrimSpace(is.Path+": "+is.Message))
			}
		}
		return model.RetroHuntResult{}, errors.New("sygnatura odrzucona: " + strings.Join(msgs, "; "))
	}
	switch {
	case w.MaxHits == 0:
		h.MaxHits = DefaultMaxHits
	case w.MaxHits > 0:
		h.MaxHits = w.MaxHits
	}
	err := w.st.EachObservation(ctx, store.ObsFilter{LatestOnly: latestOnly}, func(o *store.ObservationRow) error {
		if o.Result.Port == 0 {
			o.Result.Port = o.Port
		}
		if !cookieValues && o.Result.HTTP != nil {
			// Names and flags stay; a value rule then never matches, so hit
			// or no hit tells nothing about the value (security review M1).
			for i := range o.Result.HTTP.Cookies {
				o.Result.HTTP.Cookies[i].Value = ""
			}
		}
		h.Add(&o.ServiceObservation, o.IP)
		return ctx.Err()
	})
	res := h.Result()
	if err != nil {
		return res, fmt.Errorf("sigwire: read observations: %w", err)
	}
	w.log.Info("retro-hunt done", "scanned", res.Scanned, "hits", res.TotalHits, "latest_only", latestOnly, "took_ms", res.TookMs)
	return res, nil
}

// UpdateMatchCounts stores, for every signature, the number of services whose
// newest observation it matched (Signature.MatchCount). It counts the matches
// that the scan stored, in one query; it does not match again. Call it after
// a finished run or import.
func (w *Wire) UpdateMatchCounts(ctx context.Context) (map[string]int, error) {
	rows, err := w.st.Pool().Query(ctx, `
		SELECT m->>'signature' AS slug, count(*)::int
		FROM (SELECT DISTINCT ON (o.service_id) o.result
		      FROM service_observations o ORDER BY o.service_id, o.at DESC, o.id DESC) l,
		     jsonb_array_elements(CASE WHEN jsonb_typeof(l.result->'matches') = 'array' THEN l.result->'matches' ELSE '[]'::jsonb END) m
		GROUP BY 1`)
	if err != nil {
		return nil, fmt.Errorf("sigwire: count matches: %w", err)
	}
	counts := map[string]int{}
	for rows.Next() {
		var slug *string
		var n int
		if err := rows.Scan(&slug, &n); err != nil {
			rows.Close()
			return nil, fmt.Errorf("sigwire: count matches: %w", err)
		}
		if slug != nil && *slug != "" {
			counts[*slug] = n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sigwire: count matches: %w", err)
	}
	// A signature that no longer matches anything must go back to zero.
	all := make(map[string]int, len(counts))
	for _, s := range w.eng.Signatures() {
		all[s.Slug] = 0
	}
	for slug, n := range counts {
		all[slug] = n
	}
	if err := w.st.SetSignatureMatchCounts(ctx, all); err != nil {
		return nil, fmt.Errorf("sigwire: store match counts: %w", err)
	}
	return counts, nil
}
