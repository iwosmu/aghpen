package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iwosmu/aghpen/internal/api"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/reprobe"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/timeline"
)

// seedReprobe stores the default re-probing settings (enabled) when none are
// stored. Re-probing sends the profile's own probes to single addresses that
// a scan already found, within an hourly budget, the safety policy and the
// emergency stop; it confirms a silent host within minutes instead of waiting
// for the next scheduled scan. An administrator can turn it off
// (PUT /api/v1/settings/reprobe). It reports whether it stored them.
func seedReprobe(ctx context.Context, st *store.Store) (bool, error) {
	s := reprobe.DefaultSettings()
	raw, err := json.Marshal(s)
	if err != nil {
		return false, err
	}
	tag, err := st.Pool().Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ('reprobe', $1::jsonb, now()) ON CONFLICT (key) DO NOTHING`, raw)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// targetedRequest turns a re-probe request into the ad-hoc scope of a run:
// the addresses, and the union of their known ports (empty: the profile ports).
func targetedRequest(req reprobe.Request) model.AdHocScope {
	scope := model.AdHocScope{Reason: req.Reason}
	if req.ProfileID != nil {
		scope.ProfileID = *req.ProfileID
	}
	ports := map[int]bool{}
	seen := map[string]bool{}
	for _, t := range req.Targets {
		ip := strings.TrimSpace(t.IP)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		scope.Addresses = append(scope.Addresses, ip)
		for _, p := range t.Ports {
			if p > 0 && p <= 65535 {
				ports[p] = true
			}
		}
	}
	list := make([]int, 0, len(ports))
	for p := range ports {
		list = append(list, p)
	}
	sort.Ints(list)
	parts := make([]string, len(list))
	for i, p := range list {
		parts[i] = strconv.Itoa(p)
	}
	scope.Ports = strings.Join(parts, ",")
	return scope
}

// targeted is the runner capability of the re-probe executor (StartTargeted):
// a run on exactly the requested addresses and ports through the normal
// engine, safety policy, sink and analysis, with trigger "reprobe" and no
// profile id. The plan hints every requested address, so a silent one gets a
// down observation.
func targeted(mgr *runner.Manager) reprobe.Starter {
	return func(ctx context.Context, req reprobe.Request) (model.ScanRun, error) {
		trigger := req.Trigger
		if trigger == "" {
			trigger = runner.TriggerReprobe
		}
		return mgr.StartAdHoc(ctx, targetedRequest(req), nil, trigger)
	}
}

// timeMachine wires the time machine and model-driven re-probing (they live
// outside internal/wire: their integration tests import it). It returns the
// route registration for the API and starts the re-probe executor.
func timeMachine(ctx context.Context, st *store.Store, mgr *runner.Manager, loc *time.Location, log *slog.Logger) (func(r chi.Router, can api.Guard), error) {
	tl := timeline.New(st, log)
	if err := tl.Start(ctx); err != nil {
		return nil, fmt.Errorf("timeline: %w", err)
	}
	rb := reprobe.NewStoreBackend(st, loc, nil, log)
	if err := rb.Init(ctx); err != nil {
		return nil, fmt.Errorf("reprobe: %w", err)
	}
	if seeded, err := seedReprobe(ctx, st); err != nil {
		return nil, fmt.Errorf("reprobe settings: %w", err)
	} else if seeded {
		log.Info("first start: re-probing is on (confirmation probes of silent hosts, budgeted); PUT /api/v1/settings/reprobe turns it off")
	}
	rb.SetStarter(targeted(mgr))
	go (&reprobe.Executor{B: rb, Log: log}).Run(ctx)
	return func(r chi.Router, can api.Guard) {
		tl.Register(r, timeline.Middleware(can))
		(&reprobe.Service{B: rb}).Register(r, reprobe.Middleware(can))
	}, nil
}
