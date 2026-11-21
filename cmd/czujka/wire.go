package main

import (
	"log/slog"

	"github.com/iwosmu/aghpen/internal/config"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/wire"
)

// wire connects the packages of Czujka. The adapters and the list of what is
// wired live in internal/wire (Build); cmd/czujka only starts them.
func wire2(cfg config.Config, st *store.Store, log *slog.Logger) wire.Wiring {
	return wire.Build(cfg, st, log)
}
