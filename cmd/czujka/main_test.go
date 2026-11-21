package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/config"
)

func TestHealthcheckCommand(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("path %q", r.URL.Path)
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	t.Setenv("CZUJKA_LISTEN", strings.TrimPrefix(srv.URL, "http://"))
	if err := healthcheck(); err != nil {
		t.Fatalf("healthy server: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := healthcheck(); err == nil {
		t.Fatal("an unhealthy server must fail the check")
	}
	srv.Close()
	if err := healthcheck(); err == nil {
		t.Fatal("a stopped server must fail the check")
	}
}

func TestUserCommandNeedsArguments(t *testing.T) {
	if err := userCmd(nil); err == nil {
		t.Fatal("no subcommand must be an error")
	}
	if err := userCmd([]string{"unlock"}); err == nil || !strings.Contains(err.Error(), "user unlock EMAIL") {
		t.Fatalf("unlock without an e-mail: %v", err)
	}
	if err := userCmd([]string{"create"}); err == nil || !strings.Contains(err.Error(), "--email") {
		t.Fatalf("missing --email: %v", err)
	}
}

func TestWiring(t *testing.T) {
	w := wire2(config.Config{Timezone: "Europe/Warsaw"}, nil, nil)
	if w.RunAnalyzer == nil || w.API.Analyzer == nil || w.API.Importer == nil || w.API.Exporter == nil || w.API.Dojo == nil {
		t.Fatalf("missing wiring: %+v", w)
	}
	if w.Engine == nil || w.Window == nil || w.PauseCause == nil || w.API.Signatures == nil || w.API.RetroHunter == nil ||
		w.API.SigImporter == nil || w.API.Reporter == nil || w.API.Passive == nil || w.API.TargetParser == nil ||
		w.API.Hooks.SignaturesChanged == nil || w.API.Hooks.ProfileChanged == nil || w.API.EngineInfo == nil {
		t.Fatalf("missing wiring: %+v", w)
	}
	// Without the embedui build tag the binary carries no UI.
	if w.API.WebFS != nil {
		t.Fatalf("WebFS set without the embedui tag")
	}
}
