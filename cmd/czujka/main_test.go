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
	if err := userCmd([]string{"create"}); err == nil || !strings.Contains(err.Error(), "--email") {
		t.Fatalf("missing --email: %v", err)
	}
}

func TestWireLeavesSeamsEmpty(t *testing.T) {
	// Nothing is faked: what other packages supply stays nil until the integration step sets it.
	if w := wire(config.Config{}, nil, nil); w.Engine != nil || w.API.Importer != nil || w.API.Dojo != nil {
		t.Fatalf("unexpected default wiring: %+v", w)
	}
}
