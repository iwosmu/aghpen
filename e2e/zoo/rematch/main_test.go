package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

func TestRematchReplacesMatches(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in.json"), filepath.Join(dir, "out.json")
	svc := model.ServiceResult{Port: 8080, Proto: "tcp", Name: "http", Technologies: []model.Technology{{Name: "Stale"}},
		HTTP: &model.HTTPFingerprint{Scheme: "http", Status: 200, Title: "phpMyAdmin", BodyExcerpt: "<input name=\"pma_username\">"}}
	b, _ := json.Marshal(map[string]any{"format": "czujka-json", "hosts": []model.HostResult{{IP: "10.0.0.1", Services: []model.ServiceResult{svc}}}})
	if err := os.WriteFile(in, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(in, out, true); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Format string             `json:"format"`
		Hosts  []model.HostResult `json:"hosts"`
	}
	ob, _ := os.ReadFile(out)
	if err := json.Unmarshal(ob, &env); err != nil {
		t.Fatal(err)
	}
	if env.Format != "czujka-json" {
		t.Error("the envelope lost its other fields")
	}
	techs := env.Hosts[0].Services[0].Technologies
	if len(techs) == 0 || techs[0].Name != "phpMyAdmin" {
		t.Errorf("technologies after rematch: %+v", techs)
	}
}
