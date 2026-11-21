package main

import (
	"testing"

	"github.com/iwosmu/aghpen/internal/reprobe"
)

func TestTargetedRequest(t *testing.T) {
	pid := int64(7)
	s := targetedRequest(reprobe.Request{ProfileID: &pid, Reason: "potwierdzenie", Targets: []reprobe.Target{
		{IP: "10.0.0.2", Ports: []int{80, 22}}, {IP: "10.0.0.3", Ports: []int{443, 80, 0}}, {IP: "10.0.0.2", Ports: []int{8080}}, {IP: " "},
	}})
	if s.ProfileID != 7 || s.Reason != "potwierdzenie" || len(s.Addresses) != 2 || s.Addresses[0] != "10.0.0.2" || s.Addresses[1] != "10.0.0.3" {
		t.Fatalf("scope: %+v", s)
	}
	if s.Ports != "22,80,443" {
		t.Fatalf("ports %q, want the sorted union of the first entry of each address", s.Ports)
	}
	if e := targetedRequest(reprobe.Request{Targets: []reprobe.Target{{IP: "10.0.0.9"}}}); e.Ports != "" || e.ProfileID != 0 {
		t.Fatalf("no ports: %+v", e)
	}
}
