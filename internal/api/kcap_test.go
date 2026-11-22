package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/kcap"
	"github.com/iwosmu/aghpen/internal/model"
)

// kernel_cap is added next to the fields of the policy, which stay where they are.
func TestSafetyViewAddsKernelCap(t *testing.T) {
	st := kcap.Status{Mode: kcap.ModeAuto, Active: true, PPS: 550, Burst: 55, PolicyPPS: 500, Dropped: 7}
	b, err := json.Marshal(safetyView{SafetyPolicy: model.SafetyPolicy{MaxPPS: 500, AllowedMethods: []string{"GET"}}, KernelCap: &st})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"max_pps":500`, `"allowed_methods":["GET"]`, `"kernel_cap":{"mode":"auto","active":true,"pps":550,"burst":55,"policy_pps":500,"dropped":7}`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	b, _ = json.Marshal(safetyView{SafetyPolicy: model.SafetyPolicy{MaxPPS: 500}})
	if strings.Contains(string(b), "kernel_cap") {
		t.Errorf("no cap, no field: %s", b)
	}
	var back model.SafetyPolicy // a client that knows only the policy still reads it
	if err := json.Unmarshal(b, &back); err != nil || back.MaxPPS != 500 {
		t.Fatalf("decode: %+v %v", back, err)
	}
}
