package main

import (
	"strings"
	"testing"
)

const sample = `{"run_id":1,"ip":"10.77.0.20","hostnames":[],"up":true,"reason":"arp-response","rtt_ms":0.5,"attempts":1,"services":[{"port":22,"proto":"tcp","state":"open","name":"ssh","product":"OpenSSH","version":"9.7","confidence":1}]}
{"run_id":1,"ip":"10.77.0.10","hostnames":[],"up":true,"reason":"arp-response","attempts":1,"services":[{"port":80,"proto":"tcp","state":"open","name":"http","product":"nginx","version":"1.31.9","confidence":1}]}
{"summary":{"status":"completed","prober":"nmap","sessions":1,"limit_pps":500,"stats":{"avg_pps":59.1,"chunks_total":4,"chunks_done":4},"groups":[{"id":1,"size":256,"rate_pps":250,"pps":77.3}],"chunks_by_status":{"done":4}}}
`

func TestParseAndChecks(t *testing.T) {
	out, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Hosts) != 2 || out.Hosts[0].IP != "10.77.0.10" || out.Summary == nil || out.Summary.LimitPPS != 500 {
		t.Fatalf("parsed = %+v", out)
	}
	fails := CheckLab(out, true)
	if len(fails) != 5 { // five lab hosts are missing in the sample
		t.Errorf("fails = %v", fails)
	}
	if f := CheckRate(out.Summary); len(f) != 0 {
		t.Errorf("rate fails = %v", f)
	}
	out.Summary.Groups[0].PPS = 300
	if f := CheckRate(out.Summary); len(f) != 1 {
		t.Errorf("a group over its share must fail: %v", f)
	}
	out.Hosts[0].Services[0].Name = "ftp"
	if f := CheckLab(out, true); len(f) != 6 {
		t.Errorf("a wrong service name must fail: %v", f)
	}
	if f := CheckLab(out, false); len(f) != 5 {
		t.Errorf("ports-only mode ignores names: %v", f)
	}
	if f := CheckRate(nil); len(f) != 1 {
		t.Error("a missing summary must fail")
	}
}
