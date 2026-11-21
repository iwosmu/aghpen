package scan

import (
	"context"
	"reflect"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
)

// udpNet is fakeNet plus a UDP stage.
type udpNet struct {
	*fakeNet
	privileged bool
	reqs       []probe.UDPScanRequest
}

func (u *udpNet) Privileged() bool { return u.privileged }

func (u *udpNet) UDPScan(_ context.Context, req probe.UDPScanRequest) (*probe.Result, error) {
	u.reqs = append(u.reqs, req)
	res := &probe.Result{Packets: int64(len(req.Hosts) * len(req.Ports))}
	for _, ip := range req.Hosts {
		res.Hosts = append(res.Hosts, probe.Host{IP: ip, Up: true, Ports: []probe.Port{{Port: 53, Proto: "udp", State: "open", Reason: "udp-response", Name: "domain", Confidence: 0.3}}})
	}
	return res, nil
}

func TestUDPStage(t *testing.T) {
	plan := basePlan("10.7.0.0/28")
	plan.Profile.UDP = model.UDPOpts{Enabled: true}
	plan.Policy.DeniedPorts = "161,1900"

	netw := &udpNet{fakeNet: &fakeNet{hosts: map[string][]int{"10.7.0.5": {80}}}, privileged: true}
	sink := newSink()
	if out := New(Deps{Prober: netw, Logger: quiet}).Run(context.Background(), plan, sink); out.Status != model.RunCompleted || out.Stats.ServicesOpen != 2 {
		t.Fatalf("outcome = %+v", out)
	}
	if len(netw.reqs) != 1 || !reflect.DeepEqual(netw.reqs[0].Hosts, []string{"10.7.0.5"}) || !reflect.DeepEqual(netw.reqs[0].Ports, []int{53, 123, 137, 500, 5353}) {
		t.Fatalf("UDP requests = %+v (live hosts only, policy ports removed)", netw.reqs)
	}
	if netw.reqs[0].MaxRate <= 0 || netw.reqs[0].MaxRate > 300 {
		t.Errorf("UDP rate = %d, must be inside the packet budget", netw.reqs[0].MaxRate)
	}
	h := sink.host("10.7.0.5")
	if h == nil || len(h.Services) != 2 || h.Services[0].Proto != "tcp" || h.Services[0].Product != "nginx" {
		t.Fatalf("host = %+v", h)
	}
	if u := h.Services[1]; u.Proto != "udp" || u.Port != 53 || u.State != "open" || u.Name != "domain" || u.HTTP != nil {
		t.Errorf("udp service = %+v", u)
	}

	// off by default
	plan.Profile.UDP.Enabled = false
	netw = &udpNet{fakeNet: &fakeNet{hosts: map[string][]int{"10.7.0.5": {80}}}, privileged: true}
	New(Deps{Prober: netw, Logger: quiet}).Run(context.Background(), plan, newSink())
	if len(netw.reqs) != 0 {
		t.Error("UDP must be off by default")
	}
	// without raw sockets the stage is skipped and the run still completes
	plan.Profile.UDP.Enabled = true
	netw = &udpNet{fakeNet: &fakeNet{hosts: map[string][]int{"10.7.0.5": {80}}}}
	sink = newSink()
	if out := New(Deps{Prober: netw, Logger: quiet}).Run(context.Background(), plan, sink); out.Status != model.RunCompleted || len(netw.reqs) != 0 || len(sink.host("10.7.0.5").Services) != 1 {
		t.Errorf("unprivileged: %+v, UDP requests %d", out, len(netw.reqs))
	}
	// a prober without a UDP stage (the native one) is skipped too
	plain := &fakeNet{hosts: map[string][]int{"10.7.0.5": {80}}}
	if out := New(Deps{Prober: plain, Logger: quiet}).Run(context.Background(), plan, newSink()); out.Status != model.RunCompleted {
		t.Errorf("no UDP stage: %+v", out)
	}
}
