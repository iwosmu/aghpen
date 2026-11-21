package probe

import (
	"context"
	"errors"
	"sort"
	"time"
)

// UDPServices is the allow-list of the UDP scan: services that answer a
// harmless protocol query. nmap sends one protocol payload per port (a DNS
// status request, an NTP client request, a NetBIOS name query, an SNMPv3
// engine discovery, an IKE proposal, an SSDP search, an mDNS query). No
// community string, no credentials, nothing that changes state.
var UDPServices = map[int]string{
	53: "domain", 123: "ntp", 137: "netbios-ns", 161: "snmp", 500: "isakmp", 1900: "upnp", 5353: "mdns",
}

// ErrNoRawSockets means the UDP scan cannot run: nmap needs raw sockets for it.
var ErrNoRawSockets = errors.New("the UDP scan needs nmap with raw sockets (root or CAP_NET_RAW)")

// UDPPorts returns the UDP ports to probe: the allow-list, cut down to spec
// when it is not empty, then filtered by the allowed and denied ports of
// the safety policy.
func UDPPorts(spec, allowed, denied string) ([]int, error) {
	var list []int
	for p := range UDPServices {
		list = append(list, p)
	}
	sort.Ints(list)
	if spec != "" {
		want, err := ParsePorts(spec)
		if err != nil {
			return nil, err
		}
		kept := list[:0]
		for _, p := range list {
			if want.Has(p) {
				kept = append(kept, p)
			}
		}
		list = kept
	}
	return FilterPorts(list, allowed, denied)
}

// UDPScanRequest is the input of the UDP stage.
type UDPScanRequest struct {
	Hosts       []string
	Ports       []int
	MaxRate     int
	HostTimeout time.Duration
	IPv6        bool
}

// UDPScanner is the optional UDP stage of a prober. Only nmap with raw
// sockets has it.
type UDPScanner interface {
	UDPScan(ctx context.Context, req UDPScanRequest) (*Result, error)
}

// UDPArgs builds the UDP command line (without targets). Version detection
// is off on purpose: its SNMP probe carries the community string "public".
// A port counts as open only when the service answered the query.
func (n *Nmap) UDPArgs(req UDPScanRequest) []string {
	var ports []int
	for _, p := range req.Ports {
		if _, ok := UDPServices[p]; ok {
			ports = append(ports, p)
		}
	}
	args := []string{"-sU", "-Pn", "-p", "U:" + portList(ports)}
	return append(args, n.commonArgs(req.MaxRate, 1, req.HostTimeout, req.IPv6)...)
}

// UDPScan probes the allow-listed UDP ports of hosts that are up.
func (n *Nmap) UDPScan(ctx context.Context, req UDPScanRequest) (*Result, error) {
	if !n.privileged {
		return nil, ErrNoRawSockets
	}
	args := n.UDPArgs(req)
	if args[3] == "U:" {
		return &Result{}, nil
	}
	res, err := n.run(ctx, "udp", args, req.Hosts)
	if err != nil {
		return res, err
	}
	if !res.PacketsExact {
		res.Packets = int64(len(req.Hosts)) * int64(len(req.Ports)) * 2
	}
	for i := range res.Hosts {
		kept := res.Hosts[i].Ports[:0]
		for _, p := range res.Hosts[i].Ports {
			if p.Proto != "udp" {
				continue
			}
			if p.Name == "" {
				p.Name = UDPServices[p.Port]
			}
			kept = append(kept, p)
		}
		res.Hosts[i].Ports = kept
	}
	return res, nil
}
