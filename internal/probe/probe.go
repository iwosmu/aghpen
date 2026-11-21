// Package probe finds live hosts, open ports and services. It wraps nmap
// (XML output, privilege detection) and has a native Go TCP-connect prober
// that is used when nmap is not installed. Both sit behind Prober.
//
// Safe detection only: no NSE script is requested, no login is tried and the
// native prober never sends application data.
package probe

import (
	"context"
	"log/slog"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Prober runs the three probe stages of a chunk.
type Prober interface {
	// Name is "nmap" or "native".
	Name() string
	// Privileged reports whether raw sockets are in use (SYN scan, ICMP, ARP).
	Privileged() bool
	// Discover finds the live hosts among the targets.
	Discover(ctx context.Context, req DiscoverRequest) (*Result, error)
	// PortScan finds the open ports of hosts that are known to be up.
	PortScan(ctx context.Context, req PortScanRequest) (*Result, error)
	// ServiceScan identifies the services on open ports.
	ServiceScan(ctx context.Context, req ServiceRequest) (*Result, error)
}

// DiscoverRequest is the input of the host-discovery stage.
type DiscoverRequest struct {
	Targets     []string // single IPs, CIDRs, "a.b.c.d-N" ranges; validated before use
	Opts        model.DiscoveryOpts
	MaxRate     int // probe packets per second for this process
	MaxRetries  int // 0 or less: the default (1)
	HostTimeout time.Duration
	IPv6        bool
	// ARPOnly asks for an ARP sweep alone (nmap -PR). The engine sets it when
	// every target is on a directly connected network and ARP is enabled:
	// every live host answers ARP, also one that drops all IP traffic.
	// Measured in the lab (docker bridge, 4 /24 blocks, 17 live hosts, 2 runs
	// each): -PR alone found 17 and 17; ARP mixed with -PE -PS -PA at the same
	// pinned rate found 8, 10, 4 and 7.
	ARPOnly bool
}

// PortScanRequest is the input of the port-scan stage.
type PortScanRequest struct {
	Hosts       []string
	Ports       *PortSet
	MaxRate     int
	MaxRetries  int
	HostTimeout time.Duration
	IPv6        bool
}

// HostPorts names the open ports of one host.
type HostPorts struct {
	IP    string
	Ports []int
}

// ServiceRequest is the input of the service-detection stage.
type ServiceRequest struct {
	Hosts       []HostPorts
	Intensity   int // nmap --version-intensity, 0..9
	MaxRate     int
	HostTimeout time.Duration
	IPv6        bool
}

// Result is the output of one stage.
type Result struct {
	Hosts        []Host
	Packets      int64 // probe packets sent
	PacketsExact bool  // true when nmap reported the raw packet count
	Elapsed      time.Duration
	Scanned      int // addresses nmap reports as scanned (0 when unknown)
}

// Host is one host in a stage result.
type Host struct {
	IP        string
	Up        bool
	Reason    string // echo-reply, syn-ack, reset, arp-response, conn-refused, tcp-connect ...
	RTTMs     float64
	MAC       string
	Vendor    string
	Hostnames []string
	Responded bool // the port scan got any answer (open or closed port)
	TimedOut  bool // nmap gave up on the host (--host-timeout): its ports are unknown
	Ports     []Port
}

// Port is one port of a host. Only open ports are kept.
type Port struct {
	Port       int
	Proto      string
	State      string
	Reason     string
	Name       string
	Product    string
	Version    string
	ExtraInfo  string
	CPE        []string
	Tunnel     string
	Method     string  // nmap: "probed" (matched a probe) or "table" (guessed from the port number)
	Confidence float64 // 0..1
	Banner     string
}

// Options choose and configure the prober.
type Options struct {
	NmapPath    string // empty: look for "nmap" in PATH
	ForceNative bool
	Logger      *slog.Logger
}

// New returns the nmap prober when nmap is installed and the native prober
// otherwise. It logs which one runs and with which privileges.
func New(opts Options) Prober {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	if !opts.ForceNative {
		n, err := NewNmap(opts.NmapPath, log)
		if err == nil {
			mode := "connect scan (-sT), TCP-connect host discovery; no raw sockets"
			if n.Privileged() {
				mode = "SYN scan (-sS), ICMP/TCP/ARP host discovery; raw sockets available"
			}
			log.Info("probe engine: nmap", "path", n.Path, "version", n.Version, "mode", mode)
			return n
		}
		log.Warn("probe engine: nmap is not available, using the native Go TCP-connect prober", "reason", err.Error())
	} else {
		log.Info("probe engine: native Go TCP-connect prober (forced)")
	}
	return NewNative(log)
}

// DefaultSynPorts and DefaultAckPorts are the TCP discovery probes used when
// a profile sets none.
var (
	DefaultSynPorts = []int{22, 80, 443, 3389, 8080}
	DefaultAckPorts = []int{80, 443}
)

// NormalizeDiscovery fills defaults: a profile with no probe at all gets ICMP
// echo and timestamp, TCP SYN and ACK probes and ARP.
func NormalizeDiscovery(o model.DiscoveryOpts) model.DiscoveryOpts {
	if !o.ICMPEcho && !o.ICMPTimestamp && len(o.TCPSynPorts) == 0 && len(o.TCPAckPorts) == 0 && !o.ARP && !o.SkipDiscovery {
		o.ICMPEcho, o.ICMPTimestamp, o.ARP = true, true, true
		o.TCPSynPorts = append([]int{}, DefaultSynPorts...)
		o.TCPAckPorts = append([]int{}, DefaultAckPorts...)
	}
	return o
}
