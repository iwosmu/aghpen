package probe

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// UDPServices is the allow-list of the UDP scan: services that answer a
// harmless protocol query (a DNS request, an NTP client request, a NetBIOS
// name query, an IKE proposal, an SSDP search, an mDNS query, an SNMPv3
// engine discovery). No community string, no credentials, nothing that
// changes state.
//
// SNMP is not probed by nmap. nmap 7.94 and later take the UDP payloads
// from nmap-service-probes, and its probes for port 161 include an SNMPv1
// GetRequest with the community string "public": a default-credential
// guess. The engine sends its own SNMPv3 engine discovery instead.
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

// snmpPort is probed by the engine itself, never by nmap.
const snmpPort = 161

// snmpEngineDiscovery is the SNMPv3 engine discovery request (RFC 3414,
// section 4): an empty GetRequest with no user name and no authentication.
// An SNMP agent answers it with a Report that carries its engine ID.
var snmpEngineDiscovery = []byte{
	0x30, 0x3a, 0x02, 0x01, 0x03, 0x30, 0x0f, 0x02, 0x02, 0x4a, 0x69, 0x02,
	0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10,
	0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00,
	0x04, 0x00, 0x04, 0x00, 0x30, 0x12, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0c,
	0x02, 0x02, 0x37, 0xf0, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
}

// snmpProbe sends the engine discovery to addr (ip:port) up to two times
// and reports whether an SNMP message came back. sent is the packet count.
func snmpProbe(ctx context.Context, addr string, timeout time.Duration, lim *Limiter) (open bool, product string, sent int64) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return false, "", 0
	}
	defer conn.Close()
	buf := make([]byte, 1500)
	for try := 0; try < 2; try++ {
		if lim.Wait(ctx) != nil {
			return false, "", sent
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(snmpEngineDiscovery); err != nil {
			return false, "", sent // ICMP port unreachable from an earlier try: closed
		}
		sent++
		n, err := conn.Read(buf)
		if err == nil && n > 2 && buf[0] == 0x30 { // an ASN.1 sequence: an SNMP message
			return true, snmpVendor(buf[:n]), sent
		}
		var ne net.Error
		if err != nil && !(errors.As(err, &ne) && ne.Timeout()) {
			return false, "", sent // refused: the port is closed
		}
	}
	return false, "", sent
}

// snmpEnterprises maps the IANA enterprise number in an SNMP engine ID
// (RFC 3411, SnmpEngineID: the first four bytes are 0x80000000 | enterprise)
// to the agent's product. Only agents whose engine ID names the software.
var snmpEnterprises = map[uint32]string{
	8072: "net-snmp", 2021: "net-snmp", 9: "Cisco SNMP agent", 311: "Microsoft SNMP agent",
	2636: "Juniper SNMP agent", 14988: "MikroTik SNMP agent", 41112: "Ubiquiti SNMP agent",
	6876: "VMware SNMP agent", 11: "HP SNMP agent", 6574: "Synology SNMP agent",
}

// snmpVendor reads the authoritative engine ID from an SNMPv3 Report (the
// answer to engine discovery) and returns the product its enterprise number
// names, or "". The engine ID is the first OCTET STRING of 5 to 32 bytes
// whose first byte has the high bit set.
func snmpVendor(msg []byte) string {
	for i := 0; i+2 < len(msg); i++ {
		if msg[i] != 0x04 {
			continue
		}
		l := int(msg[i+1])
		if l < 5 || l > 32 || i+2+l > len(msg) || msg[i+2]&0x80 == 0 {
			continue
		}
		id := msg[i+2 : i+2+l]
		ent := (uint32(id[0])&0x7f)<<24 | uint32(id[1])<<16 | uint32(id[2])<<8 | uint32(id[3])
		return snmpEnterprises[ent]
	}
	return ""
}

// snmpScan probes port 161 of every host, a few hosts at a time, under the rate limit.
func snmpScan(ctx context.Context, hosts []string, maxRate int, timeout time.Duration) (open map[string]string, sent int64) {
	lim := NewLimiter(float64(max(1, maxRate)), 1)
	open = map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for _, ip := range hosts {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ok, product, n := snmpProbe(ctx, net.JoinHostPort(ip, strconv.Itoa(snmpPort)), timeout, lim)
			mu.Lock()
			sent += n
			if ok {
				open[ip] = product
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return open, sent
}

// UDPArgs builds the UDP command line (without targets). Version detection
// is off, and port 161 never goes to nmap (see UDPServices). A port counts
// as open only when the service answered the query.
func (n *Nmap) UDPArgs(req UDPScanRequest) []string {
	var ports []int
	for _, p := range req.Ports {
		if _, ok := UDPServices[p]; ok && p != snmpPort {
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
	res := &Result{}
	if args := n.UDPArgs(req); args[3] != "U:" {
		var err error
		if res, err = n.run(ctx, "udp", args, req.Hosts); err != nil {
			return res, err
		}
		if !res.PacketsExact {
			res.Packets = int64(len(req.Hosts)) * int64(len(req.Ports)) * 2
		}
	}
	for _, p := range req.Ports {
		if p != snmpPort || req.IPv6 {
			continue
		}
		open, sent := snmpScan(ctx, req.Hosts, req.MaxRate, 2*time.Second)
		if ctx.Err() != nil {
			return res, context.Cause(ctx)
		}
		res.Packets += sent
		byIP := map[string]int{}
		for i, h := range res.Hosts {
			byIP[h.IP] = i
		}
		for ip, product := range open {
			port := Port{Port: snmpPort, Proto: "udp", State: "open", Reason: "udp-response", Name: "snmp", Product: product, Method: "probed", Confidence: 0.8}
			if i, ok := byIP[ip]; ok {
				res.Hosts[i].Ports = append(res.Hosts[i].Ports, port)
			} else {
				res.Hosts = append(res.Hosts, Host{IP: ip, Up: true, Ports: []Port{port}})
			}
		}
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
