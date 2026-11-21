package probe

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestUDPPorts(t *testing.T) {
	all, err := UDPPorts("", "", "")
	if err != nil || !reflect.DeepEqual(all, []int{53, 123, 137, 161, 500, 1900, 5353}) {
		t.Fatalf("allow-list = %v, %v", all, err)
	}
	// a profile cannot add a port that is not on the allow-list
	if got, _ := UDPPorts("53,69,123,1-20", "", ""); !reflect.DeepEqual(got, []int{53, 123}) {
		t.Errorf("subset = %v", got)
	}
	// the safety policy filters UDP ports like TCP ports
	if got, _ := UDPPorts("", "1-1024", "161"); !reflect.DeepEqual(got, []int{53, 123, 137, 500}) {
		t.Errorf("policy = %v", got)
	}
	if got, _ := UDPPorts("", "", "1-65535"); len(got) != 0 {
		t.Errorf("all denied = %v", got)
	}
	if _, err := UDPPorts("abc", "", ""); err == nil {
		t.Error("a bad spec must fail")
	}
}

func TestUDPArgsAreSafe(t *testing.T) {
	n := &Nmap{Path: "nmap", privileged: true}
	args := n.UDPArgs(UDPScanRequest{Ports: []int{53, 161, 9999, 123}, MaxRate: 200, HostTimeout: time.Minute})
	line := strings.Join(args, " ")
	// 9999 is outside the allow-list; 161 never goes to nmap, whose SNMP
	// probes include the community string "public"
	if !strings.HasPrefix(line, "-sU -Pn -p U:53,123 ") {
		t.Errorf("args = %s", line)
	}
	for _, a := range args {
		if a == "-sV" || a == "-sC" || a == "-A" || a == "-O" || strings.Contains(a, "script") {
			t.Errorf("unsafe option %q in %s", a, line)
		}
	}
	if !strings.Contains(line, "--max-rate 200") || !strings.Contains(line, "--min-rate 200") {
		t.Errorf("the UDP scan must be rate limited like TCP: %s", line)
	}
	// without raw sockets the stage refuses to run
	if _, err := (&Nmap{Path: "nmap"}).UDPScan(context.Background(), UDPScanRequest{Hosts: []string{"127.0.0.1"}, Ports: []int{53}}); !errors.Is(err, ErrNoRawSockets) {
		t.Errorf("unprivileged UDP scan: %v", err)
	}
}

// Version detection of open UDP ports sends only the probes nmap lists for
// the port (intensity 0), never to 161, never a script.
func TestUDPVersionArgsAreSafe(t *testing.T) {
	n := &Nmap{Path: "nmap", privileged: true}
	line := strings.Join(n.UDPVersionArgs([]int{53, 123, 161, 9999}, 100, time.Minute, false), " ")
	if !strings.HasPrefix(line, "-sU -sV --version-intensity 0 -Pn -p U:53,123 ") {
		t.Errorf("args = %s", line)
	}
	if strings.Contains(line, "script") || strings.Contains(line, "-sC") || strings.Contains(line, "-A ") || strings.Contains(line, "161") {
		t.Errorf("unsafe: %s", line)
	}
	if !strings.Contains(line, "--max-rate 100") {
		t.Errorf("not rate limited: %s", line)
	}
}

// The SNMP probe is the SNMPv3 engine discovery: no community string, no user.
func TestSNMPProbe(t *testing.T) {
	if len(snmpEngineDiscovery) != 60 || snmpEngineDiscovery[0] != 0x30 || snmpEngineDiscovery[1] != 0x3a || snmpEngineDiscovery[4] != 3 {
		t.Fatalf("payload = % x, want a 60-byte SNMP version 3 message", snmpEngineDiscovery)
	}
	if bytes.Contains(snmpEngineDiscovery, []byte("public")) || bytes.Contains(snmpEngineDiscovery, []byte("private")) {
		t.Fatal("the probe must not carry a community string")
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	seen := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1500)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			seen <- nil
			return
		}
		seen <- append([]byte{}, buf[:n]...)
		_, _ = pc.WriteTo([]byte{0x30, 0x03, 0x02, 0x01, 0x03}, from) // any SNMP message counts as an answer
	}()
	open, _, sent := snmpProbe(context.Background(), pc.LocalAddr().String(), time.Second, NewLimiter(100, 1))
	got := <-seen
	if !open || sent != 1 || !bytes.Equal(got, snmpEngineDiscovery) {
		t.Errorf("agent present: open=%v sent=%d, agent received % x", open, sent, got)
	}
	// a closed port: no answer, not reported
	closed, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	addr := closed.LocalAddr().String()
	closed.Close()
	if open, _, sent := snmpProbe(context.Background(), addr, 300*time.Millisecond, NewLimiter(100, 1)); open || sent > 2 {
		t.Errorf("closed port: open=%v sent=%d", open, sent)
	}
}

func TestSNMPVendorFromEngineID(t *testing.T) {
	// SNMPv3 Report from net-snmp 5.9: engine ID 80 00 1f 88 80 ... (enterprise 8072)
	report := []byte{0x30, 0x30, 0x02, 0x01, 0x03, 0x30, 0x0f, 0x02, 0x02, 0x4a, 0x69, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x00, 0x02, 0x01, 0x03,
		0x04, 0x1a, 0x30, 0x18, 0x04, 0x11, 0x80, 0x00, 0x1f, 0x88, 0x80, 0x5b, 0x2c, 0x1d, 0x6f, 0x0e, 0x4a, 0x5a, 0x67, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x05}
	if got := snmpVendor(report); got != "net-snmp" {
		t.Errorf("vendor = %q, want net-snmp", got)
	}
	if got := snmpVendor([]byte{0x30, 0x03, 0x04, 0x01, 0x00}); got != "" {
		t.Errorf("vendor of a message without engine ID = %q", got)
	}
}
