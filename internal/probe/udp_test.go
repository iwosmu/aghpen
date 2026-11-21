package probe

import (
	"context"
	"errors"
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
	if !strings.HasPrefix(line, "-sU -Pn -p U:53,161,123 ") {
		t.Errorf("args = %s (a port outside the allow-list must be dropped)", line)
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
