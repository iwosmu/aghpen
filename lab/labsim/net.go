package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/iwosmu/aghpen/lab/labcfg"
)

// run executes a system tool and returns its combined output on failure.
func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// firewallRules returns the iptables argument lists for a firewall spec.
func firewallRules(fw *labcfg.Firewall) [][]string {
	if fw == nil {
		return nil
	}
	var rules [][]string
	if len(fw.StealthExcept) > 0 {
		ports := make([]string, len(fw.StealthExcept))
		for i, p := range fw.StealthExcept {
			ports[i] = strconv.Itoa(p)
		}
		rules = append(rules,
			[]string{"-A", "INPUT", "-i", "lo", "-j", "ACCEPT"},
			[]string{"-A", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", strings.Join(ports, ","), "-j", "ACCEPT"},
			[]string{"-A", "INPUT", "-j", "DROP"},
		)
		return rules
	}
	if fw.DropICMP {
		rules = append(rules, []string{"-A", "INPUT", "-p", "icmp", "-j", "DROP"})
	}
	return rules
}

// applyFirewall installs the rules. It fails loudly: a hard case that is
// silently not hard would make the ground truth wrong.
func applyFirewall(fw *labcfg.Firewall) error {
	for _, r := range firewallRules(fw) {
		if err := run("iptables", r...); err != nil {
			return err
		}
	}
	return nil
}

// link toggles the network interface of the container. A host that is "down"
// answers nothing at all: no ARP, no ICMP, no TCP.
type link struct {
	iface   string
	gateway string
}

func newLink(iface string) *link {
	l := &link{iface: iface}
	// Remember the default gateway: the kernel removes the route when the
	// link goes down and does not restore it.
	if out, err := exec.Command("ip", "route", "show", "default").Output(); err == nil {
		l.gateway = parseDefaultGateway(string(out))
	}
	return l
}

func parseDefaultGateway(out string) string {
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "via" {
			return f[i+1]
		}
	}
	return ""
}

func (l *link) set(up bool) error {
	if !up {
		return run("ip", "link", "set", l.iface, "down")
	}
	if err := run("ip", "link", "set", l.iface, "up"); err != nil {
		return err
	}
	if l.gateway != "" {
		// Ignore the error: the route may already exist.
		_ = run("ip", "route", "replace", "default", "via", l.gateway, "dev", l.iface)
	}
	return nil
}
