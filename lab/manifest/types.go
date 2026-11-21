// Package manifest is the single source of truth of the Czujka test lab.
// lab/gen turns it into lab/docker-compose.yml, the labsim host
// configurations, the ground-truth files, the scenario lists, the DNS zone
// and the address plan in lab/README.md. Nothing in those files is written
// by hand, so they cannot drift apart.
package manifest

import (
	"github.com/iwosmu/aghpen/lab/labcfg"
	"github.com/iwosmu/aghpen/lab/truth"
)

const (
	Network    = "10.66.0.0/16"
	Gateway    = "10.66.0.1"
	Zone       = "lab.czujka.test"
	ScannerIP  = "10.66.0.10"
	DNSIP      = "10.66.0.53"
	ImageSpace = "czujka-lab"
)

// Build says how a custom lab image is built.
type Build struct {
	Context    string // relative to lab/
	Dockerfile string // relative to Context; empty means Dockerfile
	Args       [][2]string
}

// ConfigFile is a small file mounted into a container (compose "configs" with inline content).
type ConfigFile struct {
	Target  string
	Content string
	Mode    string // for example "0755"; empty means 0444
}

type Health struct {
	Test        string // shell command, run with CMD-SHELL
	StartPeriod string // default 60s
}

// Container is one compose service. It is a lab host when IP is in the lab
// plan; two containers may share an IP when they are never in the same state
// (that is how a version upgrade is staged).
type Container struct {
	Name      string
	IP        string
	Hostnames []string // labels inside the lab zone, for example "www"
	Group     string   // address-plan group
	Desc      string   // Polish, for the README table
	In        []string // lab states in which the container runs; nil means all

	Image      string
	Build      *Build
	Entrypoint []string
	Command    []string
	Env        [][2]string
	Configs    []ConfigFile
	Sysctls    [][2]string
	CapAdd     []string
	MemMB      int
	Health     Health
	DependsOn  []string
	User       string
	Tmpfs      []string
	DNS        string
	Init       bool // run an init process as PID 1 (reaps orphans; vsftpd crashes when it has to)
	StateRW    bool // mount the lab-state volume read-write (scanner box only)
	NotAHost   bool // tooling, not part of the ground truth

	// Sim is set for imitation hosts (labsim). Their truth comes from it.
	Sim *SimHost
	// Services is the hand-written truth of real software, the same in every state the container runs in.
	Services []truth.Service
	Avail    *labcfg.Avail
	Hard     []string
}

// SimPort is one labsim listener with the truth annotations that cannot be
// derived from the configuration itself.
type SimPort struct {
	Port int
	Kind string // "" or "http", "tarpit"
	TLS  *labcfg.TLS
	Site labcfg.Site

	Product      string
	Version      string
	NameAlt      []string
	Hard         string
	Techs        []truth.Tech
	TechOptional []string
	Classes      []string
	ClassOpt     []string
	Interesting  []truth.Interesting
	Signatures   []string
}

// SimHost is an imitation host: its listeners per lab state.
type SimHost struct {
	Firewall *labcfg.Firewall
	Ports    map[string][]SimPort // by state
}

// InState tells if the container runs in a lab state.
func (c *Container) InState(state string) bool {
	if c.In == nil {
		return true
	}
	for _, s := range c.In {
		if s == state {
			return true
		}
	}
	return false
}

// FQDNs returns the full DNS names of the container.
func (c *Container) FQDNs() []string {
	out := make([]string, 0, len(c.Hostnames))
	for _, h := range c.Hostnames {
		out = append(out, h+"."+Zone)
	}
	return out
}
