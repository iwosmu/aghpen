// Package kcap is the kernel packet cap: a second, independent limit on probe
// packets under nmap's own pacing.
//
// nmap paces an average. After a freeze of the process (a stalled VM, a
// suspended laptop, CPU starvation) it sends the backlog at once: measured
// 6000 to 12000 packets in one second against a cap of 500 to 1000. No
// userspace pacing can stop that, because the scanner itself was frozen.
// An nftables rule in the output hook of Czujka's network namespace can: the
// kernel drops probe packets over the cap, whatever the state of the scanner.
//
// The rule matches new-connection and probe packets only: TCP SYN without
// ACK, a bare TCP ACK that opens no tracked connection (nmap's ACK ping),
// ICMP echo and timestamp requests, ICMPv6 echo requests and UDP. Loopback and
// the exempt addresses (the database, the DNS resolvers) are never limited.
// Packets of established connections (the HTTP collector, the API's replies)
// are never matched. A named counter counts what the kernel dropped.
//
// The rule is installed only where the network namespace is Czujka's own (a
// container on a bridge network). In the namespace of the host it would
// limit other programs too, so there it is not installed (see HostNetwork).
package kcap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Table is the nftables table that Czujka owns. Nothing else is ever touched.
const Table = "czujka_kcap"

// Mode is the setting CZUJKA_KERNEL_CAP.
type Mode string

const (
	// ModeAuto installs the cap when possible; otherwise Czujka scans and says so.
	ModeAuto Mode = "auto"
	// ModeRequire refuses to scan while the cap is not installed.
	ModeRequire Mode = "require"
	// ModeOff never installs the cap (and removes Czujka's own table).
	ModeOff Mode = "off"
)

// ParseMode reads CZUJKA_KERNEL_CAP; empty means auto.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return ModeAuto, nil
	case ModeAuto, ModeRequire, ModeOff:
		return m, nil
	default:
		return "", fmt.Errorf("CZUJKA_KERNEL_CAP must be auto, require or off, got %q", s)
	}
}

// Rate is the kernel limit for a policy cap of pps probe packets per second:
// 10% above it, so that nmap's normal pacing never touches it.
func Rate(pps int) int {
	if pps < 1 {
		pps = 1
	}
	return (pps*11 + 9) / 10
}

// Burst is about a tenth of a second of the rate: only a burst is cut.
func Burst(rate int) int {
	return max(1, (rate+9)/10)
}

// Render returns the nft script that atomically replaces Czujka's table: the
// first line creates the table when it is missing, the second deletes it with
// everything in it, the rest defines it again. nft -f applies the file as one
// transaction, so there is no moment without the rule. Other tables are not
// named and not changed.
func Render(pps int, exempt []netip.Addr) string {
	rate := Rate(pps)
	var v4, v6 []string
	seen := map[netip.Addr]bool{}
	for _, a := range exempt {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || seen[a] {
			continue
		}
		seen[a] = true
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {}\n", Table)
	fmt.Fprintf(&b, "delete table inet %s\n", Table)
	fmt.Fprintf(&b, "table inet %s {\n", Table)
	b.WriteString("\tcounter dropped {\n\t\tcomment \"probe packets over the cap\"\n\t}\n\n")
	fmt.Fprintf(&b, "\tlimit probes {\n\t\trate over %d/second burst %d packets\n\t}\n\n", rate, Burst(rate))
	writeSet := func(name, typ string, elems []string) {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s\n", name, typ)
		if len(elems) > 0 {
			fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
		}
		b.WriteString("\t}\n\n")
	}
	writeSet("exempt4", "ipv4_addr", v4)
	writeSet("exempt6", "ipv6_addr", v6)
	b.WriteString(`	chain output {
		type filter hook output priority filter; policy accept;
		oifname "lo" accept
		ip daddr @exempt4 accept
		ip6 daddr @exempt6 accept
		tcp flags & (syn | ack) == syn jump probe
		tcp flags & (syn | ack | fin | rst) == ack ct state { new, invalid } jump probe
		icmp type { echo-request, timestamp-request } jump probe
		icmpv6 type echo-request jump probe
		meta l4proto udp jump probe
	}

	chain probe {
		limit name "probes" counter name "dropped" drop
	}
}
`)
	return b.String()
}

// Runner runs nft with the given stdin and arguments. Tests use a fake.
type Runner interface {
	Run(ctx context.Context, stdin string, args ...string) ([]byte, error)
}

// ExecRunner runs the nft binary.
type ExecRunner struct{ Path string }

// Run executes nft; the error carries nft's own message.
func (e ExecRunner) Run(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	path := e.Path
	if path == "" {
		path = "nft"
	}
	full, err := exec.LookPath(path)
	if err != nil {
		if full, err = exec.LookPath("/usr/sbin/nft"); err != nil {
			return nil, errors.New("nft not found (install the nftables package)")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, full, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		msg := strings.Join(strings.Fields(out.String()), " ")
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if msg == "" {
			return nil, fmt.Errorf("nft: %w", err)
		}
		return nil, fmt.Errorf("nft: %v: %s", err, msg)
	}
	return out.Bytes(), nil
}

// HostNetwork reports whether the network namespace is the host's, where a
// rule would also limit other programs. Outside a container it always is. In
// a container it is when the operator says so (CZUJKA_NETWORK_MODE=host, set
// by deploy/docker-compose.host-network.yml) or when the namespace holds the
// interfaces of a docker host (docker0, br-*, veth*), which a container on a
// bridge network never sees.
func HostNetwork(inContainer bool, networkMode string, ifaces []string) (bool, string) {
	if !inContainer {
		return true, "unavailable: host network (Czujka does not run in a container, so its network namespace is the host's)"
	}
	if strings.EqualFold(strings.TrimSpace(networkMode), "host") {
		return true, "unavailable: host network (CZUJKA_NETWORK_MODE=host)"
	}
	for _, n := range ifaces {
		if n == "docker0" || strings.HasPrefix(n, "br-") || strings.HasPrefix(n, "veth") {
			return true, fmt.Sprintf("unavailable: host network (the namespace holds the host interface %s)", n)
		}
	}
	return false, ""
}

// Status is the visible state of the cap (GET /settings/safety, /healthz).
type Status struct {
	Mode   Mode `json:"mode"`
	Active bool `json:"active"`
	// PPS is the kernel limit in packets per second (the policy cap plus
	// 10%); Burst is the bucket in packets. 0 when not active.
	PPS   int `json:"pps"`
	Burst int `json:"burst"`
	// PolicyPPS is the policy cap the kernel limit was derived from.
	PolicyPPS int `json:"policy_pps"`
	// Dropped counts the probe packets the kernel dropped since Czujka started.
	Dropped int64 `json:"dropped"`
	// Reason says why the cap is not active (empty when it is).
	Reason string `json:"reason,omitempty"`
}

// Options configure a Cap.
type Options struct {
	Mode   Mode
	Runner Runner
	// Unsafe returns a reason when the namespace is not Czujka's own (see
	// HostNetwork); "" allows the install.
	Unsafe func() string
	// Exempt returns the addresses that are never limited (database, DNS).
	Exempt func(ctx context.Context) []netip.Addr
	Logger *slog.Logger
}

// Cap installs the rule and keeps its state. It is safe for concurrent use.
type Cap struct {
	opt Options

	mu        sync.Mutex
	active    bool
	pps       int // policy cap of the installed rule
	attempted int // policy cap of the last attempt
	tried     bool
	reason    string
	base      int64 // dropped packets of rules replaced earlier
}

// New returns a Cap. Nothing is installed until Sync.
func New(opt Options) *Cap {
	if opt.Mode == "" {
		opt.Mode = ModeAuto
	}
	if opt.Runner == nil {
		opt.Runner = ExecRunner{}
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	c := &Cap{opt: opt}
	if opt.Mode == ModeOff {
		c.reason = "off (CZUJKA_KERNEL_CAP=off)"
	}
	return c
}

// Mode returns the configured mode.
func (c *Cap) Mode() Mode { return c.opt.Mode }

func (c *Cap) unsafe() string {
	if c.opt.Unsafe == nil {
		return ""
	}
	return c.opt.Unsafe()
}

// Sync installs the rule for a policy cap of pps, or replaces it when the cap
// changed. A failed attempt is not repeated for the same cap until Retry.
// With ModeOff it removes Czujka's own table once (in its own namespace only).
func (c *Cap) Sync(ctx context.Context, pps int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt.Mode == ModeOff {
		if !c.tried {
			c.tried = true
			if c.unsafe() == "" {
				_, _ = c.opt.Runner.Run(ctx, "", "delete", "table", "inet", Table)
			}
		}
		return
	}
	if c.tried && c.attempted == pps {
		return
	}
	c.tried, c.attempted = true, pps
	if r := c.unsafe(); r != "" {
		if c.reason != r {
			c.opt.Logger.Warn("kernel packet cap not installed", "reason", r, "mode", c.opt.Mode)
		}
		c.reason, c.active = r, false
		return
	}
	if c.active {
		// The counter starts again at zero in the new table: keep what it had.
		if n, err := c.counter(ctx); err == nil {
			c.base += n
		}
	}
	var exempt []netip.Addr
	if c.opt.Exempt != nil {
		exempt = c.opt.Exempt(ctx)
	}
	if _, err := c.opt.Runner.Run(ctx, Render(pps, exempt), "-f", "-"); err != nil {
		was := c.active
		c.active, c.reason = false, "not installed: "+err.Error()
		if was {
			// The old table may still hold the old rate: remove it, so that the
			// kernel matches what the status says.
			_, _ = c.opt.Runner.Run(ctx, "", "delete", "table", "inet", Table)
		}
		c.opt.Logger.Warn("kernel packet cap not installed; nmap's own pacing is the only limit", "err", err, "mode", c.opt.Mode)
		return
	}
	c.active, c.pps, c.reason = true, pps, ""
	rate := Rate(pps)
	c.opt.Logger.Info("kernel packet cap installed", "table", "inet "+Table, "policy_pps", pps, "kernel_pps", rate, "burst", Burst(rate), "exempt", len(exempt))
}

// Retry forgets a failed attempt, so that the next Sync tries again.
func (c *Cap) Retry() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		c.tried = false
	}
}

// Ready returns nil when a scan may start: always, except with ModeRequire
// and no installed rule.
func (c *Cap) Ready() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt.Mode != ModeRequire || c.active {
		return nil
	}
	r := c.reason
	if r == "" {
		r = "not installed yet"
	}
	return fmt.Errorf("CZUJKA_KERNEL_CAP=require, but the kernel packet cap is not installed: %s", r)
}

type counterJSON struct {
	Nftables []struct {
		Counter *struct {
			Packets int64 `json:"packets"`
		} `json:"counter"`
	} `json:"nftables"`
}

// counter reads the named counter of the installed table (lock held).
func (c *Cap) counter(ctx context.Context) (int64, error) {
	out, err := c.opt.Runner.Run(ctx, "", "-j", "list", "counter", "inet", Table, "dropped")
	if err != nil {
		return 0, err
	}
	return ParseCounter(out)
}

// ParseCounter reads the packets of "nft -j list counter".
func ParseCounter(out []byte) (int64, error) {
	var v counterJSON
	if err := json.Unmarshal(out, &v); err != nil {
		return 0, fmt.Errorf("nft counter output: %w", err)
	}
	for _, e := range v.Nftables {
		if e.Counter != nil {
			return e.Counter.Packets, nil
		}
	}
	return 0, errors.New("nft counter output has no counter")
}

// Dropped returns the probe packets the kernel dropped since start, and false
// when the cap is not active or the counter cannot be read.
func (c *Cap) Dropped(ctx context.Context) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return c.base, false
	}
	n, err := c.counter(ctx)
	if err != nil {
		return c.base, false
	}
	return c.base + n, true
}

// Status returns the visible state.
func (c *Cap) Status(ctx context.Context) Status {
	dropped, _ := c.Dropped(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Status{Mode: c.opt.Mode, Active: c.active, Dropped: dropped, Reason: c.reason}
	if c.active {
		s.PolicyPPS, s.PPS = c.pps, Rate(c.pps)
		s.Burst = Burst(s.PPS)
	} else if s.Reason == "" {
		s.Reason = "not installed yet"
	}
	return s
}
