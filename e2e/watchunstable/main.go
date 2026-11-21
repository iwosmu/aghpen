// watchunstable probes the unstable lab hosts at a fixed interval and prints
// a timeline: what a ping scan from the scanner box saw, and what the
// availability model of the ground truth says for that moment.
//
//	go run ./e2e/watchunstable -truth lab/ground-truth/t0.json -for 7m -every 15s
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/lab/truth"
)

// parseUp reads "nmap -oG -" output and returns the addresses that are up.
func parseUp(out string) map[string]bool {
	up := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "Host:" && strings.Contains(line, "Status: Up") {
			up[f[1]] = true
		}
	}
	return up
}

func mark(b bool) string {
	if b {
		return "UP  "
	}
	return "down"
}

func main() {
	truthPath := flag.String("truth", "lab/ground-truth/t0.json", "ground-truth file")
	compose := flag.String("compose", "lab/docker-compose.yml", "compose file of the lab")
	total := flag.Duration("for", 7*time.Minute, "how long to watch")
	every := flag.Duration("every", 15*time.Second, "interval between probes")
	flag.Parse()

	t, err := truth.Load(*truthPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var hosts []truth.Host
	var ips []string
	for _, h := range t.Hosts {
		if h.Availability != nil {
			hosts = append(hosts, h)
			ips = append(ips, h.IP)
		}
	}
	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "the ground truth has no unstable hosts")
		os.Exit(1)
	}
	fmt.Printf("%-9s", "UTC")
	for _, h := range hosts {
		fmt.Printf("  %-26s", h.Name+" seen/model")
	}
	fmt.Println()
	agree, samples := 0, 0
	end := time.Now().Add(*total)
	for now := time.Now(); now.Before(end); now = time.Now() {
		args := append([]string{"compose", "-f", *compose, "exec", "-T", "scanner-box", "nmap", "-sn", "-n", "--max-retries", "1", "-oG", "-"}, ips...)
		out, err := exec.Command("docker", args...).Output()
		if err != nil {
			fmt.Fprintln(os.Stderr, "probe failed:", err)
			os.Exit(1)
		}
		up := parseUp(string(out))
		// The probe takes a moment; judge it against the model at its middle.
		at := now.Add(time.Since(now) / 2)
		fmt.Printf("%-9s", at.UTC().Format("15:04:05"))
		for _, h := range hosts {
			seen, want := up[h.IP], h.Availability.UpAt(at)
			flag := " "
			samples++
			if seen == want {
				agree++
			} else {
				flag = "!" // a probe at the edge of a slot can disagree
			}
			fmt.Printf("  %-26s", fmt.Sprintf("%s / %s %s", mark(seen), mark(want), flag))
		}
		fmt.Println()
		time.Sleep(time.Until(now.Add(*every)))
	}
	fmt.Printf("agreement with the availability model: %d of %d samples (%.1f%%)\n", agree, samples, 100*float64(agree)/float64(samples))
}
