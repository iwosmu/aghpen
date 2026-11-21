// labsim is the imitation server of the Czujka test lab. One binary plays
// every host that has no real software behind it: IoT login pages, staging
// sites, the TLS zoo, header and cookie cases and the hard cases. Its
// behaviour comes from an embedded JSON configuration (hosts/NAME.json, made
// by lab/gen) and from the current lab state (t0, t1, t2) read from a file.
//
// labsim only answers GET and HEAD. It serves static, harmless content.
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/iwosmu/aghpen/lab/labcfg"
)

//go:embed hosts/*.json
var hostFS embed.FS

const (
	readyFile        = "/tmp/labsim.ready"
	appliedStateFile = "/tmp/labsim.state"
)

func loadHost(name string) (*labcfg.Host, error) {
	raw, err := hostFS.ReadFile("hosts/" + name + ".json")
	if err != nil {
		return nil, fmt.Errorf("no embedded config for host %q: %w", name, err)
	}
	var h labcfg.Host
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("config of %q: %w", name, err)
	}
	return &h, nil
}

// readState returns the wanted lab state. A missing or empty file means t0.
func readState(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "t0"
	}
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return "t0"
	}
	return s
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	name := env("LABSIM_HOST", "")
	if len(os.Args) > 1 && os.Args[1] == "list" {
		entries, _ := hostFS.ReadDir("hosts")
		for _, e := range entries {
			fmt.Println(strings.TrimSuffix(e.Name(), ".json"))
		}
		return
	}
	if name == "" {
		log.Fatal("LABSIM_HOST is not set")
	}
	host, err := loadHost(name)
	if err != nil {
		log.Fatal(err)
	}
	stateFile := env("LAB_STATE_FILE", "/lab-state/current")
	iface := env("LABSIM_IFACE", "eth0")

	if err := applyFirewall(host.Firewall); err != nil {
		log.Fatalf("firewall: %v", err)
	}

	srv := newServer(host)
	state := readState(stateFile)
	if err := srv.apply(state); err != nil {
		log.Fatalf("apply state %s: %v", state, err)
	}
	writeFile(appliedStateFile, state)
	writeFile(readyFile, "ok")
	log.Printf("labsim %s ready in state %s", host.Name, state)

	link := newLink(iface)
	linkUp := true

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-sig:
			if !linkUp {
				_ = link.set(true)
			}
			return
		case now := <-tick.C:
			if s := readState(stateFile); s != state {
				if err := srv.apply(s); err != nil {
					log.Printf("apply state %s: %v (keeping %s)", s, err, state)
				} else {
					log.Printf("state %s -> %s", state, s)
					state = s
					writeFile(appliedStateFile, state)
				}
			}
			if host.Avail != nil {
				want := host.Avail.UpAt(now)
				if want != linkUp {
					if err := link.set(want); err != nil {
						log.Printf("link %v: %v", want, err)
					} else {
						linkUp = want
						log.Printf("availability: link up=%v", want)
					}
				}
			}
		}
	}
}

func writeFile(path, content string) {
	if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil {
		log.Printf("write %s: %v", path, err)
	}
}
