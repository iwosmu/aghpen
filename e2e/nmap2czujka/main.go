// nmap2czujka converts nmap XML files to one Czujka JSON export
// ([]model.HostResult). Several files are merged by address.
//
//	nmap2czujka tcp.xml udp.xml > export.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/iwosmu/aghpen/e2e/nmapconv"
	"github.com/iwosmu/aghpen/internal/model"
)

// convert reads the nmap XML files and merges them by address.
func convert(paths []string, upOnly bool) ([]model.HostResult, error) {
	var scans [][]model.HostResult
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		hosts, err := nmapconv.Parse(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		scans = append(scans, hosts)
	}
	merged := nmapconv.Merge(scans...)
	if !upOnly {
		return merged, nil
	}
	kept := merged[:0]
	for _, h := range merged {
		if h.Up {
			kept = append(kept, h)
		}
	}
	return kept, nil
}

func main() {
	out := flag.String("o", "", "output file (default: standard output)")
	upOnly := flag.Bool("up-only", true, "keep only hosts that are up")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: nmap2czujka [-o export.json] scan.xml [more.xml ...]")
		os.Exit(2)
	}
	merged, err := convert(flag.Args(), *upOnly)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(merged); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
