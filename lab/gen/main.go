// gen writes every generated file of the lab from lab/manifest:
// the compose file, the labsim host configurations, the ground truth, the
// scenario lists and the address plan in lab/README.md.
//
//	go run ./lab/gen          # write
//	go run ./lab/gen -check   # fail when a file on disk is out of date
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/iwosmu/aghpen/lab/manifest"
)

// run writes the generated files under root. With check it writes nothing
// and returns the number of files that differ from the manifest.
func run(root string, check bool, w io.Writer) (stale int, err error) {
	l := manifest.New()
	if err := l.Validate(); err != nil {
		return 0, fmt.Errorf("manifest: %w", err)
	}
	files, err := l.Files(root)
	if err != nil {
		return 0, err
	}
	for _, f := range files {
		old, _ := os.ReadFile(f.Path)
		if string(old) == f.Content {
			continue
		}
		if check {
			fmt.Fprintln(w, "out of date:", f.Path)
			stale++
			continue
		}
		if err := manifest.WriteFile(f); err != nil {
			return stale, err
		}
		fmt.Fprintln(w, "wrote", f.Path)
	}
	hosts := 0
	for _, c := range l.Containers {
		if !c.NotAHost && c.InState("t0") {
			hosts++
		}
	}
	fmt.Fprintf(w, "lab: %d containers, %d hosts in t0\n", len(l.Containers), hosts)
	return stale, nil
}

func main() {
	root := flag.String("lab", "lab", "path of the lab directory")
	check := flag.Bool("check", false, "do not write; exit 1 when a generated file differs")
	flag.Parse()
	stale, err := run(*root, *check, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if stale > 0 {
		os.Exit(1)
	}
}
