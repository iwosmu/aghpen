// Command czujka is the single binary of Czujka: API server, scheduler and scan engine.
package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("czujka", version)
		return
	}
	fmt.Fprintln(os.Stderr, "czujka: subcommands are wired in by the integration step (serve, migrate, scan, user)")
	os.Exit(2)
}
