package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/iwosmu/aghpen/internal/config"
	"github.com/iwosmu/aghpen/internal/kcap"
)

// newKernelCap builds the kernel packet cap from CZUJKA_KERNEL_CAP (auto,
// require, off) and CZUJKA_NETWORK_MODE ("host" in the host-network compose
// file). The database and the DNS resolvers are exempt.
func newKernelCap(dbURL string, log *slog.Logger) (*kcap.Cap, error) {
	mode, err := kcap.ParseMode(os.Getenv("CZUJKA_KERNEL_CAP"))
	if err != nil {
		return nil, err
	}
	return kcap.New(kcap.Options{
		Mode:   mode,
		Runner: kcap.ExecRunner{Path: os.Getenv("CZUJKA_NFT_PATH")},
		Unsafe: kcap.SystemUnsafe(os.Getenv("CZUJKA_NETWORK_MODE")),
		Exempt: kcap.SystemExempt(dbURL),
		Logger: log,
	}), nil
}

// kcapCmd is "czujka kcap": install, read or remove the kernel packet cap of
// this network namespace without the server (for the operator and e2e/kcap).
//
//	czujka kcap apply --pps N   install or replace the cap for a policy cap of N
//	czujka kcap status          print the dropped counter as JSON
//	czujka kcap show --pps N    print the ruleset without installing it
//	czujka kcap remove          delete Czujka's own table
func kcapCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: czujka kcap apply --pps N | status | show --pps N | remove")
	}
	fs := flag.NewFlagSet("kcap "+args[0], flag.ContinueOnError)
	pps := fs.Int("pps", 1000, "policy cap in probe packets per second (the kernel limit is 10% above it)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ctx := context.Background()
	cfg, _ := config.Load()
	run := kcap.ExecRunner{Path: os.Getenv("CZUJKA_NFT_PATH")}
	unsafe := kcap.SystemUnsafe(os.Getenv("CZUJKA_NETWORK_MODE"))
	out := json.NewEncoder(os.Stdout)
	switch args[0] {
	case "show":
		fmt.Print(kcap.Render(*pps, kcap.SystemExempt(cfg.DBURL)(ctx)))
		return nil
	case "apply":
		c := kcap.New(kcap.Options{Mode: kcap.ModeRequire, Runner: run, Unsafe: unsafe, Exempt: kcap.SystemExempt(cfg.DBURL), Logger: slog.New(slog.NewTextHandler(os.Stderr, nil))})
		c.Sync(ctx, *pps)
		_ = out.Encode(c.Status(ctx))
		return c.Ready()
	case "status":
		if r := unsafe(); r != "" {
			return errors.New(r)
		}
		b, err := run.Run(ctx, "", "-j", "list", "counter", "inet", kcap.Table, "dropped")
		if err != nil {
			return err
		}
		n, err := kcap.ParseCounter(b)
		if err != nil {
			return err
		}
		return out.Encode(map[string]int64{"dropped": n})
	case "remove":
		if r := unsafe(); r != "" {
			return errors.New(r)
		}
		_, err := run.Run(ctx, "", "delete", "table", "inet", kcap.Table)
		return err
	}
	return fmt.Errorf("czujka kcap: unknown action %q", args[0])
}
