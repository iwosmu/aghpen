package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/iwosmu/aghpen/internal/config"
	"github.com/iwosmu/aghpen/internal/crypto"
	"github.com/iwosmu/aghpen/internal/doctor"
	"github.com/iwosmu/aghpen/internal/store"
)

// doctorCmd checks the installation and prints a plain Polish fix for every
// failure. It never creates a key file and never changes the database.
func doctorCmd(args []string) error {
	asJSON := len(args) > 0 && (args[0] == "--json" || args[0] == "-json")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	d := doctor.Deps{Version: version, NmapPath: cfg.NmapPath, DataDir: doctor.DataDir(cfg.MasterKeyFile), TDEMode: cfg.TDE}
	kr, keyInfo, keyErr := doctorKeyring(cfg)
	d.KeyErr, d.KeyInfo = keyErr, keyInfo
	if kr == nil {
		// A throwaway keyring lets the database checks run; the key check reports the real problem.
		k, _ := crypto.GenerateKey()
		kr, _, _ = crypto.LoadKeyring(k, "", nil)
	}
	if err := cfg.RequireDB(); err != nil {
		d.StoreErr = err
	} else {
		st, err := store.Open(ctx, cfg.DBURL, store.Options{Keyring: kr, TDE: cfg.TDE, OperatorNetworks: cfg.AllowedNetworks})
		if err != nil {
			d.StoreErr = err
		} else {
			defer st.Close()
			d.Store = st
		}
	}
	rep := doctor.Run(ctx, d)
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		fmt.Print(doctor.Text(rep))
	}
	if !rep.OK {
		return doctor.ErrFailed
	}
	return nil
}

// doctorKeyring loads the master key like serve does, but never creates a key file.
func doctorKeyring(cfg config.Config) (*crypto.Keyring, string, error) {
	if cfg.MasterKey == "" && cfg.MasterKeyFile != "" {
		if _, err := os.Stat(cfg.MasterKeyFile); errors.Is(err, os.ErrNotExist) {
			return nil, "", fmt.Errorf("plik klucza %s nie istnieje (serve utworzy nowy klucz przy pierwszym starcie; przy istniejącej bazie to oznacza utratę dostępu do zaszyfrowanych pól)", cfg.MasterKeyFile)
		}
	}
	kr, _, err := crypto.LoadKeyring(cfg.MasterKey, cfg.MasterKeyFile, cfg.OldMasterKeys)
	if err != nil {
		return nil, "", err
	}
	src := "CZUJKA_MASTER_KEY"
	if cfg.MasterKey == "" {
		src = cfg.MasterKeyFile
	}
	return kr, fmt.Sprintf("klucz %s z %s, kluczy poprzednich: %d", kr.CurrentID(), src, len(kr.IDs())-1), nil
}
