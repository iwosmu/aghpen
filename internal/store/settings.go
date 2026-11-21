package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

const (
	keySafety     = "safety"
	keyDefectDojo = "defectdojo"
)

// DefaultSafetyPolicy is the policy of a new installation: conservative limits, GET and HEAD only.
func DefaultSafetyPolicy() model.SafetyPolicy {
	return model.SafetyPolicy{
		MaxPPS:          1000,
		MaxHTTPRPS:      50,
		MaxPerHostRPS:   2,
		MaxPathsPerHost: 8,
		Exclusions:      []string{},
		AllowedMethods:  []string{"GET", "HEAD"},
		UserAgent:       "Czujka/1.0 (attack surface inventory; safe detection only)",
	}
}

func (s *Store) getSetting(ctx context.Context, key string, v any) (secret string, updated time.Time, err error) {
	var raw []byte
	err = s.db.QueryRow(ctx, `SELECT value, secret, updated_at FROM settings WHERE key = $1`, key).Scan(&raw, &secret, &updated)
	if err != nil {
		return "", time.Time{}, mapErr(err)
	}
	return secret, updated, json.Unmarshal(raw, v)
}

func (s *Store) putSetting(ctx context.Context, key string, v any, secret string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO settings (key, value, secret, updated_at) VALUES ($1, $2::jsonb, $3, now())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, secret = EXCLUDED.secret, updated_at = now()`, key, js(v), secret)
	return mapErr(err)
}

// GetSafetyPolicy returns the global safety policy; the default when none is stored yet.
func (s *Store) GetSafetyPolicy(ctx context.Context) (model.SafetyPolicy, error) {
	p := DefaultSafetyPolicy()
	_, updated, err := s.getSetting(ctx, keySafety, &p)
	if errors.Is(err, ErrNotFound) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	p.UpdatedAt = updated
	p.Exclusions = nonNil(p.Exclusions)
	p.AllowedMethods = nonNil(p.AllowedMethods)
	return p, nil
}

// PutSafetyPolicy stores the global safety policy.
func (s *Store) PutSafetyPolicy(ctx context.Context, p model.SafetyPolicy) (model.SafetyPolicy, error) {
	p.Exclusions = nonNil(p.Exclusions)
	p.AllowedMethods = nonNil(p.AllowedMethods)
	if err := s.putSetting(ctx, keySafety, p, ""); err != nil {
		return p, err
	}
	return s.GetSafetyPolicy(ctx)
}

// SetEmergencyStop sets or clears the emergency stop flag of the safety policy.
func (s *Store) SetEmergencyStop(ctx context.Context, on bool) (model.SafetyPolicy, error) {
	p, err := s.GetSafetyPolicy(ctx)
	if err != nil {
		return p, err
	}
	p.EmergencyStop = on
	return s.PutSafetyPolicy(ctx, p)
}

// GetDefectDojo returns the DefectDojo settings. withKey also decrypts the API
// key (for the client); without it the key stays hidden and only APIKeySet is filled.
func (s *Store) GetDefectDojo(ctx context.Context, withKey bool) (model.DefectDojoSettings, error) {
	d := model.DefectDojoSettings{VerifyTLS: true}
	secret, _, err := s.getSetting(ctx, keyDefectDojo, &d)
	if errors.Is(err, ErrNotFound) {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	d.APIKey = ""
	d.APIKeySet = secret != ""
	if withKey && secret != "" {
		if d.APIKey, err = s.kr.DecryptString(secret, "settings|"+keyDefectDojo); err != nil {
			return d, err
		}
	}
	return d, nil
}

// PutDefectDojo stores the DefectDojo settings. The API key is stored with
// field-level encryption. An empty APIKey keeps the stored key.
func (s *Store) PutDefectDojo(ctx context.Context, d model.DefectDojoSettings) (model.DefectDojoSettings, error) {
	var cur model.DefectDojoSettings
	secret, _, err := s.getSetting(ctx, keyDefectDojo, &cur)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return d, err
	}
	if d.APIKey != "" {
		if secret, err = s.kr.EncryptString(d.APIKey, "settings|"+keyDefectDojo); err != nil {
			return d, err
		}
	}
	d.APIKey, d.APIKeySet = "", false
	if err := s.putSetting(ctx, keyDefectDojo, d, secret); err != nil {
		return d, err
	}
	return s.GetDefectDojo(ctx, false)
}

// ClearDefectDojoKey removes the stored API key.
func (s *Store) ClearDefectDojoKey(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `UPDATE settings SET secret = '' WHERE key = $1`, keyDefectDojo)
	return err
}
