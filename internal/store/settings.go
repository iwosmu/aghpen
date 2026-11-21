package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

const (
	keySafety     = "safety"
	keyDefectDojo = "defectdojo"
	keyWebhook    = "webhook"
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
	// The operator lock comes from the environment, never from the database.
	p.OperatorNetworks = append([]string{}, s.sh.operator...)
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

// PutSafetyPolicy stores the global safety policy. It never changes the
// emergency stop flag of a stored policy: the stored flag is kept in the same
// statement, so a policy read before a stop and written after it cannot
// clear the stop (security review M3). Only SetEmergencyStop changes it.
func (s *Store) PutSafetyPolicy(ctx context.Context, p model.SafetyPolicy) (model.SafetyPolicy, error) {
	p.Exclusions = nonNil(p.Exclusions)
	p.AllowedMethods = nonNil(p.AllowedMethods)
	p.OperatorNetworks = nil // never stored: see GetSafetyPolicy
	p.EmergencyStop = false  // a new row starts released; an existing row keeps its flag
	_, err := s.db.Exec(ctx, `INSERT INTO settings (key, value, secret, updated_at) VALUES ($1, $2::jsonb, '', now())
		ON CONFLICT (key) DO UPDATE SET
			value = EXCLUDED.value || jsonb_build_object('emergency_stop', COALESCE(settings.value->'emergency_stop', 'false'::jsonb)),
			secret = '', updated_at = now()`, keySafety, js(p))
	if err != nil {
		return p, mapErr(err)
	}
	return s.GetSafetyPolicy(ctx)
}

// SetEmergencyStop sets or clears the emergency stop flag of the safety
// policy in one atomic statement (jsonb_set); the other fields stay as they are.
func (s *Store) SetEmergencyStop(ctx context.Context, on bool) (model.SafetyPolicy, error) {
	def := DefaultSafetyPolicy()
	def.EmergencyStop = on
	_, err := s.db.Exec(ctx, `INSERT INTO settings (key, value, secret, updated_at) VALUES ($1, $2::jsonb, '', now())
		ON CONFLICT (key) DO UPDATE SET value = jsonb_set(settings.value, '{emergency_stop}', to_jsonb($3::boolean), true), updated_at = now()`,
		keySafety, js(def), on)
	if err != nil {
		return model.SafetyPolicy{}, mapErr(err)
	}
	return s.GetSafetyPolicy(ctx)
}

// GetDefectDojo returns the DefectDojo settings. withKey also decrypts the API
// key (for the client); without it the key stays hidden and only APIKeySet is filled.
const keyPassive = "passive"

// PassiveSettings turn the passive sources that leave the organisation on or off.
type PassiveSettings struct {
	// CTEnabled lets POST /passive/crtsh send the scope domains to crt.sh, a
	// public service outside the organisation. Off by default.
	CTEnabled bool `json:"crtsh_enabled"`
}

// GetPassiveSettings returns the passive-source settings; the default is everything external off.
func (s *Store) GetPassiveSettings(ctx context.Context) (PassiveSettings, error) {
	var p PassiveSettings
	if _, _, err := s.getSetting(ctx, keyPassive, &p); err != nil && !errors.Is(err, ErrNotFound) {
		return p, err
	}
	return p, nil
}

// PutPassiveSettings stores the passive-source settings.
func (s *Store) PutPassiveSettings(ctx context.Context, p PassiveSettings) (PassiveSettings, error) {
	return p, s.putSetting(ctx, keyPassive, p, "")
}

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

// LockClamp is what ClampAllowedToLock changed in the stored allowed_networks.
type LockClamp struct {
	Lock     []string `json:"lock"`
	Before   []string `json:"before"`
	After    []string `json:"after"`
	Dropped  []string `json:"dropped"`  // no address in common with the lock
	Narrowed []string `json:"narrowed"` // "wider → part inside the lock"
}

// Changed reports whether the stored policy was rewritten.
func (c LockClamp) Changed() bool { return len(c.Dropped)+len(c.Narrowed) > 0 }

// ClampAllowedToLock intersects the stored allowed_networks with the operator
// lock (Options.OperatorNetworks). Call it at start: a policy saved before the
// lock (or under a wider lock) then lies inside the lock again. A network
// inside the lock stays; a network wider than parts of the lock is replaced
// by those parts; a network with nothing in common is dropped. A change is
// stored and written to the audit log ("safety.lock_clamp", by "system").
// When every network is dropped the list becomes empty, which leaves the lock
// alone as the bound.
func (s *Store) ClampAllowedToLock(ctx context.Context) (LockClamp, error) {
	out := LockClamp{Lock: append([]string{}, s.sh.operator...)}
	var lock []netip.Prefix
	for _, v := range s.sh.operator {
		if p, ok := parseNet(v); ok {
			lock = append(lock, p)
		}
	}
	if len(lock) == 0 {
		return out, nil
	}
	p := DefaultSafetyPolicy()
	if _, _, err := s.getSetting(ctx, keySafety, &p); err != nil {
		if errors.Is(err, ErrNotFound) {
			return out, nil
		}
		return out, err
	}
	out.Before = nonNil(p.AllowedNetworks)
	after := []string{}
	seen := map[string]bool{}
	add := func(v string) {
		if !seen[v] {
			seen[v] = true
			after = append(after, v)
		}
	}
	for _, v := range p.AllowedNetworks {
		n, ok := parseNet(v)
		if !ok {
			out.Dropped = append(out.Dropped, v)
			continue
		}
		inside := false
		var parts []string
		for _, q := range lock {
			if q.Addr().BitLen() != n.Addr().BitLen() {
				continue
			}
			switch {
			case q.Bits() <= n.Bits() && q.Contains(n.Addr()):
				inside = true
			case n.Bits() < q.Bits() && n.Contains(q.Addr()):
				parts = append(parts, q.String())
			}
		}
		switch {
		case inside:
			add(n.String())
		case len(parts) > 0:
			for _, x := range parts {
				add(x)
			}
			out.Narrowed = append(out.Narrowed, n.String()+" → "+strings.Join(parts, ", "))
		default:
			out.Dropped = append(out.Dropped, v)
		}
	}
	out.After = after
	if !out.Changed() {
		return out, nil
	}
	p.AllowedNetworks = after
	if _, err := s.PutSafetyPolicy(ctx, p); err != nil {
		return out, err
	}
	err := s.InsertAudit(ctx, model.AuditEntry{UserEmail: "system", Action: "safety.lock_clamp", Entity: "safety",
		Detail: map[string]any{"lock": out.Lock, "before": out.Before, "after": out.After, "dropped": nonNil(out.Dropped), "narrowed": nonNil(out.Narrowed)}})
	return out, err
}

// parseNet reads a CIDR or a single address as a masked prefix.
func parseNet(v string) (netip.Prefix, bool) {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		return p.Masked(), err == nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

// webhookSecret is the encrypted part of the webhook settings.
type webhookSecret struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

// GetWebhook returns the webhook settings. withSecret also returns the HMAC
// key (for the sender); without it only SecretSet is filled. The URL is
// returned in both cases.
func (s *Store) GetWebhook(ctx context.Context, withSecret bool) (model.WebhookSettings, error) {
	w := model.WebhookSettings{MinSeverity: model.SevMedium}
	enc, _, err := s.getSetting(ctx, keyWebhook, &w)
	if errors.Is(err, ErrNotFound) {
		return w, nil
	}
	if err != nil {
		return w, err
	}
	w.URL, w.Secret, w.SecretSet = "", "", false
	if enc == "" {
		return w, nil
	}
	plain, err := s.kr.DecryptString(enc, "settings|"+keyWebhook)
	if err != nil {
		return w, err
	}
	var sec webhookSecret
	if err := json.Unmarshal([]byte(plain), &sec); err != nil {
		return w, err
	}
	w.URL, w.SecretSet = sec.URL, sec.Secret != ""
	if withSecret {
		w.Secret = sec.Secret
	}
	return w, nil
}

// PutWebhook stores the webhook settings; the URL and the key are encrypted.
// An empty Secret keeps the stored key; clearSecret removes it.
func (s *Store) PutWebhook(ctx context.Context, w model.WebhookSettings, clearSecret bool) (model.WebhookSettings, error) {
	cur, err := s.GetWebhook(ctx, true)
	if err != nil {
		return w, err
	}
	sec := webhookSecret{URL: w.URL, Secret: cur.Secret}
	if w.Secret != "" {
		sec.Secret = w.Secret
	}
	if clearSecret {
		sec.Secret = ""
	}
	enc, err := s.kr.EncryptString(string(js(sec)), "settings|"+keyWebhook)
	if err != nil {
		return w, err
	}
	w.URL, w.Secret, w.SecretSet = "", "", false
	if err := s.putSetting(ctx, keyWebhook, w, enc); err != nil {
		return w, err
	}
	return s.GetWebhook(ctx, false)
}
