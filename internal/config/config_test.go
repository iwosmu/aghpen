package config

import (
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaults(t *testing.T) {
	c, err := FromEnv(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.TDE != "auto" || c.SessionTTL != 12*time.Hour || c.LoginMaxFails != 5 || !c.AutoResume || c.Timezone != "Europe/Warsaw" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if err := c.RequireDB(); err == nil {
		t.Fatal("RequireDB must fail without CZUJKA_DB_URL")
	}
}

func TestOverridesAndValidation(t *testing.T) {
	c, err := FromEnv(env(map[string]string{
		"CZUJKA_LISTEN": "127.0.0.1:9000", "CZUJKA_DB_URL": "postgres://x", "CZUJKA_ADMIN_EMAIL": " Admin@Example.org ",
		"CZUJKA_MASTER_KEY_OLD": "a, b", "CZUJKA_SESSION_TTL": "30m", "CZUJKA_AUTO_RESUME": "false", "CZUJKA_TDE": "require",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:9000" || c.AdminEmail != "admin@example.org" || len(c.OldMasterKeys) != 2 || c.SessionTTL != 30*time.Minute || c.AutoResume || c.TDE != "require" {
		t.Fatalf("unexpected config: %+v", c)
	}
	for k, v := range map[string]string{"CZUJKA_TDE": "maybe", "CZUJKA_SESSION_TTL": "soon", "CZUJKA_LOGIN_MAX_FAILURES": "-1", "CZUJKA_TZ": "Mars/Olympus", "CZUJKA_COOKIE_SECURE": "x", "CZUJKA_TRUST_PROXY": "perhaps"} {
		if _, err := FromEnv(env(map[string]string{k: v})); err == nil {
			t.Errorf("%s=%s must be rejected", k, v)
		}
	}
}
