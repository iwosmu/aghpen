package sig

import (
	"net/url"
	"testing"
)

// A same-origin redirect may land on a common landing path that is also a
// deny token (landingWords); every other refused word stays refused, the
// query keeps the full deny words, and a signature path keeps CheckPath.
func TestRedirectToALandingPath(t *testing.T) {
	check := func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return CheckRedirect(u)
	}
	for _, ok := range []string{"http://h/start", "http://h/start/", "http://h/pl/start", "http://h/pl/home", "http://h/startPage"} {
		if r := check(ok); r != "" {
			t.Errorf("redirect to %s refused: %s", ok, r)
		}
	}
	for _, bad := range []string{"http://h/run", "http://h/trigger", "http://h/start?cmd=x", "http://h/start/delete",
		"http://h/send", "http://h/api/set", "http://h/edit", "http://h/exec", "http://h/?next=/start/run"} {
		if check(bad) == "" {
			t.Errorf("redirect to %s allowed", bad)
		}
	}
	if CheckPath("/start") == "" {
		t.Error("signature path /start allowed: the landing exception is only for redirects")
	}
}
