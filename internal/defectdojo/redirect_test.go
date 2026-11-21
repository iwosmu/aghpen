package defectdojo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// L2 of the security review: the client follows no redirect (the API key
// would go with it) and does not echo response bodies into its errors.
func TestClientFollowsNoRedirectAndEchoesNoBody(t *testing.T) {
	var reached atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user":{"username":"x"}}`))
	}))
	defer other.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirect.Close()
	c, err := New(Config{URL: redirect.URL, APIKey: "tajny-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Test(context.Background()); err == nil || reached.Load() != 0 {
		t.Fatalf("a redirect was followed (reached=%d, err=%v)", reached.Load(), err)
	} else if !strings.Contains(err.Error(), "302") {
		t.Fatalf("the error must name the status: %v", err)
	}

	leaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"internal-db-host=10.0.0.5 password=hunter2"}`))
	}))
	defer leaky.Close()
	c, _ = New(Config{URL: leaky.URL, APIKey: "tajny-token"})
	info, err := c.Test(context.Background())
	if err == nil || strings.Contains(err.Error(), "hunter2") || strings.Contains(info.Message, "hunter2") || !strings.Contains(err.Error(), "400") {
		t.Fatalf("the response body was echoed: %v / %q", err, info.Message)
	}
}
