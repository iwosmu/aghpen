package httpfp

import (
	"net/http"
	"strings"
	"testing"
)

func TestMaskSetCookie(t *testing.T) {
	cases := map[string]string{
		"sid=abc123; Path=/; HttpOnly":          "sid=[masked len=6]; Path=/; HttpOnly",
		"token=\"q1w2\"; Secure; SameSite=None": "token=[masked len=4]; Secure; SameSite=None",
		"rememberMe=deleteMe; Max-Age=0":        "rememberMe=[masked len=8]; Max-Age=0",
		"empty=; Path=/":                        "empty=; Path=/",
		"novalue":                               "novalue",
		"a=b=c":                                 "a=[masked len=3]",
	}
	for in, want := range cases {
		if got := MaskSetCookie(in); got != want {
			t.Errorf("MaskSetCookie(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanHeadersHidesCookieValues(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "PHPSESSID=s3cr3t-session-value; path=/; HttpOnly")
	h.Add("set-cookie", "lang=pl")
	h.Add("Server", "nginx")
	out := cleanHeaders(h)
	joined := strings.Join(out["Set-Cookie"], "|")
	if strings.Contains(joined, "s3cr3t") || strings.Contains(joined, "=pl") {
		t.Fatalf("cookie value leaked into headers: %q", joined)
	}
	if !strings.Contains(joined, "PHPSESSID=[masked len=20]; path=/; HttpOnly") {
		t.Fatalf("name and attributes must stay: %q", joined)
	}
	if out["Server"][0] != "nginx" {
		t.Fatal("other headers must not change")
	}
}

// The parsed cookie keeps the value for the encrypted path while the stored
// header does not.
func TestFetchKeepsValueOnlyInParsedCookies(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Set-Cookie": {"JSESSIONID=ABCDEF123; Path=/; Secure"}}}
	cs := cookiesOf(resp)
	if len(cs) != 1 || cs[0].Value != "ABCDEF123" || cs[0].ValueLen != 9 {
		t.Fatalf("parsed cookies %+v", cs)
	}
	if v := cleanHeaders(resp.Header)["Set-Cookie"][0]; strings.Contains(v, "ABCDEF123") {
		t.Fatalf("header %q", v)
	}
}
