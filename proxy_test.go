package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// testLogger returns a silent Logger suitable for unit tests (no output, no file).
func testLogger() *Logger {
	return newDiscardLogger()
}

// ---- Replacer unit tests ----

func TestReplacerEmpty(t *testing.T) {
	r, err := NewReplacer("", false)
	if err != nil {
		t.Fatal(err)
	}
	if r.ToOriginal("hello acme") != "hello acme" {
		t.Error("expected no-op with empty replacer")
	}
}

func TestReplacerToOriginal(t *testing.T) {
	r, _ := NewReplacer("ctf:acme,ctfd:foo", false)
	// "acme" → "ctf", "foo" → "ctfd"
	got := r.ToOriginal("/blabla/acme?q=foo")
	want := "/blabla/ctf?q=ctfd"
	if got != want {
		t.Errorf("ToOriginal: got %q want %q", got, want)
	}
}

func TestReplacerToAlias(t *testing.T) {
	r, _ := NewReplacer("ctf:acme,ctfd:foo", false)
	// "ctfd" → "foo" (must happen before "ctf" → "acme")
	got := r.ToAlias("welcome to ctfd and ctf!")
	want := "welcome to foo and acme!"
	if got != want {
		t.Errorf("ToAlias: got %q want %q", got, want)
	}
}

func TestReplacerLongestFirst(t *testing.T) {
	// If "ctf" were replaced before "ctfd", "ctfd" → "acmed" instead of "foo".
	r, _ := NewReplacer("ctf:acme,ctfd:foo", false)
	got := r.ToAlias("ctfd")
	if got != "foo" {
		t.Errorf("longest-first: got %q want %q", got, "foo")
	}
}

func TestReplacerAliasLongestFirst(t *testing.T) {
	// Reverse direction: "foobar" should not be split into "foo"+"bar".
	r, _ := NewReplacer("ctf:acme,ctfd:foobar", false)
	got := r.ToOriginal("foobar")
	if got != "ctfd" {
		t.Errorf("alias longest-first: got %q want %q", got, "ctfd")
	}
}

func TestReplacerInvalidPair(t *testing.T) {
	_, err := NewReplacer("ctf", false)
	if err == nil {
		t.Error("expected error for missing colon")
	}
}

// ---- Integration tests via httptest ----

// newUpstream returns a test server that echoes back the request URL path and
// optionally the given body text.
func newUpstream(t *testing.T, responseBody string, gzipped bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if gzipped {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			defer gz.Close()
			fmt.Fprint(gz, responseBody)
		} else {
			fmt.Fprint(w, responseBody)
		}
	}))
}

func newProxy(t *testing.T, upstream *httptest.Server, replaceSpec string) *httptest.Server {
	t.Helper()
	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, err := NewReplacer(replaceSpec, false)
	if err != nil {
		t.Fatalf("NewReplacer: %v", err)
	}
	proxy := NewReverseProxy(host, "http", rep, false, "", true, testLogger())
	return httptest.NewServer(proxy)
}

func TestProxyResponseReplacement(t *testing.T) {
	upstream := newUpstream(t, "Hello from ctfd and ctf!", false)
	defer upstream.Close()

	ps := newProxy(t, upstream, "ctf:acme,ctfd:foo")
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)
	want := "Hello from foo and acme!"
	if got != want {
		t.Errorf("response rewrite: got %q want %q", got, want)
	}
}

func TestProxyRequestURLReplacement(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	rep, _ := NewReplacer("ctf:acme,ctfd:foo", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, testLogger())
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	// Client sends /acme/foo — proxy should forward /ctf/ctfd
	http.Get(ps.URL + "/acme/foo")
	if capturedPath != "/ctf/ctfd" {
		t.Errorf("request URL rewrite: got %q want %q", capturedPath, "/ctf/ctfd")
	}
}

func TestProxyGzipResponse(t *testing.T) {
	upstream := newUpstream(t, "ctf gzip response", true)
	defer upstream.Close()

	ps := newProxy(t, upstream, "ctf:acme")
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)
	want := "acme gzip response"
	if got != want {
		t.Errorf("gzip rewrite: got %q want %q", got, want)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding should be stripped, got %q", enc)
	}
}

func TestProxyBinaryNotRewritten(t *testing.T) {
	// A binary (image/png) response should pass through unchanged.
	orig := "ctf binary data \x89PNG"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		fmt.Fprint(w, orig)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, testLogger())
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != orig {
		t.Errorf("binary response should not be rewritten, got %q", string(body))
	}
}

func TestProxyNoReplacements(t *testing.T) {
	upstream := newUpstream(t, "plain response", false)
	defer upstream.Close()

	ps := newProxy(t, upstream, "")
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "plain response" {
		t.Errorf("no-replacement proxy: got %q", string(body))
	}
}

func TestProxyLargeBodySkipsRewrite(t *testing.T) {
	// Build a body that is STRICTLY larger than maxBodyRewrite+1 so that a naive
	// implementation would truncate the tail.  We append a distinct sentinel so
	// we can detect truncation: if the suffix is missing, bytes were lost.
	//
	// Body layout:
	//   [maxBodyRewrite+1 bytes of "x"] + "SENTINEL"
	//
	// A buggy proxy that does strings.NewReader(raw[:maxBodyRewrite+1]) would
	// drop "SENTINEL" and the test would fail.
	prefix := strings.Repeat("x", maxBodyRewrite+1)
	sentinel := "SENTINEL"
	large := prefix + sentinel

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, large)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false) // no matches in body, but rewrite path is triggered
	proxy := NewReverseProxy(host, "http", rep, false, "", true, testLogger())
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if len(body) != len(large) {
		t.Errorf("large body truncated: got %d bytes, want %d bytes", len(body), len(large))
	}
	if !strings.HasSuffix(string(body), sentinel) {
		t.Errorf("large body tail lost: sentinel %q not found at end of response", sentinel)
	}
}

func TestProxyContentLengthHeader(t *testing.T) {
	// After rewriting, Content-Length must match the rewritten body length.
	// "ctf" (3 bytes) → "acme" (4 bytes): every occurrence adds 1 byte.
	upstream := newUpstream(t, "ctf ctf ctf", false) // 11 bytes
	defer upstream.Close()

	ps := newProxy(t, upstream, "ctf:acme")
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	want := "acme acme acme" // 14 bytes
	if string(body) != want {
		t.Errorf("body: got %q want %q", string(body), want)
	}
	cl := resp.Header.Get("Content-Length")
	if cl != strconv.Itoa(len(want)) {
		t.Errorf("Content-Length: got %q want %q", cl, strconv.Itoa(len(want)))
	}
}

// TestProxyHostMasking verifies that absolute URLs pointing at the upstream host
// are rewritten to the proxy address, and that bare hostname occurrences are
// masked.  This is the core masking invariant: the client must never see the
// real upstream hostname in any response body or header.
func TestProxyHostMasking(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The upstream returns content that mentions its own host in multiple forms.
		upHost := r.Host
		w.Header().Set("Content-Type", "text/html")
		// Simulate a Location redirect and a Link header too.
		w.Header().Set("Location", "https://"+upHost+"/dashboard")
		fmt.Fprintf(w, `<a href="https://%s/login">login</a> <img src="http://%s/logo.png"> host=%s`,
			upHost, upHost, upHost)
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false) // no user replacements; masking alone is under test
	const fakeProxyAddr = "masked.proxy:9999"
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, fakeProxyAddr, true, testLogger())
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)

	// The upstream host must not appear anywhere in the response body.
	if strings.Contains(got, upstreamHost) {
		t.Errorf("upstream host %q leaked into body: %q", upstreamHost, got)
	}
	// The proxy address must appear in place of the upstream host.
	if !strings.Contains(got, fakeProxyAddr) {
		t.Errorf("proxy addr %q not found in body: %q", fakeProxyAddr, got)
	}
	// Absolute https:// URLs must be rewritten to http:// proxy.
	if strings.Contains(got, "https://"+upstreamHost) {
		t.Errorf("https upstream URL leaked: %q", got)
	}
	wantBody := fmt.Sprintf(`<a href="http://%s/login">login</a> <img src="http://%s/logo.png"> host=%s`,
		fakeProxyAddr, fakeProxyAddr, fakeProxyAddr)
	if got != wantBody {
		t.Errorf("body:\n got  %q\n want %q", got, wantBody)
	}

	// Location header must also be rewritten.
	loc := resp.Header.Get("Location")
	wantLoc := "http://" + fakeProxyAddr + "/dashboard"
	if loc != wantLoc {
		t.Errorf("Location: got %q want %q", loc, wantLoc)
	}
}

// TestProxyHostMaskingWithUserReplacements verifies the ORDER of operations:
// host masking must run before user replacements.  With -replace ctf:acme,
// if user replacements ran first, "ctf.io" would become "acme.io" and the
// host-masking step would no longer recognise the upstream hostname.
func TestProxyHostMaskingWithUserReplacements(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upHost := r.Host // e.g. "127.0.0.1:PORT" — note: does not contain "ctf"
		w.Header().Set("Content-Type", "text/html")
		// Include both a hostname URL and a user-replacement target in the body.
		fmt.Fprintf(w, `href="https://%s/ctf/page" text="ctfd and ctf"`, upHost)
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme,ctfd:foo", false)
	const fakeProxyAddr = "masked.proxy:9999"
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, fakeProxyAddr, true, testLogger())
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)

	// Upstream host must not appear.
	if strings.Contains(got, upstreamHost) {
		t.Errorf("upstream host leaked: %q", got)
	}
	// URL must point at proxy, path must have user replacement applied.
	wantHref := fmt.Sprintf(`href="http://%s/acme/page"`, fakeProxyAddr)
	if !strings.Contains(got, wantHref) {
		t.Errorf("expected %q in body: %q", wantHref, got)
	}
	// User replacements in plain text must also be applied.
	if !strings.Contains(got, `text="foo and acme"`) {
		t.Errorf("user replacements not applied in body: %q", got)
	}
}

// TestProxySetCookieRewrite verifies that Set-Cookie headers are fixed so that
// cookies work when the client talks to the proxy over plain HTTP on localhost:
//   - Domain attribute cleared (browser defaults to the proxy host)
//   - Secure flag removed (cookies are sent over plain HTTP)
//   - SameSite=None downgraded to SameSite=Lax (None requires Secure)
func TestProxySetCookieRewrite(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// Upstream sets three kinds of problematic cookies.
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Domain: "ctf.io", Secure: true, HttpOnly: true, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "pref", Value: "dark", Domain: "ctf.io", SameSite: http.SameSiteNoneMode, Secure: true})
		http.SetCookie(w, &http.Cookie{Name: "plain", Value: "val"})
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, testLogger())
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	cookies := resp.Cookies()
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range cookies {
		cookieMap[c.Name] = c
	}

	// "session" cookie: Domain and Secure must be stripped.
	sess := cookieMap["session"]
	if sess == nil {
		t.Fatal("session cookie missing")
	}
	if sess.Domain != "" {
		t.Errorf("session cookie Domain should be empty, got %q", sess.Domain)
	}
	if sess.Secure {
		t.Error("session cookie Secure flag should be cleared")
	}
	if !sess.HttpOnly {
		t.Error("session cookie HttpOnly should be preserved")
	}

	// "pref" cookie: SameSite=None must be downgraded to Lax when Secure is removed.
	pref := cookieMap["pref"]
	if pref == nil {
		t.Fatal("pref cookie missing")
	}
	if pref.SameSite == http.SameSiteNoneMode {
		t.Error("pref cookie SameSite=None should be downgraded (requires Secure)")
	}

	// "plain" cookie: must pass through untouched.
	plain := cookieMap["plain"]
	if plain == nil {
		t.Fatal("plain cookie missing")
	}
	if plain.Value != "val" {
		t.Errorf("plain cookie value: got %q want %q", plain.Value, "val")
	}
}

// ---- Subdomain masking tests ----

func TestComputeRootDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"www.ynet.co.il", "ynet.co.il"},
		{"ynet.co.il", "ynet.co.il"},      // ccTLD — should NOT strip to co.il
		{"bbc.co.uk", "bbc.co.uk"},         // ccTLD — should NOT strip to co.uk
		{"www.bbc.co.uk", "bbc.co.uk"},     // 4-label ccTLD — strip www only
		{"domain.com.au", "domain.com.au"}, // ccTLD — should NOT strip to com.au
		{"app.logz.io", "logz.io"},
		{"en.wikipedia.org", "wikipedia.org"},
		{"github.com", "github.com"},
		{"api.github.com", "github.com"},
		{"a.b.example.com", "b.example.com"},
		{"127.0.0.1", "127.0.0.1"},       // IP — unchanged
		{"127.0.0.1:8080", "127.0.0.1"}, // IP+port — port stripped, IP unchanged
	}
	for _, c := range cases {
		got := computeRootDomain(c.in)
		if got != c.want {
			t.Errorf("computeRootDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// buildTestSubdomainRe compiles the subdomain regex the same way NewReverseProxy does.
func buildTestSubdomainRe(targetHost string) *regexp.Regexp {
	root := computeRootDomain(targetHost)
	return regexp.MustCompile(
		`(?i)((?:https?:)?//(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+` +
			regexp.QuoteMeta(root) +
			`)([/?#"'\s\x00]|$)`,
	)
}

func TestMaskResponseStringSubdomains(t *testing.T) {
	target := "www.example.com"
	proxy := "localhost:8081"
	re := buildTestSubdomainRe(target)

	cases := []struct{ in, want string }{
		// Exact target — handled by literal replacement in maskResponseString.
		{"https://www.example.com/page", "http://localhost:8081/page"},
		{"http://www.example.com/page", "http://localhost:8081/page"},
		// Subdomains — should be rewritten to proxy address with /__sd__/ prefix.
		{"https://api.example.com/v1", "http://localhost:8081/__sd__/api.example.com/v1"},
		// protocol-relative with path
		{`//cdn.example.com/logo.png`, `http://localhost:8081/__sd__/cdn.example.com/logo.png`},
		// URL inside an HTML attribute — boundary char is "
		{`href="http://auth.example.com/login"`, `href="http://localhost:8081/__sd__/auth.example.com/login"`},
		// Bare root domain without www prefix (e.g. canonical <meta> URL) — must be masked.
		{`content="https://example.com/page"`, `content="http://localhost:8081/page"`},
		{`content="http://example.com/page"`, `content="http://localhost:8081/page"`},
		// Unrelated domains — must pass through unchanged.
		{"https://google.com/search", "https://google.com/search"},
		{"https://cdn.other.net/img.png", "https://cdn.other.net/img.png"},
		// Boundary guard — evil.com suffix must NOT be consumed.
		{"https://sub.example.com.evil.com/path", "https://sub.example.com.evil.com/path"},
	}

	for _, c := range cases {
		got := maskResponseString(c.in, target, computeRootDomain(target), proxy, re)
		if got != c.want {
			t.Errorf("maskResponseString(%q)\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}
}

// TestMaskResponseString2LabelTarget verifies that subdomains of a 2-label target
// (e.g. github.com) are masked when exactDomain is false.
func TestMaskResponseString2LabelTarget(t *testing.T) {
	target := "github.com"
	proxy := "localhost:8081"
	re := buildTestSubdomainRe(target) // must NOT be nil

	if re == nil {
		t.Fatal("buildTestSubdomainRe returned nil for 2-label target")
	}

	cases := []struct{ in, want string }{
		// Subdomains of a 2-label target must be masked with /__sd__/ prefix.
		{"https://api.github.com/v3", "http://localhost:8081/__sd__/api.github.com/v3"},
		{"https://gist.github.com/", "http://localhost:8081/__sd__/gist.github.com/"},
		// Bare target is handled by literal replacements (no prefix).
		{"https://github.com/explore", "http://localhost:8081/explore"},
		// Note: "github.com" inside a third-party hostname that starts with it
		// (e.g. "github.com.evil.com") will be corrupted by the bare targetHost
		// replacement.  This is a known limitation of the plain-text scan and
		// only occurs if adversarially controlled upstream content is proxied.
	}

	for _, c := range cases {
		got := maskResponseString(c.in, target, computeRootDomain(target), proxy, re)
		if got != c.want {
			t.Errorf("maskResponseString(2-label) %q\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}
}

func TestMaskResponseStringExactDomainNoSubdomainRe(t *testing.T) {
	// With exactDomain=true, subdomainRe is nil — subdomains must pass through.
	target := "www.example.com"
	proxy := "localhost:8081"

	cases := []struct{ in, want string }{
		// Exact target is still rewritten.
		{"https://www.example.com/page", "http://localhost:8081/page"},
		// Subdomains must NOT be touched (no subdomainRe).
		{"https://api.example.com/v1", "https://api.example.com/v1"},
		{"//cdn.example.com/logo.png", "//cdn.example.com/logo.png"},
	}

	for _, c := range cases {
		got := maskResponseString(c.in, target, computeRootDomain(target), proxy, nil)
		if got != c.want {
			t.Errorf("maskResponseStringExact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
