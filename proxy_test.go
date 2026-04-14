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

// TestReplacerCaseInsensitiveDefault verifies that caseInsensitive=true (the
// default when the proxy is invoked without -cs) matches mixed-case strings.
func TestReplacerCaseInsensitiveDefault(t *testing.T) {
	// caseInsensitive=true mirrors the production default (!*cs where cs=false).
	// Replacement always returns the alias as specified (lowercase), regardless
	// of the case of the matched token in the input.
	r, _ := NewReplacer("microsoft:msctf", true)

	tests := []struct{ input, want string }{
		{"Microsoft", "msctf"},
		{"MICROSOFT", "msctf"},
		{"microsoft", "msctf"},
		{"MiCrOsOfT", "msctf"},
	}
	for _, tc := range tests {
		got := r.ToAlias(tc.input)
		if got != tc.want {
			t.Errorf("CI ToAlias(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestReplacerCasePreservingRoundTrip verifies the /__sd__/ path-protection
// mechanism: file names like BBCReithSans_W_Rg.woff2 inside proxy URL paths
// are shielded from ToAlias by withExternalURLsProtected, so the CDN filename
// case is preserved end-to-end.  This test checks the replacer behaviour in
// isolation: ToAlias converts all case variants to the lowercase alias string.
func TestReplacerCasePreservingRoundTrip(t *testing.T) {
	r, _ := NewReplacer("bbc:britcast", true)

	// ToAlias is NOT case-preserving — always returns the lowercase alias.
	// The /__sd__/ path-protection in withExternalURLsProtected ensures the
	// original filename case is preserved in proxy URLs so the director can
	// round-trip the exact upstream filename back to the CDN.
	aliasTests := []struct{ original, alias string }{
		{"bbc.co.uk", "britcast.co.uk"},
		{"BBC News", "britcast News"},    // uppercase input → lowercase alias
		{"static.files.bbci.co.uk", "static.files.britcasti.co.uk"},
	}
	for _, tc := range aliasTests {
		got := r.ToAlias(tc.original)
		if got != tc.alias {
			t.Errorf("ToAlias(%q) = %q, want %q", tc.original, got, tc.alias)
		}
	}
}

// TestReplacerCaseSensitiveFlag verifies that caseInsensitive=false (the
// behaviour when -cs is passed) only matches exact case.
func TestReplacerCaseSensitiveFlag(t *testing.T) {
	// caseInsensitive=false mirrors -cs behaviour.
	r, _ := NewReplacer("microsoft:msctf", false)

	if got := r.ToAlias("microsoft"); got != "msctf" {
		t.Errorf("CS exact match: got %q want %q", got, "msctf")
	}
	// Mixed-case should NOT be rewritten when case-sensitive.
	if got := r.ToAlias("Microsoft"); got != "Microsoft" {
		t.Errorf("CS should not rewrite mixed-case: got %q want %q", got, "Microsoft")
	}
	if got := r.ToAlias("MICROSOFT"); got != "MICROSOFT" {
		t.Errorf("CS should not rewrite upper-case: got %q want %q", got, "MICROSOFT")
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
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
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
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
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
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
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
	// Build a body that is STRICTLY larger than maxBodyRewriteDefault+1 so that a naive
	// implementation would truncate the tail.  We append a distinct sentinel so
	// we can detect truncation: if the suffix is missing, bytes were lost.
	//
	// Body layout:
	//   [maxBodyRewriteDefault+1 bytes of "x"] + "SENTINEL"
	//
	// A buggy proxy that does strings.NewReader(raw[:maxBodyRewriteDefault+1]) would
	// drop "SENTINEL" and the test would fail.
	prefix := strings.Repeat("x", int(maxBodyRewriteDefault)+1)
	sentinel := "SENTINEL"
	large := prefix + sentinel

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, large)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false) // no matches in body, but rewrite path is triggered
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
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
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, fakeProxyAddr, true, 0, testLogger(), nil, nil, 0, nil)
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
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, fakeProxyAddr, true, 0, testLogger(), nil, nil, 0, nil)
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
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, nil, 0, nil)
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

// buildTestBareTargetRe compiles the bare-targetHost regex the same way NewReverseProxy does.
func buildTestBareTargetRe(targetHost string) *regexp.Regexp {
	return regexp.MustCompile(
		`(?i)(^|[^-a-zA-Z0-9.])` +
			regexp.QuoteMeta(targetHost) +
			`([^-a-zA-Z0-9.]|$)`,
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
		// Domain-boundary guard on step 4 (bare targetHost scan):
		// "target.www.example.com" in plain text (dot-separated) — the preceding dot
		// means bareTargetRe won't corrupt it.
		{`target.www.example.com/rest/v1`, `target.www.example.com/rest/v1`},
		// Bare targetHost in non-URL context should still be replaced.
		{`Domain=www.example.com; Path=/`, `Domain=localhost:8081; Path=/`},
		{`visit www.example.com today`, `visit localhost:8081 today`},
	}

	for _, c := range cases {
		got := maskResponseString(c.in, target, computeRootDomain(target), proxy, re, buildTestBareTargetRe(target), nil)
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
		// Protocol-relative form of the exact target host must also be rewritten.
		{"//github.com/explore", "//localhost:8081/explore"},
		{`src="//github.com/logo.png"`, `src="//localhost:8081/logo.png"`},
		// Boundary guard: "sub-github.com" has "github.com" as a substring of a
		// different root domain — must NOT be corrupted.
		{`url(//sub-github.com/asset.js)`, `url(//sub-github.com/asset.js)`},
	}

	for _, c := range cases {
		got := maskResponseString(c.in, target, computeRootDomain(target), proxy, re, buildTestBareTargetRe(target), nil)
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
		got := maskResponseString(c.in, target, computeRootDomain(target), proxy, nil, buildTestBareTargetRe(target), nil)
		if got != c.want {
			t.Errorf("maskResponseStringExact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---- Bug-fix regression tests ----

// TestMaskResponseStringDomainBoundary is a regression test for the bug where
// step 4's bare targetHost scan would corrupt domains that share targetHost as
// a substring but have a different root domain.
// Bug: target="microsoft.com", body contains "//c.s-microsoft.com/font.woff2"
//      (c.s-microsoft.com has root domain "s-microsoft.com", not "microsoft.com")
//      → step 4 used to replace "microsoft.com" → "localhost:9001" giving
//        "//c.s-localhost:9001/font.woff2" (broken URL).
func TestMaskResponseStringDomainBoundary(t *testing.T) {
	target := "microsoft.com"
	proxy := "localhost:9001"
	re := buildTestSubdomainRe(target)

	cases := []struct{ in, want string }{
		// The core bug: "c.s-microsoft.com" is NOT a subdomain of "microsoft.com"
		// (its root domain is "s-microsoft.com"), so it must pass through unchanged.
		{`url(//c.s-microsoft.com/font.woff2)`, `url(//c.s-microsoft.com/font.woff2)`},
		// Similarly, "target.microsoft.com" in a bare (no-scheme) context has a dot
		// before microsoft.com — the bare scan must leave it intact (subdomainRe handles
		// URL-scheme contexts).
		{`target.microsoft.com/rest/v1`, `target.microsoft.com/rest/v1`},
		// Legitimate bare targetHost replacements must still work.
		{`Domain=microsoft.com; Path=/`, `Domain=localhost:9001; Path=/`},
		{`visit microsoft.com today`, `visit localhost:9001 today`},
		{`microsoft.com/pricing`, `localhost:9001/pricing`},
	}

	for _, c := range cases {
		got := maskResponseString(c.in, target, computeRootDomain(target), proxy, re, buildTestBareTargetRe(target), nil)
		if got != c.want {
			t.Errorf("maskResponseString(domain-boundary) %q\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}
}

// TestSSRFBlockedViaSdPath verifies that /__sd__/<host> requests for hosts that
// are NOT under the rootDomain are blocked and do not proxy to arbitrary hosts.
func TestSSRFBlockedViaSdPath(t *testing.T) {
	// Upstream that the SSRF would reach — should never receive a request.
	ssrfTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("SSRF: request reached forbidden host %s", r.Host)
		fmt.Fprint(w, "ssrf")
	}))
	defer ssrfTarget.Close()

	// Legitimate upstream.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", false, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	// Attempt SSRF: request targets a host that is not under the upstream's root domain.
	ssrfHost := strings.TrimPrefix(ssrfTarget.URL, "http://")
	resp, err := ps.Client().Get(ps.URL + "/__sd__/" + ssrfHost + "/secret")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Proxy must return 403 Forbidden and never forward to the ssrfTarget
	// (tested via t.Errorf in the ssrfTarget handler above).
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for SSRF attempt, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), ssrfHost) {
		t.Errorf("403 body should contain the blocked host %q; got %q", ssrfHost, string(body))
	}
}

// TestSSRFBlockedAtSignBypass verifies that a crafted /__sd__/ host containing
// "@" (e.g. "evil.com:80@real.rootdomain.com") is rejected by the SSRF guard
// even though it passes a naive HasSuffix(".rootdomain.com") check.
func TestSSRFBlockedAtSignBypass(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	targetHost := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(targetHost, "http", rep, false, "localhost:8080", false, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	// Craft a host that suffix-matches targetHost but contains "@".
	// e.g. "evil.com:80@127.0.0.1" where targetHost is "127.0.0.1:PORT"
	bypassHost := "evil.com:80@" + targetHost
	resp, err := ps.Client().Get(ps.URL + "/__sd__/" + bypassHost + "/secret")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for @-bypass attempt, got %d", resp.StatusCode)
	}
}


// inside /__sd__/<host>/ path segments, so the client-visible URL is consistent
// with the replacement alias.
//
// E.g. -replace ynet:news SHOULD turn /__sd__/api.ynet.co.il/ into
// /__sd__/api.news.co.il/ — the director's rep.ToOriginal restores the real host
// for routing, so no functionality is lost.
//
// This is required so that pages accessed via an alias URL (e.g.
// /__sd__/copilot.msctf.com/) have all internal references consistently pointing
// to the alias hostname rather than the original, preventing client-side router
// hydration mismatches (e.g. Remix "Invariant failed").
func TestSdHostUserReplaceApplied(t *testing.T) {
	body := `<html><a href="http://localhost:9000/__sd__/api.ynet.co.il/data">link</a>` +
		`<p>Visit ynet for news</p></html>`

	rep, err := NewReplacer("ynet:news", false)
	if err != nil {
		t.Fatal(err)
	}

	result := withExternalURLsProtected(body, "http://localhost:9000", rep.ToAlias)

	// /__sd__/ host segment SHOULD have the replacement applied.
	if !strings.Contains(result, "/__sd__/api.news.co.il/") {
		t.Errorf("expected /__sd__/ host to be replaced: %q", result)
	}
	if strings.Contains(result, "/__sd__/api.ynet.co.il/") {
		t.Errorf("old /__sd__/ host unexpectedly still present: %q", result)
	}

	// The free-text "ynet" outside the /__sd__/ segment SHOULD also be replaced.
	if !strings.Contains(result, "Visit news for") {
		t.Errorf("expected free-text 'ynet' → 'news' replacement in body: %q", result)
	}
}

// TestHEADRequestNoGzipError verifies that a HEAD response with Content-Encoding: gzip
// does not trigger a spurious "failed to decode gzip" error and returns cleanly.
func TestHEADRequestNoGzipError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Real servers may send Content-Encoding on HEAD even though there is no body.
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		// No body — correct behaviour per HTTP spec for HEAD.
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", false, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest(http.MethodHead, ps.URL+"/", nil)
	resp, err := ps.Client().Do(req)
	if err != nil {
		t.Fatalf("HEAD request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// ---- rewriteRootRelativePaths unit tests ----

// TestRewriteRootRelativePathsHTML verifies that root-relative paths in common
// HTML attributes are prefixed with the /__sd__/<subHost> routing path so that
// browsers resolve them against the correct upstream subdomain.
func TestRewriteRootRelativePathsHTML(t *testing.T) {
	sub := "copilot.microsoft.com"
	pfx := "/__sd__/" + sub

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "href",
			input: `<link href="/static/app.css">`,
			want:  `<link href="` + pfx + `/static/app.css">`,
		},
		{
			name:  "src",
			input: `<script src="/assets/vendor.js"></script>`,
			want:  `<script src="` + pfx + `/assets/vendor.js"></script>`,
		},
		{
			name:  "action form",
			input: `<form action="/submit">`,
			want:  `<form action="` + pfx + `/submit">`,
		},
		{
			name:  "data-src",
			input: `<img data-src="/img/lazy.jpg">`,
			want:  `<img data-src="` + pfx + `/img/lazy.jpg">`,
		},
		{
			name:  "manifest",
			input: `<link rel="manifest" manifest="/app.webmanifest">`,
			want:  `<link rel="manifest" manifest="` + pfx + `/app.webmanifest">`,
		},
		{
			name:  "already /__sd__/ — leave unchanged",
			input: `<img src="/__sd__/other.microsoft.com/img/logo.png">`,
			want:  `<img src="/__sd__/other.microsoft.com/img/logo.png">`,
		},
		{
			name:  "protocol-relative — leave unchanged",
			input: `<img src="//cdn.microsoft.com/img/logo.png">`,
			want:  `<img src="//cdn.microsoft.com/img/logo.png">`,
		},
		{
			name:  "absolute https — leave unchanged",
			input: `<a href="https://microsoft.com/page">link</a>`,
			want:  `<a href="https://microsoft.com/page">link</a>`,
		},
		{
			name:  "fragment only — leave unchanged (no leading slash in value)",
			input: `<a href="#section">jump</a>`,
			want:  `<a href="#section">jump</a>`,
		},
		{
			name:  "base href root — rewrite",
			input: `<base href="/">`,
			want:  `<base href="` + pfx + `/">`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rewriteRootRelativePaths(tc.input, sub)
			if got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestRewriteRootRelativePathsSrcset verifies that each URL in a multi-entry
// srcset value is individually prefixed with the /__sd__/ route.
func TestRewriteRootRelativePathsSrcset(t *testing.T) {
	sub := "copilot.microsoft.com"
	pfx := "/__sd__/" + sub

	input := `<img srcset="/img/small.jpg 300w, /img/large.jpg 1000w" src="/img/small.jpg">`
	got := rewriteRootRelativePaths(input, sub)

	wants := []string{
		`srcset="` + pfx + `/img/small.jpg 300w,` + ` ` + pfx + `/img/large.jpg 1000w"`,
		`src="` + pfx + `/img/small.jpg"`,
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("expected output to contain %q\ngot: %q", w, got)
		}
	}
}

// TestRewriteRootRelativePathsSrcsetMixed verifies srcset entries without
// descriptors (space < 0 branch) and entries that don't start with "/" (continue branch).
func TestRewriteRootRelativePathsSrcsetMixed(t *testing.T) {
	sub := "assets.microsoft.com"
	pfx := "/__sd__/" + sub

	// No descriptor: srcset="/img/logo.png" (space < 0 path)
	in := `<img srcset="/img/logo.png" alt="logo">`
	got := rewriteRootRelativePaths(in, sub)
	want := `srcset="` + pfx + `/img/logo.png"`
	if !strings.Contains(got, want) {
		t.Errorf("no-descriptor srcset: expected %q in %q", want, got)
	}

	// Mixed: one absolute (skip), one root-relative (rewrite)
	in2 := `<img srcset="https://cdn.example.com/logo.png 2x, /img/logo.png 1x">`
	got2 := rewriteRootRelativePaths(in2, sub)
	// The absolute entry should be left alone (continue branch fires)
	if strings.Contains(got2, pfx+"/img/logo.png 1x") == false {
		t.Errorf("mixed srcset: expected root-relative to be rewritten in %q", got2)
	}
	if strings.Contains(got2, pfx+"https://") {
		t.Errorf("mixed srcset: absolute URL should not be rewritten, got %q", got2)
	}
}

// url() expressions are prefixed with the /__sd__/ route.
func TestRewriteRootRelativePathsCSS(t *testing.T) {
	sub := "copilot.microsoft.com"
	pfx := "/__sd__/" + sub

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "url with double quotes",
			input: `background: url("/img/bg.png");`,
			want:  `background: url("` + pfx + `/img/bg.png");`,
		},
		{
			name:  "url without quotes",
			input: `background: url(/img/bg.png);`,
			want:  `background: url(` + pfx + `/img/bg.png);`,
		},
		{
			name:  "absolute url — leave unchanged",
			input: `background: url(https://cdn.microsoft.com/img/bg.png);`,
			want:  `background: url(https://cdn.microsoft.com/img/bg.png);`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rewriteRootRelativePaths(tc.input, sub)
			if got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestSubdomainRootRelativeIntegration verifies the full proxy pipeline:
// a response from a subdomain host containing root-relative asset paths
// must have those paths rewritten to /__sd__/<subHost>/... in the proxied HTML.
func TestSubdomainRootRelativeIntegration(t *testing.T) {
	const subHost = "sub.example.com"
	const rootHost = "example.com"

	// Upstream server that serves different content depending on the Host header.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.Host {
		case subHost:
			fmt.Fprint(w, `<link href="/static/app.css"><script src="/js/main.js"></script>`)
		default:
			fmt.Fprint(w, `<a href="/">root</a>`)
		}
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	// We need a custom transport that routes all connections to the test upstream
	// regardless of the requested hostname (so /__sd__/sub.example.com/ actually
	// reaches our test server instead of trying DNS on the real Internet).
	rt := &fixedHostTransport{upstream: upstream}

	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(rootHost, "http", rep, false, "localhost:9999", false, 0, testLogger(), nil, nil, 0, nil)
	// Override the transport so subdomain requests hit the test upstream.
	proxy.Transport = rt
	_ = upstreamHost // used via rt

	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := ps.Client().Get(ps.URL + "/__sd__/" + subHost + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)

	wantHref := `href="/__sd__/` + subHost + `/static/app.css"`
	wantSrc := `src="/__sd__/` + subHost + `/js/main.js"`
	if !strings.Contains(got, wantHref) {
		t.Errorf("missing rewritten href in body\nwant substring: %q\ngot: %q", wantHref, got)
	}
	if !strings.Contains(got, wantSrc) {
		t.Errorf("missing rewritten src in body\nwant substring: %q\ngot: %q", wantSrc, got)
	}
}

// fixedHostTransport is a test RoundTripper that routes every request to a
// fixed httptest.Server, ignoring the request's Host/URL.Host.  This lets
// integration tests exercise subdomain routing without real DNS lookups.
type fixedHostTransport struct {
	upstream *httptest.Server
}

func (f *fixedHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	origHost := req.URL.Host
	// Clone the request so we can mutate it safely.
	clone := req.Clone(req.Context())
	// Point all requests at the test upstream's address while keeping the
	// Host header intact so the upstream handler can differentiate by r.Host.
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(f.upstream.URL, "http://")
	resp, err := http.DefaultTransport.RoundTrip(clone)
	if resp != nil {
		// Restore the original subdomain hostname on resp.Request so that
		// modifyResponse in the proxy sees the intended subdomain host
		// (e.g. "sub.example.com") rather than the test server's IP:port.
		// Without this, rewriteRootRelativePaths would be called with the
		// wrong host and the test assertions would fail.
		rr := *resp.Request
		ru := *resp.Request.URL
		ru.Host = origHost
		rr.URL = &ru
		resp.Request = &rr
	}
	return resp, err
}

// ---- Extra upstream headers tests ----

// TestExtraHeadersSentUpstream verifies that headers specified via -header are
// forwarded on every upstream request and are NOT reflected back to the client.
func TestExtraHeadersSentUpstream(t *testing.T) {
	var capturedAuthor, capturedToken string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuthor = r.Header.Get("X-Author")
		capturedToken = r.Header.Get("X-Token")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	extra := []headerPair{
		{name: "X-Author", value: "Rotem"},
		{name: "X-Token", value: "secret123"},
	}
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), extra, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if capturedAuthor != "Rotem" {
		t.Errorf("X-Author upstream: got %q want %q", capturedAuthor, "Rotem")
	}
	if capturedToken != "secret123" {
		t.Errorf("X-Token upstream: got %q want %q", capturedToken, "secret123")
	}
	// The extra headers must NOT be returned to the client in the response.
	if got := resp.Header.Get("X-Author"); got != "" {
		t.Errorf("X-Author leaked to client response: %q", got)
	}
}

// TestExtraHeadersOverrideClient verifies that a -header value overrides the
// same header sent by the client browser.
func TestExtraHeadersOverrideClient(t *testing.T) {
	var captured string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Get("X-Author")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	extra := []headerPair{{name: "X-Author", value: "ProxyValue"}}
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), extra, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest(http.MethodGet, ps.URL+"/", nil)
	req.Header.Set("X-Author", "ClientValue")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if captured != "ProxyValue" {
		t.Errorf("X-Author upstream: got %q want %q (proxy value should override client)", captured, "ProxyValue")
	}
}

// TestExtraHeadersMultiple verifies that all headers from multiple -header
// flags are present on the upstream request.
func TestExtraHeadersMultiple(t *testing.T) {
	captured := make(map[string]string)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{"X-A", "X-B", "X-C"} {
			captured[name] = r.Header.Get(name)
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	extra := []headerPair{
		{name: "X-A", value: "alpha"},
		{name: "X-B", value: "beta"},
		{name: "X-C", value: "gamma"},
	}
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), extra, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	for name, want := range map[string]string{"X-A": "alpha", "X-B": "beta", "X-C": "gamma"} {
		if got := captured[name]; got != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
}

// TestParseHeaders verifies the parseHeaders validation function.
func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr bool
		wantLen int
	}{
		{
			name:    "single valid header",
			input:   []string{"X-Author: Rotem"},
			wantLen: 1,
		},
		{
			name:    "multiple valid headers",
			input:   []string{"X-Author: Rotem", "X-Token: abc123"},
			wantLen: 2,
		},
		{
			name:    "value with colon preserved",
			input:   []string{"Authorization: Bearer tok:en"},
			wantLen: 1,
		},
		{
			name:    "canonical name applied",
			input:   []string{"x-author: Rotem"},
			wantLen: 1,
		},
		{
			name:    "missing colon",
			input:   []string{"X-Author"},
			wantErr: true,
		},
		{
			name:    "empty name",
			input:   []string{": value"},
			wantErr: true,
		},
		{
			name:    "empty value",
			input:   []string{"X-Author: "},
			wantErr: true,
		},
		{
			name:    "hop-by-hop rejected",
			input:   []string{"Connection: keep-alive"},
			wantErr: true,
		},
		{
			name:    "CRLF injection in value",
			input:   []string{"X-Injected: foo\r\nX-Evil: bar"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pairs, err := parseHeaders(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (pairs=%v)", pairs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pairs) != tc.wantLen {
				t.Errorf("got %d pairs, want %d", len(pairs), tc.wantLen)
			}
		})
	}
}

// TestSdPathNotUnreplaced verifies that when the director handles a /__sd__/<host>/<path>
// request, only the host segment has ToOriginal applied — not the path.
// Regression: with -replace ynet:news, a request for
//   /__sd__/<cdnHost>/static/newsRoomScript.js
// was incorrectly forwarded as /static/ynetRoomScript.js (404 on CDN).
func TestSdPathNotUnreplaced(t *testing.T) {
	var capturedPath string
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstreamSrv.Close()

	// upHost is e.g. "127.0.0.1:PORT" — add it to alsoProxy so the SSRF guard allows it.
	// proxyAddr must be non-empty for alsoProxyDomains to be registered.
	upHost := strings.TrimPrefix(upstreamSrv.URL, "http://")
	rep, _ := NewReplacer("ynet:news", false)
	proxy := NewReverseProxy("ynet.co.il", "http", rep, false, "localhost:9999", true, 0, testLogger(), nil, nil, 0,
		[]string{upHost})
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	// The path contains "news" as part of a CDN filename — it must NOT be
	// reversed to "ynet" by the director's ToOriginal pass.
	resp, err := ps.Client().Get(ps.URL + "/__sd__/" + upHost + "/static/newsRoomScript.js")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if capturedPath != "/static/newsRoomScript.js" {
		t.Errorf("path corrupted: got %q want %q", capturedPath, "/static/newsRoomScript.js")
	}
}
