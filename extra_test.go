package main

// extra_test.go — thorough unit tests covering gaps in proxy_test.go.
//
// Coverage areas:
//   - isTextContent: all content-type categories
//   - unmaskRequestString: Referer / Origin outbound header rewriting
//   - withExternalURLsProtected: external-URL shielding and /__sd__/ protection
//   - rewriteSetCookies: domain, Secure, SameSite rules
//   - Replacer: multi-pair collision prevention, exact diff counts, bidirectionality,
//     CI-mode ToOriginal, ToAlias with no-op, identical-value pairs
//   - maskResponseString: rootDomain step 5 (www.bbc.com / bbc.com), disabled masking
//   - rewriteRootRelativePaths: single-quoted attributes, inline style tag
//   - Integration: redirect downgrade (301→302, 308→307), CSP/HSTS stripped,
//     204/304 noBody, POST body replacement, Referer request-header masking,
//     query-string replacement, CI-mode pipeline, X-Forwarded-For not forwarded,
//     effectiveProxyAddr (127.0.0.1 → 127.0.0.1 in Location, not localhost)

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── isTextContent ───────────────────────────────────────────────────────────

func TestIsTextContent(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		// Text types — must be rewritten.
		{"text/html; charset=utf-8", true},
		{"text/html", true},
		{"text/plain", true},
		{"text/css", true},
		{"text/javascript", true},
		{"text/xml", true},

		// Application text-like types — must be rewritten.
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"application/xml", true},
		{"application/xhtml+xml", true},
		{"application/javascript", true},
		{"application/x-javascript", true},
		{"application/ld+json", true},
		{"application/graphql", true},
		{"application/x-www-form-urlencoded", true},

		// Binary types — must NOT be rewritten.
		{"image/png", false},
		{"image/jpeg", false},
		{"image/gif", false},
		{"image/svg+xml", false},
		{"image/webp", false},
		{"video/mp4", false},
		{"audio/mpeg", false},
		{"application/octet-stream", false},
		{"application/zip", false},
		{"application/pdf", false},
		{"font/woff2", false},
		{"", false},
	}
	for _, c := range cases {
		got := isTextContent(c.ct)
		if got != c.want {
			t.Errorf("isTextContent(%q) = %v, want %v", c.ct, got, c.want)
		}
	}
}

// ─── unmaskRequestString ──────────────────────────────────────────────────────

func TestUnmaskRequestString(t *testing.T) {
	cases := []struct {
		desc   string
		in     string
		target string
		scheme string
		proxy  string
		want   string
	}{
		{
			desc:   "http scheme in Referer rewritten to upstream",
			in:     "http://localhost:8080/page",
			target: "ctf.io", scheme: "https", proxy: "localhost:8080",
			want: "https://ctf.io/page",
		},
		{
			desc:   "bare proxy addr in Origin replaced with upstream",
			in:     "localhost:8080",
			target: "ctf.io", scheme: "https", proxy: "localhost:8080",
			want: "ctf.io",
		},
		{
			desc:   "unrelated string unchanged",
			in:     "https://other.com/path",
			target: "ctf.io", scheme: "https", proxy: "localhost:8080",
			want: "https://other.com/path",
		},
		{
			desc:   "empty proxyAddr disables rewriting",
			in:     "http://localhost:8080/page",
			target: "ctf.io", scheme: "https", proxy: "",
			want: "http://localhost:8080/page",
		},
		{
			desc:   "proxy addr embedded in longer URL",
			in:     "Referer: http://localhost:8080/ctf/dashboard",
			target: "ctf.io", scheme: "https", proxy: "localhost:8080",
			want: "Referer: https://ctf.io/ctf/dashboard",
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			got := unmaskRequestString(c.in, c.target, c.scheme, c.proxy)
			if got != c.want {
				t.Errorf("unmaskRequestString(%q)\n  got  %q\n  want %q", c.in, got, c.want)
			}
		})
	}
}

// ─── withExternalURLsProtected ───────────────────────────────────────────────

func TestWithExternalURLsProtected(t *testing.T) {
	replace := func(s string) string {
		return strings.ReplaceAll(s, "ynet", "news")
	}

	t.Run("external URL not modified", func(t *testing.T) {
		// "ynet" appears inside an external CDN hostname — must survive.
		in := `<img src="https://ynet-pic1.yit.co.il/picserver5/photo.jpg">`
		got := withExternalURLsProtected(in, "http://localhost:9002", replace)
		if strings.Contains(got, "news-pic1") {
			t.Errorf("external URL corrupted: %q", got)
		}
		if !strings.Contains(got, "ynet-pic1.yit.co.il") {
			t.Errorf("external URL lost: %q", got)
		}
	})

	t.Run("proxy-local URL path gets replacement", func(t *testing.T) {
		// A proxy-local href — the path /ynet/page should become /news/page.
		in := `<a href="http://localhost:9002/ynet/page">link</a>`
		got := withExternalURLsProtected(in, "http://localhost:9002", replace)
		if !strings.Contains(got, "/news/page") {
			t.Errorf("proxy-local path not replaced: %q", got)
		}
	})

	t.Run("free text replaced", func(t *testing.T) {
		in := `<p>Visit ynet for breaking news</p>`
		got := withExternalURLsProtected(in, "http://localhost:9002", replace)
		if !strings.Contains(got, "Visit news for") {
			t.Errorf("free-text replacement missing: %q", got)
		}
	})

	t.Run("__sd__ host segment protected", func(t *testing.T) {
		in := `<a href="http://localhost:9002/__sd__/api.ynet.co.il/data">x</a>`
		got := withExternalURLsProtected(in, "http://localhost:9002", replace)
		if strings.Contains(got, "/__sd__/api.news.co.il/") {
			t.Errorf("__sd__ host corrupted: %q", got)
		}
		if !strings.Contains(got, "/__sd__/api.ynet.co.il/") {
			t.Errorf("__sd__ host lost: %q", got)
		}
	})

	t.Run("empty proxyBase protects all external URLs", func(t *testing.T) {
		// With proxyBase="" every absolute URL is shielded.
		in := `visit ynet or https://ynet-cdn.co.il/img.jpg`
		got := withExternalURLsProtected(in, "", replace)
		// Free text "ynet" should be replaced; the CDN URL should be intact.
		if !strings.Contains(got, "visit news or") {
			t.Errorf("free-text not replaced with empty base: %q", got)
		}
		if strings.Contains(got, "news-cdn") {
			t.Errorf("external URL corrupted with empty base: %q", got)
		}
	})

	t.Run("multiple external URLs all preserved", func(t *testing.T) {
		in := `<link rel="dns-prefetch" href="//ynet-static.akamaized.net/x.js">` +
			`<link rel="dns-prefetch" href="//ynet2.cdn.net/y.js">` +
			`<p>ynet news</p>`
		got := withExternalURLsProtected(in, "http://localhost:9002", replace)
		if strings.Contains(got, "//news-static.akamaized.net") {
			t.Errorf("first CDN URL corrupted: %q", got)
		}
		if strings.Contains(got, "//news2.cdn.net") {
			t.Errorf("second CDN URL corrupted: %q", got)
		}
		if !strings.Contains(got, "<p>news news</p>") {
			t.Errorf("free-text not replaced: %q", got)
		}
	})
}

// ─── rewriteSetCookies unit tests ────────────────────────────────────────────

func TestRewriteSetCookiesUnit(t *testing.T) {
	t.Run("domain cleared, secure stripped", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Add("Set-Cookie", "session=abc; Domain=ctf.io; Secure; HttpOnly; Path=/")
		rewriteSetCookies(resp, false)
		sc := resp.Header.Get("Set-Cookie")
		if strings.Contains(sc, "Domain=") {
			t.Errorf("Domain not removed: %q", sc)
		}
		if strings.Contains(strings.ToLower(sc), "secure") {
			t.Errorf("Secure not removed: %q", sc)
		}
		if !strings.Contains(strings.ToLower(sc), "httponly") {
			t.Errorf("HttpOnly should be preserved: %q", sc)
		}
	})

	t.Run("SameSite=None downgraded to Lax when plain HTTP", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Add("Set-Cookie", "pref=dark; SameSite=None; Secure")
		rewriteSetCookies(resp, false)
		sc := resp.Header.Get("Set-Cookie")
		if strings.Contains(sc, "SameSite=None") {
			t.Errorf("SameSite=None not downgraded: %q", sc)
		}
		if !strings.Contains(sc, "SameSite=Lax") {
			t.Errorf("expected SameSite=Lax: %q", sc)
		}
	})

	t.Run("SameSite=None kept when proxy is HTTPS", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Add("Set-Cookie", "pref=dark; SameSite=None; Secure")
		rewriteSetCookies(resp, true) // proxy is HTTPS
		sc := resp.Header.Get("Set-Cookie")
		if !strings.Contains(sc, "SameSite=None") {
			t.Errorf("SameSite=None incorrectly removed when proxy is HTTPS: %q", sc)
		}
		if !strings.Contains(strings.ToLower(sc), "secure") {
			t.Errorf("Secure incorrectly removed when proxy is HTTPS: %q", sc)
		}
	})

	t.Run("plain cookie unchanged", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Add("Set-Cookie", "token=xyz; Path=/; HttpOnly")
		rewriteSetCookies(resp, false)
		sc := resp.Header.Get("Set-Cookie")
		if !strings.Contains(sc, "token=xyz") {
			t.Errorf("plain cookie value corrupted: %q", sc)
		}
	})

	t.Run("no Set-Cookie headers is a no-op", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		rewriteSetCookies(resp, false) // must not panic
	})

	t.Run("multiple cookies all rewritten", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Add("Set-Cookie", "a=1; Domain=example.com; Secure")
		resp.Header.Add("Set-Cookie", "b=2; Domain=example.com; Secure")
		rewriteSetCookies(resp, false)
		cookies := resp.Header.Values("Set-Cookie")
		if len(cookies) != 2 {
			t.Fatalf("expected 2 cookies, got %d", len(cookies))
		}
		for _, sc := range cookies {
			if strings.Contains(sc, "Domain=") {
				t.Errorf("Domain not cleared: %q", sc)
			}
			if strings.Contains(strings.ToLower(sc), "secure") {
				t.Errorf("Secure not cleared: %q", sc)
			}
		}
	})
}

// ─── maskResponseString: rootDomain step 5 ────────────────────────────────────

func TestMaskResponseStringRootDomainStep5(t *testing.T) {
	// When targetHost="www.bbc.com" and rootDomain="bbc.com", step 5 must also
	// rewrite "https://bbc.com/..." → "http://proxyAddr/..." so the canonical
	// root URL doesn't leak the upstream domain.
	target := "www.bbc.com"
	proxy := "localhost:8080"
	re := buildTestSubdomainRe(target)

	cases := []struct{ in, want string }{
		{
			"https://bbc.com/news/article",
			"http://localhost:8080/news/article",
		},
		{
			"http://bbc.com/news/article",
			"http://localhost:8080/news/article",
		},
		// The exact target is always rewritten.
		{
			"https://www.bbc.com/sport",
			"http://localhost:8080/sport",
		},
		// Subdomains are rewritten with the /__sd__/ prefix.
		{
			"https://static.bbc.co.uk/scripts/vendor.js",
			// "bbc.co.uk" is not under "bbc.com" — must pass through unchanged.
			"https://static.bbc.co.uk/scripts/vendor.js",
		},
	}

	for _, c := range cases {
		got := maskResponseString(c.in, target, computeRootDomain(target), proxy, re, buildTestBareTargetRe(target))
		if got != c.want {
			t.Errorf("step5(%q)\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}
}

// TestMaskResponseStringDisabled verifies that passing proxyAddr="" leaves the
// string unchanged (masking is disabled).
func TestMaskResponseStringDisabled(t *testing.T) {
	in := `href="https://ctf.io/page" visit ctf.io today`
	got := maskResponseString(in, "ctf.io", "ctf.io", "", nil, nil)
	if got != in {
		t.Errorf("disabled masking should be no-op, got %q", got)
	}
}

// ─── Replacer: additional edge cases ─────────────────────────────────────────

// TestReplacerThreePairCollision verifies that three-pair sets are applied
// longest-first so no shorter match consumes part of a longer key.
func TestReplacerThreePairCollision(t *testing.T) {
	// "abc" > "ab" > "a" in original length.  Each must be replaced independently.
	r, err := NewReplacer("a:X,ab:Y,abc:Z", false)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct{ in, want string }{
		{"abc", "Z"},  // "abc" wins over "ab" and "a"
		{"ab", "Y"},   // "ab" wins over "a"
		{"a", "X"},    // lone "a"
		{"aabc", "XZ"}, // "a" then "abc" (non-overlapping, longest-first)
	}
	for _, c := range cases {
		got := r.ToAlias(c.in)
		if got != c.want {
			t.Errorf("ToAlias(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestReplacerToAliasDiffExactCount verifies the replacement count is accurate.
func TestReplacerToAliasDiffExactCount(t *testing.T) {
	r, _ := NewReplacer("ctf:acme,ctfd:foo", false)

	// "ctfd" (×2) + "ctf" (×3) = 5 total occurrences. Each must count once.
	result, count := r.ToAliasDiff("ctfd login ctf page ctf end ctf ctfd")
	if count != 5 {
		t.Errorf("ToAliasDiff count = %d, want 5; result=%q", count, result)
	}
}

// TestReplacerToOriginalDiffExactCount verifies the reverse diff count.
func TestReplacerToOriginalDiffExactCount(t *testing.T) {
	r, _ := NewReplacer("ctf:acme,ctfd:foo", false)

	result, count := r.ToOriginalDiff("acme acme foo")
	if count != 3 {
		t.Errorf("ToOriginalDiff count = %d, want 3; result=%q", count, result)
	}
}

// TestReplacerBidirectional verifies that ToOriginal and ToAlias are exact
// inverses when given non-overlapping pairs.
func TestReplacerBidirectional(t *testing.T) {
	r, _ := NewReplacer("ctf:acme,ctfd:foo", false)

	original := "ctfd login ctf page"
	alias := r.ToAlias(original)
	backToOriginal := r.ToOriginal(alias)

	if backToOriginal != original {
		t.Errorf("bidirectional round-trip failed:\n  original: %q\n  alias:    %q\n  back:     %q",
			original, alias, backToOriginal)
	}
}

// TestReplacerCIToOriginal verifies that case-insensitive mode also works
// bidirectionally: aliases typed in any case are mapped back to originals.
func TestReplacerCIToOriginal(t *testing.T) {
	r, _ := NewReplacer("ctf:acme", true) // CI mode

	cases := []struct{ in, want string }{
		{"ACME", "ctf"},
		{"Acme", "ctf"},
		{"acme", "ctf"},
	}
	for _, c := range cases {
		got := r.ToOriginal(c.in)
		if got != c.want {
			t.Errorf("CI ToOriginal(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestReplacerNoMatchIsNoOp confirms that strings containing neither originals
// nor aliases are returned byte-for-byte unchanged.
func TestReplacerNoMatchIsNoOp(t *testing.T) {
	r, _ := NewReplacer("ctf:acme", false)
	in := "completely unrelated string 12345"
	if got := r.ToAlias(in); got != in {
		t.Errorf("ToAlias no-match mutated string: %q", got)
	}
	if got := r.ToOriginal(in); got != in {
		t.Errorf("ToOriginal no-match mutated string: %q", got)
	}
}

// TestReplacerEmptyStringInput confirms empty strings don't panic.
func TestReplacerEmptyStringInput(t *testing.T) {
	r, _ := NewReplacer("ctf:acme", false)
	if got := r.ToAlias(""); got != "" {
		t.Errorf("ToAlias(\"\") = %q", got)
	}
	if got := r.ToOriginal(""); got != "" {
		t.Errorf("ToOriginal(\"\") = %q", got)
	}
}

// ─── rewriteRootRelativePaths: additional cases ───────────────────────────────

// TestRewriteRootRelativePathsSingleQuote verifies that single-quoted HTML
// attribute values are also rewritten (the regex supports both quote styles).
func TestRewriteRootRelativePathsSingleQuote(t *testing.T) {
	sub := "app.example.com"
	pfx := "/__sd__/" + sub

	cases := []struct{ in, want string }{
		{
			`<link href='/static/app.css'>`,
			`<link href='` + pfx + `/static/app.css'>`,
		},
		{
			`<script src='/js/vendor.js'></script>`,
			`<script src='` + pfx + `/js/vendor.js'></script>`,
		},
		{
			`<form action='/submit'>`,
			`<form action='` + pfx + `/submit'>`,
		},
	}
	for _, c := range cases {
		got := rewriteRootRelativePaths(c.in, sub)
		if got != c.want {
			t.Errorf("single-quote:\n  got  %q\n  want %q", got, c.want)
		}
	}
}

// TestRewriteRootRelativePathsInlineStyle verifies that CSS url() expressions
// inside <style> tags (i.e. inline in HTML documents) are rewritten.
func TestRewriteRootRelativePathsInlineStyle(t *testing.T) {
	sub := "app.example.com"
	pfx := "/__sd__/" + sub

	in := `<style>.hero { background: url('/img/hero.jpg'); }</style>`
	want := `<style>.hero { background: url('` + pfx + `/img/hero.jpg'); }</style>`
	got := rewriteRootRelativePaths(in, sub)
	if got != want {
		t.Errorf("inline style:\n  got  %q\n  want %q", got, want)
	}
}

// TestRewriteRootRelativePathsNoDoublePrefix verifies idempotency: calling
// rewriteRootRelativePaths twice does not add the prefix twice.
func TestRewriteRootRelativePathsNoDoublePrefix(t *testing.T) {
	sub := "app.example.com"

	in := `<img src="/img/logo.png">`
	once := rewriteRootRelativePaths(in, sub)
	twice := rewriteRootRelativePaths(once, sub)

	if once != twice {
		t.Errorf("second call mutated output:\n  first:  %q\n  second: %q", once, twice)
	}
}

// ─── Integration tests ────────────────────────────────────────────────────────

// TestProxyRedirectDowngrade verifies that 301 (Moved Permanently) is downgraded
// to 302 (Found), and 308 (Permanent Redirect) is downgraded to 307 (Temporary
// Redirect), so browsers do not cache proxy-internal redirect destinations.
func TestProxyRedirectDowngrade(t *testing.T) {
	tests := []struct {
		name       string
		upstreamSC int
		wantSC     int
	}{
		{"301 -> 302", http.StatusMovedPermanently, http.StatusFound},
		{"308 -> 307", http.StatusPermanentRedirect, http.StatusTemporaryRedirect},
		{"302 unchanged", http.StatusFound, http.StatusFound},
		{"307 unchanged", http.StatusTemporaryRedirect, http.StatusTemporaryRedirect},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/new-location", tc.upstreamSC)
			}))
			defer upstream.Close()

			host := strings.TrimPrefix(upstream.URL, "http://")
			rep, _ := NewReplacer("", false)
			proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil)
			ps := httptest.NewServer(proxy)
			defer ps.Close()

			client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // don't follow redirects
			}}
			resp, err := client.Get(ps.URL + "/")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			if resp.StatusCode != tc.wantSC {
				t.Errorf("status: got %d, want %d", resp.StatusCode, tc.wantSC)
			}
		})
	}
}

// TestProxyCSPHSTSStripped verifies that security headers which would break or
// expose the proxy session are handled correctly:
//   - CSP is REWRITTEN (not stripped) — target domains replaced with proxy addr
//   - HSTS, HPKP, Expect-CT are still stripped entirely
func TestProxyCSPHSTSStripped(t *testing.T) {
	var upstreamHost string // set once we know the test server addr

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CSP contains the upstream's own host (mirrors real-world behaviour where
		// the server's CSP references its own domain).
		w.Header().Set("Content-Security-Policy", "default-src 'self' https://"+upstreamHost)
		w.Header().Set("Content-Security-Policy-Report-Only", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Public-Key-Pins", `pin-sha256="abc"; max-age=60`)
		w.Header().Set("Expect-CT", "max-age=86400, enforce")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost = strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// CSP must be PRESENT (rewritten, not stripped).
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy should be present (rewritten, not stripped)")
	} else if strings.Contains(csp, upstreamHost) {
		t.Errorf("Content-Security-Policy still contains upstream host: %q", csp)
	}

	// report-only CSP with no target-domain refs passes through unchanged.
	if v := resp.Header.Get("Content-Security-Policy-Report-Only"); v == "" {
		t.Error("Content-Security-Policy-Report-Only should be present")
	}

	// Security headers that reveal upstream identity must be stripped entirely.
	for _, h := range []string{"Strict-Transport-Security", "Public-Key-Pins", "Expect-CT"} {
		if v := resp.Header.Get(h); v != "" {
			t.Errorf("header %q should be stripped, got %q", h, v)
		}
	}
}

// TestProxy204NoBody verifies that a 204 No Content response is handled cleanly
// (no gzip decode attempt, no body, correct status code).
func TestProxy204NoBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip") // some upstreams do this
		w.WriteHeader(http.StatusNoContent)
		// No body written.
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false)
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("expected empty body for 204, got %q", string(body))
	}
}

// TestProxy304NotModified verifies that a 304 Not Modified response is handled
// cleanly without attempting to decode or rewrite a (non-existent) body.
func TestProxy304NotModified(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("ETag", `"abc123"`)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false)
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest(http.MethodGet, ps.URL+"/", nil)
	req.Header.Set("If-None-Match", `"abc123"`)
	resp, err := ps.Client().Do(req)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Errorf("expected 304, got %d", resp.StatusCode)
	}
}

// TestProxyPOSTBodyReplacement verifies that alias→original replacement is
// applied to POST request bodies before they are forwarded upstream.
func TestProxyPOSTBodyReplacement(t *testing.T) {
	var capturedBody string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme,ctfd:foo", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	// Client sends aliases; upstream should receive originals.
	body := strings.NewReader(`{"team":"acme","challenge":"foo"}`)
	resp, err := http.Post(ps.URL+"/api/submit", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if capturedBody != `{"team":"ctf","challenge":"ctfd"}` {
		t.Errorf("POST body not de-aliased: got %q", capturedBody)
	}
}

// TestProxyRequestHeaderMasking verifies that proxy-address references in
// outbound request headers (e.g. Referer, Origin) are rewritten to the real
// upstream host before being forwarded.
func TestProxyRequestHeaderMasking(t *testing.T) {
	var capturedReferer, capturedOrigin string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReferer = r.Header.Get("Referer")
		capturedOrigin = r.Header.Get("Origin")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	const proxyAddr = "localhost:8080"
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, proxyAddr, true, 0, testLogger(), nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest(http.MethodGet, ps.URL+"/page", nil)
	// Simulate a browser that sends proxy-address-based Referer and Origin.
	req.Header.Set("Referer", "http://"+proxyAddr+"/previous-page")
	req.Header.Set("Origin", "http://"+proxyAddr)
	resp, err := ps.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// The proxy address must NOT appear in outbound headers.
	if strings.Contains(capturedReferer, proxyAddr) {
		t.Errorf("Referer still contains proxy addr: %q", capturedReferer)
	}
	if strings.Contains(capturedOrigin, proxyAddr) {
		t.Errorf("Origin still contains proxy addr: %q", capturedOrigin)
	}
	// The upstream host must appear instead.
	if !strings.Contains(capturedReferer, upstreamHost) {
		t.Errorf("Referer does not contain upstream host: %q", capturedReferer)
	}
}

// TestProxyQueryStringReplacement verifies that alias→original replacement is
// applied to URL query parameters in GET requests.
func TestProxyQueryStringReplacement(t *testing.T) {
	var capturedQuery string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme,ctfd:foo", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	// Query string contains alias values that should be converted to originals.
	http.Get(ps.URL + "/search?q=acme&category=foo")

	if capturedQuery != "q=ctf&category=ctfd" {
		t.Errorf("query string not de-aliased: got %q, want %q", capturedQuery, "q=ctf&category=ctfd")
	}
}

// TestProxyCaseInsensitivePipeline verifies that the full proxy pipeline applies
// case-insensitive replacement in both directions.
func TestProxyCaseInsensitivePipeline(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Uppercase and mixed-case variants in the response body.
		fmt.Fprint(w, `<title>Welcome to CTF Platform</title><p>CTFD login</p>`)
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme,ctfd:foo", true) // CI mode (the default)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)

	// CTF and CTFD (in any case) must be replaced.
	if strings.Contains(strings.ToLower(got), "ctfd") {
		t.Errorf("CTFD not replaced in CI mode: %q", got)
	}
	if strings.Contains(strings.ToLower(got), "ctf") {
		t.Errorf("CTF not replaced in CI mode: %q", got)
	}
	if !strings.Contains(got, "acme") && !strings.Contains(got, "foo") {
		t.Errorf("replacement aliases not found in CI output: %q", got)
	}
}

// TestProxyXForwardedForStripped verifies that any client-supplied
// X-Forwarded-For header is NOT forwarded upstream (IP spoofing prevention).
func TestProxyXForwardedForStripped(t *testing.T) {
	var capturedXFF string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedXFF = r.Header.Get("X-Forwarded-For")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest(http.MethodGet, ps.URL+"/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	resp, err := ps.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// httputil.ReverseProxy always appends the real client IP to X-Forwarded-For
	// after the director runs (RFC 7239 behaviour).  What matters is that the
	// client-supplied *spoofed* value "1.2.3.4" was stripped and never forwarded.
	if strings.Contains(capturedXFF, "1.2.3.4") {
		t.Errorf("spoofed X-Forwarded-For value leaked upstream: %q", capturedXFF)
	}
}

// TestEffectiveProxyAddrContextPropagation verifies that when a client accesses
// the proxy via 127.0.0.1:PORT, redirect Location headers in the response are
// also written with 127.0.0.1:PORT (not localhost:PORT), preventing CORS errors.
func TestEffectiveProxyAddrContextPropagation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate an upstream redirect to itself.
		upHost := r.Host
		http.Redirect(w, r, "https://"+upHost+"/dashboard", http.StatusFound)
	}))
	defer upstream.Close()

	// Bind the proxy listener first so we know the port, then build proxyAddr
	// with the same port.  The port-matching guard in modifyResponse only
	// substitutes the hostname when clientPort == proxyPort, so both must agree.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	// proxyAddr uses "localhost" — but client will connect via 127.0.0.1.
	proxyAddr := fmt.Sprintf("localhost:%d", port)
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, proxyAddr, true, 0, testLogger(), nil)

	srv := &http.Server{Handler: proxy}
	go srv.Serve(ln) //nolint:errcheck
	defer srv.Close()

	// Connect via 127.0.0.1:PORT — different hostname string than "localhost".
	connectURL := fmt.Sprintf("http://127.0.0.1:%d/", port)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(connectURL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	// The Location must use the same host (127.0.0.1:PORT) the client connected to.
	// If it instead uses "localhost:PORT" (the configured proxyAddr), the browser
	// would see a cross-origin redirect (different hostname) → CORS failure.
	if loc == "" {
		t.Fatal("expected a Location header")
	}
	want := fmt.Sprintf("127.0.0.1:%d", port)
	if !strings.Contains(loc, want) {
		t.Errorf("Location %q should contain %q (same addr as client connected to)", loc, want)
	}
	if strings.Contains(loc, fmt.Sprintf("localhost:%d", port)) {
		t.Errorf("Location %q leaked configured proxyAddr instead of effective client addr", loc)
	}
}

// TestProxyAcceptEncodingOverridden verifies that the proxy always requests
// gzip (or identity) from upstream, overriding any Accept-Encoding the client
// sent. This ensures the proxy can always decode and rewrite the response body.
func TestProxyAcceptEncodingOverridden(t *testing.T) {
	var capturedAE string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAE = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest(http.MethodGet, ps.URL+"/", nil)
	// Client requests brotli — proxy must override this.
	req.Header.Set("Accept-Encoding", "br, zstd, gzip")
	resp, err := ps.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if !strings.Contains(capturedAE, "gzip") {
		t.Errorf("upstream Accept-Encoding should contain gzip, got %q", capturedAE)
	}
	if strings.Contains(capturedAE, "br") || strings.Contains(capturedAE, "zstd") {
		t.Errorf("upstream Accept-Encoding should not contain br/zstd, got %q", capturedAE)
	}
}

// TestProxyLocationHeaderMasking verifies that the upstream host in a redirect
// Location header is replaced with the proxy address.
func TestProxyLocationHeaderMasking(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upHost := r.Host
		http.Redirect(w, r, "https://"+upHost+"/new-path", http.StatusFound)
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	const proxyAddr = "proxy.local:8080"
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, proxyAddr, true, 0, testLogger(), nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	client := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(ps.URL + "/old-path")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	if strings.Contains(loc, upstreamHost) {
		t.Errorf("Location leaks upstream host: %q", loc)
	}
	if !strings.Contains(loc, proxyAddr) {
		t.Errorf("Location does not contain proxy addr: %q", loc)
	}
}

// TestProxyUserReplacementInLocationHeader verifies that user-defined alias
// replacements are applied to Location headers in redirect responses.
func TestProxyUserReplacementInLocationHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upHost := r.Host
		// Upstream redirects to a path that contains the original keyword.
		http.Redirect(w, r, "https://"+upHost+"/ctf/dashboard", http.StatusFound)
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false)
	const proxyAddr = "proxy.local:8080"
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, proxyAddr, true, 0, testLogger(), nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	client := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(ps.URL + "/old-path")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	// The path "/ctf/dashboard" should be aliased to "/acme/dashboard".
	if !strings.Contains(loc, "/acme/dashboard") {
		t.Errorf("Location path not aliased: %q", loc)
	}
	if strings.Contains(loc, "/ctf/dashboard") {
		t.Errorf("Location path still has original keyword: %q", loc)
	}
}

// TestProxySubdomainUserReplaceNotCorruptedInBody verifies the full pipeline:
// a subdomain URL that gets encoded into /__sd__/ must NOT have the encoded
// hostname corrupted by subsequent user alias replacements.
func TestProxySubdomainUserReplaceNotCorruptedInBody(t *testing.T) {
	const rootHost = "ynet.co.il"

	// Upstream that returns a subdomain URL in its response body.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<img src="https://pic.ynet.co.il/photo.jpg">`)
	}))
	defer upstream.Close()

	rep, _ := NewReplacer("ynet:news", false)
	const proxyAddr = "localhost:9002"
	// Use rootHost as targetHost so subdomainRe matches "pic.ynet.co.il".
	// fixedHostTransport routes all requests (including the subdomain ones) to
	// the test upstream without real DNS.
	proxy := NewReverseProxy(rootHost, "http", rep, false, proxyAddr, false, 0, testLogger(), nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}

	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)

	// The /__sd__/ path must use the real hostname — NOT the aliased one.
	if strings.Contains(got, "/__sd__/pic.news.co.il/") {
		t.Errorf("/__sd__/ host was corrupted by user replacement: %q", got)
	}
	if !strings.Contains(got, "/__sd__/pic.ynet.co.il/") {
		t.Errorf("/__sd__/ path not found or incorrectly rewritten: %q", got)
	}
}

// TestProxyResponseHostAndUserReplacementCombined is a combined correctness
// check: host masking runs BEFORE user replacements, so the target host in
// absolute URLs is replaced with the proxy address (step 1), and then user
// replacements are applied to paths (step 3) — in that order.
func TestProxyResponseHostAndUserReplacementCombined(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upHost := r.Host
		w.Header().Set("Content-Type", "text/html")
		// Body: absolute URL contains both upstream host AND a replaceable keyword in the path.
		fmt.Fprintf(w, `<a href="https://%s/ctf/page">link</a>`, upHost)
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false)
	const proxyAddr = "localhost:8080"
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, proxyAddr, true, 0, testLogger(), nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)

	want := fmt.Sprintf(`<a href="http://%s/acme/page">link</a>`, proxyAddr)
	if got != want {
		t.Errorf("combined masking:\n  got  %q\n  want %q", got, want)
	}
}

// ─── rewriteCSP ──────────────────────────────────────────────────────────────

func TestRewriteCSP(t *testing.T) {
const target = "microsoft.com"
const root = "microsoft.com"
const proxy = "localhost:9001"

cases := []struct {
name string
in   string
want string
}{
{
name: "https scheme replaced with http://proxy",
in:   "default-src 'self' https://microsoft.com",
want: "default-src 'self' http://localhost:9001",
},
{
name: "wildcard subdomain collapses to proxy addr",
in:   "script-src 'self' *.microsoft.com",
want: "script-src 'self' localhost:9001",
},
{
name: "https wildcard subdomain → http://proxy",
in:   "img-src https://*.microsoft.com",
want: "img-src http://localhost:9001",
},
{
name: "wss scheme becomes ws://proxy",
in:   "connect-src wss://microsoft.com",
want: "connect-src ws://localhost:9001",
},
{
name: "bare host replaced",
in:   "font-src microsoft.com",
want: "font-src localhost:9001",
},
{
name: "named subdomain replaced",
in:   "script-src cdn.microsoft.com",
want: "script-src localhost:9001",
},
{
name: "report-uri directive dropped",
in:   "default-src 'self'; report-uri https://csp.microsoft.com/report",
want: "default-src 'self'",
},
{
name: "report-to directive dropped",
in:   "default-src 'self'; report-to csp-endpoint",
want: "default-src 'self'",
},
{
name: "non-target domain unchanged",
in:   "img-src https://cdn.google.com",
want: "img-src https://cdn.google.com",
},
{
name: "keywords preserved",
in:   "script-src 'self' 'nonce-abc123' 'sha256-abc' 'unsafe-inline'",
want: "script-src 'self' 'nonce-abc123' 'sha256-abc' 'unsafe-inline'",
},
{
name: "multiple directives all rewritten",
in:   "default-src 'self' https://microsoft.com; script-src *.microsoft.com 'nonce-x'; connect-src wss://api.microsoft.com",
want: "default-src 'self' http://localhost:9001; script-src localhost:9001 'nonce-x'; connect-src ws://localhost:9001",
},
{
name: "empty CSP unchanged",
in:   "",
want: "",
},
{
name: "proxyAddr empty disables rewriting",
// tested by calling rewriteCSP with empty proxyAddr
in:   "default-src https://microsoft.com",
want: "default-src https://microsoft.com",
},
}

for _, tc := range cases {
t.Run(tc.name, func(t *testing.T) {
pa := proxy
if tc.name == "proxyAddr empty disables rewriting" {
pa = ""
}
got := rewriteCSP(tc.in, target, root, pa)
if got != tc.want {
t.Errorf("\n  got  %q\n  want %q", got, tc.want)
}
})
}
}

// TestProxyCSPRewrittenInResponse is an integration test verifying that the
// proxy rewrites Content-Security-Policy headers in real responses.
func TestProxyCSPRewrittenInResponse(t *testing.T) {
	const proxyAddr = "localhost:9003"
	var upstreamHost string // filled after server starts

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate upstream CSP that references its own hostname (real-world pattern).
		w.Header().Set("Content-Security-Policy",
			"default-src 'self' https://"+upstreamHost+"; script-src *."+upstreamHost+"; report-uri https://"+upstreamHost+"/csp")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "hello")
	}))
	defer upstream.Close()

	upstreamHost = strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, proxyAddr, true, 0, testLogger(), nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("expected Content-Security-Policy header to be present (not stripped)")
	}
	if strings.Contains(csp, upstreamHost) {
		t.Errorf("CSP still contains upstream host: %q", csp)
	}
	if strings.Contains(csp, "report-uri") {
		t.Errorf("CSP report-uri not stripped: %q", csp)
	}
	if !strings.Contains(csp, "'self'") {
		t.Errorf("CSP 'self' keyword was removed: %q", csp)
	}
}

// ─── WebSocket frame logging ──────────────────────────────────────────────────

// wsLogger returns a Logger that writes to a strings.Builder so tests can
// inspect the log output.
func wsLogger(buf *strings.Builder) *Logger {
return &Logger{
l:     log.New(buf, "", 0),
logWS: true,
}
}

// buildWSTextFrame builds a minimal unmasked FIN text frame (opcode 0x1).
func buildWSTextFrame(payload string) []byte {
p := []byte(payload)
frame := make([]byte, 2+len(p))
frame[0] = 0x81 // FIN + opcode=1 (text)
frame[1] = byte(len(p))
copy(frame[2:], p)
return frame
}

// buildWSMaskedTextFrame builds a client-style masked FIN text frame.
func buildWSMaskedTextFrame(payload string) []byte {
p := []byte(payload)
frame := make([]byte, 2+4+len(p))
frame[0] = 0x81                     // FIN + opcode=1
frame[1] = 0x80 | byte(len(p))      // MASK + len
frame[2], frame[3], frame[4], frame[5] = 0xDE, 0xAD, 0xBE, 0xEF // mask key
for i, b := range p {
frame[6+i] = b ^ frame[2+i%4]
}
return frame
}

// buildWSBinaryFrame builds an unmasked FIN binary frame (opcode 0x2).
func buildWSBinaryFrame(payload []byte) []byte {
frame := make([]byte, 2+len(payload))
frame[0] = 0x82 // FIN + opcode=2 (binary)
frame[1] = byte(len(payload))
copy(frame[2:], payload)
return frame
}

// buildWS16BitFrame builds an unmasked FIN text frame with a 16-bit extended length.
func buildWS16BitFrame(payloadLen int) []byte {
frame := make([]byte, 2+2+payloadLen)
frame[0] = 0x81 // FIN + text
frame[1] = 126  // 16-bit extended length follows
frame[2] = byte(payloadLen >> 8)
frame[3] = byte(payloadLen)
// payload is all zeros
return frame
}

// buildWSPingFrame builds an unmasked FIN ping frame (opcode 0x9).
func buildWSPingFrame() []byte {
return []byte{0x89, 0x00} // FIN + ping, 0 payload bytes
}

// buildWSFragmentFrame builds a non-FIN text frame (first fragment, opcode 0x1).
func buildWSFragmentFrame(payload string) []byte {
p := []byte(payload)
frame := make([]byte, 2+len(p))
frame[0] = 0x01 // FIN=0 + opcode=1 (text)
frame[1] = byte(len(p))
copy(frame[2:], p)
return frame
}

// TestWSFrameParserText verifies a simple unmasked text frame.
func TestWSFrameParserText(t *testing.T) {
var buf strings.Builder
lg := wsLogger(&buf)
var s wsFrameParseState

frame := buildWSTextFrame("hello")
s.feed(frame, 7, "WS↓", lg)

got := buf.String()
if !strings.Contains(got, "text") {
t.Errorf("expected opcode 'text', got: %q", got)
}
if !strings.Contains(got, "len=5") {
t.Errorf("expected len=5, got: %q", got)
}
if !strings.Contains(got, "conn#7") {
t.Errorf("expected conn#7, got: %q", got)
}
if !strings.Contains(got, "WS↓") {
t.Errorf("expected direction WS↓, got: %q", got)
}
}

// TestWSFrameParserMasked verifies a masked (client→upstream) frame.
func TestWSFrameParserMasked(t *testing.T) {
var buf strings.Builder
lg := wsLogger(&buf)
var s wsFrameParseState

frame := buildWSMaskedTextFrame("hi")
s.feed(frame, 1, "WS↑", lg)

got := buf.String()
if !strings.Contains(got, "[masked]") {
t.Errorf("expected [masked] flag, got: %q", got)
}
if !strings.Contains(got, "len=2") {
t.Errorf("expected len=2, got: %q", got)
}
}

// TestWSFrameParserPing verifies a ping control frame.
func TestWSFrameParserPing(t *testing.T) {
var buf strings.Builder
lg := wsLogger(&buf)
var s wsFrameParseState

s.feed(buildWSPingFrame(), 1, "WS↓", lg)
if !strings.Contains(buf.String(), "ping") {
t.Errorf("expected 'ping', got: %q", buf.String())
}
}

// TestWSFrameParserFragment verifies a non-FIN (fragment) frame is flagged.
func TestWSFrameParserFragment(t *testing.T) {
var buf strings.Builder
lg := wsLogger(&buf)
var s wsFrameParseState

s.feed(buildWSFragmentFrame("part"), 1, "WS↓", lg)
if !strings.Contains(buf.String(), "[fragment]") {
t.Errorf("expected [fragment] flag, got: %q", buf.String())
}
}

// TestWSFrameParser16BitLen verifies a frame with 16-bit extended payload length.
func TestWSFrameParser16BitLen(t *testing.T) {
var buf strings.Builder
lg := wsLogger(&buf)
var s wsFrameParseState

s.feed(buildWS16BitFrame(300), 1, "WS↓", lg)
if !strings.Contains(buf.String(), "len=300") {
t.Errorf("expected len=300, got: %q", buf.String())
}
}

// TestWSFrameParserChunked verifies correct parsing when frame bytes arrive in
// tiny chunks (e.g. one byte at a time) — exercises cross-chunk header accumulation.
func TestWSFrameParserChunked(t *testing.T) {
var buf strings.Builder
lg := wsLogger(&buf)
var s wsFrameParseState

frame := buildWSTextFrame("abc") // 5 bytes total
// Feed one byte at a time.
for _, b := range frame {
s.feed([]byte{b}, 1, "WS↓", lg)
}
got := buf.String()
if !strings.Contains(got, "text") {
t.Errorf("expected 'text' after byte-by-byte feed, got: %q", got)
}
if !strings.Contains(got, "len=3") {
t.Errorf("expected len=3, got: %q", got)
}
}

// TestWSFrameParserMultipleFrames verifies that two frames concatenated in one
// buffer are both parsed and logged.
func TestWSFrameParserMultipleFrames(t *testing.T) {
var buf strings.Builder
lg := wsLogger(&buf)
var s wsFrameParseState

// Two frames back-to-back.
data := append(buildWSTextFrame("hello"), buildWSPingFrame()...)
s.feed(data, 1, "WS↓", lg)

got := buf.String()
if !strings.Contains(got, "text") {
t.Errorf("expected 'text' frame, got: %q", got)
}
if !strings.Contains(got, "ping") {
t.Errorf("expected 'ping' frame, got: %q", got)
}
}

// TestLogWSFrameDisabled verifies that LogWSFrame is a no-op when logWS=false.
func TestLogWSFrameDisabled(t *testing.T) {
var buf strings.Builder
lg := &Logger{l: log.New(&buf, "", 0), logWS: false}
lg.LogWSFrame(1, "WS↓", 0x1, true, false, 5)
if buf.String() != "" {
t.Errorf("expected no output when logWS=false, got: %q", buf.String())
}
}

// TestWSLoggingTransportWraps101 verifies that wsLoggingTransport replaces the
// response body with a wsLoggingConn for 101 responses and logs the connection.
func TestWSLoggingTransportWraps101(t *testing.T) {
var buf strings.Builder
lg := wsLogger(&buf)

// // Use a pipe as a valid ReadWriteCloser.
pr, pw := io.Pipe()
go pw.Close()

// Mock transport that returns 101 with a pipe as body.
mockRT := roundTripFunc(func(req *http.Request) (*http.Response, error) {
return &http.Response{
StatusCode: 101,
Header:     make(http.Header),
Body:       pipeRWC{pr, pw},
}, nil
})

wlt := &wsLoggingTransport{rt: mockRT, logger: lg}
req, _ := http.NewRequest("GET", "http://example.com/ws", nil)
resp, err := wlt.RoundTrip(req)
if err != nil {
t.Fatal(err)
}
if _, ok := resp.Body.(*wsLoggingConn); !ok {
t.Errorf("expected resp.Body to be *wsLoggingConn, got %T", resp.Body)
}
if !strings.Contains(buf.String(), "conn#") {
t.Errorf("expected connection established log, got: %q", buf.String())
}
}

// TestWSLoggingTransportPassesNon101 verifies that non-101 responses are
// returned unchanged (no wrapping).
func TestWSLoggingTransportPassesNon101(t *testing.T) {
var buf strings.Builder
lg := wsLogger(&buf)

mockRT := roundTripFunc(func(req *http.Request) (*http.Response, error) {
return &http.Response{
StatusCode: 200,
Header:     make(http.Header),
Body:       io.NopCloser(strings.NewReader("ok")),
}, nil
})

wlt := &wsLoggingTransport{rt: mockRT, logger: lg}
req, _ := http.NewRequest("GET", "http://example.com/", nil)
resp, err := wlt.RoundTrip(req)
if err != nil {
t.Fatal(err)
}
if _, ok := resp.Body.(*wsLoggingConn); ok {
t.Error("non-101 response body should NOT be wrapped")
}
}

// pipeRWC wraps an io.PipeReader+Writer as an io.ReadWriteCloser so it
// satisfies the interface that httputil expects for 101 response bodies.
type pipeRWC struct {
r *io.PipeReader
w *io.PipeWriter
}

func (p pipeRWC) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p pipeRWC) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p pipeRWC) Close() error                { p.w.Close(); return p.r.Close() }

// roundTripFunc adapts a function to the http.RoundTripper interface.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
