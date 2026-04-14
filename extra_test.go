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
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
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
		{"application/manifest+json", true},       // PWA web app manifests
		{"application/manifest+json; charset=utf-8", true},
		{"application/feed+json", true},            // JSON Feed
		{"application/xml", true},
		{"application/xhtml+xml", true},
		{"application/javascript", true},
		{"application/x-javascript", true},
		{"application/ld+json", true},
		{"application/graphql", true},
		{"application/x-www-form-urlencoded", true},
		{"application/rss+xml", true},
		{"application/atom+xml", true},

		// Binary types — must NOT be rewritten.
		{"image/png", false},
		{"image/jpeg", false},
		{"image/gif", false},
		{"image/svg+xml", true},   // SVG is XML text; may contain href/url() referencing upstream hosts
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
		{
			desc:   "protocol-relative //proxyAddr/ rewritten to //targetHost/",
			in:     "//localhost:8080/static/app.js",
			target: "ctf.io", scheme: "https", proxy: "localhost:8080",
			want: "//ctf.io/static/app.js",
		},
		{
			desc:   "Referer from /__sd__/ page gets correct subdomain host",
			in:     "http://localhost:8080/__sd__/api.ctf.io/path?q=1",
			target: "ctf.io", scheme: "https", proxy: "localhost:8080",
			want: "https://api.ctf.io/path?q=1",
		},
		{
			desc:   "Referer from /__sd__/ page with no trailing path",
			in:     "http://localhost:8080/__sd__/api.ctf.io",
			target: "ctf.io", scheme: "https", proxy: "localhost:8080",
			want: "https://api.ctf.io/",
		},
		{
			desc:   "multiple /__sd__/ occurrences all rewritten",
			in:     "x=http://localhost:8080/__sd__/a.ctf.io/p&y=http://localhost:8080/__sd__/b.ctf.io/q",
			target: "ctf.io", scheme: "https", proxy: "localhost:8080",
			want: "x=https://a.ctf.io/p&y=https://b.ctf.io/q",
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

	t.Run("__sd__ host segment gets replacement applied", func(t *testing.T) {
		// The /__sd__/ HOST is replaced so the browser sees the aliased hostname.
		// The PATH is shielded to preserve exact CDN filenames for correct routing.
		in := `<a href="http://localhost:9002/__sd__/api.ynet.co.il/data">x</a>`
		got := withExternalURLsProtected(in, "http://localhost:9002", replace)
		if !strings.Contains(got, "/__sd__/api.news.co.il/") {
			t.Errorf("__sd__ host not replaced: %q", got)
		}
		if strings.Contains(got, "/__sd__/api.ynet.co.il/") {
			t.Errorf("__sd__ host unexpectedly unchanged: %q", got)
		}
	})

	t.Run("__sd__ path preserved to protect CDN filenames", func(t *testing.T) {
		// The path portion of a /__sd__/ URL must NOT have ToAlias applied.
		// This ensures CDN files whose names contain the original-case token
		// (e.g. "BBCReithSans_W_Rg.woff2" when -replace bbc:britcast) are not
		// corrupted, preventing 404s when the director reverses the alias.
		bReplace := func(s string) string {
			return strings.ReplaceAll(s, "bbc", "britcast")
		}
		in := `src="http://localhost:9002/__sd__/static.files.bbci.co.uk/fonts/BBCReithSans_W_Rg.woff2"`
		got := withExternalURLsProtected(in, "http://localhost:9002", bReplace)
		// Host "bbci.co.uk" should be aliased.
		if !strings.Contains(got, "britcasti.co.uk") {
			t.Errorf("__sd__ host not aliased: %q", got)
		}
		// Path filename "BBCReithSans_W_Rg.woff2" should be preserved exactly.
		if !strings.Contains(got, "BBCReithSans_W_Rg.woff2") {
			t.Errorf("CDN filename corrupted in __sd__ path: %q", got)
		}
		if strings.Contains(got, "britcastReithSans") {
			t.Errorf("CDN filename was aliased (should be protected): %q", got)
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
		rewriteSetCookies(resp, false, "")
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
		rewriteSetCookies(resp, false, "")
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
		rewriteSetCookies(resp, true, "") // proxy is HTTPS
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
		rewriteSetCookies(resp, false, "")
		sc := resp.Header.Get("Set-Cookie")
		if !strings.Contains(sc, "token=xyz") {
			t.Errorf("plain cookie value corrupted: %q", sc)
		}
	})

	t.Run("no Set-Cookie headers is a no-op", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		rewriteSetCookies(resp, false, "") // must not panic
	})

	t.Run("multiple cookies all rewritten", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Add("Set-Cookie", "a=1; Domain=example.com; Secure")
		resp.Header.Add("Set-Cookie", "b=2; Domain=example.com; Secure")
		rewriteSetCookies(resp, false, "")
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

	t.Run("subdomain Path prefixed with __sd__ route", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Add("Set-Cookie", "sess=tok; Path=/api/; HttpOnly")
		rewriteSetCookies(resp, false, "sub.example.com")
		sc := resp.Header.Get("Set-Cookie")
		if !strings.Contains(sc, "Path=/__sd__/sub.example.com/api/") {
			t.Errorf("subdomain cookie Path not prefixed: %q", sc)
		}
	})

	t.Run("subdomain root Path becomes __sd__ prefix", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Add("Set-Cookie", "sid=1; Path=/")
		rewriteSetCookies(resp, false, "api.example.com")
		sc := resp.Header.Get("Set-Cookie")
		if !strings.Contains(sc, "Path=/__sd__/api.example.com/") {
			t.Errorf("root Path not rewritten for subdomain: %q", sc)
		}
	})

	t.Run("main target cookies path unchanged", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Add("Set-Cookie", "sid=1; Path=/app/")
		rewriteSetCookies(resp, false, "") // subHost="" = main target
		sc := resp.Header.Get("Set-Cookie")
		if !strings.Contains(sc, "Path=/app/") || strings.Contains(sc, "/__sd__/") {
			t.Errorf("main target cookie Path incorrectly modified: %q", sc)
		}
	})

	t.Run("__Host- prefix stripped when Secure removed", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Add("Set-Cookie", "__Host-session=abc; Path=/; Secure; HttpOnly")
		rewriteSetCookies(resp, false, "")
		sc := resp.Header.Get("Set-Cookie")
		if strings.HasPrefix(sc, "__Host-") {
			t.Errorf("__Host- prefix not stripped when Secure removed: %q", sc)
		}
		if !strings.Contains(sc, "session=abc") {
			t.Errorf("cookie value lost after prefix strip: %q", sc)
		}
		if strings.Contains(strings.ToLower(sc), "secure") {
			t.Errorf("Secure flag not removed: %q", sc)
		}
	})

	t.Run("__Secure- prefix stripped when Secure removed", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Add("Set-Cookie", "__Secure-token=xyz; Path=/; Secure")
		rewriteSetCookies(resp, false, "")
		sc := resp.Header.Get("Set-Cookie")
		if strings.HasPrefix(sc, "__Secure-") {
			t.Errorf("__Secure- prefix not stripped when Secure removed: %q", sc)
		}
		if !strings.Contains(sc, "token=xyz") {
			t.Errorf("cookie value lost after prefix strip: %q", sc)
		}
	})

	t.Run("__Host- prefix kept when proxy is HTTPS", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Add("Set-Cookie", "__Host-session=abc; Path=/; Secure; HttpOnly")
		rewriteSetCookies(resp, true, "") // proxy is HTTPS — keep Secure + prefix
		sc := resp.Header.Get("Set-Cookie")
		if !strings.HasPrefix(sc, "__Host-") {
			t.Errorf("__Host- prefix incorrectly stripped for HTTPS proxy: %q", sc)
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
		got := maskResponseString(c.in, target, computeRootDomain(target), proxy, re, buildTestBareTargetRe(target), nil)
		if got != c.want {
			t.Errorf("step5(%q)\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}
}

// TestMaskResponseStringDisabled verifies that passing proxyAddr="" leaves the
// string unchanged (masking is disabled).
func TestMaskResponseStringDisabled(t *testing.T) {
	in := `href="https://ctf.io/page" visit ctf.io today`
	got := maskResponseString(in, "ctf.io", "ctf.io", "", nil, nil, nil)
	if got != in {
		t.Errorf("disabled masking should be no-op, got %q", got)
	}
}

// TestMaskResponseStringAlsoProxy verifies that -also-proxy domains are routed
// via /__sd__/<host>/ in responses.
func TestMaskResponseStringAlsoProxy(t *testing.T) {
	proxy := "localhost:8080"
	alsoProxyRe := regexp.MustCompile(
		`(?i)((?:https?:)?//(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)*bbci\.co\.uk)([/?#"'\s\x00]|$)`,
	)
	cases := []struct{ in, want string }{
		{
			`<script src="https://static.files.bbci.co.uk/fonts/main.js">`,
			`<script src="http://localhost:8080/__sd__/static.files.bbci.co.uk/fonts/main.js">`,
		},
		{
			`href="//news.bbci.co.uk/news/"`,
			`href="http://localhost:8080/__sd__/news.bbci.co.uk/news/"`,
		},
		// Non-alsoProxy domain — must not be routed
		{
			`<img src="https://cdn.yit.co.il/img.png">`,
			`<img src="https://cdn.yit.co.il/img.png">`,
		},
	}
	for _, c := range cases {
		got := maskResponseString(c.in, "www.bbc.com", "bbc.com", proxy, nil, nil, alsoProxyRe)
		if got != c.want {
			t.Errorf("alsoProxy: input %q\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}
}



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
			proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, nil, 0, nil)
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
		// NEL and Report-To send network telemetry to upstream — must be stripped.
		w.Header().Set("Report-To", `{"group":"default","max_age":86400,"endpoints":[{"url":"https://upstream.example/report"}]}`)
		w.Header().Set("Nel", `{"report_to":"default","max_age":86400}`)
		// COOP/COEP enforce cross-origin isolation and break the proxy model.
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost = strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, nil, 0, nil)
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

	// Security/isolation headers that must be stripped entirely.
	for _, h := range []string{
		"Strict-Transport-Security", "Public-Key-Pins", "Expect-CT",
		"Report-To", "Nel",
		"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
		"Cross-Origin-Resource-Policy",
	} {
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
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, nil, 0, nil)
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
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, nil, 0, nil)
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
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
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
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, proxyAddr, true, 0, testLogger(), nil, nil, 0, nil)
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
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
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
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
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
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
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

// TestConditionalRequestHeadersStripped verifies that If-None-Match and
// If-Modified-Since are stripped before reaching the upstream.  If forwarded,
// a 304 Not Modified response would skip body rewriting and leave the browser
// with a stale cached copy containing unrewritten upstream hostnames.
func TestConditionalRequestHeadersStripped(t *testing.T) {
	var capturedIfNoneMatch, capturedIfModifiedSince string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIfNoneMatch = r.Header.Get("If-None-Match")
		capturedIfModifiedSince = r.Header.Get("If-Modified-Since")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest(http.MethodGet, ps.URL+"/page", nil)
	req.Header.Set("If-None-Match", `"abc123"`)
	req.Header.Set("If-Modified-Since", "Wed, 01 Jan 2020 00:00:00 GMT")
	resp, err := ps.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if capturedIfNoneMatch != "" {
		t.Errorf("If-None-Match was forwarded upstream: %q", capturedIfNoneMatch)
	}
	if capturedIfModifiedSince != "" {
		t.Errorf("If-Modified-Since was forwarded upstream: %q", capturedIfModifiedSince)
	}
}

// TestETagLastModifiedStripped verifies that ETag and Last-Modified response
// headers are removed by the proxy.  If left in place, the browser would cache
// these and send conditional requests on re-visits; a 304 response would then
// bypass body rewriting entirely.
func TestETagLastModifiedStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"strongetag123"`)
		w.Header().Set("Last-Modified", "Wed, 01 Jan 2020 00:00:00 GMT")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if v := resp.Header.Get("ETag"); v != "" {
		t.Errorf("ETag should be stripped, got %q", v)
	}
	if v := resp.Header.Get("Last-Modified"); v != "" {
		t.Errorf("Last-Modified should be stripped, got %q", v)
	}
}


// also written with 127.0.0.1:PORT (not localhost:PORT), preventing CORS errors.
func TestEffectiveProxyAddrContextPropagation(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a body containing the upstream's own URL so the proxy will mask it.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<a href="http://%s/link">click</a>`, upstreamHost)
	}))
	defer upstream.Close()
	upstreamHost = strings.TrimPrefix(upstream.URL, "http://")

	// Bind the proxy listener first so we know the port, then build proxyAddr
	// with the same port.  The port-matching guard in modifyResponse only
	// substitutes the hostname when clientPort == proxyPort, so both must agree.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	rep, _ := NewReplacer("", false)
	// proxyAddr uses "localhost" — but client will connect via 127.0.0.1.
	proxyAddr := fmt.Sprintf("localhost:%d", port)
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, proxyAddr, true, 0, testLogger(), nil, nil, 0, nil)

	srv := &http.Server{Handler: proxy}
	go srv.Serve(ln) //nolint:errcheck
	defer srv.Close()

	// Connect via 127.0.0.1:PORT — different hostname string than "localhost".
	connectURL := fmt.Sprintf("http://127.0.0.1:%d/", port)

	resp, err := http.Get(connectURL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// The body URL must use the same host (127.0.0.1:PORT) the client connected to.
	// If it instead uses "localhost:PORT" (the configured proxyAddr), the browser
	// would see a cross-origin link (different hostname) — this tests that the
	// effectiveProxyAddr context value overrides the configured proxyAddr.
	want := fmt.Sprintf("127.0.0.1:%d", port)
	if !strings.Contains(bodyStr, want) {
		t.Errorf("body URL should contain %q (effective client addr), got %q", want, bodyStr)
	}
	if strings.Contains(bodyStr, fmt.Sprintf("localhost:%d", port)) {
		t.Errorf("body URL leaked configured proxyAddr instead of effective client addr: %q", bodyStr)
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
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
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
// Location header is replaced with the proxy address when the upstream host is
// in the redirect target.
func TestProxyLocationHeaderMasking(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/old-path" {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "ok")
			return
		}
		// Redirect to /new-path on the same upstream host.
		// The proxy should follow this server-side and return the final 200 body.
		// The upstream host should not appear in the final response body.
		w.Header().Set("Location", "http://"+upstreamHost+"/new-path")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()
	upstreamHost = strings.TrimPrefix(upstream.URL, "http://")

	rep, _ := NewReplacer("", false)
	const proxyAddr = "proxy.local:8080"
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, proxyAddr, true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	// The redirect is followed server-side, so the client receives the 200 /new-path response.
	resp, err := ps.Client().Get(ps.URL + "/old-path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 after server-side redirect follow, got %d", resp.StatusCode)
	}
	// The upstream host must not leak in any response header.
	for name, vals := range resp.Header {
		for _, v := range vals {
			if strings.Contains(v, upstreamHost) {
				t.Errorf("response header %s leaks upstream host: %q", name, v)
			}
		}
	}
}

// TestProxyUserReplacementInLocationHeader verifies that user-defined alias
// replacements are applied to the path in Location headers after host-masking.
// Upstream redirects to its own host; the proxy masks the host and aliases the path.
func TestProxyUserReplacementInLocationHeader(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to an upstream URL containing the original keyword in the path.
		http.Redirect(w, r, "http://"+upstreamHost+"/ctf/dashboard", http.StatusFound)
	}))
	defer upstream.Close()
	upstreamHost = strings.TrimPrefix(upstream.URL, "http://")

	rep, _ := NewReplacer("ctf:acme", false)
	const proxyAddr = "proxy.local:8080"
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, proxyAddr, true, 0, testLogger(), nil, nil, 0, nil)
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

	// The redirect chain is followed server-side (same host) so the final
	// response arrives at /ctf/dashboard → another redirect → loop → last 302.
	// What matters is the Location path has the alias applied by ModifyResponse.
	loc := resp.Header.Get("Location")
	// The path "/ctf/dashboard" in the Location should be aliased to "/acme/dashboard".
	// The host portion should be masked to the proxy address.
	if !strings.Contains(loc, "/acme/dashboard") {
		t.Errorf("Location path not aliased: %q", loc)
	}
	if strings.Contains(loc, "/ctf/dashboard") {
		t.Errorf("Location path still has original keyword: %q", loc)
	}
}

// TestProxySubdomainUserReplaceAppliedInBody verifies the full pipeline:
// a subdomain URL encoded into /__sd__/ SHOULD have the user alias replacement
// applied so that the client-visible URL is consistent with the alias.
// The director's rep.ToOriginal restores the real host for routing.
func TestProxySubdomainUserReplaceAppliedInBody(t *testing.T) {
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
	proxy := NewReverseProxy(rootHost, "http", rep, false, proxyAddr, false, 0, testLogger(), nil, nil, 0, nil)
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

	// The /__sd__/ path SHOULD use the aliased hostname so URLs are consistent.
	// (The director restores the original hostname for routing via rep.ToOriginal.)
	if !strings.Contains(got, "/__sd__/pic.news.co.il/") {
		t.Errorf("/__sd__/ host not replaced with alias: %q", got)
	}
	if strings.Contains(got, "/__sd__/pic.ynet.co.il/") {
		t.Errorf("/__sd__/ path still uses original hostname: %q", got)
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
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, proxyAddr, true, 0, testLogger(), nil, nil, 0, nil)
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
// 'sha256-abc' is stripped (content rewriting invalidates the hash);
// 'unsafe-inline' already present so no duplicate is added.
want: "script-src 'self' 'nonce-abc123' 'unsafe-inline'",
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
{
name: "token with path rewritten (connect-src)",
in:   "connect-src https://api.microsoft.com/v2/*",
want: "connect-src http://localhost:9001",
},
{
name: "token with port and path rewritten",
in:   "connect-src https://api.microsoft.com:8443/v2/*",
want: "connect-src http://localhost:9001",
},
{
name: "ws scheme (plain WS) becomes ws://proxy",
in:   "connect-src ws://microsoft.com",
want: "connect-src ws://localhost:9001",
},
{
name: "trailing semicolon produces no empty directive",
in:   "default-src 'self'; script-src https://microsoft.com;",
want: "default-src 'self'; script-src http://localhost:9001",
},
{
name: "hash in script-src stripped and unsafe-inline added",
in:   "script-src 'sha256-abc123=' https://microsoft.com",
want: "script-src http://localhost:9001 'unsafe-inline'",
},
{
name: "sha384 and sha512 also stripped",
in:   "script-src 'sha256-abc=' 'sha384-xyz=' 'sha512-ZZZ='",
want: "script-src 'unsafe-inline'",
},
{
name: "hash in default-src stripped",
in:   "default-src 'sha256-abc=' 'self'",
want: "default-src 'self' 'unsafe-inline'",
},
{
name: "hash in style-src stripped",
in:   "style-src 'sha256-abc='",
want: "style-src 'unsafe-inline'",
},
{
name: "hash in non-content directive (img-src) preserved",
in:   "img-src 'sha256-abc='",
want: "img-src 'sha256-abc='",
},
{
name: "hash stripped + unsafe-inline already present = no duplicate",
in:   "script-src 'sha256-abc=' 'unsafe-inline'",
want: "script-src 'unsafe-inline'",
},
{
name: "frame-ancestors none dropped (consistent with X-Frame-Options stripping)",
in:   "default-src 'self'; frame-ancestors 'none'",
want: "default-src 'self'",
},
{
name: "frame-ancestors self preserved (allows proxy origin to frame)",
in:   "default-src 'self'; frame-ancestors 'self'",
want: "default-src 'self'; frame-ancestors 'self'",
},
{
name: "frame-ancestors upstream host rewritten to proxy",
in:   "frame-ancestors https://microsoft.com",
want: "frame-ancestors http://localhost:9001",
},
{
name: "strict-dynamic stripped when hashes are stripped",
in:   "script-src 'strict-dynamic' 'sha256-abc' 'nonce-xyz'",
want: "script-src 'nonce-xyz' 'unsafe-inline'",
},
{
name: "strict-dynamic stripped case-insensitive",
in:   "script-src 'STRICT-DYNAMIC' 'sha384-def'",
want: "script-src 'unsafe-inline'",
},
{
name: "strict-dynamic preserved when no hashes stripped",
in:   "script-src 'strict-dynamic' 'nonce-abc'",
want: "script-src 'strict-dynamic' 'nonce-abc'",
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
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, proxyAddr, true, 0, testLogger(), nil, nil, 0, nil)
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

// ─── -ignore-host ─────────────────────────────────────────────────────────────

// TestIgnoredHostResponseNotRewritten verifies that responses from an ignored
// host are NOT subject to string replacement or host masking in the body.
// Simulates the real-world case where a JS bundle contains "microsoft-graph"
// (an OAuth2 scope ID) that must not be corrupted by the replacement pairs.
func TestIgnoredHostResponseNotRewritten(t *testing.T) {
	const original = "microsoft"
	const alias = "msctf"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `const scope = "microsoft-graph"; const tenant = "microsoft.com";`)
	}))
	defer upstream.Close()
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	rep, _ := NewReplacer(original+":"+alias, true)
	ignored, _ := parseIgnoreHosts([]string{upstreamHost})
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, ignored, 0, nil)

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL + "/script.js")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// "microsoft-graph" and "microsoft.com" must be preserved verbatim.
	if strings.Contains(string(body), alias) {
		t.Errorf("ignored host body was rewritten: got %q, want original strings preserved", string(body))
	}
	if !strings.Contains(string(body), original) {
		t.Errorf("ignored host body: expected original string %q to be present, got %q", original, string(body))
	}
}

// TestIgnoredHostRequestNotRewritten verifies that outbound request paths are
// NOT alias-replaced when the destination is an ignored host.
func TestIgnoredHostRequestNotRewritten(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	rep, _ := NewReplacer("microsoft:msctf", true)
	ignored, _ := parseIgnoreHosts([]string{upstreamHost})
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, ignored, 0, nil)

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	// The alias "msctf" in the path must NOT be un-aliased to "microsoft"
	// when the destination host is ignored.
	http.Get(proxyServer.URL + "/msctf/token")

	if receivedPath != "/msctf/token" {
		t.Errorf("ignored host request path was rewritten: got %q, want /msctf/token", receivedPath)
	}
}

// TestNonIgnoredHostStillReplaces confirms the ignore list only suppresses
// rewriting on listed hosts; unlisted hosts are still fully rewritten.
func TestNonIgnoredHostStillReplaces(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<p>example content</p>`)
	}))
	defer upstream.Close()
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	rep, _ := NewReplacer("example:demo", true)
	// Ignore a different host — upstreamHost must still be rewritten.
	ignored := map[string]bool{"some.other.host.example.com": true}
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, ignored, 0, nil)

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(body), "demo") {
		t.Errorf("non-ignored host body not rewritten: got %q, want 'demo'", string(body))
	}
}

// TestIgnoredHostHSTSStillStripped verifies that HSTS is stripped even for
// ignored hosts (security-critical header removal always runs).
func TestIgnoredHostHSTSStillStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	rep, _ := NewReplacer("", true)
	ignored, _ := parseIgnoreHosts([]string{upstreamHost})
	proxy := NewReverseProxy(upstreamHost, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, ignored, 0, nil)

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS must be stripped even for ignored hosts, got %q", hsts)
	}
}

// TestParseIgnoreHosts verifies flag parsing and validation.
func TestParseIgnoreHosts(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		m, err := parseIgnoreHosts([]string{"login.microsoftonline.com"})
		if err != nil || !m["login.microsoftonline.com"] {
			t.Fatalf("basic: err=%v, map=%v", err, m)
		}
	})
	t.Run("comma-separated", func(t *testing.T) {
		m, err := parseIgnoreHosts([]string{"foo.com,bar.com"})
		if err != nil || !m["foo.com"] || !m["bar.com"] {
			t.Fatalf("comma-separated: err=%v, map=%v", err, m)
		}
	})
	t.Run("lowercased", func(t *testing.T) {
		m, err := parseIgnoreHosts([]string{"Login.MicrosoftOnline.Com"})
		if err != nil || !m["login.microsoftonline.com"] {
			t.Fatalf("lowercased: err=%v, map=%v", err, m)
		}
	})
	t.Run("rejects-scheme", func(t *testing.T) {
		if _, err := parseIgnoreHosts([]string{"https://foo.com"}); err == nil {
			t.Error("expected error for host with scheme")
		}
	})
	t.Run("rejects-path", func(t *testing.T) {
		if _, err := parseIgnoreHosts([]string{"foo.com/path"}); err == nil {
			t.Error("expected error for host with path")
		}
	})
	t.Run("nil-input", func(t *testing.T) {
		m, err := parseIgnoreHosts(nil)
		if err != nil || m != nil {
			t.Errorf("expected nil,nil; got %v,%v", m, err)
		}
	})
	t.Run("wildcard-stored-as-suffix", func(t *testing.T) {
		m, err := parseIgnoreHosts([]string{"*.bbci.co.uk"})
		if err != nil {
			t.Fatalf("wildcard: unexpected error: %v", err)
		}
		// Must be stored as ".bbci.co.uk" (dot prefix), not "*.bbci.co.uk".
		if !m[".bbci.co.uk"] {
			t.Errorf("wildcard key not found; map=%v", m)
		}
		if m["*.bbci.co.uk"] {
			t.Error("raw wildcard key must not be stored")
		}
	})
	t.Run("wildcard-mixed", func(t *testing.T) {
		m, err := parseIgnoreHosts([]string{"exact.com,*.cdn.example.com"})
		if err != nil {
			t.Fatalf("mixed: unexpected error: %v", err)
		}
		if !m["exact.com"] || !m[".cdn.example.com"] {
			t.Errorf("missing keys; map=%v", m)
		}
	})
}

// TestIsIgnoredHost unit-tests the isIgnoredHost helper directly.
func TestIsIgnoredHost(t *testing.T) {
	ignored := map[string]bool{
		"login.microsoftonline.com": true,
		"graph.microsoft.com":       true,
		".bbci.co.uk":               true, // wildcard suffix (*.bbci.co.uk)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"login.microsoftonline.com", true},
		{"login.microsoftonline.com:443", true},  // port must be stripped
		{"LOGIN.MicrosoftOnline.COM", true},       // case-insensitive lookup
		{"graph.microsoft.com", true},
		{"microsoft.com", false},                  // parent domain not ignored
		{"api.graph.microsoft.com", false},        // child subdomain not ignored
		{"evil.login.microsoftonline.com", false}, // prefix subdomain not ignored
		{"", false},                               // empty host is never ignored
		// Wildcard suffix tests
		{"news.bbci.co.uk", true},                // subdomain matches *.bbci.co.uk
		{"static.files.bbci.co.uk", true},        // deep subdomain matches *.bbci.co.uk
		{"STATIC.FILES.BBCI.CO.UK", true},        // wildcard match is case-insensitive
		{"bbci.co.uk", false},                    // apex itself does NOT match (wildcard, not exact)
		{"notbbci.co.uk", false},                 // different domain not matched
		{"evilbbci.co.uk", false},                // must not match bare suffix overlap
	}
	for _, c := range cases {
		got := isIgnoredHost(c.host, ignored)
		if got != c.want {
			t.Errorf("isIgnoredHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// ─── SVG body rewriting ───────────────────────────────────────────────────────

// TestSVGBodyRewrite verifies that image/svg+xml responses undergo host masking
// and user-string replacement, since SVG is a text/XML format.
//
// The upstream serves an SVG that references its own host (as would happen in a
// real site that embeds absolute self-references).  maskResponseString converts
// those upstream-host URLs to proxy-local ones, and the user alias replaces any
// remaining alias strings in the path.
func TestSVGBodyRewrite(t *testing.T) {
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Embed the upstream's own address as would happen with a real SVG asset.
		upHost := strings.TrimPrefix(upstream.URL, "http://")
		svgBody := `<svg xmlns="http://www.w3.org/2000/svg">` +
			`<image href="http://` + upHost + `/ctflogo.png"/>` +
			`<text>Plain ctf text</text>` +
			`</svg>`
		w.Header().Set("Content-Type", "image/svg+xml")
		fmt.Fprint(w, svgBody)
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false)
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", false, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := ps.Client().Get(ps.URL + "/logo.svg")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	body := string(got)

	// The upstream host URL must be rewritten to the proxy address.
	if strings.Contains(body, host) {
		t.Errorf("SVG body still contains upstream host %q:\n%s", host, body)
	}
	// The user alias "ctf"→"acme" must apply to text content (e.g. the image path).
	if strings.Contains(body, "ctflogo.png") {
		t.Errorf("SVG body path 'ctflogo.png' was not rewritten to 'acmelogo.png':\n%s", body)
	}
	if !strings.Contains(body, "acmelogo.png") {
		t.Errorf("SVG body missing expected 'acmelogo.png':\n%s", body)
	}
	// Plain text "ctf" inside SVG should also be replaced.
	if strings.Contains(body, "Plain ctf text") {
		t.Errorf("SVG text 'Plain ctf text' was not replaced:\n%s", body)
	}
	if !strings.Contains(body, "Plain acme text") {
		t.Errorf("SVG text missing 'Plain acme text':\n%s", body)
	}
}

// TestRequestBodyBinarySkip verifies that binary request bodies (e.g. image
// uploads) are forwarded to the upstream unchanged, even when replacement pairs
// are configured — corrupting binary data would break file uploads entirely.
func TestRequestBodyBinarySkip(t *testing.T) {
var capturedBody []byte

upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
capturedBody, _ = io.ReadAll(r.Body)
w.Header().Set("Content-Type", "text/plain")
fmt.Fprint(w, "ok")
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "http://")
rep, _ := NewReplacer("ctf:acme", false)
proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
ps := httptest.NewServer(proxy)
defer ps.Close()

// Construct a fake binary payload that contains "ctf" — it must NOT be replaced.
binaryPayload := []byte{0xFF, 0xD8, 0xFF, 'c', 't', 'f', 0x00, 0x42}
req, _ := http.NewRequest("POST", ps.URL+"/upload", bytes.NewReader(binaryPayload))
req.Header.Set("Content-Type", "image/jpeg")
resp, err := ps.Client().Do(req)
if err != nil {
t.Fatal(err)
}
resp.Body.Close()

if !bytes.Equal(capturedBody, binaryPayload) {
t.Errorf("binary request body was modified: got %v, want %v", capturedBody, binaryPayload)
}
}

// TestRequestBodySizeLimit verifies that a request body larger than maxBodyRewriteDefault
// is forwarded intact (not truncated) and does not panic or OOM.
func TestRequestBodySizeLimit(t *testing.T) {
var capturedLen int

upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
b, _ := io.ReadAll(r.Body)
capturedLen = len(b)
w.Header().Set("Content-Type", "text/plain")
fmt.Fprint(w, "ok")
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "http://")
rep, _ := NewReplacer("ctf:acme", false)
proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
ps := httptest.NewServer(proxy)
defer ps.Close()

// Build a body that exceeds maxBodyRewriteDefault (51 MiB of text that contains "ctf").
const overLimitBytes = maxBodyRewriteDefault + 1024
bigBody := strings.Repeat("ctf.", int(overLimitBytes)/4)
req, _ := http.NewRequest("POST", ps.URL+"/big", strings.NewReader(bigBody))
req.Header.Set("Content-Type", "text/plain")
resp, err := ps.Client().Do(req)
if err != nil {
t.Fatal(err)
}
resp.Body.Close()

if capturedLen != len(bigBody) {
t.Errorf("oversized body truncated: upstream received %d bytes, expected %d", capturedLen, len(bigBody))
}
}

// TestChunkedResponseBodyRewrite verifies that when an upstream sends a
// chunked-encoded response (Transfer-Encoding: chunked, no Content-Length),
// the proxy rewrites the body correctly and removes Transfer-Encoding so the
// browser receives a clean Content-Length response — not a malformed one with
// both headers where chunked would take precedence and corrupt the body.
func TestChunkedResponseBodyRewrite(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Del("Content-Length")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream ResponseWriter does not implement Flusher")
			return
		}
		fmt.Fprint(w, "<p>Hello from ctf challenge!</p>")
		flusher.Flush()
		fmt.Fprint(w, "<p>More ctf content</p>")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false)
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := ps.Client().Get(ps.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	body := string(got)

	// User replacement must have applied.
	if strings.Contains(body, "ctf") {
		t.Errorf("body still contains 'ctf': %s", body)
	}
	if !strings.Contains(body, "acme") {
		t.Errorf("body missing 'acme': %s", body)
	}
	// Transfer-Encoding must be removed since body is now fixed-length.
	if te := resp.Header.Get("Transfer-Encoding"); te != "" {
		t.Errorf("Transfer-Encoding header still present: %q", te)
	}
	// Content-Length must now be set.
	if cl := resp.Header.Get("Content-Length"); cl == "" {
		t.Error("Content-Length header missing after rewrite")
	}
}

// TestSubdomainLinkHeaderRewrite verifies that root-relative URLs in Link headers
// (e.g., </api/data>; rel=preload) from subdomain responses get prefixed with
// /__sd__/<host> so preload/prefetch hints don't escape the proxy context.
func TestSubdomainLinkHeaderRewrite(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `</api/data>; rel=preload, </fonts/x.woff2>; rel=preload; as=font`)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rootHost := "example.com"
	subHost := "api.example.com"

	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(rootHost, "http", rep, false, "localhost:8080", false, 0, testLogger(), nil, nil, 0, nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}

	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := ps.Client().Get(ps.URL + "/__sd__/" + subHost + "/page")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	link := resp.Header.Get("Link")
	if !strings.Contains(link, "</__sd__/"+subHost+"/api/data>") {
		t.Errorf("Link header missing rewritten /api/data: %q", link)
	}
	if !strings.Contains(link, "</__sd__/"+subHost+"/fonts/x.woff2>") {
		t.Errorf("Link header missing rewritten /fonts/x.woff2: %q", link)
	}
}

// TestSubdomainRefreshHeaderRewrite verifies that a root-relative Refresh header
// (format: "N; url=/path") from a subdomain response gets its url= part prefixed
// with /__sd__/<host> so timed redirects stay within the proxy's routing.
func TestSubdomainRefreshHeaderRewrite(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Refresh", "0; url=/login")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rootHost := "example.com"
	subHost := "api.example.com"

	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(rootHost, "http", rep, false, "localhost:8080", false, 0, testLogger(), nil, nil, 0, nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}

	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := ps.Client().Get(ps.URL + "/__sd__/" + subHost + "/page")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	refresh := resp.Header.Get("Refresh")
	expected := "0; url=/__sd__/" + subHost + "/login"
	if refresh != expected {
		t.Errorf("Refresh header = %q; want %q", refresh, expected)
	}
}

// TestMetaRefreshBodyRewrite verifies that <meta http-equiv="refresh"> with a
// root-relative url= in the body gets the url= path prefixed with /__sd__/<host>.
func TestMetaRefreshBodyRewrite(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><meta http-equiv="refresh" content="5; url=/dashboard"></head></html>`))
	}))
	defer upstream.Close()

	rootHost := "example.com"
	subHost := "api.example.com"

	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(rootHost, "http", rep, false, "localhost:8080", false, 0, testLogger(), nil, nil, 0, nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}

	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := ps.Client().Get(ps.URL + "/__sd__/" + subHost + "/page")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	expected := `content="5; url=/__sd__/` + subHost + `/dashboard"`
	if !strings.Contains(string(body), expected) {
		t.Errorf("body does not contain rewritten meta refresh\ngot:  %s\nwant: %s", string(body), expected)
	}
}

// TestSubdomainRedirectLocationRewrite verifies that a root-relative Location
// redirect from a subdomain response is prefixed with /__sd__/<host> so the
// browser stays within the proxy's routing rather than navigating to the main
// target root.
func TestSubdomainRedirectLocationRewrite(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}))
	defer upstream.Close()

	rootHost := "example.com"
	subHost := "api.example.com"

	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(rootHost, "http", rep, false, "localhost:8080", false, 0, testLogger(), nil, nil, 0, nil)
	// Route all connections to the test upstream regardless of requested host.
	proxy.Transport = &fixedHostTransport{upstream: upstream}

	ps := httptest.NewServer(proxy)
	defer ps.Close()

	client := ps.Client()
	// Disable redirect following so we can inspect the Location header.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Get(ps.URL + "/__sd__/" + subHost + "/page")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	expected := "/__sd__/" + subHost + "/dashboard"
	if loc != expected {
		t.Errorf("Location header = %q; want %q", loc, expected)
	}
}

// TestUnknownContentEncodingSkipsRewrite verifies that when an upstream sends
// a response with an unsupported Content-Encoding (e.g., br, zstd), the proxy
// forwards the body unchanged rather than applying string replacement to the
// compressed binary bytes, which would corrupt the response.
func TestUnknownContentEncodingSkipsRewrite(t *testing.T) {
	const fakeCompressed = "\x1b\x28\x00\x00\x18\x00\x00\x00\x00\x00" // fake brotli-like bytes
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "br")
		w.Write([]byte(fakeCompressed))
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false)
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := ps.Client().Get(ps.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Body must be forwarded byte-for-byte unchanged.
	if string(body) != fakeCompressed {
		t.Errorf("body was modified: got %d bytes, want %d bytes", len(body), len(fakeCompressed))
	}
	// Content-Encoding must still be present.
	if ce := resp.Header.Get("Content-Encoding"); ce != "br" {
		t.Errorf("Content-Encoding = %q; want %q", ce, "br")
	}
}

// TestDeflateResponseBodyRewrite verifies that deflate-encoded responses are
// correctly decompressed, string replacements applied, and Content-Encoding stripped.
// Both zlib-wrapped and raw-deflate variants are tested.
func TestDeflateResponseBodyRewrite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		encode func([]byte) []byte
	}{
		{
			name: "zlib-wrapped deflate",
			encode: func(plain []byte) []byte {
				var buf bytes.Buffer
				w := zlib.NewWriter(&buf)
				w.Write(plain)
				w.Close()
				return buf.Bytes()
			},
		},
		{
			name: "raw deflate (no zlib header)",
			encode: func(plain []byte) []byte {
				var buf bytes.Buffer
				w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
				w.Write(plain)
				w.Close()
				return buf.Bytes()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plainBody := "Welcome to ctf! Visit ctf.io for ctf challenges."
			compressed := tc.encode([]byte(plainBody))

			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Content-Encoding", "deflate")
				w.Write(compressed)
			}))
			defer upstream.Close()

			host := strings.TrimPrefix(upstream.URL, "http://")
			rep, _ := NewReplacer("ctf:acme", false)
			proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, nil, 0, nil)
			ps := httptest.NewServer(proxy)
			defer ps.Close()

			resp, err := ps.Client().Get(ps.URL + "/page")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			got := string(body)
			if strings.Contains(got, "ctf") {
				t.Errorf("replacements not applied; body still contains 'ctf': %q", got)
			}
			if !strings.Contains(got, "acme") {
				t.Errorf("replacements not applied; body missing 'acme': %q", got)
			}
			if ce := resp.Header.Get("Content-Encoding"); ce != "" {
				t.Errorf("Content-Encoding not stripped; got %q", ce)
			}
		})
	}
}

// TestDeflateOversizedBodyRestored verifies that when a deflate-encoded response
// body exceeds maxBodyBytes (set to 1 byte via -max-body 0 trick won't work;
// use a direct unit test instead), the original compressed bytes and
// Content-Encoding header are restored intact.
func TestDeflateOversizedBodyRestored(t *testing.T) {
plain := []byte("hello ctf world")

// Compress with zlib (deflate variant).
var compressed bytes.Buffer
zw := zlib.NewWriter(&compressed)
zw.Write(plain)
zw.Close()
compressedBytes := compressed.Bytes()

upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "text/html")
w.Header().Set("Content-Encoding", "deflate")
w.Write(compressedBytes)
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "http://")
rep, _ := NewReplacer("ctf:acme", false)
// Set maxBodyBytes to 1 so the body always exceeds the limit.
proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, nil, 1, nil)
ps := httptest.NewServer(proxy)
defer ps.Close()

resp, err := ps.Client().Get(ps.URL + "/page")
if err != nil {
t.Fatal(err)
}
defer resp.Body.Close()
body, _ := io.ReadAll(resp.Body)

// Content-Encoding must be restored.
if ce := resp.Header.Get("Content-Encoding"); ce != "deflate" {
t.Errorf("Content-Encoding = %q; want %q", ce, "deflate")
}
// Body must be the original compressed bytes (not decompressed, not modified).
if !bytes.Equal(body, compressedBytes) {
t.Errorf("body was not restored: got %d bytes, want %d bytes (original compressed)", len(body), len(compressedBytes))
}
}

// TestSSEPassthrough verifies that text/event-stream responses are not buffered:
// the proxy must pass the streaming body through without calling io.ReadAll.
func TestSSEPassthrough(t *testing.T) {
// Use a pipe so we control when the stream ends.
pr, pw := io.Pipe()
defer pw.Close()

upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "text/event-stream")
w.Header().Set("Cache-Control", "no-cache")
w.WriteHeader(http.StatusOK)
// Write one event and flush — client should see it without waiting for stream close.
fmt.Fprint(w, "data: hello ctf world\n\n")
if f, ok := w.(http.Flusher); ok {
f.Flush()
}
// Block until the test's pipe reader signals done.
io.Copy(io.Discard, pr)
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "http://")
rep, _ := NewReplacer("ctf:acme", false)
proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, nil, 0, nil)
ps := httptest.NewServer(proxy)
defer ps.Close()

resp, err := http.Get(ps.URL + "/events")
if err != nil {
t.Fatal(err)
}
defer resp.Body.Close()

// We must be able to read the first event immediately (no full-stream buffering).
buf := make([]byte, 256)
done := make(chan error, 1)
go func() {
n, err := resp.Body.Read(buf)
if err != nil && err != io.EOF {
done <- err
return
}
got := string(buf[:n])
if !strings.Contains(got, "data: hello ctf world") {
done <- fmt.Errorf("expected SSE event, got: %q", got)
return
}
done <- nil
}()

select {
case err := <-done:
if err != nil {
t.Fatal(err)
}
case <-time.After(3 * time.Second):
t.Fatal("SSE response timed out — proxy is buffering the entire stream")
}
// Close the pipe to let the upstream handler finish.
pw.Close()
}

// TestRemoveVaryAcceptEncoding verifies that Accept-Encoding is stripped from
// Vary after decompression while other Vary values are preserved.
func TestRemoveVaryAcceptEncoding(t *testing.T) {
cases := []struct {
desc   string
vary   []string // initial Vary header values
want   string   // expected Vary after removal ("" = header deleted)
}{
{"only Accept-Encoding", []string{"Accept-Encoding"}, ""},
{"Accept-Encoding with other", []string{"Accept-Encoding, Accept-Language"}, "Accept-Language"},
{"multiple values, one has AE", []string{"Accept-Language", "Accept-Encoding"}, "Accept-Language"},
{"no Vary header", nil, ""},
{"case-insensitive", []string{"accept-encoding"}, ""},
{"AE only with spaces", []string{" Accept-Encoding "}, ""},
}
for _, c := range cases {
t.Run(c.desc, func(t *testing.T) {
h := http.Header{}
for _, v := range c.vary {
h.Add("Vary", v)
}
removeVaryAcceptEncoding(h)
got := h.Get("Vary")
// Normalise: trim spaces for comparison.
got = strings.TrimSpace(got)
if got != c.want {
t.Errorf("got Vary=%q, want %q", got, c.want)
}
})
}
}

// TestVaryAcceptEncodingStrippedAfterDecompress verifies that a gzip response
// whose Vary header includes Accept-Encoding has that directive removed by the
// proxy after decompression (since the body is now identity-encoded).
func TestVaryAcceptEncodingStrippedAfterDecompress(t *testing.T) {
var buf bytes.Buffer
gz := gzip.NewWriter(&buf)
fmt.Fprint(gz, "hello world")
gz.Close()

upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Encoding", "gzip")
w.Header().Set("Vary", "Accept-Encoding, Accept-Language")
w.Header().Set("Content-Type", "text/plain")
w.Write(buf.Bytes())
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "http://")
rep, _ := NewReplacer("", false)
proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
ps := httptest.NewServer(proxy)
defer ps.Close()

resp, err := http.Get(ps.URL + "/")
if err != nil {
t.Fatal(err)
}
resp.Body.Close()

vary := resp.Header.Get("Vary")
if strings.Contains(strings.ToLower(vary), "accept-encoding") {
t.Errorf("Vary still contains Accept-Encoding after gzip decompression: %q", vary)
}
// Accept-Language must still be present.
if !strings.Contains(vary, "Accept-Language") {
t.Errorf("Vary lost Accept-Language: %q", vary)
}
// Content-Encoding must be gone.
if ce := resp.Header.Get("Content-Encoding"); ce != "" {
t.Errorf("Content-Encoding not stripped: %q", ce)
}
}

// TestSRIIntegrityStripped verifies that integrity attributes are removed from
// HTML responses so that Subresource Integrity checks don't block resources
// whose bytes have been modified by the proxy's string replacement.
func TestSRIIntegrityStripped(t *testing.T) {
	htmlBody := "<html><head>" +
		`<script src="/app.js" integrity="sha256-abc123" crossorigin="anonymous"></script>` +
		`<link rel="stylesheet" href="/style.css" integrity="sha384-xyz789">` +
		"<script src=\"/other.js\"></script>" +
		"</head></html>"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, htmlBody)
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp2, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	got, _ := io.ReadAll(resp2.Body)
	s := string(got)

	if strings.Contains(s, "integrity=") {
		t.Errorf("integrity attribute not stripped from HTML: %s", s)
	}
	// crossorigin and src should remain untouched.
	if !strings.Contains(s, `crossorigin="anonymous"`) {
		t.Errorf("crossorigin attribute unexpectedly removed: %s", s)
	}
	if !strings.Contains(s, `src="/app.js"`) {
		t.Errorf("src attribute unexpectedly removed: %s", s)
	}
}

// TestLinkHeaderIntegrityStripped verifies that the integrity parameter is
// removed from Link response headers so that browser preload SRI checks don't
// block resources whose bytes have been modified by the proxy.
func TestLinkHeaderIntegrityStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A typical preload Link header with integrity and crossorigin params.
		w.Header().Set("Link", `</app.js>; rel=preload; as=script; integrity=sha256-abc123; crossorigin=anonymous, </style.css>; rel=preload; as=style; integrity="sha384-xyz789"`)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html></html>")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	link := resp.Header.Get("Link")
	if strings.Contains(strings.ToLower(link), "integrity") {
		t.Errorf("integrity param not stripped from Link header: %q", link)
	}
	// rel=preload and crossorigin should remain.
	if !strings.Contains(link, "rel=preload") {
		t.Errorf("rel=preload unexpectedly removed from Link header: %q", link)
	}
	if !strings.Contains(link, "crossorigin=anonymous") {
		t.Errorf("crossorigin unexpectedly removed from Link header: %q", link)
	}
}

// TestServiceWorkerAllowedStripped verifies that Service-Worker-Allowed is
// removed from responses to prevent a SW from claiming the entire proxy origin.
func TestServiceWorkerAllowedStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Service-Worker-Allowed", "/")
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, "self.addEventListener('fetch', ()=>{})")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/sw.js")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if v := resp.Header.Get("Service-Worker-Allowed"); v != "" {
		t.Errorf("Service-Worker-Allowed not stripped: %q", v)
	}
}

// TestClearSiteDataStripped verifies that Clear-Site-Data is removed from
// responses.  Forwarding it would clear cookies/storage for ALL sites proxied
// through localhost:PORT, not just the one that sent the header.
func TestClearSiteDataStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Clear-Site-Data", `"cookies", "storage"`)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "logged out")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp2, err := http.Get(ps.URL + "/logout")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()

	if v := resp2.Header.Get("Clear-Site-Data"); v != "" {
		t.Errorf("Clear-Site-Data not stripped: %q", v)
	}
}

// TestPermissionsPolicyStripped verifies Permissions-Policy and Feature-Policy
// are stripped.  These restrict browser APIs for the proxy's entire localhost
// origin, affecting every site being proxied simultaneously.
func TestPermissionsPolicyStripped(t *testing.T) {
upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Permissions-Policy", "camera=(), microphone=()")
w.Header().Set("Feature-Policy", "vibrate 'none'")
w.Header().Set("Content-Type", "text/html")
fmt.Fprint(w, "<html></html>")
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "http://")
rep, _ := NewReplacer("", false)
proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
ps := httptest.NewServer(proxy)
defer ps.Close()

resp, err := http.Get(ps.URL + "/")
if err != nil {
t.Fatal(err)
}
resp.Body.Close()

if v := resp.Header.Get("Permissions-Policy"); v != "" {
t.Errorf("Permissions-Policy not stripped: %q", v)
}
if v := resp.Header.Get("Feature-Policy"); v != "" {
t.Errorf("Feature-Policy not stripped: %q", v)
}
}

// TestOriginAgentClusterStripped verifies Origin-Agent-Cluster is removed.
func TestOriginAgentClusterStripped(t *testing.T) {
upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Origin-Agent-Cluster", "?1")
w.Header().Set("Content-Type", "text/plain")
fmt.Fprint(w, "ok")
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "http://")
rep, _ := NewReplacer("", false)
proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
ps := httptest.NewServer(proxy)
defer ps.Close()

resp, err := http.Get(ps.URL + "/")
if err != nil {
t.Fatal(err)
}
resp.Body.Close()

if v := resp.Header.Get("Origin-Agent-Cluster"); v != "" {
t.Errorf("Origin-Agent-Cluster not stripped: %q", v)
}
}

// TestViaHeaderStripped verifies Via is removed from outbound requests and responses.
func TestViaHeaderStripped(t *testing.T) {
var sawVia string
upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
sawVia = r.Header.Get("Via")
w.Header().Set("Via", "1.1 cdn.example.com")
w.Header().Set("Content-Type", "text/plain")
fmt.Fprint(w, "ok")
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "http://")
rep, _ := NewReplacer("", false)
proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
ps := httptest.NewServer(proxy)
defer ps.Close()

req, _ := http.NewRequest("GET", ps.URL+"/", nil)
req.Header.Set("Via", "1.1 client-proxy")
resp, err := http.DefaultClient.Do(req)
if err != nil {
t.Fatal(err)
}
resp.Body.Close()

if sawVia != "" {
t.Errorf("Via forwarded to upstream: %q", sawVia)
}
if v := resp.Header.Get("Via"); v != "" {
t.Errorf("Via not stripped from response: %q", v)
}
}

// TestAltSvcStripped verifies Alt-Svc is removed.  If forwarded, the browser
// would connect directly to the upstream host using HTTP/3 or another protocol,
// bypassing the proxy entirely on subsequent requests.
func TestAltSvcStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", "h3=:443; ma=86400")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if v := resp.Header.Get("Alt-Svc"); v != "" {
		t.Errorf("Alt-Svc not stripped: %q", v)
	}
}

// TestXFrameOptionsStripped verifies X-Frame-Options is removed.  DENY or
// SAMEORIGIN would prevent the proxy from embedding subdomain pages in iframes
// within the proxy context.
func TestXFrameOptionsStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html></html>")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if v := resp.Header.Get("X-Frame-Options"); v != "" {
		t.Errorf("X-Frame-Options not stripped: %q", v)
	}
}

// TestSecFetchAndUpgradeInsecureStripped verifies that Sec-Fetch-* and
// Upgrade-Insecure-Requests headers are stripped from outbound requests.
// These describe the browser's security context relative to the proxy
// origin (localhost:PORT), not the upstream, and can mislead upstream CORS
// or security logic.
func TestSecFetchAndUpgradeInsecureStripped(t *testing.T) {
	var sawHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest("GET", ps.URL+"/", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	for _, hdr := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User", "Upgrade-Insecure-Requests"} {
		if v := sawHeaders.Get(hdr); v != "" {
			t.Errorf("%s forwarded to upstream: %q", hdr, v)
		}
	}
}

// TestSubdomainSPAScriptInjected verifies that a subdomain HTML response has
// the SPA pathname-patching <script> injected immediately after <head>.
// The script rewrites window.location.pathname to strip the /__sd__/<host>
// prefix so that SPA routers (Remix, React Router, Next.js) can match routes.
func TestSubdomainSPAScriptInjected(t *testing.T) {
	const subHost = "copilot.example.com"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!DOCTYPE html><html><head><title>App</title></head><body><h1>Hi</h1></body></html>")
	}))
	defer upstream.Close()

	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy("example.com", "http", rep, false, "localhost:9045", false, 0, testLogger(), nil, nil, 0, nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}

	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest("GET", ps.URL+"/__sd__/"+subHost+"/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "/__sd__/"+subHost) {
		t.Errorf("SPA script prefix not found in subdomain HTML response.\ngot:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "history.replaceState") {
		t.Errorf("history.replaceState not found in injected script:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "window.fetch") {
		t.Errorf("fetch patching not found in injected script:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "window.WebSocket") {
		t.Errorf("WebSocket patching not found in injected script:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "EventSource") {
		t.Errorf("EventSource patching not found in injected script:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "sendBeacon") {
		t.Errorf("sendBeacon patching not found in injected script:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, `'assign','replace'`) && !strings.Contains(bodyStr, `"assign","replace"`) {
		t.Errorf("location.assign/replace patching not found in injected script:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "serviceWorker") {
		t.Errorf("serviceWorker block not found in injected script:\n%s", bodyStr)
	}
}

// TestSubdomainSPAScriptNonceInjected verifies that when the page has existing
// <script nonce="..."> tags, the injected SPA script gets the same nonce so
// it is not blocked by nonce-based CSP policies.
func TestSubdomainSPAScriptNonceInjected(t *testing.T) {
	const subHost = "copilot.example.com"
	const testNonce = "abc123xyz"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>App</title></head><body>`+
			`<script nonce="%s">var x=1;</script></body></html>`, testNonce)
	}))
	defer upstream.Close()

	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy("example.com", "http", rep, false, "localhost:9047", false, 0, testLogger(), nil, nil, 0, nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}

	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest("GET", ps.URL+"/__sd__/"+subHost+"/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	bodyStr := string(body)
	wantNonce := `<script nonce="` + testNonce + `">`
	if !strings.Contains(bodyStr, wantNonce) {
		t.Errorf("SPA script missing nonce %q.\ngot:\n%s", testNonce, bodyStr)
	}
}

// TestSubdomainSPAScriptNotInjectedForMainTarget verifies that the SPA script
// is NOT injected for responses from the main target host.
func TestSubdomainSPAScriptNotInjectedForMainTarget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!DOCTYPE html><html><head><title>Main</title></head><body></body></html>")
	}))
	defer upstream.Close()

	mainHost := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(mainHost, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if strings.Contains(string(body), "history.replaceState") {
		t.Errorf("SPA script injected for main target response (should not be):\n%s", body)
	}
}

// TestAccessControlAllowOriginSubdomainNormalized verifies that
// Access-Control-Allow-Origin values rewritten by the subdomain rewriter
// are normalized to a bare origin (scheme+host+port), not a URL with a
// /__sd__/<host> path.  Without this fix the browser's CORS check fails
// because the header value wouldn't match the request's Origin.
func TestAccessControlAllowOriginSubdomainNormalized(t *testing.T) {
const apiHost = "api.example.com"
upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// Upstream reports that the API allows cross-origin requests from its
// own subdomain (e.g. the SPA lives on example.com and the API on
// api.example.com).
w.Header().Set("Access-Control-Allow-Origin", "https://"+apiHost)
w.Header().Set("Content-Type", "text/plain")
fmt.Fprint(w, "data")
}))
defer upstream.Close()

rep, _ := NewReplacer("", false)
proxy := NewReverseProxy("example.com", "http", rep, false, "localhost:9048", false, 0, testLogger(), nil, nil, 0, nil)
proxy.Transport = &fixedHostTransport{upstream: upstream}

ps := httptest.NewServer(proxy)
defer ps.Close()

req, _ := http.NewRequest("GET", ps.URL+"/__sd__/"+apiHost+"/data", nil)
resp, err := http.DefaultClient.Do(req)
if err != nil {
t.Fatalf("request failed: %v", err)
}
resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	// Must be a bare origin — no path or /__sd__/ component.
	if strings.Contains(acao, "/__sd__/") {
		t.Errorf("ACAO still contains /__sd__/ path (browser CORS would fail): %q", acao)
	}
	if strings.Contains(acao, apiHost) {
		t.Errorf("ACAO still contains upstream hostname %q: %q", apiHost, acao)
	}
	// Should be a bare origin (no path after scheme+host:port).
	withoutScheme := strings.TrimPrefix(acao, "http://")
	if strings.Contains(withoutScheme, "/") {
		t.Errorf("ACAO contains path component (not a bare origin): %q", acao)
	}
}

// TestBaseHrefSubdomainRewrite verifies that <base href> on subdomain pages
// is rewritten to point to /__sd__/<host>/ so relative URLs resolve correctly.
func TestBaseHrefSubdomainRewrite(t *testing.T) {
	const subHost = "assets.example.com"
	cases := []struct {
		name    string
		body    string
		wantPfx string
	}{
		{
			name:    "absolute proxy base",
			body:    `<html><head><base href="http://PROXYADDR/"></head></html>`,
			wantPfx: "/__sd__/" + subHost,
		},
		{
			name:    "root-relative slash",
			body:    `<html><head><base href="/"></head></html>`,
			wantPfx: "/__sd__/" + subHost,
		},
		{
			name:    "root-relative path",
			body:    `<html><head><base href="/app/"></head></html>`,
			wantPfx: "/__sd__/" + subHost + "/app/",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, tc.body)
			}))
			defer upstream.Close()
			rep, _ := NewReplacer("", false)
			proxy := NewReverseProxy("example.com", "http", rep, false, "localhost:9049", false, 0, testLogger(), nil, nil, 0, nil)
			proxy.Transport = &fixedHostTransport{upstream: upstream}
			ps := httptest.NewServer(proxy)
			defer ps.Close()
			req, _ := http.NewRequest("GET", ps.URL+"/__sd__/"+subHost+"/", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !strings.Contains(string(body), tc.wantPfx) {
				t.Errorf("base href missing %q; got: %s", tc.wantPfx, body)
			}
		})
	}
}

// TestSpeculationRulesStripped verifies that the Speculation-Rules and
// Document-Policy response headers are stripped unconditionally.
func TestSpeculationRulesStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Speculation-Rules", "/speculation-rules.json")
		w.Header().Set("Document-Policy", "document-write=?0")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>page</body></html>")
	}))
	defer upstream.Close()
	mainHost := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(mainHost, "http", rep, false, "", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()
	resp, err := http.Get(ps.URL + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if v := resp.Header.Get("Speculation-Rules"); v != "" {
		t.Errorf("Speculation-Rules not stripped: %q", v)
	}
	if v := resp.Header.Get("Document-Policy"); v != "" {
		t.Errorf("Document-Policy not stripped: %q", v)
	}
}

// TestManifestScopeSubdomainRewrite verifies that scope and start_url in a
// PWA manifest served from a subdomain page are prefixed with /__sd__/<host>/.
func TestManifestScopeSubdomainRewrite(t *testing.T) {
	const subHost = "app.example.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/manifest+json")
		fmt.Fprint(w, `{"name":"App","scope":"/","start_url":"/app/","display":"standalone"}`)
	}))
	defer upstream.Close()
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy("example.com", "http", rep, false, "localhost:9050", false, 0, testLogger(), nil, nil, 0, nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}
	ps := httptest.NewServer(proxy)
	defer ps.Close()
	req, _ := http.NewRequest("GET", ps.URL+"/__sd__/"+subHost+"/manifest.json", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(body)
	sdPfx := "/__sd__/" + subHost
	if !strings.Contains(bodyStr, `"scope":"`+sdPfx+`/"`) {
		t.Errorf("scope not rewritten; got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `"start_url":"`+sdPfx+`/app/"`) {
		t.Errorf("start_url not rewritten; got: %s", bodyStr)
	}
}

// TestImportMapSubdomainRewrite verifies that root-relative URL values inside
// a <script type="importmap"> block are prefixed with /__sd__/<host>/ on
// subdomain pages so ES module imports route to the correct upstream.
func TestImportMapSubdomainRewrite(t *testing.T) {
	const subHost = "app.example.com"
	const pageBody = `<!DOCTYPE html><html><head>` +
		`<script type="importmap">{"imports":{"/mod/a.js":"/mod/a.js","lodash":"/vendor/lodash.js"}}</script>` +
		`</head><body></body></html>`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, pageBody)
	}))
	defer upstream.Close()
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy("example.com", "http", rep, false, "localhost:9051", false, 0, testLogger(), nil, nil, 0, nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}
	ps := httptest.NewServer(proxy)
	defer ps.Close()
	req, _ := http.NewRequest("GET", ps.URL+"/__sd__/"+subHost+"/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	sdPfx := "/__sd__/" + subHost
	bs := string(respBody)
	if !strings.Contains(bs, sdPfx+"/mod/a.js") {
		t.Errorf("importmap /mod/a.js not rewritten; got:\n%s", bs)
	}
	if !strings.Contains(bs, sdPfx+"/vendor/lodash.js") {
		t.Errorf("importmap /vendor/lodash.js not rewritten; got:\n%s", bs)
	}
}

// TestCSPSandboxStripped verifies that the CSP sandbox directive is dropped
// by rewriteCSP so proxy-injected scripts can run on sandboxed pages.
func TestCSPSandboxStripped(t *testing.T) {
cases := []struct {
in   string
want string
desc string
}{
{
in:   "sandbox; script-src 'self'",
want: "script-src 'self'",
desc: "standalone sandbox",
},
{
in:   "script-src 'self'; sandbox allow-scripts; default-src 'none'",
want: "script-src 'self'; default-src 'none'",
desc: "sandbox with flags",
},
}
for _, tc := range cases {
got := rewriteCSP(tc.in, "example.com", "example.com", "localhost:9090")
if got != tc.want {
t.Errorf("rewriteCSP(%q) [%s]:\n got  %q\n want %q", tc.in, tc.desc, got, tc.want)
}
}
}

// TestSpeculationRulesSubdomainRewrite verifies that root-relative URL values
// inside <script type="speculationrules"> blocks are prefixed with /__sd__/<host>/
// on subdomain pages so Chrome's pre-fetch/pre-render targets route through the proxy.
func TestSpeculationRulesSubdomainRewrite(t *testing.T) {
	const subHost = "app.example.com"
	const pageBody = `<!DOCTYPE html><html><head>` +
		`<script type="speculationrules">{"prefetch":[{"source":"list","urls":["/page-a","/page-b"]}]}</script>` +
		`</head><body></body></html>`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, pageBody)
	}))
	defer upstream.Close()
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy("example.com", "http", rep, false, "localhost:9052", false, 0, testLogger(), nil, nil, 0, nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}
	ps := httptest.NewServer(proxy)
	defer ps.Close()
	req, _ := http.NewRequest("GET", ps.URL+"/__sd__/"+subHost+"/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	sdPfx := "/__sd__/" + subHost
	bs := string(respBody)
	if !strings.Contains(bs, sdPfx+"/page-a") {
		t.Errorf("speculationrules /page-a not rewritten; got:\n%s", bs)
	}
	if !strings.Contains(bs, sdPfx+"/page-b") {
		t.Errorf("speculationrules /page-b not rewritten; got:\n%s", bs)
	}
}

// TestToOriginalDiffEmptyReplacer verifies that ToOriginalDiff returns
// the input unchanged with count 0 when no pairs are configured.
func TestToOriginalDiffEmptyReplacer(t *testing.T) {
	r, _ := NewReplacer("", false)
	got, count := r.ToOriginalDiff("hello world")
	if got != "hello world" || count != 0 {
		t.Errorf("ToOriginalDiff on empty replacer: got %q, %d; want %q, 0", got, count, "hello world")
	}
}

// TestToAliasDiffEmptyReplacer verifies that ToAliasDiff returns
// the input unchanged with count 0 when no pairs are configured.
func TestToAliasDiffEmptyReplacer(t *testing.T) {
	r, _ := NewReplacer("", false)
	got, count := r.ToAliasDiff("hello world")
	if got != "hello world" || count != 0 {
		t.Errorf("ToAliasDiff on empty replacer: got %q, %d; want %q, 0", got, count, "hello world")
	}
}

// TestSubdomainSPAScriptSingleQuotedNonce verifies that when an HTML page uses a
// single-quoted nonce attribute (nonce='xyz'), the injected SPA script still
// picks up the nonce and applies it to the injected <script> tag.
func TestSubdomainSPAScriptSingleQuotedNonce(t *testing.T) {
	const subHost = "copilot.example.com"
	const testNonce = "sq123nonce"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// single-quoted nonce
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>App</title></head><body>`+
			`<script nonce='%s'>var x=1;</script></body></html>`, testNonce)
	}))
	defer upstream.Close()

	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy("example.com", "http", rep, false, "localhost:9048", false, 0, testLogger(), nil, nil, 0, nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest("GET", ps.URL+"/__sd__/"+subHost+"/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	wantNonce := `<script nonce="` + testNonce + `">`
	if !strings.Contains(string(body), wantNonce) {
		t.Errorf("SPA script missing single-quoted nonce %q in output:\n%s", testNonce, body)
	}
}

// TestGzipOversizedBodyForwarded verifies that a gzip-encoded response whose
// decompressed size exceeds maxBodyBytes is forwarded as the decompressed bytes
// (with Content-Encoding stripped) rather than truncated or dropped.
func TestGzipOversizedBodyForwarded(t *testing.T) {
	plain := []byte("hello ctf world")
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Write(plain)
	gz.Close()
	compressedBytes := compressed.Bytes()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(compressedBytes)
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false)
	// maxBodyBytes=1 forces the oversized path for any non-trivial body.
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, nil, 1, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := ps.Client().Get(ps.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Content-Encoding should already be stripped (gzip was decompressed before the limit check).
	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding = %q; want empty (gzip decompressed before limit)", ce)
	}
	// Body must be the first (maxBodyBytes+1) decompressed bytes — the gzip stream was
	// already decompressed and can't be re-compressed, so we forward the decompressed prefix.
	// With maxBodyBytes=1, LimitReader reads maxBodyBytes+1 = 2 bytes.
	want := plain[:2]
	if !bytes.Equal(body, want) {
		t.Errorf("gzip oversized: got %q; want first 2 bytes %q", body, want)
	}
}

// TestGzipDecodeFailurePassthrough verifies that when the proxy receives a
// response with Content-Encoding: gzip but an invalid (non-gzip) body, it
// logs the error and returns the response without attempting replacement.
func TestGzipDecodeFailurePassthrough(t *testing.T) {
	const badBody = "this is not gzip data at all"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		// Write invalid gzip bytes.
		fmt.Fprint(w, badBody)
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false)
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := ps.Client().Get(ps.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// The proxy must respond (not crash or hang).
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 passthrough on gzip error, got %d", resp.StatusCode)
	}
}

// TestLinkHeaderAlreadyPrefixedSkipped verifies that Link header values which
// already start with /__sd__/ are not double-prefixed, and that protocol-relative
// (//host/path) links are passed through unmodified.
func TestLinkHeaderAlreadyPrefixedSkipped(t *testing.T) {
	subHost := "api.example.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// already-prefixed link + protocol-relative link
		w.Header().Set("Link",
			`</__sd__/`+subHost+`/already>; rel=preload, `+
				`<//cdn.example.com/font.woff2>; rel=preload; as=font`)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy("example.com", "http", rep, false, "localhost:8080", false, 0, testLogger(), nil, nil, 0, nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := ps.Client().Get(ps.URL + "/__sd__/" + subHost + "/page")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	link := resp.Header.Get("Link")
	// Already-prefixed link must not be double-prefixed.
	if strings.Count(link, "/__sd__/"+subHost+"/already") != 1 {
		t.Errorf("already-prefixed link was double-prefixed: %q", link)
	}
	// Protocol-relative link must not be modified (no /__sd__/ prefix added).
	if strings.Contains(link, "/__sd__/") && strings.Contains(link, "//cdn.example.com") {
		t.Errorf("protocol-relative link was incorrectly prefixed: %q", link)
	}
}

// TestBaseHrefAlreadyPrefixedSkipped verifies that a <base href> which already
// contains /__sd__/ is left unmodified (no double-prefix).
func TestBaseHrefAlreadyPrefixedSkipped(t *testing.T) {
	const subHost = "assets.example.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><base href="/__sd__/%s/"></head></html>`, subHost)
	}))
	defer upstream.Close()

	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy("example.com", "http", rep, false, "localhost:9049", false, 0, testLogger(), nil, nil, 0, nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest("GET", ps.URL+"/__sd__/"+subHost+"/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// The /__sd__/assets.example.com/ prefix must appear exactly once.
	if count := strings.Count(string(body), "/__sd__/"+subHost+"/"); count != 1 {
		t.Errorf("base href /__sd__/ prefix count = %d; want 1\nbody: %s", count, body)
	}
}

// TestBaseHrefAbsoluteProxyURLRewritten verifies that when a subdomain page
// has <base href="http://upstream/"> — which maskResponseString rewrites to
// the proxy address — the base href is then updated to point to the subdomain
// proxy route instead of the proxy root.
func TestBaseHrefAbsoluteProxyURLRewritten(t *testing.T) {
	const subHost = "assets.example.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Use the upstream host in the base href — maskResponseString will rewrite
		// "example.com" → proxyAddr, then the base-href pass rewrites proxy root → subdomain route.
		fmt.Fprint(w, `<html><head><base href="http://example.com/"></head></html>`)
	}))
	defer upstream.Close()

	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy("example.com", "http", rep, false, "localhost:9049", false, 0, testLogger(), nil, nil, 0, nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest("GET", ps.URL+"/__sd__/"+subHost+"/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// After rewriting: base href should contain the subdomain prefix.
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "/__sd__/"+subHost) {
		t.Errorf("base href not rewritten to subdomain route; got:\n%s", bodyStr)
	}
}

// TestManifestAlreadyPrefixedSkipped verifies that a manifest root-relative
// path that already starts with /__sd__/ is not double-prefixed.
func TestManifestAlreadyPrefixedSkipped(t *testing.T) {
	const subHost = "app.example.com"
	const originalBody = `{"scope":"/__sd__/` + subHost + `/","start_url":"/__sd__/` + subHost + `/"}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/manifest+json")
		fmt.Fprint(w, originalBody)
	}))
	defer upstream.Close()

	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy("example.com", "http", rep, false, "localhost:9049", false, 0, testLogger(), nil, nil, 0, nil)
	proxy.Transport = &fixedHostTransport{upstream: upstream}
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	req, _ := http.NewRequest("GET", ps.URL+"/__sd__/"+subHost+"/manifest.json", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Already-prefixed paths must not be double-prefixed.
	// "/__sd__/app.example.com" should appear exactly twice (once per key).
	const sdPfx = "/__sd__/" + subHost
	count := strings.Count(string(body), sdPfx)
	if count != 2 {
		t.Errorf("expected exactly 2 occurrences of %q (no double-prefix), got %d; body: %s", sdPfx, count, body)
	}
}

// TestFollowTargetRedirects303PostToGet verifies that a 303 See Other redirect
// always follows with GET, regardless of the original request method.
func TestFollowTargetRedirects303PostToGet(t *testing.T) {
	var capturedMethod string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/submit":
			// 303 must always redirect with GET.
			w.Header().Set("Location", "http://"+r.Host+"/result")
			w.WriteHeader(http.StatusSeeOther)
		case "/result":
			capturedMethod = r.Method
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("", false)
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:9999", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	noRedirectClient := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest(http.MethodPost, ps.URL+"/submit", strings.NewReader("data"))
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 after 303, got %d", resp.StatusCode)
	}
	if capturedMethod != http.MethodGet {
		t.Errorf("303 must always use GET for redirect, got %q", capturedMethod)
	}
}

// TestDeflateDecodeFailurePassthrough verifies that when upstream sends
// Content-Encoding: deflate with bytes that begin with the zlib magic (0x78)
// but have an invalid checksum byte, the proxy falls back to returning the raw
// (undecoded) body instead of crashing.
func TestDeflateDecodeFailurePassthrough(t *testing.T) {
	// 0x78 triggers the zlib.NewReader path. Second byte 0x00 makes
	// (0x78*256 + 0x00) % 31 = 30 ≠ 0, so zlib.NewReader returns an error.
	badDeflate := []byte{0x78, 0x00, 0xff, 0xfe, 0xde, 0xad}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "deflate")
		w.Write(badDeflate)
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	rep, _ := NewReplacer("ctf:acme", false)
	proxy := NewReverseProxy(host, "http", rep, false, "localhost:8080", true, 0, testLogger(), nil, nil, 0, nil)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := ps.Client().Get(ps.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Must respond (not crash or hang).
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 passthrough on deflate error, got %d", resp.StatusCode)
	}
	// Body must be the raw (undecoded) bytes forwarded as-is.
	if !bytes.Equal(body, badDeflate) {
		t.Errorf("deflate failure: got %x; want raw %x", body, badDeflate)
	}
}

// TestAlsoProxyEmptyStringSkipped verifies that passing an empty string in the
// alsoProxy list does not panic and is silently skipped (the domain is not
// registered in alsoProxyDomains).
func TestAlsoProxyEmptyStringSkipped(t *testing.T) {
upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "text/plain")
fmt.Fprint(w, "ok")
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "http://")
rep, _ := NewReplacer("", false)
// Pass empty string and whitespace — both must be silently skipped.
proxy := NewReverseProxy(host, "http", rep, false, "localhost:9999", true, 0, testLogger(), nil, nil, 0, []string{"", "  ", "valid.com"})
ps := httptest.NewServer(proxy)
defer ps.Close()

resp, err := ps.Client().Get(ps.URL + "/")
if err != nil {
t.Fatal(err)
}
defer resp.Body.Close()
if resp.StatusCode != http.StatusOK {
t.Errorf("expected 200, got %d", resp.StatusCode)
}
}

// TestRawPathReplacement verifies that when a request has a non-empty RawPath
// (percent-encoded URL), the director applies alias→original replacement to
// both Path and RawPath.
func TestRawPathReplacement(t *testing.T) {
var capturedPath, capturedRawPath string
upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
capturedPath = r.URL.Path
capturedRawPath = r.URL.RawPath
w.WriteHeader(http.StatusOK)
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "http://")
rep, _ := NewReplacer("foo:bar", false)
proxy := NewReverseProxy(host, "http", rep, false, "localhost:9999", true, 0, testLogger(), nil, nil, 0, nil)
ps := httptest.NewServer(proxy)
defer ps.Close()

// Request with RawPath that contains the alias "bar" (→ should become "foo").
// Use a manually-crafted request so RawPath is set explicitly.
req, _ := http.NewRequest("GET", ps.URL+"/path/bar%2Fmore", nil)
resp, err := http.DefaultClient.Do(req)
if err != nil {
t.Fatal(err)
}
resp.Body.Close()

// "bar" is the alias for "foo" — ToOriginal("bar") = "foo".
if !strings.Contains(capturedPath, "foo") {
t.Errorf("Path not de-aliased: %q", capturedPath)
}
if capturedRawPath != "" && !strings.Contains(capturedRawPath, "foo") {
t.Errorf("RawPath not de-aliased: %q", capturedRawPath)
}
}

// TestInsecureTLSSkipsVerification verifies that when -skip-verify is set,
// the proxy connects to an upstream with a self-signed TLS certificate without
// returning an error (TLS certificate verification is skipped).
func TestInsecureTLSSkipsVerification(t *testing.T) {
upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "text/plain")
fmt.Fprint(w, "secure-ok")
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "https://")
rep, _ := NewReplacer("", false)
// insecure=true — must accept the self-signed test certificate.
proxy := NewReverseProxy(host, "https", rep, true, "localhost:9999", true, 0, testLogger(), nil, nil, 0, nil)
ps := httptest.NewServer(proxy)
defer ps.Close()

resp, err := ps.Client().Get(ps.URL + "/")
if err != nil {
t.Fatalf("expected no TLS error with insecure=true, got: %v", err)
}
defer resp.Body.Close()
body, _ := io.ReadAll(resp.Body)

if resp.StatusCode != http.StatusOK {
t.Errorf("expected 200, got %d", resp.StatusCode)
}
if string(body) != "secure-ok" {
t.Errorf("expected 'secure-ok', got %q", body)
}
}

// TestSecureTLSVerificationFails verifies that when insecure=false (default),
// connecting to an upstream with a self-signed certificate causes a 502.
func TestSecureTLSVerificationFails(t *testing.T) {
upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
fmt.Fprint(w, "should-not-reach")
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "https://")
rep, _ := NewReplacer("", false)
// insecure=false — TLS cert verification must reject the self-signed cert.
proxy := NewReverseProxy(host, "https", rep, false, "localhost:9999", true, 0, testLogger(), nil, nil, 0, nil)
ps := httptest.NewServer(proxy)
defer ps.Close()

resp, err := ps.Client().Get(ps.URL + "/")
if err != nil {
t.Fatal(err)
}
defer resp.Body.Close()
// Self-signed cert must cause a 502 Bad Gateway.
if resp.StatusCode != http.StatusBadGateway {
t.Errorf("expected 502 with TLS verification, got %d", resp.StatusCode)
}
}

// errorReader is an io.ReadCloser that returns an error after the first read.
type errorReader struct{ called bool }

func (e *errorReader) Read(p []byte) (int, error) {
if e.called {
return 0, fmt.Errorf("simulated read error")
}
e.called = true
return 0, fmt.Errorf("simulated read error")
}
func (e *errorReader) Close() error { return nil }

// TestRequestBodyReadFailure verifies that when reading the request body fails,
// the proxy still forwards the request upstream (with empty body) and logs the
// error rather than crashing or hanging.
func TestRequestBodyReadFailure(t *testing.T) {
var upstreamCalled bool
upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
upstreamCalled = true
w.Header().Set("Content-Type", "text/plain")
fmt.Fprint(w, "ok")
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "http://")
rep, _ := NewReplacer("foo:bar", false)
proxy := NewReverseProxy(host, "http", rep, false, "localhost:9999", true, 0, testLogger(), nil, nil, 0, nil)
ps := httptest.NewServer(proxy)
defer ps.Close()

// Craft a request with a body that immediately fails on Read.
req, _ := http.NewRequest(http.MethodPost, ps.URL+"/submit", &errorReader{})
req.Header.Set("Content-Type", "text/plain")
req.ContentLength = 10 // non-zero so director attempts to read body

resp, err := http.DefaultClient.Do(req)
if err != nil {
// A connection error is acceptable here since the body errors immediately.
return
}
defer resp.Body.Close()

// If the proxy responds at all, it must have called upstream and responded.
if !upstreamCalled {
t.Error("expected upstream to be called even on body read failure")
}
}

// TestWSLoggingConnReadWrite verifies that wsLoggingConn.Read and Write
// pass data through correctly and trigger frame-header logging.
func TestWSLoggingConnReadWrite(t *testing.T) {
var buf strings.Builder
lg := wsLogger(&buf)

// Build a simple WS text frame for the server→client direction.
serverFrame := buildWSTextFrame("hello")

pr, pw := io.Pipe()
conn := &wsLoggingConn{
rwc:    pipeRWC{pr, pw},
id:     1,
logger: lg,
}

// Write the frame into the pipe so Read can consume it.
go func() {
pw.Write(serverFrame)
pw.Close()
}()

received := make([]byte, len(serverFrame))
n, err := conn.Read(received)
if err != nil && err != io.EOF {
t.Fatalf("Read: unexpected error: %v", err)
}
if !bytes.Equal(received[:n], serverFrame) {
t.Errorf("Read: got %x; want %x", received[:n], serverFrame)
}

// Write direction: write a frame, it should pass through.
pr2, pw2 := io.Pipe()
conn2 := &wsLoggingConn{
rwc:    pipeRWC{pr2, pw2},
id:     2,
logger: lg,
}
clientFrame := buildWSTextFrame("world")
done := make(chan struct{})
go func() {
defer close(done)
got := make([]byte, len(clientFrame))
io.ReadFull(pr2, got)
}()
conn2.Write(clientFrame)
<-done

// Close: should not error.
if err := conn2.Close(); err != nil {
t.Errorf("Close: unexpected error: %v", err)
}
}

// TestNewReverseProxyWithWSLogging verifies that a proxy built with a logWS
// Logger wraps its transport with wsLoggingTransport (coverage for lines 1646-1648).
func TestNewReverseProxyWithWSLogging(t *testing.T) {
upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "text/plain")
fmt.Fprint(w, "ok")
}))
defer upstream.Close()

host := strings.TrimPrefix(upstream.URL, "http://")
rep, _ := NewReplacer("", false)
// Build a Logger with logWS=true to exercise the wsLoggingTransport wrapping path.
lg := &Logger{l: log.New(io.Discard, "", 0), logWS: true}
proxy := NewReverseProxy(host, "http", rep, false, "localhost:9999", true, 0, lg, nil, nil, 0, nil)
ps := httptest.NewServer(proxy)
defer ps.Close()

resp, err := ps.Client().Get(ps.URL + "/")
if err != nil {
t.Fatal(err)
}
defer resp.Body.Close()
if resp.StatusCode != http.StatusOK {
t.Errorf("expected 200, got %d", resp.StatusCode)
}
}

// TestVerboseLogRequestResponse verifies the verbose=true code paths in
// LogRequest and LogResponse, covering the header+body dump branches.
func TestVerboseLogRequestResponse(t *testing.T) {
var buf strings.Builder
lg := &Logger{l: log.New(&buf, "", 0), verbose: true}

// Craft a request with a sensitive header (should be redacted) and a normal one.
req, _ := http.NewRequest("GET", "http://example.com/path", nil)
req.Header.Set("Authorization", "Bearer secret")
req.Header.Set("X-Custom", "value")

start := lg.LogRequest(req, "request-body", false, 3)
if start.IsZero() {
t.Error("expected non-zero start time")
}
out := buf.String()
if !strings.Contains(out, "[redacted]") {
t.Errorf("expected Authorization header to be redacted; got: %q", out)
}
if !strings.Contains(out, "X-Custom: value") {
t.Errorf("expected X-Custom header; got: %q", out)
}
if !strings.Contains(out, "request-body") {
t.Errorf("expected body snapshot; got: %q", out)
}
if !strings.Contains(out, "[3 replaced]") {
t.Errorf("expected replacement count; got: %q", out)
}

// LogResponse verbose path: build a minimal *http.Response.
buf.Reset()
respReq, _ := http.NewRequest("GET", "http://example.com/path", nil)
resp := &http.Response{
StatusCode:    200,
ContentLength: -1,
Header:        http.Header{"Set-Cookie": []string{"sess=abc"}},
Request:       respReq,
}
lg.LogResponse(resp, "response-body", start, 2)
out = buf.String()
if !strings.Contains(out, "[redacted]") {
t.Errorf("expected Set-Cookie header to be redacted; got: %q", out)
}
if !strings.Contains(out, "response-body") {
t.Errorf("expected body snapshot in response; got: %q", out)
}
if !strings.Contains(out, "[2 replaced]") {
t.Errorf("expected replacement count in response; got: %q", out)
}
}

// TestBodyDumpTruncation verifies that bodyDump truncates long bodies.
func TestBodyDumpTruncation(t *testing.T) {
// Build a body larger than verboseBodyPreview (512 bytes).
longBody := strings.Repeat("x", verboseBodyPreview+100)
out := bodyDump("test", longBody)
if !strings.Contains(out, "truncated") {
t.Errorf("expected truncation notice; got: %q", out[:100])
}
if !strings.Contains(out, "100 bytes truncated") {
t.Errorf("expected 100 bytes truncated; got: %q", out[:200])
}
}

// TestBodyDumpEmpty verifies that bodyDump handles empty body.
func TestBodyDumpEmpty(t *testing.T) {
out := bodyDump("test", "")
if !strings.Contains(out, "empty") {
t.Errorf("expected empty body note; got: %q", out)
}
}

// TestVerboseLogRequestWSMethod verifies that WS requests show "WS↑" as method.
func TestVerboseLogRequestWSMethod(t *testing.T) {
var buf strings.Builder
lg := &Logger{l: log.New(&buf, "", 0), verbose: false}
req, _ := http.NewRequest("GET", "http://example.com/ws", nil)
lg.LogRequest(req, "", true, 0)
if !strings.Contains(buf.String(), "WS↑") {
t.Errorf("expected WS method; got: %q", buf.String())
}
}

// ─── logger helpers ───────────────────────────────────────────────────────────

// TestNewLoggerToFile verifies that NewLogger writes to a file when logPath
// is non-empty, and that the closer properly closes it.
func TestNewLoggerToFile(t *testing.T) {
tmp := t.TempDir()
path := filepath.Join(tmp, "proxy.log")
lg, closer, err := NewLogger(false, false, path)
if err != nil {
t.Fatalf("NewLogger: %v", err)
}
defer closer()
lg.Printf("hello logger")
closer() // flush/close

data, err := os.ReadFile(path)
if err != nil {
t.Fatalf("ReadFile: %v", err)
}
if !strings.Contains(string(data), "hello logger") {
t.Errorf("log file missing expected content; got: %q", string(data))
}
}

// TestNewLoggerBadPath verifies that NewLogger returns an error for an
// unwritable log path.
func TestNewLoggerBadPath(t *testing.T) {
_, _, err := NewLogger(false, false, "/nonexistent/dir/proxy.log")
if err == nil {
t.Error("expected error for bad logPath, got nil")
}
}

// TestHumanBytes verifies humanBytes for various magnitudes.
func TestHumanBytes(t *testing.T) {
tests := []struct {
n    int64
want string
}{
{0, "0 B"},
{512, "512 B"},
{1023, "1023 B"},
{1024, "1.0 KB"},
{1536, "1.5 KB"},
{1048576, "1.0 MB"},
{1073741824, "1.0 GB"},
}
for _, tc := range tests {
got := humanBytes(tc.n)
if got != tc.want {
t.Errorf("humanBytes(%d) = %q; want %q", tc.n, got, tc.want)
}
}
}

// ─── main.go helpers ──────────────────────────────────────────────────────────

// TestProxyAddr verifies proxyAddr normalises listener addresses.
func TestProxyAddr(t *testing.T) {
tests := []struct {
listen string
port   int
want   string
}{
{"0.0.0.0", 8080, "localhost:8080"},
{"::", 8080, "localhost:8080"},
{"", 9000, "localhost:9000"},
{"192.168.1.1", 9001, "192.168.1.1:9001"},
}
for _, tc := range tests {
got := proxyAddr(tc.listen, tc.port)
if got != tc.want {
t.Errorf("proxyAddr(%q, %d) = %q; want %q", tc.listen, tc.port, got, tc.want)
}
}
}

// TestParseHeadersValid verifies that well-formed header strings are accepted.
func TestParseHeadersValid(t *testing.T) {
pairs, err := parseHeaders([]string{"X-Custom: value", "Authorization: Bearer tok"})
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if len(pairs) != 2 {
t.Fatalf("expected 2 pairs, got %d", len(pairs))
}
if pairs[0].name != "X-Custom" || pairs[0].value != "value" {
t.Errorf("pair[0] wrong: %+v", pairs[0])
}
}

// TestParseHeadersErrors covers all validation branches.
func TestParseHeadersErrors(t *testing.T) {
tests := []struct {
input   string
errFrag string
}{
{"NoColon", "expected"},
{": emptyname", "empty"},
{"X-Header: ", "empty"},
{"X Header: val", "invalid character"},
{"X-Header: val\r\ninjected: x", "illegal CR or LF"},
{"Transfer-Encoding: chunked", "hop-by-hop"},
}
for _, tc := range tests {
_, err := parseHeaders([]string{tc.input})
if err == nil {
t.Errorf("%q: expected error, got nil", tc.input)
continue
}
if !strings.Contains(err.Error(), tc.errFrag) {
t.Errorf("%q: error %q doesn't contain %q", tc.input, err.Error(), tc.errFrag)
}
}
}

// TestParseIgnoreHostsValid verifies hostname normalisation and wildcard support.
func TestParseIgnoreHostsValid(t *testing.T) {
m, err := parseIgnoreHosts([]string{"Login.Microsoft.com", "*.bbci.co.uk", "host:443"})
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if !m["login.microsoft.com"] {
t.Error("expected login.microsoft.com")
}
if !m[".bbci.co.uk"] {
t.Error("expected .bbci.co.uk (wildcard)")
}
if !m["host"] {
t.Error("expected host (port stripped)")
}
}

// TestParseIgnoreHostsErrors covers validation error branches.
func TestParseIgnoreHostsErrors(t *testing.T) {
tests := []struct {
input   string
errFrag string
}{
{"https://example.com", "scheme"},
{"example.com/path", "hostname"},
}
for _, tc := range tests {
_, err := parseIgnoreHosts([]string{tc.input})
if err == nil {
t.Errorf("%q: expected error, got nil", tc.input)
continue
}
if !strings.Contains(err.Error(), tc.errFrag) {
t.Errorf("%q: error %q doesn't contain %q", tc.input, err.Error(), tc.errFrag)
}
}
}

// TestLoadReplaceFileValid verifies normal file parsing with comments and blanks.
func TestLoadReplaceFileValid(t *testing.T) {
tmp := t.TempDir()
f := filepath.Join(tmp, "pairs.txt")
os.WriteFile(f, []byte("# comment\nctf:acme\nctfd:foo\n\n"), 0o644)
got, err := loadReplaceFile(f)
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if got != "ctf:acme,ctfd:foo" {
t.Errorf("got %q; want %q", got, "ctf:acme,ctfd:foo")
}
}

// TestLoadReplaceFileInlineComment verifies inline '#' comment stripping.
func TestLoadReplaceFileInlineComment(t *testing.T) {
tmp := t.TempDir()
f := filepath.Join(tmp, "pairs.txt")
os.WriteFile(f, []byte("bbc:britcast # UK broadcaster\n"), 0o644)
got, err := loadReplaceFile(f)
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if got != "bbc:britcast" {
t.Errorf("got %q; want %q", got, "bbc:britcast")
}
}

// TestLoadReplaceFileMissing verifies error for non-existent file.
func TestLoadReplaceFileMissing(t *testing.T) {
_, err := loadReplaceFile("/nonexistent/path/pairs.txt")
if err == nil {
t.Error("expected error, got nil")
}
}

// TestLoadReplaceFileBadLine verifies error for malformed pair.
func TestLoadReplaceFileBadLine(t *testing.T) {
tmp := t.TempDir()
f := filepath.Join(tmp, "bad.txt")
os.WriteFile(f, []byte("nocolon\n"), 0o644)
_, err := loadReplaceFile(f)
if err == nil {
t.Error("expected error for invalid pair, got nil")
}
if !strings.Contains(err.Error(), "invalid pair") {
t.Errorf("error %q doesn't mention 'invalid pair'", err.Error())
}
}

// ─── flag types ───────────────────────────────────────────────────────────────

// TestHeaderFlagStringAndSet verifies the headerFlag custom flag type.
func TestHeaderFlagStringAndSet(t *testing.T) {
var f headerFlag
if f.String() != "" {
t.Errorf("empty String() should be empty, got %q", f.String())
}
if err := f.Set("X-Foo: bar"); err != nil {
t.Fatalf("Set: %v", err)
}
if err := f.Set("X-Baz: qux"); err != nil {
t.Fatalf("Set: %v", err)
}
if !strings.Contains(f.String(), "X-Foo: bar") {
t.Errorf("String() missing first entry: %q", f.String())
}
// Empty value should be rejected.
if err := f.Set("   "); err == nil {
t.Error("expected error for blank Set, got nil")
}
}

// TestIgnoreHostFlagStringAndSet verifies the ignoreHostFlag custom flag type.
func TestIgnoreHostFlagStringAndSet(t *testing.T) {
var f ignoreHostFlag
if f.String() != "" {
t.Errorf("empty String() should be empty, got %q", f.String())
}
if err := f.Set("example.com"); err != nil {
t.Fatalf("Set: %v", err)
}
if !strings.Contains(f.String(), "example.com") {
t.Errorf("String() missing entry: %q", f.String())
}
// Empty value should be rejected.
if err := f.Set(""); err == nil {
t.Error("expected error for empty Set, got nil")
}
}

// ─── logger Verbosef ──────────────────────────────────────────────────────────

// TestVerbosefOnlyLogsWhenVerbose verifies that Verbosef is a no-op when
// verbose=false and logs when verbose=true.
func TestVerbosefOnlyLogsWhenVerbose(t *testing.T) {
var buf strings.Builder
lg := &Logger{l: log.New(&buf, "", 0), verbose: false}
lg.Verbosef("should not appear")
if buf.Len() > 0 {
t.Errorf("expected no output when verbose=false; got %q", buf.String())
}

buf.Reset()
lg.verbose = true
lg.Verbosef("should appear: %d", 42)
if !strings.Contains(buf.String(), "should appear: 42") {
t.Errorf("expected verbose output; got %q", buf.String())
}
}
