package main

import (
	"compress/gzip"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// absURLRe matches absolute and protocol-relative URLs (used to protect
// external links from being corrupted by user-defined string replacements).
var absURLRe = regexp.MustCompile(`(?:https?:)?//[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}[^\s"'<>\x00-\x1F]*`)

// subdomainPathRe matches an already-encoded /__sd__/<host>[/...] segment.
// Used to temporarily shield these from the bare targetHost scan in
// maskResponseString so that "github.com" inside "/__sd__/api.github.com/"
// is not corrupted into "/__sd__/api.localhost:8081/".
var subdomainPathRe = regexp.MustCompile(`/__sd__/[^\s"'<>\x00-\x1F]+`)

// maxBodyRewrite is the maximum response body size (in bytes) that will be
// buffered and rewritten. Responses larger than this are forwarded unchanged to
// prevent out-of-memory conditions when proxying large file downloads.
const maxBodyRewrite = 50 * 1024 * 1024 // 50 MiB

// subdomainPrefix is the URL path prefix used to encode subdomain routing.
// When the response masker rewrites "https://assets.example.com/foo.js" to a
// proxy-local URL, it uses this prefix to preserve the original subdomain:
//
//	"https://assets.example.com/foo.js" → "http://localhost:PORT/__sd__/assets.example.com/foo.js"
//
// The director then detects this prefix, extracts the original host, and routes
// the outbound request to the correct upstream subdomain instead of the default
// target host.
const subdomainPrefix = "/__sd__/"

// headersSkipRewrite is the set of response headers managed explicitly by the
// proxy that must not be touched by the generic header-rewrite loop.
var headersSkipRewrite = map[string]bool{
	"Content-Length":    true,
	"Content-Encoding":  true,
	"Transfer-Encoding": true,
	"Set-Cookie":        true, // handled by rewriteSetCookies
}

// headersStrip is the set of response headers that must be removed entirely.
// These headers are either tied to the upstream origin (CSP, HSTS) and would
// break the proxy, or expose security metadata the masking proxy must hide.
var headersStrip = map[string]bool{
	"Content-Security-Policy":            true, // domain-pinned; breaks when origin changes to localhost
	"Content-Security-Policy-Report-Only": true,
	"Strict-Transport-Security":          true, // HSTS on plain-HTTP proxy confuses browsers
	"Public-Key-Pins":                    true,
	"Public-Key-Pins-Report-Only":        true,
	"Expect-CT":                          true,
}

// textContentTypes lists MIME type prefixes for which body replacement is safe.
// Binary formats (images, audio, video, archives) are intentionally excluded to
// avoid corrupting them.
var textContentTypes = []string{
	"text/",
	"application/json",
	"application/xml",
	"application/xhtml",
	"application/javascript",
	"application/x-www-form-urlencoded",
	"application/x-javascript",
	"application/ld+json",
	"application/graphql",
}

// withExternalURLsProtected applies fn to s while shielding any absolute URLs
// that do NOT point to the proxy itself (external / third-party CDN URLs) from
// modification.  This prevents third-party CDN hostnames that happen to contain
// the user's search string (e.g. "ynet-pic1.yit.co.il") from being silently
// broken by user-defined string replacements.
//
// proxyBase is the scheme+host prefix of the proxy (e.g. "http://localhost:8081").
// URLs starting with proxyBase are NOT protected so user replacements still apply
// to proxy-local paths (e.g. "/ctf/page" → "/acme/page").
// When proxyBase is "" (host masking disabled), all absolute URLs are protected.
//
// Mechanism: each protected URL is temporarily replaced with a NUL-delimited
// numeric placeholder, fn is applied to the surrounding text, and then every
// placeholder is swapped back to the original URL.
func withExternalURLsProtected(s, proxyBase string, fn func(string) string) string {
	type entry struct{ placeholder, original string }
	var saved []entry
	result := absURLRe.ReplaceAllStringFunc(s, func(u string) string {
		// Keep proxy-local URLs unprotected so their paths are still rewritten.
		// Check both "http://host" and "//host" (protocol-relative) forms.
		if proxyBase != "" {
			proxyRel := "//" + strings.TrimPrefix(proxyBase, "http://")
			if strings.HasPrefix(u, proxyBase) || strings.HasPrefix(u, proxyRel) {
				return u
			}
		}
		ph := "\x00" + strconv.Itoa(len(saved)) + "\x00"
		saved = append(saved, entry{ph, u})
		return ph
	})
	result = fn(result)
	for _, e := range saved {
		result = strings.Replace(result, e.placeholder, e.original, 1)
	}
	return result
}

func isTextContent(contentType string) bool {
	ct := strings.ToLower(strings.SplitN(contentType, ";", 2)[0])
	ct = strings.TrimSpace(ct)
	for _, prefix := range textContentTypes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}

// rewriteSetCookies fixes Set-Cookie response headers so they work through the
// proxy, which the browser sees as a plain-HTTP localhost server:
//
//   - Domain attribute: cleared so the browser scopes the cookie to whatever
//     host it actually sees (the proxy), not the upstream hostname.
//
//   - Secure flag: removed when the proxy listens on plain HTTP.  Browsers
//     refuse to send Secure cookies over non-HTTPS connections, which would
//     silently break any session-based flow.
//
//   - SameSite=None: downgraded to SameSite=Lax when Secure is removed.
//     SameSite=None is only valid together with Secure; browsers ignore or
//     reject the cookie otherwise.
//
// This must run unconditionally — every response can carry Set-Cookie, not
// just text responses.
func rewriteSetCookies(resp *http.Response, proxyIsHTTPS bool) {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}
	// Replace all Set-Cookie headers with the rewritten versions.
	resp.Header.Del("Set-Cookie")
	for _, c := range cookies {
		// Clear Domain: let the browser default to the serving host (the proxy).
		c.Domain = ""
		if !proxyIsHTTPS {
			c.Secure = false
			// SameSite=None without Secure is rejected by browsers; downgrade.
			if c.SameSite == http.SameSiteNoneMode {
				c.SameSite = http.SameSiteLaxMode
			}
		}
		resp.Header.Add("Set-Cookie", c.String())
	}
}

// computeRootDomain strips the leading hostname label from host so that
// the organisational / registrable domain is returned.  This is used to
// identify all subdomains that belong to the same site.
//
// Examples:
//
//	"www.ynet.co.il"  → "ynet.co.il"
//	"app.logz.io"     → "logz.io"
//	"en.wikipedia.org" → "wikipedia.org"
//	"github.com"       → "github.com"   (two labels, nothing to strip)
//
// The heuristic strips the first dot-separated label when there are three or
// more labels.  This is correct for all common TLDs and even for two-label
// ccTLD suffixes such as .co.il or .co.uk (e.g. www.ynet.co.il → ynet.co.il).
// A full Public Suffix List would be more precise but adds unnecessary weight.
// IP addresses (IPv4 and IPv6) are returned unchanged.
func computeRootDomain(host string) string {
	// Strip port if present (e.g. "www.example.com:8443").
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	// IP addresses have no domain hierarchy — return as-is.
	if net.ParseIP(host) != nil {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host // e.g. "github.com" — nothing to strip
	}
	return strings.Join(parts[1:], ".")
}

// maskResponseString rewrites s from an upstream response so that the upstream
// host is invisible to the client.  Substitutions are applied in order:
//
//  1. When subdomainRe is non-nil (default, subdomain masking enabled):
//     "https://sub.rootDomain/…" and "//sub.rootDomain/…" → "http://proxyAddr/…"
//     This hides any subdomain of the target (api.*, cdn.*, auth.*, …).
//     Must run BEFORE the bare targetHost scan (step 4) so that, for 2-label
//     targets like "github.com", the bare replacement doesn't corrupt
//     "api.github.com" into "api.localhost:8081" before the regex fires.
//
//  2. "https://targetHost" → "http://proxyAddr"  (absolute HTTPS URLs)
//
//  3. "http://targetHost"  → "http://proxyAddr"  (absolute HTTP URLs)
//
//  4. bare "targetHost"    → proxyAddr           (hostname-only references, e.g.
//     Set-Cookie Domain, Location without scheme, or plain text mentions)
//
//  5. When rootDomain differs from targetHost (e.g. targetHost="www.bbc.com",
//     rootDomain="bbc.com"): also rewrite "https://rootDomain" and
//     "http://rootDomain" so that canonical URLs like https://bbc.com/ don't leak.
//
// This MUST run before user-supplied replacements.  If the user has -replace
// ctf:acme, then "ctf.io" would become "acme.io" before we can substitute it
// with "localhost:8080", leaving the upstream hostname partially visible.
func maskResponseString(s, targetHost, rootDomain, proxyAddr string, subdomainRe *regexp.Regexp) string {
	if proxyAddr == "" {
		return s
	}
	proxyBase := "http://" + proxyAddr

	// Step 1: rewrite subdomain URLs first (before the bare targetHost scan).
	// Must run before steps 2-4 to prevent the bare "github.com" replacement from
	// corrupting "api.github.com" into "api.localhost:8081" before the regex fires.
	//
	// The original subdomain host is preserved in the proxy URL via subdomainPrefix
	// so that the director can route the request to the correct upstream host:
	//   "https://assets.example.com/foo.js"
	//   → "http://localhost:PORT/__sd__/assets.example.com/foo.js"
	//
	// Exception: if the matched host equals targetHost (e.g. the subdomainRe
	// matches "www.example.com" for targetHost="www.example.com"), fall back to
	// the plain proxy-base rewrite — no /__sd__/ prefix needed.
	//
	// Group 1 = scheme+host, Group 2 = boundary character — restore group 2.
	if subdomainRe != nil {
		s = subdomainRe.ReplaceAllStringFunc(s, func(match string) string {
			sub := subdomainRe.FindStringSubmatch(match)
			if len(sub) < 3 {
				return match
			}
			// Extract just the hostname from sub[1] (strips leading "https:" or "").
			hostStr := sub[1]
			if idx := strings.Index(hostStr, "//"); idx >= 0 {
				hostStr = hostStr[idx+2:]
			}
			// If the matched host IS the target itself (e.g. www.example.com), rewrite
			// without the subdomain prefix — the director already knows where to send it.
			if strings.EqualFold(hostStr, targetHost) {
				return proxyBase + sub[2]
			}
			return proxyBase + subdomainPrefix + hostStr + sub[2]
		})
	}

	// Protect already-encoded /__sd__/<host> segments from steps 2-5.
	// Without protection, a 2-label targetHost like "github.com" would corrupt
	// "/__sd__/api.github.com/" into "/__sd__/api.localhost:8081/" during the
	// bare targetHost scan below.
	type sdEntry struct{ ph, orig string }
	var sdSaved []sdEntry
	s = subdomainPathRe.ReplaceAllStringFunc(s, func(m string) string {
		ph := "\x01\x02" + strconv.Itoa(len(sdSaved)) + "\x01\x02"
		sdSaved = append(sdSaved, sdEntry{ph, m})
		return ph
	})

	// Steps 2-4: rewrite the exact target host in scheme+host and bare forms.
	s = strings.ReplaceAll(s, "https://"+targetHost, proxyBase)
	s = strings.ReplaceAll(s, "http://"+targetHost, proxyBase)
	s = strings.ReplaceAll(s, targetHost, proxyAddr)

	// Step 5: also mask the bare root domain when it differs from targetHost.
	// e.g. target="www.bbc.com" but upstream emits canonical "https://bbc.com/".
	if rootDomain != "" && rootDomain != targetHost {
		s = strings.ReplaceAll(s, "https://"+rootDomain, proxyBase)
		s = strings.ReplaceAll(s, "http://"+rootDomain, proxyBase)
		// Do NOT do a bare rootDomain scan here — "bbc.com" appears legitimately
		// in third-party tracker query params (utm_source=bbc.com) and replacing
		// it blindly would corrupt those partner URLs.
	}

	// Restore /__sd__/<host> segments after the bare scans are done.
	for _, e := range sdSaved {
		s = strings.Replace(s, e.ph, e.orig, 1)
	}

	return s
}

// unmaskRequestString is the reverse of maskResponseString: it rewrites s from
// an outbound request so that proxy-address references become the upstream host.
// This MUST run after user-supplied replacements (which convert aliases to
// originals) so that the final header/body value is fully upstream-native.
func unmaskRequestString(s, targetHost, scheme, proxyAddr string) string {
	if proxyAddr == "" {
		return s
	}
	upstreamBase := scheme + "://" + targetHost
	s = strings.ReplaceAll(s, "http://"+proxyAddr, upstreamBase)
	s = strings.ReplaceAll(s, proxyAddr, targetHost)
	return s
}

// NewReverseProxy builds an httputil.ReverseProxy that fully masks the upstream
// from the client:
//
//   - Outbound requests: aliases → originals; proxy address → upstream host.
//   - Inbound responses: upstream host → proxy address; originals → aliases.
//   - Set-Cookie headers rewritten so cookies work on the proxy's localhost origin.
//   - TLS certificate verification optionally skipped (insecure=true).
//
// proxyAddr is the host:port that clients use to reach this proxy (e.g.
// "localhost:8080").  It drives the automatic host-masking rewrites.
// Pass "" to disable host masking (useful in unit tests).
//
// When exactDomain is false (the default), every subdomain of the target's
// root domain (e.g. api.ynet.co.il, cdn.ynet.co.il) is also rewritten to the
// proxy address so no subdomain leaks to the client.  Set exactDomain=true to
// restrict masking to the exact target host only.
func NewReverseProxy(targetHost, scheme string, rep *Replacer, insecure bool, proxyAddr string, exactDomain bool) *httputil.ReverseProxy {
	target := &url.URL{Scheme: scheme, Host: targetHost}

	// Build a single regex that matches the scheme+host prefix of any subdomain
	// of the target's root domain, so we can rewrite those to the proxy address.
	// E.g. for targetHost="www.ynet.co.il", root="ynet.co.il", the regex matches:
	//   "https://api.ynet.co.il"  "http://cdn.ynet.co.il"  "//auth.ynet.co.il"
	//
	// For 2-label targets like "github.com", root == targetHost, so there is no
	// subdomain label to strip — but we still need to catch "api.github.com" etc.
	// The regex handles both cases:
	//   - 3-label target "www.ynet.co.il": root="ynet.co.il", matches "//ynet.co.il"
	//     and "//cdn.ynet.co.il" (zero-or-more prefix labels).
	//   - 2-label target "github.com":     root="github.com",  matches "//api.github.com"
	//     (one-or-more prefix labels).  Bare "//github.com" is handled by the
	//     literal targetHost replacement in maskResponseString so no double work.
	//
	// Domain-boundary guard: the capture group wraps the host match; a second group
	// captures the first character AFTER the host (path separator, quote, whitespace,
	// or end-of-string).  ReplaceAllStringFunc restores that trailing character so
	// only the exact host—and not a host that merely starts with the root domain
	// (e.g. "//sub.ynet.co.il.evil.com")—is rewritten.
	var subdomainRe *regexp.Regexp
	rootDomain := computeRootDomain(targetHost)
	if !exactDomain && proxyAddr != "" {
		// Build pattern with a mandatory domain-boundary assertion.
		// Group 1 = scheme+host, Group 2 = the character that terminates the host.
		subdomainRe = regexp.MustCompile(
			`(?i)((?:https?:)?//(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+` +
				regexp.QuoteMeta(rootDomain) +
				`)([/?#"'\s\x00]|$)`,
		)
	}

	// Clone DefaultTransport to preserve connection-pooling and timeout settings,
	// then override TLS config when certificate verification must be skipped.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // intentional for CTF
		log.Printf("maskproxy: WARNING — TLS certificate verification disabled (-skip-verify)")
	}

	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		// Set Host header explicitly so the upstream server receives the correct
		// virtual-host name, not "localhost:PORT".
		req.Host = targetHost

		// Rewrite URL path and query: client aliases → server originals.
		if rep.HasPairs() {
			req.URL.Path = rep.ToOriginal(req.URL.Path)
			if req.URL.RawPath != "" {
				req.URL.RawPath = rep.ToOriginal(req.URL.RawPath)
			}
			if req.URL.RawQuery != "" {
				req.URL.RawQuery = rep.ToOriginal(req.URL.RawQuery)
			}
		}

		// Subdomain routing: if the path starts with subdomainPrefix, the request
		// was originally destined for a subdomain of the target root domain.
		// Extract the encoded host and route to it instead of the main target.
		//
		//   "/__sd__/assets.example.com/foo.js" → GET /foo.js to assets.example.com
		//   "/__sd__/api.example.com/v2/data"   → GET /v2/data to api.example.com
		if strings.HasPrefix(req.URL.Path, subdomainPrefix) {
			rest := req.URL.Path[len(subdomainPrefix):]
			subHost := rest
			subPath := "/"
			if i := strings.Index(rest, "/"); i >= 0 {
				subHost = rest[:i]
				subPath = rest[i:]
			}
			req.URL.Host = subHost
			req.Host = subHost
			req.URL.Path = subPath
			// Clear RawPath to avoid inconsistency; it will be recomputed if needed.
			req.URL.RawPath = ""
		}

		// Rewrite request headers in a single pass:
		//   1. User replacements (alias → original), e.g. /acme/page → /ctf/page
		//   2. Reverse host masking (proxy addr → upstream host), e.g.
		//      Referer: http://localhost:8080/... → https://ctf.io/...
		// Use req.Host (which may have been updated for subdomain requests) as the
		// upstream hostname so Referer and Origin headers are rewritten correctly.
		// Order matters: user replacements first so the reverse-mask step sees
		// fully-original values when looking for the proxy address.
		outboundHost := req.Host
		for key, vals := range req.Header {
			for i, v := range vals {
				if rep.HasPairs() {
					v = rep.ToOriginal(v)
				}
				v = unmaskRequestString(v, outboundHost, scheme, proxyAddr)
				req.Header[key][i] = v
			}
		}

		// Same two-pass rewrite for the request body (e.g. form POST, JSON).
		if req.Body != nil {
			body, err := io.ReadAll(req.Body)
			req.Body.Close()
			if err == nil {
				rewritten := string(body)
				if rep.HasPairs() {
					rewritten = rep.ToOriginal(rewritten)
				}
				rewritten = unmaskRequestString(rewritten, outboundHost, scheme, proxyAddr)
				req.Body = io.NopCloser(strings.NewReader(rewritten))
				req.ContentLength = int64(len(rewritten))
			}
		}

		// Limit accepted encodings to what we can transparently decompress.
		// Other encodings (brotli, zstd) that Go stdlib cannot decode natively
		// would reach ModifyResponse compressed and corrupt after string replacement.
		req.Header.Del("Accept-Encoding")
		req.Header.Add("Accept-Encoding", "gzip, identity")

		// Strip client-supplied X-Forwarded-For to prevent header injection.
		req.Header.Del("X-Forwarded-For")
	}

	modifyResponse := func(resp *http.Response) error {
		// ── Phase 1: header rewrites — run on EVERY response ─────────────────
		// Redirects (301/302/307/308) and non-text assets can carry headers that
		// leak the upstream hostname.  These must be rewritten unconditionally
		// regardless of Content-Type so the browser never escapes the proxy.

		// Set-Cookie: clear Domain, remove Secure/SameSite=None for plain-HTTP.
		rewriteSetCookies(resp, false /* proxy listens on plain HTTP */)

		// Strip headers that are tied to the upstream origin and would break
		// the proxy (CSP with upstream domain names, HSTS, key pinning).
		for key := range headersStrip {
			resp.Header.Del(key)
		}

		// Rewrite all other headers (Location, Link, Content-Location, …).
		for key, vals := range resp.Header {
			if headersSkipRewrite[key] {
				continue
			}
			for i, v := range vals {
				v = maskResponseString(v, targetHost, rootDomain, proxyAddr, subdomainRe)
				v = withExternalURLsProtected(v, "http://"+proxyAddr, rep.ToAlias)
				resp.Header[key][i] = v
			}
		}

		// ── Phase 2: body rewrite — only for text content types ──────────────
		// Binary responses (images, fonts, archives) must NOT be rewritten;
		// byte-level replacement would corrupt them.
		contentType := resp.Header.Get("Content-Type")
		if !isTextContent(contentType) {
			return nil
		}

		// Decompress gzip before string replacement.
		var bodyReader io.Reader = resp.Body
		isGzip := strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip")
		if isGzip {
			gz, err := gzip.NewReader(resp.Body)
			if err != nil {
				log.Printf("ctfproxy: failed to decode gzip response: %v", err)
				return nil
			}
			defer gz.Close()
			bodyReader = gz
			resp.Header.Del("Content-Encoding")
		}

		raw, err := io.ReadAll(io.LimitReader(bodyReader, maxBodyRewrite+1))
		if err != nil {
			return err
		}

		// If the body exceeded the limit, forward it unchanged to avoid data loss.
		// For non-gzip bodies bodyReader IS resp.Body, so we stitch the already-read
		// prefix back together with the remaining stream via io.MultiReader.
		// For gzip, the compressed stream is already partially consumed and cannot
		// be reconstructed; we forward the decompressed portion and log a warning.
		if int64(len(raw)) > maxBodyRewrite {
			log.Printf("ctfproxy: response body exceeds %d bytes; skipping rewrite", maxBodyRewrite)
			if isGzip {
				resp.Body = io.NopCloser(strings.NewReader(string(raw)))
			} else {
				resp.Body = io.NopCloser(io.MultiReader(strings.NewReader(string(raw)), resp.Body))
			}
			return nil
		}
		resp.Body.Close()

		// Rewrite body in two passes — ORDER IS CRITICAL:
		//
		//   Pass 1 — Host masking (upstream host → proxy address):
		//     "https://ctf.io/page" → "http://localhost:8080/page"
		//     Must run BEFORE user replacements.  If user has -replace ctf:acme,
		//     running user replacements first turns "ctf.io" → "acme.io", and we
		//     can no longer match the upstream hostname to replace it with the proxy.
		//
		//   Pass 2 — User replacements (original → alias):
		//     "ctf" → "acme",  "ctfd" → "foo"
		rewritten := maskResponseString(string(raw), targetHost, rootDomain, proxyAddr, subdomainRe)
		rewritten = withExternalURLsProtected(rewritten, "http://"+proxyAddr, rep.ToAlias)

		resp.Body = io.NopCloser(strings.NewReader(rewritten))
		// Recalculate Content-Length — byte length may change when replacement
		// strings differ in length from the originals.
		resp.ContentLength = int64(len(rewritten))
		resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(rewritten)), 10))

		return nil
	}

	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("ctfproxy: upstream error for %s %s: %v", r.Method, r.URL, err)
		http.Error(w, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
	}

	return &httputil.ReverseProxy{
		Director:       director,
		ModifyResponse: modifyResponse,
		ErrorHandler:   errorHandler,
		Transport:      transport,
	}
}
