package main

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// headerPair holds a pre-parsed upstream header name and value supplied via
// the -header flag.  Parsing at construction time avoids allocations on the
// hot path (once per request in the director).
type headerPair struct{ name, value string }

// hopByHopHeaders is the set of headers that must NOT be set manually because
// they are managed by the HTTP transport layer.  Injecting them causes protocol
// errors or undefined behaviour.
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// clientHostContextKey is used to thread the original client-facing Host
// (e.g. "127.0.0.1:9001" or "localhost:9001") from the director to
// modifyResponse via the request context.  Using a typed key avoids clashes
// with other context values.
type clientHostContextKey struct{}

// absURLRe matches absolute and protocol-relative URLs (used to protect
// external links from being corrupted by user-defined string replacements).
var absURLRe = regexp.MustCompile(`(?:https?:)?//[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}[^\s"'<>\x00-\x1F]*`)

// subdomainPathRe matches an already-encoded /__sd__/<host>[/...] segment.
// Used to temporarily shield these from the bare targetHost scan in
// maskResponseString so that "github.com" inside "/__sd__/api.github.com/"
// is not corrupted into "/__sd__/api.localhost:8081/".
var subdomainPathRe = regexp.MustCompile(`/__sd__/[^\s"'<>\x00-\x1F]+`)

// rootRelativeAttrRe matches HTML attribute values that are root-relative paths
// (start with "/" but not "//" or "/__sd__/").
// Group 1 = attribute name + "=" + opening quote (e.g. `href="`).
// Group 2 = the root-relative path (e.g. `/static/app.js`).
// Attributes covered: href, src, action, formaction, data-*, manifest, poster.
var rootRelativeAttrRe = regexp.MustCompile(
	`(?i)((?:href|src|action|formaction|data-[a-zA-Z-]+|manifest|poster)\s*=\s*["'])(/[^"'<>\s]*)`,
)

// srcsetAttrRe captures the opening quote+prefix and raw value of a srcset
// attribute for special multi-URL processing.
// Group 1 = `srcset="` (or single-quoted equivalent).
// Group 2 = the comma-separated list of URL+descriptor entries.
var srcsetAttrRe = regexp.MustCompile(`(?i)(srcset\s*=\s*["'])([^"']*)`)

// rootRelativeCSSRe matches CSS url() values that are root-relative paths.
// Group 1 = `url(` with optional opening quote.
// Group 2 = the root-relative path.
var rootRelativeCSSRe = regexp.MustCompile(`(?i)(url\s*\(\s*["']?)(/[^"')<>\s]*)`)

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
//
// Additionally, /__sd__/<host> segments within proxy-local URLs are specifically
// shielded so that user string replacements cannot corrupt the encoded upstream
// hostname (e.g. "ynet" in "/__sd__/www.ynet.co.il/" must not become "news").
func withExternalURLsProtected(s, proxyBase string, fn func(string) string) string {
	type entry struct{ placeholder, original string }
	var saved []entry

	// Step 1: shield /__sd__/<host> segments BEFORE the external-URL scan.
	// These encoded upstream hosts live inside proxy-local URLs and must survive
	// user replacements intact so the director can route correctly.
	s = subdomainPathRe.ReplaceAllStringFunc(s, func(m string) string {
		ph := "\x01" + strconv.Itoa(len(saved)) + "\x01"
		saved = append(saved, entry{ph, m})
		return ph
	})

	// Step 2: shield external (non-proxy) URLs.
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

	// Step 3: apply user replacements to everything not shielded.
	result = fn(result)

	// Step 4: restore all shielded segments in reverse-insertion order so that
	// nested or overlapping placeholders resolve correctly.
	for i := len(saved) - 1; i >= 0; i-- {
		result = strings.Replace(result, saved[i].placeholder, saved[i].original, 1)
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

// knownSLDs is the set of well-known "second-level domain" labels that are
// used as organisational separators beneath country-code TLDs (ccTLDs).
// Examples: co.il, co.uk, com.au, net.nz, org.br, gov.au, ac.uk …
// When stripping the leading label from a 3-label hostname would produce one
// of these 2-label ccTLD-style suffixes, the original hostname is already the
// registrable/root domain and should not be stripped further.
var knownSLDs = map[string]bool{
	"co": true, "com": true, "net": true, "org": true, "gov": true,
	"edu": true, "ac": true, "mil": true, "biz": true, "info": true,
	"ltd": true, "plc": true, "sch": true, "ne": true, "or": true,
	"go": true, "med": true, "pro": true, "int": true,
}

// computeRootDomain strips the leading hostname label from host so that
// the organisational / registrable domain is returned.  This is used to
// identify all subdomains that belong to the same site.
//
// Examples:
//
//	"www.ynet.co.il"   → "ynet.co.il"
//	"ynet.co.il"       → "ynet.co.il"   (already the registrable domain)
//	"app.logz.io"      → "logz.io"
//	"en.wikipedia.org" → "wikipedia.org"
//	"github.com"       → "github.com"   (two labels, nothing to strip)
//	"bbc.co.uk"        → "bbc.co.uk"    (co.uk is a ccTLD SLD — don't strip)
//
// The heuristic strips the first dot-separated label when there are three or
// more labels, UNLESS doing so would leave a recognised two-label ccTLD-style
// suffix (e.g. co.il, co.uk, com.au).  In that case the original hostname is
// already the registrable domain and is returned unchanged.
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
	candidate := strings.Join(parts[1:], ".")
	candidateParts := strings.Split(candidate, ".")
	// If stripping one label would leave a 2-label ccTLD-style suffix where
	// the first part is a known SLD label (co, com, net, org, gov, ac, …),
	// the input is already the registrable domain — return it unchanged.
	// Example: "ynet.co.il" → candidate "co.il" → first part "co" is a known
	// SLD → return "ynet.co.il" (not "co.il").
	if len(candidateParts) == 2 && knownSLDs[candidateParts[0]] {
		return host
	}
	return candidate
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
//  4. bare "targetHost"    → proxyAddr (hostname-only references, e.g.
//     Set-Cookie Domain, Location without scheme, or plain text mentions).
//     Uses bareTargetRe (domain-boundary-aware regex) to avoid corrupting domains
//     that share targetHost as a substring, e.g. "c.s-microsoft.com" must not
//     become "c.s-localhost:9001" when targetHost="microsoft.com".
//
//  5. When rootDomain differs from targetHost (e.g. targetHost="www.bbc.com",
//     rootDomain="bbc.com"): also rewrite "https://rootDomain" and
//     "http://rootDomain" so that canonical URLs like https://bbc.com/ don't leak.
//
// This MUST run before user-supplied replacements.  If the user has -replace
// ctf:acme, then "ctf.io" would become "acme.io" before we can substitute it
// with "localhost:8080", leaving the upstream hostname partially visible.
//
// bareTargetRe matches targetHost only when NOT preceded or followed by a
// domain-continuation character (letter, digit, hyphen, dot), preventing
// substring corruption in unrelated hostnames.
func maskResponseString(s, targetHost, rootDomain, proxyAddr string, subdomainRe, bareTargetRe *regexp.Regexp) string {
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
	// Step 4: bare targetHost scan with domain-boundary guards.
	// Using regex instead of strings.ReplaceAll to avoid corrupting domains where
	// targetHost appears as a suffix (e.g. "c.s-microsoft.com" when target="microsoft.com").
	// Group 1 = preceding boundary char (preserved), Group 2 = trailing boundary char (preserved).
	if bareTargetRe != nil {
		s = bareTargetRe.ReplaceAllString(s, "${1}"+proxyAddr+"${2}")
	}

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

// rewriteRootRelativePaths prepends "/__sd__/<subHost>" to every root-relative
// path in s so that browsers fetch subdomain resources through the proxy's
// routing mechanism rather than against the proxy root.
//
// Background: when a subdomain page (e.g. copilot.microsoft.com) is served at
//
//	http://localhost:PORT/__sd__/copilot.microsoft.com/
//
// its root-relative resource references like href="/static/app.js" resolve to
//
//	http://localhost:PORT/static/app.js   ← routes to the main target, not the subhost
//
// instead of the intended
//
//	http://localhost:PORT/__sd__/copilot.microsoft.com/static/app.js
//
// This function corrects that for HTML attribute values (href, src, action,
// formaction, data-*, manifest, poster), srcset entries, and CSS url() expressions.
//
// Call order matters:
//   - AFTER maskResponseString  so absolute subdomain URLs are already routed to /__sd__/
//   - BEFORE withExternalURLsProtected so the new /__sd__/ paths are shielded from
//     user string replacements (subdomainPathRe in withExternalURLsProtected handles this)
//
// subHost is the unmasked upstream hostname (e.g. "copilot.microsoft.com").
func rewriteRootRelativePaths(s, subHost string) string {
	pfx := subdomainPrefix + subHost // e.g. "/__sd__/copilot.microsoft.com"

	// rewritePath prepends pfx unless the path is already routed (/__sd__/) or
	// protocol-relative (//cdn.example.com/...) — those are handled elsewhere.
	rewritePath := func(path string) string {
		if strings.HasPrefix(path, subdomainPrefix) || strings.HasPrefix(path, "//") {
			return path
		}
		return pfx + path
	}

	// Rewrite href, src, action, formaction, data-*, manifest, poster values.
	s = rootRelativeAttrRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := rootRelativeAttrRe.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		return sub[1] + rewritePath(sub[2])
	})

	// Rewrite srcset values: comma-separated "url [descriptor], url [descriptor]" lists.
	// Each entry may begin with a root-relative URL that needs rewriting.
	s = srcsetAttrRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := srcsetAttrRe.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		// sub[1] = `srcset="`, sub[2] = the raw comma-separated value
		entries := strings.Split(sub[2], ",")
		for i, entry := range entries {
			// Each entry is optionally-spaced "url [descriptor]".
			// Preserve any leading whitespace (e.g. after a comma).
			trimmed := strings.TrimLeft(entry, " \t")
			if !strings.HasPrefix(trimmed, "/") {
				continue
			}
			leading := entry[:len(entry)-len(trimmed)]
			// Split URL from optional descriptor (e.g. "300w", "2x").
			space := strings.IndexByte(trimmed, ' ')
			if space < 0 {
				entries[i] = leading + rewritePath(trimmed)
			} else {
				entries[i] = leading + rewritePath(trimmed[:space]) + trimmed[space:]
			}
		}
		return sub[1] + strings.Join(entries, ",")
	})

	// Rewrite CSS url() expressions.
	s = rootRelativeCSSRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := rootRelativeCSSRe.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		return sub[1] + rewritePath(sub[2])
	})

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
//
// upstreamTimeout controls how long the proxy waits for upstream dial, TLS
// handshake, and response headers.  Zero means no timeout (use with caution).
//
// logger handles all per-request and startup logging; pass a Logger constructed
// with NewLogger.
func NewReverseProxy(targetHost, scheme string, rep *Replacer, insecure bool, proxyAddr string, exactDomain bool, upstreamTimeout time.Duration, logger *Logger, extraHeaders []headerPair) *httputil.ReverseProxy {
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

	// bareTargetRe matches targetHost as a standalone hostname (step 4 in maskResponseString).
	// Domain-boundary guards: requires that targetHost is NOT preceded or followed by a
	// hostname-continuation character (letter, digit, hyphen, or dot).  This prevents
	// corrupting unrelated domains that share targetHost as a substring.
	// Example: target="microsoft.com" → "c.s-microsoft.com" must NOT become "c.s-localhost:9001".
	// Group 1 = preceding boundary char, Group 2 = trailing boundary char (both preserved).
	var bareTargetRe *regexp.Regexp
	if proxyAddr != "" {
		bareTargetRe = regexp.MustCompile(
			`(?i)(^|[^-a-zA-Z0-9.])` +
				regexp.QuoteMeta(targetHost) +
				`([^-a-zA-Z0-9.]|$)`,
		)
	}

	// Clone DefaultTransport to preserve connection-pooling and timeout settings,
	// then override TLS config when certificate verification must be skipped and
	// apply explicit per-phase timeouts to prevent hung upstreams from leaking
	// goroutines indefinitely.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if upstreamTimeout > 0 {
		// DialContext: how long to wait for TCP connection to upstream.
		transport.DialContext = (&net.Dialer{Timeout: upstreamTimeout}).DialContext
		// TLSHandshakeTimeout: how long to wait for the TLS handshake.
		transport.TLSHandshakeTimeout = upstreamTimeout
		// ResponseHeaderTimeout: how long to wait for the upstream to start
		// sending response headers after the request body has been sent.
		// This is separate from reading the body — streaming responses are fine.
		transport.ResponseHeaderTimeout = upstreamTimeout
	}
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // intentional for CTF
		logger.Printf("maskproxy: WARNING — TLS certificate verification disabled (-skip-verify)")
	}

	// reqTimes stores the start time recorded in the director so that
	// modifyResponse can compute round-trip latency.  sync.Map is used because
	// director and modifyResponse run concurrently for different requests.
	var reqTimes sync.Map // key: *http.Request → value: time.Time

	director := func(req *http.Request) {
		// Capture the client-visible host (e.g. "127.0.0.1:9001" or "localhost:9001")
		// before the director overwrites req.Host with the upstream target.
		// modifyResponse reads this to rewrite redirect Location headers and body
		// URLs with the same hostname the browser is using, preventing CORS errors
		// when the browser follows redirects that cross 127.0.0.1 ↔ localhost.
		clientHost := req.Host
		if clientHost == "" {
			clientHost = req.URL.Host
		}
		if clientHost != "" {
			*req = *req.WithContext(context.WithValue(req.Context(), clientHostContextKey{}, clientHost))
		}

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
		//
		// Security: we validate that the extracted host is actually a subdomain of
		// rootDomain.  Without this check any client could use /__sd__/evil.com/ to
		// proxy requests to arbitrary external hosts (SSRF).
		if strings.HasPrefix(req.URL.Path, subdomainPrefix) {
			rest := req.URL.Path[len(subdomainPrefix):]
			subHost := rest
			subPath := "/"
			if i := strings.Index(rest, "/"); i >= 0 {
				subHost = rest[:i]
				subPath = rest[i:]
			}
			// Validate: subHost must be the rootDomain itself, or a subdomain of it.
			// A valid subdomain satisfies: strings.HasSuffix(subHost, "."+rootDomain)
			// OR subHost == rootDomain (bare root, no subdomain label).
			subHostLower := strings.ToLower(subHost)
			rootLower := strings.ToLower(rootDomain)
			validSubdomain := subHostLower == rootLower ||
				strings.HasSuffix(subHostLower, "."+rootLower)
			if !validSubdomain {
				// Route to the main target and drop the /__sd__ prefix — this prevents
				// SSRF while still serving a (possibly wrong) response rather than a
				// hard 400 that could break page loads if a stale URL slips through.
				logger.Printf("maskproxy: blocked SSRF attempt via /__sd__/%s (not under %s)", subHost, rootDomain)
				req.URL.Path = subPath
				req.URL.RawPath = ""
			} else {
				req.URL.Host = subHost
				req.Host = subHost
				req.URL.Path = subPath
				// Clear RawPath to avoid inconsistency; it will be recomputed if needed.
				req.URL.RawPath = ""
			}
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
				replaceCount := 0
				if rep.HasPairs() {
					rewritten, replaceCount = rep.ToOriginalDiff(rewritten)
				}
				rewritten = unmaskRequestString(rewritten, outboundHost, scheme, proxyAddr)
				req.Body = io.NopCloser(strings.NewReader(rewritten))
				req.ContentLength = int64(len(rewritten))
				start := logger.LogRequest(req, rewritten, false, replaceCount)
				reqTimes.Store(req, start)
			}
		} else {
			// Bodyless request (GET, HEAD, etc.) — still log + record start time.
			// Detect WebSocket upgrade so the log line is clearly distinct from
			// ordinary HTTP requests (WS connections live for minutes; they never
			// produce a matching response log line from ModifyResponse).
			isWS := strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
			start := logger.LogRequest(req, "", isWS, 0)
			reqTimes.Store(req, start)
		}

		// Inject user-defined extra headers (from -header flags).  Use Set so
		// that if the client also sent the same header, our value wins.  This
		// runs BEFORE the Accept-Encoding override below so that a user-supplied
		// -header "Accept-Encoding: ..." cannot silently bypass the proxy's
		// gzip-only enforcement (which is needed for correct body rewriting).
		for _, h := range extraHeaders {
			req.Header.Set(h.name, h.value)
		}

		// Limit accepted encodings to what we can transparently decompress.
		// Other encodings (brotli, zstd) that Go stdlib cannot decode natively
		// would reach ModifyResponse compressed and corrupt after string replacement.
		// This runs AFTER extraHeaders so our enforcement always wins.
		req.Header.Del("Accept-Encoding")
		req.Header.Add("Accept-Encoding", "gzip, identity")

		// Strip client-supplied X-Forwarded-For to prevent header injection.
		req.Header.Del("X-Forwarded-For")
	}

	modifyResponse := func(resp *http.Response) error {
		// Retrieve the start time stored by the director for this request.
		// Use a zero time as fallback if somehow it wasn't stored.
		var start time.Time
		if v, ok := reqTimes.LoadAndDelete(resp.Request); ok {
			start = v.(time.Time)
		}

		// Per-request effective proxy address: use the client-facing Host that
		// the browser sent (captured in the director via context) so that rewritten
		// URLs in the response body and Location headers use the same hostname
		// the browser used to connect.  This prevents CORS errors when the browser
		// follows redirects: if the page was loaded from "127.0.0.1:9001", redirect
		// Location headers must also point to "127.0.0.1:9001", not "localhost:9001".
		//
		// Safety guard: only substitute when the port matches proxyAddr's port.
		// This ensures the override is only applied when the client is genuinely
		// talking to this proxy (same port), and prevents test environments where
		// a fixed proxyAddr (e.g. "masked.proxy:9999") is used but the test HTTP
		// client connects to a random ephemeral port.
		effectiveProxyAddr := proxyAddr
		if ch, ok := resp.Request.Context().Value(clientHostContextKey{}).(string); ok && ch != "" {
			_, proxyPort, err1 := net.SplitHostPort(proxyAddr)
			_, clientPort, err2 := net.SplitHostPort(ch)
			if err1 == nil && err2 == nil && clientPort == proxyPort {
				effectiveProxyAddr = ch
			}
		}

		// ── Redirect downgrade: 301 → 302, 308 → 307 ────────────────────────
		// Browsers cache 301/308 (permanent) redirects indefinitely.  The
		// Location URLs the proxy emits contain proxy-internal path prefixes
		// (/__sd__/…) and localhost addresses that are meaningless outside of
		// the current proxy session.  If the browser caches them and the user
		// restarts the proxy (or switches targets), those cached redirects will
		// loop or point to the wrong place.  Downgrading to temporary redirects
		// prevents any caching.
		switch resp.StatusCode {
		case http.StatusMovedPermanently: // 301 → 302
			resp.StatusCode = http.StatusFound
			resp.Status = "302 Found"
		case http.StatusPermanentRedirect: // 308 → 307
			resp.StatusCode = http.StatusTemporaryRedirect
			resp.Status = "307 Temporary Redirect"
		}

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
				v = maskResponseString(v, targetHost, rootDomain, effectiveProxyAddr, subdomainRe, bareTargetRe)
				v = withExternalURLsProtected(v, "http://"+effectiveProxyAddr, rep.ToAlias)
				resp.Header[key][i] = v
			}
		}

		// ── Phase 2: body rewrite — only for text content types ──────────────
		// Binary responses (images, fonts, archives) must NOT be rewritten;
		// byte-level replacement would corrupt them.
		contentType := resp.Header.Get("Content-Type")
		if !isTextContent(contentType) {
			// Log before returning — no body snapshot for binary content.
			logger.LogResponse(resp, "", start, 0)
			return nil
		}

		// HEAD, 204 No Content, and 304 Not Modified responses have no body.
		// The upstream may still send Content-Encoding: gzip (describing what the
		// body *would* have been), so we must skip gzip decoding here to avoid
		// "failed to decode gzip response: EOF" noise in the logs.
		noBody := resp.Request.Method == http.MethodHead ||
			resp.StatusCode == http.StatusNoContent ||
			resp.StatusCode == http.StatusNotModified
		if noBody {
			logger.LogResponse(resp, "", start, 0)
			return nil
		}

		// Decompress gzip before string replacement.
		var bodyReader io.Reader = resp.Body
		isGzip := strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip")
		if isGzip {
			gz, err := gzip.NewReader(resp.Body)
			if err != nil {
				logger.Printf("maskproxy: failed to decode gzip response: %v", err)
				logger.LogResponse(resp, "", start, 0)
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
			logger.Printf("maskproxy: response body exceeds %d bytes; skipping rewrite", maxBodyRewrite)
			logger.LogResponse(resp, "", start, 0)
			if isGzip {
				resp.Body = io.NopCloser(strings.NewReader(string(raw)))
			} else {
				resp.Body = io.NopCloser(io.MultiReader(strings.NewReader(string(raw)), resp.Body))
			}
			return nil
		}
		resp.Body.Close()

		// Rewrite body in three passes — ORDER IS CRITICAL:
		//
		//   Pass 1 — Host masking (upstream host → proxy address):
		//     "https://ctf.io/page" → "http://localhost:8080/page"
		//     Must run BEFORE user replacements.  If user has -replace ctf:acme,
		//     running user replacements first turns "ctf.io" → "acme.io", and we
		//     can no longer match the upstream hostname to replace it with the proxy.
		//
		//   Pass 2 — Root-relative path prefixing (subdomain responses only):
		//     href="/static/app.js" → href="/__sd__/copilot.microsoft.com/static/app.js"
		//     When the browser is at http://localhost:PORT/__sd__/copilot.microsoft.com/,
		//     root-relative paths resolve against http://localhost:PORT/ (the proxy root),
		//     routing them to the main target instead of the subdomain.  Prefixing with
		//     the /__sd__/ routing path fixes the browser's base-URL resolution.
		//     Must run AFTER pass 1 (absolute URLs already handled) and BEFORE pass 3
		//     (so the new /__sd__/ paths are shielded from user string replacements).
		//
		//   Pass 3 — User replacements (original → alias):
		//     "ctf" → "acme",  "ctfd" → "foo"
		//
		// We also count how many user-substitutions happened so the log line can
		// report "[N replaced]" even in non-verbose mode.
		rewritten := maskResponseString(string(raw), targetHost, rootDomain, effectiveProxyAddr, subdomainRe, bareTargetRe)

		// Pass 2: if this response came from a subdomain host (not the main target),
		// rewrite root-relative paths so browsers resolve them against the subdomain
		// /__sd__/ route rather than the proxy root.
		if reqHost := resp.Request.URL.Host; !strings.EqualFold(reqHost, targetHost) && reqHost != "" {
			rewritten = rewriteRootRelativePaths(rewritten, reqHost)
		}

		var replaceCount int
		rewritten = withExternalURLsProtected(rewritten, "http://"+effectiveProxyAddr, func(s string) string {
			var n int
			s, n = rep.ToAliasDiff(s)
			replaceCount += n
			return s
		})

		resp.Body = io.NopCloser(strings.NewReader(rewritten))
		// Recalculate Content-Length — byte length may change when replacement
		// strings differ in length from the originals.
		resp.ContentLength = int64(len(rewritten))
		resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(rewritten)), 10))

		logger.LogResponse(resp, rewritten, start, replaceCount)
		return nil
	}

	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		// Clean up the timing entry if the request never reached modifyResponse.
		reqTimes.Delete(r)
		logger.Printf("maskproxy: upstream error for %s %s: %v", r.Method, r.URL, err)
		http.Error(w, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
	}

	return &httputil.ReverseProxy{
		Director:       director,
		ModifyResponse: modifyResponse,
		ErrorHandler:   errorHandler,
		Transport:      transport,
		// FlushInterval=-1 enables immediate flushing (streaming mode).
		// This is required for WebSocket and Server-Sent Events: when a client
		// sends "Upgrade: websocket", httputil.ReverseProxy detects the 101
		// Switching Protocols response and enters bidirectional copy mode,
		// bypassing ModifyResponse entirely (correct — WS frames are binary and
		// cannot be string-replaced without corrupting the framing protocol).
		// Without this setting the proxy would attempt to buffer the connection
		// indefinitely and the upgrade would never complete.
		FlushInterval: -1,
	}
}
