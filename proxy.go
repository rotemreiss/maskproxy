package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// ssrfBlockedKey is set on the request context by the director when a
// /__sd__/<host> request targets a host outside the proxy's allowed domain.
// The ssrfGuardTransport detects this and returns a 403 response directly,
// never making an upstream connection.
type ssrfBlockedKey struct{}

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

// metaRefreshRe matches the url= part inside <meta http-equiv="refresh" content="…">.
// Format: content="<seconds>; url=<path>"
// Group 1 = everything up to and including "url=" (preserves the "N; url=" prefix).
// Group 2 = the root-relative path (starts with /).
var metaRefreshRe = regexp.MustCompile(`(?i)(content\s*=\s*["'][0-9]+\s*;\s*url=)(/[^"'<>\s]*)`)

// baseHrefRe matches a <base href="..."> tag in HTML.
// After maskResponseString, an upstream absolute base URL such as
// "https://copilot.microsoft.com/" is already rewritten to "http://localhost:PORT/".
// For subdomain pages we must further rewrite it to "http://localhost:PORT/__sd__/<host>/"
// so the browser resolves relative (non-root-relative) asset paths against the correct
// subdomain route rather than the proxy root.
// Group 1 = everything up to and including href= plus opening quote.
// Group 2 = the URL value (may be absolute or root-relative).
// Group 3 = the closing quote.
var baseHrefRe = regexp.MustCompile(`(?i)(<base[^>]+\bhref\s*=\s*)(["'])([^"']*)(["'])`)

// manifestRootRelativeRe matches JSON string values for "scope" and "start_url"
// keys in a PWA manifest that are root-relative paths.  Used to prefix them with
// the /__sd__/<host> proxy route so PWA scoping resolves correctly.
// Group 1 = the key+colon+space prefix (e.g. `"scope":`).
// Group 2 = the root-relative path value (e.g. `/`).
var manifestRootRelativeRe = regexp.MustCompile(`("(?:scope|start_url)"\s*:\s*)"(/[^"]*)"`)

// importMapRe matches an entire <script type="importmap">…</script> block.
// Import maps define module specifier → URL mappings used by ES module `import`
// statements.  Root-relative URL values (e.g. "/app/module.js") inside the JSON
// body resolve against the browser's base URL, which for subdomain pages is the
// proxy root — not the subdomain route.  We capture the entire block for targeted
// JSON-string-value rewriting.
var importMapRe = regexp.MustCompile(`(?si)<script[^>]+type\s*=\s*["']importmap["'][^>]*>(.*?)</script>`)

// speculationRulesRe matches an entire <script type="speculationrules">…</script>
// block.  Speculation-rules JSON contains URL lists (e.g. "/page1") that the
// browser prefetches/prerenders.  Root-relative values resolve against the proxy
// root on subdomain pages, causing prefetches to hit the wrong upstream.  We
// rewrite them with the same JSON-string-value approach as importmap.
var speculationRulesRe = regexp.MustCompile(`(?si)<script[^>]+type\s*=\s*["']speculationrules["'][^>]*>(.*?)</script>`)

// importMapValueRe matches JSON string values that are root-relative paths inside
// an importmap or speculationrules script block (after the block has been isolated).
// Group 1 = the root-relative path.
var importMapValueRe = regexp.MustCompile(`"(/[^"]*)"`)

// linkHeaderRe matches root-relative URLs inside Link header angle brackets.
// Format: `</path/to/resource>; rel=preload`
// Group 1 = the root-relative path (the part between < and >).
var linkHeaderRe = regexp.MustCompile(`<(/[^/][^>]*)>`)

// sriIntegrityRe matches Subresource Integrity `integrity` attributes on
// HTML elements.  When the proxy rewrites script or stylesheet content via
// string replacement, the cryptographic hash encoded in the attribute no
// longer matches the (now-modified) bytes, causing the browser to block the
// resource.  We strip the attribute so the browser skips the SRI check.
//
// The same logic applies to the paired `crossorigin` attribute when it is
// present solely to enable the CORS fetch needed for SRI checking — but we
// leave `crossorigin` in place because it can also control how credentials
// are sent and stripping it might break requests unnecessarily.
var sriIntegrityRe = regexp.MustCompile(`(?i)\s+integrity\s*=\s*(?:"[^"]*"|'[^']*')`)

// linkIntegrityRe strips the `; integrity=<hash>` parameter from HTTP Link
// header values.  A Link header can carry an integrity attribute for
// preload/preconnect hints (e.g. `Link: </app.js>; rel=preload; integrity=sha256-xxx`).
// After the proxy rewrites the referenced resource, the hash is stale and the
// browser would reject the preloaded bytes.  Strip it unconditionally.
var linkIntegrityRe = regexp.MustCompile(`(?i);\s*integrity\s*=\s*(?:"[^"]*"|'[^']*'|[^\s;,>]*)`)

// scriptNonceRe extracts the nonce value from a <script nonce="..."> attribute.
// Used to apply the same nonce to the injected SPA script so it is not blocked
// by nonce-based Content-Security-Policy directives.
// Group 1 = the nonce value (without quotes).
var scriptNonceRe = regexp.MustCompile(`(?i)<script[^>]+\bnonce\s*=\s*(?:"([^"]*)"|'([^']*)')`)

// maxBodyRewriteDefault is the default maximum body size for rewriting.
const maxBodyRewriteDefault = int64(50 * 1024 * 1024) // 50 MiB

// subdomainSPAScript is injected into the <head> of every subdomain HTML page.
//
// Problem: the browser is at http://localhost:PORT/__sd__/<host>/path, so
// window.location.pathname === "/__sd__/<host>/path".  SPA frameworks (Remix,
// React Router, Next.js, etc.) read location.pathname to match routes.  Their
// route table was generated for the original server where the path is just
// "/path" — not the proxy-prefixed form.  The mismatch causes invariant failures
// ("No routes matched location") or hard client-side crashes.
//
// Fix: patch the browser's visible URL with history.replaceState so the SPA
// router sees "/path" instead of "/__sd__/<host>/path".  Also patch
// history.pushState / replaceState to transparently re-add the proxy prefix so
// that subsequent SPA navigations stay routed through /__sd__/<host>/.  Fetch,
// XHR, WebSocket, and EventSource root-relative calls are likewise prefixed so
// API/socket requests don't accidentally route to the main proxy target.
//
// Additional hardening:
//   - navigator.sendBeacon: root-relative analytics beacons would otherwise
//     hit the main proxy target instead of the subdomain.
//   - location.assign / location.replace: full-page navigations to root-relative
//     paths would load the main proxy target; prefix them so they stay on the
//     subdomain route.
//   - navigator.serviceWorker.register: a SW registered from a subdomain page
//     at scope "/" would intercept ALL requests on localhost:PORT — including
//     other proxied sites.  Block SW registration entirely from subdomain pages.
//
// %s is replaced with the /__sd__/<host> prefix (e.g. "/__sd__/copilot.microsoft.com").
const subdomainSPAScript = `<script>(function(){` +
	`var pfx=%q;` +
	`if(!location.pathname.startsWith(pfx))return;` +
	// Patch visible URL so SPA routers see the real path.
	`var path=location.pathname.slice(pfx.length)||'/';` +
	`history.replaceState(history.state,document.title,path+location.search+location.hash);` +
	// Patch pushState/replaceState to re-add the prefix on navigation.
	`['pushState','replaceState'].forEach(function(fn){` +
	`var o=history[fn].bind(history);` +
	`history[fn]=function(st,ti,url){` +
	`if(typeof url==='string'&&url.startsWith('/')&&!url.startsWith('/__sd__/'))url=pfx+url;` +
	`return o(st,ti,url);};});` +
	// Patch location.assign / location.replace for full-page navigations.
	`['assign','replace'].forEach(function(fn){` +
	`var o=location[fn].bind(location);` +
	`location[fn]=function(url){` +
	`if(typeof url==='string'&&url.startsWith('/')&&!url.startsWith('/__sd__/'))url=pfx+url;` +
	`return o(url);};});` +
	// Patch window.fetch for root-relative API calls.
	// Handles string URLs, Request objects, and URL objects.
	`var oF=window.fetch;` +
	`window.fetch=function(i,o){` +
	`var s=typeof i==='string'?i:(i instanceof URL?i.href:(i&&i.url?i.url:''));` +
	`if(s.startsWith('/')&&!s.startsWith('/__sd__/')){` +
	`if(typeof i==='string')i=pfx+i;` +
	`else if(i instanceof URL)i=new URL(pfx+i.pathname+i.search+i.hash,i.origin);` +
	`else if(i&&i.url)i=new Request(location.origin+pfx+i.url.slice(location.origin.length),i);}` +
	`else if(s.startsWith(location.origin+'/')&&!s.slice(location.origin.length).startsWith('/__sd__/')){` +
	`if(typeof i==='string')i=location.origin+pfx+i.slice(location.origin.length);` +
	`else if(i instanceof URL)i=new URL(pfx+i.pathname+i.search+i.hash,i.origin);` +
	`else if(i&&i.url)i=new Request(location.origin+pfx+i.url.slice(location.origin.length),i);}` +
	`return oF.call(this,i,o);};` +
	// Patch XMLHttpRequest.open for root-relative XHR calls.
	`var oX=XMLHttpRequest.prototype.open;` +
	`XMLHttpRequest.prototype.open=function(m,u){` +
	`if(u instanceof URL)u=u.href;` +
	`if(typeof u==='string'&&u.startsWith('/')&&!u.startsWith('/__sd__/'))u=pfx+u;` +
	`else if(typeof u==='string'&&u.startsWith(location.origin+'/')&&!u.slice(location.origin.length).startsWith('/__sd__/'))u=location.origin+pfx+u.slice(location.origin.length);` +
	`return oX.apply(this,arguments);};` +
	// Patch navigator.sendBeacon for root-relative analytics/telemetry.
	`if(navigator.sendBeacon){` +
	`var oB=navigator.sendBeacon.bind(navigator);` +
	`navigator.sendBeacon=function(u,d){` +
	`if(typeof u==='string'&&u.startsWith('/')&&!u.startsWith('/__sd__/'))u=pfx+u;` +
	`return oB(u,d);};` +
	`}` +
	// Patch WebSocket for root-relative WS connections.
	`var WS=window.WebSocket;` +
	`window.WebSocket=function(u,p){` +
	`if(typeof u==='string'&&u.startsWith('/')&&!u.startsWith('/__sd__/')){` +
	`var sch=location.protocol==='https:'?'wss://':'ws://';` +
	`u=sch+location.host+pfx+u;}` +
	`return p!==undefined?new WS(u,p):new WS(u);};` +
	`window.WebSocket.prototype=WS.prototype;` +
	// Patch EventSource for root-relative SSE streams.
	`if(window.EventSource){` +
	`var ES=window.EventSource;` +
	`window.EventSource=function(u,o){` +
	`if(typeof u==='string'&&u.startsWith('/')&&!u.startsWith('/__sd__/'))u=pfx+u;` +
	`return o!==undefined?new ES(u,o):new ES(u);};` +
	`}` +
	// Block Service Worker registration: a SW at scope "/" would intercept ALL
	// requests on localhost:PORT — including requests from other proxied sites —
	// silently corrupting or logging cross-site traffic.
	`if(navigator.serviceWorker){` +
	`navigator.serviceWorker.register=function(){` +
	`return Promise.reject(new Error('SW blocked by proxy'));};` +
	`}` +
	`})();</script>`

// headTagRe matches an opening <head> tag (with optional attributes) to find
// the injection point for the subdomain SPA script.
var headTagRe = regexp.MustCompile(`(?i)<head[^>]*>`)

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
	"Content-Length":                     true,
	"Content-Encoding":                   true,
	"Transfer-Encoding":                  true,
	"Set-Cookie":                         true, // handled by rewriteSetCookies
	"Content-Security-Policy":            true, // handled by rewriteCSP
	"Content-Security-Policy-Report-Only": true, // handled by rewriteCSP
}

// headersStrip is the set of response headers that must be removed entirely.
// These headers are either tied to the upstream origin and would break the
// proxy, or expose security metadata the masking proxy must hide.
var headersStrip = map[string]bool{
	"Strict-Transport-Security":   true, // HSTS on plain-HTTP proxy confuses browsers
	"Public-Key-Pins":             true,
	"Public-Key-Pins-Report-Only": true,
	"Expect-CT":                   true,

	// Alt-Svc: advertises alternative service endpoints (HTTP/3, h2c, etc.).
	// If forwarded, the browser would attempt to connect directly to the upstream
	// host/port using the alternative protocol, bypassing the proxy entirely on
	// subsequent requests.  Strip it unconditionally.
	"Alt-Svc": true,

	// X-Frame-Options: DENY/SAMEORIGIN prevents the proxy from embedding
	// subdomain pages in iframes within the proxy context (e.g. /__sd__/host/
	// framed inside the main proxy page). The proxy already controls the framing
	// context, so this restriction is counterproductive.
	"X-Frame-Options": true,

	// Report-To and NEL instruct the browser to send error/network reports to
	// upstream collection endpoints, leaking real hostnames and traffic details.
	"Report-To":                     true,
	"Nel":                           true,

	// Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy enforce strict
	// cross-origin isolation. When the proxy serves pages from multiple upstream
	// origins (via /__sd__/), COOP same-origin would prevent cross-window comms
	// and COEP require-corp would block subresources that don't opt in — both
	// break normal proxy operation.
	"Cross-Origin-Opener-Policy":          true,
	"Cross-Origin-Opener-Policy-Report-Only": true,
	"Cross-Origin-Embedder-Policy":        true,
	"Cross-Origin-Embedder-Policy-Report-Only": true,

	// Cross-Origin-Resource-Policy: same-origin would block the proxy from
	// forwarding cross-origin subresources (images, fonts, etc.).
	"Cross-Origin-Resource-Policy": true,

	// Via: discloses proxy software and hop count to clients, unnecessarily
	// revealing internal topology.  Strip from responses.
	"Via": true,

	// Service-Worker-Allowed: if set to "/", a service worker registered
	// at /__sd__/<host>/sw.js could claim the entire proxy origin (including
	// other subdomain routes), intercepting and potentially corrupting
	// requests.  Strip the header so the SW scope is limited to its own path.
	"Service-Worker-Allowed": true,

	// Clear-Site-Data: instructs the browser to clear cookies, storage, or
	// cache for the current origin.  Since all proxied sites share
	// localhost:PORT as their origin, forwarding this header from one site's
	// logout endpoint would wipe the cookies and storage of every other site
	// being proxied simultaneously.  Strip it unconditionally.
	"Clear-Site-Data": true,

	// ETag and Last-Modified enable conditional requests (If-None-Match /
	// If-Modified-Since).  If the browser cached a previous proxy response and
	// later sends a conditional GET, the upstream would return 304 Not Modified,
	// causing ModifyResponse to skip body rewriting — the browser then uses its
	// stale cached copy that may contain unrewritten hostnames.  Strip these
	// validators so the browser never makes conditional requests for proxied pages.
	"Etag":          true,
	"Last-Modified": true,

	// Permissions-Policy (formerly Feature-Policy): restricts browser APIs
	// (camera, microphone, geolocation, payment, etc.) for the page's origin.
	// Since all proxied sites share localhost:PORT, a restrictive policy from
	// one site would apply globally to every other proxied site.  Strip it.
	"Permissions-Policy": true,
	"Feature-Policy":     true,

	// Origin-Agent-Cluster: when set to "?1", the browser places the page in
	// a separate agent cluster which may prevent certain cross-window
	// interactions needed when multiple proxied pages interoperate.  Strip it.
	"Origin-Agent-Cluster": true,

	// Speculation-Rules: a Chrome 109+ header whose value is a URL pointing to a
	// JSON file that lists pages to prefetch/prerender.  If forwarded, Chrome
	// would make those speculative requests directly to the upstream host
	// (bypassing the proxy) or to paths on the proxy that resolve to the wrong
	// upstream host.  Strip the header so speculative loads don't escape.
	// Note: <script type="speculationrules"> elements in the body are still
	// processed by maskResponseString / rewriteRootRelativePaths like any other
	// JS/HTML content, so inline speculation rules are handled correctly.
	"Speculation-Rules": true,

	// Document-Policy: a newer header (like Permissions-Policy) that restricts
	// document behaviour (e.g. no-document-write, sync-xhr=?0).  Since all proxied
	// sites share localhost:PORT, a restrictive policy from one site would apply
	// globally to every other proxied site on the same origin.  Strip it.
	"Document-Policy": true,

	// Accept-CH and Critical-CH instruct browsers to send Client Hint request
	// headers (Sec-CH-UA, Sec-CH-UA-Platform, Viewport-Width, DPR, etc.) on
	// subsequent requests to this origin.  Since the browser's "origin" is
	// localhost:PORT (the proxy), accepting Client Hints would cause the browser
	// to advertise the proxy's origin context in future requests — not the upstream
	// context.  Strip both to avoid leaking proxy fingerprint data to upstream.
	"Accept-Ch":          true,
	"Accept-Ch-Lifetime": true, // deprecated but still seen in the wild
	"Critical-Ch":        true,

	// Digest and Content-Digest carry a cryptographic hash of the response body
	// (RFC 3230 / RFC 9530).  After the proxy rewrites body content (host names,
	// replacement strings) the hash is stale and verification by the client would
	// fail.  Strip both so clients don't reject the rewritten body.
	"Digest":         true,
	"Content-Digest": true,
}

// textContentTypes lists MIME type prefixes for which body replacement is safe.
// Binary formats (images, audio, video, archives) are intentionally excluded to
// avoid corrupting them.
var textContentTypes = []string{
	"text/",
	"image/svg+xml",            // SVG is XML text; may contain href/url() referencing upstream hosts
	"application/json",
	"application/manifest+json", // PWA web app manifests (start_url, icons, etc.)
	"application/xml",
	"application/xhtml",
	"application/javascript",
	"application/x-www-form-urlencoded",
	"application/x-javascript",
	"application/ld+json",
	"application/graphql",
	"application/feed+json", // JSON Feed
	"application/rss+xml",
	"application/atom+xml",
}

// withExternalURLsProtected applies fn to s while shielding any absolute URLs
// that do NOT point to the proxy itself (external / third-party CDN URLs) from
// modification.  This prevents third-party CDN hostnames that happen to contain
// the user's search string (e.g. "ynet-pic1.yit.co.il") from being silently
// broken by user-defined string replacements.
//
// proxyBase is the scheme+host prefix of the proxy (e.g. "http://localhost:8081").
// URLs starting with proxyBase are NOT protected so user replacements still apply
// to proxy-local paths including /__sd__/<host> segments (e.g. "microsoft" in
// "/__sd__/copilot.microsoft.com/" becomes "msctf" when -replace microsoft:msctf).
// The director applies rep.ToOriginal on every inbound request path, so the encoded
// hostname is restored before routing regardless of what the client URL contains.
// When proxyBase is "" (host masking disabled), all absolute URLs are protected.
//
// Mechanism: each protected URL is temporarily replaced with a NUL-delimited
// numeric placeholder, fn is applied to the surrounding text, and then every
// placeholder is swapped back to the original URL.
func withExternalURLsProtected(s, proxyBase string, fn func(string) string) string {
	type entry struct{ placeholder, original string }
	var saved []entry

	// Shield external (non-proxy) absolute URLs.
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

	// Apply user replacements to everything not shielded.
	result = fn(result)

	// Restore shielded segments in reverse-insertion order.
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
//   - Path attribute: prefixed with /__sd__/<subHost> when the response came
//     from a subdomain route.  Browsers match cookies by path; without this
//     a cookie with Path=/api/ set by "/__sd__/sub.host.com/api/" would never
//     be sent back because the browser path-matches against the proxy's URL
//     (/__sd__/sub.host.com/api/), not the upstream path (/api/).
//     When subHost is empty (main target response) the Path is left unchanged.
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
func rewriteSetCookies(resp *http.Response, proxyIsHTTPS bool, subHost string) {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}
	// Replace all Set-Cookie headers with the rewritten versions.
	resp.Header.Del("Set-Cookie")
	for _, c := range cookies {
		// Clear Domain: let the browser default to the serving host (the proxy).
		c.Domain = ""
		// Prefix Path with /__sd__/<subHost> for subdomain-routed responses so
		// the browser path-matches against the proxy URL, not the upstream path.
		if subHost != "" {
			pfx := subdomainPrefix + subHost // e.g. "/__sd__/sub.example.com"
			if c.Path == "" || c.Path == "/" {
				c.Path = pfx + "/"
			} else {
				c.Path = pfx + c.Path
			}
		}
		if !proxyIsHTTPS {
			// Strip __Host- and __Secure- cookie name prefixes before removing
			// the Secure flag.  Both prefixes require the Secure attribute; once
			// Secure is gone the browser rejects the cookie entirely.  Renaming
			// preserves the session by dropping the security guarantee (which is
			// acceptable in a local proxy/CTF context).
			if strings.HasPrefix(c.Name, "__Host-") {
				c.Name = strings.TrimPrefix(c.Name, "__Host-")
				// __Host- also requires Path=/ and no Domain — both already handled.
			} else if strings.HasPrefix(c.Name, "__Secure-") {
				c.Name = strings.TrimPrefix(c.Name, "__Secure-")
			}
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
//  6. When alsoProxyRe is non-nil: additional external domains are routed via
//     /__sd__/<host>/ the same way as target subdomains. This handles CDN
//     domains that share content with the target but live on a different TLD
//     (e.g. bbci.co.uk for www.bbc.com). Provided via -also-proxy flag.
//
// This MUST run before user-supplied replacements.  If the user has -replace
// ctf:acme, then "ctf.io" would become "acme.io" before we can substitute it
// with "localhost:8080", leaving the upstream hostname partially visible.
//
// bareTargetRe matches targetHost only when NOT preceded or followed by a
// domain-continuation character (letter, digit, hyphen, dot), preventing
// substring corruption in unrelated hostnames.
func maskResponseString(s, targetHost, rootDomain, proxyAddr string, subdomainRe, bareTargetRe, alsoProxyRe *regexp.Regexp) string {
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
	// Also rewrite the protocol-relative form "//targetHost" (no scheme).
	// This appears when upstream HTML uses src="//ctf.io/logo.png" style URLs.
	// Step 1 (subdomainRe) covers "//sub.rootDomain" but not "//rootDomain" itself.
	s = strings.ReplaceAll(s, "//"+targetHost+"/", "//"+proxyAddr+"/")
	s = strings.ReplaceAll(s, "//"+targetHost+"\"", "//"+proxyAddr+"\"")
	s = strings.ReplaceAll(s, "//"+targetHost+"'", "//"+proxyAddr+"'")
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
		s = strings.ReplaceAll(s, "//"+rootDomain+"/", "//"+proxyAddr+"/")
		s = strings.ReplaceAll(s, "//"+rootDomain+"\"", "//"+proxyAddr+"\"")
		s = strings.ReplaceAll(s, "//"+rootDomain+"'", "//"+proxyAddr+"'")
		// Do NOT do a bare rootDomain scan here — "bbc.com" appears legitimately
		// in third-party tracker query params (utm_source=bbc.com) and replacing
		// it blindly would corrupt those partner URLs.
	}

	// Step 6: route -also-proxy extra domains through /__sd__/<host>/ so that
	// CDN scripts from related-but-different-TLD domains are fetched via the
	// proxy and receive string replacement treatment.
	if alsoProxyRe != nil {
		s = alsoProxyRe.ReplaceAllStringFunc(s, func(match string) string {
			sub := alsoProxyRe.FindStringSubmatch(match)
			if len(sub) < 3 {
				return match
			}
			hostStr := sub[1]
			if idx := strings.Index(hostStr, "//"); idx >= 0 {
				hostStr = hostStr[idx+2:]
			}
			return proxyBase + subdomainPrefix + hostStr + sub[2]
		})
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

	// Rewrite <meta http-equiv="refresh" content="N; url=/path"> values.
	s = metaRefreshRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := metaRefreshRe.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		return sub[1] + rewritePath(sub[2])
	})

	// Rewrite root-relative URL values inside <script type="importmap"> blocks.
	// Import maps define module specifier → URL mappings consumed by ES module
	// import statements.  Example:
	//   <script type="importmap">
	//     {"imports": {"/app/chunk.js": "/app/chunk.js"}}
	//   </script>
	// For subdomain pages, the JSON string values are root-relative paths that
	// resolve against the browser's base URL (proxy root, not the subdomain route).
	// We find each importmap block and rewrite JSON string values that start with "/".
	rewriteJSONRootRelativeBlock := func(blockRe *regexp.Regexp, s string) string {
		return blockRe.ReplaceAllStringFunc(s, func(m string) string {
			sub := blockRe.FindStringSubmatch(m)
			if len(sub) < 2 {
				return m
			}
			inner := sub[1]
			rewrittenInner := importMapValueRe.ReplaceAllStringFunc(inner, func(jv string) string {
				sub2 := importMapValueRe.FindStringSubmatch(jv)
				if len(sub2) < 2 {
					return jv
				}
				path := sub2[1]
				if strings.HasPrefix(path, subdomainPrefix) || strings.HasPrefix(path, "//") {
					return jv
				}
				return `"` + pfx + path + `"`
			})
			return strings.Replace(m, inner, rewrittenInner, 1)
		})
	}
	s = rewriteJSONRootRelativeBlock(importMapRe, s)
	// Speculation rules are inline JSON URL lists (prefetch/prerender).
	// Root-relative paths in them resolve against the proxy root on subdomain pages.
	s = rewriteJSONRootRelativeBlock(speculationRulesRe, s)

	return s
}

// rewriteCSP rewrites a Content-Security-Policy (or CSP-Report-Only) header
// value so that all host-source references to the proxied target domain are
// replaced with the proxy's own address.  This lets the browser load resources
// through the proxy without violating the policy.
//
// Rewriting rules per source token:
//   - `'self'`, `'nonce-…'`, `'sha256-…'`, `'unsafe-inline'`, etc. → unchanged
//   - `https://target.com`   → `http://proxyAddr`
//   - `https://*.target.com` → `http://proxyAddr`  (wildcard; all subdomains
//     are served from the same proxy origin via /__sd__/)
//   - `wss://target.com`     → `ws://proxyAddr`     (WebSocket scheme downgrade)
//   - `*.target.com`         → `proxyAddr`           (no scheme)
//   - `target.com`           → `proxyAddr`
//   - Non-target tokens      → unchanged
//
// `report-uri` and `report-to` directives are dropped: they would send
// violation reports to the upstream's collection endpoint, leaking traffic
// and the real hostname.
func rewriteCSP(csp, targetHost, rootDomain, proxyAddr string) string {
	if proxyAddr == "" || csp == "" {
		return csp
	}
	targetLower := strings.ToLower(targetHost)
	rootLower := strings.ToLower(rootDomain)

	directives := strings.Split(csp, ";")
	out := make([]string, 0, len(directives))

	// Directives that govern inline content the proxy may rewrite (URL replacement
	// runs on the whole body including inline <script> and <style> blocks).
	// Hash-based sources ('sha256-…', 'sha384-…', 'sha512-…') are invalidated when
	// the content changes, so we strip those tokens and replace them with
	// 'unsafe-inline' to keep scripts/styles functional.
	contentDirectives := map[string]bool{
		"default-src": true,
		"script-src":  true,
		"script-src-elem": true,
		"style-src":   true,
		"style-src-elem": true,
	}

	for _, dir := range directives {
		trimmed := strings.TrimSpace(dir)
		if trimmed == "" {
			continue
		}
		tokens := strings.Fields(trimmed)
		if len(tokens) == 0 {
			continue
		}
		// Drop violation-reporting directives — they reference upstream endpoints.
		name := strings.ToLower(tokens[0])
		if name == "report-uri" || name == "report-to" {
			continue
		}
		// Drop frame-ancestors 'none': this directive prevents any framing of the
		// page, including by the proxy itself.  We already strip X-Frame-Options
		// for the same reason.  'frame-ancestors *' or 'frame-ancestors http://…'
		// are handled by rewriteCSPToken (upstream origins rewritten to proxy addr).
		if name == "frame-ancestors" && len(tokens) == 2 &&
			strings.ToLower(tokens[1]) == "'none'" {
			continue
		}

		// Drop the sandbox directive.  The CSP sandbox is equivalent to the
		// <iframe sandbox> attribute and restricts powerful features like scripts,
		// forms, and same-origin access.  Without 'allow-scripts' and
		// 'allow-same-origin', the proxy's injected SPA script cannot run, and
		// most JS-heavy pages break entirely.  Strip the whole directive so the
		// proxy can operate normally; the sandboxing context is only meaningful
		// for the original upstream deployment.
		if name == "sandbox" {
			continue
		}

		// Drop require-sri-for.  This directive requires SRI on all scripts and
		// styles.  The proxy strips SRI integrity attributes from HTML elements
		// (sriIntegrityRe) because rewriting changes the hash.  But if require-sri-for
		// is still present, the browser will block all resources that lack integrity
		// attributes — exactly the ones we just stripped.  Remove this directive so
		// resources can load without SRI enforcement.
		if name == "require-sri-for" {
			continue
		}

		rewritten := make([]string, 0, len(tokens))
		rewritten = append(rewritten, tokens[0]) // directive name unchanged
		hadHash := false
		for _, tok := range tokens[1:] {
			lower := strings.ToLower(tok)
			// Strip hash-based source tokens for content directives: 'sha256-…',
			// 'sha384-…', 'sha512-…'. The proxy rewrites URL strings inside inline
			// <script> and <style> blocks, invalidating the hash. We'll add
			// 'unsafe-inline' below to keep the content functional.
			if contentDirectives[name] &&
				(strings.HasPrefix(lower, "'sha256-") ||
					strings.HasPrefix(lower, "'sha384-") ||
					strings.HasPrefix(lower, "'sha512-")) {
				hadHash = true
				continue
			}
			rewritten = append(rewritten, rewriteCSPToken(tok, targetLower, rootLower, proxyAddr))
		}
		// If we stripped hashes, inject 'unsafe-inline' so inline scripts/styles
		// still load. Without it, the directive's source list may become overly
		// restrictive (e.g. only 'nonce-…' sources) or even empty.
		//
		// Also strip 'strict-dynamic' when we've stripped hashes: CSP Level 3
		// browsers ignore 'unsafe-inline' (and host allowlists) when
		// 'strict-dynamic' is present, so our injected 'unsafe-inline' would be
		// silently ignored and inline content would remain blocked.
		if hadHash {
			filtered := rewritten[:1] // keep directive name
			for _, t := range rewritten[1:] {
				if strings.ToLower(t) == "'strict-dynamic'" {
					continue
				}
				filtered = append(filtered, t)
			}
			rewritten = filtered

			alreadyUnsafe := false
			for _, t := range rewritten[1:] {
				if strings.ToLower(t) == "'unsafe-inline'" {
					alreadyUnsafe = true
					break
				}
			}
			if !alreadyUnsafe {
				rewritten = append(rewritten, "'unsafe-inline'")
			}
		}
		out = append(out, strings.Join(rewritten, " "))
	}
	return strings.Join(out, "; ")
}

// rewriteCSPToken rewrites a single CSP source token if it references the
// proxied target domain or any of its subdomains.
func rewriteCSPToken(token, targetLower, rootLower, proxyAddr string) string {
	// CSP keywords always start with a single-quote — leave them untouched.
	if strings.HasPrefix(token, "'") {
		return token
	}
	// Lowercase for matching only; we'll build the output from scratch.
	lower := strings.ToLower(token)

	// Extract and strip optional scheme prefix.
	scheme := ""
	rest := lower
	for _, s := range []string{"https://", "http://", "wss://", "ws://"} {
		if strings.HasPrefix(rest, s) {
			scheme = s
			rest = rest[len(s):]
			break
		}
	}

	// Strip optional wildcard subdomain prefix "*.".
	rest = strings.TrimPrefix(rest, "*.")

	// Strip optional path suffix to isolate the host[:port] portion.
	// CSP connect-src entries can include paths, e.g. "https://api.github.com/v2/*".
	hostPort := rest
	if i := strings.Index(rest, "/"); i >= 0 {
		hostPort = rest[:i]
	}

	// Strip optional port suffix to isolate the bare hostname.
	host := hostPort
	if i := strings.LastIndex(hostPort, ":"); i >= 0 {
		host = hostPort[:i]
	}

	// Check whether the host belongs to the target domain (exact match or subdomain).
	isTarget := host == targetLower ||
		strings.HasSuffix(host, "."+targetLower) ||
		host == rootLower ||
		strings.HasSuffix(host, "."+rootLower)

	if !isTarget {
		return token
	}

	// Map scheme: wss → ws (proxy is plain HTTP); ws → ws; everything else → http.
	switch scheme {
	case "wss://", "ws://":
		return "ws://" + proxyAddr
	case "", "https://", "http://":
		if scheme == "" {
			return proxyAddr
		}
		return "http://" + proxyAddr
	default:
		return "http://" + proxyAddr
	}
}

// ignoredHostSet holds two disjoint sets for efficient ignored-host lookup:
//   - exact: O(1) map lookup for precise hostnames
//   - wildcards: pre-built slice of ".suffix" strings for O(k) HasSuffix scan
//     where k is the number of wildcard entries (typically very small).
//
// This avoids iterating the whole map on every request, as the old
// map[string]bool implementation did when checking wildcard entries.
type ignoredHostSet struct {
	exact     map[string]bool
	wildcards []string // each entry is a ".suffix" (leading dot)
}

// newIgnoredHostSet converts the flat map produced by parseIgnoreHosts into a
// typed set with separate exact and wildcard buckets.
func newIgnoredHostSet(m map[string]bool) *ignoredHostSet {
	if len(m) == 0 {
		return nil
	}
	s := &ignoredHostSet{exact: make(map[string]bool, len(m))}
	for k := range m {
		if strings.HasPrefix(k, ".") {
			s.wildcards = append(s.wildcards, k)
		} else {
			s.exact[k] = true
		}
	}
	return s
}

// contains reports whether host (with or without port) matches an exact entry
// or any wildcard suffix in the set.
func (s *ignoredHostSet) contains(host string) bool {
	if s == nil {
		return false
	}
	// Strip port if present (e.g. "login.microsoftonline.com:443" → "login.microsoftonline.com").
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	if s.exact[host] {
		return true
	}
	// Wildcard suffix scan: O(k) where k = number of wildcard entries (typically ≤ 5).
	for _, suffix := range s.wildcards {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// isIgnoredHost is a convenience wrapper for the old map[string]bool API,
// used by callers that still pass the flat map directly.
func isIgnoredHost(host string, ignoredHosts map[string]bool) bool {
	return newIgnoredHostSet(ignoredHosts).contains(host)
}

// unmaskRequestString is the reverse of maskResponseString: it rewrites s from
// an outbound request so that proxy-address references become the upstream host.
// This MUST run after user-supplied replacements (which convert aliases to
// originals) so that the final header/body value is fully upstream-native.
//
// Special case: subdomain proxy paths of the form
//   http://proxyAddr/__sd__/<subHost>/path
// must be unwound to their original upstream URL:
//   https://<subHost>/path
// Without this, Referer and Origin headers sent from a /__sd__/ page would
// become "https://targetHost/__sd__/sub.host/path" — wrong upstream host.
func unmaskRequestString(s, targetHost, scheme, proxyAddr string) string {
	if proxyAddr == "" {
		return s
	}
	// Rewrite /__sd__/<subHost>/... form first, before the plain proxy-base
	// replacement, so we don't end up with "https://targetHost/__sd__/..." as
	// an intermediate that then fails the next ReplaceAll.
	sdPrefix := "http://" + proxyAddr + subdomainPrefix
	for {
		idx := strings.Index(s, sdPrefix)
		if idx < 0 {
			break
		}
		rest := s[idx+len(sdPrefix):]
		// Extract <subHost> (everything up to the first '/' or end of string).
		var subHost, subPath string
		if end := strings.IndexByte(rest, '/'); end < 0 {
			// No trailing slash — reconstruct as "scheme://subHost/"
			subHost = rest
			subPath = "/"
			// consumed characters in original string: len(sdPrefix) + len(subHost)
			s = s[:idx] + scheme + "://" + subHost + subPath + s[idx+len(sdPrefix)+len(subHost):]
		} else {
			subHost = rest[:end]
			subPath = rest[end:] // includes leading '/'
			// consumed characters: len(sdPrefix) + len(subHost) + len(subPath)
			s = s[:idx] + scheme + "://" + subHost + subPath + s[idx+len(sdPrefix)+len(subHost)+len(subPath):]
		}
		if subHost == "" {
			break
		}
	}
	upstreamBase := scheme + "://" + targetHost
	s = strings.ReplaceAll(s, "http://"+proxyAddr, upstreamBase)
	// Also rewrite the protocol-relative form "//proxyAddr" that may appear in
	// request headers like Referer or Origin when the browser constructs them
	// from a page served via the proxy.
	s = strings.ReplaceAll(s, "//"+proxyAddr+"/", "//"+targetHost+"/")
	s = strings.ReplaceAll(s, proxyAddr, targetHost)
	return s
}

// removeVaryAcceptEncoding removes "Accept-Encoding" from the Vary header
// after decompressing the response body.  Once the body is identity-encoded
// there is no variant for Accept-Encoding; leaving the directive would
// confuse downstream caches.
func removeVaryAcceptEncoding(h http.Header) {
	varyVals := h["Vary"]
	if len(varyVals) == 0 {
		return
	}
	out := varyVals[:0]
	for _, v := range varyVals {
		parts := strings.Split(v, ",")
		kept := parts[:0]
		for _, p := range parts {
			if !strings.EqualFold(strings.TrimSpace(p), "Accept-Encoding") {
				kept = append(kept, p)
			}
		}
		if len(kept) > 0 {
			out = append(out, strings.Join(kept, ","))
		}
	}
	if len(out) == 0 {
		h.Del("Vary")
	} else {
		h["Vary"] = out
	}
}

// ── Follow-target-redirects transport ────────────────────────────────────────

// followTargetRedirectsTransport follows upstream 3xx redirects that stay
// within the same root domain (e.g. www.github.com → github.com).  Without
// this, the proxy would forward the redirect to the browser as
// "Location: http://localhost:PORT/" which the browser follows forever in a
// loop (the proxy always fetches www.github.com, which always 302s to
// github.com, which the proxy rewrites back to localhost:PORT…).
//
// Only redirects whose target host is identical to, or a subdomain of,
// rootDomain are followed.  Cross-domain redirects (e.g. to an OAuth provider)
// are passed through so the browser can handle them properly.
const maxFollowRedirects = 10

type followTargetRedirectsTransport struct {
	rt                http.RoundTripper
	rootDomain        string          // e.g. "github.com"
	scheme            string          // "https" or "http"
	alsoProxyDomains  map[string]bool // lowercase extra-proxy domains
}

func (t *followTargetRedirectsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req
	for i := 0; i < maxFollowRedirects; i++ {
		resp, err := t.rt.RoundTrip(r)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return resp, nil
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			return resp, nil
		}
		locURL, err := url.Parse(loc)
		if err != nil || locURL.Host == "" {
			return resp, nil
		}
		// Only follow if the redirect target is within the same root domain or an
		// explicitly allowed extra-proxy domain.
		h := strings.ToLower(locURL.Host)
		root := strings.ToLower(t.rootDomain)
		withinRoot := h == root || strings.HasSuffix(h, "."+root)
		withinAlso := false
		for extra := range t.alsoProxyDomains {
			if h == extra || strings.HasSuffix(h, "."+extra) {
				withinAlso = true
				break
			}
		}
		if !withinRoot && !withinAlso {
			return resp, nil // cross-domain redirect — let the browser handle it
		}
		resp.Body.Close()
		// Build a new request for the redirect target, preserving method for
		// 307/308 and switching to GET for 301/302/303 (matching browser behaviour).
		method := r.Method
		var body io.ReadCloser
		if resp.StatusCode == 303 || ((resp.StatusCode == 301 || resp.StatusCode == 302) && r.Method != http.MethodGet && r.Method != http.MethodHead) {
			method = http.MethodGet
			body = http.NoBody
		} else if r.Body != nil && r.Body != http.NoBody {
			// Body already consumed by the previous RoundTrip — cannot replay.
			// For non-idempotent same-domain redirects without a body reader, skip.
			body = http.NoBody
		}
		newReq := r.Clone(r.Context())
		newReq.URL = locURL
		if locURL.Scheme == "" {
			newReq.URL.Scheme = t.scheme
		}
		newReq.Host = locURL.Host
		newReq.Method = method
		newReq.Body = body
		newReq.ContentLength = 0
		r = newReq
	}
	// Exceeded redirect limit — fall back to final RoundTrip without following.
	return t.rt.RoundTrip(r)
}

// ── SSRF guard transport ──────────────────────────────────────────────────────

// ssrfGuardTransport wraps an http.RoundTripper and short-circuits requests
// that the director flagged as SSRF attempts (via ssrfBlockedKey context).
// Returning a synthetic 403 response means no upstream connection is made and
// the client gets a clear, actionable error instead of a silently wrong page.
type ssrfGuardTransport struct {
	rt http.RoundTripper
}

func (t *ssrfGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if blockedHost, ok := req.Context().Value(ssrfBlockedKey{}).(string); ok {
		body := "403 Forbidden: /__sd__/" + blockedHost + " is not under the proxy's target domain\n"
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Status:     "403 Forbidden",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	}
	return t.rt.RoundTrip(req)
}


// After a 101 Switching Protocols upgrade, httputil.ReverseProxy calls
// Hijack() on both connections and copies raw bytes bidirectionally — no
// middleware hook exists.  To observe WS frames we wrap the backend
// ReadWriteCloser returned by the transport with wsLoggingConn, which parses
// WS frame headers statefully as bytes stream through.

// wsConnCounter assigns a monotonically increasing ID to each WebSocket
// connection, making concurrent connections distinguishable in the log.
var wsConnCounter atomic.Uint64

// wsLoggingTransport wraps an http.RoundTripper and intercepts 101 Switching
// Protocols responses to attach per-frame logging to the upgraded connection.
type wsLoggingTransport struct {
	rt     http.RoundTripper
	logger *Logger
}

func (t *wsLoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.rt.RoundTrip(req)
	if err != nil || resp == nil || resp.StatusCode != http.StatusSwitchingProtocols {
		return resp, err
	}
	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		// Body is not writable — httputil will handle the error; proceed without logging.
		return resp, nil
	}
	id := wsConnCounter.Add(1)
	t.logger.Printf("WS↕  conn#%d established", id)
	resp.Body = &wsLoggingConn{rwc: rwc, id: id, logger: t.logger}
	return resp, nil
}

// wsFrameParseState tracks the frame-header parser position for one direction
// of a WebSocket connection.
//
// WS frame header layout (RFC 6455 §5.2):
//
//	Byte 0: FIN(1) RSV1-3(3) opcode(4)
//	Byte 1: MASK(1) payload_len(7)
//	  payload_len == 126 → 2 more bytes (uint16 big-endian)
//	  payload_len == 127 → 8 more bytes (uint64 big-endian)
//	  MASK bit set       → 4 masking-key bytes (after extended length)
//	Then: payloadLen bytes of payload (not buffered — counted and skipped)
type wsFrameParseState struct {
	header     [14]byte // accumulates raw header bytes (max WS header size)
	headerLen  int      // bytes collected so far
	need       int      // total header bytes required for this frame
	payloadRem uint64   // remaining payload bytes before the next frame header
}

// feed processes len(data) bytes that just passed through the connection.
// It advances the parse state machine and calls logger.LogWSFrame once per
// complete frame header encountered within data.
//
// Called from a single goroutine per direction (Read from one goroutine, Write
// from another), so no locking is needed.
func (s *wsFrameParseState) feed(data []byte, id uint64, dir string, logger *Logger) {
	pos := 0
	for pos < len(data) {
		// Skip payload bytes belonging to the current frame.
		if s.payloadRem > 0 {
			avail := uint64(len(data) - pos)
			skip := avail
			if skip > s.payloadRem {
				skip = s.payloadRem
			}
			s.payloadRem -= skip
			pos += int(skip)
			continue
		}

		// Accumulate header bytes one at a time.
		s.header[s.headerLen] = data[pos]
		s.headerLen++
		pos++

		switch s.headerLen {
		case 1:
			s.need = 2 // always need at least 2 bytes
		case 2:
			// Byte 1 tells us how many extended-length and masking-key bytes follow.
			payLen7 := s.header[1] & 0x7F
			masked := (s.header[1] & 0x80) != 0
			s.need = 2
			switch payLen7 {
			case 126:
				s.need += 2 // 16-bit extended payload length
			case 127:
				s.need += 8 // 64-bit extended payload length
			}
			if masked {
				s.need += 4 // masking key
			}
		}

		if s.headerLen < s.need {
			continue // still accumulating header bytes
		}

		// Full header received — parse, log, and prepare to skip payload.
		s.parseAndLog(id, dir, logger)
	}
}

// parseAndLog extracts fields from the completed header buffer, emits a log
// line, then resets the state for the next frame.
func (s *wsFrameParseState) parseAndLog(id uint64, dir string, logger *Logger) {
	fin := (s.header[0] & 0x80) != 0
	opcode := s.header[0] & 0x0F
	masked := (s.header[1] & 0x80) != 0
	payLen7 := s.header[1] & 0x7F

	var payloadLen uint64
	switch payLen7 {
	case 126:
		payloadLen = uint64(s.header[2])<<8 | uint64(s.header[3])
	case 127:
		payloadLen = uint64(s.header[2])<<56 | uint64(s.header[3])<<48 |
			uint64(s.header[4])<<40 | uint64(s.header[5])<<32 |
			uint64(s.header[6])<<24 | uint64(s.header[7])<<16 |
			uint64(s.header[8])<<8 | uint64(s.header[9])
	default:
		payloadLen = uint64(payLen7)
	}
	s.payloadRem = payloadLen

	// Reset for the next frame.
	s.headerLen = 0
	s.need = 0

	logger.LogWSFrame(id, dir, opcode, fin, masked, payloadLen)
}

// wsLoggingConn wraps the hijacked backend connection for a WebSocket upgrade.
// It observes WS frame headers in both directions without buffering or
// modifying any payload bytes (zero latency impact on the data stream).
//
// Thread safety: httputil's switchProtocolCopier calls Read and Write from
// separate goroutines.  rstate and wstate are each accessed from exactly one
// goroutine, so no mutex is needed.
type wsLoggingConn struct {
	rwc    io.ReadWriteCloser
	id     uint64
	logger *Logger
	rstate wsFrameParseState // upstream→client (Read) parser
	wstate wsFrameParseState // client→upstream (Write) parser
}

// Read passes bytes through unchanged and feeds them to the upstream→client parser.
func (c *wsLoggingConn) Read(b []byte) (int, error) {
	n, err := c.rwc.Read(b)
	if n > 0 {
		c.rstate.feed(b[:n], c.id, "WS↓", c.logger)
	}
	return n, err
}

// Write passes bytes through unchanged and feeds them to the client→upstream parser.
func (c *wsLoggingConn) Write(b []byte) (int, error) {
	n, err := c.rwc.Write(b)
	if n > 0 {
		c.wstate.feed(b[:n], c.id, "WS↑", c.logger)
	}
	return n, err
}

// Close closes the underlying connection.
func (c *wsLoggingConn) Close() error { return c.rwc.Close() }

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
// alsoProxy is an optional list of additional external domains (not subdomains
// of the target) whose URLs should be routed through the proxy via /__sd__/.
// Useful for CDN domains on different TLDs that share content with the target
// (e.g. bbci.co.uk for www.bbc.com). Pass nil to disable.
func NewReverseProxy(targetHost, scheme string, rep *Replacer, insecure bool, proxyAddr string, exactDomain bool, upstreamTimeout time.Duration, logger *Logger, extraHeaders []headerPair, ignoredHosts map[string]bool, maxBodyBytes int64, alsoProxy []string) *httputil.ReverseProxy {
	if maxBodyBytes <= 0 {
		maxBodyBytes = maxBodyRewriteDefault
	}
	// Convert the flat map into a typed set with separate exact/wildcard buckets
	// so that isIgnoredHost does not pay O(n) map iteration for wildcard matching.
	ignored := newIgnoredHostSet(ignoredHosts)
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

	// Build alsoProxyRe — matches URLs from -also-proxy domains so they can be
	// routed through /__sd__/<host>/ the same way as target subdomains.
	// alsoProxyDomains is a normalised lowercase set used in the SSRF validator.
	var alsoProxyRe *regexp.Regexp
	alsoProxyDomains := map[string]bool{} // lower-case set for quick lookup
	if len(alsoProxy) > 0 && proxyAddr != "" {
		var parts []string
		for _, d := range alsoProxy {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			alsoProxyDomains[d] = true
			// Match the domain itself and all its subdomains.
			parts = append(parts, `(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)*`+regexp.QuoteMeta(d))
		}
		if len(parts) > 0 {
			alsoProxyRe = regexp.MustCompile(
				`(?i)((?:https?:)?//(?:` + strings.Join(parts, "|") + `))([/?#"'\s\x00]|$)`,
			)
		}
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

	// Wrap transport with WS frame logging when enabled.
	// The wrapper intercepts 101 Switching Protocols responses and attaches a
	// wsLoggingConn to the backend body so frame headers are logged in both
	// directions without buffering or modifying the data stream.
	var rt http.RoundTripper = transport
	if logger.logWS {
		rt = &wsLoggingTransport{rt: transport, logger: logger}
	}
	// Follow upstream redirects that stay within the same root domain (e.g.
	// www.github.com → github.com).  This prevents infinite redirect loops
	// where the proxy rewrites the Location back to itself indefinitely.
	rt = &followTargetRedirectsTransport{rt: rt, rootDomain: rootDomain, scheme: scheme, alsoProxyDomains: alsoProxyDomains}
	// Always wrap with the SSRF guard so that /__sd__/ requests flagged by the
	// director are short-circuited with a 403 before any upstream connection.
	rt = &ssrfGuardTransport{rt: rt}

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
		// Skipped when the destination is an ignored host.
		//
		// For subdomain requests (/__sd__/<host>/...) we can determine the
		// outbound host by peeking at the path before extraction, so we can
		// correctly suppress path/query rewriting for ignored subdomain hosts
		// without restructuring the entire director.
		outboundHostForPath := req.Host // default: main target
		if strings.HasPrefix(req.URL.Path, subdomainPrefix) {
			rest := req.URL.Path[len(subdomainPrefix):]
			if i := strings.Index(rest, "/"); i >= 0 {
				outboundHostForPath = rest[:i]
			} else {
				outboundHostForPath = rest
			}
		}
		if rep.HasPairs() && !ignored.contains(outboundHostForPath) {
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
			// Un-replace any alias strings in the subHost before validation and routing.
			// The response rewriter applied ToAlias to the /__sd__/<host> path, so
			// "bbci.co.uk" in the response becomes "britcasti.co.uk" when the user
			// has -replace bbc:britcast.  Reverse that here so we route to the real host.
			if rep.HasPairs() {
				subHost = rep.ToOriginal(subHost)
			}
			// Validate: subHost must be the rootDomain itself, or a subdomain of it.
			// A valid subdomain satisfies: strings.HasSuffix(subHost, "."+rootDomain)
			// OR subHost == rootDomain (bare root, no subdomain label).
			//
			// Additionally, reject hosts containing characters that are illegal in
			// DNS hostnames or that could be interpreted as URL authority components:
			//   '@' — userinfo separator (e.g. "evil@real.domain.com" suffix-passes
			//          the rootDomain check yet routes to a different host)
			//   '/' — path separator
			//   '\x00'–'\x1f', '\x7f'+ — control/non-ASCII characters
			subHostLower := strings.ToLower(subHost)
			rootLower := strings.ToLower(rootDomain)
			hostnameInvalid := func(h string) bool {
				for _, c := range h {
					if c < 0x21 || c > 0x7e || c == '@' || c == '/' {
						return true
					}
				}
				return false
			}
			validSubdomain := !hostnameInvalid(subHostLower) &&
				(subHostLower == rootLower || strings.HasSuffix(subHostLower, "."+rootLower))
			// Also allow hosts from the -also-proxy whitelist.
			if !validSubdomain && len(alsoProxyDomains) > 0 && !hostnameInvalid(subHostLower) {
				for extra := range alsoProxyDomains {
					if subHostLower == extra || strings.HasSuffix(subHostLower, "."+extra) {
						validSubdomain = true
						break
					}
				}
			}
			if !validSubdomain {
				// Flag request as SSRF-blocked in the context.
				// ssrfGuardTransport intercepts this and returns a 403 directly,
				// so no upstream connection is made for the malicious host.
				logger.Printf("maskproxy: blocked SSRF attempt via /__sd__/%s (not under %s)", subHost, rootDomain)
				*req = *req.WithContext(context.WithValue(req.Context(), ssrfBlockedKey{}, subHost))
				req.URL.Path = "/"
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
		//
		// Both rewrites are skipped for ignored hosts — their requests must flow
		// through unchanged so that functional strings (OAuth scopes, tenant IDs,
		// etc.) are not corrupted by the user-defined replacement pairs.
		outboundHost := req.Host
		if !ignored.contains(outboundHost) {
			for key, vals := range req.Header {
				for i, v := range vals {
					if rep.HasPairs() {
						v = rep.ToOriginal(v)
					}
					v = unmaskRequestString(v, outboundHost, scheme, proxyAddr)
					req.Header[key][i] = v
				}
			}
		}

		// Same two-pass rewrite for the request body (e.g. form POST, JSON).
		// Also skipped for ignored hosts and non-text content types.
		if req.Body != nil {
			// Gate on Content-Type to avoid corrupting binary uploads (images,
			// multipart file uploads, protobuf, etc.).
			reqCT := req.Header.Get("Content-Type")
			bodyIsText := reqCT == "" || isTextContent(reqCT)

			// Read up to maxBodyBytes+1 bytes to detect oversized bodies.
			// Do NOT close req.Body yet — the tail of the stream may still be there.
			raw, err := io.ReadAll(io.LimitReader(req.Body, maxBodyBytes+1))
			if err == nil {
				if int64(len(raw)) > maxBodyBytes || !bodyIsText {
					// Body too large or binary: stitch already-read prefix back with
					// the remaining stream (like the response path does) so no bytes
					// are lost.  ContentLength stays at the original value so the
					// upstream receives the correct Transfer-Encoding.
					req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(raw), req.Body))
					start := logger.LogRequest(req, "", false, 0)
					reqTimes.Store(req, start)
				} else {
					req.Body.Close()
					rewritten := string(raw)
					replaceCount := 0
					if !ignored.contains(outboundHost) {
						if rep.HasPairs() {
							rewritten, replaceCount = rep.ToOriginalDiff(rewritten)
						}
						rewritten = unmaskRequestString(rewritten, outboundHost, scheme, proxyAddr)
					}
					req.Body = io.NopCloser(strings.NewReader(rewritten))
					req.ContentLength = int64(len(rewritten))
					start := logger.LogRequest(req, rewritten, false, replaceCount)
					reqTimes.Store(req, start)
				}
			} else {
				// Body read failed — still record timing so modifyResponse can log duration.
				start := logger.LogRequest(req, "", false, 0)
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
		// encoding enforcement (gzip/deflate only, needed for body rewriting).
		for _, h := range extraHeaders {
			req.Header.Set(h.name, h.value)
		}

		// Limit accepted encodings to what we can transparently decompress.
		// gzip and deflate are handled; brotli and zstd would reach ModifyResponse
		// still compressed and corrupt after string replacement.
		// This runs AFTER extraHeaders so our enforcement always wins.
		req.Header.Del("Accept-Encoding")
		req.Header.Add("Accept-Encoding", "gzip, deflate, identity")

		// Strip client-supplied X-Forwarded-For to prevent header injection.
		req.Header.Del("X-Forwarded-For")

		// Strip Via to avoid leaking proxy metadata to the upstream server.
		req.Header.Del("Via")

		// Strip Sec-Fetch-* headers.  These describe the browser's security
		// context relative to the proxy origin (localhost:PORT), not the upstream.
		// For example, Sec-Fetch-Site: same-origin is accurate from the browser's
		// perspective (both pages are at localhost:PORT), but misleading to the
		// upstream which sees its own origin.  Removing them lets upstream apply
		// its normal CORS and Fetch-Metadata policies without confusion.
		req.Header.Del("Sec-Fetch-Site")
		req.Header.Del("Sec-Fetch-Mode")
		req.Header.Del("Sec-Fetch-Dest")
		req.Header.Del("Sec-Fetch-User")

		// Strip Client Hints request headers.  The browser sends these because a
		// previous response from this origin contained Accept-CH (now stripped on
		// responses).  The values describe the browser's UA, platform, device, etc.
		// relative to the proxy origin — meaningless to upstream and leaking metadata.
		req.Header.Del("Sec-Ch-Ua")
		req.Header.Del("Sec-Ch-Ua-Mobile")
		req.Header.Del("Sec-Ch-Ua-Platform")
		req.Header.Del("Sec-Ch-Ua-Platform-Version")
		req.Header.Del("Sec-Ch-Ua-Full-Version")
		req.Header.Del("Sec-Ch-Ua-Full-Version-List")
		req.Header.Del("Sec-Ch-Ua-Arch")
		req.Header.Del("Sec-Ch-Ua-Bitness")
		req.Header.Del("Sec-Ch-Ua-Model")
		req.Header.Del("Sec-Ch-Ua-Wow64")
		req.Header.Del("Dpr")
		req.Header.Del("Viewport-Width")
		req.Header.Del("Width")

		// Strip Upgrade-Insecure-Requests.  This header asks upstream to redirect
		// HTTP requests to HTTPS.  When the proxy is talking HTTP to upstream (non-
		// SSL mode) forwarding it can cause an unnecessary 301 redirect loop.
		req.Header.Del("Upgrade-Insecure-Requests")

		// Strip conditional-request headers sent by the browser so the upstream
		// always returns the full response body.  If we forwarded these and got
		// a 304 Not Modified, ModifyResponse would skip body rewriting (noBody
		// path) and the browser would use a cached copy that may contain
		// unrewritten upstream hostnames or old string-replacement results.
		req.Header.Del("If-None-Match")
		req.Header.Del("If-Modified-Since")
		req.Header.Del("If-Match")
		req.Header.Del("If-Unmodified-Since")
		req.Header.Del("If-Range")
	}

	modifyResponse := func(resp *http.Response) error {
		// Retrieve the start time stored by the director for this request.
		// Use a zero time as fallback if somehow it wasn't stored.
		var start time.Time
		if v, ok := reqTimes.LoadAndDelete(resp.Request); ok {
			start = v.(time.Time)
		}

		// Short-circuit for SSRF-blocked responses: the synthetic 403 body from
		// ssrfGuardTransport needs no host masking or string replacement.
		if _, blocked := resp.Request.Context().Value(ssrfBlockedKey{}).(string); blocked {
			logger.LogResponse(resp, "", start, 0)
			return nil
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

		// Set-Cookie: clear Domain, fix Path for subdomain routes, remove Secure/SameSite=None.
		// subHost is non-empty only when the response came from a subdomain route
		// (/__sd__/<host>/...) so that cookie Paths are prefixed correctly.
		var cookieSubHost string
		if rh := resp.Request.URL.Host; !strings.EqualFold(rh, targetHost) && rh != "" {
			cookieSubHost = rh
		}
		rewriteSetCookies(resp, false /* proxy listens on plain HTTP */, cookieSubHost)

		// Strip headers that are tied to the upstream origin and would break
		// the proxy (HSTS, key pinning).  Runs unconditionally — even for ignored
		// hosts — because these headers are security-relevant regardless of whether
		// the user chose to bypass rewriting for this host.
		for key := range headersStrip {
			resp.Header.Del(key)
		}

		// For ignored hosts, all remaining rewriting (CSP, Location, body) is
		// skipped.  Traffic flows through untouched so that functional strings
		// embedded in the response (OAuth scopes, tenant IDs, library internals)
		// are never corrupted by user-defined replacement pairs.
		if ignored.contains(resp.Request.URL.Host) {
			logger.LogResponse(resp, "", start, 0)
			return nil
		}

		// Rewrite Content-Security-Policy: replace target-domain host sources
		// with the proxy's own address so the browser can load resources without
		// CSP violations.  This is done separately from the generic loop because
		// CSP values need token-level parsing (not simple string replacement).
		for _, cspKey := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
			for i, v := range resp.Header[cspKey] {
				resp.Header[cspKey][i] = rewriteCSP(v, targetHost, rootDomain, effectiveProxyAddr)
			}
		}

		// Rewrite all other headers (Location, Link, Content-Location, Refresh …).
		// For subdomain-routed responses, also prefix any root-relative redirect
		// value with /__sd__/<host> so redirects stay within the proxy's routing.
		// Handles:
		//   Location: /login                     → Location: /__sd__/sub.host.com/login
		//   Refresh: 0; url=/login               → Refresh: 0; url=/__sd__/sub.host.com/login
		//   Link: </api/data>; rel=preload        → Link: </__sd__/sub.host.com/api/data>; …
		headerSubHost := ""
		if rh := resp.Request.URL.Host; !strings.EqualFold(rh, targetHost) && rh != "" {
			headerSubHost = rh
		}
		for key, vals := range resp.Header {
			if headersSkipRewrite[key] {
				continue
			}
			for i, v := range vals {
				v = maskResponseString(v, targetHost, rootDomain, effectiveProxyAddr, subdomainRe, bareTargetRe, alsoProxyRe)
			if headerSubHost != "" {
				switch key {
				case "Location", "Content-Location":
					// Plain URL value — prefix root-relative paths.
					if strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") && !strings.HasPrefix(v, subdomainPrefix) {
						v = subdomainPrefix + headerSubHost + v
					}
				case "Refresh":
					// Format: "N" or "N; url=<url>" — fix the url= part if present.
					if idx := strings.Index(strings.ToLower(v), "url="); idx >= 0 {
						urlPart := v[idx+4:]
						if strings.HasPrefix(urlPart, "/") && !strings.HasPrefix(urlPart, "//") && !strings.HasPrefix(urlPart, subdomainPrefix) {
							v = v[:idx+4] + subdomainPrefix + headerSubHost + urlPart
						}
					}
				case "Link":
					// Format: comma-separated entries like `</path>; rel=preload`.
					// Prefix root-relative paths inside <…> angle brackets.
					v = linkHeaderRe.ReplaceAllStringFunc(v, func(m string) string {
						sub := linkHeaderRe.FindStringSubmatch(m)
						if len(sub) < 2 {
							return m
						}
						path := sub[1]
						if strings.HasPrefix(path, "//") || strings.HasPrefix(path, subdomainPrefix) {
							return m
						}
						return "<" + subdomainPrefix + headerSubHost + path + ">"
					})
				}
			}
			// Strip integrity parameters from Link header values — they reference
			// the upstream hash which is stale after any body rewriting.
			if key == "Link" {
				v = linkIntegrityRe.ReplaceAllString(v, "")
			}
				v = withExternalURLsProtected(v, "http://"+effectiveProxyAddr, rep.ToAlias)
				resp.Header[key][i] = v
			}
		}

		// Normalize Access-Control-Allow-Origin after the generic header loop.
		// maskResponseString rewrites subdomain URLs with the /__sd__/<host>
		// path prefix, which is correct for Location/Link/body URLs but wrong
		// for ACAO: "http://localhost:PORT/__sd__/api.upstream.com" is not a
		// valid origin and browsers won't accept it as matching "http://localhost:PORT".
		// Strip the /__sd__/<host> suffix so the header holds a bare origin.
		if acao := resp.Header.Get("Access-Control-Allow-Origin"); acao != "" && acao != "*" && acao != "null" {
			if idx := strings.Index(acao, subdomainPrefix); idx > 0 {
				resp.Header.Set("Access-Control-Allow-Origin", acao[:idx])
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

		// Server-Sent Events (text/event-stream) are long-lived streaming
		// responses that must not be fully buffered — io.ReadAll would block
		// until the stream closes.  FlushInterval=-1 on the ReverseProxy
		// handles progressive flushing; we skip body rewriting here so the
		// client receives each "data: …\n\n" event in real time.
		// Header rewriting above already ran, so host masking in headers is
		// still applied even for SSE responses.
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0])), "text/event-stream") {
			logger.LogResponse(resp, "", start, 0)
			return nil
		}


		// We advertise Accept-Encoding: gzip, deflate, identity. Anything else
		// (br, zstd) is forwarded unchanged to avoid corrupting compressed bytes.
		var bodyReader io.Reader = resp.Body
		ce := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
		isGzip := ce == "gzip"
		isDeflate := ce == "deflate"
		// compressedDeflate holds the raw compressed bytes for deflate responses so
		// we can restore the body if the decompressed size exceeds the rewrite limit.
		var compressedDeflate []byte
		if !isGzip && !isDeflate && ce != "" && ce != "identity" {
			// Unknown encoding (br, zstd, …) — forward body unchanged and skip rewriting.
			logger.Printf("maskproxy: skipping body rewrite: unsupported Content-Encoding %q", ce)
			logger.LogResponse(resp, "", start, 0)
			return nil
		}
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
			// Strip Vary: Accept-Encoding — the body is no longer compressed, so
			// different encodings would produce identical content.  Leaving it
			// confuses downstream caches into thinking variants exist.
			removeVaryAcceptEncoding(resp.Header)
		}
		if isDeflate {
			// HTTP "deflate" is ambiguous: some servers send zlib-wrapped DEFLATE
			// (RFC 1950), others send raw DEFLATE (RFC 1951). Try zlib first; if
			// the header bytes don't match (0x78 magic), fall back to raw flate.
			// Read ALL compressed bytes up-front so we can restore them intact if
			// the decompressed size exceeds the rewrite limit (compressedDeflate
			// is checked in the oversized-body branch below).  Use maxBodyBytes as
			// an upper bound for the compressed stream too — a deflate body that is
			// already larger than maxBodyBytes compressed will definitely exceed it
			// decompressed, so we can skip without even trying.
			var err error
			// Read the full compressed body (no inner limit — size-gating happens
			// after decompression in the shared oversized check below).
			compressedDeflate, err = io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			var dr io.ReadCloser
			if len(compressedDeflate) >= 2 && compressedDeflate[0] == 0x78 {
				dr, err = zlib.NewReader(bytes.NewReader(compressedDeflate))
			} else {
				dr = flate.NewReader(bytes.NewReader(compressedDeflate))
				err = nil
			}
			if err != nil {
				logger.Printf("maskproxy: failed to decode deflate response: %v", err)
				resp.Body = io.NopCloser(bytes.NewReader(compressedDeflate))
				logger.LogResponse(resp, "", start, 0)
				return nil
			}
			defer dr.Close()
			bodyReader = dr
			resp.Header.Del("Content-Encoding")
			removeVaryAcceptEncoding(resp.Header)
		}

		raw, err := io.ReadAll(io.LimitReader(bodyReader, maxBodyBytes+1))
		if err != nil {
			return err
		}

		// If the body exceeded the limit, forward it unchanged to avoid data loss.
		// - plain identity: stitch prefix back with the remaining stream via io.MultiReader
		// - gzip: compressed stream is consumed; forward the decompressed prefix (Content-Encoding already stripped)
		// - deflate: restore original compressed bytes and Content-Encoding header
		if int64(len(raw)) > maxBodyBytes {
			logger.Printf("maskproxy: response body exceeds %d bytes; skipping rewrite", maxBodyBytes)
			logger.LogResponse(resp, "", start, 0)
			switch {
			case isDeflate:
				resp.Header.Set("Content-Encoding", "deflate")
				resp.Body = io.NopCloser(bytes.NewReader(compressedDeflate))
			case isGzip:
				resp.Body = io.NopCloser(bytes.NewReader(raw))
			default:
				resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(raw), resp.Body))
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
		rewritten := maskResponseString(string(raw), targetHost, rootDomain, effectiveProxyAddr, subdomainRe, bareTargetRe, alsoProxyRe)

		// Pass 2: if this response came from a subdomain host (not the main target),
		// rewrite root-relative paths so browsers resolve them against the subdomain
		// /__sd__/ route rather than the proxy root.
		reqHost := resp.Request.URL.Host
		isSubdomain := !strings.EqualFold(reqHost, targetHost) && reqHost != ""
		if isSubdomain {
			rewritten = rewriteRootRelativePaths(rewritten, reqHost)
			// Rewrite <base href> so relative (non-root-relative) URLs resolve
			// against the subdomain route.  maskResponseString already turned
			// "https://host/" into "http://proxyAddr/" so we just need to
			// prefix any proxy-base or root-relative href with /__sd__/<host>/.
			if strings.HasPrefix(contentType, "text/html") {
				sdPfx := subdomainPrefix + reqHost // "/__sd__/host.com"
				proxyBase := "http://" + effectiveProxyAddr
				rewritten = baseHrefRe.ReplaceAllStringFunc(rewritten, func(m string) string {
					sub := baseHrefRe.FindStringSubmatch(m)
					if len(sub) < 5 {
						return m
					}
					pre, q1, href, q2 := sub[1], sub[2], sub[3], sub[4]
					// Already pointing into /__sd__/ — leave it.
					if strings.Contains(href, subdomainPrefix) {
						return m
					}
					// Absolute proxy base URL → replace with subdomain base.
					if strings.HasPrefix(href, proxyBase) {
						href = proxyBase + sdPfx + href[len(proxyBase):]
					} else if strings.HasPrefix(href, "/") && !strings.HasPrefix(href, "//") {
						// Root-relative href → prefix with /__sd__/<host>.
						href = sdPfx + href
					}
					return pre + q1 + href + q2
				})
			}
		}

		// Pass 2b: for subdomain HTML pages inject the SPA pathname-patching
		// script at the start of <head>.  This fixes SPA frameworks (Remix,
		// Next.js, React Router) that read window.location.pathname and fail
		// when they see "/__sd__/<host>/path" instead of the expected "/path".
		// The script:
		//   1. Rewrites the visible URL with history.replaceState so the router
		//      sees the real application path.
		//   2. Patches history.pushState/replaceState to transparently re-add the
		//      proxy routing prefix so subsequent SPA navigations route correctly.
		//   3. Patches fetch() and XMLHttpRequest so root-relative API calls
		//      are sent to the subdomain host, not the main proxy target.
		if isSubdomain && strings.HasPrefix(contentType, "text/html") {
			pfx := subdomainPrefix + reqHost // e.g. "/__sd__/copilot.microsoft.com"
			script := fmt.Sprintf(subdomainSPAScript, pfx)

			// If the page uses nonce-based CSP (script-src 'nonce-xxx'), the browser
			// will block our injected <script> because it has no nonce attribute.
			// Extract any nonce from existing <script nonce="..."> tags and add it
			// to the injected script so CSP allows it to run.
			if m := scriptNonceRe.FindStringSubmatch(rewritten); m != nil {
				nonce := m[1]
				if nonce == "" {
					nonce = m[2] // single-quoted form
				}
				if nonce != "" {
					script = strings.Replace(script, "<script>", `<script nonce="`+nonce+`">`, 1)
				}
			}

			rewritten = headTagRe.ReplaceAllStringFunc(rewritten, func(tag string) string {
				return tag + script
			})
		}

		// Pass 2c: for subdomain PWA manifest (application/manifest+json) responses,
		// rewrite root-relative "scope" and "start_url" JSON string values so the
		// PWA is scoped to the subdomain proxy route, not the proxy root.
		// maskResponseString already handles absolute URLs in the manifest body;
		// this pass handles the root-relative form ("/" or "/app/") that
		// maskResponseString intentionally skips (to avoid corrupting non-URL strings).
		//
		// JSON string values matching root-relative paths are prefixed with
		// "/__sd__/<host>" so the browser navigates within the correct proxy route.
		if isSubdomain && strings.Contains(contentType, "manifest+json") {
			sdPfx := subdomainPrefix + reqHost
			// Match JSON string values that are root-relative paths.
			// e.g.: "scope": "/" → "scope": "/__sd__/host.com/"
			//       "start_url": "/app/" → "start_url": "/__sd__/host.com/app/"
			rewritten = manifestRootRelativeRe.ReplaceAllStringFunc(rewritten, func(m string) string {
				sub := manifestRootRelativeRe.FindStringSubmatch(m)
				if len(sub) < 3 {
					return m
				}
				key, path := sub[1], sub[2]
				if strings.HasPrefix(path, subdomainPrefix) {
					return m
				}
				return key + `"` + sdPfx + path + `"`
			})
		}

		// Pass 2b: strip SRI integrity attributes from HTML.
		// When string replacements are active, modified script/stylesheet bytes
		// will no longer match the integrity hash, causing the browser to block
		// the resource.  Stripping the attribute lets the browser load the
		// (possibly rewritten) content without the SRI check.
		// We strip unconditionally for HTML responses: even URL-only rewrites in
		// the HTML page itself change the document bytes, and any proxied asset
		// might have been rewritten if the replacer has active pairs.
		if strings.HasPrefix(contentType, "text/html") {
			rewritten = sriIntegrityRe.ReplaceAllString(rewritten, "")
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
		// Remove Transfer-Encoding: chunked — the body is now a known-length
		// buffer.  RFC 7230 §3.3: if both Transfer-Encoding and Content-Length
		// are present, Transfer-Encoding takes precedence, so we must delete it
		// or browsers would try to parse our plain body as chunked frames.
		resp.Header.Del("Transfer-Encoding")

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
		Transport:      rt,
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
