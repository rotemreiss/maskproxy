# Changelog

All notable changes to maskproxy are documented here.

## [v1.6.0] — 2026-04-14

### New Features
- **`-no-ui` flag** — explicitly disables the built-in traffic inspection UI without needing to remember `-ui-port 0`. Use when you don't need the UI and want to avoid binding an extra port.
- **ngrok-style startup banner** — replaces the flat log-line dump with a framed summary printed to stderr. The banner shows the Proxy URL, Target URL, and UI URL (or omits it when disabled) at a glance, followed by an optional config section (replacements, ignored hosts, also-proxy domains, active flags). The config section is omitted entirely for simple invocations so the output stays clean.

### Improvements
- `0.0.0.0` is substituted with `localhost` in the banner URLs so the links are immediately clickable.
- A single compact machine-readable log line is still written via the logger (for `-log` file consumers): `maskproxy v1.5.0 started  proxy=…  target=…  ui=…`
- Added `version` constant (`"1.5.0"`) to the codebase; version appears in the banner and the log line.

### Documentation
- Updated README with `-no-ui` flag, startup banner section (with example output), and updated traffic inspection UI section.
- Updated `-port`/`-listen` usage string with new `-ui-port`/`-no-ui` entries.

---



### New Features
- **Alias minimum-length enforcement** — the proxy now refuses to start if any alias is shorter than 5 Unicode characters. Short aliases like `ing`, `com`, `api` appear as substrings in countless URLs and request bodies; allowing them would silently corrupt unrelated traffic (e.g. `-replace microsoft:ing` would turn `/loading.js` into `/loaMicrosoftg.js`). The startup error message includes a concrete corruption example and the offending alias.
- **Runtime embedded-word stability warning** — on the first request where an alias is found embedded inside a larger alphanumeric word in the URL path/query, a warning is printed to the proxy console **and** recorded in the UI's `/api/config` response (`stabilityWarnings` array). This catches cases where a ≥5-char alias is still too common (e.g. `loading` embedded in `/preloading.js`).

### Bug Fixes
- **Stability warning `sync.Once` logic corrected** — the embedded-word check previously used `sync.Once` per alias, which was consumed on the very first request regardless of whether the URL embedded the alias. If the first proxied URL was `/` or `/favicon.ico` the `Once` was spent and all subsequent warnings were silently dropped forever. Fixed by using `atomic.Bool` CAS so the check runs on every request until the first match fires, then permanently suppresses further warnings for that alias.
- **Alias length check uses Unicode code-point count** — the minimum-length validation now uses `utf8.RuneCountInString` instead of `len()` (byte count), so multi-byte Unicode aliases are measured in characters, not bytes.

### Tests
- `TestStabilityWarningFiredAfterNonMatchingRequests` — regression test for the `sync.Once` bug: sends multiple non-embedding requests first, then verifies the warning fires on the first embedding request.
- `TestMinAliasLenValidation` updated — added a Unicode test case (`"niño"` = 4 code points, 5 bytes) to verify rune-count validation.
- Total test count: **209**.

---

## [v1.4.0] — 2026-04-13

### New Features
- **Traffic Inspection UI** (`-ui-port`) — a built-in HTTP dashboard that streams every proxied request/response in real time via SSE. Shows method, status, URL, headers (original vs rewritten), body replacement count, and timing. Access at `http://localhost:<ui-port>`.
- **`-also-proxy` flag** — route additional upstream hostnames through the proxy alongside the main `-target`. Useful for CDN subdomains (e.g. `*.bbci.co.uk` for a BBC proxy).
- **`-ignore-host` flag** — pass specific upstream hosts through unmodified (no rewriting), useful for auth endpoints that must not be touched.
- **`-header` flag** — inject custom headers into every upstream request.
- **`-verbose` flag** — enable detailed per-request logging.
- **`-max-body` flag** — limit response body size eligible for string rewriting (default 50 MB).

### Bug Fixes
- **Context-threading fix** — transaction and timing state is now threaded through `context.WithValue` in the Director (not `sync.Map` keyed by `*http.Request`). Go's `httputil.ReverseProxy` calls `req.WithContext` internally after the Director, creating a new pointer; a `sync.Map` keyed by the old pointer would silently drop all state.
- **UI server binds to `-listen` address** — previously the UI server always bound to `0.0.0.0` regardless of the `-listen` flag.
- **CORS wildcard removed** from UI server.
- **`-ignore-host` example in README** corrected — was incorrectly showing a BBC domain in a Microsoft proxy example.

---

## [v1.3.0] — 2026-04-13

### New Features
- **SSRF hardening** — `localhost` and RFC-1918 addresses are blocked as proxy targets.
- **Port validation** — listen port range enforced (1–65535).
- **Subdomain routing** (`/__sd__/<host>/...`) — transparent rewriting of subresources served from CDN subdomains.

### Bug Fixes
- Path corruption fix for assets with URL-encoded characters.
- Redirect port fix (preserves proxy listen port in Location headers).

---

## [v1.2.0] — 2026-04-13

### New Features
- **BBC font CDN fix** — `/__sd__/` URL paths are protected from string replacement to prevent CDN filename corruption.
- **GitHub CSP fix** — `Content-Security-Policy` and `HSTS` headers stripped on proxied responses.

---

## [v1.1.0] — 2026-04-13

### New Features
- **Subdomain masking** — rewrites absolute URLs in HTML, CSS, and JS to route all subresource requests through the proxy.
- Bidirectional replacement: aliases→originals in requests, originals→aliases in responses.
- `srcset`, `importmap`, and speculation-rules rewriting.

---

## [v1.0.0] — 2026-04-13

Initial release — basic rewriting reverse proxy with:
- `-target`, `-replace`, `-ssl`, `-listen`, `-skip-verify` flags.
- Collision-safe replacement (sorted by length descending).
- gzip/deflate/zlib decompression before body rewriting.
- Binary content protection (rewriting only applied to text MIME types).
- `Content-Length` recalculation after body rewrite.
