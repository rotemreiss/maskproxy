# maskproxy

A lightweight, transparent rewriting reverse proxy written in Go.  
It forwards local HTTP traffic to a remote host and rewrites configurable strings bidirectionally — aliases in the client view, originals on the wire.

## Install

**From GitHub (no clone needed):**

```bash
go install github.com/rotemreiss/maskproxy@latest
```

The binary will be placed in `$(go env GOPATH)/bin/maskproxy` (typically `~/go/bin/maskproxy`).  
Make sure that directory is in your `$PATH`.

**Build from source:**

```bash
git clone https://github.com/rotemreiss/maskproxy.git
cd maskproxy
go build -o maskproxy .
```

## Usage

```
maskproxy -target <host> [options]
```

### Required

| Flag | Description |
|------|-------------|
| `-target <host>` | Upstream host to proxy to. No scheme — HTTPS is used by default. |

### Replacement

| Flag | Description |
|------|-------------|
| `-replace <pairs>` | Comma-separated `original:alias` pairs, e.g. `ctf:acme,ctfd:foo`. |
| `-replace-file <path>` | File with one `original:alias` pair per line (`#` comments and blank lines ignored). Combined with `-replace`; CLI pairs win on conflict. |
| `-ignore-host <hosts>` | Comma-separated upstream hostnames to exclude from all rewriting. Supports wildcard prefix `*.domain.com` to match any subdomain. Traffic still flows through the proxy but bodies and headers are passed through unchanged. Useful to protect hosts whose JS bundles contain strings that must not be touched (e.g. OAuth scope IDs). Repeatable. |
| `-cs` | Case-sensitive matching. Default is case-insensitive (`Microsoft`, `MICROSOFT`, `microsoft` all match). |

### Upstream connection

| Flag | Description |
|------|-------------|
| `-insecure` | Connect to upstream over plain HTTP instead of HTTPS. |
| `-skip-verify` | Skip TLS certificate verification (for self-signed certs). |
| `-exact-domain` | Only mask the literal `-target` host. By default all subdomains of the target's root domain are also masked. |
| `-timeout <duration>` | Timeout for dial, TLS handshake, and response headers (default: `30s`). |

### Requests

| Flag | Description |
|------|-------------|
| `-header <h>` | Add/override a header on every upstream request. Format: `"Name: Value"`. Repeatable. |

### Listening

| Flag | Description |
|------|-------------|
| `-port <n>` | Local port to listen on (default: `8080`). |
| `-listen <addr>` | Local bind address (default: `0.0.0.0`). Use `127.0.0.1` to restrict to loopback. |

### Logging

| Flag | Description |
|------|-------------|
| `-verbose` | Log every request/response with full headers and a body preview. Sensitive headers are redacted. |
| `-ws-no-log` | Suppress WebSocket frame logging. By default every WS frame opcode and payload length is logged to stderr. |
| `-log <path>` | Append all log output to a file in addition to stderr. |
| `-max-body <n>` | Maximum body size (MiB) to buffer for rewriting (default: `50`). Bodies larger than this are forwarded unchanged. Increase for large HTML pages; decrease to reduce memory usage. |
| `-drain <duration>` | Grace period to drain in-flight requests on Ctrl+C / SIGTERM (default: `15s`). |

## Examples

```bash
# HTTPS upstream — rewrite ctf↔acme and ctfd↔foo
maskproxy -target ctf.io -replace ctf:acme,ctfd:foo

# Load replacement pairs from a file
maskproxy -target ctf.io -replace-file pairs.txt

# Self-signed certificate
maskproxy -target ctf.io -replace ctf:acme,ctfd:foo -skip-verify

# Plain HTTP upstream
maskproxy -target ctf.io -replace ctf:acme,ctfd:foo -insecure

# Verbose logging to a file, loopback only, port 9001
maskproxy -target ctf.io -replace ctf:acme,ctfd:foo -verbose -log proxy.log -listen 127.0.0.1 -port 9001

# Exclude an auth host and a wildcard CDN domain from rewriting
maskproxy -target microsoft.com -replace microsoft:msctf \
  -ignore-host login.microsoftonline.com -ignore-host "*.bbci.co.uk"
```

| Direction | Example |
|-----------|---------|
| Request `localhost:8080/blabla/acme?q=foo` | Forwarded as `https://ctf.io/blabla/ctf?q=ctfd` |
| Response body `"Hello from ctfd and ctf"` | Delivered as `"Hello from foo and acme"` |

## Replacement behaviour

- `-replace ctf:acme,ctfd:foo` means **original:alias**.
- **Outbound requests** (client → upstream): alias → original
- **Inbound responses** (upstream → client): original → alias
- Pairs are applied **longest-key-first** to prevent partial-match bugs (`ctfd` is always matched before `ctf`).
- Only **text** content types are rewritten. Binary responses (images, fonts, etc.) pass through unchanged.
- **gzip/deflate-compressed** responses are transparently decompressed, rewritten, and forwarded as plain text.

## Design notes

- No external dependencies — stdlib only (`net/http/httputil`).
- `Content-Length` is recalculated after every body rewrite.
- `Accept-Encoding` on outbound requests is limited to `gzip, deflate, identity` so only supported encodings reach the upstream.
- `X-Forwarded-For` from the client is stripped to prevent header injection.
- **Conditional requests** (`If-None-Match`, `If-Modified-Since`, `If-Match`, etc.) are stripped outbound and `ETag`/`Last-Modified` are stripped from responses, ensuring upstream always returns a full body that goes through rewriting.
- **HSTS, key-pinning, Report-To, NEL, COOP, COEP, CORP, and Clear-Site-Data headers** are stripped so the browser never locks on to the upstream's security policy or sends telemetry to upstream endpoints.
- **SRI `integrity` attributes** are stripped from HTML `<script>` and `<link>` tags, and `integrity=` parameters are stripped from `Link` response headers — after string replacement the precomputed hash is stale.
- **`__Host-`/`__Secure-` cookie name prefixes** are stripped when the proxy runs on plain HTTP, since those prefixes require the `Secure` attribute that we must remove.
- **Service-Worker-Allowed** response header is stripped to prevent a service worker registered under `/__sd__/<host>/` from claiming the entire proxy origin.
- **`text/event-stream` (SSE)** responses are streamed directly without buffering — headers are still rewritten.
- **WebSocket** connections are transparently proxied. WS frames are not string-replaced (binary framing), but opcodes and payload lengths are logged to stderr by default (`-ws-no-log` suppresses this).
- **Subdomain routing**: upstream subdomains are encoded as `/__sd__/<subdomain>/path` in the proxy URL so the browser never needs to know about them directly.
- **SSRF guard**: only subdomains of the configured root domain are allowed through `/__sd__/`; hostnames containing `@` or path separators are rejected with HTTP 400.
- **Graceful shutdown**: Ctrl+C / SIGTERM drains in-flight requests for up to `-drain` seconds before exiting.
- **Replacement count** is logged on every request/response line so you can confirm replacements are firing without enabling `-verbose`.
