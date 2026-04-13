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

Options:
  -target       <host>     Upstream host (required, no scheme — HTTPS by default)
  -replace      <pairs>    Comma-separated original:alias pairs (e.g. ctf:acme,ctfd:foo)
  -replace-file <path>     File with one original:alias pair per line (# comments ok)
  -insecure                Connect to upstream over plain HTTP instead of HTTPS
  -skip-verify             Skip TLS certificate verification (self-signed certs)
  -ci                      Case-insensitive string replacement
  -exact-domain            Only mask the exact target host, not subdomains
  -timeout      <duration> Upstream dial/TLS/response-header timeout (default: 30s)
  -drain        <duration> Grace period for in-flight requests on Ctrl+C (default: 15s)
  -verbose                 Log every request/response with full headers and body preview
  -log          <path>     Append log output to file in addition to stderr
  -port         <n>        Local port (default: 8080)
  -listen       <addr>     Local bind address (default: 0.0.0.0)
```

## Example

```bash
# HTTPS upstream (default)
maskproxy -target ctf.io -replace ctf:acme,ctfd:foo

# Load pairs from a file (one per line, # comments ok)
maskproxy -target ctf.io -replace-file pairs.txt

# Self-signed certificate
maskproxy -target ctf.io -replace ctf:acme,ctfd:foo -skip-verify

# Plain HTTP upstream
maskproxy -target ctf.io -replace ctf:acme,ctfd:foo -insecure

# Show full request/response details and save to a log file
maskproxy -target ctf.io -replace ctf:acme,ctfd:foo -verbose -log proxy.log
```

| Direction | What happens |
|-----------|-------------|
| Request `localhost:8080/blabla/acme?q=foo` | Forwarded as `https://ctf.io/blabla/ctf?q=ctfd` |
| Response body `"Hello from ctfd and ctf"` | Delivered as `"Hello from foo and acme"` |

## Replacement rules

- `-replace ctf:acme,ctfd:foo` means **original:alias**.
- **Outbound requests** (client → upstream): alias → original  
- **Inbound responses** (upstream → client): original → alias  
- Pairs are applied **longest-key-first** to prevent partial-match bugs  
  (e.g. `ctfd` is always matched before `ctf`).
- Only **text** content types are rewritten. Binary responses (images, fonts, etc.) pass through unchanged to avoid corruption.
- **gzip-compressed** responses are transparently decompressed, rewritten, and forwarded as plain text.

## Design notes

- No external dependencies — stdlib only (`net/http/httputil`).
- `Content-Length` is recalculated after every body rewrite.
- `Accept-Encoding` on outbound requests is limited to `gzip, identity` so only encodings the proxy can handle reach the upstream.
- `X-Forwarded-For` from the client is stripped to prevent header injection.
- **WebSocket** connections are transparently proxied (upgraded through `httputil.ReverseProxy` with `FlushInterval=-1`). WS frames are binary-framed and therefore not string-replaced — the upgrade is logged as `WS↑`.
- **Graceful shutdown**: Ctrl+C / SIGTERM drain in-flight requests for up to `-drain` seconds before exiting.
- **Replacement count** is logged on every request/response line so you can confirm replacements are firing without enabling `-verbose`.
- **Upstream timeouts** (`-timeout`) guard against hung upstreams: covers TCP dial, TLS handshake, and response-header wait phases independently.
- **`-replace-file`** lets you maintain replacement pairs in a text file with comments, avoiding shell quoting headaches for large pair sets.
