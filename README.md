# ctfproxy

A lightweight, transparent rewriting reverse proxy written in Go.  
It forwards local HTTP traffic to a remote host and rewrites configurable strings bidirectionally — aliases in the client view, originals on the wire.

## Build

```bash
go build -o ctfproxy .
```

## Usage

```
ctfproxy -target <host> [options]

Options:
  -target  <host>   Upstream host (required, no scheme)
  -replace <pairs>  Comma-separated original:alias pairs (e.g. ctf:acme,ctfd:foo)
  -ssl              Use HTTPS for the upstream target
  -port    <n>      Local port (default: 8080)
  -listen  <addr>   Local bind address (default: 0.0.0.0)
```

## Example

```bash
./ctfproxy -target ctf.io -replace ctf:acme,ctfd:foo -ssl
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
