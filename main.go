package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
)

const usage = `maskproxy — a transparent rewriting reverse proxy

Usage:
  maskproxy -target <host> [options]

Options:
  -target      <host>    Upstream host to proxy traffic to (required).
                         Do NOT include a scheme — HTTPS is used by default.
                         Use -insecure to connect over plain HTTP instead.
  -replace     <pairs>   Comma-separated list of original:alias pairs.
                         Aliases are used by the client; originals are sent
                         to the upstream server.
                         Example: ctf:acme,ctfd:foo
  -insecure              Connect to the upstream over plain HTTP (no TLS).
                         Default is HTTPS.
  -skip-verify           Skip TLS certificate verification for the upstream.
                         Use this when the target has a self-signed certificate.
  -ci                    Case-insensitive string replacement.
                         Matches "Microsoft", "MICROSOFT", "microsoft", etc.
  -exact-domain          Only mask the exact target host.
                         By default maskproxy also masks every subdomain of the
                         target's root domain (api.*, cdn.*, auth.*, …) so
                         no subdomain leaks to the client.  Use -exact-domain
                         to restrict masking to the literal -target host only.
  -verbose               Log every request and response with full headers and
                         a body preview (first 4 KiB).  Sensitive headers
                         (Authorization, Cookie, Set-Cookie) are redacted.
  -log         <path>    Append all log output to <path> in addition to stderr.
                         Works with both normal and -verbose mode.
  -port        <n>       Local port to listen on (default: 8080).
  -listen      <addr>    Local listen address (default: 0.0.0.0).
                         Use "127.0.0.1" to restrict to loopback only.

Examples:
  # Proxy localhost:8080 → https://ctf.io, rewriting ctf↔acme and ctfd↔foo
  maskproxy -target ctf.io -replace ctf:acme,ctfd:foo

  # Same but skip TLS certificate verification (self-signed cert)
  maskproxy -target ctf.io -replace ctf:acme,ctfd:foo -skip-verify

  # Connect to an HTTP-only upstream
  maskproxy -target ctf.io -replace ctf:acme,ctfd:foo -insecure

  # Show full request/response details and persist to a log file
  maskproxy -target ctf.io -replace ctf:acme,ctfd:foo -verbose -log proxy.log

  # Listen only on loopback, port 9090
  maskproxy -target ctf.io -replace ctf:acme,ctfd:foo -port 9090 -listen 127.0.0.1

Replacement behaviour:
  Outbound requests  (client → upstream): aliases  are rewritten to originals.
  Inbound  responses (upstream → client): originals are rewritten to aliases.

  Pairs are applied longest-first to prevent partial-match bugs
  (e.g. "ctfd" is always matched before "ctf").
`

func main() {
	target := flag.String("target", "", "Upstream host (required, no scheme)")
	replace := flag.String("replace", "", "Comma-separated original:alias pairs, e.g. ctf:acme,ctfd:foo")
	insecure := flag.Bool("insecure", false, "Use plain HTTP for the upstream (no TLS)")
	skipVerify := flag.Bool("skip-verify", false, "Skip TLS certificate verification (for self-signed certs)")
	ci := flag.Bool("ci", false, "Case-insensitive string replacement (e.g. matches 'Microsoft' and 'MICROSOFT')")
	exactDomain := flag.Bool("exact-domain", false, "Only mask the exact target host, not subdomains")
	verbose := flag.Bool("verbose", false, "Log full request/response headers and body preview")
	logFile := flag.String("log", "", "Append log output to this file in addition to stderr")
	port := flag.Int("port", 8080, "Local port to listen on")
	listen := flag.String("listen", "0.0.0.0", "Local listen address")

	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "error: -target is required")
		fmt.Fprintln(os.Stderr)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	// Strip any scheme the user may have accidentally included (e.g. "https://ctf.io").
	// The scheme is controlled exclusively by the -insecure flag.
	if i := strings.Index(*target, "://"); i >= 0 {
		stripped := (*target)[i+3:]
		fmt.Fprintf(os.Stderr, "warning: scheme stripped from -target; using %q\n", stripped)
		*target = stripped
	}
	if strings.ContainsAny(*target, " /") {
		fmt.Fprintln(os.Stderr, "error: -target must be a host (and optional port), e.g. ctf.io or ctf.io:8443")
		os.Exit(1)
	}

	rep, err := NewReplacer(*replace, *ci)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid -replace value: %v\n", err)
		os.Exit(1)
	}

	logger, closeLog, err := NewLogger(*verbose, *logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer closeLog()

	scheme := "https"
	if *insecure {
		scheme = "http"
	}

	proxy := NewReverseProxy(*target, scheme, rep, *skipVerify, proxyAddr(scheme, *listen, *port), *exactDomain, logger)

	addr := fmt.Sprintf("%s:%d", *listen, *port)
	logger.Printf("maskproxy listening on http://%s", addr)
	logger.Printf("  → upstream: %s://%s", scheme, *target)
	if rep.HasPairs() {
		logger.Printf("  → replacements: %s", *replace)
	}
	if *exactDomain {
		logger.Printf("  → subdomain masking: disabled (-exact-domain)")
	} else {
		root := computeRootDomain(*target)
		if root != *target {
			logger.Printf("  → subdomain masking: *.%s → proxy", root)
		}
	}
	if *verbose {
		logger.Printf("  → verbose logging enabled")
	}
	if *logFile != "" {
		logger.Printf("  → log file: %s", *logFile)
	}

	if err := http.ListenAndServe(addr, proxy); err != nil {
		logger.Fatal("maskproxy: %v", err)
	}
}

// proxyAddr returns the host:port string that clients use to reach the proxy.
// When bound to 0.0.0.0 (all interfaces), "localhost" is used as the
// client-visible hostname because that is what browsers send in Referer/Origin.
func proxyAddr(scheme, listenAddr string, port int) string {
	host := listenAddr
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = "localhost"
	}
	return fmt.Sprintf("%s:%d", host, port)
}
