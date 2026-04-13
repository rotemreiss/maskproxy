package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

const usage = `ctfproxy — a transparent rewriting reverse proxy

Usage:
  ctfproxy -target <host> [options]

Options:
  -target   <host>         Upstream host to proxy traffic to (required).
                           Do NOT include a scheme — use -ssl to choose https.
  -replace  <pairs>        Comma-separated list of original:alias pairs.
                           Aliases are used by the client; originals are sent
                           to the upstream server.
                           Example: ctf:acme,ctfd:foo
  -ssl                     Use HTTPS when connecting to the upstream target.
  -insecure                Skip TLS certificate verification for the upstream.
                           Use this when the target has a self-signed certificate.
  -ci                      Case-insensitive string replacement.
                           Matches "Microsoft", "MICROSOFT", "microsoft", etc.
  -exact-domain            Only mask the exact target host.
                           By default ctfproxy also masks every subdomain of the
                           target's root domain (api.*, cdn.*, auth.*, …) so
                           no subdomain leaks to the client.  Use -exact-domain
                           to restrict masking to the literal -target host only.
  -port     <n>            Local port to listen on (default: 8080).
  -listen   <addr>         Local listen address (default: 0.0.0.0).
                           Use "127.0.0.1" to restrict to loopback only.

Examples:
  # Proxy localhost:8080 → https://ctf.io, rewriting ctf↔acme and ctfd↔foo
  ctfproxy -target ctf.io -replace ctf:acme,ctfd:foo -ssl

  # Same but allow a self-signed TLS certificate on the upstream
  ctfproxy -target ctf.io -replace ctf:acme,ctfd:foo -ssl -insecure

  # Same but listen only on loopback, port 9090
  ctfproxy -target ctf.io -replace ctf:acme,ctfd:foo -ssl -port 9090 -listen 127.0.0.1

Replacement behaviour:
  Outbound requests  (client → upstream): aliases  are rewritten to originals.
  Inbound  responses (upstream → client): originals are rewritten to aliases.

  Pairs are applied longest-first to prevent partial-match bugs
  (e.g. "ctfd" is always matched before "ctf").
`

func main() {
	target := flag.String("target", "", "Upstream host (required, no scheme)")
	replace := flag.String("replace", "", "Comma-separated original:alias pairs, e.g. ctf:acme,ctfd:foo")
	ssl := flag.Bool("ssl", false, "Use HTTPS for the upstream target")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification (for self-signed certs)")
	ci := flag.Bool("ci", false, "Case-insensitive string replacement (e.g. matches 'Microsoft' and 'MICROSOFT')")
	exactDomain := flag.Bool("exact-domain", false, "Only mask the exact target host, not subdomains")
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
	// The scheme is controlled exclusively by the -ssl flag.
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

	scheme := "http"
	if *ssl {
		scheme = "https"
	}

	proxy := NewReverseProxy(*target, scheme, rep, *insecure, proxyAddr(scheme, *listen, *port), *exactDomain)

	addr := fmt.Sprintf("%s:%d", *listen, *port)
	log.Printf("ctfproxy listening on http://%s", addr)
	log.Printf("  → upstream: %s://%s", scheme, *target)
	if rep.HasPairs() {
		log.Printf("  → replacements: %s", *replace)
	}
	if *exactDomain {
		log.Printf("  → subdomain masking: disabled (-exact-domain)")
	} else {
		root := computeRootDomain(*target)
		if root != *target {
			log.Printf("  → subdomain masking: *.%s → proxy", root)
		}
	}

	if err := http.ListenAndServe(addr, proxy); err != nil {
		log.Fatalf("ctfproxy: %v", err)
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
