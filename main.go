package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

const usage = `maskproxy — a transparent rewriting reverse proxy

Usage:
  maskproxy -target <host> [options]

Options:
  -target       <host>     Upstream host to proxy traffic to (required).
                           Do NOT include a scheme — HTTPS is used by default.
                           Use -insecure to connect over plain HTTP instead.
  -replace      <pairs>    Comma-separated list of original:alias pairs.
                           Aliases are used by the client; originals are sent
                           to the upstream server.
                           Example: ctf:acme,ctfd:foo
  -replace-file <path>     Path to a file with one original:alias pair per line.
                           Lines starting with '#' and blank lines are ignored.
                           Combined with any -replace pairs (CLI pairs win on conflict).
  -ignore-host  <hosts>    Comma-separated list of upstream hostnames to exclude
                            from all proxy rewriting (repeatable).
                            Wildcard prefix "*.domain.com" matches any subdomain.
                            Traffic to these hosts still flows through the proxy
                            but bodies and headers are passed through unchanged:
                            no host masking, no string replacement.
                            Security-critical headers (HSTS, key pinning) and
                            Set-Cookie cleanup still run for ignored hosts.
                            Use this to protect hosts whose responses contain
                            library-internal strings (e.g. OAuth scope IDs in
                            an MSAL bundle) that must not be touched.
                            Example: -ignore-host login.microsoftonline.com
                                     -ignore-host "*.bbci.co.uk,cdn.example.com"
  -header       <h>        Add a header to every upstream request (repeatable).
                           Format: "Name: Value". Overrides same-named client headers.
                           Example: -header "X-Author: Rotem" -header "X-Token: abc"
  -insecure                Connect to the upstream over plain HTTP (no TLS).
                           Default is HTTPS.
  -skip-verify             Skip TLS certificate verification for the upstream.
                           Use this when the target has a self-signed certificate.
  -cs                      Case-sensitive string replacement.
                           By default replacements are case-insensitive and match
                           "Microsoft", "MICROSOFT", "microsoft", etc.
                           Use -cs to match only the exact case you specify.
  -exact-domain            Only mask the exact target host.
                           By default maskproxy also masks every subdomain of the
                           target's root domain (api.*, cdn.*, auth.*, …) so
                           no subdomain leaks to the client.  Use -exact-domain
                           to restrict masking to the literal -target host only.
  -timeout      <duration> Timeout for upstream dial, TLS handshake and response
                           headers (default: 30s). Set 0 to disable.
  -drain        <duration> Grace period for in-flight requests on Ctrl+C/SIGTERM
                           (default: 15s).
  -verbose                 Log every request and response with full headers and
                           a body preview (first 4 KiB).  Sensitive headers
                           (Authorization, Cookie, Set-Cookie) are redacted.
  -ws-no-log               Suppress WebSocket frame logging.
                           By default every WS frame opcode and payload length
                           is logged to stderr so you can observe WS traffic.
                           Use this flag to silence that output.
  -log          <path>     Append all log output to <path> in addition to stderr.
                           Works with both normal and -verbose mode.
  -port         <n>        Local port to listen on (default: 8080).
  -listen       <addr>     Local listen address (default: 0.0.0.0).
                           Use "127.0.0.1" to restrict to loopback only.

Examples:
  # Proxy localhost:8080 → https://ctf.io, rewriting ctf↔acme and ctfd↔foo
  maskproxy -target ctf.io -replace ctf:acme,ctfd:foo

  # Load replacement pairs from a file
  maskproxy -target ctf.io -replace-file pairs.txt

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

// headerFlag is a repeatable -header flag value.  Each call to Set appends one
// "Name: Value" entry.  flag.Var registers it so the user can write:
//
//	-header "X-Author: Rotem" -header "X-Token: secret"
type headerFlag []string

func (h *headerFlag) String() string { return strings.Join(*h, ", ") }
func (h *headerFlag) Set(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("header value must not be empty")
	}
	*h = append(*h, s)
	return nil
}

// ignoreHostFlag is a repeatable -ignore-host flag value.  Each call to Set
// appends one or more comma-separated hostnames.
type ignoreHostFlag []string

func (f *ignoreHostFlag) String() string { return strings.Join(*f, ", ") }
func (f *ignoreHostFlag) Set(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("ignore-host value must not be empty")
	}
	*f = append(*f, s)
	return nil
}

func main() {
	target := flag.String("target", "", "Upstream host (required, no scheme)")
	replace := flag.String("replace", "", "Comma-separated original:alias pairs, e.g. ctf:acme,ctfd:foo")
	replaceFile := flag.String("replace-file", "", "File with one original:alias pair per line (# comments ok)")
	insecure := flag.Bool("insecure", false, "Use plain HTTP for the upstream (no TLS)")
	skipVerify := flag.Bool("skip-verify", false, "Skip TLS certificate verification (for self-signed certs)")
	cs := flag.Bool("cs", false, "Case-sensitive string replacement (default is case-insensitive)")
	exactDomain := flag.Bool("exact-domain", false, "Only mask the exact target host, not subdomains")
	timeout := flag.Duration("timeout", 30*time.Second, "Upstream dial/TLS/response-header timeout (0 = no timeout)")
	verbose := flag.Bool("verbose", false, "Log full request/response headers and body preview")
	wsNoLog := flag.Bool("ws-no-log", false, "Suppress WebSocket frame logging (frames are logged by default)")
	logFile := flag.String("log", "", "Append log output to this file in addition to stderr")
	port := flag.Int("port", 8080, "Local port to listen on")
	listen := flag.String("listen", "0.0.0.0", "Local listen address")
	drain := flag.Duration("drain", 15*time.Second, "Grace period for in-flight requests on SIGINT/SIGTERM")
	var headers headerFlag
	flag.Var(&headers, "header", `Add a header to every upstream request (repeatable). Format: "Name: Value". Example: -header "X-Author: Rotem"`)
	var ignoreHosts ignoreHostFlag
	flag.Var(&ignoreHosts, "ignore-host", `Exclude hosts from all proxy rewriting (comma-separated, repeatable). Wildcard "*.domain.com" matches any subdomain. Example: -ignore-host "*.bbci.co.uk,login.microsoftonline.com"`)

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

	// Build the combined replacement spec: -replace-file pairs first (lower
	// priority), then -replace pairs (higher priority / override on conflict).
	combinedSpec := *replace
	if *replaceFile != "" {
		fileSpec, err := loadReplaceFile(*replaceFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: -replace-file: %v\n", err)
			os.Exit(1)
		}
		if fileSpec != "" && combinedSpec != "" {
			combinedSpec = fileSpec + "," + combinedSpec
		} else if fileSpec != "" {
			combinedSpec = fileSpec
		}
	}

	rep, err := NewReplacer(combinedSpec, !*cs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid replacement pairs: %v\n", err)
		os.Exit(1)
	}

	// Parse and validate -header flags into headerPair structs.
	// Parsing happens once here (not per-request) for efficiency.
	extraHeaders, err := parseHeaders(headers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: -header: %v\n", err)
		os.Exit(1)
	}

	// Parse and validate -ignore-host flags into a lowercase set.
	ignoredHostsMap, err := parseIgnoreHosts(ignoreHosts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: -ignore-host: %v\n", err)
		os.Exit(1)
	}

	logger, closeLog, err := NewLogger(*verbose, !*wsNoLog, *logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer closeLog()

	scheme := "https"
	if *insecure {
		scheme = "http"
	}

	pAddr := proxyAddr(*listen, *port)
	proxy := NewReverseProxy(*target, scheme, rep, *skipVerify, pAddr, *exactDomain, *timeout, logger, extraHeaders, ignoredHostsMap)

	addr := fmt.Sprintf("%s:%d", *listen, *port)
	logger.Printf("maskproxy listening on http://%s", addr)
	logger.Printf("  → upstream: %s://%s", scheme, *target)
	if rep.HasPairs() {
		logger.Printf("  → replacements: %s", combinedSpec)
		if *cs {
			logger.Printf("  → replacement mode: case-sensitive (-cs)")
		}
	}
	if len(extraHeaders) > 0 {
		for _, h := range extraHeaders {
			// Redact values for well-known sensitive header names so that tokens
			// don't appear in log files when -log is active.
			val := h.value
			nameLower := strings.ToLower(h.name)
			if nameLower == "authorization" || nameLower == "cookie" || strings.Contains(nameLower, "token") || strings.Contains(nameLower, "secret") || strings.Contains(nameLower, "key") {
				val = "<redacted>"
			}
			logger.Printf("  → extra header: %s: %s", h.name, val)
		}
	}
	if len(ignoredHostsMap) > 0 {
		// Collect and sort for deterministic output.
		// Dot-prefixed keys are wildcard entries — restore "*.domain" display form.
		sorted := make([]string, 0, len(ignoredHostsMap))
		for h := range ignoredHostsMap {
			if strings.HasPrefix(h, ".") {
				sorted = append(sorted, "*"+h)
			} else {
				sorted = append(sorted, h)
			}
		}
		sort.Strings(sorted)
		logger.Printf("  → ignored hosts (no rewriting): %s", strings.Join(sorted, ", "))
	}
	if *exactDomain {
		logger.Printf("  → subdomain masking: disabled (-exact-domain)")
	} else {
		root := computeRootDomain(*target)
		if root != *target {
			logger.Printf("  → subdomain masking: *.%s → proxy", root)
		} else {
			logger.Printf("  → subdomain masking: *.%s → proxy", *target)
		}
	}
	if *timeout > 0 {
		logger.Printf("  → upstream timeout: %s", *timeout)
	}
	if *verbose {
		logger.Printf("  → verbose logging enabled")
	}
	if *wsNoLog {
		logger.Printf("  → WebSocket frame logging: disabled (-ws-no-log)")
	}
	if *logFile != "" {
		logger.Printf("  → log file: %s", *logFile)
	}

	// Use http.Server instead of http.ListenAndServe so we can call Shutdown.
	// On SIGINT (Ctrl+C) or SIGTERM the server stops accepting new connections
	// and waits up to -drain seconds for in-flight requests to complete before
	// the process exits.
	srv := &http.Server{
		Addr:    addr,
		Handler: proxy,
		// ReadHeaderTimeout guards against Slowloris-style attacks on the proxy
		// itself (clients that never finish sending headers).
		ReadHeaderTimeout: 30 * time.Second,
	}

	// Run the server in a goroutine so the main goroutine can block on signals.
	serverErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
		close(serverErr)
	}()

	// Block until SIGINT/SIGTERM or the server exits on its own.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if err != nil {
			logger.Fatal("maskproxy: %v", err)
		}
	case sig := <-quit:
		logger.Printf("maskproxy: received %v — shutting down (drain: %s)", sig, *drain)
		ctx, cancel := context.WithTimeout(context.Background(), *drain)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			logger.Printf("maskproxy: shutdown error: %v", err)
		} else {
			logger.Printf("maskproxy: shutdown complete")
		}
	}
}

// proxyAddr returns the host:port string that clients use to reach the proxy.
// When bound to 0.0.0.0 (all interfaces), "localhost" is used as the
// client-visible hostname because that is what browsers send in Referer/Origin.
func proxyAddr(listenAddr string, port int) string {
	host := listenAddr
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = "localhost"
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// parseHeaders converts the raw "-header Name: Value" strings collected by
// headerFlag into []headerPair, validating each entry.
//
// Validation:
//   - "Name: Value" format required (SplitN on first ":")
//   - Name must be a valid HTTP header token (non-empty, no control chars)
//   - Name is normalised with http.CanonicalHeaderKey
//   - Hop-by-hop headers are rejected (they are transport-managed)
//   - Value must be non-empty after trimming
func parseHeaders(raw []string) ([]headerPair, error) {
	pairs := make([]headerPair, 0, len(raw))
	for _, s := range raw {
		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format %q — expected \"Name: Value\"", s)
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if name == "" {
			return nil, fmt.Errorf("header name must not be empty in %q", s)
		}
		if value == "" {
			return nil, fmt.Errorf("header value must not be empty in %q", s)
		}
		// Reject characters that are illegal in HTTP header names (RFC 7230 token).
		for _, c := range name {
			if c <= 32 || c >= 127 || strings.ContainsRune(`"(),/:;<=>?@[\]{}`, c) {
				return nil, fmt.Errorf("header name %q contains invalid character %q", name, c)
			}
		}
		// Reject CRLF injection in values.
		if strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("header value for %q contains illegal CR or LF", name)
		}
		name = http.CanonicalHeaderKey(name)
		if hopByHopHeaders[name] {
			return nil, fmt.Errorf("header %q is a hop-by-hop header and cannot be injected", name)
		}
		pairs = append(pairs, headerPair{name: name, value: value})
	}
	return pairs, nil
}

// parseIgnoreHosts converts the raw "-ignore-host" strings (each may be a
// comma-separated list) into a lowercase hostname set for O(1) exact lookup
// and O(n) wildcard suffix lookup.
//
// Two entry kinds are accepted:
//   - Exact hostname: "login.microsoftonline.com" — stored as-is (lowercased).
//   - Wildcard:       "*.bbci.co.uk"              — stored as ".bbci.co.uk"
//     (leading dot) so isIgnoredHost can match any subdomain via HasSuffix.
//
// Validation:
//   - Each token must be a bare hostname, "*.domain" wildcard, or host:port.
//   - No scheme (e.g. https://), no path, no spaces.
//   - Ports are stripped at parse time: "login.microsoft.com:443" → "login.microsoft.com".
//   - All keys are lowercased so lookups are case-insensitive.
//   - Empty tokens (e.g. trailing commas) are silently skipped.
func parseIgnoreHosts(raw []string) (map[string]bool, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	result := make(map[string]bool)
	for _, entry := range raw {
		for _, token := range strings.Split(entry, ",") {
			host := strings.TrimSpace(token)
			if host == "" {
				continue
			}
			// Reject obvious scheme or path presence.
			if strings.Contains(host, "://") {
				return nil, fmt.Errorf("ignore-host %q must not include a scheme (use the bare hostname)", host)
			}
			if strings.ContainsAny(host, "/ ") {
				return nil, fmt.Errorf("ignore-host %q must be a hostname (no path or spaces)", host)
			}
			// Handle wildcard prefix: "*.bbci.co.uk" → store as ".bbci.co.uk"
			// isIgnoredHost detects dot-prefixed entries and uses HasSuffix matching.
			if strings.HasPrefix(host, "*.") {
				suffix := host[1:] // strip "*", keep leading "."
				result[strings.ToLower(suffix)] = true
				continue
			}
			// Strip port so that "host:443" and "host" both normalise to "host".
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			result[strings.ToLower(host)] = true
		}
	}
	return result, nil
}


// loadReplaceFile reads a replacement-pairs file and returns a comma-separated
// spec string suitable for NewReplacer.
//
// File format (one pair per line):
//
//	# This is a comment — ignored
//	ctf:acme
//	ctfd:foo
//
// Blank lines and lines starting with '#' are ignored.
// Inline '#' comments (after a pair) are also stripped.
func loadReplaceFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot open %q: %w", path, err)
	}
	defer f.Close()

	var pairs []string
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Strip inline comment.
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Validate format early so the error message references the file+line.
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return "", fmt.Errorf("%s:%d: invalid pair %q (expected non-empty original:alias)", path, lineNum, line)
		}
		pairs = append(pairs, strings.TrimSpace(parts[0])+":"+strings.TrimSpace(parts[1]))
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("reading %q: %w", path, err)
	}
	return strings.Join(pairs, ","), nil
}
