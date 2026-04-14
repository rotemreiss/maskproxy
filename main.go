package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// version is the current release version, shown in the startup banner.
const version = "1.5.0"

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
  -also-proxy   <domains>  Comma-separated list of extra domains to route via /__sd__/.
                            Use for CDN/related domains on a different TLD that share
                            content with -target.  Their URLs are rewritten to
                            http://localhost:PORT/__sd__/<host>/ so scripts load through
                            the proxy and receive full string-replacement treatment.
                            Example: -also-proxy bbci.co.uk,bbc.co.uk
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
  -max-body     <n>        Maximum body size in MiB to buffer for rewriting
                           (default: 50 MiB).  Bodies larger than this limit
                           are forwarded unchanged (no string replacement).
                           Increase for large HTML files; decrease to reduce
                           memory pressure on memory-limited hosts.
  -port         <n>        Local port to listen on (default: 8080).
  -listen       <addr>     Local listen address (default: 0.0.0.0).
                           Use "127.0.0.1" to restrict to loopback only.
  -ui-port      <n>        Port for the built-in traffic inspection web UI
                           (default: 4040). Set to 0 to disable the UI.
                           Open http://localhost:<n> to view live traffic,
                           headers, body diffs, and proxy config.
  -no-ui                   Disable the built-in traffic inspection UI entirely.
                           Equivalent to -ui-port 0 but more explicit.
                           Use this when you don't need the UI and want to avoid
                           binding an extra port.

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
	maxBody := flag.Int64("max-body", 50, "Maximum response/request body size to buffer for rewriting, in MiB (0 = default 50 MiB)")
	uiPort := flag.Int("ui-port", 4040, "Port for the traffic inspection UI (0 to disable)")
	noUI := flag.Bool("no-ui", false, "Disable the built-in traffic inspection UI (equivalent to -ui-port 0)")
	var headers headerFlag
	flag.Var(&headers, "header", `Add a header to every upstream request (repeatable). Format: "Name: Value". Example: -header "X-Author: Rotem"`)
	var ignoreHosts ignoreHostFlag
	flag.Var(&ignoreHosts, "ignore-host", `Exclude hosts from all proxy rewriting (comma-separated, repeatable). Wildcard "*.domain.com" matches any subdomain. Example: -ignore-host "*.bbci.co.uk,login.microsoftonline.com"`)
	alsoProxyFlag := flag.String("also-proxy", "", "Comma-separated list of extra domains to route via /__sd__/ (e.g. bbci.co.uk,bbc.co.uk). Use for CDN domains on different TLDs that share content with -target.")
	stripCSP := flag.Bool("strip-csp", false, "Completely remove Content-Security-Policy headers from responses")

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

	// Enforce a minimum alias length of 5 characters (measured in Unicode code
	// points, not bytes, so multi-byte characters are counted correctly).
	// Short aliases (e.g. "ing", "com", "api") are extremely common substrings
	// that appear in URLs, headers, and request bodies.  When the proxy rewrites
	// outbound requests (alias→original) such a short alias will corrupt
	// unrelated content: "loading.js" → "loaMicrosoftg.js".
	// This check runs at startup so the proxy never silently corrupts traffic.
	const minAliasLen = 5
	for _, p := range rep.Pairs() {
		if utf8.RuneCountInString(p.Alias) < minAliasLen {
			fmt.Fprintf(os.Stderr,
				"error: alias %q (for %q) is only %d character(s) long.\n"+
					"  Aliases shorter than %d characters are too common to be unique —\n"+
					"  they will corrupt unrelated URLs and request bodies by replacing\n"+
					"  every occurrence of %q with %q.\n"+
					"  Example: /loading.js would become /lo%sg.js\n"+
					"  Please choose a more unique alias (at least %d characters).\n",
				p.Alias, p.Original, utf8.RuneCountInString(p.Alias), minAliasLen,
				p.Alias, p.Original, p.Original, minAliasLen,
			)
			os.Exit(1)
		}
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

	// Parse -also-proxy domains.
	var alsoProxyDomains []string
	if *alsoProxyFlag != "" {
		for _, d := range strings.Split(*alsoProxyFlag, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				alsoProxyDomains = append(alsoProxyDomains, d)
			}
		}
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
	maxBodyBytes := *maxBody * 1024 * 1024

	// Build UI traffic store (populated via proxy hooks; displayed on -ui-port).
	trafficStore := NewTrafficStore()
	trafficStore.Target = *target
	trafficStore.Replacements = buildReplacementPairs(rep)
	{
		sorted := make([]string, 0, len(ignoredHostsMap))
		for h := range ignoredHostsMap {
			if strings.HasPrefix(h, ".") {
				sorted = append(sorted, "*"+h)
			} else {
				sorted = append(sorted, h)
			}
		}
		sort.Strings(sorted)
		trafficStore.IgnoredHosts = sorted
	}

	proxy := NewReverseProxy(*target, scheme, rep, *skipVerify, pAddr, *exactDomain, *timeout, logger, extraHeaders, ignoredHostsMap, maxBodyBytes, alsoProxyDomains, trafficStore, *stripCSP)

	// addr is the network address the main proxy server binds to.
	addr := fmt.Sprintf("%s:%d", *listen, *port)

	// Determine the UI URL (or empty string if disabled).
	// -no-ui overrides -ui-port; either disables the UI.
	uiEnabled := *uiPort > 0 && !*noUI
	uiAddr := ""
	if uiEnabled {
		uiAddr = fmt.Sprintf("%s:%d", *listen, *uiPort)
	}

	// Build the config rows for the startup banner: only include rows that
	// apply to this invocation (keep the banner clean for simple cases).
	var configRows [][2]string
	if rep.HasPairs() {
		val := combinedSpec
		if *cs {
			val += "  (case-sensitive)"
		}
		configRows = append(configRows, [2]string{"Replace", val})
	}
	if len(ignoredHostsMap) > 0 {
		sorted := make([]string, 0, len(ignoredHostsMap))
		for h := range ignoredHostsMap {
			if strings.HasPrefix(h, ".") {
				sorted = append(sorted, "*"+h)
			} else {
				sorted = append(sorted, h)
			}
		}
		sort.Strings(sorted)
		configRows = append(configRows, [2]string{"Ignored", strings.Join(sorted, ", ")})
	}
	if len(alsoProxyDomains) > 0 {
		configRows = append(configRows, [2]string{"Also-proxy", strings.Join(alsoProxyDomains, ", ")})
	}
	// Collect notable flags into a single "Flags" row so they don't clutter
	// the banner individually — only show when at least one is set.
	var flags []string
	if *skipVerify {
		flags = append(flags, "-skip-verify")
	}
	if *exactDomain {
		flags = append(flags, "-exact-domain")
	}
	if *verbose {
		flags = append(flags, "-verbose")
	}
	if *wsNoLog {
		flags = append(flags, "-ws-no-log")
	}
	if len(flags) > 0 {
		configRows = append(configRows, [2]string{"Flags", strings.Join(flags, "  ")})
	}

	// Display URL shown in the banner: substitute 0.0.0.0/:: with "localhost"
	// so users see a clickable URL, not an unroutable bind address.
	displayHost := *listen
	if displayHost == "0.0.0.0" || displayHost == "::" || displayHost == "" {
		displayHost = "localhost"
	}

	proxyDisplayURL := fmt.Sprintf("http://%s:%d", displayHost, *port)
	targetDisplayURL := fmt.Sprintf("%s://%s", scheme, *target)
	uiDisplayURL := ""
	if uiEnabled {
		uiDisplayURL = fmt.Sprintf("http://%s:%d", displayHost, *uiPort)
	}

	printBanner(os.Stderr, proxyDisplayURL, targetDisplayURL, uiDisplayURL, configRows)

	// Write a single compact machine-readable line to the logger so that
	// -log file consumers get the essential startup info in their log.
	logger.Printf("maskproxy v%s started  proxy=%s  target=%s  ui=%s",
		version, proxyDisplayURL, targetDisplayURL, func() string {
			if uiEnabled {
				return uiDisplayURL
			}
			return "disabled"
		}())

	// Start the UI inspection server on a separate port.
	// It binds to the same listen address as the main proxy (respects -listen flag).
	if uiEnabled {
		uiSrv := NewUIServer(trafficStore, uiAddr)
		go func() {
			if err := uiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Printf("maskproxy: UI server error: %v", err)
			}
		}()
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

// buildReplacementPairs extracts the configured Pair list from a Replacer for
// display in the UI.  Returns nil when no pairs are configured.
func buildReplacementPairs(rep *Replacer) []ReplacementPair {
	if rep == nil || !rep.HasPairs() {
		return nil
	}
	pairs := make([]ReplacementPair, len(rep.forResponse))
	for i, p := range rep.forResponse {
		pairs[i] = ReplacementPair{Original: p.Original, Alias: p.Alias}
	}
	return pairs
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

// printBanner writes a framed startup banner to w, similar to ngrok's output.
//
// The banner has three sections separated by horizontal dividers:
//  1. Title row:   "maskproxy" left-aligned, version right-aligned
//  2. URL rows:    Proxy, Target, and (optionally) UI
//  3. Config rows: only printed when configRows is non-empty (replacements,
//     ignored hosts, also-proxy domains, active flags)
//
// Example output:
//
//╔══════════════════════════════════════════════════════╗
//║  maskproxy                                  v1.5.0  ║
//╠══════════════════════════════════════════════════════╣
//║  Proxy    http://localhost:8080                      ║
//║  Target   https://copilot.microsoft.com              ║
//║  UI       http://localhost:4040                      ║
//╠══════════════════════════════════════════════════════╣
//║  Replace  microsoft → msctf                         ║
//║  Ignored  login.microsoftonline.com                  ║
//╚══════════════════════════════════════════════════════╝
//
// uiURL may be empty string when the UI is disabled; the UI row is omitted.
// configRows is [][2]string where [0] is the label and [1] is the value.
func printBanner(w io.Writer, proxyURL, targetURL, uiURL string, configRows [][2]string) {
const labelW = 10 // label column width (right-padded with spaces)
const lpad = 2    // spaces between ║ and content on the left
const rpad = 2    // spaces between content and ║ on the right

// fmtRow formats a "label  value" string for width measurement.
fmtRow := func(label, value string) string {
return fmt.Sprintf("%-*s  %s", labelW, label, value)
}

// Determine the URL rows (only include UI row when UI is enabled).
urlRows := [][2]string{
{"Proxy", proxyURL},
{"Target", targetURL},
}
if uiURL != "" {
urlRows = append(urlRows, [2]string{"UI", uiURL})
}

// Compute maxContent: the widest content string across all rows.
// The title row is the minimum: "maskproxy  v<version>" with at least 2 gap.
titleL := "maskproxy"
titleR := "v" + version
maxContent := len(titleL) + 2 + len(titleR)
for _, r := range urlRows {
if n := len(fmtRow(r[0], r[1])); n > maxContent {
maxContent = n
}
}
for _, r := range configRows {
if n := len(fmtRow(r[0], r[1])); n > maxContent {
maxContent = n
}
}

// innerW is the total width between the box-drawing wall characters.
// It equals lpad + maxContent + rpad.
innerW := lpad + maxContent + rpad

// line returns a full box row with ║ walls and the content left-aligned,
// right-padded to fill exactly innerW chars between the walls.
line := func(content string) string {
// "║" + " "*lpad + content + " "*(innerW-lpad-len(content)) + "║"
// The right-side padding fills innerW-lpad-len(content) chars; the rpad
// minimum is always satisfied because len(content) <= maxContent and
// innerW = lpad + maxContent + rpad.
rightFill := innerW - lpad - len(content)
return "║" + strings.Repeat(" ", lpad) + content + strings.Repeat(" ", rightFill) + "║"
}

// hline returns a horizontal divider with the given corner/junction chars.
hline := func(left, right string) string {
return left + strings.Repeat("═", innerW) + right
}

// titleLine builds the title row with "maskproxy" left and "vX.Y.Z" right.
titleLine := func() string {
gap := maxContent - len(titleL) - len(titleR)
return line(titleL + strings.Repeat(" ", gap) + titleR)
}

// — Print the banner —
fmt.Fprintln(w, hline("╔", "╗"))
fmt.Fprintln(w, titleLine())
fmt.Fprintln(w, hline("╠", "╣"))
for _, r := range urlRows {
fmt.Fprintln(w, line(fmtRow(r[0], r[1])))
}
if len(configRows) > 0 {
fmt.Fprintln(w, hline("╠", "╣"))
for _, r := range configRows {
fmt.Fprintln(w, line(fmtRow(r[0], r[1])))
}
}
fmt.Fprintln(w, hline("╚", "╝"))
}
