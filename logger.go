package main

import (
"fmt"
"io"
"log"
"net/http"
"os"
"sort"
"strings"
"time"
)

// verboseBodyPreview is the maximum number of bytes of a body printed in
// verbose mode. Anything beyond this is truncated with a notice.
const verboseBodyPreview = 4 * 1024 // 4 KiB

// sensitiveHeaders lists headers whose values are redacted in verbose output
// to avoid leaking credentials into log files.
var sensitiveHeaders = map[string]bool{
"Authorization": true,
"Cookie":        true,
"Set-Cookie":    true,
"X-Api-Key":     true,
"X-Auth-Token":  true,
}

// Logger is a thin wrapper around the standard library logger that supports
// two log levels (normal and verbose) and optional tee output to a file.
//
// Normal:  one line per request/response — method + URL + status + size + replacement count.
// Verbose: the above plus all headers and a body preview (4 KiB).
type Logger struct {
l       *log.Logger
verbose bool
}

// NewLogger creates a Logger. If logPath is non-empty the file is opened in
// append mode and all output is tee'd to it in addition to stderr.
// The returned closer must be deferred in main to flush and close the file.
func NewLogger(verbose bool, logPath string) (*Logger, func(), error) {
writers := []io.Writer{os.Stderr}

closer := func() {}
if logPath != "" {
f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
if err != nil {
return nil, nil, fmt.Errorf("cannot open log file %q: %w", logPath, err)
}
writers = append(writers, f)
closer = func() { f.Close() }
}

l := log.New(io.MultiWriter(writers...), "", log.LstdFlags)
return &Logger{l: l, verbose: verbose}, closer, nil
}

// newDiscardLogger returns a silent Logger that discards all output.
// Used in unit tests to keep test output clean.
func newDiscardLogger() *Logger {
return &Logger{l: log.New(io.Discard, "", 0), verbose: false}
}

// Printf formats and writes a message at normal level (always shown).
func (lg *Logger) Printf(format string, args ...any) {
lg.l.Printf(format, args...)
}

// Fatal logs a message and terminates the program with status 1.
func (lg *Logger) Fatal(format string, args ...any) {
lg.l.Fatalf(format, args...)
}

// Verbosef formats and writes a message only when verbose mode is active.
func (lg *Logger) Verbosef(format string, args ...any) {
if lg.verbose {
lg.l.Printf(format, args...)
}
}

// LogRequest writes one log line per outbound request (always shown), plus a
// full header + body dump when verbose is enabled.
//
// bodySnapshot is the rewritten request body string; pass "" for bodyless requests.
// isWS must be true for WebSocket upgrades — the log line shows "WS↑" instead of
// the HTTP method and no matching response line will appear (WS connections live
// for the duration of the session and bypass ModifyResponse).
// replaceCount is the total number of string substitutions made in the request.
//
// Returns the current time so LogResponse can compute round-trip latency.
func (lg *Logger) LogRequest(req *http.Request, bodySnapshot string, isWS bool, replaceCount int) time.Time {
start := time.Now()

method := req.Method
if isWS {
method = "WS↑  "
}

// Show replacement count in normal mode so operators can confirm replacements are firing.
suffix := ""
if replaceCount > 0 {
suffix = fmt.Sprintf("  [%d replaced]", replaceCount)
}
lg.l.Printf("-> %-6s %s%s", method, req.URL, suffix)

if !lg.verbose {
return start
}

// Dump all headers (sorted for determinism) with sensitive ones redacted,
// then show a body preview. Print the whole block atomically so concurrent
// requests do not interleave their verbose output.
var sb strings.Builder
sb.WriteString("   [request headers]\n")
for _, key := range sortedKeys(req.Header) {
if sensitiveHeaders[key] {
fmt.Fprintf(&sb, "   %s: [redacted]\n", key)
continue
}
for _, v := range req.Header[key] {
fmt.Fprintf(&sb, "   %s: %s\n", key, v)
}
}
sb.WriteString(bodyDump("request", bodySnapshot))
lg.l.Print(strings.TrimRight(sb.String(), "\n"))

return start
}

// LogResponse writes one log line per inbound response (always shown), plus a
// full header + body dump when verbose is enabled.
//
// bodySnapshot is the rewritten response body; pass "" for binary assets or empty bodies.
// replaceCount is the total number of string substitutions made in the response body.
// start is the time returned by LogRequest; used to compute round-trip latency.
func (lg *Logger) LogResponse(resp *http.Response, bodySnapshot string, start time.Time, replaceCount int) {
elapsed := time.Since(start)
// Use ContentLength from headers when available; fall back to snapshot size.
size := resp.ContentLength
if size < 0 {
size = int64(len(bodySnapshot))
}

suffix := ""
if replaceCount > 0 {
suffix = fmt.Sprintf("  [%d replaced]", replaceCount)
}
lg.l.Printf("<- %-3d  %s  (%s, %s)%s",
resp.StatusCode, resp.Request.URL, humanBytes(size), elapsed.Round(time.Millisecond), suffix)

if !lg.verbose {
return
}

var sb strings.Builder
sb.WriteString("   [response headers]\n")
for _, key := range sortedKeys(resp.Header) {
if sensitiveHeaders[key] {
fmt.Fprintf(&sb, "   %s: [redacted]\n", key)
continue
}
for _, v := range resp.Header[key] {
fmt.Fprintf(&sb, "   %s: %s\n", key, v)
}
}
sb.WriteString(bodyDump("response", bodySnapshot))
lg.l.Print(strings.TrimRight(sb.String(), "\n"))
}

// bodyDump formats a labelled body preview for verbose output.
func bodyDump(label, body string) string {
if body == "" {
return fmt.Sprintf("   [%s body: empty]\n", label)
}
total := len(body)
preview := body
truncated := total > verboseBodyPreview
if truncated {
preview = body[:verboseBodyPreview]
}
var sb strings.Builder
if truncated {
fmt.Fprintf(&sb, "   [%s body preview — %d of %d bytes]\n", label, verboseBodyPreview, total)
} else {
fmt.Fprintf(&sb, "   [%s body — %d bytes]\n", label, total)
}
for _, line := range strings.Split(preview, "\n") {
sb.WriteString("   ")
sb.WriteString(line)
sb.WriteString("\n")
}
if truncated {
fmt.Fprintf(&sb, "   [... %d bytes truncated]\n", total-verboseBodyPreview)
}
return sb.String()
}

// sortedKeys returns header keys in lexicographic order.
func sortedKeys(h http.Header) []string {
keys := make([]string, 0, len(h))
for k := range h {
keys = append(keys, k)
}
sort.Strings(keys)
return keys
}

// humanBytes formats a byte count as a human-readable string.
func humanBytes(n int64) string {
const unit = 1024
if n < unit {
return fmt.Sprintf("%d B", n)
}
div, exp := int64(unit), 0
for v := n / unit; v >= unit; v /= unit {
div *= unit
exp++
}
return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
