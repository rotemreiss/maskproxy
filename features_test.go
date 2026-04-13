package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestUpstreamTimeout verifies that a -timeout flag causes the proxy to return
// 502 Bad Gateway when the upstream does not respond within the deadline.
func TestUpstreamTimeout(t *testing.T) {
	// Upstream that blocks until the test tells it to stop (via context cancel).
	stop := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stop:
		case <-r.Context().Done():
		}
	}))
	defer func() {
		close(stop)
		hung.Close()
	}()

	host := strings.TrimPrefix(hung.URL, "http://")
	rep, _ := NewReplacer("", false)
	// 100ms timeout — short enough for a fast test.
	proxy := NewReverseProxy(host, "http", rep, false, "", false, 100*time.Millisecond, testLogger(), nil, nil, 0)
	ps := httptest.NewServer(proxy)
	defer ps.Close()

	resp, err := ps.Client().Get(ps.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 Bad Gateway for hung upstream, got %d", resp.StatusCode)
	}
}

// TestReplaceDiff verifies that ToAliasDiff and ToOriginalDiff return correct counts.
func TestReplaceDiff(t *testing.T) {
	rep, err := NewReplacer("ctf:acme,ctfd:foo", false)
	if err != nil {
		t.Fatal(err)
	}

	// ToAliasDiff: original → alias — "ctfd" → "foo", "ctf" (×2) → "acme".
	result, count := rep.ToAliasDiff("ctfd login ctf page ctf end")
	if count == 0 {
		t.Error("expected non-zero replacement count from ToAliasDiff")
	}
	if !strings.Contains(result, "foo") {
		t.Errorf("expected 'foo' in ToAliasDiff result, got: %q", result)
	}
	if !strings.Contains(result, "acme") {
		t.Errorf("expected 'acme' in ToAliasDiff result, got: %q", result)
	}

	// ToOriginalDiff: alias → original — "acme" → "ctf", "foo" → "ctfd".
	result2, count2 := rep.ToOriginalDiff("acme page foo end")
	if count2 == 0 {
		t.Error("expected non-zero replacement count from ToOriginalDiff")
	}
	if !strings.Contains(result2, "ctf") {
		t.Errorf("expected 'ctf' in ToOriginalDiff result, got: %q", result2)
	}
}

// TestLoadReplaceFile verifies parsing of a replacement pairs file.
// The file supports # comments (both full-line and inline) and blank lines.
func TestLoadReplaceFile(t *testing.T) {
	f, err := os.CreateTemp("", "maskproxy-pairs-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	// File with comment, blank line, inline comment, and valid pairs.
	fileContent := "# comment line\n\nctf:acme  # inline comment\nctfd:foo\n"
	if _, err := f.WriteString(fileContent); err != nil {
		t.Fatal(err)
	}
	f.Close()

	spec, err := loadReplaceFile(f.Name())
	if err != nil {
		t.Fatalf("loadReplaceFile: %v", err)
	}

	rep, err := NewReplacer(spec, false)
	if err != nil {
		t.Fatalf("NewReplacer: %v", err)
	}

	// Verify the pairs were loaded correctly.
	got := rep.ToAlias("ctfd login ctf")
	want := "foo login acme"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestLoadReplaceFileInvalidLine verifies that a malformed line (no colon) returns an error.
func TestLoadReplaceFileInvalidLine(t *testing.T) {
	f, err := os.CreateTemp("", "maskproxy-bad-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString("this-line-has-no-colon\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	_, err = loadReplaceFile(f.Name())
	if err == nil {
		t.Error("expected error for invalid line, got nil")
	}
}

// TestCaseInsensitiveReplacer verifies that the default (case-insensitive) mode
// matches upper, lower, and mixed-case occurrences while preserving the exact
// replacement string (not the matched casing).
func TestCaseInsensitiveReplacer(t *testing.T) {
	// caseInsensitive = true (production default — -cs flag not set)
	rep, err := NewReplacer("ctf:acme,ctfd:foo", true)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		input string
		want  string
	}{
		{"ctf", "acme"},
		{"CTF", "acme"},
		{"Ctf", "acme"},
		{"ctfd", "foo"},
		{"CTFD", "foo"},
		// Longer match wins over shorter (ctfd before ctf).
		{"CTFd login CTF", "foo login acme"},
		// Mixed sentence.
		{"Welcome to CTFd, the ctf platform", "Welcome to foo, the acme platform"},
	}
	for _, tc := range tests {
		got := rep.ToAlias(tc.input)
		if got != tc.want {
			t.Errorf("ToAlias(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}

	// ToOriginal (alias → original): acme → ctf, foo → ctfd
	origTests := []struct {
		input string
		want  string
	}{
		{"ACME", "ctf"},
		{"acme", "ctf"},
		{"FOO", "ctfd"},
		{"foo", "ctfd"},
		{"Acme login Foo", "ctf login ctfd"},
	}
	for _, tc := range origTests {
		got := rep.ToOriginal(tc.input)
		if got != tc.want {
			t.Errorf("ToOriginal(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestCaseSensitiveReplacer verifies that -cs mode does NOT match different cases.
func TestCaseSensitiveReplacer(t *testing.T) {
	// caseInsensitive = false (passes -cs flag)
	rep, err := NewReplacer("ctf:acme", false)
	if err != nil {
		t.Fatal(err)
	}

	// Exact case matches.
	if got := rep.ToAlias("ctf"); got != "acme" {
		t.Errorf("ToAlias(exact): got %q want %q", got, "acme")
	}
	// Different case must NOT match.
	if got := rep.ToAlias("CTF"); got != "CTF" {
		t.Errorf("ToAlias(upper case): got %q, expected no replacement", got)
	}
}

// TestCaseInsensitiveDiff verifies ToAliasDiff counts replacements correctly in CI mode.
func TestCaseInsensitiveDiff(t *testing.T) {
	rep, err := NewReplacer("ctf:acme", true)
	if err != nil {
		t.Fatal(err)
	}
	result, count := rep.ToAliasDiff("CTF ctf Ctf")
	if count != 3 {
		t.Errorf("expected 3 replacements, got %d", count)
	}
	if result != "acme acme acme" {
		t.Errorf("unexpected result: %q", result)
	}
}

// BenchmarkReplacerToAlias measures the hot-path cost of response body replacement.
// Run with: go test -bench=BenchmarkReplacer -benchtime=5s
func BenchmarkReplacerToAlias(b *testing.B) {
rep, _ := NewReplacer("microsoft:msctf,windows:winx,azure:cloudx", false)
body := strings.Repeat("Visit https://www.microsoft.com for windows and azure info. ", 500)
b.ResetTimer()
b.ReportAllocs()
for i := 0; i < b.N; i++ {
_ = rep.ToAlias(body)
}
}

// BenchmarkReplacerToOriginal measures the hot-path cost of request rewriting.
func BenchmarkReplacerToOriginal(b *testing.B) {
rep, _ := NewReplacer("microsoft:msctf,windows:winx,azure:cloudx", false)
body := strings.Repeat("Visit https://www.msctf.com for winx and cloudx info. ", 500)
b.ResetTimer()
b.ReportAllocs()
for i := 0; i < b.N; i++ {
_ = rep.ToOriginal(body)
}
}

// TestReplacerNoPairs verifies that a Replacer with no pairs is a no-op
// and that ToOriginalDiff/ToAliasDiff return zero counts.
func TestReplacerNoPairs(t *testing.T) {
	rep, err := NewReplacer("", false)
	if err != nil {
		t.Fatal(err)
	}
	if s := rep.ToOriginal("hello ctf world"); s != "hello ctf world" {
		t.Errorf("ToOriginal with no pairs should be no-op, got %q", s)
	}
	if s := rep.ToAlias("hello ctf world"); s != "hello ctf world" {
		t.Errorf("ToAlias with no pairs should be no-op, got %q", s)
	}
	if s, n := rep.ToOriginalDiff("hello ctf world"); s != "hello ctf world" || n != 0 {
		t.Errorf("ToOriginalDiff with no pairs should return (s,0), got (%q, %d)", s, n)
	}
	if s, n := rep.ToAliasDiff("hello ctf world"); s != "hello ctf world" || n != 0 {
		t.Errorf("ToAliasDiff with no pairs should return (s,0), got (%q, %d)", s, n)
	}
	if rep.HasPairs() {
		t.Error("HasPairs should be false when no pairs configured")
	}
}
