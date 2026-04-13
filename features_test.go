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
	proxy := NewReverseProxy(host, "http", rep, false, "", false, 100*time.Millisecond, testLogger(), nil, nil)
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
