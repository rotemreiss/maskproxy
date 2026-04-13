package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Pair holds one replacement mapping: Original is the server-side string,
// Alias is the client-side string that the proxy exposes.
//
// On requests  (client → server): Alias   → Original
// On responses (server → client): Original → Alias
type Pair struct {
	Original string
	Alias    string
}

// Replacer holds two pre-sorted replacement lists to avoid partial-match bugs.
// Both lists are sorted by the match-key length in descending order so that
// longer keys are replaced first (e.g. "ctfd" before "ctf").
type Replacer struct {
	// forRequest: sorted by Alias length desc (used to rewrite outbound requests)
	forRequest []Pair
	// forResponse: sorted by Original length desc (used to rewrite inbound responses)
	forResponse []Pair
	// caseInsensitive enables case-insensitive matching via regexp when true.
	caseInsensitive bool
	// reReq / reResp are single-pass compiled regexps for single-scan replacement,
	// preventing cascading rewrites (e.g. "wikipedia"→"wikifake", then "wiki"→"wf"
	// would otherwise corrupt "wikifake" into "wffake").
	// nil when there are no pairs or only one pair (fallback to strings.ReplaceAll).
	reReq  *regexp.Regexp
	reResp *regexp.Regexp
	// lookupReq / lookupResp are pre-built dispatch tables for ReplaceAllStringFunc.
	// Keys are lowercased when caseInsensitive is true.  Built once in NewReplacer
	// to avoid per-call allocations on the hot path.
	lookupReq  map[string]string
	lookupResp map[string]string
}

// NewReplacer parses the -replace flag value (e.g. "ctf:acme,ctfd:foo").
// Format: a comma-separated list of "original:alias" pairs.
// caseInsensitive controls matching behaviour: when true (the default when
// invoked from main), ToOriginal and ToAlias match regardless of case.
// Pass false (via -cs flag) to restrict matching to the exact case specified.
func NewReplacer(spec string, caseInsensitive bool) (*Replacer, error) {
	r := &Replacer{caseInsensitive: caseInsensitive}
	if spec == "" {
		return r, nil
	}

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("invalid replacement pair %q (expected non-empty original:alias)", part)
		}
		p := Pair{Original: kv[0], Alias: kv[1]}
		r.forRequest = append(r.forRequest, p)
		r.forResponse = append(r.forResponse, p)
	}

	// Sort by Alias length descending for request rewrites.
	sort.Slice(r.forRequest, func(i, j int) bool {
		return len(r.forRequest[i].Alias) > len(r.forRequest[j].Alias)
	})

	// Sort by Original length descending for response rewrites.
	sort.Slice(r.forResponse, func(i, j int) bool {
		return len(r.forResponse[i].Original) > len(r.forResponse[j].Original)
	})

	// Compile single-pass regexps.  A single alternation scan prevents cascading
	// rewrites where the alias of one pair contains the key of another pair
	// (e.g. wikipedia→wikifake then wiki→wf would corrupt wikifake→wffake).
	// Also pre-build dispatch lookup tables so ReplaceAllStringFunc never needs
	// to allocate a new map on the hot path (called for every proxied body).
	if len(r.forRequest) > 0 {
		r.reReq = buildRegexp(r.forRequest, "Alias", caseInsensitive)
		r.lookupReq = make(map[string]string, len(r.forRequest))
		for _, p := range r.forRequest {
			key := p.Alias
			if caseInsensitive {
				key = strings.ToLower(key)
			}
			r.lookupReq[key] = p.Original
		}
	}
	if len(r.forResponse) > 0 {
		r.reResp = buildRegexp(r.forResponse, "Original", caseInsensitive)
		r.lookupResp = make(map[string]string, len(r.forResponse))
		for _, p := range r.forResponse {
			key := p.Original
			if caseInsensitive {
				key = strings.ToLower(key)
			}
			r.lookupResp[key] = p.Alias
		}
	}

	return r, nil
}

// buildRegexp compiles a single alternation regexp from pairs, using the
// specified field ("Alias" or "Original") as the match key.
func buildRegexp(pairs []Pair, field string, caseInsensitive bool) *regexp.Regexp {
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		if field == "Alias" {
			parts[i] = regexp.QuoteMeta(p.Alias)
		} else {
			parts[i] = regexp.QuoteMeta(p.Original)
		}
	}
	prefix := ""
	if caseInsensitive {
		prefix = "(?i)"
	}
	return regexp.MustCompile(prefix + "(?:" + strings.Join(parts, "|") + ")")
}

// replaceCI replaces all case-insensitive occurrences of old with new in s.
func replaceCI(s, old, newVal string) string {
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(old))
	return re.ReplaceAllString(s, newVal)
}

// ToOriginal rewrites s by replacing every Alias with its Original.
// Used when rewriting outbound requests (client aliases → server originals).
func (r *Replacer) ToOriginal(s string) string {
	if r.reReq != nil {
		return r.reReq.ReplaceAllStringFunc(s, func(m string) string {
			key := m
			if r.caseInsensitive {
				key = strings.ToLower(key)
			}
			if v, ok := r.lookupReq[key]; ok {
				return v
			}
			return m
		})
	}
	// Fallback for empty pairs (should not occur, but be safe).
	for _, p := range r.forRequest {
		if r.caseInsensitive {
			s = replaceCI(s, p.Alias, p.Original)
		} else {
			s = strings.ReplaceAll(s, p.Alias, p.Original)
		}
	}
	return s
}

// ToAlias rewrites s by replacing every Original with its Alias.
// Used when rewriting inbound responses (server originals → client aliases).
func (r *Replacer) ToAlias(s string) string {
	if r.reResp != nil {
		return r.reResp.ReplaceAllStringFunc(s, func(m string) string {
			key := m
			if r.caseInsensitive {
				key = strings.ToLower(key)
			}
			if v, ok := r.lookupResp[key]; ok {
				return v
			}
			return m
		})
	}
	// Fallback for empty pairs.
	for _, p := range r.forResponse {
		if r.caseInsensitive {
			s = replaceCI(s, p.Original, p.Alias)
		} else {
			s = strings.ReplaceAll(s, p.Original, p.Alias)
		}
	}
	return s
}

// HasPairs reports whether any replacement pairs were configured.
func (r *Replacer) HasPairs() bool {
	return len(r.forResponse) > 0
}

// ToOriginalDiff is like ToOriginal but also returns the number of substitutions made.
func (r *Replacer) ToOriginalDiff(s string) (string, int) {
	count := 0
	if r.reReq != nil {
		result := r.reReq.ReplaceAllStringFunc(s, func(m string) string {
			key := m
			if r.caseInsensitive {
				key = strings.ToLower(key)
			}
			if v, ok := r.lookupReq[key]; ok {
				count++
				return v
			}
			return m
		})
		return result, count
	}
	result := s
	for _, p := range r.forRequest {
		var rewritten string
		if r.caseInsensitive {
			rewritten = replaceCI(result, p.Alias, p.Original)
		} else {
			rewritten = strings.ReplaceAll(result, p.Alias, p.Original)
		}
		// Count occurrences by measuring length difference against alias/original lengths.
		if len(p.Alias) > 0 {
			count += (len(result) - len(rewritten) + len(p.Original)*countOccurrences(result, p.Alias, r.caseInsensitive)) / max(len(p.Alias), 1)
		}
		result = rewritten
	}
	return result, count
}

// ToAliasDiff is like ToAlias but also returns the number of substitutions made.
func (r *Replacer) ToAliasDiff(s string) (string, int) {
	count := 0
	if r.reResp != nil {
		result := r.reResp.ReplaceAllStringFunc(s, func(m string) string {
			key := m
			if r.caseInsensitive {
				key = strings.ToLower(key)
			}
			if v, ok := r.lookupResp[key]; ok {
				count++
				return v
			}
			return m
		})
		return result, count
	}
	result := s
	for _, p := range r.forResponse {
		var rewritten string
		if r.caseInsensitive {
			rewritten = replaceCI(result, p.Original, p.Alias)
		} else {
			rewritten = strings.ReplaceAll(result, p.Original, p.Alias)
		}
		result = rewritten
	}
	return result, count
}

// countOccurrences returns the number of times sub appears in s.
// When ci is true the comparison is case-insensitive.
func countOccurrences(s, sub string, ci bool) int {
	if sub == "" {
		return 0
	}
	if ci {
		s = strings.ToLower(s)
		sub = strings.ToLower(sub)
	}
	return strings.Count(s, sub)
}

// max returns the larger of a and b (for Go <1.21 compatibility).
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
