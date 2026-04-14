package main

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// maxTransactions is the ring-buffer capacity for recorded traffic.
const maxTransactions = 1000

// uiBodyPreview is the maximum number of bytes stored per body in a transaction.
const uiBodyPreview = 16 * 1024 // 16 KiB

// Transaction captures one complete request/response pair as it passed
// through the proxy, including original and rewritten versions so the UI
// can show a Burp-style diff view.
type Transaction struct {
	ID          uint64    `json:"id"`
	Time        time.Time `json:"time"`
	Method      string    `json:"method"`
	URL         string    `json:"url"`         // original client-visible URL
	ModifiedURL string    `json:"modifiedUrl"` // upstream URL after rewriting
	Host        string    `json:"host"`

	// Response fields (zero until the response arrives).
	StatusCode   int           `json:"statusCode"`
	Duration     time.Duration `json:"duration"`
	ResponseSize int64         `json:"responseSize"`
	ContentType  string        `json:"contentType"`

	// Request capture.
	OriginalRequestHeaders  http.Header `json:"originalRequestHeaders"`
	OriginalRequestBody     string      `json:"originalRequestBody"`
	ModifiedRequestHeaders  http.Header `json:"modifiedRequestHeaders"`
	ModifiedRequestBody     string      `json:"modifiedRequestBody"`
	RequestReplaceCount     int         `json:"requestReplaceCount"`

	// Response capture.
	ResponseHeaders         http.Header `json:"responseHeaders"`
	OriginalResponseBody    string      `json:"originalResponseBody"`
	ModifiedResponseBody    string      `json:"modifiedResponseBody"`
	ResponseReplaceCount    int         `json:"responseReplaceCount"`

	// Flags.
	IsIgnored bool `json:"isIgnored"`
	IsWS      bool `json:"isWS"`
}

// TrafficStore is a thread-safe ring buffer that stores recent transactions
// and broadcasts new ones to subscribed SSE clients.
type TrafficStore struct {
	mu           sync.RWMutex
	transactions []*Transaction
	head         int // index of the next write slot (ring)
	count        int // total stored (capped at maxTransactions)

	// Real-time broadcast: new transactions are sent to all active SSE listeners.
	subsMu  sync.Mutex
	subs    []chan *Transaction

	// Monotonic ID counter.
	nextID atomic.Uint64

	// Active hosts: maps lowercase host → request count.
	hostsMu     sync.Mutex
	activeHosts map[string]int

	// Ignored hosts list (display only, copied from proxy config).
	IgnoredHosts []string

	// Proxy config (display).
	Target       string
	Replacements []ReplacementPair
}

// ReplacementPair holds one original↔alias mapping for display in the UI.
type ReplacementPair struct {
	Original string `json:"original"`
	Alias    string `json:"alias"`
}

// NewTrafficStore allocates an empty store.
func NewTrafficStore() *TrafficStore {
	return &TrafficStore{
		transactions: make([]*Transaction, maxTransactions),
		activeHosts:  make(map[string]int),
	}
}

// NewTransaction allocates a Transaction with a fresh ID and current timestamp.
func (s *TrafficStore) NewTransaction() *Transaction {
	return &Transaction{
		ID:   s.nextID.Add(1),
		Time: time.Now(),
	}
}

// Save stores tx in the ring buffer and broadcasts it to SSE subscribers.
func (s *TrafficStore) Save(tx *Transaction) {
	s.mu.Lock()
	s.transactions[s.head] = tx
	s.head = (s.head + 1) % maxTransactions
	if s.count < maxTransactions {
		s.count++
	}
	s.mu.Unlock()

	// Track active host counts.
	if tx.Host != "" {
		s.hostsMu.Lock()
		s.activeHosts[tx.Host]++
		s.hostsMu.Unlock()
	}

	// Broadcast to all SSE subscribers.
	s.subsMu.Lock()
	for _, ch := range s.subs {
		select {
		case ch <- tx:
		default: // drop if subscriber is too slow
		}
	}
	s.subsMu.Unlock()
}

// All returns all stored transactions in insertion order (oldest first).
func (s *TrafficStore) All() []*Transaction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.count == 0 {
		return nil
	}
	out := make([]*Transaction, s.count)
	if s.count < maxTransactions {
		// Buffer not yet full: elements are at indices [0, s.count).
		copy(out, s.transactions[:s.count])
	} else {
		// Buffer full: head points to the oldest element.
		n := copy(out, s.transactions[s.head:])
		copy(out[n:], s.transactions[:s.head])
	}
	return out
}

// Get returns a single transaction by ID, or nil if not found.
func (s *TrafficStore) Get(id uint64) *Transaction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, tx := range s.transactions {
		if tx != nil && tx.ID == id {
			return tx
		}
	}
	return nil
}

// ActiveHosts returns a snapshot of {host: count} pairs.
func (s *TrafficStore) ActiveHosts() map[string]int {
	s.hostsMu.Lock()
	defer s.hostsMu.Unlock()
	out := make(map[string]int, len(s.activeHosts))
	for k, v := range s.activeHosts {
		out[k] = v
	}
	return out
}

// Subscribe returns a channel that receives each new transaction as it is saved.
// The caller must call Unsubscribe when done to avoid a goroutine leak.
func (s *TrafficStore) Subscribe() chan *Transaction {
	ch := make(chan *Transaction, 64)
	s.subsMu.Lock()
	s.subs = append(s.subs, ch)
	s.subsMu.Unlock()
	return ch
}

// Unsubscribe removes and closes a subscriber channel.
func (s *TrafficStore) Unsubscribe(ch chan *Transaction) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for i, c := range s.subs {
		if c == ch {
			s.subs = append(s.subs[:i], s.subs[i+1:]...)
			close(ch)
			return
		}
	}
}

// Stats returns aggregate statistics computed over all stored transactions.
type Stats struct {
	Total         int            `json:"total"`
	TotalBytes    int64          `json:"totalBytes"`
	StatusCodes   map[string]int `json:"statusCodes"`
	AvgDurationMs float64        `json:"avgDurationMs"`
	ErrorRate     float64        `json:"errorRate"`
	// RequestsPerMinute is a slice of {minute: count} for the last 60 minutes.
	RequestsPerMinute []TimePoint `json:"requestsPerMinute"`
}

// TimePoint is one bucket in a time-series chart.
type TimePoint struct {
	Time  time.Time `json:"time"`
	Count int       `json:"count"`
}

// ComputeStats builds stats from the current transaction buffer.
func (s *TrafficStore) ComputeStats() Stats {
	txns := s.All()
	st := Stats{
		StatusCodes: make(map[string]int),
	}

	// Bucket requests into 1-minute slots over the last 60 minutes.
	now := time.Now().Truncate(time.Minute)
	buckets := make(map[time.Time]int, 60)
	for i := 0; i < 60; i++ {
		buckets[now.Add(-time.Duration(i)*time.Minute)] = 0
	}

	var totalDurMs float64
	var errors int
	for _, tx := range txns {
		st.Total++
		st.TotalBytes += tx.ResponseSize
		totalDurMs += float64(tx.Duration.Milliseconds())

		code := ""
		switch {
		case tx.StatusCode >= 500:
			code = "5xx"
			errors++
		case tx.StatusCode >= 400:
			code = "4xx"
			errors++
		case tx.StatusCode >= 300:
			code = "3xx"
		case tx.StatusCode >= 200:
			code = "2xx"
		default:
			code = "other"
		}
		st.StatusCodes[code]++

		minute := tx.Time.Truncate(time.Minute)
		if _, ok := buckets[minute]; ok {
			buckets[minute]++
		}
	}
	if st.Total > 0 {
		st.AvgDurationMs = totalDurMs / float64(st.Total)
		st.ErrorRate = float64(errors) / float64(st.Total) * 100
	}

	// Build sorted time-series slice (oldest first).
	st.RequestsPerMinute = make([]TimePoint, 0, 60)
	for i := 59; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Minute)
		st.RequestsPerMinute = append(st.RequestsPerMinute, TimePoint{Time: t, Count: buckets[t]})
	}

	return st
}
