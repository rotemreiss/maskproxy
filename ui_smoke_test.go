package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
"testing"
)

func TestUIServerSmoke(t *testing.T) {
store := NewTrafficStore()
store.Target = "ctf.example.com"
store.IgnoredHosts = []string{"cdn.example.com"}

// Inject a synthetic transaction.
tx := store.NewTransaction()
tx.Method = "GET"
tx.URL = "http://localhost:4040/foo?bar=1"
tx.ModifiedURL = "http://ctf.example.com/foo?bar=1"
tx.Host = "ctf.example.com"
tx.StatusCode = 200
tx.OriginalRequestBody = "hello"
tx.ModifiedRequestBody = "hello"
tx.OriginalResponseBody = "world"
tx.ModifiedResponseBody = "world"
store.Save(tx)

srv := NewUIServer(store, "127.0.0.1:0")
ts := httptest.NewServer(srv.Handler)
defer ts.Close()

// GET / — HTML page
resp, err := http.Get(ts.URL + "/")
if err != nil { t.Fatal(err) }
body, _ := io.ReadAll(resp.Body); resp.Body.Close()
if !strings.Contains(string(body), "maskproxy") {
t.Errorf("index.html missing expected content")
}

// GET /api/transactions
resp, err = http.Get(ts.URL + "/api/transactions")
if err != nil { t.Fatal(err) }
var txns []*Transaction
json.NewDecoder(resp.Body).Decode(&txns); resp.Body.Close()
if len(txns) != 1 {
t.Errorf("expected 1 transaction, got %d", len(txns))
}

// GET /api/stats
resp, err = http.Get(ts.URL + "/api/stats")
if err != nil { t.Fatal(err) }
var stats Stats
json.NewDecoder(resp.Body).Decode(&stats); resp.Body.Close()
if stats.Total != 1 {
t.Errorf("expected stats.Total=1, got %d", stats.Total)
}

// GET /api/config
resp, err = http.Get(ts.URL + "/api/config")
if err != nil { t.Fatal(err) }
body, _ = io.ReadAll(resp.Body); resp.Body.Close()
if !strings.Contains(string(body), "ctf.example.com") {
t.Errorf("config missing target: %s", body)
}

// GET /api/hosts
resp, err = http.Get(ts.URL + "/api/hosts")
if err != nil { t.Fatal(err) }
var hosts map[string]int
json.NewDecoder(resp.Body).Decode(&hosts); resp.Body.Close()
if hosts["ctf.example.com"] != 1 {
t.Errorf("expected 1 request for ctf.example.com, got %v", hosts)
}

// GET /api/transaction/:id
resp, err = http.Get(ts.URL + "/api/transaction/" + strconv.FormatUint(tx.ID, 10))
if err != nil { t.Fatal(err) }
var single Transaction
json.NewDecoder(resp.Body).Decode(&single); resp.Body.Close()
if single.ID != tx.ID {
t.Errorf("expected tx ID %d, got %d", tx.ID, single.ID)
}

// 404 for unknown path
resp, err = http.Get(ts.URL + "/does-not-exist")
if err != nil { t.Fatal(err) }
resp.Body.Close()
if resp.StatusCode != 404 {
t.Errorf("expected 404, got %d", resp.StatusCode)
}
}
