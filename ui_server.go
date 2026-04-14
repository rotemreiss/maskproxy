package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// NewUIServer creates an HTTP server that serves the traffic inspection UI.
// addr is the listen address, e.g. "127.0.0.1:4040". All endpoints are
// intentionally same-origin only (no CORS headers) since the HTML page is
// served from the same host:port as the API, and the UI contains sensitive
// proxy traffic data (auth headers, cookies, request/response bodies).
func NewUIServer(store *TrafficStore, addr string) *http.Server {
	mux := http.NewServeMux()

	// jsonAPI is a helper that sets JSON headers and handles OPTIONS preflight.
	// No CORS is set: the UI page is served from the same origin as the API.
	jsonAPI := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, uiHTML)
	})

	// GET /api/transactions → JSON array of all transactions (newest first)
	mux.HandleFunc("/api/transactions", func(w http.ResponseWriter, r *http.Request) {
		jsonAPI(w)
		txns := store.All()
		// Reverse so newest is first.
		for i, j := 0, len(txns)-1; i < j; i, j = i+1, j-1 {
			txns[i], txns[j] = txns[j], txns[i]
		}
		json.NewEncoder(w).Encode(txns)
	})

	// GET /api/transaction/:id → single transaction JSON
	mux.HandleFunc("/api/transaction/", func(w http.ResponseWriter, r *http.Request) {
		jsonAPI(w)
		idStr := strings.TrimPrefix(r.URL.Path, "/api/transaction/")
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
			return
		}
		tx := store.Get(id)
		if tx == nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(tx)
	})

	// GET /api/stats → aggregated statistics
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		jsonAPI(w)
		json.NewEncoder(w).Encode(store.ComputeStats())
	})

	// GET /api/config → proxy configuration (target, replacements, ignored hosts)
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		jsonAPI(w)
		type config struct {
			Target       string            `json:"target"`
			Replacements []ReplacementPair `json:"replacements"`
			IgnoredHosts []string          `json:"ignoredHosts"`
		}
		json.NewEncoder(w).Encode(config{
			Target:       store.Target,
			Replacements: store.Replacements,
			IgnoredHosts: store.IgnoredHosts,
		})
	})

	// GET /api/hosts → active host counts
	mux.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		jsonAPI(w)
		json.NewEncoder(w).Encode(store.ActiveHosts())
	})

	// GET /events → SSE stream of new transactions
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Send a heartbeat comment to keep the connection alive.
		fmt.Fprintf(w, ": connected\n\n")
		flusher.Flush()

		ch := store.Subscribe()
		defer store.Unsubscribe(ch)

		tick := time.NewTicker(15 * time.Second)
		defer tick.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
				fmt.Fprintf(w, ": heartbeat\n\n")
				flusher.Flush()
			case tx, ok := <-ch:
				if !ok {
					return
				}
				data, err := json.Marshal(tx)
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		}
	})

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// uiHTML is the complete single-page UI embedded directly in the binary.
// It uses Chart.js (CDN) for graphs and plain ES6 for interactivity.
const uiHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>maskproxy — Traffic Inspector</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg: #0f1117;
  --surface: #1a1d27;
  --surface2: #252836;
  --border: #2d3148;
  --accent: #6c7cfc;
  --accent2: #a78bfa;
  --green: #34d399;
  --red: #f87171;
  --yellow: #fbbf24;
  --blue: #60a5fa;
  --text: #e2e8f0;
  --text2: #94a3b8;
  --text3: #64748b;
  --font: 'SF Mono', 'Fira Code', 'Menlo', monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: var(--font); font-size: 13px; display: flex; flex-direction: column; height: 100vh; overflow: hidden; }

/* ── Header ── */
header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 10px 20px; display: flex; align-items: center; gap: 16px; flex-shrink: 0; }
header h1 { font-size: 15px; font-weight: 600; color: var(--accent); letter-spacing: .5px; }
#status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 6px var(--green); }
#proxy-target { color: var(--text2); font-size: 12px; }
.tab-bar { margin-left: auto; display: flex; gap: 2px; }
.tab { padding: 5px 14px; border-radius: 6px; cursor: pointer; color: var(--text2); transition: all .15s; user-select: none; }
.tab:hover { background: var(--surface2); color: var(--text); }
.tab.active { background: var(--accent); color: #fff; }

/* ── Main layout ── */
main { display: flex; flex: 1; overflow: hidden; }

/* ── Left panel ── */
#left-panel { width: 380px; flex-shrink: 0; display: flex; flex-direction: column; border-right: 1px solid var(--border); }
#filter-bar { padding: 8px 12px; border-bottom: 1px solid var(--border); display: flex; gap: 8px; }
#filter-bar input { flex: 1; background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 5px 10px; color: var(--text); font-family: var(--font); font-size: 12px; outline: none; }
#filter-bar input:focus { border-color: var(--accent); }
#filter-bar select { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 5px 8px; color: var(--text); font-family: var(--font); font-size: 12px; outline: none; }
#req-list { overflow-y: auto; flex: 1; }

/* ── Request list item ── */
.req-item { border-bottom: 1px solid var(--border); padding: 8px 12px; cursor: pointer; transition: background .1s; display: grid; grid-template-columns: 52px 1fr auto; grid-template-rows: auto auto; gap: 2px 8px; }
.req-item:hover { background: var(--surface); }
.req-item.selected { background: #1e2440; border-left: 3px solid var(--accent); }
.req-item.ignored { opacity: .55; }
.req-method { font-weight: 700; font-size: 11px; grid-row: 1; align-self: center; }
.req-method.GET { color: var(--green); }
.req-method.POST { color: var(--yellow); }
.req-method.PUT { color: var(--blue); }
.req-method.DELETE { color: var(--red); }
.req-method.PATCH { color: var(--accent2); }
.req-method.WS { color: var(--accent); }
.req-url { grid-column: 2; grid-row: 1; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; }
.req-meta { grid-column: 3; grid-row: 1; white-space: nowrap; }
.req-host { grid-column: 2 / 4; grid-row: 2; color: var(--text3); font-size: 11px; }
.status-badge { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; }
.s2xx { background: rgba(52,211,153,.15); color: var(--green); }
.s3xx { background: rgba(251,191,36,.15); color: var(--yellow); }
.s4xx { background: rgba(248,113,113,.15); color: var(--red); }
.s5xx { background: rgba(248,113,113,.2); color: var(--red); }
.s0xx { background: rgba(100,116,139,.15); color: var(--text3); }
.duration { color: var(--text3); font-size: 11px; margin-left: 6px; }
.replaced-badge { display: inline-block; padding: 1px 5px; border-radius: 4px; background: rgba(108,124,252,.2); color: var(--accent); font-size: 10px; margin-left: 4px; }

/* ── Right panel ── */
#right-panel { flex: 1; display: flex; flex-direction: column; overflow: hidden; }

/* ── Dashboard tab ── */
#dashboard { padding: 20px; overflow-y: auto; flex: 1; display: none; }
#dashboard.active-tab { display: block; }
.stat-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
.stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
.stat-card .label { color: var(--text2); font-size: 11px; text-transform: uppercase; letter-spacing: .8px; margin-bottom: 6px; }
.stat-card .value { font-size: 26px; font-weight: 700; color: var(--text); }
.stat-card .sub { font-size: 11px; color: var(--text3); margin-top: 3px; }
.charts-row { display: grid; grid-template-columns: 2fr 1fr; gap: 12px; margin-bottom: 20px; }
.chart-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
.chart-card h3 { font-size: 12px; color: var(--text2); margin-bottom: 12px; text-transform: uppercase; letter-spacing: .5px; }
.hosts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.hosts-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
.hosts-card h3 { font-size: 12px; color: var(--text2); margin-bottom: 10px; text-transform: uppercase; letter-spacing: .5px; display: flex; align-items: center; gap: 8px; }
.hosts-card h3 .count-badge { background: var(--surface2); border-radius: 10px; padding: 1px 8px; font-size: 11px; color: var(--text3); }
.host-row { display: flex; justify-content: space-between; align-items: center; padding: 5px 0; border-bottom: 1px solid var(--border); }
.host-row:last-child { border-bottom: none; }
.host-name { color: var(--text); font-size: 12px; }
.host-count { color: var(--text3); font-size: 11px; }
.ignored-host { color: var(--yellow); font-size: 12px; display: flex; align-items: center; gap: 6px; }
.ignored-host::before { content: '⊘'; font-size: 10px; }

/* ── Traffic (request/response detail) tab ── */
#traffic { display: flex; flex: 1; overflow: hidden; }
#traffic.active-tab { display: flex; }
#detail-panel { flex: 1; overflow: hidden; display: flex; flex-direction: column; }
#detail-empty { flex: 1; display: flex; align-items: center; justify-content: center; color: var(--text3); font-size: 14px; }
#detail-content { flex: 1; overflow-y: auto; padding: 16px; display: none; }
#detail-content.visible { display: block; }

.detail-header { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; padding-bottom: 14px; border-bottom: 1px solid var(--border); flex-wrap: wrap; }
.detail-header .method { font-size: 13px; font-weight: 700; }
.detail-header .url { color: var(--text); font-size: 13px; flex: 1; word-break: break-all; }
.detail-header .badges { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }

.section { margin-bottom: 16px; }
.section-title { font-size: 11px; text-transform: uppercase; letter-spacing: .7px; color: var(--text3); margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
.section-title .pill { background: var(--surface2); border-radius: 10px; padding: 1px 8px; font-size: 10px; }

.diff-row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.diff-box { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
.diff-box-header { background: var(--surface2); padding: 5px 10px; font-size: 10px; color: var(--text3); text-transform: uppercase; letter-spacing: .5px; display: flex; justify-content: space-between; }
.diff-box pre { padding: 10px; overflow-x: auto; font-size: 11px; line-height: 1.6; color: var(--text); max-height: 280px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }
.diff-box pre:empty::before { content: '(empty)'; color: var(--text3); }

.headers-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.headers-table td { padding: 3px 6px; border-bottom: 1px solid var(--border); }
.headers-table td:first-child { color: var(--text2); width: 35%; word-break: break-all; }
.headers-table td:last-child { color: var(--text); word-break: break-all; }

.replacements-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.replacements-table th { text-align: left; padding: 4px 8px; color: var(--text3); font-weight: 600; border-bottom: 1px solid var(--border); }
.replacements-table td { padding: 4px 8px; border-bottom: 1px solid var(--border); }
.original-val { color: var(--red); }
.alias-val { color: var(--green); }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

/* ── Spinner ── */
.spinner { width: 16px; height: 16px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>

<header>
  <div id="status-dot"></div>
  <h1>maskproxy</h1>
  <span id="proxy-target">loading…</span>
  <div class="tab-bar">
    <div class="tab active" data-tab="dashboard">Dashboard</div>
    <div class="tab" data-tab="traffic">Traffic</div>
  </div>
</header>

<main>
  <!-- Left: request list (visible on Traffic tab) -->
  <div id="left-panel" style="display:none">
    <div id="filter-bar">
      <input id="search" placeholder="Filter by URL, host, status…" />
      <select id="method-filter">
        <option value="">All</option>
        <option value="GET">GET</option>
        <option value="POST">POST</option>
        <option value="PUT">PUT</option>
        <option value="DELETE">DELETE</option>
        <option value="PATCH">PATCH</option>
        <option value="WS">WS</option>
      </select>
    </div>
    <div id="req-list"></div>
  </div>

  <!-- Right: tabs content -->
  <div id="right-panel">

    <!-- Dashboard -->
    <div id="dashboard" class="active-tab">
      <div class="stat-cards">
        <div class="stat-card">
          <div class="label">Total Requests</div>
          <div class="value" id="stat-total">—</div>
          <div class="sub" id="stat-rps">—</div>
        </div>
        <div class="stat-card">
          <div class="label">Error Rate</div>
          <div class="value" id="stat-errors">—</div>
          <div class="sub">4xx + 5xx</div>
        </div>
        <div class="stat-card">
          <div class="label">Avg Latency</div>
          <div class="value" id="stat-latency">—</div>
          <div class="sub">round-trip</div>
        </div>
        <div class="stat-card">
          <div class="label">Total Bytes</div>
          <div class="value" id="stat-bytes">—</div>
          <div class="sub">response traffic</div>
        </div>
      </div>
      <div class="charts-row">
        <div class="chart-card">
          <h3>Requests / Minute</h3>
          <canvas id="rpm-chart" height="110"></canvas>
        </div>
        <div class="chart-card">
          <h3>Status Codes</h3>
          <canvas id="status-chart" height="110"></canvas>
        </div>
      </div>
      <div class="hosts-row">
        <div class="hosts-card">
          <h3>Active Hosts <span class="count-badge" id="active-host-count">0</span></h3>
          <div id="active-hosts-list"></div>
        </div>
        <div class="hosts-card">
          <h3>Ignored Hosts <span class="count-badge" id="ignored-host-count">0</span></h3>
          <div id="ignored-hosts-list"></div>
        </div>
      </div>
    </div>

    <!-- Traffic -->
    <div id="traffic">
      <div id="detail-panel">
        <div id="detail-empty">← Select a request to inspect</div>
        <div id="detail-content"></div>
      </div>
    </div>

  </div>
</main>

<script>
/* ═══════════════════════════ State ═══════════════════════════ */
let transactions = [];
let selectedId = null;
let config = {};
let rpmChart = null;
let statusChart = null;
let filterText = '';
let filterMethod = '';

/* ═══════════════════════════ Init ═══════════════════════════ */
async function init() {
  await loadConfig();
  await loadTransactions();
  await loadStats();
  setupSSE();
  setInterval(loadStats, 5000);
  setInterval(() => { loadTransactions(true); }, 10000);
}

async function loadConfig() {
  try {
    const r = await fetch('/api/config');
    config = await r.json();
    const t = config.target || '—';
    document.getElementById('proxy-target').textContent = '→ ' + t;
    renderIgnoredHosts();
  } catch(e) {}
}

async function loadTransactions(silent) {
  try {
    const r = await fetch('/api/transactions');
    const data = await r.json();
    transactions = data || [];
    renderList();
  } catch(e) {}
}

async function loadStats() {
  try {
    const r = await fetch('/api/stats');
    const s = await r.json();
    renderStats(s);
    await loadHosts();
  } catch(e) {}
}

async function loadHosts() {
  try {
    const r = await fetch('/api/hosts');
    const h = await r.json();
    renderActiveHosts(h);
  } catch(e) {}
}

function setupSSE() {
  const es = new EventSource('/events');
  const dot = document.getElementById('status-dot');
  es.onopen = () => { dot.style.background = 'var(--green)'; dot.style.boxShadow = '0 0 6px var(--green)'; };
  es.onerror = () => { dot.style.background = 'var(--red)'; dot.style.boxShadow = '0 0 6px var(--red)'; setTimeout(setupSSE, 3000); es.close(); };
  es.onmessage = (e) => {
    try {
      const tx = JSON.parse(e.data);
      const idx = transactions.findIndex(t => t.id === tx.id);
      if (idx >= 0) transactions[idx] = tx;
      else transactions.unshift(tx);
      renderList();
    } catch(err) {}
  };
}

/* ═══════════════════════════ Rendering ═══════════════════════════ */
function renderStats(s) {
  document.getElementById('stat-total').textContent = fmt(s.total || 0);
  // Show the most recent 1-minute bucket count as the "current" rate.
  const pts = s.requestsPerMinute || [];
  const lastMin = pts.length > 0 ? pts[pts.length - 1].count : 0;
  document.getElementById('stat-rps').textContent = lastMin + ' req / current min';
  const errRate = (s.errorRate || 0).toFixed(1);
  document.getElementById('stat-errors').textContent = errRate + '%';
  document.getElementById('stat-latency').textContent = Math.round(s.avgDurationMs || 0) + 'ms';
  document.getElementById('stat-bytes').textContent = humanBytes(s.totalBytes || 0);

  const labels = pts.map(p => {
    const d = new Date(p.time);
    return d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0');
  });
  const counts = pts.map(p => p.count);

  if (!rpmChart) {
    const ctx = document.getElementById('rpm-chart').getContext('2d');
    rpmChart = new Chart(ctx, {
      type: 'line',
      data: { labels, datasets: [{ data: counts, borderColor: '#6c7cfc', backgroundColor: 'rgba(108,124,252,.15)', tension: .4, fill: true, pointRadius: 0 }] },
      options: { plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#64748b', maxTicksLimit: 8, font: { family: 'monospace', size: 10 } }, grid: { color: '#2d3148' } }, y: { ticks: { color: '#64748b', font: { family: 'monospace', size: 10 } }, grid: { color: '#2d3148' }, beginAtZero: true } }, animation: false }
    });
  } else {
    rpmChart.data.labels = labels;
    rpmChart.data.datasets[0].data = counts;
    rpmChart.update('none');
  }

  const codes = s.statusCodes || {};
  const cLabels = ['2xx', '3xx', '4xx', '5xx', 'other'];
  const cData = cLabels.map(l => codes[l] || 0);
  const cColors = ['#34d399','#fbbf24','#f87171','#ef4444','#64748b'];
  if (!statusChart) {
    const ctx2 = document.getElementById('status-chart').getContext('2d');
    statusChart = new Chart(ctx2, {
      type: 'doughnut',
      data: { labels: cLabels, datasets: [{ data: cData, backgroundColor: cColors, borderColor: '#1a1d27', borderWidth: 2 }] },
      options: { plugins: { legend: { position: 'right', labels: { color: '#94a3b8', font: { family: 'monospace', size: 11 }, boxWidth: 12 } } }, animation: false }
    });
  } else {
    statusChart.data.datasets[0].data = cData;
    statusChart.update('none');
  }
}

function renderActiveHosts(h) {
  const list = document.getElementById('active-hosts-list');
  const entries = Object.entries(h).sort((a,b) => b[1]-a[1]);
  document.getElementById('active-host-count').textContent = entries.length;
  list.innerHTML = entries.slice(0, 20).map(([host, count]) =>
    '<div class="host-row"><span class="host-name">'+esc(host)+'</span><span class="host-count">'+fmt(count)+' req</span></div>'
  ).join('');
}

function renderIgnoredHosts() {
  const hosts = config.ignoredHosts || [];
  document.getElementById('ignored-host-count').textContent = hosts.length;
  const list = document.getElementById('ignored-hosts-list');
  if (hosts.length === 0) {
    list.innerHTML = '<div style="color:var(--text3);padding:8px 0;font-size:12px">None configured</div>';
    return;
  }
  list.innerHTML = hosts.map(h => '<div class="host-row"><span class="ignored-host">'+esc(h)+'</span></div>').join('');
}

function methodClass(m) {
  return 'req-method ' + (m || 'GET').toUpperCase().replace(/[^A-Z]/g,'');
}
function statusClass(code) {
  if (!code) return 's0xx';
  if (code >= 500) return 's5xx';
  if (code >= 400) return 's4xx';
  if (code >= 300) return 's3xx';
  if (code >= 200) return 's2xx';
  return 's0xx';
}
function statusText(code) { return code || '—'; }

function renderList() {
  const list = document.getElementById('req-list');
  const q = filterText.toLowerCase();
  const fm = filterMethod.toUpperCase();

  const visible = transactions.filter(tx => {
    if (fm && tx.method !== fm && !(fm === 'WS' && tx.isWS)) return false;
    if (q && !(tx.url||'').toLowerCase().includes(q) && !(tx.host||'').toLowerCase().includes(q) && !String(tx.statusCode).includes(q)) return false;
    return true;
  });

  list.innerHTML = visible.map(tx => {
    const m = tx.isWS ? 'WS' : (tx.method || 'GET');
    const sc = tx.statusCode || 0;
    const dur = tx.duration ? formatDuration(tx.duration) : '';
    const path = urlPath(tx.url);
    const replaced = (tx.requestReplaceCount || 0) + (tx.responseReplaceCount || 0);
    const ts = tx.time ? new Date(tx.time).toLocaleTimeString() : '';
    return '<div class="req-item' + (tx.isIgnored?' ignored':'') + (tx.id===selectedId?' selected':'') + '" data-id="'+tx.id+'">' +
      '<span class="'+methodClass(m)+' '+m+'">'+esc(m)+'</span>' +
      '<span class="req-url" title="'+esc(normalizeUrl(tx.url)||tx.url||'')+'">'+esc(path)+'</span>' +
      '<span class="req-meta"><span class="status-badge '+statusClass(sc)+'">'+statusText(sc)+'</span>' +
      (dur ? '<span class="duration">'+dur+'</span>' : '') +
      (replaced > 0 ? '<span class="replaced-badge">'+replaced+'↺</span>' : '') + '</span>' +
      '<span class="req-host">'+esc(tx.host||'')+
        (ts ? '<span style="float:right;color:var(--text3)">'+esc(ts)+'</span>' : '')+
      '</span>' +
      '</div>';
  }).join('');

  list.querySelectorAll('.req-item').forEach(el => {
    el.addEventListener('click', () => selectTransaction(Number(el.dataset.id)));
  });
}

function selectTransaction(id) {
  selectedId = id;
  renderList();
  const tx = transactions.find(t => t.id === id);
  if (!tx) return;
  renderDetail(tx);
}

function renderDetail(tx) {
  const empty = document.getElementById('detail-empty');
  const content = document.getElementById('detail-content');
  empty.style.display = 'none';
  content.classList.add('visible');

  const m = tx.isWS ? 'WS' : (tx.method || 'GET');
  const sc = tx.statusCode || 0;
  const replaced = (tx.requestReplaceCount||0) + (tx.responseReplaceCount||0);

  content.innerHTML = '<div class="detail-header">' +
    '<span class="'+methodClass(m)+' '+m+'" style="font-size:14px">'+esc(m)+'</span>' +
    '<span class="url">'+esc(normalizeUrl(tx.url)||'')+'</span>' +
    '<div class="badges">' +
    (sc ? '<span class="status-badge '+statusClass(sc)+'">'+sc+'</span>' : '') +
    (tx.duration ? '<span class="duration">'+formatDuration(tx.duration)+'</span>' : '') +
    (replaced > 0 ? '<span class="replaced-badge">'+replaced+' replacement'+(replaced!==1?'s':'')+'</span>' : '') +
    (tx.isIgnored ? '<span class="replaced-badge" style="color:var(--yellow)">ignored host</span>' : '') +
    '</div></div>' +

    /* Request diff */
    '<div class="section"><div class="section-title">Request' +
    (tx.requestReplaceCount > 0 ? '<span class="pill">'+tx.requestReplaceCount+' replacement'+(tx.requestReplaceCount!==1?'s':'')+'</span>' : '') + '</div>' +
    '<div class="diff-row">' +
    diffBox('Original (as sent by browser)', formatReqHead(m, tx.url, tx.originalRequestHeaders, tx.originalRequestBody)) +
    diffBox('Modified (sent to upstream)', formatReqHead(m, tx.modifiedUrl, tx.modifiedRequestHeaders, tx.modifiedRequestBody)) +
    '</div></div>' +

    /* Response diff */
    (tx.statusCode ? '<div class="section"><div class="section-title">Response' +
    (tx.responseReplaceCount > 0 ? '<span class="pill">'+tx.responseReplaceCount+' replacement'+(tx.responseReplaceCount!==1?'s':'')+'</span>' : '') + '</div>' +
    '<div class="diff-row">' +
    diffBox('Original (from upstream)', tx.originalResponseBody || '') +
    diffBox('Modified (sent to browser)', tx.modifiedResponseBody || '') +
    '</div>' +
    (tx.responseHeaders ? '<div style="margin-top:8px"><div class="section-title">Response Headers</div>' + headersTable(tx.responseHeaders) + '</div>' : '') +
    '</div>' : '') +

    /* Replacements configured */
    ((config.replacements||[]).length > 0 ? '<div class="section"><div class="section-title">Active Replacements</div>' + replacementsTable(config.replacements) + '</div>' : '');
}

function diffBox(title, content) {
  return '<div class="diff-box"><div class="diff-box-header"><span>'+esc(title)+'</span></div><pre>'+esc(content)+'</pre></div>';
}

function headersTable(headers) {
  if (!headers) return '';
  const rows = Object.entries(headers).flatMap(([k,vals]) => (Array.isArray(vals)?vals:[vals]).map(v => '<tr><td>'+esc(k)+'</td><td>'+esc(v)+'</td></tr>'));
  return '<table class="headers-table">'+rows.join('')+'</table>';
}

function replacementsTable(pairs) {
  const rows = pairs.map(p => '<tr><td class="original-val">'+esc(p.original)+'</td><td style="color:var(--text3);text-align:center">→</td><td class="alias-val">'+esc(p.alias)+'</td></tr>');
  return '<table class="replacements-table"><thead><tr><th>Original (upstream)</th><th></th><th>Alias (client sees)</th></tr></thead><tbody>'+rows.join('')+'</tbody></table>';
}

function formatReqHead(method, url, headers, body) {
  let out = '';
  if (url) {
    try {
      const u = new URL(url);
      // Show a standard HTTP request-line: METHOD path?query HTTP/1.1
      out += (method || '?') + ' ' + (u.pathname + u.search || '/') + ' HTTP/1.1\n';
      out += 'Host: ' + u.host + '\n';
    } catch {
      out += url + '\n';
    }
  }
  if (headers) {
    Object.entries(headers).forEach(([k,vals]) => {
      // Skip Host header — already shown above from the URL.
      if (k.toLowerCase() === 'host') return;
      (Array.isArray(vals)?vals:[vals]).forEach(v => { out += k+': '+v+'\n'; });
    });
  }
  if (body) out += '\n' + body;
  return out;
}

/* ═══════════════════════════ Tabs ═══════════════════════════ */
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    const name = tab.dataset.tab;
    document.getElementById('dashboard').style.display = name === 'dashboard' ? 'block' : 'none';
    document.getElementById('traffic').style.display = name === 'traffic' ? 'flex' : 'none';
    document.getElementById('left-panel').style.display = name === 'traffic' ? 'flex' : 'none';
  });
});

/* ═══════════════════════════ Filters ═══════════════════════════ */
document.getElementById('search').addEventListener('input', e => { filterText = e.target.value; renderList(); });
document.getElementById('method-filter').addEventListener('change', e => { filterMethod = e.target.value; renderList(); });

/* ═══════════════════════════ Helpers ═══════════════════════════ */
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
// normalizeUrl converts internal /__sd__/<host>/<path> routing URLs back to
// the real upstream URL for display purposes.
function normalizeUrl(url) {
  if (!url) return url;
  try {
    const u = new URL(url);
    const sdPrefix = '/__sd__/';
    if (u.pathname.startsWith(sdPrefix)) {
      const rest = u.pathname.slice(sdPrefix.length);
      const slash = rest.indexOf('/');
      const subHost = slash >= 0 ? rest.slice(0, slash) : rest;
      const subPath = slash >= 0 ? rest.slice(slash) : '/';
      return u.protocol + '//' + subHost + subPath + u.search;
    }
  } catch {}
  return url;
}
function urlPath(u) {
  const norm = normalizeUrl(u);
  try { return new URL(norm).pathname || norm; } catch { return norm || ''; }
}
function fmt(n) {
  if (n >= 1e6) return (n/1e6).toFixed(1)+'M';
  if (n >= 1e3) return (n/1e3).toFixed(1)+'K';
  return String(n);
}
function humanBytes(b) {
  if (b >= 1073741824) return (b/1073741824).toFixed(1)+' GiB';
  if (b >= 1048576) return (b/1048576).toFixed(1)+' MiB';
  if (b >= 1024) return (b/1024).toFixed(1)+' KiB';
  return b+' B';
}
function formatDuration(ns) {
  const ms = ns / 1000000;
  if (ms >= 1000) return (ms/1000).toFixed(1)+'s';
  if (ms >= 1) return Math.round(ms)+'ms';
  return Math.round(ns/1000)+'µs';
}

init();
</script>
</body>
</html>`
