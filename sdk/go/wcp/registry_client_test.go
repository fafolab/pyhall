package wcp

// RegistryClient tests — uses httptest.Server (no real network calls)

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func newTestClient(srv *httptest.Server) *RegistryClient {
	return NewRegistryClient(RegistryClientOptions{BaseURL: srv.URL})
}

func activeWorkerJSON() map[string]any {
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return map[string]any{
		"worker_id":              "x.test.worker1",
		"status":                 "active",
		"current_hash":           hash,
		"banned":                 false,
		"ban_reason":             nil,
		"attested_at":            "2026-03-03T00:00:00Z",
		"ai_generated":           false,
		"ai_service":             nil,
		"ai_model":               nil,
		"ai_session_fingerprint": nil,
	}
}

func banListJSON() []map[string]any {
	return []map[string]any{
		{
			"sha256":        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"reason":        "malware",
			"reported_at":   "2026-03-01T00:00:00Z",
			"source":        "community",
			"review_status": "approved",
		},
	}
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// ── Verify() ─────────────────────────────────────────────────────────────────

func TestVerifyReturnsActiveWorker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, activeWorkerJSON())
	}))
	defer srv.Close()

	c := newTestClient(srv)
	resp, err := c.Verify("x.test.worker1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "active" {
		t.Errorf("expected active, got %s", resp.Status)
	}
	if resp.CurrentHash == nil || *resp.CurrentHash != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("unexpected hash: %v", resp.CurrentHash)
	}
	if resp.Banned {
		t.Error("expected banned=false")
	}
}

func TestVerify404ReturnsUnknownNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, map[string]string{"error": "not found"})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	resp, err := c.Verify("x.nonexistent.worker")
	if err != nil {
		t.Fatalf("404 should not return error, got: %v", err)
	}
	if resp.Status != "unknown" {
		t.Errorf("expected unknown, got %s", resp.Status)
	}
	if resp.CurrentHash != nil {
		t.Error("expected nil current_hash for unknown worker")
	}
}

func TestVerify429ReturnsRateLimitError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 429, map[string]string{})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.Verify("x.test.w")
	if _, ok := err.(*RegistryRateLimitError); !ok {
		t.Errorf("expected RegistryRateLimitError, got %T: %v", err, err)
	}
}

func TestVerify500ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 500, map[string]string{"error": "internal"})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.Verify("x.test.w")
	if err == nil {
		t.Error("expected error for 500, got nil")
	}
}

func TestVerifyCacheSkipsSecondFetch(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeJSON(w, 200, activeWorkerJSON())
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, _ = c.Verify("x.test.worker1")
	_, _ = c.Verify("x.test.worker1")
	if calls != 1 {
		t.Errorf("expected 1 fetch call, got %d", calls)
	}
}

// ── IsHashBanned() ────────────────────────────────────────────────────────────

func TestIsHashBannedReturnsTrueForBannedHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, banListJSON())
	}))
	defer srv.Close()

	c := newTestClient(srv)
	banned, err := c.IsHashBanned("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !banned {
		t.Error("expected banned=true")
	}
}

func TestIsHashBannedReturnsFalseForCleanHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, banListJSON())
	}))
	defer srv.Close()

	c := newTestClient(srv)
	banned, err := c.IsHashBanned("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if banned {
		t.Error("expected banned=false")
	}
}

// ── GetBanList() ──────────────────────────────────────────────────────────────

func TestGetBanListReturnEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, banListJSON())
	}))
	defer srv.Close()

	c := newTestClient(srv)
	entries, err := c.GetBanList(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].SHA256 != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Errorf("unexpected sha256: %s", entries[0].SHA256)
	}
}

func TestGetBanListIncludesLimitParam(t *testing.T) {
	gotURL := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		writeJSON(w, 200, []map[string]any{})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, _ = c.GetBanList(100)
	if gotURL != "/api/v1/ban-list?limit=100" {
		t.Errorf("unexpected URL: %s", gotURL)
	}
}

// ── Health() ─────────────────────────────────────────────────────────────────

func TestHealthReturnsVersionAndOk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "version": "0.2.0"})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	h, err := c.Health()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h["version"] != "0.2.0" {
		t.Errorf("unexpected version: %v", h["version"])
	}
}

// ── GetWorkerHash() ───────────────────────────────────────────────────────────

func TestGetWorkerHashReturnsHashForActiveWorker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, activeWorkerJSON())
	}))
	defer srv.Close()

	c := newTestClient(srv)
	hash, ok := c.GetWorkerHash("x.test.worker1")
	if !ok {
		t.Error("expected ok=true for active worker")
	}
	if hash != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("unexpected hash: %s", hash)
	}
}

func TestGetWorkerHashReturnsFalseForUnknownWorker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, map[string]string{"error": "not found"})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, ok := c.GetWorkerHash("x.nonexistent")
	if ok {
		t.Error("expected ok=false for unknown worker")
	}
}

func TestGetWorkerHashReturnsFalseForBannedWorker(t *testing.T) {
	banned := activeWorkerJSON()
	banned["status"] = "banned"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, banned)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, ok := c.GetWorkerHash("x.test.worker1")
	if ok {
		t.Error("expected ok=false for banned worker")
	}
}

// ── Prefetch() ────────────────────────────────────────────────────────────────

func TestPrefetchPopulatesCache(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeJSON(w, 200, activeWorkerJSON())
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_ = c.Prefetch([]string{"x.test.worker1"})
	_, _ = c.Verify("x.test.worker1") // should hit cache
	if calls != 1 {
		t.Errorf("expected 1 fetch call, got %d", calls)
	}
}

func TestPrefetchNonFatalOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, map[string]string{"error": "not found"})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.Prefetch([]string{"x.nonexistent"})
	if err != nil {
		t.Errorf("prefetch should be non-fatal on 404, got: %v", err)
	}
}
